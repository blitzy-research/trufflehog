# Why TruffleHog reports the same AWS key inconsistently (plain text vs. Base64): a run-first investigation

**Commit under investigation:** `e42153d4` (branch `trufflehog_e42153d44a5e`) — `[Fix] Added Prefix In Dockerhub Detector Regex (#4084)`
**Module:** `github.com/trufflesecurity/trufflehog/v3`

## 1. Title & scope

This document answers, **from observed runtime behavior** (not code reading alone), why TruffleHog produces inconsistent output when one file contains the *same* AWS access key both as raw plain text and Base64‑encoded. The user reported:

> "sometimes TruffleHog reported the secret twice with different decoder types, sometimes it reported an overlap error, and sometimes it deduplicated down to a single result," and the behavior "seemed inconsistent depending on how I structured the test file."

It resolves all six sub‑questions explicitly and by name:

1. How the decoder pipeline handles the same secret in multiple encoded forms — **plain text, Base64, and escaped Unicode**.
2. **Which decoder types are reported** (`PLAIN`, `BASE64`, `UTF16`, `ESCAPED_UNICODE`).
3. **Whether overlap detection occurs** — including the negative "no overlap for a single‑detector AWS key" result.
4. **How deduplication affects the final result count.**
5. **Whether deduplication happens before or after overlap detection.**
6. **Why the same logical secret sometimes produces one result and sometimes multiple.**

**Methodology (run‑first):** every factual claim below is backed by output captured from a canonical build of this commit, exercised through the real `trufflehog filesystem` entry point (`main.go:143`). Code `file:line` citations are the grounding; the captured output is the primary evidence. All fixtures, scripts, and binaries were created outside the repository tree and removed afterward (see §10); the only persisted change is this document.

**A note on the keys used.** The verified public test key `AKIAYVP4CIPPERUVIFXG` shown in `README.md:197-199` lives in the *external* module `github.com/trufflesecurity/test_keys`, not in this repo, and the AWS‑documentation example id `AKIAIOSFODNN7EXAMPLE` is dropped as a **known false positive** by the engine's false‑positive filter (`engine.go:1141-1142` invokes `detectors.FilterKnownFalsePositives`, `pkg/detectors/falsepositives.go:177`) because its lowercased form contains the term `example` — the "contains term" branch of `IsKnownFalsePositive` (`falsepositives.go:85`, `falsepositives.go:95-99`); this is shown by the observed output immediately below. The AWS fixtures therefore use a **synthetic, randomly‑generated, non‑verifiable** AWS‑format key id `AKIA2HAFCFGWPBBBW43J` with secret `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`. These are not real credentials; all runs use `--no-verification`, so the keys surface only as *unverified* results.

*Observed evidence for the example‑id filtering.* The AWS‑documentation example pair `aws_access_key_id = AKIAIOSFODNN7EXAMPLE aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (a 106‑byte fixture) yields **zero** results — `finished scanning` reports `"unverified_secrets": 0`:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/g_examplekey --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-07T00:11:37Z	info-0	trufflehog	running source	{"source_manager_worker_id": "qGpHJ", "with_units": true}
2026-07-07T00:11:37Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.699515ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Re‑running the identical scan at `--log-level=4` and filtering with `grep` (the per‑worker "finished scanning chunks" shutdown lines are excluded *by the `grep` in the command shown*, so the block below is exactly what that command emits) surfaces the engine's `V(4)` skip log naming the reason:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/g_examplekey --log-level=4 --no-verification --results=verified,unverified,unknown 2>&1 | grep 'Skipping result: false positive'
2026-07-07T00:12:42Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "fUEME", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

The skip log is emitted at `falsepositives.go:194` (`ctx.Logger().V(4).Info("Skipping result: false positive", "result", string(result.Raw), "reason", reason)`) immediately before the result is discarded via `continue` (`falsepositives.go:195`); the `reason` string `contains term: example` is constructed by the "contains term" branch of `IsKnownFalsePositive` (`falsepositives.go:98`). The filtered value is the AWS **access key id** (`result.Raw`), which is why this synthetic‑key note uses a randomly‑generated id instead of the AWS‑documentation example.

---

## 2. Build & environment

All building and running was performed inside the project's canonical container image `ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0`, with the repository mounted **read‑only** so the source tree could not be modified.

**Toolchain (observed):**

```text
$ go version
go version go1.24.3 linux/amd64
```

The module targets `go 1.23.1` with `toolchain go1.24.2` (`go.mod:3`, `go.mod:5`); CI pins Go 1.24, and the container resolves Go 1.24.3, which satisfies it.

**Canonical build command and result:**

```text
$ CGO_ENABLED=0 go build -o /tmp/th_investigation/trufflehog . && echo BUILD_OK
BUILD_OK
$ ls -la /tmp/th_investigation/trufflehog
-rwxr-xr-x 1 root root 194183078 Jul  6 23:36 /tmp/th_investigation/trufflehog
```

(The AAP‑canonical form is `CGO_ENABLED=0 go build -o trufflehog .`; only the output path differs.)

**Version banner (observed):**

```text
$ /tmp/th_investigation/trufflehog --version
trufflehog dev
```

All output shown below therefore comes from build `trufflehog dev` on Go 1.24.3.

**Concurrency:** the container reports `nproc` = **128**, and `--concurrency` defaults to `runtime.NumCPU()` (`main.go:58`). The engine does **not** run one flat pool of that size — it starts four pools whose sizes derive from `concurrency`: the **scanner** pool is `concurrency` workers (`engine.go:663-664`); the **detector** pool is `concurrency × detectorWorkerMultiplier`, where the multiplier defaults to **8** (`engine.go:676`, default set at `engine.go:345`); the **verification‑overlap** and **notifier** pools are each `concurrency × 1` (multipliers default to `1` at `engine.go:353` and `engine.go:349`; pool sizes computed at `engine.go:691` and `engine.go:706`). On this 128‑CPU host that is **128 scanner, 1024 detector, 128 verification‑overlap, and 128 notifier** workers — confirmed by the engine's own `V(2)` startup log:

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/a_plaintext --log-level=4 --no-verification --results=verified,unverified,unknown 2>&1 | grep 'starting .* workers'
2026-07-07T00:17:02Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-07T00:17:02Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-07T00:17:02Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-07T00:17:02Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

This matters because having multiple concurrent workers per pool makes the **arrival order** of results at the notifier non‑deterministic, which is directly observable in §5 (which decoder type survives dedup for fixture (d), and which detector carries the overlap error for fixture (f)).

**Invocation flags used** (default configuration as a normal user would run it, plus the result selection needed to surface *unverified* keys):

- `--no-verification` (`main.go:59`) — don't attempt network verification.
- `--results=verified,unverified,unknown` (`main.go:61`) — emit unverified results (the AWS test keys) and unknown results (results carrying a verification error, such as the overlap error).
- `--json` (`main.go:55`) — for machine‑readable field inspection.
- `--allow-verification-overlap` (`main.go:65`) — toggled in §5 to demonstrate the overlap override.
- `--config <yaml>` — used only for the overlap fixture (f), to add a second detector (explained there).

---

## 3. Fixtures used

Six fixtures isolate every condition the question implies. The AWS pair is a single physical line:

```text
aws_access_key_id = AKIA2HAFCFGWPBBBW43J aws_secret_access_key = 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
```

Its Base64 encoding (single line, no wrapping) is:

```text
YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMkhBRkNGR1dQQkJCVzQzSiBhd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSBMWE9CK2ZJN0lMRmlJbTl0aWZaNkNKQXFTOHdWR0ovVUpiU0RzT1Nu
```

### (a) `a_plaintext/secrets.txt` — plain text only
```text
aws_access_key_id = AKIA2HAFCFGWPBBBW43J aws_secret_access_key = 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
```

### (b) `b_base64/secrets.txt` — Base64 only
```text
YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMkhBRkNGR1dQQkJCVzQzSiBhd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSBMWE9CK2ZJN0lMRmlJbTl0aWZaNkNKQXFTOHdWR0ovVUpiU0RzT1Nu
```

### (c) `c_twoline_blobfirst/secrets.txt` — Base64 on line 1, plain text on line 2
```text
YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMkhBRkNGR1dQQkJCVzQzSiBhd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSBMWE9CK2ZJN0lMRmlJbTl0aWZaNkNKQXFTOHdWR0ovVUpiU0RzT1Nu
aws_access_key_id = AKIA2HAFCFGWPBBBW43J aws_secret_access_key = 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
```

### (d) `d_twoline_plainfirst/secrets.txt` — plain text on line 1, Base64 on line 2
```text
aws_access_key_id = AKIA2HAFCFGWPBBBW43J aws_secret_access_key = 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
YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMkhBRkNGR1dQQkJCVzQzSiBhd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSBMWE9CK2ZJN0lMRmlJbTl0aWZaNkNKQXFTOHdWR0ovVUpiU0RzT1Nu
```

> **(c) and (d) contain exactly the same two lines in opposite order.** That single difference is what flips the outcome between "two results" and "one result" — see §5 and §7‑Q6.

### (e) `e_escunicode/secrets.txt` — escaped‑Unicode form of the AWS pair
Every byte of the AWS pair is written as a `\u00XX` escape (630 characters), so the raw bytes contain **no** literal `AKIA` and **no** long Base64 run — only the escaped‑Unicode decoder can reveal the key:
```text
\u0061\u0077\u0073\u005f\u0061\u0063\u0063\u0065\u0073\u0073\u005f\u006b\u0065\u0079\u005f\u0069\u0064\u0020\u003d\u0020\u0041\u004b\u0049\u0041\u0032\u0048\u0041\u0046\u0043\u0046\u0047\u0057\u0050\u0042\u0042\u0042\u0057\u0034\u0033\u004a\u0020\u0061\u0077\u0073\u005f\u0073\u0065\u0063\u0072\u0065\u0074\u005f\u0061\u0063\u0063\u0065\u0073\u0073\u005f\u006b\u0065\u0079\u0020\u003d\u0020\u004c\u0058\u004f\u0042\u002b\u0066\u0049\u0037\u0049\u004c\u0046\u0069\u0049\u006d\u0039\u0074\u0069\u0066\u005a\u0036\u0043\u004a\u0041\u0071\u0053\u0038\u0077\u0056\u0047\u004a\u002f\u0055\u004a\u0062\u0053\u0044\u0073\u004f\u0053\u006e
```

### (f) multi‑detector overlap fixture
A lone AWS key matches only the AWS detector, so it can never trigger overlap (see §7‑Q3). To exercise the overlap path we need **one chunk matched by two detectors of different types**. `likelyDuplicate` explicitly *skips* pairs of the **same** detector type (`engine.go:900-902`), and all custom‑regex detectors share the single type `CustomRegex` — which is exactly why the repository's own `TestVerificationOverlapChunk` (using two custom detectors) expects `wantDupe = 0` (`pkg/engine/engine_test.go:503-555`). So we pair a **built‑in** detector (`Postman`) with **one** custom `--config` detector matching the *identical* token; the two carry different `DetectorType`s and the overlap fires.

`f_overlap/data/s.txt` (the token is the synthetic Postman‑format key from the repo's own testdata, `pkg/engine/testdata/verificationoverlap_secrets.txt`):
```text
POSTMAN_API_KEY="PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r"
```

`f_overlap/overlap_detectors.yaml`:
```yaml
detectors:
  - name: overlapdemo
    keywords:
      - PMAK
    regex:
      api_key: (PMAK-[a-zA-Z0-9]{59})
```

---

## 4. Per‑condition runs (complete, unedited output)

Each fixture was run through the real entry point in **both** plain and JSON modes, and the **complete, unedited** output of each invocation is shown below — the exact command on the first `$` line, then everything the process wrote to the terminal (`2>&1`): the stderr banner/logs and the stdout results, in the order they were emitted. In plain mode the run‑variable fields are the log timestamps, the random `source_manager_worker_id`, the `scan_duration`, and (because `ExtraData` is a Go map) the relative order of the `Account:`/`Resource_type:` lines. In JSON mode the two structured log lines (`"msg":"running source"` and `"msg":"finished scanning"`) frame the result object(s). The `Detector Type:` / `Decoder Type:` (plain, `pkg/output/plain.go:63-64`) and `DetectorName` / `DecoderName` (JSON, `pkg/output/json.go:63,65`) fields are quoted exactly as printed.


### (a) Plain text — 1 result, `Decoder Type: PLAIN`

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/a_plaintext --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:34Z	info-0	trufflehog	running source	{"source_manager_worker_id": "HwhQn", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIA2HAFCFGWPBBBW43J
Account: 702237780396
Resource_type: Access key
File: /tmp/th_investigation/fixtures/a_plaintext/secrets.txt
Line: 1

2026-07-06T23:50:34Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.086842ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/a_plaintext --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:36Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"v4AyE","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/a_plaintext/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:36Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":106,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.081597ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 1.** `"DecoderName":"PLAIN"`, `"DetectorType":2` (= AWS in the `DetectorType` enum, `pkg/pb/detectorspb/detectors.pb.go:83`). The result is printed between the `running source` and `finished scanning` log lines; `finished scanning` reports `"unverified_secrets": 1`.

### (b) Base64 only — 1 result, `Decoder Type: BASE64`

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/b_base64 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:38Z	info-0	trufflehog	running source	{"source_manager_worker_id": "n6pJm", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIA2HAFCFGWPBBBW43J
Resource_type: Access key
Account: 702237780396
File: /tmp/th_investigation/fixtures/b_base64/secrets.txt
Line: 1

2026-07-06T23:50:38Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.105488ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/b_base64 --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:40Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"qDmGa","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/b_base64/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:40Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":106,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.415928ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 1.** `"DecoderName":"BASE64"`. Same `Raw`/`RawV2`/`DetectorType` as (a): the Base64 decoder decoded the blob in place and the AWS detector matched the recovered key. The blob text itself contains no literal `AKIA`, so the `PLAIN` decoder produced no match here. (The fixture file is 141 bytes, yet `finished scanning` reports `"bytes": 106` — the counter reflects decoded/scanned chunk bytes, not raw file size.)

### (c) Base64 line 1 + plain text line 2 — **2 results** (`PLAIN` + `BASE64`, different lines)

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/c_twoline_blobfirst --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:41Z	info-0	trufflehog	running source	{"source_manager_worker_id": "CLIrR", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIA2HAFCFGWPBBBW43J
Resource_type: Access key
Account: 702237780396
File: /tmp/th_investigation/fixtures/c_twoline_blobfirst/secrets.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIA2HAFCFGWPBBBW43J
Resource_type: Access key
Account: 702237780396
File: /tmp/th_investigation/fixtures/c_twoline_blobfirst/secrets.txt
Line: 2

2026-07-06T23:50:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 212, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "6.12908ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/c_twoline_blobfirst --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:43Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"9lMaX","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/c_twoline_blobfirst/secrets.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/c_twoline_blobfirst/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:43Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":212,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"5.856848ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 2** — this is the user's "reported twice with different decoder types." One result is `Decoder Type: PLAIN` at `line 2`, the other `Decoder Type: BASE64` at `line 1`; identical `Raw`/`RawV2`/`DetectorType`, different `SourceMetadata` line. (Which of the two results prints first is arrival‑order dependent and varies run‑to‑run — here the plain run emitted `BASE64`@line1 first while the JSON run emitted `PLAIN`@line2 first — but the count is always 2; see §5.2. Both JSON objects are shown complete and verbatim, including the full `DetectorDescription`.)

### (d) Plain text line 1 + Base64 line 2 — **1 result** (dedup collapse)

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/d_twoline_plainfirst --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:45Z	info-0	trufflehog	running source	{"source_manager_worker_id": "erISk", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIA2HAFCFGWPBBBW43J
Account: 702237780396
Resource_type: Access key
File: /tmp/th_investigation/fixtures/d_twoline_plainfirst/secrets.txt
Line: 1

2026-07-06T23:50:45Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 212, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.3914ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/d_twoline_plainfirst --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:47Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"QzaUL","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/d_twoline_plainfirst/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:47Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":212,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"4.651895ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 1** — this is the user's "deduplicated down to a single result." Same content as (c), lines swapped. `finished scanning` reports `"unverified_secrets": 1`. Here the surviving result is `Decoder Type: PLAIN` at `line 1`; the `BASE64` decoder decodes the line‑2 blob but the line‑1 plaintext key is *still present*, so the recovered key's first occurrence is at `line 1` too — identical `SourceMetadata` to the `PLAIN` match, so the second result is deduplicated away (§7‑Q4/Q6). The single survivor's decoder type is **not fixed** across runs — both runs shown above happened to survive as `PLAIN`, but §5.1 shows it is sometimes `BASE64`.

### (e) Escaped Unicode — 1 result, `Decoder Type: ESCAPED_UNICODE`

```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/e_escunicode --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:48Z	info-0	trufflehog	running source	{"source_manager_worker_id": "sDvaj", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: ESCAPED_UNICODE
Raw result: AKIA2HAFCFGWPBBBW43J
Resource_type: Access key
Account: 702237780396
File: /tmp/th_investigation/fixtures/e_escunicode/secrets.txt
Line: 1

2026-07-06T23:50:48Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 631, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.758621ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/e_escunicode --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:50Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"ZaBU1","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/e_escunicode/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"ESCAPED_UNICODE","Verified":false,"VerificationFromCache":false,"Raw":"AKIA2HAFCFGWPBBBW43J","RawV2":"AKIA2HAFCFGWPBBBW43J:LXOB+fI7ILFiIm9tifZ6CJAqS8wVGJ/UJbSDsOSn","Redacted":"AKIA2HAFCFGWPBBBW43J","ExtraData":{"account":"702237780396","resource_type":"Access key"},"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:50Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":631,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"4.537858ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 1.** `"DecoderName":"ESCAPED_UNICODE"`. Only the escaped‑Unicode decoder produced a match: the raw bytes are `\u00XX` sequences with no literal `AKIA` and no ≥20‑char Base64 run, so neither `PLAIN` nor `BASE64` matched.

### (f) Multi‑detector overlap — 2 results; one carries the overlap error

Plain (adds the custom detector via `--config`), **without** `--allow-verification-overlap`:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:52Z	info-0	trufflehog	running source	{"source_manager_worker_id": "s4d9F", "with_units": true}
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: /tmp/th_investigation/fixtures/f_overlap/data/s.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: overlapdemo
File: /tmp/th_investigation/fixtures/f_overlap/data/s.txt
Line: 1

2026-07-06T23:50:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.993868ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

JSON (same command, `--json`), **without** the flag:
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --json --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:54Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"VaY3a","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/f_overlap/data/s.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"This is a user-defined detector with no description provided.","DecoderName":"PLAIN","Verified":false,"VerificationError":"More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.","VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":{"name":"overlapdemo"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/f_overlap/data/s.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":118,"DetectorName":"Postman","DetectorDescription":"Postman is a collaboration platform for API development. Postman API keys can be used to access and modify collections, environments, and other resources.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:54Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":83,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"6.423896ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Result count: 2**, both `Decoder Type: PLAIN`, both `line 1`, same `Raw`. Exactly one of the two results carries `"VerificationError":"More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag."` (plain: `Verification issue:` line) — this is the user's "overlap error." **Which** detector carries it is arrival‑order dependent and varies run‑to‑run: the plain run above tagged `Postman` (`"DetectorType":118`) while the JSON run tagged `CustomRegex` (`"DetectorType":904`); the other result is emitted clean (see the §5.3 distribution). Note that overlap **does not reduce the count** (still 2) — it only disables verification on the affected result.

The complete plain and JSON output **with** `--allow-verification-overlap` (no overlap error on either result) is shown in §5.3.

---

## 5. Observed run‑to‑run outcome distribution (reproducing the inconsistency)

The **count** for each fixture is stable per layout; the **nondeterminism** shows up in *which decoder type is reported* for the deduped survivor, and in *which detector carries* the overlap error. Below are the raw distributions from running each identical command in a loop (JSON mode; each run parsed to `count | sorted decoder names`).

### 5.1 Fixture (d) collapse — 30 identical runs: count always 1, survivor decoder type varies

Command (repeated unchanged 30×):
```text
/tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/d_twoline_plainfirst --no-verification --results=verified,unverified,unknown --json
```

| run | outcome | run | outcome | run | outcome |
|----:|---------|----:|---------|----:|---------|
| 1 | 1 \| BASE64 | 11 | 1 \| PLAIN | 21 | 1 \| PLAIN |
| 2 | 1 \| PLAIN | 12 | 1 \| PLAIN | 22 | 1 \| PLAIN |
| 3 | 1 \| PLAIN | 13 | 1 \| BASE64 | 23 | 1 \| BASE64 |
| 4 | 1 \| PLAIN | 14 | 1 \| PLAIN | 24 | 1 \| PLAIN |
| 5 | 1 \| PLAIN | 15 | 1 \| BASE64 | 25 | 1 \| PLAIN |
| 6 | 1 \| PLAIN | 16 | 1 \| PLAIN | 26 | 1 \| BASE64 |
| 7 | 1 \| BASE64 | 17 | 1 \| PLAIN | 27 | 1 \| PLAIN |
| 8 | 1 \| PLAIN | 18 | 1 \| PLAIN | 28 | 1 \| PLAIN |
| 9 | 1 \| PLAIN | 19 | 1 \| BASE64 | 29 | 1 \| PLAIN |
| 10 | 1 \| BASE64 | 20 | 1 \| PLAIN | 30 | 1 \| PLAIN |

**Distribution:** `1 | PLAIN` = **22/30**, `1 | BASE64` = **8/30**. The result count is always 1, but the surviving result's `Decoder Type` flips between `PLAIN` and `BASE64` from run to run. This is the observable face of "inconsistent": for a *fixed* file, the reported decoder type is not deterministic. It also proves that a `BASE64` match really was produced (it wins 8 times), so two matches exist before dedup and one is discarded — see §6.

### 5.2 Fixture (c) two‑results — 15 identical runs: stable

```text
/tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/c_twoline_blobfirst --no-verification --results=verified,unverified,unknown --json
```

**Distribution:** `2 | BASE64,PLAIN` = **15/15**. The count (2) is deterministic for this layout; both a `PLAIN` and a `BASE64` result are always emitted.

### 5.3 Fixture (f) overlap — the `--allow-verification-overlap` toggle

Without the flag (12 identical runs):
```text
/tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --no-verification --results=verified,unverified,unknown --json
```

| outcome | runs |
|---|---:|
| `count=2 errOverlap=1 [CustomRegex:ok, Postman:OVERLAP]` | 11/12 |
| `count=2 errOverlap=1 [CustomRegex:OVERLAP, Postman:ok]` | 1/12 |

The overlap error is present in **every** run (12/12), but **which** of the two detectors' results carries it varies with arrival order in the overlap worker (the result processed second becomes the "duplicate").

With the flag (12 identical runs):
```text
/tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --allow-verification-overlap --no-verification --results=verified,unverified,unknown --json
```

| outcome | runs |
|---|---:|
| `count=2 errOverlap=0 [CustomRegex:ok, Postman:ok]` | 12/12 |

With `--allow-verification-overlap`, the overlap error **never** appears (0/12): the routing condition `!e.verificationOverlap` at `engine.go:796` is now false, so the chunk is never sent to the overlap worker and `errOverlap` is never set. The suppression flips cleanly. (Complete plain/JSON output for both flag states is in §4(f) and below.)

Complete plain output **with** `--allow-verification-overlap` (exact command first; no `Verification issue:` line on either result):
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --allow-verification-overlap --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:50:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "ZPGOU", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: overlapdemo
File: /tmp/th_investigation/fixtures/f_overlap/data/s.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: /tmp/th_investigation/fixtures/f_overlap/data/s.txt
Line: 1

2026-07-06T23:50:55Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "4.65511ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Complete JSON output **with** `--allow-verification-overlap` (neither result object carries a `VerificationError` field):
```text
$ /tmp/th_investigation/trufflehog filesystem /tmp/th_investigation/fixtures/f_overlap/data --config /tmp/th_investigation/fixtures/f_overlap/overlap_detectors.yaml --json --allow-verification-overlap --no-verification --results=verified,unverified,unknown
{"level":"info-0","ts":"2026-07-06T23:50:57Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"EXOLE","with_units":true}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/f_overlap/data/s.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"This is a user-defined detector with no description provided.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":{"name":"overlapdemo"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/fixtures/f_overlap/data/s.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":118,"DetectorName":"Postman","DetectorDescription":"Postman is a collaboration platform for API development. Postman API keys can be used to access and modify collections, environments, and other resources.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"level":"info-0","ts":"2026-07-06T23:50:57Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":83,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"5.664368ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

---

## 6. Before/after counts (per‑decoder matches vs. post‑dedup results)

"Matches produced" = decoded chunks that matched a detector (before the notifier's dedup). "Results emitted" = what the notifier outputs after dedup, equal to the `unverified_secrets` value in each run's `finished scanning` banner (observed below) and to the JSON result count.

| Fixture | matches produced (before dedup) | results emitted (after dedup) | reduction |
|---|---|---|---|
| (a) plaintext | 1 — `PLAIN` | 1 | none |
| (b) base64 | 1 — `BASE64` | 1 | none |
| (c) blob line1 + plain line2 | 2 — `BASE64`@line1, `PLAIN`@line2 | 2 | none (different `SourceMetadata` line) |
| (d) plain line1 + blob line2 | 2 — `PLAIN`@line1, `BASE64`@line1 | **1** | **2 → 1** (same key, different decoder type) |
| (e) escaped unicode | 1 — `ESCAPED_UNICODE` | 1 | none |
| (f) overlap (Postman + custom) | 2 — `Postman`, `CustomRegex` | 2 | none (different `DetectorType`) |

Observed `finished scanning` banners (the `unverified_secrets` field is the post‑dedup emitted count). Each line below is the **complete, unedited** plain‑mode `finished scanning` log line for that fixture, byte‑identical to the one emitted in the corresponding §4 run (the `scan_duration` is that run's per‑run figure):

```text
# (a) plaintext
2026-07-06T23:50:34Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.086842ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# (b) base64 only
2026-07-06T23:50:38Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.105488ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# (c) blob line1 + plain line2 (two results)
2026-07-06T23:50:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 212, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "6.12908ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# (d) plain line1 + blob line2 (dedup collapse)
2026-07-06T23:50:45Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 212, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.3914ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# (e) escaped unicode
2026-07-06T23:50:48Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 631, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.758621ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# (f) multi-detector overlap, without --allow-verification-overlap
2026-07-06T23:50:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.993868ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**How "2 matches" for (d) is observed (not merely inferred):** (a) proves the `PLAIN` decoder matches the plaintext form (1), (b) proves the `BASE64` decoder matches the encoded form (1); (c) — the *same two lines* as (d) but reordered — emits both (2); and the §5.1 loop shows the (d) survivor is sometimes `BASE64`, which can only happen if a `BASE64` match was produced. Only the *emission* differs: (c) keeps both, (d) collapses to one. Note the `numFoundResults` counter incremented before the dedup check (`engine.go:1208`) is not surfaced in output, so the pre‑dedup count is established through these observations rather than a single banner field.

Key distinction the counts make explicit: **overlap (f) does not reduce the count** (2 → 2; it only disables verification), whereas **dedup (d) does** (2 → 1).


---

## 7. Explicit answers to the six questions

### Q1 — How the decoder pipeline handles the same secret in multiple encoded forms (plain text, Base64, escaped Unicode)

**Direct answer:** The pipeline applies a **fixed, single‑pass chain of four decoders** to *every* chunk, independently. Each decoder transforms a copy of the original chunk and hands the decoded bytes to the detectors; the decoders are **not** chained or applied iteratively. For our AWS pair: the `UTF8`/`PLAIN` decoder matches the raw plaintext line (fixture a → `PLAIN`); the `Base64` decoder locates the encoded substring, decodes it in place, and the detector then matches the recovered key (fixture b → `BASE64`); the `EscapedUnicode` decoder decodes `\u00XX` sequences and the detector matches the recovered key (fixture e → `ESCAPED_UNICODE`).

**Evidence:** `pkg/decoders/decoders.go:8-16` — `DefaultDecoders()` returns exactly `{&UTF8{}, &Base64{}, &UTF16{}, &EscapedUnicode{}}`, with the comment `// UTF8 must be first for duplicate detection`. `scannerWorker` loops these decoders per chunk and, for each decoded chunk, runs the keyword prefilter (`pkg/engine/engine.go:777-841`, decode + `FindDetectorMatches` at `engine.go:795`). Observed decoder types: (a) `Decoder Type: PLAIN`, (b) `Decoder Type: BASE64`, (e) `Decoder Type: ESCAPED_UNICODE` (§4). The Base64 decoder decodes substrings in place via `base64.StdEncoding.DecodeString`/`base64.RawURLEncoding.DecodeString` (`pkg/decoders/base64.go:34-49`); the escaped‑Unicode decoder matches `\uXXXX`/`U+XXXX` and copies the original `SourceMetadata` onto the decoded chunk (`pkg/decoders/escaped_unicode.go:22,25,32-64`).

**Reasoning:** Because decoders run independently on the *same* original chunk (not on each other's output), the plaintext form is seen by `PLAIN` and the encoded forms by their respective decoders — the same logical key can therefore be discovered along up to three different decoder paths in one scan. `UTF16` did not appear for these fixtures (there is no UTF‑16‑encoded key present); it is the fourth member of the chain and would report `Decoder Type: UTF16` for UTF‑16 content.

### Q2 — Which decoder types are reported

**Direct answer:** The reported values come from the `DecoderType` enum: `PLAIN`, `BASE64`, `UTF16`, `ESCAPED_UNICODE` (plus the zero value `UNKNOWN`). In this investigation we observed **`PLAIN`** (a, c, d), **`BASE64`** (b, c), and **`ESCAPED_UNICODE`** (e). `UTF16` is defined and available but was not produced (no UTF‑16 input).

**Evidence:** enum `pkg/pb/detectorspb/detectors.pb.go:26-30` — `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4`, with the string names at `detectors.pb.go:35-41`. Each decoder's `Type()`: `PLAIN` (`utf8.go:12-13`), `BASE64` (`base64.go:30-31`), `UTF16` (`utf16.go:14-15`), `ESCAPED_UNICODE` (`escaped_unicode.go:28-29`). The user sees this field as `Decoder Type:` in plain output (`pkg/output/plain.go:64`) and `DecoderName` in JSON (`pkg/output/json.go:65`, set to `r.DecoderType.String()`). Observed verbatim in §4: `Decoder Type: PLAIN`, `Decoder Type: BASE64`, `Decoder Type: ESCAPED_UNICODE`; JSON `"DecoderName":"PLAIN"`, `"BASE64"`, `"ESCAPED_UNICODE"`.

**Reasoning:** The decoder type is a property of *which decoder recovered the bytes that matched*, carried on the `DecodableChunk` (`decoders.go:18-22`) through detection and onto the result, then printed by the output layer.

### Q3 — Whether overlap detection occurs

**Direct answer (two parts):**
- **For a lone AWS key: NO.** Overlap detection does **not** occur for any of fixtures (a)–(e). An AWS access key matches exactly one detector (AWS), so the overlap condition is false and the chunk takes the normal single‑detector path. None of (a)–(e) printed any "verification has been disabled" message.
- **For a genuinely multi‑detector chunk: YES.** Overlap detection occurs in fixture (f), where two detectors of different types (`Postman` and the custom `CustomRegex`) match the same token. The chunk is routed to the overlap worker and the result is tagged with `errOverlap`.

**Evidence:** the routing gate is `if len(matchingDetectors) > 1 && !e.verificationOverlap` (`pkg/engine/engine.go:796`); `matchingDetectors` comes from `AhoCorasickCore.FindDetectorMatches` (`pkg/engine/ahocorasick/ahocorasickcore.go:241`, called at `engine.go:795`). For (a)–(e), `len(matchingDetectors)` is 1 → the branch is skipped → no overlap (observed: no "Verification issue" line, §4). For (f), the overlap worker (`engine.go:924`) runs `likelyDuplicate` (`engine.go:887-922`) and, on a match, calls `res.SetVerificationError(errOverlap)` (`engine.go:988`); `errOverlap`'s exact text is at `engine.go:39-42`. Observed in §4(f): `Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.` and JSON `"VerificationError":"More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag."`. The two detectors' distinct types are visible as `"DetectorType":118` (Postman) and `"DetectorType":904` (CustomRegex).

**Reasoning:** Overlap is fundamentally a *multiple‑detector* phenomenon. It needs `len(matchingDetectors) > 1` on a single decoded chunk, and `likelyDuplicate` further requires the two matches to come from **different detector types** and to be string‑similar above `similarityThreshold = 0.9` (`engine.go:888,900-914`) — with an exact string match short‑circuiting to `true` (`engine.go:904-909`). A single AWS key can never satisfy `> 1`, hence the honest negative result for (a)–(e).

### Q4 — How deduplication affects the final result count

**Direct answer:** Deduplication can collapse **multiple decoder‑path matches of the same secret at the same source location into a single emitted result**. It fires only when a later result has the *same* dedupe key as an earlier one but a *different* decoder type. Concretely: fixture (d) produces two matches (`PLAIN` + `BASE64`) but emits **1**; fixture (c) — the same secret reached via the same two decoders but at *different* lines — emits **2**. Dedup does **not** merge results that differ in `DetectorType` or in `SourceMetadata`.

**Evidence:** the dedupe key is built in `notifierWorker` at `pkg/engine/engine.go:1216`:
```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```
The key is composed of `DetectorType + Raw + RawV2 + SourceMetadata` — it **excludes** the decoder type and **includes** the source metadata; the cache is `dedupeCache *lru.Cache[string, detectorspb.DecoderType]` (`engine.go:207-209`). A second result with the same key but a different `DecoderType` hits `val != result.DecoderType` and is skipped via `continue` (`engine.go:1217-1220`). Observed effect (§4, §6): (d) 2 → **1**; (c) 2 → **2**.

The three fixtures triangulate the exact key composition:
- (d): identical `DetectorType`(AWS)+`Raw`+`RawV2`+file+line, only `DecoderType` differs → **collapsed** ⇒ decoder type is *excluded* from the key (and different‑decoder/same‑key is the skip trigger).
- (c): identical everything except the `line` in `SourceMetadata` → **kept** (2) ⇒ `SourceMetadata` is *included* in the key.
- (f): identical `Raw`+file+line, but different `DetectorType` (Postman vs CustomRegex) → **kept** (2) ⇒ `DetectorType` is *included* in the key.

**Reasoning:** The dedup deliberately suppresses "the same secret found again only because a different decoder re‑surfaced it at the same place," while preserving genuinely distinct findings (different location, or different detector). The code comment at `engine.go:1210-1215` states this intent: avoid duplicate results with different decoder types, but keep same‑decoder‑type duplicates.

### Q5 — Whether deduplication happens before or after overlap detection

**Direct answer:** **Deduplication happens AFTER overlap detection.** Overlap detection is a *pre‑detection routing* decision made in `scannerWorker`, before any detector's results exist; deduplication is a *post‑detection* step performed in `notifierWorker` as results are emitted.

**Evidence:** overlap routing occurs at `pkg/engine/engine.go:796` inside `scannerWorker` (`engine.go:777-841`) — i.e., immediately after decoding and the keyword prefilter, *before* detectors run. Deduplication occurs at `engine.go:1216-1221` inside `notifierWorker` (`engine.go:1189-1235`), which consumes results *after* detection and verification. The pipeline order is corroborated by `docs/concurrency.md`: `ScannerWorkers` route multi‑detector chunks to `VerificationOverlapWorkers` before `DetectorWorkers` run, and `NotifierWorkers` emit last. Runtime corroboration: in fixture (f) the overlap error is attached to a result that is still delivered to the notifier and emitted (§4(f)) — the notifier's dedup runs on results that already carry (or don't carry) the overlap verdict.

**Reasoning:** The two mechanisms operate at different pipeline stages on different inputs. Overlap looks at *how many detectors* match one decoded chunk (a property known before detection); dedup looks at *the emitted results' identities* (known only after detection). They are independent: overlap disables verification but does not deduplicate (f stays at 2 results), and dedup collapses decoder‑path duplicates but has nothing to do with multi‑detector overlap (d collapses with only the single AWS detector involved).

### Q6 — Why the same logical secret sometimes produces one result and sometimes multiple

**Direct answer:** Because **file layout controls the dedupe key**, and to a lesser extent because concurrency controls *which* decoder wins a collapse. Two things vary with how the file is structured:
1. **Whether the plaintext and Base64 occurrences resolve to the same `SourceMetadata` (line).** If they do (plaintext appears before the blob, so the Base64‑decoded chunk still shows the plaintext key first at the same line) → same dedupe key, different decoder type → **collapse to 1** (fixture d). If they don't (blob before plaintext, or separate files/lines) → different keys → **2 results** (fixture c).
2. **Whether any single decoded chunk trips ≥ 2 detectors.** A lone AWS key never does (1 result or 2, per point 1). Add a second detector matching the same token and the chunk is routed to the overlap path → **overlap error** (fixture f).

On top of that, in the collapse case the **surviving decoder type is nondeterministic** — `PLAIN` 22/30 vs `BASE64` 8/30 in §5.1 — because the notifier keeps whichever result arrives first and, with the notifier pool sized at `concurrency` = 128 workers (`engine.go:706`; `concurrency` defaults to `runtime.NumCPU()` = 128, `main.go:58`), the arrival order varies run to run.

**Evidence:** the layout‑to‑outcome mapping is observed directly: (c) and (d) are the *same two lines reordered* yet emit 2 vs 1 (§4). The dedupe key that makes layout decisive is `engine.go:1216` (includes `SourceMetadata`, excludes decoder type). The survivor variance is the §5.1 distribution. The overlap branch is `engine.go:796`. The Base64 in‑place decode that leaves the plaintext key in the chunk (so the recovered key's *first* occurrence — and thus the reported line — depends on ordering) is `pkg/decoders/base64.go:34-49`.

**Reasoning:** The user's "sometimes X, sometimes Y" was three *different files* (three layouts), each of which is individually near‑deterministic in its **count** but selects a different branch: 2‑results (blob/plaintext on different lines), 1‑result (they collide on the same line), or overlap error (a second detector is involved). Within the 1‑result layout, the *reported decoder type* additionally flips between runs due to concurrency. That is the complete cause of the observed inconsistency.


---

## 7.1 The mechanism as a flow (grounded in the cited lines)

```mermaid
flowchart TD
    A[file chunk] --> B[scannerWorker<br/>engine.go:777-841]
    B --> C{apply each decoder<br/>UTF8, Base64, UTF16, EscapedUnicode<br/>decoders.go:8-16}
    C --> D[FindDetectorMatches<br/>ahocorasickcore.go:241]
    D --> E{len matchingDetectors > 1<br/>and NOT allow-overlap?<br/>engine.go:796}
    E -->|yes: multi-detector = fixture f| F[verificationOverlapWorker<br/>engine.go:924]
    F --> G{likelyDuplicate?<br/>diff type AND similarity>0.9<br/>engine.go:887-922}
    G -->|yes| H[SetVerificationError errOverlap<br/>engine.go:988,39-42<br/>count NOT reduced]
    E -->|no: single AWS detector = a..e| I[detectorWorker / detectChunk<br/>engine.go:1036]
    H --> J[notifierWorker<br/>engine.go:1189-1235]
    I --> J
    J --> K{same key seen with<br/>different DecoderType?<br/>key=DetectorType+Raw+RawV2+SourceMetadata<br/>engine.go:1216-1220}
    K -->|yes = fixture d| L[skip via continue<br/>collapse to 1 result]
    K -->|no = fixtures a,b,c,e,f| M[emit result<br/>plain.go:64 / json.go:65]
```

Overlap is the pre‑detection branch at `E`; dedup is the post‑detection branch at `K`. `E` happens before `K` — hence "dedup after overlap" (Q5).

---

## 8. Version‑model caveat (this commit)

At commit `e42153d4`, the decoder model is **single‑pass over exactly four fixed decoders**: `DefaultDecoders()` returns `{UTF8, Base64, UTF16, EscapedUnicode}` and `scannerWorker` applies each once to the original chunk with no feedback loop (`pkg/decoders/decoders.go:8-16`, `pkg/engine/engine.go:777-841`). There is **no iterative/recursive decoding**, **no `--max-decode-depth` flag**, and **no HTML decoder** at this commit — those appear in some third‑party write‑ups of *newer* TruffleHog releases and are mentioned here only for contrast; none of the behavior in this document depends on or should be attributed to them. Everything above is therefore explained by the four‑decoder single‑pass chain plus the notifier's dedup and the pre‑detection overlap routing.

---

## 9. Coverage pass

| Named item from the question | Addressed | Concrete evidence |
|---|---|---|
| Plain text | ✓ | fixture (a) → `Decoder Type: PLAIN` (§4a); Q1/Q2 |
| Base64 | ✓ | fixture (b) → `Decoder Type: BASE64` (§4b); `base64.go:34-49`; Q1/Q2 |
| Escaped Unicode | ✓ | fixture (e) → `Decoder Type: ESCAPED_UNICODE` (§4e); `escaped_unicode.go:28-29`; Q1/Q2 |
| Decoder type `PLAIN` | ✓ | observed (a,c,d); enum `detectors.pb.go:27` |
| Decoder type `BASE64` | ✓ | observed (b,c); enum `detectors.pb.go:28` |
| Decoder type `UTF16` | ✓ | defined `utf16.go:14-15` / enum `detectors.pb.go:29`; not produced (no UTF‑16 input) — stated honestly (Q2) |
| Decoder type `ESCAPED_UNICODE` | ✓ | observed (e); enum `detectors.pb.go:30` |
| Overlap detection occurs? | ✓ | negative for lone AWS key (a–e); positive for (f) with errOverlap (§4f); `engine.go:796` (Q3) |
| Deduplication + effect on count | ✓ | (d) 2→1 vs (c) 2→2; key `engine.go:1216` (Q4, §6) |
| Dedup before or after overlap | ✓ | AFTER — `scannerWorker` L796 vs `notifierWorker` L1216 (Q5, §7.1) |
| Why sometimes 1, sometimes multiple | ✓ | layout controls the dedupe key; concurrency controls the survivor (Q6, §5.1) |
| Run‑to‑run inconsistency reproduced (not stabilized) | ✓ | 30‑run (d) distribution PLAIN 22 / BASE64 8; 12‑run (f) toggle (§5) |
| `--allow-verification-overlap` toggle | ✓ | errOverlap 12/12 without, 0/12 with (§5.3) |
| Real entry point / canonical build | ✓ | `trufflehog filesystem` (`main.go:143`); build + `trufflehog dev` banner (§2) |
| Complete unedited output | ✓ | §4 (plain incl. banner + JSON) for every fixture |

---

## 10. Cleanup note (read‑only guarantee)

All investigation artifacts (the built binary, the six fixtures, the custom detector YAML, and the observation scripts) were created **outside** the repository tree (in the container's `/tmp/th_investigation/` and a read‑only mount of the repo) and were removed after capture. The repository working tree is unchanged except for this one document.

Verification from the repository root:

```text
$ git status --porcelain
?? blitzy/documentation/trufflehog_e42153d44a5e.md
```

(The `git status` confirmation is captured at completion of the investigation; the only change is the addition of this file. See the commit for this document.)

