# TruffleHog: Decoder Pipeline, Overlap Detection & Deduplication — Investigation

> **Scope note.** This is a **read-only, explain-only** investigation. No source, test, configuration, or build file was modified; the only file this investigation writes is **this document** (under `blitzy/`). The read-only guarantee is proven durably in §10: the tree is identical to the pinned source commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (dated 2025-05-05) except for this `blitzy/` document.
>
> **What "observed" means here.** A claim is **observed** only when it is a value the program *emitted* and I captured verbatim: result **counts**, `DecoderName` strings, `line` numbers, `VerificationError` text, log lines, and process **exit statuses**. Everything that reasons about *why* the program produced those values from its internal structure — the dedupe-vs-overlap **ordering** (§6.5), the **cause** of the surviving-decoder race and why it persists at `--concurrency=1` (§5.5/§6.6/F9), and which result **carries** the overlap annotation (§5.10) — is grounded in `file:line` source and labeled **(inferred / source-derived)**. Every console block below is **complete and unedited** and shows **both stdout and stderr** (volatile values — timestamps, `scan_duration`, per-run worker IDs — are shown exactly as observed). All investigation artifacts (the built binary, crafted inputs, copied fixtures, scripts) lived **outside** the repository tree under `/tmp` and were removed on completion (§10).

---

## §1 The question (verbatim)

> I was scanning a file containing both a raw AWS access key and the same key as Base64-encoded, and I got confused by the output. Sometimes TruffleHog reported the secret twice with different decoder types, sometimes it reported an overlap error, and sometime it deduplicated down to a single result. The behaviour seemed inconsistent depending on how I structured the test file. I want to understand how the decoder pipeline, overlap detection, and result deduplication interact at runtime to produce these varying outputs. Verify how TruffleHog's decoder pipeline handles the same secret in multiple encoded forms (plain text, base64, escaped unicode) by observing which decoder types are reported, whether overlap detection occurs, how deduplication affects the final result count, whether the deduplication happens before or after overlap detection, and why the same logical secret sometimes produces one result and sometimes produces multiple. Do not modify any existing source files in the repository, and remove any test data created during the investigation.

---

## §2 TL;DR — direct answers to the six named items

- **Q1 — Multi-encoding handling.** The pipeline runs an **ordered, single-pass** decoder chain `[UTF8, Base64, UTF16, EscapedUnicode]` over each chunk [`pkg/decoders/decoders.go:8-16`]. UTF8 always yields a `PLAIN` view; `Base64` **rebuilds the chunk data in place**, substituting decoded bytes where the encoded run was [`pkg/decoders/base64.go:67`]; `EscapedUnicode` **clones** the chunk and returns a new one [`pkg/decoders/escaped_unicode.go:39`]. Because the Base64 pass leaves the surrounding plaintext intact, a file holding both the raw key and its Base64 form is matched **twice** (once as `PLAIN`, once as `BASE64`). A decoder's output is **not re-fed** through the chain (single pass).
- **Q2 — Reported decoder types.** The enum is `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4` [`proto/detectors.proto:7-13`]. Observed: raw plaintext → **`PLAIN`** (Case C), Base64 → **`BASE64`** (Case B), escaped-Unicode → **`ESCAPED_UNICODE`** (Case E). `UTF16` is the fourth type but the ASCII inputs do not exercise it; `UNKNOWN=0` is the zero value, never produced by a successful decode.
- **Q3 — Overlap detection.** It occurs **only when two or more *different* detectors match the same chunk** and `--allow-verification-overlap` is off [`pkg/engine/engine.go:796`]. It **never fired for the lone AWS key** — grep count `0` across **all eight** single-key cases A–H (§5.10). Driving a two-detector config reproduces it: the offending result carries the verification error `errOverlap` [`pkg/engine/engine.go:39`, set at `:988`].
- **Q4 — Deduplication effect.** A 512-entry LRU in `notifierWorker` collapses **same-key / different-decoder** repeats [`pkg/engine/engine.go:1216-1221`]. The key is `DetectorType + Raw + RawV2 + SourceMetadata` (it **includes the computed line number** and **excludes** the decoder type). Equal computed lines → one result; different computed lines → both survive. It does **not** change the count of the overlap case (that is a separate annotation).
- **Q5 — Ordering.** **Deduplication happens *after* overlap detection.** Overlap routing/annotation is a Stage-3 pass in `scannerWorker`/`verificationOverlapWorker`; the LRU dedupe is a later Stage-4 pass in `notifierWorker` consuming `e.results` [`pkg/engine/engine.go:1186` → `:1190`]. **(inferred / source-derived** from the channel producer→consumer stage order; consistent with every observation and the `docs/concurrency.md` worker order.**)**
- **Q6 — One-vs-many variability.** The dedupe key includes the **computed line number** but **not** the decoder type, so collapse-vs-survive depends on whether the two encodings resolve to the **same computed first-occurrence line** — which is **not** the same as their physical placement. Because `Base64` rebuilds the chunk *in place* keeping the surrounding plaintext, within one chunk the `PLAIN` and `BASE64` views both report the **plaintext's** line (the first `Raw` occurrence). So raw-then-Base64 layouts (Cases A, G, H) **collapse to 1** and *which decoder type survives is a genuine race*; a Base64-**before**-plaintext layout (Case D) keeps two distinct lines and **survives as 2**; and encodings split across **different chunks** (Case F) get distinct lines and survive (**3** results). The surviving-decoder race **persists even at `--concurrency=1`** (§5.5, §6.6, F9).

---

## §3 Environment & canonical build

**Provenance (read-only proof).** The working tree is at the Blitzy branch whose only difference from the pinned source commit is this `blitzy/` document; there is **no tracked source diff**.

```console
$ git rev-parse --abbrev-ref HEAD
blitzy-d46ccd01-34ea-4c14-ab97-a0973ab3aa05
$ git merge-base --is-ancestor e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD ; echo ancestor_exit=$?
ancestor_exit=0
$ git diff --stat e42153d44a5e5c37c1bd0c70e074781e9edcb760 -- ':(exclude)blitzy/'
$ git diff --name-only e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD
blitzy/documentation/trufflehog_e42153d44a5e.md
```

> The empty `git diff --stat … -- ':(exclude)blitzy/'` proves no source/test/config/build file differs from the pinned commit `e42153d44a5e…`; the only path that differs is this document. The deliverable filename `trufflehog_e42153d44a5e.md` is the **source branch name** (`trufflehog_e42153d44a5e`).

**Toolchain & canonical build** (mirrors `Dockerfile:5-9`, where `ENV CGO_ENABLED=0` and `go build -o trufflehog .`). `go.mod` declares `go 1.23.1` [`go.mod:3`] and `toolchain go1.24.2` [`go.mod:5`]; the local build injects no release ldflags, so `BuildVersion = "dev"` [`pkg/version/version.go:3`]. Note `--version` prints to **stderr**:

```console
$ go version
go version go1.24.2 linux/amd64
$ CGO_ENABLED=0 go build -o /tmp/th/trufflehog . ; echo build_exit=$?
build_exit=0
$ /tmp/th/trufflehog --version           # stdout empty; banner is on stderr
$ /tmp/th/trufflehog --version 2>&1 1>/dev/null
trufflehog dev
```

**Runtime scan-log identity line** (stderr) — confirms the running binary is the canonical `dev` build:

```console
$ printf 'nothing to see here\n' > /tmp/th_investigation/ident.txt
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/ident.txt --no-update --json 2>&1 >/dev/null | grep '"msg":"finished scanning"'
{"level":"info-0","ts":"2026-07-13T19:38:35Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":20,"verified_secrets":0,"unverified_secrets":0,"scan_duration":"4.137788ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### §3.1 The test key (public, non-live)

All inputs are built from **one logical AWS key** — a deliberately **public, non-live** pair (a canarytokens.org canary ID + AWS's public documentation example secret), so no real credential is ever handled:

- `ID = AKIASP2TPHJSQH3FJRUX` — matches `idPat` `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` [`pkg/detectors/aws/access_keys/accesskey.go:65`]. The detector reports `is_canary:"true"` and `account:"171436882533"` (`s1.ExtraData["is_canary"] = "true"` [`accesskey.go:181`]).
- `SEC = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — matches the 40-char secret capture `([A-Za-z0-9+/]{40})` in `SecretPat` [`pkg/detectors/aws/common.go:10`].
- Both clear the entropy floors `RequiredIdEntropy = 3.0`, `RequiredSecretEntropy = 4.25` [`pkg/detectors/aws/common.go:6-7`]. `SEC` is not lowercase-hex, so it escapes the false-positive filter `FalsePositiveSecretPat = [a-f0-9]{40}` [`pkg/detectors/aws/utils.go:47`].

```console
$ python3 -c "
import math
from collections import Counter
def shannon(s):
    c=Counter(s); n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
print('ID  entropy=%.6f' % shannon('AKIASP2TPHJSQH3FJRUX'))
print('SEC entropy=%.6f' % shannon('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'))
"
ID  entropy=3.821928
SEC entropy=4.662815
```

The Base64 form used throughout is the Base64 of the string `"<ID> <SEC>"`:

```console
$ printf '%s %s' 'AKIASP2TPHJSQH3FJRUX' 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | base64 -w0
QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==
```

### §3.2 The canonical invocation

Every scan below goes through the real `filesystem` CLI entry point [`main.go:143`]:

```text
/tmp/th/trufflehog filesystem <path> --results=verified,unknown,unverified --no-verification --no-update --json
```

The flags are **explicit opt-ins**, not defaults: `--no-verification` is a boolean flag that defaults *off* [`main.go:59`] — enabled here so the run needs no network and no live credential; `--no-update` is a boolean flag [`main.go:73`]; `--allow-verification-overlap` is a boolean flag used only for the §5.10 contrast [`main.go:65`]. Only `--results` has a built-in default (`verified,unverified,unknown`) [`main.go:61`]; it is set explicitly here for clarity. **JSON results go to stdout** (one object per line); **all logs go to stderr**. In the JSON, `"DetectorType":2` = AWS [`proto/detectors.proto:18` (`AWS = 2`)], `"SourceType":15` = filesystem [`proto/sources.proto:30` (`SOURCE_TYPE_FILESYSTEM = 15`)], and the decoder appears as `"DecoderName"` = `r.DecoderType.String()` [`pkg/output/json.go:65`].

---

## §4 The runtime pipeline

The engine runs a concurrent worker pool. The worker types are created in the order `ScannerWorkers → VerificationOverlapWorkers → DetectorWorkers → NotifierWorkers` [`docs/concurrency.md:10-21`], and the chunk/result **data flow** between them is `Scanner → (Detector | VerificationOverlap) → Detector → Notifier` over dedicated channels [`docs/concurrency.md:28-37`]. The decoder loop and the overlap gate live inside `scannerWorker`.

```mermaid
flowchart TD
    A["Chunk from filesystem source"] --> B["scannerWorker: decode loop<br/>for _, decoder := range e.decoders<br/>engine.go:784"]
    B --> C{"decoder.FromChunk(chunk)<br/>UTF8 &rarr; Base64 &rarr; UTF16 &rarr; EscapedUnicode"}
    C -->|nil: decoder N/A| C
    C -->|non-nil| D["AhoCorasickCore.FindDetectorMatches<br/>engine.go:795"]
    D --> E{"len(matchingDetectors) &gt; 1<br/>&amp;&amp; !e.verificationOverlap ?<br/>engine.go:796"}
    E -->|yes| F["verificationOverlapChunksChan<br/>&rarr; verificationOverlapWorker<br/>engine.go:924-1034"]
    E -->|no| G["detectableChunksChan<br/>&rarr; detectorWorker/detectChunk<br/>engine.go:1044"]
    F --> H["likelyDuplicate (Levenshtein &gt; 0.9)<br/>engine.go:887 &rarr; SetVerificationError(errOverlap)<br/>engine.go:988"]
    H --> I["processResult: stamp DecoderType &amp; line<br/>secret.DecoderType = data.decoder<br/>engine.go:1178; e.results &lt;- secret :1186"]
    G --> I
    I --> J["notifierWorker: LRU dedupeCache<br/>engine.go:1189-1235"]
    J --> K{"key cached AND<br/>cached decoder != this decoder?<br/>engine.go:1217"}
    K -->|yes| L["skip duplicate (continue)"]
    K -->|no| M["Add(key, DecoderType) &amp; emit<br/>engine.go:1221"]
```

**Stage → worker/function → `file:line` map:**

| # | Stage | Worker / function | `file:line` |
|---|-------|-------------------|-------------|
| 1 | Decode loop over the fixed chain | `scannerWorker`, `for _, decoder := range e.decoders` | `pkg/engine/engine.go:784` |
| 2 | Keyword pre-filter (which detectors match) | `AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` | `pkg/engine/engine.go:795` |
| 3 | **Overlap gate** | `if len(matchingDetectors) > 1 && !e.verificationOverlap` → `verificationOverlapChunksChan` | `pkg/engine/engine.go:796` |
| 3a | Overlap verification-suppression | `verificationOverlapWorker` + `likelyDuplicate` (Levenshtein `> 0.9`) → `res.SetVerificationError(errOverlap)` | `pkg/engine/engine.go:924-1034`, `:887-923`, `:988` |
| 4 | Detector run (lone/`≤1` detector path) | `detectableChunksChan` → `detectChunk` | `pkg/engine/engine.go:1044` |
| 5 | Decoder-type + line stamp | **`processResult`**: `secret.DecoderType = data.decoder`; `SetResultLineNumber` | `pkg/engine/engine.go:1178`, `:1166` |
| 6 | **LRU deduplication** | `notifierWorker`, `dedupeCache *lru.Cache[string, detectorspb.DecoderType]` (size 512) | `pkg/engine/engine.go:1189-1235`, `:209`, `:491` |
| 7 | Print | `json.go` / `plain.go` | `pkg/output/json.go:65`, `pkg/output/plain.go:63-64` (types), `:100-102` (File/Line via the aggregate-metadata loop) |

The engine's own docs describe Stage 3 as choosing "which detector will verify" so as not to "duplicate verification requests" — the **De-Dupe-Detectors** stage [`docs/process_flow.md:106-108`]. This Stage-3 detector-overlap logic is distinct from the Stage-6 **result** dedupe (§7).

---

## §5 Reproduction cases (complete, unedited output)

All cases were driven through the canonical invocation (§3.2). Eight single-key layouts (A–H) plus a two-detector overlap fixture were exercised. Summary of what was observed:

| Case | File structure | Total results | Observed decoder(s) + computed line(s) | Stable? |
|------|----------------|:-------------:|-------------------------------|---------|
| B | Base64 only (1 line) | 1 | `BASE64` @ line 1 | Yes (3/3) |
| C | Plaintext only (1 line) | 1 | `PLAIN` @ line 1 | Yes (3/3) |
| E | Escaped-Unicode only (1 line) | 1 | `ESCAPED_UNICODE` @ line 1 | Yes (3/3) |
| D | Base64 (L1) + plaintext (L2) | 2 | `{BASE64@1, PLAIN@2}` | Yes (set+count 3/3; print order varies) |
| A | Plaintext (L1) + Base64 (L2), adjacent | 1 | `PLAIN` **or** `BASE64` @ line 1 | Count yes (always 1); **decoder = race** |
| G | Plaintext + Base64 on the **same physical line** | 1 | `PLAIN` **or** `BASE64` @ line 1 | Count yes (always 1); **decoder = race** |
| H | Plaintext (L1) + 8 filler lines + Base64 (L10), **one chunk** | 1 | `PLAIN` **or** `BASE64` @ line 1 | Count yes (always 1); **decoder = race** |
| F | Plaintext (L1) + 600 filler + Base64 (L602), **multi-chunk** | 3 | `{PLAIN@1, BASE64@9, BASE64@157}` | Yes (set+count 3/3; print order varies) |
| Overlap | 2-detector config on Postman key | 3 | Postman(118) + 2×CustomRegex(904) | Count yes (always 3); **errOverlap carrier = race** |

Each primary transcript shows **stdout followed by the two stderr log lines** (`running source`, `finished scanning`). The `finished scanning` line's `chunks`/`bytes` are informative (e.g. Case F `chunks:5` proves multi-chunk; Case H `chunks:1` proves single-chunk).

### §5.1 Case B — Base64 only → `BASE64`

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseB.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseB.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:02Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"rsY0F","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:02Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":62,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"4.435363ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

One result, `DecoderName:"BASE64"`, `line:1`. The `Base64` decoder found the 84-char encoded run (> the 20-char threshold in `getSubstringsOfCharacterSet(chunk.Data, 20, ...)` [`pkg/decoders/base64.go:36`]), decoded it to ASCII, and rebuilt the chunk in place [`base64.go:67`]; the AWS detector then matched on the decoded bytes.

### §5.2 Case C — plaintext only → `PLAIN`

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseC.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseC.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:04Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"eXd7d","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:04Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":62,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.036804ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

One result, `DecoderName:"PLAIN"`, `line:1`. `UTF8.FromChunk` returns a `PLAIN` view for any non-empty data [`pkg/decoders/utf8.go:16-29`]; the raw key matched directly.

### §5.3 Case E — escaped-Unicode only → `ESCAPED_UNICODE`

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseE.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseE.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"ESCAPED_UNICODE","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:06Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"p8mBv","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:06Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":367,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.787513ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

One result, `DecoderName:"ESCAPED_UNICODE"`, `line:1`. The literal `\uXXXX` form contains no plaintext `AKIA…`; only `EscapedUnicode.FromChunk` (matching `escapePat` `(?i:\\{1,2}u)([a-fA-F0-9]{4})` [`pkg/decoders/escaped_unicode.go:25`]) reconstructs the key, on a **cloned** chunk [`escaped_unicode.go:39`].

### §5.4 Case D — Base64 (L1) + plaintext (L2) → **2** results `{BASE64@1, PLAIN@2}`

Three consecutive JSON runs (stability); the **set** `{BASE64@1, PLAIN@2}` and **count 2** are stable (print order may vary run-to-run because the results are produced by concurrent workers):

```console
$ for i in 1 2 3; do /tmp/th/trufflehog filesystem /tmp/th_investigation/caseD.txt --results=verified,unknown,unverified --no-verification --no-update --json; done
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

The two objects are identical except for `DecoderName` (`BASE64` vs `PLAIN`) and the metadata `line` (1 vs 2). Plain-mode output (drop `--json`) shows the same and also reveals the **stderr banner**. Note plain-mode prints `Detector Type:` / `Decoder Type:` [`pkg/output/plain.go:63-64`], while `File:` / `Line:` come from the aggregate-metadata loop [`pkg/output/plain.go:100-102`]:

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseD.txt --results=verified,unknown,unverified --no-verification --no-update
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIASP2TPHJSQH3FJRUX
Is_canary: true
Resource_type: Access key
Account: 171436882533
Message: This is an AWS canary token generated at canarytokens.org.
File: /tmp/th_investigation/caseD.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIASP2TPHJSQH3FJRUX
Resource_type: Access key
Account: 171436882533
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/th_investigation/caseD.txt
Line: 2
```
```console
# stderr for the plain-mode run above (banner on stderr, then TAB-separated logs):
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T19:30:03Z	info-0	trufflehog	running source	{"source_manager_worker_id": "5lsRO", "with_units": true}
2026-07-13T19:30:03Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 124, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "6.144409ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

> **Log-format note.** In `--json` mode the stderr logs are **JSON objects** (`{"level":"info-0",…}`); in plain mode they are **tab-separated** lines preceded by the banner emitted at [`main.go:498`] (inside `if !*jsonLegacy && !*jsonOut`). The banner is the reason JSON results (stdout) stay clean when logs (stderr) are also shown.

### §5.5 Case A — plaintext (L1) + Base64 (L2), adjacent → always **1** result; surviving decoder is a **race**

This is the user's "deduplicated to a single result" scenario. Representative single run (**note `line:1`** even though the Base64 form is physically on line 2):

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseA.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseA.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:00Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"cEAOy","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:00Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":124,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.029841ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Why `line:1`.** After the Base64 pass rebuilds the chunk in place, the decoded key's *first* occurrence is the line-1 plaintext, so `FragmentLineOffset` (which cuts at the **first** `Raw` match [`pkg/engine/engine.go:1257`]) reports line 1 for **both** the `PLAIN` and the `BASE64` view. Both results therefore carry an **identical** dedupe key, and one is dropped.

**Race tally at default concurrency, N = 100 runs** (via the strict `race_tally.sh`, §12.2; `1` asserts the count-invariant, aborting on any run ≠ 1) — the result count is always 1, but the surviving decoder flips:

```console
$ bash /tmp/th_investigation/race_tally.sh A 100 1
--- result-count distribution (count : #runs) over N=100 ---
  count=1 : 100 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=100 ---
  BASE64 : 79
  PLAIN : 21
```

**Race tally at `--concurrency=1`, N = 50 runs:**

```console
$ bash /tmp/th_investigation/race_tally.sh A 50 1 -- --concurrency=1
--- result-count distribution (count : #runs) over N=50 ---
  count=1 : 50 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=50 ---
  BASE64 : 15
  PLAIN : 35
```

> **Why the race persists at `--concurrency=1` (source-derived).** A natural hypothesis is that `--concurrency=1` serializes the pipeline so PLAIN (UTF8 is first in the chain) always wins. **The runtime observation refutes that** — both `BASE64` (15) and `PLAIN` (35) still appear; the flag only **shifts the ratio** toward PLAIN. The mechanism is in the worker-pool sizing: `--concurrency=1` sets **1 scanner** worker [`pkg/engine/engine.go:664`] and **1 notifier** worker (`notificationWorkerMultiplier` defaults to 1) [`pkg/engine/engine.go:348-349`, `:706`], but the **detector** pool is `concurrency × detectorWorkerMultiplier` where `detectorWorkerMultiplier` **defaults to 8** [`pkg/engine/engine.go:343-345`], i.e. **8 detector workers even at `--concurrency=1`** [`pkg/engine/engine.go:676`, loop `:679-687`]. The single scanner emits **two** detectable chunks (the `PLAIN` view, then the `BASE64`-rebuilt view); those two chunks are picked up by **different** detector workers among the eight, which run the AWS detector independently and race to push onto the shared `e.results` channel feeding the one notifier. Whichever result `Add`s its key to the LRU first wins the slot; the later one is dropped as a "different decoder type" duplicate [`engine.go:1217`]. Thus the **invariant** is "always exactly 1 result; the surviving decoder type is non-deterministic," and `--concurrency=1` does not make it deterministic. (These exact ratios are point-in-time; re-running yields different splits, but the invariant holds. The count-invariant is machine-checked by `race_tally.sh`, which exits non-zero if any run's count ≠ 1.)

### §5.6 Case G — plaintext + Base64 on the **same physical line** → always **1** result; decoder race

This is the first of the two "same-chunk" layouts the question implies. `caseG.txt` is a **single physical line** holding `"<ID> <SEC> <B64>"`. Representative run (**one** result, `line:1`):

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseG.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseG.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:07Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"WcK8C","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:07Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":124,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.533019ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Both encodings are on line 1 (they are the same line), so the `PLAIN` and `BASE64` views share one dedupe key → collapse to 1, with the surviving decoder a race:

```console
$ bash /tmp/th_investigation/race_tally.sh G 100 1
--- result-count distribution (count : #runs) over N=100 ---
  count=1 : 100 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=100 ---
  BASE64 : 84
  PLAIN : 16
$ bash /tmp/th_investigation/race_tally.sh G 50 1 -- --concurrency=1
--- result-count distribution (count : #runs) over N=50 ---
  count=1 : 50 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=50 ---
  BASE64 : 17
  PLAIN : 33
```

### §5.7 Case H — plaintext (L1) + 8 filler lines + Base64 (L10), one chunk → always **1** result; decoder race

The second same-chunk layout: the two encodings are **separated by filler** but the whole file (699 bytes) is well under `ChunkSize = 10*1024` [`pkg/sources/chunker.go:14-18`], so it is **one chunk** (`chunks:1` below). The Base64 form sits on line 10, but the result still reports `line:1` — the collapse rule is about the **computed first-occurrence line**, not the physical location of the encoded run:

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseH.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseH.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation):
{"level":"info-0","ts":"2026-07-13T19:40:09Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"fm5uP","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:40:09Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":676,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"4.829034ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Because the Base64 pass keeps the surrounding plaintext, the rebuilt chunk contains `AKIA…` at **both** the line-1 plaintext position and the (later) decoded position; `bytes.Cut` finds the **earlier** one, so both views report line 1 → same key → collapse to 1, decoder a race:

```console
$ bash /tmp/th_investigation/race_tally.sh H 100 1
--- result-count distribution (count : #runs) over N=100 ---
  count=1 : 100 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=100 ---
  BASE64 : 73
  PLAIN : 27
$ bash /tmp/th_investigation/race_tally.sh H 50 1 -- --concurrency=1
--- result-count distribution (count : #runs) over N=50 ---
  count=1 : 50 runs
--- surviving-decoder distribution (decoder : #occurrences) over N=50 ---
  BASE64 : 37
  PLAIN : 13
```

> Cases A, G, and H are three physically-different raw-then-Base64 layouts (adjacent lines / same line / filler-separated) that **all collapse to a single result with a decoder race** — demonstrating that the collapse depends on the *computed* first-occurrence line (always line 1 here), not on how the encodings are physically arranged, as long as the plaintext precedes the Base64 form in a single chunk.

### §5.8 Case F — plaintext (L1) + 600 filler + Base64 (L602), multi-chunk → **3** stable results

`caseF.txt` is **41,547 bytes / 602 lines** (raw key on line 1, 600 filler lines, Base64 on the last line), exceeding `TotalChunkSize = 13312` [`pkg/sources/chunker.go:14-18`], so the file is split into **5 chunks** (`chunks:5` below). Three runs — the **set of 3** and the **count 3** are stable (print order varies):

```console
$ for i in 1 2 3; do /tmp/th/trufflehog filesystem /tmp/th_investigation/caseF.txt --results=verified,unknown,unverified --no-verification --no-update --json | python3 /tmp/th_investigation/th_parse.py; done
results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
```

Complete JSON for one run (the three objects: `PLAIN@1`, `BASE64@157`, `BASE64@9`):

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseF.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseF.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseF.txt","line":157}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseF.txt","line":9}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```
```console
# stderr (same invocation) — chunks:5 confirms multi-chunk:
{"level":"info-0","ts":"2026-07-13T19:29:41Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"Qb3kZ","with_units":true}
{"level":"info-0","ts":"2026-07-13T19:29:41Z","logger":"trufflehog","msg":"finished scanning","chunks":5,"bytes":51304,"verified_secrets":0,"unverified_secrets":3,"scan_duration":"14.284919ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Why 3, not 2 (source-derived).** The `PLAIN` view of the whole file yields one match — the raw key at line 1. The `BASE64` view yields **two** matches at **two different lines** (9 and 157). This happens because the chunker **overlaps consecutive chunks by `PeekSize = 3*1024`** bytes: after reading `chunkSize` bytes it appends a peek of the next `totalSize − n` bytes, so a Base64 run that straddles a chunk boundary appears **whole in two adjacent chunks** [`pkg/sources/chunker.go:14-18`, chunk assembly at `:121-126`]. Each of those two chunks is decoded and matched independently, producing two `BASE64` results whose computed first-occurrence lines differ (9 and 157). All three results have distinct `SourceMetadata` lines → three distinct dedupe keys → **all three survive**, stably across runs. This is the multi-chunk expression of the "different lines ⇒ both survive" rule (contrast Case D's 2).

### §5.9 Full stability sweep (all eight single-key cases)

The strict `stability_sweep.sh` (§12.2) runs each case 3× through the canonical CLI, aborting on any non-zero exit or unparseable JSON, and prints an order-independent parsed signature. It confirms B/C/E are single stable results, D is a stable 2-set, **A/G/H are always count-1 with a flipping decoder** (the race), and F is a stable 3-set:

```console
$ bash /tmp/th_investigation/stability_sweep.sh 3
=== Case B (caseB.txt) ===
  run 1: results=1 decoders=[BASE64] lines=[1]
  run 2: results=1 decoders=[BASE64] lines=[1]
  run 3: results=1 decoders=[BASE64] lines=[1]
=== Case C (caseC.txt) ===
  run 1: results=1 decoders=[PLAIN] lines=[1]
  run 2: results=1 decoders=[PLAIN] lines=[1]
  run 3: results=1 decoders=[PLAIN] lines=[1]
=== Case E (caseE.txt) ===
  run 1: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
  run 2: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
  run 3: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
=== Case D (caseD.txt) ===
  run 1: results=2 decoders=[BASE64,PLAIN] lines=[1,2]
  run 2: results=2 decoders=[BASE64,PLAIN] lines=[1,2]
  run 3: results=2 decoders=[BASE64,PLAIN] lines=[1,2]
=== Case A (caseA.txt) ===
  run 1: results=1 decoders=[PLAIN] lines=[1]
  run 2: results=1 decoders=[BASE64] lines=[1]
  run 3: results=1 decoders=[BASE64] lines=[1]
=== Case G (caseG.txt) ===
  run 1: results=1 decoders=[PLAIN] lines=[1]
  run 2: results=1 decoders=[BASE64] lines=[1]
  run 3: results=1 decoders=[BASE64] lines=[1]
=== Case H (caseH.txt) ===
  run 1: results=1 decoders=[PLAIN] lines=[1]
  run 2: results=1 decoders=[PLAIN] lines=[1]
  run 3: results=1 decoders=[BASE64] lines=[1]
=== Case F (caseF.txt) ===
  run 1: results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
  run 2: results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
  run 3: results=3 decoders=[BASE64,BASE64,PLAIN] lines=[1,9,157]
```

### §5.10 Overlap detection reproduction (two-detector config)

**Overlap is NOT triggered by the lone AWS key.** For **all eight** single-key cases A–H, the `errOverlap` text never appears (only one detector — AWS — matches, so the Stage-3 gate `len(matchingDetectors) > 1` is false). The strict `lone_aws_overlap_check.sh` (§12.2) searches **both** stdout and stderr and exits non-zero if any case shows an overlap annotation:

```console
$ bash /tmp/th_investigation/lone_aws_overlap_check.sh ; echo exit=$?
Case A: errOverlap_matches=0
Case B: errOverlap_matches=0
Case C: errOverlap_matches=0
Case D: errOverlap_matches=0
Case E: errOverlap_matches=0
Case G: errOverlap_matches=0
Case H: errOverlap_matches=0
Case F: errOverlap_matches=0
exit=0
```

**Overlap IS triggered by a multi-detector config.** Reusing the repository's own overlap fixture (copied read-only from `pkg/engine/testdata/`, the same fixture exercised by `TestVerificationOverlapChunk` [`pkg/engine/engine_test.go:503`]) — `detector1` (keyword `PMAK`) and `detector2` (keyword `ost`) — the Postman key `PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r` matches the built-in **Postman** detector (`DetectorType:118`) plus both custom detectors (`DetectorType:904`), i.e. **≥2 different detectors on one chunk**:

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/vo_secrets.txt --config /tmp/th_investigation/vo_detectors.yaml --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/vo_secrets.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":118,"DetectorName":"Postman","DetectorDescription":"Postman is a collaboration platform for API development. Postman API keys can be used to access and modify collections, environments, and other resources.","DecoderName":"PLAIN","Verified":false,"VerificationError":"More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.","VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/vo_secrets.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"This is a user-defined detector with no description provided.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":{"name":"detector1"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/vo_secrets.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":904,"DetectorName":"CustomRegex","DetectorDescription":"This is a user-defined detector with no description provided.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r","RawV2":"","Redacted":"","ExtraData":{"name":"detector2"},"StructuredData":null}
```

**All 3 results are still emitted** — overlap is a **verification annotation**, not a count reduction. In this run exactly one result (Postman) carries `"VerificationError":"More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag."` — the exact text of `errOverlap` [`pkg/engine/engine.go:39`] (note there is **no space** between "disabled." and "You", because the message is two concatenated string literals at `:40-41`). The plain printer surfaces it as the `Verification issue:` line [`pkg/output/plain.go:57`]:

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/vo_secrets.txt --config /tmp/th_investigation/vo_detectors.yaml --results=verified,unknown,unverified --no-verification --no-update
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: /tmp/th_investigation/vo_secrets.txt
Line: 2

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: detector1
File: /tmp/th_investigation/vo_secrets.txt
Line: 2

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: detector2
File: /tmp/th_investigation/vo_secrets.txt
Line: 2
```

**Which / how many results carry the annotation is itself a race** (source-derived: `likelyDuplicate` runs across concurrently-arriving cross-detector candidates). N = 20 runs; the total is always 3, but the number of results carrying `errOverlap` flips between 1 and 2:

```console
$ bash /tmp/th_investigation/overlap_tally.sh 20
run 1: total_results=3 errOverlap_count=1
run 2: total_results=3 errOverlap_count=1
run 3: total_results=3 errOverlap_count=1
run 4: total_results=3 errOverlap_count=2
run 5: total_results=3 errOverlap_count=1
run 6: total_results=3 errOverlap_count=1
run 7: total_results=3 errOverlap_count=1
run 8: total_results=3 errOverlap_count=1
run 9: total_results=3 errOverlap_count=1
run 10: total_results=3 errOverlap_count=1
run 11: total_results=3 errOverlap_count=2
run 12: total_results=3 errOverlap_count=1
run 13: total_results=3 errOverlap_count=2
run 14: total_results=3 errOverlap_count=1
run 15: total_results=3 errOverlap_count=1
run 16: total_results=3 errOverlap_count=1
run 17: total_results=3 errOverlap_count=2
run 18: total_results=3 errOverlap_count=1
run 19: total_results=3 errOverlap_count=1
run 20: total_results=3 errOverlap_count=1
--- distribution over 20 runs (total_results errOverlap_count : #runs) ---
  16 run(s): total_results=3 errOverlap_count=1
  4 run(s): total_results=3 errOverlap_count=2
```

**`--allow-verification-overlap` contrast** [`main.go:65`, documented `README.md:433`] — still 3 results, but **0** `errOverlap` annotations every run (N = 5):

```console
$ bash /tmp/th_investigation/overlap_tally.sh 5 -- --allow-verification-overlap
run 1: total_results=3 errOverlap_count=0
run 2: total_results=3 errOverlap_count=0
run 3: total_results=3 errOverlap_count=0
run 4: total_results=3 errOverlap_count=0
run 5: total_results=3 errOverlap_count=0
--- distribution over 5 runs (total_results errOverlap_count : #runs) ---
  5 run(s): total_results=3 errOverlap_count=0
```

---

## §6 Per-question answers (by name)

### §6.1 Q1 — Multi-encoding handling

**Direct answer:** the same secret is handled by running an **ordered, single-pass** chain of decoders over each chunk; the plaintext copy is surfaced by `UTF8`, the Base64 copy by `Base64` (which **rebuilds the chunk in place**), and the escaped-Unicode copy by `EscapedUnicode` (which **clones** the chunk). A decoder's output is **not** re-fed through the chain.

- The chain is fixed: `DefaultDecoders()` returns exactly `[&UTF8{}, &Base64{}, &UTF16{}, &EscapedUnicode{}]` with the comment `// UTF8 must be first for duplicate detection` [`pkg/decoders/decoders.go:8-16`]. `scannerWorker` iterates it once per chunk: `for _, decoder := range e.decoders { decoded := decoder.FromChunk(chunk) ... }` [`pkg/engine/engine.go:784-786`].
- `UTF8.FromChunk` returns a `PLAIN` view for any non-empty data (sanitizing invalid UTF-8) [`pkg/decoders/utf8.go:16-29`] → observed as Case C.
- `Base64.FromChunk` finds base64-charset runs longer than 20 chars (`getSubstringsOfCharacterSet(chunk.Data, 20, ...)` [`pkg/decoders/base64.go:36`]), decodes those that are valid ASCII, and **rebuilds `chunk.Data` in place** — writing the surrounding plaintext, then the decoded bytes where the encoded run was: `result.Write(chunk.Data[start : start+end]); result.Write(decoded); ...; chunk.Data = result.Bytes()` [`pkg/decoders/base64.go:60-67`]; it returns `nil` if nothing decoded [`base64.go:71`] → observed as Case B.
- `EscapedUnicode.FromChunk` first `bytes.Clone`s the data ("Necessary to avoid data races") and returns a **new** `sources.Chunk`, leaving the original untouched [`pkg/decoders/escaped_unicode.go:32-68`, clone at `:39`] → observed as Case E.

**Why one file yields multiple matches (the crux for Q4/Q6):** because the `Base64` pass writes the *surrounding plaintext back* and only replaces the encoded run, a file that contains **both** a plaintext copy and a Base64 copy still contains the plaintext copy after decoding — so the AWS detector matches the key **twice** in one scan (once via the `PLAIN` view, once via the `BASE64`-rebuilt view). This is exactly what Cases A, D, G, H, and F show.

### §6.2 Q2 — Reported decoder types

**Direct answer:** `PLAIN` for plaintext, `BASE64` for Base64, `ESCAPED_UNICODE` for escaped-Unicode; the fourth defined type is `UTF16` (not exercised by ASCII inputs), and `UNKNOWN=0` is the never-emitted zero value.

- The enum: `UNKNOWN = 0; PLAIN = 1; BASE64 = 2; UTF16 = 3; ESCAPED_UNICODE = 4` [`proto/detectors.proto:7-13`] (generated as `DecoderType_UNKNOWN … DecoderType_ESCAPED_UNICODE` [`pkg/pb/detectorspb/detectors.pb.go:25-31`]).
- Each decoder's `Type()`: `UTF8 → PLAIN` [`pkg/decoders/utf8.go:12-14`], `Base64 → BASE64` [`pkg/decoders/base64.go:30-32`], `UTF16 → UTF16` [`pkg/decoders/utf16.go:14-16`], `EscapedUnicode → ESCAPED_UNICODE` [`pkg/decoders/escaped_unicode.go:28-30`].
- The type is stamped onto the result by **`processResult`**: `secret.DecoderType = data.decoder` [`pkg/engine/engine.go:1178`], and surfaced to the user as `DecoderName = r.DecoderType.String()` [`pkg/output/json.go:65`] / `Decoder Type: %s` [`pkg/output/plain.go:64`].

**Observed** (from §5): `PLAIN` (Case C), `BASE64` (Case B), `ESCAPED_UNICODE` (Case E). `UTF16` is enumerated for completeness but the ASCII test inputs never trigger `UTF16.FromChunk` (which requires alternating zero-bytes) [`pkg/decoders/utf16.go:18-33`].

### §6.3 Q3 — Overlap detection

**Direct answer:** overlap detection occurs **only when two or more *different* detectors match the same chunk of data** and the `--allow-verification-overlap` flag is off. It **never occurs for the lone AWS key** (one detector), and when it does occur it **disables verification** for the offending result rather than changing the result count.

- The gate is `if len(matchingDetectors) > 1 && !e.verificationOverlap { … verificationOverlapChunksChan <- … }` [`pkg/engine/engine.go:796`]. `matchingDetectors` comes from the Aho-Corasick keyword pre-filter `FindDetectorMatches` [`engine.go:795`].
- In `verificationOverlapWorker`, `likelyDuplicate` compares candidate secrets with a Levenshtein similarity threshold of `0.9`, **skipping** same-detector-type candidates and length-divergent ones [`pkg/engine/engine.go:887-923`]; on a cross-detector duplicate it calls `res.SetVerificationError(errOverlap)` [`engine.go:988`]. `errOverlap` is defined at [`pkg/engine/engine.go:39`].

**Observed** (§5.10): grep count `0` across **all eight** lone-AWS cases (A–H); the two-detector fixture yields 3 detectors and stamps the exact `errOverlap` text on at least one result; `--allow-verification-overlap` suppresses it (0 annotations) while still emitting all 3 results. **Overlap is a verification annotation, not a count change.**

### §6.4 Q4 — Deduplication effect on the final result count

**Direct answer:** deduplication is an LRU pass in `notifierWorker` that **collapses same-secret repeats whose decoder type differs but whose key otherwise matches** — so the raw-then-Base64 layouts (A/G/H) collapse to **1**, while different-line layouts (D→2, F→3) all survive.

- `notifierWorker` holds `dedupeCache *lru.Cache[string, detectorspb.DecoderType]` [`pkg/engine/engine.go:209`], sized `const cacheSize = 512` [`engine.go:491`].
- The key is `key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)` [`pkg/engine/engine.go:1216`] — it **includes `SourceMetadata` (which contains the line number)** and **excludes the decoder type**; the decoder type is stored as the cache **value**.
- The skip rule: `if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType || result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) { continue }` else `e.dedupeCache.Add(key, result.DecoderType)` [`engine.go:1217-1221`]. So a second result with the **same key but a different decoder type** is dropped. (The Postman clause dedupes Postman results regardless of decoder type — a deliberate special case noted in the code comment [`engine.go:1207-1214`].)

**Observed:** Cases A/G/H → 1 result (the two decoder-typed matches share one key); Case D → 2 and Case F → 3 (different lines → different keys). The overlap fixture's count (3) is **unaffected** by this dedupe (different `DetectorType`/`Raw` per detector → distinct keys).

### §6.5 Q5 — Dedupe-vs-overlap ordering

**Direct answer:** **deduplication happens *after* overlap detection.** **(inferred / source-derived** from the channel producer→consumer stage order.**)**

- Overlap routing and annotation happen in `scannerWorker` (the gate [`engine.go:796`]) and `verificationOverlapWorker` [`engine.go:924-1034`, error set at `:988`]. Both the overlap path and the normal path converge on `processResult` [`engine.go:1152-1188`], which sends the result onto the `e.results` channel: `e.results <- secret` [`engine.go:1186`].
- The LRU dedupe runs strictly later, when `notifierWorker` **consumes** `e.results`: `for result := range e.ResultsChan() { … dedupeCache … }` [`engine.go:1190`, dedupe at `:1216-1221`].
- Because the overlap error is attached upstream and the dedupe is a downstream consumer of that same channel, dedupe necessarily observes results *after* any overlap annotation is applied. This matches the documented worker order `ScannerWorkers → VerificationOverlapWorkers → DetectorWorkers → NotifierWorkers` [`docs/concurrency.md:10-21`] and channel flow [`docs/concurrency.md:28-37`].

This is labeled **(inferred / source-derived)** because the two mechanisms are not expressed in one straight-line function — they are separate pipeline stages joined by channels — but the stage order is unambiguous from the channel producer/consumer relationship and is consistent with every observation above.

### §6.6 Q6 — One-vs-many variability

**Direct answer:** the same logical secret yields **one** result when both encodings resolve to the **same computed first-occurrence line** (identical dedupe key → collapse) and **multiple** results when they resolve to **different computed lines** (distinct keys → both survive). The discriminator is the *computed* `SourceMetadata` line — **not** the physical placement of the encodings. When it collapses to one, *which decoder type survives is a genuine race*, so the reported `DecoderName` flips run-to-run.

- The dedupe key includes the line number (via `SourceMetadata`) but **not** the decoder type [`engine.go:1216`]. The line number is the **first-occurrence** line: `FragmentLineOffset` does `before, after, found := bytes.Cut(chunk.Data, result.Raw)` and counts newlines in `before` [`pkg/engine/engine.go:1256-1261`]; `SetResultLineNumber` applies it [`engine.go:1321-1324`], invoked from `processResult` [`engine.go:1166`].
- **Physical placement ≠ computed line.** Because `Base64` rebuilds the chunk *in place* and keeps the surrounding plaintext, within one chunk the rebuilt data contains the key at **both** the plaintext position and the decoded position; `bytes.Cut` finds the **earlier** (plaintext) one. So for any layout where the **plaintext precedes the Base64 form in one chunk**, both the `PLAIN` and `BASE64` views compute the **same** line — even though the Base64 bytes physically sit on a later line. This is why:
  - **Case A** (plaintext L1, Base64 L2, adjacent) → both compute line 1 → **collapse to 1**.
  - **Case G** (both on the same physical line 1) → both compute line 1 → **collapse to 1**.
  - **Case H** (plaintext L1, Base64 L10, filler between, one chunk) → both compute line 1 → **collapse to 1**.
  All three collapse *despite different physical arrangements*, confirming the discriminator is the computed line.
- **Raw→Base64 collapses; Base64→raw survives (asymmetry).** In **Case D** the Base64 form is on line 1 and the plaintext on line 2. The `BASE64` view's first `AKIA…` occurrence is the decoded line-1 run (line 1); the `PLAIN` view's first occurrence is the line-2 plaintext (line 2). The two computed lines **differ** → two distinct keys → **both survive (2)**. So an otherwise-identical file **collapses** when the plaintext comes first (A/G/H) but **survives as two** when the Base64 comes first (D).
- **Different chunks always survive.** **Case F** splits the encodings across chunks; the `PLAIN` match (line 1) and the two `BASE64` matches (lines 9 and 157, from the `PeekSize` chunk overlap, §5.8) have three distinct lines → **3 results**.
- **Which decoder survives on collapse is a race (source-derived).** The `PLAIN` and `BASE64` results are produced by concurrent detector workers (8 of them even at `--concurrency=1`, §5.5) and delivered to the shared LRU; whichever `Add`s its key first wins the slot, and the later one is dropped as a "different decoder type" duplicate [`engine.go:1217`]. Measured: BASE64:79 / PLAIN:21 (Case A, default); BASE64:15 / PLAIN:35 (Case A, `--concurrency=1`) — the race **persists** at `--concurrency=1`, only shifting toward PLAIN.

---

## §7 The three outcomes the user saw, disambiguated

The three behaviors are produced by **two independent mechanisms**: (i) **result deduplication**, which affects the **count**, and (ii) **verification-overlap detection**, which affects a **verification annotation** (never the count). The user's file structure decides which shows up.

| User's observation | Mechanism | Effect | Reproduced by | Root cause |
|--------------------|-----------|--------|---------------|------------|
| "reported twice with different decoder types" | **Deduplication — no collapse** | count = 2 (or 3) | Case D (§5.4) → 2; Case F (§5.8) → 3 | Encodings on **different computed lines** → different `SourceMetadata` → **different dedupe keys** → all survive [`engine.go:1216`]. Base64-before-plaintext (D) or split across chunks (F) |
| "deduplicated down to a single result" | **Deduplication — collapse** | count = 1 | Cases A (§5.5), G (§5.6), H (§5.7) | Plaintext precedes Base64 in one chunk → both compute the **same first-occurrence line** → identical key → second dropped; **surviving decoder type is a race** [`engine.go:1217-1221`] |
| "reported an overlap error" | **Verification-overlap** (separate) | count unchanged; adds `errOverlap` annotation | Two-detector fixture (§5.10) | **≥2 different detectors** match one chunk [`engine.go:796`, `:988`]; **never** fired by the lone AWS key (0 across A–H) |

Key insight: the "overlap error" is **not** a deduplication outcome and **cannot** be produced by a single AWS key no matter how it is encoded — it requires a second, different detector matching the same bytes. Conversely, the "one vs many results" behavior is purely about the dedupe key's **computed-line** component (and the raw-first vs Base64-first asymmetry) and never emits an overlap error. Conflating the two is the source of the apparent inconsistency.

---

## §8 Pitfall — `--results=all` is invalid and yields zero results

A natural but wrong guess is `--results=all`. The flag validator `parseResults` only accepts `verified,unknown,unverified,filtered_unverified` [`main.go:970-991`], so `all` is rejected, the process **exits 1**, and **no results** are printed (stdout empty; the error is on stderr):

```console
$ /tmp/th/trufflehog filesystem /tmp/th_investigation/caseC.txt --results=all --no-verification --no-update --json ; echo "exit=$?"
{"level":"error","ts":"2026-07-13T19:27:22Z","logger":"trufflehog","msg":"failed to configure results flag","error":"invalid value 'all', valid values are 'verified,unknown,unverified,filtered_unverified'"}
exit=1
```

The error is logged by `logFatal(err, "failed to configure results flag")` [`main.go:508`] with the message string from `parseResults` [`main.go:988`]. Standard output contains zero result objects. Throughout this investigation the explicit, valid `--results=verified,unknown,unverified` was used.

---

## §9 Version note — this HEAD is single-pass (four decoders, no iterative decoding)

**Direct answer:** at this commit the decoder stage is a **flat, single-pass loop over exactly four decoders**. Newer upstream features described elsewhere — iterative/recursive decoding, a `--max-decode-depth` flag, and an HTML decoder — are **not present here** and are not attributed to this checkout.

```console
$ [ -f pkg/decoders/html.go ] && echo FOUND || echo ABSENT
ABSENT
$ ls -1 pkg/decoders/*.go | grep -v _test.go
pkg/decoders/base64.go
pkg/decoders/decoders.go
pkg/decoders/escaped_unicode.go
pkg/decoders/utf16.go
pkg/decoders/utf8.go
$ grep -rin 'max.decode.depth' main.go pkg/ | wc -l
0
$ grep -rin 'MaxDecodeDepth' pkg/ | wc -l
0
```

`DefaultDecoders()` returns exactly four decoders and the scanner loops over them once per chunk (no re-feeding of decoder output) [`pkg/decoders/decoders.go:8-16`, `pkg/engine/engine.go:784-786`]. The HEAD commit `e42153d44a5e…` is dated 2025-05-05, predating those newer features.

---

## §10 Read-only & cleanup confirmation

No tracked source/test/config/build file was modified; the only path that differs from the pinned source commit is this `blitzy/` document. All investigation artifacts lived **outside** the repository under `/tmp` and were removed on completion.

```console
$ rm -rf /tmp/th /tmp/th_investigation /tmp/th_probe /tmp/th_evidence
$ for p in /tmp/th /tmp/th_investigation /tmp/th_probe /tmp/th_evidence; do test ! -e "$p" && echo "absent: $p" || echo "PRESENT: $p"; done
absent: /tmp/th
absent: /tmp/th_investigation
absent: /tmp/th_probe
absent: /tmp/th_evidence
$ git -C /tmp/blitzy/trufflehog/blitzy-d46ccd01-34ea-4c14-ab97-a0973ab3aa05_051aa8 diff --stat e42153d44a5e5c37c1bd0c70e074781e9edcb760 -- ':(exclude)blitzy/'
$ git -C /tmp/blitzy/trufflehog/blitzy-d46ccd01-34ea-4c14-ab97-a0973ab3aa05_051aa8 status --porcelain
 M blitzy/documentation/trufflehog_e42153d44a5e.md
```

Notes:

- The overlap fixtures were **copied** (never moved or modified) from `pkg/engine/testdata/`; the source tree diff stayed empty throughout (§3).
- The empty `git diff --stat … -- ':(exclude)blitzy/'` is the durable read-only proof: **no** source/test/config/build file differs from the pinned commit. The only working-tree change is this document (`M blitzy/documentation/trufflehog_e42153d44a5e.md`).
- The Go build/module caches used to compile the binary live **outside** both the repository and `/tmp` — `GOCACHE=/root/.cache/go-build`, `GOMODCACHE=/root/go/pkg/mod`, `GOPATH=/root/go` — and are shared, pre-warmed toolchain state; they were read during `go build` but not created or modified by this investigation, and are intentionally left untouched.
- The `/app` directory was never inspected.

---

## §11 Coverage-pass checklist

- [x] **Q1 (multi-encoding handling)** — ordered single-pass chain, Base64 in-place rebuild vs EscapedUnicode clone; `file:line` [`decoders.go:8-16`, `base64.go:67`, `escaped_unicode.go:39`] + observed Cases B/C/E (§6.1)
- [x] **Q2 (decoder types)** — `PLAIN`/`BASE64`/`UTF16`/`ESCAPED_UNICODE` (+`UNKNOWN=0`); enum [`proto/detectors.proto:7-13`] + per-decoder `Type()` + observed (§6.2)
- [x] **Q3 (overlap detection)** — gate `>1 detector` [`engine.go:796`], `errOverlap` [`engine.go:39`, `:988`]; observed 0 for lone AWS across **A–H**, fired by 2-detector fixture (§6.3, §5.10)
- [x] **Q4 (dedup effect)** — 512-entry LRU, key excludes decoder type / includes computed line [`engine.go:1216-1221`]; observed A/G/H→1, D→2, F→3 (§6.4)
- [x] **Q5 (ordering)** — dedupe **after** overlap, **(inferred / source-derived)** from stage order [`engine.go:1186`→`:1190`, `docs/concurrency.md:10-21`, `:28-37`] (§6.5)
- [x] **Q6 (one-vs-many)** — same **computed** line→1 (decoder a race), different lines→2/3; physical-placement-vs-computed-line distinction and raw-first-vs-Base64-first asymmetry; first-occurrence line via `FragmentLineOffset` [`engine.go:1256-1261`]; observed distributions + concurrency mechanism (§6.6, §5.5)
- [x] **Same-physical-line layout (Case G)** and **filler-separated single-chunk layout (Case H)** exercised, each collapsing to 1 with a decoder race (§5.6, §5.7); both included in the lone-AWS zero-overlap check (§5.10)
- [x] **Read-only mandate** — only this `blitzy/` doc differs from the pinned commit; empty source diff; artifacts removed (§10)
- [x] **Test-data removal** — all `/tmp` artifacts removed with post-cleanup absence checks; fixtures only copied; Go caches documented as external/untouched (§10)
- [x] **Version caveat** — single-pass 4-decoder loop; html.go/MaxDecodeDepth/max-decode-depth absent (§9)
- [x] **Three outcomes disambiguated** into two independent mechanisms (count vs annotation) (§7)
- [x] **Verbatim question** quoted (§1); **canonical build/invocation** stated with commands, flags labeled as explicit opt-ins (§3)

---

## §12 Appendix — reproducible inputs, fixtures & scripts

Everything below lived under `/tmp/th_investigation/` (outside the repo). The generator is deterministic; the stated `sha256`/byte/line values are the exact ground-truth of the inputs used for every transcript above.

### §12.1 Deterministic input generator (`generate_inputs.sh`)

```bash
#!/usr/bin/env bash
# generate_inputs.sh — deterministically (re)creates every crafted input used in the
# investigation, then prints byte/line counts and sha256 for reproducibility.
set -euo pipefail

DIR=/tmp/th_investigation
mkdir -p "$DIR"

ID='AKIASP2TPHJSQH3FJRUX'
SEC='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
PLAIN="$ID $SEC"                       # the one logical AWS key, plaintext form
B64="$(printf '%s' "$PLAIN" | base64 -w0)"   # Base64 of "<ID> <SEC>"

# Deterministic filler: spaces guarantee no base64 run >= 20 chars (no spurious decode).
FILLER='padding line to separate the two encodings safely without any secret'

# --- single-encoding cases -------------------------------------------------
printf '%s\n'            "$B64"                 > "$DIR/caseB.txt"   # base64 only
printf '%s\n'            "$PLAIN"               > "$DIR/caseC.txt"   # plaintext only

# escaped-unicode of "<ID> <SEC>" (\uXXXX per rune), single line
python3 - "$PLAIN" > "$DIR/caseE.txt" <<'PYEOF'
import sys
s = sys.argv[1]
sys.stdout.write(''.join('\\u%04x' % ord(c) for c in s) + '\n')
PYEOF

# --- adjacent-line cases ---------------------------------------------------
printf '%s\n%s\n'       "$PLAIN" "$B64"        > "$DIR/caseA.txt"   # plaintext L1 + base64 L2
printf '%s\n%s\n'       "$B64"  "$PLAIN"       > "$DIR/caseD.txt"   # base64 L1 + plaintext L2

# --- same physical line (Case G) -------------------------------------------
printf '%s %s\n'        "$PLAIN" "$B64"        > "$DIR/caseG.txt"   # plaintext + base64 on ONE line

# --- filler-separated, SINGLE chunk (Case H) -------------------------------
# plaintext L1, 8 filler lines, base64 on last line; total < ChunkSize(10240) so it is ONE chunk.
{
  printf '%s\n' "$PLAIN"
  for i in $(seq 1 8); do printf '%s\n' "$FILLER"; done
  printf '%s\n' "$B64"
} > "$DIR/caseH.txt"

# --- multi-chunk (Case F) --------------------------------------------------
# plaintext L1, 600 filler lines, base64 on last line; > TotalChunkSize(13312) so the
# encodings land in DIFFERENT chunks.
{
  printf '%s\n' "$PLAIN"
  for i in $(seq 1 600); do printf '%s\n' "$FILLER"; done
  printf '%s\n' "$B64"
} > "$DIR/caseF.txt"

echo "PLAIN = $PLAIN"
echo "B64   = $B64"
echo
printf '%-10s %8s %6s  %s\n' FILE BYTES LINES SHA256
for f in caseA caseB caseC caseD caseE caseF caseG caseH; do
  p="$DIR/$f.txt"
  b=$(wc -c < "$p"); l=$(wc -l < "$p"); h=$(sha256sum "$p" | cut -d' ' -f1)
  printf '%-10s %8s %6s  %s\n' "$f.txt" "$b" "$l" "$h"
done
```

Running it produces exactly these inputs (ground-truth `bytes / lines / sha256`):

```console
$ bash /tmp/th_investigation/generate_inputs.sh
PLAIN = AKIASP2TPHJSQH3FJRUX wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
B64   = QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==

FILE          BYTES  LINES  SHA256
caseA.txt       147      2  d8e39a18696c2da525d6e22300a28e873b95a9957f5624edc290bde6499bcdbf
caseB.txt        85      1  740f139d364a7537c287c703b1d4a5816ec8906d80b3362178c0026e93565c05
caseC.txt        62      1  3575568331d110dec10f386a4a031d131c5406934db96052c8a40a4e336d1d5a
caseD.txt       147      2  ad323609a74faaacbda83135aabac2cdab9f0a75ea53fef884f13aaa952c6ee7
caseE.txt       367      1  30e8d22c6d6ea15ca68cd4095997b1c6a3c3d598045d99c63ec92ce3d53a5c50
caseF.txt     41547    602  ec4ccf8342b469172cb07c20aef18f732b22d8c8f197a9668be9c2f6a23a634f
caseG.txt       147      1  9469331a1d86af369ebbb2d1d30a914290c943fb6ba6a6b2dd0125720ed14d3d
caseH.txt       699     10  2ff726da073daaec843c1d6c9d2c4b750ccbeddda2f43f9a5019c97658ae1720
```

### §12.2 Copied fixtures (read-only) and reproduction scripts

The overlap fixtures are **copied** from the repo (never modified). Their content hash matches the source, proving they are unchanged:

```console
$ cp pkg/engine/testdata/verificationoverlap_detectors.yaml /tmp/th_investigation/vo_detectors.yaml
$ cp pkg/engine/testdata/verificationoverlap_secrets.txt    /tmp/th_investigation/vo_secrets.txt
$ sha256sum /tmp/th_investigation/vo_detectors.yaml /tmp/th_investigation/vo_secrets.txt
54df034ea7c18ee321d38fcdbfc022db8626eb61c81ad2a13d8df468c96a4bfc  /tmp/th_investigation/vo_detectors.yaml
f4cb170d883f3d90f35eec7dbbec2852656e3f573a75ebc62ffd91629be3b7e0  /tmp/th_investigation/vo_secrets.txt
$ sha256sum pkg/engine/testdata/verificationoverlap_detectors.yaml pkg/engine/testdata/verificationoverlap_secrets.txt
54df034ea7c18ee321d38fcdbfc022db8626eb61c81ad2a13d8df468c96a4bfc  pkg/engine/testdata/verificationoverlap_detectors.yaml
f4cb170d883f3d90f35eec7dbbec2852656e3f573a75ebc62ffd91629be3b7e0  pkg/engine/testdata/verificationoverlap_secrets.txt
```

All scripts share strict helpers so that any non-zero CLI exit or unparseable JSON aborts the run (no silent failures), and result-count / decoder / line invariants are asserted rather than assumed.

```bash
# lib_assert.sh — shared strict helpers. Source this. Requires th_parse.py alongside.
set -euo pipefail
TH=/tmp/th/trufflehog
DIR=/tmp/th_investigation
PARSE="python3 $DIR/th_parse.py"
FLAGS_BASE="--results=verified,unknown,unverified --no-verification --no-update --json"

# run_json <outfile.stdout> <outfile.stderr> <path> [extra flags...]
# Runs a scan, REQUIRES exit status 0, captures stdout/stderr to separate files.
run_json() {
  local so="$1" se="$2" path="$3"; shift 3
  set +e
  "$TH" filesystem "$path" $FLAGS_BASE "$@" >"$so" 2>"$se"
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "FATAL: trufflehog exited $rc for $path (flags: $*)" >&2
    echo "----- stderr -----" >&2; cat "$se" >&2
    exit 1
  fi
  # Structurally validate stdout is parseable JSON (parser exits nonzero otherwise).
  $PARSE <"$so" >/dev/null
}
```

```python
#!/usr/bin/env python3
# th_parse.py — structurally parse TruffleHog JSON stdout (one object per line).
# Reads JSON from stdin. Prints "results=<n> decoders=[..] lines=[..]" with decoders
# and lines sorted for a stable, order-independent signature. Exits nonzero if any
# line is not valid JSON or lacks required fields.
import sys, json
results = []
for ln in sys.stdin:
    ln = ln.strip()
    if not ln:
        continue
    try:
        o = json.loads(ln)
    except json.JSONDecodeError as e:
        sys.stderr.write("PARSE-ERROR: not valid JSON: %r (%s)\n" % (ln[:80], e))
        sys.exit(3)
    for k in ("DetectorType", "DecoderName", "SourceMetadata"):
        if k not in o:
            sys.stderr.write("STRUCT-ERROR: missing %s in %r\n" % (k, ln[:80]))
            sys.exit(4)
    dec = o["DecoderName"]
    try:
        line = o["SourceMetadata"]["Data"]["Filesystem"]["line"]
    except (KeyError, TypeError):
        line = None
    results.append((dec, line))
decoders = sorted(r[0] for r in results)
lines = sorted((r[1] for r in results), key=lambda x: (x is None, x))
print("results=%d decoders=[%s] lines=[%s]" % (
    len(results), ",".join(decoders),
    ",".join(str(x) for x in lines)))
```

```bash
#!/usr/bin/env bash
# stability_sweep.sh — run each named case RUNS times through the canonical CLI,
# fail hard on any nonzero exit or unparseable JSON, and print a stable
# (order-independent) parsed signature per run. Usage: stability_sweep.sh [RUNS]
set -euo pipefail
DIR=/tmp/th_investigation
source "$DIR/lib_assert.sh"
RUNS="${1:-3}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for c in B C E D A G H F; do
  echo "=== Case $c (case$c.txt) ==="
  for i in $(seq 1 "$RUNS"); do
    run_json "$TMP/o" "$TMP/e" "$DIR/case$c.txt"
    printf '  run %d: ' "$i"; $PARSE <"$TMP/o"
  done
done
```

```bash
#!/usr/bin/env bash
# race_tally.sh — repeatedly scan ONE case and tally (a) result-count distribution
# and (b) surviving-decoder distribution. Fails hard on any nonzero CLI exit or
# unparseable JSON. Asserts the result-count invariant if EXPECT_COUNT is given.
# Usage: race_tally.sh <caseLetter> <N> [EXPECT_COUNT] [-- extra CLI flags...]
set -euo pipefail
DIR=/tmp/th_investigation
source "$DIR/lib_assert.sh"
CASE="$1"; N="$2"; EXPECT="${3:-}"
shift $(( $# >= 3 ? 3 : 2 ))
EXTRA=(); if [ "${1:-}" = "--" ]; then shift; EXTRA=("$@"); fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
counts_file="$TMP/counts"; decs_file="$TMP/decs"; : >"$counts_file"; : >"$decs_file"
for i in $(seq 1 "$N"); do
  run_json "$TMP/o" "$TMP/e" "$DIR/case$CASE.txt" "${EXTRA[@]}"
  c=$(grep -c '"DetectorType"' "$TMP/o" || true)
  echo "$c" >>"$counts_file"
  if [ -n "$EXPECT" ] && [ "$c" != "$EXPECT" ]; then
    echo "INVARIANT-FAIL: run $i produced count=$c, expected $EXPECT" >&2
    cat "$TMP/o" >&2; exit 2
  fi
  # surviving decoder(s), one per line, for the count distribution
  grep -o '"DecoderName":"[A-Z_0-9]*"' "$TMP/o" | sed 's/.*:"//;s/"//' >>"$decs_file"
done
echo "--- result-count distribution (count : #runs) over N=$N ---"
sort "$counts_file" | uniq -c | awk '{print "  count="$2" : "$1" runs"}'
echo "--- surviving-decoder distribution (decoder : #occurrences) over N=$N ---"
sort "$decs_file" | uniq -c | awk '{print "  "$2" : "$1}'
```

```bash
#!/usr/bin/env bash
# overlap_tally.sh — repeatedly scan the 2-detector overlap fixture and tally the
# total result count and the number of results carrying the errOverlap verification
# error. Fails hard on nonzero CLI exit or unparseable JSON. Asserts total==3.
# Usage: overlap_tally.sh <N> [-- extra CLI flags e.g. --allow-verification-overlap]
set -euo pipefail
DIR=/tmp/th_investigation
source "$DIR/lib_assert.sh"
N="$1"; shift || true
EXTRA=(); if [ "${1:-}" = "--" ]; then shift; EXTRA=("$@"); fi
SEC="$DIR/vo_secrets.txt"; CFG="$DIR/vo_detectors.yaml"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tally="$TMP/tally"; : >"$tally"
for i in $(seq 1 "$N"); do
  set +e
  "$TH" filesystem "$SEC" --config "$CFG" $FLAGS_BASE "${EXTRA[@]}" >"$TMP/o" 2>"$TMP/e"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then echo "FATAL: exit $rc run $i" >&2; cat "$TMP/e" >&2; exit 1; fi
  $PARSE <"$TMP/o" >/dev/null                     # structural JSON validation
  total=$(grep -c '"DetectorType"' "$TMP/o" || true)
  err=$(grep -c 'More than one detector' "$TMP/o" || true)
  if [ "$total" != "3" ]; then
    echo "INVARIANT-FAIL: run $i total_results=$total (expected 3)" >&2; cat "$TMP/o" >&2; exit 2
  fi
  echo "run $i: total_results=${total} errOverlap_count=${err}"
  echo "${total} ${err}" >>"$tally"
done
echo "--- distribution over $N runs (total_results errOverlap_count : #runs) ---"
sort "$tally" | uniq -c | awk '{print "  "$1" run(s): total_results="$2" errOverlap_count="$3}'
```

```bash
#!/usr/bin/env bash
# lone_aws_overlap_check.sh — for every lone-AWS case, assert the errOverlap message
# NEVER appears (only one detector matches, so the >1-detector gate is false).
# Fails hard on nonzero CLI exit. Prints the errOverlap match count per case (must be 0).
set -euo pipefail
DIR=/tmp/th_investigation
source "$DIR/lib_assert.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
rc_all=0
for c in A B C D E G H F; do
  run_json "$TMP/o" "$TMP/e" "$DIR/case$c.txt"           # asserts exit 0 + valid JSON
  # search BOTH streams for the overlap message
  n=$( { cat "$TMP/o"; cat "$TMP/e"; } | grep -c 'More than one detector' || true)
  echo "Case $c: errOverlap_matches=$n"
  if [ "$n" != "0" ]; then echo "UNEXPECTED: Case $c produced overlap annotation" >&2; rc_all=1; fi
done
exit $rc_all
```

### §12.3 Raw run tallies (point-in-time; the ratios are genuine races and will differ on re-run — only the invariants are fixed)

- **Case A, N=100, default concurrency:** `count=1 : 100 runs`; `BASE64 : 79`, `PLAIN : 21`. Invariant: always 1 result.
- **Case A, N=50, `--concurrency=1`:** `count=1 : 50 runs`; `BASE64 : 15`, `PLAIN : 35`. Invariant: always 1 result; race persists (not deterministic).
- **Case G, N=100, default / N=50, `--concurrency=1`:** `count=1` every run; `BASE64 : 84 / PLAIN : 16` and `BASE64 : 17 / PLAIN : 33`. Invariant: always 1 result.
- **Case H, N=100, default / N=50, `--concurrency=1`:** `count=1` every run; `BASE64 : 73 / PLAIN : 27` and `BASE64 : 37 / PLAIN : 13`. Invariant: always 1 result.
- **Overlap fixture, N=20:** `total_results=3` every run; `errOverlap_count=1` on 16 runs, `=2` on 4 runs. Invariant: always 3 results.
- **Overlap fixture + `--allow-verification-overlap`, N=5:** `total_results=3 errOverlap_count=0` every run. Invariant: always 3 results, 0 annotations.

---

*Provenance: all output above was produced by the canonical `trufflehog dev` build (`CGO_ENABLED=0 go build -o /tmp/th/trufflehog .`, Go 1.24.2) at the pinned source commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`, driven through the real `filesystem` CLI entry point. Every console block is real and unedited (stdout and stderr both shown; volatile timestamps/durations/worker-IDs as observed). Directly-observed claims are the emitted result counts, `DecoderName` values, line numbers, `VerificationError` text, and exit statuses; the dedupe-after-overlap ordering (§6.5), the cause and concurrency-persistence of the surviving-decoder race (§5.5, §6.6), and the overlap-annotation carrier variability (§5.10) are grounded in `file:line` source and labeled **(inferred / source-derived)**.*
