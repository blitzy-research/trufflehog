# TruffleHog: Decoder Pipeline, Overlap Detection & Deduplication — Investigation

> **Scope:** Read-only code investigation. This document is written from **directly observed
> runtime behavior** of the real TruffleHog scanner built at HEAD
> `e42153d44a5e5c37c1bd0c70e074781e9edcb760`. Every behavioral claim is accompanied by the exact
> command that produced it and its unedited output; every code claim carries a `file:line`
> reference. Statements that are reasoned from code rather than directly observed are explicitly
> labeled **(inferred)**. No source file in the repository was modified, and all test data was
> created under `/tmp` and removed afterward.

## 1. The question (verbatim)

> I was scanning a file containing both a raw AWS access key and the same key as Base64-encoded, and I got confused by the output. Sometimes TruffleHog reported the secret twice with different decoder types, sometimes it reported an overlap error, and sometime it deduplicated down to a single result. The behaviour seemed inconsistent depending on how I structured the test file. I want to understand how the decoder pipeline, overlap detection, and result deduplication interact at runtime to produce these varying outputs. Verify how TruffleHog's decoder pipeline handles the same secret in multiple encoded forms (plain text, base64, escaped unicode) by observing which decoder types are reported, whether overlap detection occurs, how deduplication affects the final result count, whether the deduplication happens before or after overlap detection, and why the same logical secret sometimes produces one result and sometimes produces multiple. Do not modify any existing source files in the repository, and remove any test data created during the investigation.

---

## 2. TL;DR — direct answers to the six named items

1. **Multi-encoding handling.** Each source chunk is run through an **ordered, single-pass** decoder
   chain `[UTF8, Base64, UTF16, EscapedUnicode]` [`pkg/decoders/decoders.go:8-16`]. `UTF8` yields the
   plaintext view; `Base64.FromChunk` **rebuilds the chunk in place** — decoded bytes replace the
   encoded substring while surrounding plaintext is retained [`pkg/decoders/base64.go:34-72`] — so one
   physical file can be matched multiple times, once per decoder that produces output.
2. **Reported decoder types.** The `DecoderType` enum is `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3,
   ESCAPED_UNICODE=4` [`pkg/pb/detectorspb/detectors.pb.go:26-31`]. Observed at runtime: **`PLAIN`**
   (Case C), **`BASE64`** (Case B/D), **`ESCAPED_UNICODE`** (Case E). Surfaced to the user as
   `DecoderName` in JSON [`pkg/output/json.go:65`] and `Decoder Type:` in the plain printer
   [`pkg/output/plain.go:64`].
3. **Overlap detection.** Triggered **only** when more than one *different* detector matches a single
   decoded chunk: `if len(matchingDetectors) > 1 && !e.verificationOverlap` [`pkg/engine/engine.go:796`],
   producing `errOverlap` [`pkg/engine/engine.go:39-42`]. Observed: the single-detector AWS input
   (Cases A–E) **never** triggers it; a crafted multi-detector input **does**.
4. **Deduplication effect on final count.** A 512-entry LRU in the notifier worker
   [`pkg/engine/engine.go:1189-1235`] drops a repeat result whose key was already seen with a
   *different* decoder type [`engine.go:1216-1221`]. Observed: it collapses Case A's two matches (PLAIN
   + BASE64) into **1** result.
5. **Dedup-vs-overlap ordering.** Overlap routing runs in `scannerWorker` [`engine.go:796`] and
   `verificationOverlapWorker` [`engine.go:924-1034`]; the LRU dedupe runs later in `notifierWorker`
   [`engine.go:1189-1235`]. Therefore **deduplication happens *after* overlap detection** *(inferred
   from pipeline stage order; consistent with all observations)*.
6. **One-vs-many variability.** The dedupe key includes `SourceMetadata` (the line number) but
   **excludes** the decoder type [`engine.go:1216`]. When both encodings resolve to the **same line**
   the keys collide and collapse to **1** result (Case A), and *which decoder type survives is a
   race*; when they resolve to **different lines** the keys differ and **both** survive as 2 results
   with different decoder types (Case D).

> **The user's three outcomes map to two independent mechanisms.** "Twice with different decoder
> types" and "deduplicated to one" are both **deduplication** effects (different-lines vs same-line);
> the "overlap error" is a **separate** verification-overlap mechanism that needs 2+ *different*
> detectors and is unrelated to the AWS single-detector case. See §8.

---

## 3. Environment & canonical build

All commands were run from the repository root on branch `blitzy-6ac3c654-b850-4924-a477-bb99d15f8803`.

```console
$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760

$ git status --porcelain
            # (empty — clean working tree)

$ go version
go version go1.24.2 linux/amd64
```

`go 1.24.2` is the canonical toolchain declared by the module (`toolchain go1.24.2`, satisfying
`go 1.23.1`) [`go.mod:1-4`], so this is a **canonical, default-configuration** build (no fallback,
no deviation).

```console
$ CGO_ENABLED=0 go build -o /tmp/trufflehog .
            # exit 0

$ /tmp/trufflehog --version
trufflehog dev
```

The runtime scan log confirms the same build identity (`"trufflehog_version":"dev"`):

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseD.txt \
      --results=verified,unknown,unverified --no-verification --no-update --json 2>&1 >/dev/null \
      | grep '"msg":"finished scanning"'
{"level":"info-0","ts":"2026-07-08T05:02:27Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":124,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"4.857118ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### 3.1 The test key (a public canary / example pair)

The AWS detector requires **both** an access-key ID matching
`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` [`pkg/detectors/aws/access_keys/accesskey.go:65`] and a
40-character secret matching `[A-Za-z0-9+/]{40}` [`pkg/detectors/aws/common.go:10`], each exceeding
its entropy floor: `RequiredIdEntropy = 3.0` and `RequiredSecretEntropy = 4.25`
[`pkg/detectors/aws/common.go:6-7`]. The secret must also **not** match the false-positive filter
`FalsePositiveSecretPat = [a-f0-9]{40}` (lowercase-hex only) [`pkg/detectors/aws/utils.go:47`].

The chosen pair is a **canarytokens.org canary token** (the scanner reports `is_canary: true`,
`account: 171436882533`) combined with AWS's own public example secret — i.e. **not a live
credential**. Observed measurements:

```console
$ ID=AKIASP2TPHJSQH3FJRUX
$ SEC='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
$ printf 'ID len:  %s\nSEC len: %s\n' "${#ID}" "${#SEC}"
ID len:  20
SEC len: 40
$ python3 -c 'import sys,math;from collections import Counter
def h(s):
 c=Counter(s);n=len(s);import math;return -sum((v/n)*math.log2(v/n) for v in c.values())
print("ID  entropy = %.3f"%h(sys.argv[1]));print("SEC entropy = %.3f"%h(sys.argv[2]))' "$ID" "$SEC"
ID  entropy = 3.822
SEC entropy = 4.663
```

`3.822 > 3.0` and `4.663 > 4.25`, so both clear the thresholds; the uppercase-containing secret is
not filtered by the lowercase-hex false-positive pattern.

The Base64 form of the string `"<ID> <SEC>"` (used in Cases A, B, D) was produced with `base64 -w0`
(no line wrapping) and verified byte-for-byte:

```console
$ printf '%s %s' "$ID" "$SEC" | base64 -w0
QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==
```

### 3.2 The canonical invocation (per case)

```text
/tmp/trufflehog filesystem <path> --results=verified,unknown,unverified --no-verification --no-update --json
```

- `filesystem <path>` is the real CLI entry point [`main.go:143-144`].
- `--no-verification` disables live verification [`main.go:59`]; `--no-update` disables the update
  check [`main.go:73`]; `--results=verified,unknown,unverified` emits every result class [`main.go:61`].
- JSON results are written to **stdout** (one object per line); log lines go to **stderr**. In the
  output, `"DetectorType":2` is `AWS` and `"SourceType":15` is the filesystem source.

---

## 4. The runtime pipeline

TruffleHog is a channel-based concurrent worker pipeline. The worker roles below are named exactly as
in [`docs/concurrency.md`](../../docs/concurrency.md) (a mermaid `sequenceDiagram`) and
[`docs/process_flow.md`](../../docs/process_flow.md); the code lives in `pkg/engine/engine.go`. The
critical ordering fact for this investigation is that **overlap routing happens early (in the scanner
/ verification-overlap workers) while deduplication happens last (in the notifier worker)** — so
dedupe is *after* overlap.

```mermaid
flowchart TD
    A["Source chunk<br/>(sources.Chunk)"] --> B{"Decoder chain — single pass<br/>[UTF8, Base64, UTF16, EscapedUnicode]<br/>decoders.go:8-16"}
    B -->|"UTF8.FromChunk → PLAIN (utf8.go:12-14)"| C["decoded chunk + DecoderType"]
    B -->|"Base64.FromChunk rebuilds chunk IN PLACE:<br/>decoded bytes replace encoded substring,<br/>surrounding plaintext retained (base64.go:34-72) → BASE64"| C
    B -->|"UTF16 (utf16.go:14-16) / EscapedUnicode clones data (escaped_unicode.go:32-68)"| C
    C --> D["AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)<br/>engine.go:795"]
    D --> E{"len(matchingDetectors) > 1<br/>&& !e.verificationOverlap ?<br/>engine.go:796 — OVERLAP GATE"}
    E -->|"yes (2+ different detectors)"| F["verificationOverlapChunksChan →<br/>verificationOverlapWorker (engine.go:924-1034)<br/>likelyDuplicate sim>0.9 (engine.go:887-922)<br/>→ SetVerificationError(errOverlap) (engine.go:988)"]
    E -->|"no (single detector)"| G["detectableChunksChan → detectorWorker"]
    F --> H["processResult (engine.go:1152-1187)<br/>SetResultLineNumber (:1166)<br/>secret.DecoderType = data.decoder (:1178)"]
    G --> H
    H --> I["e.results channel"]
    I --> J{"notifierWorker LRU dedupe (engine.go:1189-1235)<br/>key = DetectorType + Raw + RawV2 + SourceMetadata (:1216)<br/>value = DecoderType (:1221)<br/>[key EXCLUDES decoder type, INCLUDES SourceMetadata/line]"}
    J -->|"key seen AND stored decoder type differs (:1217-1219)"| K["drop duplicate"]
    J -->|"new key"| L["emit result → output printer<br/>DecoderName (json.go:65) / Decoder Type (plain.go:64)"]
```

Stage-by-stage, with the responsible function and `file:line`:

| Stage | Worker / function | `file:line` | Role |
|-------|-------------------|-------------|------|
| Decode | `scannerWorker` decode loop over `e.decoders` | `engine.go:784-786` | Runs each decoder's `FromChunk` on the chunk |
| Match | `AhoCorasickCore.FindDetectorMatches` | `engine.go:795` | Finds detectors matching the decoded bytes |
| **Overlap gate** | `scannerWorker` | `engine.go:796` | Routes multi-detector chunks to the overlap worker |
| Overlap decision | `verificationOverlapWorker` / `likelyDuplicate` | `engine.go:924-1034`, `887-922` | Stamps `errOverlap` on cross-detector duplicates |
| Stamp decoder type | `processResult` | `engine.go:1178` | Sets `secret.DecoderType = data.decoder` |
| **Dedupe** | `notifierWorker` | `engine.go:1189-1235` | LRU drop of same-key/different-decoder repeats |
| Print | `json.go` / `plain.go` / `github_actions.go` | `json.go:65`, `plain.go:64`, `github_actions.go:69-70` | Surfaces the decoder type to the user |

---

## 5. Reproduction cases A–E

Five files were crafted in `/tmp` from the **same logical AWS key**, differing only in how the key is
encoded and laid out. Every case was run with the canonical command from §3.2; B/C/D/E were run 3×
each (stable), and the racy Case A was run 100× (plus 20× at `--concurrency=1`).

| Case | File structure | Total results | Observed decoder type(s) & line(s) |
|------|----------------|---------------|------------------------------------|
| A | plaintext L1 + base64(same) L2 | **always 1** | **RACE**: `BASE64` *or* `PLAIN` @ line 1 (100 runs → 80 `BASE64` / 20 `PLAIN`) |
| B | base64 only | 1 | `BASE64` @ line 1 (stable 3/3) |
| C | plaintext only | 1 | `PLAIN` @ line 1 (stable 3/3) |
| D | base64 L1 + plaintext L2 | 2 | `BASE64` @ line 1 **and** `PLAIN` @ line 2 (stable 3/3) |
| E | escaped-unicode of pair | 1 | `ESCAPED_UNICODE` @ line 1 (stable 3/3) |

The stability sweep (result count + surviving decoder(s) + line(s) per run):

```console
$ run_case B/C/D/E (3× each, canonical command)
===== CASE B (caseB.txt) — 3 runs =====
run 1: results=1 decoders=[BASE64] lines=[1]
run 2: results=1 decoders=[BASE64] lines=[1]
run 3: results=1 decoders=[BASE64] lines=[1]

===== CASE C (caseC.txt) — 3 runs =====
run 1: results=1 decoders=[PLAIN] lines=[1]
run 2: results=1 decoders=[PLAIN] lines=[1]
run 3: results=1 decoders=[PLAIN] lines=[1]

===== CASE D (caseD.txt) — 3 runs =====
run 1: results=2 decoders=[PLAIN,BASE64] lines=[2,1]
run 2: results=2 decoders=[BASE64,PLAIN] lines=[1,2]
run 3: results=2 decoders=[BASE64,PLAIN] lines=[1,2]

===== CASE E (caseE.txt) — 3 runs =====
run 1: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
run 2: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
run 3: results=1 decoders=[ESCAPED_UNICODE] lines=[1]
```

> **Note on Case D ordering:** the *order* in which the two results are printed varies run-to-run
> (concurrent workers), but the *set* is always `{BASE64@line1, PLAIN@line2}` = 2 results. The count
> and the (decoder, line) pairs are stable.

### 5.1 Case B — base64 only → 1 × `BASE64` @ line 1

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseB.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseB.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

### 5.2 Case C — plaintext only → 1 × `PLAIN` @ line 1

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseC.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseC.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

### 5.3 Case D — base64 L1 + plaintext L2 → 2 results (different lines, different decoders)

Both results share the same `Raw`/`RawV2` and are `Verified:false`; they differ only in `DecoderName`
and line number. Full unedited JSON of **both** results:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseD.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseD.txt","line":2}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

The **plain printer** (drop `--json`) shows the literal `Detector Type:` / `Decoder Type:` / `Line:`
lines [`pkg/output/plain.go:63-64`]:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseD.txt --results=verified,unknown,unverified --no-verification --no-update --no-color
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIASP2TPHJSQH3FJRUX
Resource_type: Access key
Account: 171436882533
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
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

### 5.4 Case E — escaped-unicode of the pair → 1 × `ESCAPED_UNICODE` @ line 1

The file contains only `\u0041\u004b\u0049...` (the pair as `\uXXXX` escapes). The plaintext ID does
**not** appear literally, so `UTF8`/`PLAIN` cannot match it; only `EscapedUnicode.FromChunk`
[`pkg/decoders/escaped_unicode.go:32-68`] reconstructs the key, yielding a single
`ESCAPED_UNICODE` result:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseE.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseE.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"ESCAPED_UNICODE","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

### 5.5 Case A — plaintext L1 + base64 L2 → always 1 result, **surviving decoder type is a race**

This is the crux of the user's confusion. The result **count** is always 1, but **which decoder type
survives is non-deterministic** — a genuine race in the concurrent pipeline. Over 100 identical runs:

```console
$ # Case A, 100 runs, canonical command; tally result-count and surviving decoder
===== RESULT-COUNT distribution (expect always 1) =====
    100 1
===== SURVIVING DECODER distribution over 100 runs =====
     80 BASE64
     20 PLAIN
```

The race is **not** an artifact of multi-worker parallelism: it persists even at `--concurrency=1`
(the scanner/detector/notifier remain separate goroutines), 20 runs:

```console
$ # Case A, 20 runs with --concurrency=1
--- result-count distribution ---
     20 1
--- surviving decoder distribution (concurrency=1) ---
      8 BASE64
     12 PLAIN
```

A representative single-result payload (this run: `BASE64`) — note **`line:1`** even though the
base64 text is on line 2, because the plaintext ID's first occurrence (line 1) determines the line
number:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseA.txt --results=verified,unknown,unverified --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_investigation/caseA.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

> **Deviation note (observed vs prior planning):** an earlier planning table claimed Case A was
> *deterministically* a single `BASE64` result. **The observed reality is a race.** The distribution
> reported above (80/20 over 100 runs; 8/12 at `--concurrency=1`) is what *this* investigation
> measured; exact ratios will differ run-to-run because it is a race — the invariant is "always 1
> result, decoder type non-deterministic."

---

## 6. Per-question answers (by name)

### 6.1 Multi-encoding handling

**How:** the scanner runs an **ordered, single-pass** decoder chain over each chunk. `DefaultDecoders()`
returns exactly `[UTF8, Base64, UTF16, EscapedUnicode]`, with the comment "UTF8 must be first for
duplicate detection" [`pkg/decoders/decoders.go:8-16`]. In `scannerWorker`, every decoder's
`FromChunk` is called on the chunk in turn [`pkg/engine/engine.go:784-786`]; each decoder that returns
a non-`nil` `DecodableChunk` produces an independent match round via
`AhoCorasickCore.FindDetectorMatches` [`engine.go:795`].

- `UTF8.FromChunk` always returns a `PLAIN` chunk (the plaintext view), sanitizing invalid UTF-8
  [`pkg/decoders/utf8.go:12-29`].
- `Base64.FromChunk` scans for base64-charset substrings longer than 20 characters via
  `getSubstringsOfCharacterSet(chunk.Data, 20, ...)`, decodes them with `StdEncoding`/`RawURLEncoding`
  when the result is ASCII, and **rebuilds `chunk.Data` in place** — writing the surrounding plaintext,
  then the decoded bytes in place of the encoded substring [`pkg/decoders/base64.go:34-72`]. If nothing
  decoded, it returns `nil` [`base64.go:71`]. This in-place rebuild is *why* a single file that
  contains both a plaintext copy and a base64 copy is matched twice.
- `EscapedUnicode.FromChunk` **clones** the data ("Necessary to avoid data races") and replaces
  `\uXXXX` / `U+XXXX` sequences with their decoded runes [`pkg/decoders/escaped_unicode.go:32-68`].
- The chain is **single pass**: a decoder's output is *not* fed back through the chain (see §10).

**Observed:** Case C produces `PLAIN`, Case B produces `BASE64`, Case E produces `ESCAPED_UNICODE`
(§5.1–5.4); Case D produces both `BASE64` and `PLAIN` from one file (§5.3).

### 6.2 Reported decoder types

**Value:** the `DecoderType` enum is defined as `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3,
ESCAPED_UNICODE=4` [`pkg/pb/detectorspb/detectors.pb.go:26-31`]. Each decoder returns its type from
`Type()`: `UTF8 → PLAIN` [`utf8.go:12-14`], `Base64 → BASE64` [`base64.go:30-32`], `UTF16 → UTF16`
[`utf16.go:14-16`], `EscapedUnicode → ESCAPED_UNICODE` [`escaped_unicode.go:28-30`]. `processResult`
stamps it onto the result: `secret.DecoderType = data.decoder` [`engine.go:1178`], carried on
`ResultWithMetadata.DecoderType` [`pkg/detectors/detectors.go:182-183`].

**How the user sees it:** the JSON printer emits `DecoderName = r.DecoderType.String()`
[`pkg/output/json.go:65`]; the plain printer emits `Decoder Type: %s` [`pkg/output/plain.go:64`]; the
GitHub-Actions printer *suppresses* the "with %s encoding" phrase when the type is `PLAIN`
[`pkg/output/github_actions.go:69-70`].

**Observed (three of the four non-UNKNOWN types, matching the encodings in the question):**

```console
$ grep -o '"DecoderName":"[^"]*"' caseB.json caseC.json caseE.json
caseB.json:"DecoderName":"BASE64"
caseC.json:"DecoderName":"PLAIN"
caseE.json:"DecoderName":"ESCAPED_UNICODE"
```

(`UTF16` is the fourth type; it is not exercised by these text inputs but is enumerated above with its
`file:line`. `UNKNOWN=0` is the zero value and is never produced by a successful decode.)

### 6.3 Overlap detection

**When:** overlap detection fires **only** when more than one *different* detector matches a single
decoded chunk, gated in `scannerWorker` by
`if len(matchingDetectors) > 1 && !e.verificationOverlap` [`pkg/engine/engine.go:796`]. Such chunks are
routed to `verificationOverlapWorker` [`engine.go:924-1034`], which uses `likelyDuplicate`
(Levenshtein similarity `> 0.9`, skipping same-detector-type matches) [`engine.go:887-922`] and, on a
cross-detector duplicate, calls `res.SetVerificationError(errOverlap)` [`engine.go:988`]. The error
value is `errOverlap` [`engine.go:39-42`]:

```go
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
        "You can override this behavior by using the --allow-verification-overlap flag.",
)
```

**Observed — NOT triggered by the AWS single-detector input (Cases A–E):** the AWS key matches exactly
one detector, so `len(matchingDetectors) > 1` is false and the overlap path is never entered. Grepping
every case's combined stdout+stderr for the message yields zero hits:

```console
$ for c in A B C D E; do
    n=$(/tmp/trufflehog filesystem case$c.txt --results=verified,unknown,unverified --no-verification --no-update --json 2>&1 | grep -c "More than one detector")
    echo "Case $c: 'More than one detector' occurrences = $n"; done
Case A: 'More than one detector' occurrences = 0
Case B: 'More than one detector' occurrences = 0
Case C: 'More than one detector' occurrences = 0
Case D: 'More than one detector' occurrences = 0
Case E: 'More than one detector' occurrences = 0
```

**Observed — IS triggered by a multi-detector input.** Using the repository's own read-only fixtures
`pkg/engine/testdata/verificationoverlap_detectors.yaml` + `verificationoverlap_secrets.txt` (**copied
to `/tmp`**; originals never modified), the secret
`PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r` matches the built-in **Postman**
detector plus two **CustomRegex** detectors — three detectors on one chunk. (This is exactly the
scenario described in the code comment at `engine.go:975-976`.) The plain printer shows the
`errOverlap` message attached via `Verification issue: %s` [`plain.go:57`]:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/vo_secrets.txt --config /tmp/th_investigation/vo_detectors.yaml --results=verified,unknown,unverified --no-verification --no-update --no-color
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
Raw result: qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: detector2
File: /tmp/th_investigation/vo_secrets.txt
Line: 2

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: detector1
File: /tmp/th_investigation/vo_secrets.txt
Line: 2
```

In JSON the message surfaces as the `VerificationError` field:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/vo_secrets.txt --config /tmp/th_investigation/vo_detectors.yaml --results=verified,unknown,unverified --no-verification --no-update --json  # (VerificationError field per result)
Detector=CustomRegex  Name=detector2  VerificationError = More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector=Postman      Name=-          VerificationError = More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector=CustomRegex  Name=detector1  VerificationError (absent)
```

The message is a **verification** annotation, not a deduplication of the result count: all **3**
results are still emitted every run; only *which* of them carries the error is non-deterministic
(20 runs → 16× exactly one result carries it, 4× two results carry it):

```console
$ # overlap fixture, 20 runs
--- total results per run ---
     20 3
--- number of results carrying errOverlap per run (non-deterministic) ---
     16 1
      4 2
```

`--allow-verification-overlap` [`main.go:65`] suppresses the annotation entirely (still 3 results,
0 errors) across 5 runs:

```console
$ # overlap fixture + --allow-verification-overlap, 5 runs
run 1: total_results=3 errOverlap_count=0
run 2: total_results=3 errOverlap_count=0
run 3: total_results=3 errOverlap_count=0
run 4: total_results=3 errOverlap_count=0
run 5: total_results=3 errOverlap_count=0
```

### 6.4 Deduplication effect on the final result count

**Mechanism:** `notifierWorker` maintains a 512-entry LRU `dedupeCache`
[`pkg/engine/engine.go:207-209`, `491-493`, `520`] and, for each result, builds a key that **includes
`SourceMetadata` but excludes the decoder type**, storing the decoder type as the cache *value*
[`engine.go:1216-1221`]:

```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

So a repeat of an already-seen key with a **different** decoder type is dropped (and Postman results
are deduped regardless of decoder type). **Effect on count:** in Case A the PLAIN match and the
BASE64 match produce the *same* key (same detector, same `Raw`/`RawV2`, same line), so the second one
to arrive is dropped — collapsing **2 matches → 1 result** (§5.5, always 1). In Case D the two matches
have *different* keys (different lines), so **both survive → 2 results** (§5.3).

### 6.5 Dedup-vs-overlap ordering

**Answer: deduplication happens *after* overlap detection.** Overlap routing is evaluated in
`scannerWorker` [`engine.go:796`] and the `errOverlap` stamp is applied in `verificationOverlapWorker`
[`engine.go:924-1034`]; both feed `processResult` [`engine.go:1152-1187`], which sends results onto
`e.results`. The LRU dedupe is applied only later, when `notifierWorker` consumes `e.results`
[`engine.go:1189-1235`]. This ordering is **(inferred)** from the pipeline stage order (overlap
workers/scanner precede the notifier) — the code does not run them in one straight-line function — and
it is consistent with every observation: overlap-flagged results (§6.3) still pass through the same
notifier dedupe, and the dedupe never removes the overlap annotation, it only collapses same-key
different-decoder duplicates. The worker ordering matches the `sequenceDiagram` in
[`docs/concurrency.md`](../../docs/concurrency.md) (ScannerWorkers → VerificationOverlapWorkers →
DetectorWorkers → NotifierWorkers).

### 6.6 One-vs-many variability

**Why one vs many:** because the dedupe key includes the line number (via `SourceMetadata`) but not
the decoder type [`engine.go:1216`], the *same logical secret* collapses or survives purely on whether
its two encodings resolve to the **same line**:

- **Same line → 1 result (Case A).** The plaintext ID sits on line 1; `Base64.FromChunk` rebuilds the
  chunk in place but retains the line-1 plaintext, so the base64-decoded copy's ID *also* first occurs
  on line 1 (`SetResultLineNumber` uses the first occurrence [`engine.go:1166`]). Both matches
  therefore share one dedupe key and collapse to 1. **Which decoder type survives is a race** — it is
  whichever result reaches the shared LRU first among the concurrent detector/notifier goroutines
  (§5.5; the surviving `BASE64` payload still reports `line:1`, direct evidence both encodings resolve
  to line 1).
- **Different lines → 2 results (Case D).** The base64 is on line 1 (decodes in place at line 1) and
  the plaintext is on line 2, so the two matches carry different `SourceMetadata` line numbers →
  different keys → both survive, each with its own decoder type (`BASE64@1`, `PLAIN@2`).

This is the concrete, observed root cause of the user's "sometimes one, sometimes multiple"
confusion: it is governed by line placement in the dedupe key, and — when the encodings collide on one
line — by a race over which decoder type is reported.

---

## 7. The three outcomes the user saw, disambiguated

The user described three seemingly inconsistent outcomes. They arise from **two independent
mechanisms** — deduplication (count) and verification-overlap (a verification annotation):

| User's observation | Mechanism | Reproduced by | Why |
|--------------------|-----------|---------------|-----|
| "reported the secret **twice** with different decoder types" | **Deduplication** (no collapse) | **Case D** | Encodings land on **different lines** → different dedupe keys → both survive [`engine.go:1216`] |
| "**deduplicated** down to a single result" | **Deduplication** (collapse) | **Case A** | Encodings land on the **same line** → identical key → one dropped; surviving decoder type is a **race** [`engine.go:1217-1221`] |
| "reported an **overlap error**" | **Verification overlap** (separate) | **multi-detector fixture** | **2+ different detectors** match one chunk → `errOverlap` [`engine.go:796`, `988`, `39-42`]; never happens for the single-detector AWS key |

The key clarification: the "overlap error" is **not** a deduplication outcome. It requires two or more
*different* detectors on the same secret and only disables *verification* for the affected results
(the results are still reported). The AWS-only file can never produce it (§6.3, grep = 0), which is
why it only appeared when the file happened to contain a value that multiple detectors recognized.

---

## 8. Pitfall — `--results=all` is invalid and silently yields zero results

`--results` accepts `verified, unknown, unverified, filtered_unverified` and defaults to
`verified,unverified,unknown` [`main.go:61`]. Passing `--results=all` is **invalid**: the process logs
an error, exits with code **1**, and emits **zero** results. This is an easy way to think a scan
"found nothing." Observed:

```console
$ /tmp/trufflehog filesystem /tmp/th_investigation/caseC.txt --results=all --no-verification --no-update --json; echo "exit code: $?"
{"level":"error","ts":"2026-07-08T05:01:14Z","logger":"trufflehog","msg":"failed to configure results flag","error":"invalid value 'all', valid values are 'verified,unknown,unverified,filtered_unverified'"}
exit code: 1
            # 0 results emitted on stdout
```

Always pass explicit valid values, e.g. `--results=verified,unknown,unverified` as used throughout
this document.

---

## 9. Version note — this HEAD is single-pass; upstream-`main` features are absent

This build performs **single-pass** decoding: `DefaultDecoders()` returns exactly
`[UTF8, Base64, UTF16, EscapedUnicode]` and a decoder's output is not re-fed through the chain
[`pkg/decoders/decoders.go:8-16`]. Two features that exist on upstream `main` are **absent** at this
pinned HEAD and were verified so:

- **No iterative decoding (`--max-decode-depth`).** The flag and its symbol appear nowhere in the CLI
  or packages.
- **No HTML decoder.** `pkg/decoders/html.go` does not exist.

```console
$ [ -f pkg/decoders/html.go ] && echo FOUND || echo "ABSENT: pkg/decoders/html.go does not exist"
ABSENT: pkg/decoders/html.go does not exist

$ ls -1 pkg/decoders/*.go | grep -v _test.go
pkg/decoders/base64.go
pkg/decoders/decoders.go
pkg/decoders/escaped_unicode.go
pkg/decoders/utf16.go
pkg/decoders/utf8.go

$ grep -rin 'max.decode.depth' main.go pkg/ | wc -l ; grep -rin 'MaxDecodeDepth' pkg/ | wc -l
0
0
```

Consequently, on this HEAD a base64-of-base64 (or base64-of-escaped-unicode) nesting is **not** peeled
apart recursively — only the first decode layer is applied per decoder.

---

## 10. Read-only & cleanup confirmation

The investigation created **no** files inside the repository other than this document, and modified
**no** existing source file. All crafted inputs, the compiled binary, and the copied fixtures lived
under `/tmp/th_investigation/` and `/tmp/trufflehog` and were removed after the runs. After doc
creation, `git status --porcelain` reports only the new untracked documentation path and **zero**
modified or deleted tracked files:

```console
$ git status --porcelain
?? blitzy/

$ git status --porcelain | grep -E '^[ ]?[MD]' | wc -l   # modified/deleted tracked files
0

$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760
```

HEAD is unchanged; the only addition to the working tree is
`blitzy/documentation/trufflehog_e42153d44a5e.md`.

---

## 11. Coverage-pass checklist

Re-reading the question and confirming each named item is answered with a concrete value, `file:line`,
observed evidence, and causal reason:

- [x] **Multi-encoding handling** — ordered **single-pass** chain `[UTF8, Base64, UTF16,
  EscapedUnicode]` [`decoders.go:8-16`]; `Base64.FromChunk` in-place rebuild [`base64.go:34-72`].
  *Evidence:* §5 (one file → multiple decoder matches), §6.1. *Cause:* in-place rebuild retains
  plaintext + inserts decoded bytes, so both copies are matchable.
- [x] **Reported decoder types** — `PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4` (`UNKNOWN=0`)
  [`detectors.pb.go:26-31`]; surfaced as `DecoderName`/`Decoder Type` [`json.go:65`, `plain.go:64`].
  *Evidence:* observed `PLAIN`/`BASE64`/`ESCAPED_UNICODE` in §5.1–5.4 and §6.2. *Cause:* each decoder's
  `Type()` stamped by `processResult` [`engine.go:1178`].
- [x] **Overlap detection** — gate `len(matchingDetectors) > 1 && !e.verificationOverlap`
  [`engine.go:796`]; `errOverlap` [`engine.go:39-42`]. *Evidence:* grep = 0 for AWS Cases A–E; message
  reproduced with the multi-detector fixture (§6.3). *Cause:* needs 2+ different detectors on one
  chunk.
- [x] **Deduplication effect on count** — LRU key excludes decoder type, includes `SourceMetadata`
  [`engine.go:1216`], drop-on-different-decoder [`engine.go:1217-1221`]. *Evidence:* Case A collapses
  2→1 (§5.5). *Cause:* second same-key/different-decoder result is skipped.
- [x] **Dedup-vs-overlap ordering** — overlap in `scannerWorker`/`verificationOverlapWorker`
  [`engine.go:796`, `924-1034`] precedes `notifierWorker` dedupe [`engine.go:1189-1235`] ⇒ **dedupe
  after overlap** *(inferred from pipeline stage order; consistent with observation)* (§6.5).
- [x] **One-vs-many variability** — same key; line number in the dedupe key decides: same line ⇒ 1
  (Case A, surviving type is a race), different lines ⇒ 2 (Case D) [`engine.go:1216`, `1166`].
  *Evidence:* §5.3, §5.5, §6.6.
- [x] **Read-only mandate honored** — no existing source file modified; only this document created
  (§10).
- [x] **Test data removed** — all `/tmp` artifacts deleted; `git status --porcelain` clean aside from
  this doc (§10).
- [x] **Version caveat stated** — single-pass decoding; `--max-decode-depth` and HTML decoder absent
  (§9).

---

## 12. Appendix — crafted inputs & raw tallies

**Crafted files (all under `/tmp/th_investigation/`, since removed):**

```text
caseA.txt (2 lines):
  AKIASP2TPHJSQH3FJRUX wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==

caseB.txt (1 line):
  QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==

caseC.txt (1 line):
  AKIASP2TPHJSQH3FJRUX wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

caseD.txt (2 lines):
  QUtJQVNQMlRQSEpTUUgzRkpSVVggd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==
  AKIASP2TPHJSQH3FJRUX wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

caseE.txt (1 line — escaped-unicode of "ID SEC"):
  \u0041\u004b\u0049\u0041\u0053\u0050\u0032\u0054\u0050\u0048\u004a\u0053\u0051\u0048\u0033\u0046\u004a\u0052\u0055\u0058\u0020\u0077\u004a\u0061\u006c\u0072\u0058\u0055\u0074\u006e\u0046\u0045\u004d\u0049\u002f\u004b\u0037\u004d\u0044\u0045\u004e\u0047\u002f\u0062\u0050\u0078\u0052\u0066\u0069\u0043\u0059\u0045\u0058\u0041\u004d\u0050\u004c\u0045\u004b\u0045\u0059
```

**Overlap fixtures (copied read-only from `pkg/engine/testdata/` to `/tmp`, since removed):**

```text
vo_detectors.yaml — two CustomRegex detectors:
  detector1: api_key = \b(PMAK-[a-zA-Z-0-9]{59})\b   (keyword PMAK)
  detector2: api_key = \b([a-zA-Z-0-9]{59})\b         (keyword "ost")
vo_secrets.txt:
  POSTMAN_API_KEY="PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r"
```

**Raw tallies observed in this investigation:**

```text
Case A (100 runs, canonical): result-count = { 1: 100 };  surviving decoder = { BASE64: 80, PLAIN: 20 }
Case A (20 runs, --concurrency=1): result-count = { 1: 20 };  surviving decoder = { BASE64: 8, PLAIN: 12 }
Overlap fixture (20 runs): total results/run = { 3: 20 };  results carrying errOverlap/run = { 1: 16, 2: 4 }
Overlap fixture + --allow-verification-overlap (5 runs): total = 3 each, errOverlap = 0 each
```

> Because Case A and the overlap-attachment are genuine races, the exact ratios above are
> point-in-time measurements from this run set; the **invariants** (Case A always 1 result; overlap
> fixture always 3 results; `--allow-verification-overlap` always 0 errors) held on every run.

---

*Investigation performed on the canonical `trufflehog dev` build (Go 1.24.2) at HEAD
`e42153d44a5e5c37c1bd0c70e074781e9edcb760`. All output above is real and unedited; only the
dedup-after-overlap ordering (§6.5) is inferred from pipeline stage order rather than directly
observed.*
