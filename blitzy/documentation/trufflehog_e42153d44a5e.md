# Decoder Pipeline, Cross-Detector Overlap, and Cross-Decoder Deduplication in TruffleHog

## Scenario and thesis

A user scanned a single file that contained the **same AWS access key twice** — once as raw text and once as a Base64‑encoded copy — and saw inconsistent output: sometimes the secret was reported twice with different decoder types, sometimes an "overlap" error appeared, and sometimes the results collapsed to one. This document explains, from **observed runtime behavior**, why the output varies.

The confusion comes from conflating **two independent mechanisms** that the codebase deliberately keeps separate. This distinction is the thesis of the entire document:

- **Cross‑DETECTOR overlap detection (Stage 3).** Fires when **more than one detector** matches the *same decoded chunk*. It is implemented in `verificationOverlapWorker` via the `likelyDuplicate` helper; on a match it attaches the `errOverlap` verification error and **disables verification**. It prints the console line *"Verification issue: More than one detector has found this result…"*. **It does not delete a result** — both results are still emitted.
- **Cross‑DECODER LRU deduplication (Stage 4).** Fires inside `notifierWorker`. An LRU cache keyed on `DetectorType + Raw + RawV2 + SourceMetadata` **drops a later result whose only difference from an earlier one is its `DecoderType`**. This is what actually **removes** a result and collapses "the same secret reported twice" to a single line.

These two stages run in a fixed architectural order: **overlap detection (Stage 3) always runs before LRU deduplication (Stage 4).**

> **Pin‑to‑commit note.** Everything below describes the pinned `HEAD` only. Iterative / chained decoding (`--max-decode-depth`) **does not exist at this commit** — a source‑wide search for `max-decode-depth` / `maxDecodeDepth` / `DecodeDepth` returns zero matches — so the decoder stage is a **single pass** over `DefaultDecoders()` (`pkg/engine/engine.go:784`). No iterative decoding is attributed to this version.

---

## Environment & build

All investigation artifacts (the binary, crafted inputs, and custom‑detector YAML) were created **outside** the repository tree, under `/tmp/th-investigation`, and deleted afterward, so the source tree is left byte‑for‑byte unchanged (see the *Read‑only compliance* section).

The binary was built with the project's documented Go toolchain (`toolchain go1.24.2`, `go.mod:5`; language level `go 1.23.1`, `go.mod:3`; module `github.com/trufflesecurity/trufflehog/v3`, `go.mod:1`):

```
# command
CGO_ENABLED=0 go build -o /tmp/th-investigation/trufflehog .

# self-reported version (build evidence)
$ /tmp/th-investigation/trufflehog --version
trufflehog dev
```

The fake, high‑entropy credential used throughout (real "EXAMPLE" keys such as `AKIAIOSFODNN7EXAMPLE` are dropped as wordlist false positives):

- **ID** = `AKIAWTNVF3N27L9HX6D3` — Shannon entropy ≈ **4.022**, clears `RequiredIdEntropy = 3.0` (`pkg/detectors/aws/common.go:6`).
- **SECRET** = `zeSwzZZQ1MD9YuS6DqmeHNKcAPNROmsC6ZuYNBYJ` — Shannon entropy ≈ **4.615**, clears `RequiredSecretEntropy = 4.25` (`pkg/detectors/aws/common.go:7`) and matches the secret pattern `([A-Za-z0-9+/]{40})` (`pkg/detectors/aws/common.go:10`).

Because these fake keys are unverifiable, scans use `--no-verification` (`main.go:59`) or `--results=verified,unverified,unknown` (`main.go:61`). The AWS access‑key detector requires **both** an ID match and a secret match — the result is only emitted inside the `for secretMatch := range secretMatches` loop (`pkg/detectors/aws/access_keys/accesskey.go:131`) — so every crafted input contains both.

---

## Sub‑part 1 — How the pipeline handles the same secret in plain text, Base64, and escaped Unicode

### The single‑pass decoder chain

Each chunk of source data is run once through an **ordered chain of decoders**. The chain is assigned once at engine construction, `e.decoders = decoders.DefaultDecoders()` (`pkg/engine/engine.go:358`), and `DefaultDecoders()` returns exactly four decoders in this order (`pkg/decoders/decoders.go:8-16`):

```go
// pkg/decoders/decoders.go:8-16
func DefaultDecoders() []Decoder {
	return []Decoder{
		// UTF8 must be first for duplicate detection
		&UTF8{},
		&Base64{},
		&UTF16{},
		&EscapedUnicode{},
	}
}
```

The comment *"UTF8 must be first for duplicate detection"* (`pkg/decoders/decoders.go:10`) is significant — it establishes the intended order in which the plain and decoded copies are seen. The chunk is passed through this slice in a **single `for` loop** in `scannerWorker` — `for _, decoder := range e.decoders` (`pkg/engine/engine.go:784`) — and the output of a decoder is **not** fed back into the chain (single pass, no recursion).

Each decoder implements the `Decoder` interface (`pkg/decoders/decoders.go:25-28`): `FromChunk(chunk *sources.Chunk) *DecodableChunk` and `Type() detectorspb.DecoderType`. The result is wrapped in a `DecodableChunk` (`pkg/decoders/decoders.go:20-23`), which embeds the chunk plus a `DecoderType` label.

### The critical difference: which decoders mutate the shared chunk vs. clone it

The reason the *same logical secret* behaves differently across encodings is that the decoders differ in **whether they mutate the shared chunk buffer in place or clone it**:

- **UTF8 (`DecoderType_PLAIN`)** — sanitizes the shared chunk **in place** when the bytes are not valid UTF‑8. Guard `if !utf8.Valid(chunk.Data)` (`pkg/decoders/utf8.go:23`) then `chunk.Data = extractSubstrings(chunk.Data)` (`pkg/decoders/utf8.go:24`). For already‑valid UTF‑8 it passes the bytes through unchanged.
- **Base64 (`DecoderType_BASE64`)** — finds Base64 candidate runs of **≥ 20 chars** (`getSubstringsOfCharacterSet(chunk.Data, 20, …)`, `pkg/decoders/base64.go:36`), decodes them, and **substitutes the decoded bytes in place** within the chunk: `chunk.Data = result.Bytes()` (`pkg/decoders/base64.go:67`). This in‑place substitution is exactly why a single decoded chunk can carry **both** a plain copy and a decoded‑from‑Base64 copy of the id — and, crucially, why the decoded id lands at the *byte position where the Base64 blob was* (relevant to Sub‑part 6).
- **UTF16 (`DecoderType_UTF16`)** — converts UTF‑16, keeping only printable bytes via `isPrintableByte` (used at `pkg/decoders/utf16.go:40` and `pkg/decoders/utf16.go:45`; defined at `pkg/decoders/utf8.go:85` as `func isPrintableByte(c byte) bool { return c > 31 && c < 127 }`).
- **EscapedUnicode (`DecoderType_ESCAPED_UNICODE`)** — the only decoder that **clones** rather than mutates: `chunkData = bytes.Clone(chunk.Data)` (`pkg/decoders/escaped_unicode.go:39`), decodes `\uXXXX` / `U+XXXX` sequences (patterns `codePointPat` and `escapePat`, `pkg/decoders/escaped_unicode.go:22-25`), and returns a brand‑new `Chunk` that preserves `SourceMetadata` and friends (`pkg/decoders/escaped_unicode.go:54-63`).

### Evidence — plain text → `PLAIN`

Input `plain.txt`:
```
aws_access_key_id = AKIAWTNVF3N27L9HX6D3
aws_secret_access_key = zeSwzZZQ1MD9YuS6DqmeHNKcAPNROmsC6ZuYNBYJ
```

```
# command
$ /tmp/th-investigation/trufflehog filesystem plain.txt --no-verification

# verbatim output
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWTNVF3N27L9HX6D3
Resource_type: Access key
File: plain.txt
Line: 1
… "chunks": 1, … "unverified_secrets": 1, … "trufflehog_version": "dev" …
```

The `UTF8` decoder passes valid UTF‑8 through unchanged, and the AWS detector matches the plain id → **`Decoder Type: PLAIN`**.

### Evidence — Base64 → `BASE64`

Input `b64.txt` contains only `credential_blob = ` followed by the Base64 of the string `"AKIAWTNVF3N27L9HX6D3 zeSwzZZQ1MD9YuS6DqmeHNKcAPNROmsC6ZuYNBYJ"`:
```
credential_blob = QUtJQVdUTlZGM04yN0w5SFg2RDMgemVTd3paWlExTUQ5WXVTNkRxbWVITktjQVBOUk9tc0M2WnVZTkJZSg==
```

```
# command
$ /tmp/th-investigation/trufflehog filesystem b64.txt --no-verification

# verbatim output
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIAWTNVF3N27L9HX6D3
Resource_type: Access key
File: b64.txt
Line: 1
```

The plain bytes contain no `AKIA…` id, so `UTF8`/`PLAIN` matches nothing; the `Base64` decoder decodes the blob in place, after which the AWS detector matches → **`Decoder Type: BASE64`**.

### Evidence — escaped Unicode → `ESCAPED_UNICODE`

Input `escaped.txt` encodes both the id and secret as `\uXXXX` sequences (so nothing matches until the `EscapedUnicode` decoder runs). The escaped id is `\u0041\u004b\u0049\u0041\u0057\u0054\u004e\u0056\u0046\u0033\u004e\u0032\u0037\u004c\u0039\u0048\u0058\u0036\u0044\u0033`.

```
# command
$ /tmp/th-investigation/trufflehog filesystem escaped.txt --no-verification

# verbatim output
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: ESCAPED_UNICODE
Raw result: AKIAWTNVF3N27L9HX6D3
Resource_type: Access key
File: escaped.txt
Line: 1
```

The `escapePat` regex `(?i:\\{1,2}u)([a-fA-F0-9]{4})` (`pkg/decoders/escaped_unicode.go:25`) matches the `\u00XX` sequences; the decoder clones the buffer and decodes them, and the AWS detector then matches → **`Decoder Type: ESCAPED_UNICODE`**.

### Evidence — UTF‑16 → `UTF16` (fourth enum value, for completeness)

Input `utf16le.txt` is `key <ID> secret <SECRET> end` encoded **UTF‑16LE, no BOM, space separators**:

```
# command
$ /tmp/th-investigation/trufflehog filesystem utf16le.txt --no-verification

# verbatim output
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: UTF16
Raw result: AKIAWTNVF3N27L9HX6D3
Resource_type: Access key
File: utf16le.txt
Line: 1
```

**Two UTF‑16 "gotchas" — reported exactly as observed (both yield 0 results):**

*(a) A UTF‑16 BOM destroys the hit.* Prepending the BOM `0xFF 0xFE` makes the bytes invalid UTF‑8, so the **first** decoder (`UTF8`) hits its guard `if !utf8.Valid(chunk.Data)` (`pkg/decoders/utf8.go:23`) and sanitizes the shared buffer with `extractSubstrings` (`pkg/decoders/utf8.go:24`), destroying the UTF‑16 structure before the `UTF16` decoder ever sees it:

```
# input hexdump head (BOM ff fe present)
00000000  ff fe 6b 00 65 00 79 00  20 00 41 00 4b 00 49 00  |..k.e.y. .A.K.I.|

# command
$ /tmp/th-investigation/trufflehog filesystem utf16_bom.txt --no-verification --json | grep -c DetectorName
0
# "unverified_secrets": 0
```

*(b) Non‑printable separators break the word boundary.* With **newline** separators (`0x0A`), the `UTF16` decoder drops the newline via `isPrintableByte` (`0x0A = 10`, not `> 31`), so `key` concatenates onto the id and the AWS `idPat` `\b(…)\b` word boundary (`pkg/detectors/aws/access_keys/accesskey.go:65`) no longer matches:

```
# input hexdump head (no BOM; 0x0a newline after "key")
00000000  6b 00 65 00 79 00 0a 00  41 00 4b 00 49 00 41 00  |k.e.y...A.K.I.A.|

# command
$ /tmp/th-investigation/trufflehog filesystem utf16_newline.txt --no-verification --json | grep -c DetectorName
0
# "unverified_secrets": 0
```

This is why the working UTF‑16 input above uses *no BOM* and *space* separators (space is `0x20 = 32`, which **is** printable under `isPrintableByte`).

---

## Sub‑part 2 — Which decoder types are reported

The reported label is the `DecoderType` enum, defined canonically in the protobuf (`proto/detectors.proto:7-13`):

```proto
// proto/detectors.proto:7-13
enum DecoderType {
  UNKNOWN = 0;
  PLAIN = 1;
  BASE64 = 2;
  UTF16 = 3;
  ESCAPED_UNICODE = 4;
}
```

Each decoder returns its own value from `Type()`:

| Enum value | `file:line` of the value | `file:line` of the `Type()` that returns it | Observed `Decoder Type:` line |
|---|---|---|---|
| `UNKNOWN = 0` | `proto/detectors.proto:8` | — (zero/default; not emitted for a decoded hit) | *(never seen on a hit)* |
| `PLAIN = 1` | `proto/detectors.proto:9` | `pkg/decoders/utf8.go:12-13` | `Decoder Type: PLAIN` |
| `BASE64 = 2` | `proto/detectors.proto:10` | `pkg/decoders/base64.go:30-31` | `Decoder Type: BASE64` |
| `UTF16 = 3` | `proto/detectors.proto:11` | `pkg/decoders/utf16.go:14-15` | `Decoder Type: UTF16` |
| `ESCAPED_UNICODE = 4` | `proto/detectors.proto:12` | `pkg/decoders/escaped_unicode.go:28-29` | `Decoder Type: ESCAPED_UNICODE` |

The label is stamped onto the result late in the pipeline, in `detectChunk`: `secret.DecoderType = data.decoder` (`pkg/engine/engine.go:1178`). Every one of the four `Decoder Type:` lines was observed verbatim in Sub‑part 1 (`PLAIN`, `BASE64`, `ESCAPED_UNICODE`, `UTF16`).

`DecoderType_UNKNOWN = 0` (`proto/detectors.proto:8`) is the zero/default value and was **never** observed on a decoded hit — every result carried one of the four concrete labels above.

---

## Sub‑part 3 — Whether and when cross‑detector overlap detection occurs

Overlap detection is **cross‑DETECTOR**: it only becomes relevant when **more than one detector** matches the *same decoded chunk*. The gate is in `scannerWorker`: `if len(matchingDetectors) > 1 && !e.verificationOverlap` (`pkg/engine/engine.go:796`), which routes such chunks to the `verificationOverlapChunksChan` (`pkg/engine/engine.go:798`) and thence to `verificationOverlapWorker` (`pkg/engine/engine.go:924`).

Inside that worker, for each result it builds a comparison string — `val = RawV2` if present, else `Raw` (`pkg/engine/engine.go:966-971`) — wraps it in a `chunkSecretKey` (`pkg/engine/engine.go:977`), and calls `likelyDuplicate` (`pkg/engine/engine.go:982`, defined `pkg/engine/engine.go:887`). On a positive result it attaches `errOverlap`: `res.SetVerificationError(errOverlap)` (`pkg/engine/engine.go:988`). The error text lives at `pkg/engine/engine.go:39-41`.

### Evidence — overlap DOES fire (two different detector types on one chunk)

`overlap.txt` = `cred = AKIAWTNVF3N27L9HX6D3:zeSwzZZQ1MD9YuS6DqmeHNKcAPNROmsC6ZuYNBYJ`. A custom detector `OverlapProbe` (keyword `AKIA`, regex `(AKIA[A-Z0-9]{16}:[A-Za-z0-9+/]{40})`) captures the same `id:secret` string, so its `Raw` (~61 chars) closely matches the AWS `RawV2` (`idMatch + ":" + secretMatch`, `pkg/detectors/aws/access_keys/accesskey.go:140`).

```
# command
$ /tmp/th-investigation/trufflehog filesystem overlap.txt --config custom.yaml --results=verified,unverified,unknown

# verbatim console output
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: CustomRegex
Decoder Type: PLAIN
Detector Type: AWS
Decoder Type: PLAIN
… "unverified_secrets": 2 …
```

Note the exact literal `disabled.You` with **no space** — an artifact of the two‑line string concatenation at `pkg/engine/engine.go:40-41`. Also note the count is still **2**: overlap **disables verification, it does not delete a result**.

The machine‑readable view confirms the error lands on exactly **one** of the two detectors:

```
# command
$ /tmp/th-investigation/trufflehog filesystem overlap.txt --config custom.yaml --results=verified,unverified,unknown --json

# parsed verbatim
DetectorName=CustomRegex  VerificationError='More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.'
DetectorName=AWS          VerificationError=None
```

Which detector receives `errOverlap` depends on **which is processed second** (the results are iterated from a map, so it is iteration‑order dependent). In this run it was `CustomRegex`; `AWS` came through clean.

### Evidence — three conditions under which overlap does NOT fire

**(a) The `--allow-verification-overlap` flag.** The flag is defined at `main.go:65` (help text: *"Allow verification of similar credentials across detectors"*). When set, `e.verificationOverlap` is true, so the gate `len(matchingDetectors) > 1 && !e.verificationOverlap` (`pkg/engine/engine.go:796`) is false and the chunk bypasses the overlap worker entirely:

```
# command
$ /tmp/th-investigation/trufflehog filesystem overlap.txt --config custom.yaml --results=verified,unverified,unknown --allow-verification-overlap

# verbatim: 'Verification issue' lines = 0 ; "unverified_secrets": 2
```

**(b) Same detector type is skipped.** `likelyDuplicate` skips any pair sharing a detector type — `if val.detectorKey.Type() == dupeKey.detectorKey.Type() { continue }` (`pkg/engine/engine.go:900`). All custom detectors emit `DetectorType_CustomRegex` (`pkg/custom_detectors/custom_detectors.go:199`, `Raw`‑only at `:201`, `Type()` at `:346`), so two custom detectors matching one string never overlap. Input `sametype.txt` scanned with two `CustomRegex` detectors (`sametype.yaml`):

```
# command
$ /tmp/th-investigation/trufflehog filesystem sametype.txt --config sametype.yaml --results=verified,unverified,unknown --json | grep -c DetectorName
2
# console: 'Verification issue' lines = 0
```

**(c) The length gate.** Before any similarity is computed, `likelyDuplicate` rejects pairs whose lengths differ by more than ~10%: `if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 { continue }` (`pkg/engine/engine.go:894`). A custom detector `IdOnlyProbe` capturing only the 20‑char id (`(AKIA[A-Z0-9]{16})`) versus the AWS `RawV2` (~61 chars, `id:secret`) is outside the band (`20*10 = 200 < 61*9 = 549`), so the comparison is skipped:

```
# command
$ /tmp/th-investigation/trufflehog filesystem overlap.txt --config idonly.yaml --results=verified,unverified,unknown --json | grep -c DetectorName
2
# console: 'Verification issue' lines = 0
```

When the length gate and same‑type checks are both passed and the strings are close, similarity is measured with Levenshtein distance — `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())` (`pkg/engine/engine.go:911`, backed by `github.com/adrg/strutil v0.3.1`, `go.mod:19`) — and overlap fires when `similarity > similarityThreshold`, where `const similarityThreshold = 0.9` (`pkg/engine/engine.go:888`, compared at `:914`). Exact matches short‑circuit to `true` (`if valStr == dupe`, `pkg/engine/engine.go:904`).

**Summary:** overlap fires only when (1) more than one detector matches the same chunk, (2) the two detectors are of **different** types, (3) their comparison strings are within ~10% length of each other, and (4) their Levenshtein similarity exceeds `0.9` — and it is **not** suppressed by `--allow-verification-overlap`.


---

## Sub‑part 4 — How deduplication affects the final result count

Deduplication is **cross‑DECODER** and lives in the final stage, `notifierWorker` (`pkg/engine/engine.go:1189`). It uses a shared LRU cache, `dedupeCache *lru.Cache[string, detectorspb.DecoderType]` (`pkg/engine/engine.go:209`), sized `const cacheSize = 512` (`pkg/engine/engine.go:491`, backed by `github.com/hashicorp/golang-lru/v2 v2.0.7`, `go.mod:64`).

The intent is stated in a comment block (`pkg/engine/engine.go:1210-1215`): *dedupe by detector type + raw result + source metadata, deliberately dropping duplicates that differ **only** by decoder type.* The key and skip logic:

```go
// pkg/engine/engine.go:1216-1221
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
	result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
	continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

So the key is `DetectorType + Raw + RawV2 + SourceMetadata`. For the *same logical secret* found by two decoders, `DetectorType`, `Raw`, and `RawV2` are **identical**; the only thing that can differ in the key is the `SourceMetadata` (which includes the **line number**). If the keys collide, the second result is dropped (`continue`) because its `DecoderType` differs from the cached one — collapsing **2 → 1**.

### Evidence — collapse to one (same line)

`adjacent.txt` has the raw id+secret on line 1 and the Base64 blob on line 2:

```
# command
$ /tmp/th-investigation/trufflehog filesystem adjacent.txt --no-verification --json

# parsed verbatim (repeatable): RESULT COUNT = 1
RESULT COUNT = 1
 -> Detector=AWS  Decoder=PLAIN  Line=1
```

`far.txt` has the raw id+secret on line 1, then 20 blank lines, then the Base64 blob on line 22:

```
# command
$ /tmp/th-investigation/trufflehog filesystem far.txt --no-verification --json

# parsed verbatim (repeatable): RESULT COUNT = 1
RESULT COUNT = 1
 -> Detector=AWS  Decoder=BASE64  Line=1
```

In both, the `PLAIN` and `BASE64` results resolve the id to **line 1** (see Sub‑part 6 for why), so the keys collide and the count deduplicates to **1**. Across 12 repetitions each, `adjacent.txt` and `far.txt` **always** returned exactly one result.

### Evidence — no collapse (different lines) → count stays 2

`b64first_far.txt` has the Base64 blob on line 1, 20 blank lines, then the raw id+secret on line 22:

```
# command
$ /tmp/th-investigation/trufflehog filesystem b64first_far.txt --no-verification --json

# parsed verbatim (stable across 12 runs): RESULT COUNT = 2
RESULT COUNT = 2
 -> Detector=AWS  Decoder=BASE64  Line=1
 -> Detector=AWS  Decoder=PLAIN   Line=22
```

Here the two results resolve to **different lines** (1 vs 22), so their `SourceMetadata` differs, the keys differ, and both survive — the count stays **2**.

> **Distinction from overlap (Sub‑part 3).** Deduplication actually **removes** a result (2 → 1). Overlap detection does **not** — in the overlap evidence the count remained 2; overlap only attaches `errOverlap` and disables verification.

---

## Sub‑part 5 — Whether deduplication happens before or after overlap detection

**Deduplication always runs after overlap detection.** This is architectural, not incidental. The pipeline is a fixed sequence of worker stages, and this ordering is already documented in the repository's own `docs/concurrency.md` (participants created in order: `ScannerWorkers` → `VerificationOverlapWorkers` → `DetectorWorkers` → `NotifierWorkers`, `docs/concurrency.md:10-19`).

The flow for a chunk matched by multiple detectors:

1. **`scannerWorker`** (`pkg/engine/engine.go:777`) runs the single decoder pass (`:784`), calls `FindDetectorMatches` (`:795`), and on `len(matchingDetectors) > 1 && !e.verificationOverlap` (`:796`) forwards to `verificationOverlapChunksChan` (`:798`).
2. **Stage 3 — `verificationOverlapWorker`** (`pkg/engine/engine.go:924-1034`) runs `likelyDuplicate` and, on a match, sets `errOverlap` (`:988`), then forwards to `detectableChunksChan` (`:1014`).
3. **`detectorWorker` / `detectChunk`** (`pkg/engine/engine.go:1036` / `:1044`) run the detectors and stamp `secret.DecoderType = data.decoder` (`:1178`), sending results to `e.results`.
4. **Stage 4 — `notifierWorker`** (`pkg/engine/engine.go:1189`) applies the LRU dedup (`:1216-1221`).

The `Finish()` teardown (`pkg/engine/engine.go:723`) proves the notifier/dedup stage is **last** by waiting on the stages in order: `e.workersWg.Wait()` (`:728`) → `e.wgDetectorWorkers.Wait()` (`:734`) → `close(e.results)` (`:736`) → `e.WgNotifier.Wait()` (`:737`). The notifier cannot finish until after the detector workers (which are themselves fed by the overlap worker) are done.

```mermaid
flowchart TD
    A["Chunk (source data)"] --> B["scannerWorker: single decoder pass<br/>UTF8 → Base64 → UTF16 → EscapedUnicode<br/>engine.go:784"]
    B --> C["FindDetectorMatches (Aho-Corasick)<br/>engine.go:795"]
    C --> D{"len(matchingDetectors) &gt; 1<br/>&amp;&amp; !e.verificationOverlap ?<br/>engine.go:796"}
    D -- "Yes" --> E["STAGE 3: verificationOverlapWorker<br/>likelyDuplicate → SetVerificationError(errOverlap)<br/>engine.go:924-1034 (:988)"]
    D -- "No" --> F["detectorWorker / detectChunk<br/>stamps secret.DecoderType = data.decoder<br/>engine.go:1178"]
    E --> F
    F --> G["STAGE 4: notifierWorker<br/>LRU dedup key = DetectorType+Raw+RawV2+SourceMetadata<br/>engine.go:1216-1221"]
    G --> H["Emitted results"]
```

**Ordering answer:** overlap detection is Stage 3; LRU deduplication is Stage 4; **dedup runs after overlap detection**.

---

## Sub‑part 6 — Why the same logical secret sometimes yields one result and sometimes many

The crux is that the dedup key includes `SourceMetadata`, i.e. the **line number** (`pkg/engine/engine.go:1216`). The reported line is the **first occurrence** of the id within each decoder's (possibly rewritten) chunk. Because the `Base64` decoder **substitutes decoded bytes in place** (`chunk.Data = result.Bytes()`, `pkg/decoders/base64.go:67`), the decoded id lands at the byte position where the Base64 blob was. So the line the id resolves to depends on **where the encodings sit relative to each other**:

- **Raw appears first / on the same line as the blob** (`adjacent.txt`, `far.txt`): the `PLAIN` result finds the raw id at line 1; the `BASE64` result's chunk still contains that same raw id at line 1 (plus the decoded copy later). Both resolve to **line 1** → identical dedup keys → the later result is dropped → **1 result**. Because `UTF8` is first in the chain (`pkg/decoders/decoders.go:10`, *"UTF8 must be first for duplicate detection"*), this "same line ⇒ collapse" is the intended design.

  ```
  # far.txt (raw line 1, blob line 22) — repeatable
  RESULT COUNT = 1
  ```

- **Base64 blob appears first, raw far below** (`b64first_far.txt`): the `PLAIN` result finds the raw id only at **line 22** (the blob at line 1 is not valid `AKIA…` text), while the `Base64` decoder's in‑place substitution puts the decoded id at **line 1**. Different lines → different `SourceMetadata` → different keys → **both survive → 2 results**.

  ```
  # b64first_far.txt (blob line 1, raw line 22) — stable across 12 runs
  RESULT COUNT = 2
   -> Decoder=BASE64  Line=1
   -> Decoder=PLAIN   Line=22
  ```

So the **result count** is deterministic and is governed entirely by whether the two encodings resolve the id to the *same* line (collapse to 1) or *different* lines (stay at 2).

### An observed nuance: which decoder survives the collapse is non‑deterministic

The AAP dossier predicted that when the count collapses to 1 the survivor is deterministically `PLAIN` (because `UTF8` is first in the decoder chain). **My runtime observation differs, and per the "report exactly what is observed" rule I record it here:** the *count* is deterministic (always 1 for the same‑line cases), but the *surviving decoder label* is **not**.

```
# adjacent.txt — survivor decoder over 12 runs (count:decoder)
      8   1:BASE64
      4   1:PLAIN
# far.txt — survivor decoder over 12 runs
     10   1:BASE64
      2   1:PLAIN
```

The cause is concurrency downstream of the single decoder pass. The engine spawns `numWorkers := e.concurrency * e.detectorWorkerMultiplier` detector workers (`pkg/engine/engine.go:676`) with `detectorWorkerMultiplier` defaulting to `8` (`pkg/engine/engine.go:345`) — i.e. 32 workers on this 4‑core host — feeding a shared `e.results` channel drained by `numWorkers := e.notificationWorkerMultiplier * e.concurrency` notifier workers (`pkg/engine/engine.go:706`), with `notificationWorkerMultiplier` defaulting to `1` (`pkg/engine/engine.go:349`) — i.e. 4 notifier workers sharing one `dedupeCache`. The LRU keeps whichever result with a given key is **added first** (`e.dedupeCache.Add(key, result.DecoderType)`, `pkg/engine/engine.go:1221`); since the arrival order across concurrent workers is a race, the surviving `DecoderType` (`PLAIN` vs `BASE64`) varies run‑to‑run. This does not change the user‑visible answer to "one vs many" — the **count** is what the dedup key determines, and that remains deterministic.


---

## Related detector detail — AWS access key vs. session key, and custom detectors

- **AWS access‑key detector** (`pkg/detectors/aws/access_keys/accesskey.go`): id pattern `idPat = \b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` (`:65`); keywords `"AKIA"` (`:72`), `"ABIA"` (`:73`), `"ACCA"` (`:74`) declared by `Keywords()` (`:70`); emits `DetectorType_AWS` (`:137`) with `Raw = []byte(idMatch)` (`:138`) and `RawV2 = []byte(idMatch + ":" + secretMatch)` (`:140`). The `RawV2` length is exactly what the overlap length gate compares. The `Resource_type: Access key` line observed on every AWS hit comes from `"AKIA": "Access key"` (`pkg/detectors/aws/utils.go:24`).
- **AWS session‑key detector** (`pkg/detectors/aws/session_keys/sessionkey.go`): a *distinct* detector with `idPat = \b((?:ASIA)[A-Z0-9]{16})\b` (`:61`) and keyword `["ASIA"]` (`:68`) that emits a **different** type, `DetectorType_AWSSessionKey` (`:116`, `:301`) — labeled `"Temporary (AWS STS) access key IDs"` (`pkg/detectors/aws/utils.go:30`). Being a different detector type from `DetectorType_AWS`, an ASIA hit and an AKIA hit are not skipped by the same‑type rule, but the `ASIA`/`AKIA` prefixes mean they never match the same id string in practice.
- **Custom detectors** (`pkg/custom_detectors/custom_detectors.go`): `FromData` at `:64`; every custom detector emits `DetectorType_CustomRegex` (`:199`, `Type()` at `:346`) and sets only `Raw = []byte(raw)` (`:201`) with no `RawV2`. This is why two custom detectors never overlap each other (same‑type skip, Sub‑part 3b) and why the overlap comparison for a custom detector uses its `Raw` (there is no `RawV2` to prefer).

---

## Coverage pass

Every named item from the question is addressed:

- [x] **Named encoded form — plain text** → `Decoder Type: PLAIN` (Sub‑part 1; `pkg/decoders/utf8.go:12-13`).
- [x] **Named encoded form — base64** → `Decoder Type: BASE64` (Sub‑part 1; `pkg/decoders/base64.go:30-31`, in‑place substitution `:67`).
- [x] **Named encoded form — escaped unicode** → `Decoder Type: ESCAPED_UNICODE` (Sub‑part 1; `pkg/decoders/escaped_unicode.go:28-29`, clone `:39`).
- [x] **UTF16 (4th enum, completeness)** → `Decoder Type: UTF16` plus the two 0‑result gotchas (BOM; non‑printable separators) (Sub‑part 1; `pkg/decoders/utf16.go:14-15`).
- [x] **DecoderType enum labels** including `UNKNOWN=0` never emitted (Sub‑part 2; `proto/detectors.proto:7-13`); stamp site `pkg/engine/engine.go:1178`.
- [x] **Single‑pass decoder chain** / no `--max-decode-depth` (Sub‑part 1 & pin note; `pkg/decoders/decoders.go:8-16`, loop `pkg/engine/engine.go:784`).
- [x] **`errOverlap`** message + when it fires (Sub‑part 3; `pkg/engine/engine.go:39-41`, `:988`).
- [x] **`likelyDuplicate`** with threshold `0.9` and Levenshtein (Sub‑part 3; `pkg/engine/engine.go:887`, `:888`, `:911`, `:914`).
- [x] **Length gate** (Sub‑part 3c; `pkg/engine/engine.go:894`).
- [x] **Same‑detector‑type skip** (Sub‑part 3b; `pkg/engine/engine.go:900`).
- [x] **`--allow-verification-overlap`** (Sub‑part 3a; `main.go:65`, gate `pkg/engine/engine.go:796`), **`--config`** (`main.go:70`), **`--results`** (`main.go:61`), **`--no-verification`** (`main.go:59`).
- [x] **LRU dedup key** = `DetectorType + Raw + RawV2 + SourceMetadata`; `cacheSize = 512` (Sub‑part 4; `pkg/engine/engine.go:1216`, `:1217`, `:1221`, `:491`).
- [x] **Ordering** — dedup after overlap (Sub‑part 5; `Finish()` wait chain `pkg/engine/engine.go:723/728/734/736/737`; `docs/concurrency.md:10-19`).
- [x] **One‑vs‑many** — line number inside dedup key + Base64 in‑place substitution + UTF8‑first (Sub‑part 6).
- [x] **AWS `idPat` / `Raw` / `RawV2`** (`pkg/detectors/aws/access_keys/accesskey.go:65`, `:138`, `:140`).
- [x] **AWS session‑key detector** (`pkg/detectors/aws/session_keys/sessionkey.go:61`, `:68`, `:116`).
- [x] **Custom detectors** (`pkg/custom_detectors/custom_detectors.go:199`, `:201`, `:346`).
- [x] **Pin‑to‑commit** — no iterative `--max-decode-depth` at this commit (zero source matches).
- [x] **Two mechanisms kept distinct** — overlap disables verification (count unchanged); dedup removes a result (2 → 1).

### Mapping back to the user's three observed symptoms

- *"Reported the secret twice with different decoder types"* → the two encodings resolved to **different lines**, producing distinct dedup keys so both survived (`b64first_far.txt` → 2 results: `BASE64` @ line 1, `PLAIN` @ line 22).
- *"Deduplicated down to a single result"* → the two encodings resolved to the **same line**, producing an identical dedup key so the later copy was dropped (`adjacent.txt` / `far.txt` → 1 result).
- *"An overlap error"* → a **second detector of a different type** matched the same chunk closely enough to trip `likelyDuplicate`, attaching `errOverlap` and printing *"Verification issue: More than one detector has found this result…"* (`overlap.txt` + custom detector).

---

## Read‑only compliance

All investigation artifacts — the compiled `trufflehog` binary, the crafted input files (`plain.txt`, `b64.txt`, `escaped.txt`, `utf16le.txt`, `utf16_bom.txt`, `utf16_newline.txt`, `overlap.txt`, `adjacent.txt`, `far.txt`, `b64first_far.txt`, `sametype.txt`) and the custom‑detector configs (`custom.yaml`, `idonly.yaml`, `sametype.yaml`) — were created under `/tmp/th-investigation`, **outside** the repository tree, and deleted after the investigation. The build used the committed `go.sum` in read‑only module mode (no `-mod=mod`), so neither `go.mod` nor `go.sum` was modified. No existing repository file was changed; the only addition to the repository is **this document**. A final `git status --porcelain` from the repository root shows only this new file (see the commit accompanying this document), confirming the source tree is otherwise byte‑for‑byte unchanged.

