# TruffleHog v3: Decoder Pipeline, Overlap Detection, and Deduplication Analysis

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Architecture Overview](#2-architecture-overview)
  - [2.1 Pipeline Stage Diagram](#21-pipeline-stage-diagram)
  - [2.2 Key Data Structures](#22-key-data-structures)
- [3. Decoder Pipeline Mechanics](#3-decoder-pipeline-mechanics)
  - [3.1 DefaultDecoders Ordering](#31-defaultdecoders-ordering)
  - [3.2 Scanner Worker Iteration](#32-scanner-worker-iteration)
  - [3.3 Individual Decoder Behavior](#33-individual-decoder-behavior)
  - [3.4 Critical: Chunk Data Mutation](#34-critical-chunk-data-mutation)
  - [3.5 Answer: Which DecoderType Values Are Attached to Results?](#35-answer-which-decodertype-values-are-attached-to-results)
- [4. Overlap Detection Logic](#4-overlap-detection-logic)
  - [4.1 Aho-Corasick Matching](#41-aho-corasick-matching)
  - [4.2 Routing Decision](#42-routing-decision)
  - [4.3 Verification Overlap Worker](#43-verification-overlap-worker)
  - [4.4 The likelyDuplicate Function](#44-the-likelyduplicate-function)
  - [4.5 Answer: When Does Overlap Detection Trigger?](#45-answer-when-does-overlap-detection-trigger)
- [5. Deduplication Behavior](#5-deduplication-behavior)
  - [5.1 Cache Structure](#51-cache-structure)
  - [5.2 Key Construction](#52-key-construction)
  - [5.3 Cache Check Logic](#53-cache-check-logic)
  - [5.4 Answer: How Does the Deduplication Cache Decide What to Keep?](#54-answer-how-does-the-deduplication-cache-decide-what-to-keep)
- [6. Pipeline Ordering (Temporal Sequence)](#6-pipeline-ordering-temporal-sequence)
  - [6.1 Stage-by-Stage Sequence](#61-stage-by-stage-sequence)
  - [6.2 Answer: Overlap Detection vs. Deduplication Ordering](#62-answer-overlap-detection-vs-deduplication-ordering)
- [7. Variable Result Count Explanation](#7-variable-result-count-explanation)
  - [7.1 Scenario A: Raw AWS Key Only](#71-scenario-a-raw-aws-key-only)
  - [7.2 Scenario B: Base64-Encoded AWS Key Only](#72-scenario-b-base64-encoded-aws-key-only)
  - [7.3 Scenario C: Both Raw and Base64-Encoded AWS Key](#73-scenario-c-both-raw-and-base64-encoded-aws-key)
  - [7.4 Concurrency and Timing Effects](#74-concurrency-and-timing-effects)
  - [7.5 Edge Cases](#75-edge-cases)
  - [7.6 Answer: Why Does the Same Secret Sometimes Produce Variable Result Counts?](#76-answer-why-does-the-same-secret-sometimes-produce-variable-result-counts)
- [8. Scenario Walkthroughs](#8-scenario-walkthroughs)
  - [8.1 Walkthrough A: File Contains Only the Raw AWS Key](#81-walkthrough-a-file-contains-only-the-raw-aws-key)
  - [8.2 Walkthrough B: File Contains Only the Base64-Encoded AWS Key](#82-walkthrough-b-file-contains-only-the-base64-encoded-aws-key)
  - [8.3 Walkthrough C: File Contains Both Raw and Base64-Encoded AWS Key](#83-walkthrough-c-file-contains-both-raw-and-base64-encoded-aws-key)
- [9. Appendix: Key Code References](#9-appendix-key-code-references)

---

## 1. Executive Summary

This document presents a detailed investigative analysis of three interconnected subsystems within the TruffleHog v3 secret scanner: the **decoder pipeline**, the **verification overlap detection mechanism**, and the **result deduplication cache**. The analysis is based entirely on the source code at the current repository commit and traces exact runtime behavior through specific code paths. No source files have been modified; this document is the sole deliverable.

The investigation was motivated by observed variations in output when scanning a file that contains the same AWS access key in multiple encoded forms (plain text and Base64). Five specific questions were posed and are answered herein:

1. **Decoder type reporting** — When the same secret appears in both raw and Base64-encoded form, the decoder pipeline produces results tagged with `DecoderType_PLAIN` (value 1) and `DecoderType_BASE64` (value 2). The UTF16 and EscapedUnicode decoders return `nil` for standard ASCII/UTF-8 input and do not contribute results. The decoder iteration order is fixed: UTF8 → Base64 → UTF16 → EscapedUnicode, as defined in `pkg/decoders/decoders.go:8-16`.

2. **Overlap detection trigger conditions** — The engine routes a decoded chunk through the `verificationOverlapChunksChan` path only when **more than one distinct detector** matches the same decoded chunk **and** the `--allow-verification-overlap` flag is not set (`pkg/engine/engine.go:796`). For a typical AWS key scan with default detectors, only a single detector (the AWS access key scanner) matches, so the overlap path is **not taken**.

3. **Deduplication behavior** — The LRU-based `dedupeCache` in the notifier worker (`pkg/engine/engine.go:1216-1221`) constructs its key from `DetectorType + Raw + RawV2 + SourceMetadata`, deliberately **excluding** `DecoderType`. When a key already exists in the cache and the stored `DecoderType` **differs** from the incoming result's `DecoderType`, the new result is suppressed. This means cross-decoder duplicates are dropped while same-decoder duplicates are permitted.

4. **Temporal ordering** — Overlap detection (in the `verificationOverlapWorker` at `engine.go:924-1034`) occurs **before** deduplication (in the `notifierWorker` at `engine.go:1189-1235`). The full pipeline order is: `scannerWorker` → `verificationOverlapWorker` (if applicable) → `detectorWorker` → `processResult` → `notifierWorker`. These are complementary mechanisms addressing different problems at different stages.

5. **Variable result count** — When both raw and Base64 forms of the same secret are present in a single file, both decoder passes produce results with identical deduplication keys but different `DecoderType` values. The deduplication cache suppresses the second arrival, yielding **one final result**. The specific `DecoderType` on that result depends on which decoder's result reaches the single `notifierWorker` goroutine first — a function of concurrency settings and goroutine scheduling. The `--allow-verification-overlap` CLI flag (`main.go:65`) controls the overlap path but does not affect this deduplication behavior.

---

## 2. Architecture Overview

### 2.1 Pipeline Stage Diagram

The high-level architecture is documented in `docs/process_flow.md` and referenced by `pkg/engine/engine.go:1-2`. The following Mermaid diagram details the internal stages relevant to this investigation:

```mermaid
flowchart TD
    A["Source Chunk<br/>(raw file data from e.ChunksChan())"] --> B["scannerWorker<br/>(engine.go:777-841)"]

    B --> C1["UTF8 Decoder<br/>(DecoderType_PLAIN)"]
    B --> C2["Base64 Decoder<br/>(DecoderType_BASE64)"]
    B --> C3["UTF16 Decoder<br/>(DecoderType_UTF16)"]
    B --> C4["EscapedUnicode Decoder<br/>(DecoderType_ESCAPED_UNICODE)"]

    C1 -->|"non-nil"| D1["FindDetectorMatches<br/>(ahocorasickcore.go:241-285)"]
    C2 -->|"non-nil if Base64 found"| D2["FindDetectorMatches<br/>(ahocorasickcore.go:241-285)"]
    C3 -->|"nil for ASCII text"| X1["Skipped"]
    C4 -->|"nil if no escapes"| X2["Skipped"]

    D1 -->|">1 detectors AND<br/>!verificationOverlap"| E["verificationOverlapWorker<br/>(engine.go:924-1034)"]
    D1 -->|"1 detector OR<br/>verificationOverlap"| F["detectableChunksChan"]
    D2 -->|"same routing logic"| F

    E -->|"overlap found<br/>(likelyDuplicate=true)"| G["processResult<br/>(errOverlap set,<br/>engine.go:988-999)"]
    E -->|"no overlap"| F

    F --> H["detectorWorker / detectChunk<br/>(engine.go:1044-1124)"]
    H --> I["processResult<br/>(engine.go:1152-1187)<br/>DecoderType stamped at line 1178"]

    G --> J["e.results channel"]
    I --> J

    J --> K["notifierWorker<br/>(engine.go:1189-1235)<br/>dedupeCache check at lines 1216-1221"]
    K -->|"key new OR<br/>same DecoderType"| L["Dispatch via e.dispatcher"]
    K -->|"key exists AND<br/>different DecoderType"| M["Suppressed (continue)"]
```

### 2.2 Key Data Structures

The following data structures are central to the three subsystems under investigation:

| Structure | Location | Description |
|-----------|----------|-------------|
| `DecodableChunk` | `pkg/decoders/decoders.go:20-23` | Wraps a `*sources.Chunk` with a `DecoderType` label indicating which decoder produced it. |
| `detectableChunk` | `pkg/engine/engine.go:760-765` | Internal struct containing the chunk, the matched detector, the decoder type, and a WaitGroup done function. |
| `verificationOverlapChunk` | `pkg/engine/engine.go:770-775` | Internal struct for chunks matched by multiple detectors; contains the chunk, decoder type, list of matching detectors, and a WaitGroup done function. |
| `Result` | `pkg/detectors/detectors.go:87-115` | Core result struct with `DetectorType`, `Raw`, `RawV2`, `Verified`, `verificationError`, and other fields. |
| `ResultWithMetadata` | `pkg/detectors/detectors.go:161-184` | Extends `Result` with `DecoderType` (line 183), `SourceMetadata`, `SourceType`, `Data`, and other metadata. |
| `dedupeCache` | `pkg/engine/engine.go:207-209` | `*lru.Cache[string, detectorspb.DecoderType]` — maps deduplication keys to the `DecoderType` of the first result seen for that key. Initialized with size 512 at `engine.go:491`. |
| `chunkSecretKey` | `pkg/engine/engine.go:882-885` | Ties a secret string to the specific `DetectorKey` that found it; used for intra-chunk duplicate detection in the overlap worker. |
| `DecoderType` enum | `pkg/pb/detectorspb/detectors.pb.go:23-30` | Protobuf enum: `UNKNOWN=0`, `PLAIN=1`, `BASE64=2`, `UTF16=3`, `ESCAPED_UNICODE=4`. |

---

## 3. Decoder Pipeline Mechanics

**Investigative Question 1:** Which `DecoderType` values are attached to results when the same secret appears in raw and Base64-encoded form within a single scanned file?

### 3.1 DefaultDecoders Ordering

The decoder list is defined in `pkg/decoders/decoders.go:8-16`:

```go
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

The comment at line 10 — "UTF8 must be first for duplicate detection" — is critical. This ordering guarantees that the UTF8/PLAIN decoder processes the original, unmodified chunk data before any other decoder has a chance to mutate it. The decoder types mapped to each index are:

| Index | Decoder | `DecoderType` | Enum Value |
|-------|---------|---------------|------------|
| 0 | `&UTF8{}` | `DecoderType_PLAIN` | 1 |
| 1 | `&Base64{}` | `DecoderType_BASE64` | 2 |
| 2 | `&UTF16{}` | `DecoderType_UTF16` | 3 |
| 3 | `&EscapedUnicode{}` | `DecoderType_ESCAPED_UNICODE` | 4 |

### 3.2 Scanner Worker Iteration

The `scannerWorker` function (`pkg/engine/engine.go:777-841`) processes each incoming chunk through all decoders sequentially:

- **Line 781:** `for chunk := range e.ChunksChan()` — reads source chunks.
- **Line 784:** `for _, decoder := range e.decoders` — iterates ALL decoders in the order defined by `DefaultDecoders()`.
- **Line 786:** `decoded := decoder.FromChunk(chunk)` — calls each decoder with the **same** `*sources.Chunk` pointer.
- **Lines 790-793:** If `decoded == nil`, the decoder did not apply to this chunk; the loop continues to the next decoder.
- **Line 795:** `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` — for each non-nil decoded chunk, Aho-Corasick matching is independently performed.

Each non-nil decoded chunk carries the `DecoderType` assigned by its originating decoder. The same logical secret found by two different decoders will produce two separate `DecodableChunk` instances, each with its own `DecoderType`.

### 3.3 Individual Decoder Behavior

#### UTF8 Decoder (`pkg/decoders/utf8.go:16-29`)

- **Line 12-13:** `Type()` returns `DecoderType_PLAIN`.
- **Line 17:** Returns `nil` only if `chunk == nil || len(chunk.Data) == 0`.
- **Line 21:** Creates `DecodableChunk{Chunk: chunk, DecoderType: d.Type()}`.
- **Lines 23-26:** If data is not valid UTF-8, sanitizes via `extractSubstrings` (defined at `utf8.go:45-75`) but **still returns non-nil**.
- **Conclusion:** For any non-empty input file, the UTF8 decoder **always** returns a `DecodableChunk` with `DecoderType_PLAIN`. It is guaranteed to produce at least one decoded output for every source chunk.

#### Base64 Decoder (`pkg/decoders/base64.go:34-72`)

- **Line 30-31:** `Type()` returns `DecoderType_BASE64`.
- **Line 36:** Calls `getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)` — the threshold is **20 characters** (runs of Base64-valid characters shorter than 20 are ignored).
- **Lines 39-48:** For each candidate substring, attempts `base64.StdEncoding.DecodeString` (line 40) and `base64.RawURLEncoding.DecodeString` (line 45). Both must pass the `isASCII(dec)` check (`base64.go:74-81`) — decoded bytes containing any value > 127 are rejected.
- **Lines 51-68:** If any successful decodings exist, builds a result buffer that substitutes encoded substrings with their decoded equivalents in-place.
- **Line 67:** `chunk.Data = result.Bytes()` — **mutates the shared chunk pointer's Data field**.
- **Line 68:** Returns the `decodableChunk` with `DecoderType_BASE64`.
- **Line 71:** If no substrings decoded successfully, returns `nil`.

#### UTF16 Decoder (`pkg/decoders/utf16.go:18-33`)

- **Line 14-15:** `Type()` returns `DecoderType_UTF16`.
- **Lines 24-29:** Attempts `utf16ToUTF8` heuristic conversion (line 36-52); returns `nil` if conversion fails or produces empty output.
- **For standard ASCII/UTF-8 text files:** The heuristic looks for alternating zero bytes characteristic of UTF-16 encoding. Standard ASCII text does not have this pattern, so the decoder returns `nil`.

#### EscapedUnicode Decoder (`pkg/decoders/escaped_unicode.go:32-68`)

- **Lines 28-29:** `Type()` returns `DecoderType_ESCAPED_UNICODE`.
- **Lines 42-49:** Checks for `\uXXXX` escape sequences (regex at line 25: `(?i:\\{1,2}u)([a-fA-F0-9]{4})`) and `U+XXXX` code point notation (regex at line 22: `\bU\+([a-fA-F0-9]{4}).?`).
- **Line 39:** Makes a clone of `chunk.Data` via `bytes.Clone()` to avoid data races — unlike the Base64 decoder, this decoder does **not** mutate the original chunk.
- **For files without Unicode escapes:** Returns `nil` (line 65-67).

### 3.4 Critical: Chunk Data Mutation

A key subtlety in the decoder pipeline is that decoders operate on a **shared chunk pointer**. The `scannerWorker` at lines 784-786 passes the same `*sources.Chunk` to each decoder without cloning:

```go
for _, decoder := range e.decoders {
    decoded := decoder.FromChunk(chunk)  // same chunk pointer each time
```

This has the following consequences:

1. The **UTF8 decoder** runs first (index 0) and sees the **original, unmodified** `chunk.Data`. It always returns non-nil.
2. The **Base64 decoder** runs second (index 1). If it finds decodable Base64 substrings, it **overwrites** `chunk.Data` at `base64.go:67` (`chunk.Data = result.Bytes()`). This mutation persists across subsequent decoder iterations.
3. The **UTF16 decoder** runs third (index 2) and sees the **already-modified** data from the Base64 pass (if the Base64 decoder fired). For ASCII text, it still returns `nil`.
4. The **EscapedUnicode decoder** runs fourth (index 3). It clones `chunk.Data` (line 39: `bytes.Clone(chunk.Data)`) before processing, but the data it clones is the version already modified by the Base64 decoder.

This shared-pointer mutation is precisely why the comment at `decoders.go:10` says "UTF8 must be first for duplicate detection." The PLAIN decoder captures the unmodified original, ensuring the deduplication cache in the notifier worker can compare the original-data result against decoded-data results.

### 3.5 Answer: Which DecoderType Values Are Attached to Results?

**For the scenario where the same AWS key appears in both raw and Base64-encoded form within a single file:**

- **`DecoderType_PLAIN` (value 1):** The UTF8 decoder always returns non-nil for any non-empty input. The original file data (containing both the raw key and the Base64-encoded key) is passed through Aho-Corasick matching. The keyword "AKIA" is present in the raw key portion, so the AWS access key detector matches and produces a result tagged `DecoderType_PLAIN`.

- **`DecoderType_BASE64` (value 2):** The Base64 decoder finds the Base64-encoded segment (≥20 characters of Base64 charset), decodes it successfully (the decoded output is ASCII since it's an AWS key), and substitutes the decoded bytes in-place. The resulting `chunk.Data` now contains both the original raw key AND the newly decoded key. Aho-Corasick finds "AKIA" in this data, the AWS detector fires, and a result is tagged `DecoderType_BASE64`.

- **`DecoderType_UTF16` (value 3):** Returns `nil` for standard ASCII text. **No result produced.**

- **`DecoderType_ESCAPED_UNICODE` (value 4):** Returns `nil` when no `\uXXXX` or `U+XXXX` patterns are found. **No result produced.**

**Result:** Two decoder passes produce results — `DecoderType_PLAIN` and `DecoderType_BASE64`. The UTF16 and ESCAPED_UNICODE decoders do not fire for this input type.

---

## 4. Overlap Detection Logic

**Investigative Question 2:** Under what conditions does the engine route a decoded chunk through the `verificationOverlapChunksChan` path versus the standard `detectableChunksChan` path?

### 4.1 Aho-Corasick Matching

After each decoder produces a non-nil `DecodableChunk`, the scanner worker invokes Aho-Corasick matching at `engine.go:795`:

```go
matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
```

The `FindDetectorMatches` function (`pkg/engine/ahocorasick/ahocorasickcore.go:241-285`):

1. **Line 242:** Lowercases chunk data and runs the Aho-Corasick trie match.
2. **Lines 249-273:** Maps keyword matches to unique `DetectorKey` entries, accumulating match spans for each detector.
3. **Lines 275-284:** Merges overlapping or adjacent spans and returns `[]*DetectorMatch`, each containing a detector reference and the matched byte spans.

For the AWS access key detector, the keywords are `["AKIA", "ABIA", "ACCA"]` (defined at `pkg/detectors/aws/access_keys/accesskey.go:70-75`). A chunk containing "AKIA" will trigger a match for the AWS access key detector.

### 4.2 Routing Decision

The routing conditional is at `engine.go:796-816`:

```go
if len(matchingDetectors) > 1 && !e.verificationOverlap {
    // Route to verificationOverlapChunksChan
    wgVerificationOverlap.Add(1)
    e.verificationOverlapChunksChan <- verificationOverlapChunk{
        chunk:                       *decoded.Chunk,
        detectors:                   matchingDetectors,
        decoder:                     decoded.DecoderType,
        verificationOverlapWgDoneFn: wgVerificationOverlap.Done,
    }
    continue
}

for _, detector := range matchingDetectors {
    // Route each detector to detectableChunksChan
    decoded.Chunk.Verify = e.shouldVerifyChunk(sourceVerify, detector, e.detectorVerificationOverrides)
    wgDetect.Add(1)
    e.detectableChunksChan <- detectableChunk{
        chunk:    *decoded.Chunk,
        detector: detector,
        decoder:  decoded.DecoderType,
        wgDoneFn: wgDetect.Done,
    }
}
```

**Two conditions must BOTH be true** for the overlap path:

1. **`len(matchingDetectors) > 1`** — More than one distinct detector matched the decoded chunk. This means the chunk's data triggered keyword matches for at least two different detector types (e.g., an AWS detector AND a Postman API key detector matching the same chunk).

2. **`!e.verificationOverlap`** — The `--allow-verification-overlap` flag is NOT set. This flag is defined at `main.go:65` and maps to `Engine.verificationOverlap` at `engine.go:180`. Its default value is `false`, meaning overlap detection is active by default.

If either condition is false — only one detector matches, or the overlap flag is set — chunks go to the standard `detectableChunksChan` path.

### 4.3 Verification Overlap Worker

The `verificationOverlapWorker` (`engine.go:924-1034`) processes chunks that have multiple detector matches:

1. **Lines 932-933:** Iterates each detector that matched the chunk.
2. **Line 940:** Calls `detector.FromData(ctx, false, match)` — the second argument is `false`, meaning **verification is explicitly disabled** at this stage.
3. **Lines 952-954:** Tracks which detector keys produced results in `detectorKeysWithResults`.
4. **Lines 961-963:** Applies `filterResults` for non-targeted scans (`SecretID == 0`).
5. **Lines 965-980:** For each result, constructs a `chunkSecretKey{secret: string(val), detectorKey: detector.Key}` and checks for exact duplicates within this chunk.
6. **Line 982:** Calls `likelyDuplicate(ctx, key, chunkSecrets)` to check cross-detector similarity.
7. **Lines 988-1004:** If a likely duplicate is found:
   - Sets `errOverlap` as the verification error (`engine.go:39-42`).
   - Sends the result directly through `processResult` (lines 989-999).
   - Removes the detector from `detectorKeysWithResults` so it is not re-verified (line 1004).
8. **Lines 1011-1020:** For detectors that did NOT produce overlapping results, the chunk is re-routed to `detectableChunksChan` with verification **enabled** (via `shouldVerifyChunk` at line 1013).

### 4.4 The likelyDuplicate Function

The `likelyDuplicate` function (`engine.go:887-922`) compares a candidate secret against all previously seen secrets in the current chunk:

1. **Lines 894-896:** Length pre-check — if the two strings differ by more than ~10% in length, comparison is skipped (performance optimization).
2. **Lines 900-902:** **Critical exclusion:** `if val.detectorKey.Type() == dupeKey.detectorKey.Type() { continue }` — secrets found by the **same detector type** are never considered duplicates. Only secrets from **different** detector types are compared.
3. **Line 904:** Exact string match returns `true` (confirmed duplicate).
4. **Line 911:** If not an exact match, computes Levenshtein similarity: `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())`.
5. **Line 914:** Threshold is **0.9** (90% similar) — if exceeded, returns `true`.

### 4.5 Answer: When Does Overlap Detection Trigger?

**For the AWS key scenario with default detectors:**

The AWS access key detector has keywords `["AKIA", "ABIA", "ACCA"]` (`accesskey.go:70-75`). In a typical scan with default detectors, only the AWS access key detector matches a chunk containing an AWS key. Therefore:

- `len(matchingDetectors) == 1` — the condition `len(matchingDetectors) > 1` is **false**.
- The overlap path at `engine.go:796-805` is **NOT taken**.
- Chunks go directly to `detectableChunksChan` via the standard path at `engine.go:807-816`.

**Overlap detection activates only when:**
- Multiple different detectors (e.g., the AWS access key detector AND a custom regex detector) both have keyword matches in the same decoded chunk, AND
- The `--allow-verification-overlap` flag is not set (default behavior).

When overlap detection does activate, it runs each detector **without verification** first, then compares the extracted secrets across detector types using `likelyDuplicate`. If the same secret (or a >90% similar one) is found by two different detectors, verification is disabled for that result and an `errOverlap` error is attached.

---

## 5. Deduplication Behavior

**Investigative Question 3:** How does the LRU-based `dedupeCache` in the notifier worker decide which result to keep and which to suppress, and does the deduplication key include or exclude the `DecoderType`?

### 5.1 Cache Structure

The deduplication cache is declared at `engine.go:207-209`:

```go
// dedupeCache is used to deduplicate results by comparing the
// detector type, raw result, and source metadata
dedupeCache *lru.Cache[string, detectorspb.DecoderType]
```

It is an LRU cache mapping **string keys** to **`DecoderType` values**. It is initialized at `engine.go:489-493`:

```go
const cacheSize = 512 // number of entries in the LRU cache
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
```

The cache holds at most **512 entries**. When full, the least recently used entry is evicted.

### 5.2 Key Construction

The deduplication key is constructed at `engine.go:1216`:

```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
```

The key components are:

| Component | Source | Example |
|-----------|--------|---------|
| `result.DetectorType.String()` | The detector that found the secret (e.g., `"AWS"`) | `"AWS"` |
| `result.Raw` | The raw secret bytes (e.g., the AKIA key ID) | `"AKIA2OGYBAH6STMMNXNN"` |
| `result.RawV2` | The combined ID+secret (e.g., key ID + secret key) | `"AKIA2OGYBAH6STMMNXNN..." + secret` |
| `result.SourceMetadata` | Formatted source metadata (file path, line, etc.) | `"&{... filename ...}"` |

**`DecoderType` is deliberately EXCLUDED from this key.** This means that two results from different decoders (e.g., PLAIN and BASE64) that find the same raw secret from the same detector in the same source location will produce **identical** deduplication keys.

### 5.3 Cache Check Logic

The deduplication decision is at `engine.go:1210-1221`, with an explanatory comment at lines 1210-1215:

```go
// Dedupe results by comparing the detector type, raw result, and source metadata.
// We want to avoid duplicate results with different decoder types, but we also
// want to include duplicate results with the same decoder type.
// Duplicate results with the same decoder type SHOULD have their own entry in the
// results list, this would happen if the same secret is found multiple times.
// Note: If the source type is postman, we dedupe the results regardless of decoder type.
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

**Decision logic step by step:**

1. Compute the deduplication `key` (line 1216).
2. Check if the key exists in the cache: `val, ok := e.dedupeCache.Get(key)` (line 1217).
3. If the key **does not exist** (`ok` is false): the result passes through. The key is added to the cache with the result's `DecoderType` as the value (line 1221).
4. If the key **exists** (`ok` is true):
   - Check if the stored `DecoderType` differs from the current result's `DecoderType`: `val != result.DecoderType`.
   - **OR** check if this is a Postman source: `result.SourceType == SOURCE_TYPE_POSTMAN`.
   - If **either** is true → `continue` (the result is **suppressed**).
   - If the stored `DecoderType` **equals** the current result's `DecoderType` AND it's not Postman → the result **passes through** (same-decoder duplicates are allowed).

### 5.4 Answer: How Does the Deduplication Cache Decide What to Keep?

The deduplication behavior can be summarized in this truth table:

| Key in cache? | Stored DecoderType == Current DecoderType? | Is Postman? | Result |
|:---:|:---:|:---:|:---:|
| No | N/A | N/A | **Passes through** (first occurrence) |
| Yes | Yes | No | **Passes through** (same decoder, different occurrence) |
| Yes | No | No | **Suppressed** (cross-decoder duplicate) |
| Yes | Yes | Yes | **Suppressed** (Postman always dedupes) |
| Yes | No | Yes | **Suppressed** (Postman always dedupes) |

Key takeaways:

- **Cross-decoder duplicates are suppressed:** If the PLAIN decoder finds a secret and then the BASE64 decoder finds the same secret (same `Raw`, same `DetectorType`, same `SourceMetadata`), the second result is dropped.
- **Same-decoder duplicates are allowed:** If the PLAIN decoder finds the same secret twice (e.g., in different lines within the same chunk), both results pass through.
- **Postman exception:** For Postman sources, ALL duplicates are suppressed regardless of decoder type.
- **First arrival wins:** The first result to reach the `notifierWorker` for a given key determines the cached `DecoderType`. All subsequent results with different decoder types for the same key are suppressed.

---

## 6. Pipeline Ordering (Temporal Sequence)

**Investigative Question 4:** Does the deduplication step occur before or after overlap detection, and how does this sequencing influence the final result count?

### 6.1 Stage-by-Stage Sequence

The pipeline executes in a strict sequential stage order:

**Stage 1: `scannerWorker`** (`engine.go:777-841`)
- Reads chunks from `e.ChunksChan()`.
- Iterates all decoders for each chunk (line 784).
- Performs Aho-Corasick matching on each decoded chunk (line 795).
- Routes to `verificationOverlapChunksChan` (lines 796-805) or `detectableChunksChan` (lines 807-816).

**Stage 2: `verificationOverlapWorker`** (`engine.go:924-1034`)
- Receives chunks from `verificationOverlapChunksChan`.
- Runs each detector's `FromData` with verification disabled (line 940).
- Uses `likelyDuplicate` for cross-detector comparison (line 982).
- If overlap is found: emits result directly with `errOverlap` (lines 988-999).
- If no overlap: re-routes detector to `detectableChunksChan` with verification enabled (lines 1011-1020).

**Stage 3: `detectorWorker` / `detectChunk`** (`engine.go:1036-1124`)
- Receives chunks from `detectableChunksChan` (line 1037).
- Calls `e.verificationCache.FromData(...)` for actual detection and optional verification (line 1070-1075).
- Applies `filterResults` (line 1113), which may invoke `CleanResults` (`pkg/detectors/detectors.go:200-225`).
- Sends each surviving result through `processResult` (line 1117).

**Stage 4: `processResult`** (`engine.go:1152-1187`)
- Creates `ResultWithMetadata` via `detectors.CopyMetadata(&data.chunk, res)` (line 1177).
- **Stamps the decoder type:** `secret.DecoderType = data.decoder` (line 1178).
- Sends the result to the results channel: `e.results <- secret` (line 1186).

**Stage 5: `notifierWorker`** (`engine.go:1189-1235`)
- Reads from `e.ResultsChan()` (line 1190).
- Applies result type filtering (verified/unverified/unknown) at lines 1192-1207.
- **Applies deduplication** at lines 1216-1221.
- Dispatches surviving results via `e.dispatcher.Dispatch(ctx, result)` (line 1229).

### 6.2 Answer: Overlap Detection vs. Deduplication Ordering

**Overlap detection (Stage 2) occurs BEFORE deduplication (Stage 5).** They are not alternatives; they are complementary mechanisms that solve different problems at different pipeline stages:

| Mechanism | Stage | Purpose | Scope |
|-----------|-------|---------|-------|
| Overlap Detection | 2 (`verificationOverlapWorker`) | Prevents redundant verification when **multiple different detectors** claim the same secret in the same chunk | Intra-chunk, cross-detector |
| Deduplication | 5 (`notifierWorker`) | Prevents the **same logical result** from being reported to the user multiple times across different **decoder passes** | Cross-chunk, cross-decoder |

**How sequencing influences the final result count:**

1. Overlap detection does **not** reduce the number of results that enter the deduplication stage. It only controls whether those results have been verified or carry an `errOverlap` error. Results emitted by the overlap worker (with `errOverlap`) still flow through `processResult` → `results channel` → `notifierWorker`, where they are subject to deduplication.

2. Deduplication is the **final gate** that controls which results the user actually sees. Even if overlap detection is bypassed (because only one detector matches, as in the AWS key scenario), deduplication still operates and suppresses cross-decoder duplicates.

3. The pipeline stages are connected by Go channels, and each stage is run by one or more goroutines. The relative arrival order of results at the `notifierWorker` depends on concurrency settings and goroutine scheduling, which is what causes the variable result count discussed in Section 7.

---

## 7. Variable Result Count Explanation

**Investigative Question 5:** Why does the same logical secret sometimes produce one result and sometimes produce multiple results depending on file structure?

### 7.1 Scenario A: Raw AWS Key Only

**Input:** A file containing only the plain-text AWS access key (e.g., `AKIA2OGYBAH6STMMNXNN`).

- **UTF8 decoder** (`utf8.go:16-29`): Returns `DecoderType_PLAIN` chunk with the original data. Aho-Corasick finds "AKIA" → AWS detector matches → produces 1 PLAIN result.
- **Base64 decoder** (`base64.go:34-72`): `getSubstringsOfCharacterSet` finds "AKIA2OGYBAH6STMMNXNN" (20 characters, meets threshold of 20 at line 36). Attempts Base64 decoding — the result is non-ASCII binary data, which fails the `isASCII` check at line 41. Returns `nil`.
- **UTF16 decoder** (`utf16.go:18-33`): Returns `nil` (standard ASCII text).
- **EscapedUnicode decoder** (`escaped_unicode.go:32-68`): Returns `nil` (no escape patterns).

**Final count: 1 result (`DecoderType_PLAIN`).**

### 7.2 Scenario B: Base64-Encoded AWS Key Only

**Input:** A file containing only the Base64-encoded form of the AWS credentials (e.g., the key ID + secret key encoded as Base64).

- **UTF8 decoder**: Returns `DecoderType_PLAIN` chunk with the Base64 string as-is (it is valid UTF-8). However, the Base64 encoding of "AKIA..." does NOT contain the literal string "AKIA" — Base64 encoding transforms the character sequence. Aho-Corasick keyword match for "AKIA" fails → no detector matches → no result from this pass.
- **Base64 decoder**: Finds the long Base64 run (well above the 20-character threshold), decodes it successfully to reveal the raw AWS credentials. The decoded output is ASCII. Substitutes the decoded bytes into `chunk.Data`. Aho-Corasick now finds "AKIA" in the decoded data → AWS detector matches → produces 1 BASE64 result.
- **UTF16, EscapedUnicode decoders**: Return `nil`.

**Final count: 1 result (`DecoderType_BASE64`).**

### 7.3 Scenario C: Both Raw and Base64-Encoded AWS Key

**Input:** A file containing both the raw AWS key and a Base64-encoded version of the same key.

**Step 1 — UTF8 decoder pass:**
- Returns `DecoderType_PLAIN` chunk with the full file data containing both raw and encoded forms.
- Aho-Corasick finds "AKIA" in the raw key portion → AWS detector matches.
- Result emitted: `{DetectorType: AWS, Raw: <key bytes>, DecoderType: PLAIN, SourceMetadata: <file info>}`.

**Step 2 — Base64 decoder pass:**
- Finds the Base64-encoded segment, decodes it, substitutes decoded bytes in `chunk.Data` (mutating the shared chunk at `base64.go:67`).
- The resulting data now contains both the original raw key AND the newly decoded key from the Base64 segment.
- Aho-Corasick finds "AKIA" → AWS detector matches.
- Result emitted: `{DetectorType: AWS, Raw: <same key bytes>, DecoderType: BASE64, SourceMetadata: <file info>}`.

**Step 3 — Deduplication in notifierWorker:**
- Both results have the same `DetectorType` (AWS), same `Raw` bytes, and same `SourceMetadata`.
- The deduplication key at `engine.go:1216` is therefore **identical** for both results.
- The first result to reach the notifier is stored in the LRU cache with its `DecoderType`.
- The second result arrives with a **different** `DecoderType`. The cache check at `engine.go:1217` finds the key exists and `val != result.DecoderType` evaluates to `true` → the second result is **suppressed**.

**Final count: 1 result (whichever decoder's result reaches the notifier first).**

### 7.4 Concurrency and Timing Effects

The `DecoderType` attached to the surviving result depends on which decoder's result reaches the single `notifierWorker` goroutine first:

- **With `Concurrency=1`:** Processing is more deterministic. The `scannerWorker` iterates decoders sequentially (UTF8 first, then Base64). Each decoded chunk is dispatched to `detectableChunksChan`. With a single detector worker goroutine, the PLAIN chunk is likely processed before the BASE64 chunk, so the PLAIN result typically reaches the notifier first. The surviving result will carry `DecoderType_PLAIN`.

- **With higher concurrency:** Multiple `detectorWorker` goroutines process chunks concurrently from `detectableChunksChan`. The arrival order at the results channel depends on:
  - Goroutine scheduling by the Go runtime.
  - Channel buffer capacity (determined by `detectableChunksChanMultiplier` at `engine.go:498-500`).
  - The relative execution time of each detector call.
  - OS thread scheduling.

  In this scenario, either `DecoderType_PLAIN` or `DecoderType_BASE64` may appear on the final result.

### 7.5 Edge Cases

**Cache eviction:** The LRU cache has a fixed size of 512 entries (`engine.go:491`). If the raw and Base64 forms appear in **different source chunks** (e.g., different files in a repository scan), they may arrive at the notifier at widely separated times. If 512 or more other distinct results pass through the notifier between the two arrivals, the first entry may be evicted from the LRU cache. When the second result arrives and finds the key absent, it passes through as a new entry. **In this case, both results survive → 2 total results.**

**`CleanResults` filtration:** The `filterResults` function (`engine.go:1126-1150`) may invoke `CleanResults` (`pkg/detectors/detectors.go:200-225`) when `filterUnverified` is enabled. `CleanResults` at line 216 returns only `results[:1]` when no verified results exist. This filtering occurs at the detector worker stage (Stage 3), **before** deduplication (Stage 5), and reduces multiple unverified results from a single detector pass to just one.

**`--filter-unverified` flag:** When active, this causes `filterResults` to call `CleanResults`, potentially reducing the number of results entering the deduplication stage.

### 7.6 Answer: Why Does the Same Secret Sometimes Produce Variable Result Counts?

The variable result count is caused by the interaction of three factors:

1. **Decoder pipeline produces multiple results:** When both raw and Base64 forms are present, two decoder passes (PLAIN and BASE64) independently produce results for the same logical secret.

2. **Deduplication suppresses cross-decoder duplicates:** The `notifierWorker` at `engine.go:1216-1221` constructs a deduplication key that excludes `DecoderType`. When two results with the same key but different decoder types arrive, the second is suppressed. This typically results in **1 final result**.

3. **Edge conditions can produce multiple results:**
   - If the raw and Base64 forms are in different chunks that are separated by enough other results to cause LRU cache eviction (>512 intervening unique results), both will pass through → **2 results**.
   - If the file structure causes the raw and Base64 forms to be processed in separate scan iterations (e.g., different git diff hunks), timing-dependent cache behavior may allow both through.
   - If `SourceMetadata` differs between the two occurrences (e.g., different line numbers in a line-number-aware source like filesystem), the deduplication keys will differ → **2 results**, as each is treated as a distinct finding.

---

## 8. Scenario Walkthroughs

### 8.1 Walkthrough A: File Contains Only the Raw AWS Key

**Input data:** `AKIA2OGYBAH6STMMNXNN` and associated 40-character secret key in a plain-text file.

| Step | Component | Reference | Action | Outcome |
|------|-----------|-----------|--------|---------|
| 1 | Source | — | File ingested as a `sources.Chunk` | `chunk.Data` contains the raw key text |
| 2 | scannerWorker | `engine.go:784` | Begins iterating decoders | Decoder index 0 (UTF8) first |
| 3 | UTF8 decoder | `utf8.go:16-28` | `FromChunk(chunk)` — data is valid UTF-8 | Returns `DecodableChunk{DecoderType: PLAIN}` |
| 4 | FindDetectorMatches | `ahocorasickcore.go:241-285` | Lowercases data, runs trie match | "akia" matches → AWS detector returned |
| 5 | Routing decision | `engine.go:796` | `len(matchingDetectors) == 1` | Standard path → `detectableChunksChan` |
| 6 | detectChunk | `engine.go:1044-1124` | Calls `detector.FromData(ctx, verify, matchBytes)` | AWS detector extracts AKIA key + secret → 1 Result |
| 7 | processResult | `engine.go:1177-1178` | `CopyMetadata`, `DecoderType = PLAIN` | `ResultWithMetadata` created |
| 8 | notifierWorker | `engine.go:1216` | Key = `"AWS" + Raw + RawV2 + Metadata` | Key is new → passes through |
| 9 | scannerWorker | `engine.go:784` | Next decoder: Base64 (index 1) | — |
| 10 | Base64 decoder | `base64.go:34-71` | Finds "AKIA2OGYBAH6STMMNXNN" (20 chars), decodes as Base64 | Decoded bytes are non-ASCII → `isASCII` fails → returns `nil` |
| 11 | scannerWorker | `engine.go:790-792` | `decoded == nil` | Skips to next decoder |
| 12 | UTF16 decoder | `utf16.go:18-33` | ASCII text, no UTF-16 patterns | Returns `nil` |
| 13 | EscapedUnicode decoder | `escaped_unicode.go:32-68` | No escape patterns found | Returns `nil` |

**Final output: 1 result with `DecoderType_PLAIN`.**

### 8.2 Walkthrough B: File Contains Only the Base64-Encoded AWS Key

**Input data:** Base64-encoded string of the AWS key ID + secret key.

| Step | Component | Reference | Action | Outcome |
|------|-----------|-----------|--------|---------|
| 1 | Source | — | File ingested as a `sources.Chunk` | `chunk.Data` contains the Base64 string |
| 2 | UTF8 decoder | `utf8.go:16-28` | Valid UTF-8 | Returns `DecodableChunk{DecoderType: PLAIN}` |
| 3 | FindDetectorMatches | `ahocorasickcore.go:241-285` | Trie match on Base64 string | "AKIA" not present in encoded form → no detector matches |
| 4 | scannerWorker | `engine.go:795` | `len(matchingDetectors) == 0` | No chunks dispatched for PLAIN pass |
| 5 | Base64 decoder | `base64.go:34-68` | Finds long Base64 run, decodes successfully | Returns `DecodableChunk{DecoderType: BASE64}` with decoded data containing "AKIA..." |
| 6 | FindDetectorMatches | `ahocorasickcore.go:241-285` | Trie match on decoded data | "akia" matches → AWS detector returned |
| 7 | Routing decision | `engine.go:796` | `len(matchingDetectors) == 1` | Standard path → `detectableChunksChan` |
| 8 | detectChunk | `engine.go:1044-1124` | AWS detector extracts key | 1 Result produced |
| 9 | processResult | `engine.go:1177-1178` | `CopyMetadata`, `DecoderType = BASE64` | `ResultWithMetadata` created |
| 10 | notifierWorker | `engine.go:1216-1221` | Key is new | Passes through |
| 11 | UTF16, EscapedUnicode | `utf16.go`, `escaped_unicode.go` | No applicable patterns | Both return `nil` |

**Final output: 1 result with `DecoderType_BASE64`.**

### 8.3 Walkthrough C: File Contains Both Raw and Base64-Encoded AWS Key

**Input data:** A file with both the literal AWS key (e.g., `AKIA2OGYBAH6STMMNXNN` + secret) and a Base64-encoded version of the same credentials.

| Step | Component | Reference | Action | Outcome |
|------|-----------|-----------|--------|---------|
| 1 | Source | — | File ingested as `sources.Chunk` | `chunk.Data` contains both raw and encoded forms |
| 2 | UTF8 decoder | `utf8.go:16-28` | Valid UTF-8 | Returns `DecodableChunk{DecoderType: PLAIN}` with original data |
| 3 | FindDetectorMatches | `ahocorasickcore.go:241-285` | Trie match on original data | "akia" found in raw portion → AWS detector matches |
| 4 | Routing | `engine.go:807-816` | 1 detector matched | Standard path → `detectableChunksChan` with `decoder: PLAIN` |
| 5 | detectChunk (PLAIN) | `engine.go:1044-1124` | AWS detector extracts key from raw portion | Result A: `{Raw: <key>, DetectorType: AWS}` |
| 6 | processResult (PLAIN) | `engine.go:1177-1178` | `DecoderType = PLAIN` | ResultWithMetadata A sent to results channel |
| 7 | Base64 decoder | `base64.go:34-68` | Finds Base64 segment, decodes, **mutates `chunk.Data`** at line 67 | Returns `DecodableChunk{DecoderType: BASE64}` with modified data |
| 8 | FindDetectorMatches | `ahocorasickcore.go:241-285` | Trie match on modified data | "akia" found → AWS detector matches |
| 9 | Routing | `engine.go:807-816` | 1 detector matched | Standard path → `detectableChunksChan` with `decoder: BASE64` |
| 10 | detectChunk (BASE64) | `engine.go:1044-1124` | AWS detector extracts key | Result B: `{Raw: <same key>, DetectorType: AWS}` |
| 11 | processResult (BASE64) | `engine.go:1177-1178` | `DecoderType = BASE64` | ResultWithMetadata B sent to results channel |
| 12 | notifierWorker — Result A | `engine.go:1216` | Key = `"AWS" + Raw + RawV2 + Metadata` | Key is new → **passes through**; cache stores `(key → PLAIN)` |
| 13 | notifierWorker — Result B | `engine.go:1217-1219` | Same key → cache hit; `val=PLAIN != BASE64` | **Suppressed** (`continue`) |
| 14 | UTF16, EscapedUnicode | — | No applicable patterns | Both return `nil` |

**Final output: 1 result.** In the deterministic case (low concurrency), this result carries `DecoderType_PLAIN` because the UTF8 decoder runs first (index 0 in `DefaultDecoders()`) and its result reaches the notifier before the Base64 decoder's result. With higher concurrency, the result might carry either `DecoderType_PLAIN` or `DecoderType_BASE64` depending on goroutine scheduling.

---

## 9. Appendix: Key Code References

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| `DefaultDecoders` | `pkg/decoders/decoders.go` | 8-16 | Decoder ordering: UTF8 → Base64 → UTF16 → EscapedUnicode |
| `DecodableChunk` | `pkg/decoders/decoders.go` | 20-23 | Wraps chunk with `DecoderType` |
| `Decoder` interface | `pkg/decoders/decoders.go` | 25-28 | `FromChunk` and `Type` methods |
| `UTF8.Type` | `pkg/decoders/utf8.go` | 12-13 | Returns `DecoderType_PLAIN` |
| `UTF8.FromChunk` | `pkg/decoders/utf8.go` | 16-29 | PLAIN decoder; always returns non-nil for non-empty input |
| `Base64.Type` | `pkg/decoders/base64.go` | 30-31 | Returns `DecoderType_BASE64` |
| `Base64.FromChunk` | `pkg/decoders/base64.go` | 34-72 | BASE64 decoder; chunk mutation at line 67 |
| `getSubstringsOfCharacterSet` | `pkg/decoders/base64.go` | 83-130 | Extracts runs of ≥threshold Base64 chars |
| `isASCII` | `pkg/decoders/base64.go` | 74-81 | Rejects non-ASCII decoded output |
| `UTF16.FromChunk` | `pkg/decoders/utf16.go` | 18-33 | UTF16 decoder; returns nil for ASCII text |
| `EscapedUnicode.FromChunk` | `pkg/decoders/escaped_unicode.go` | 32-68 | Escaped unicode decoder; clones data before processing |
| `EscapedUnicode.Type` | `pkg/decoders/escaped_unicode.go` | 28-29 | Returns `DecoderType_ESCAPED_UNICODE` |
| `DecoderType` enum | `pkg/pb/detectorspb/detectors.pb.go` | 23-30 | `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4` |
| `errOverlap` | `pkg/engine/engine.go` | 39-42 | Overlap error sentinel value |
| `Engine.verificationOverlap` | `pkg/engine/engine.go` | 180 | Internal flag for `--allow-verification-overlap` |
| `detectableChunk` | `pkg/engine/engine.go` | 760-765 | Struct: chunk + detector + decoder + wgDoneFn |
| `verificationOverlapChunk` | `pkg/engine/engine.go` | 770-775 | Struct: chunk + decoder + detectors list + wgDoneFn |
| `dedupeCache` declaration | `pkg/engine/engine.go` | 207-209 | `*lru.Cache[string, DecoderType]` |
| `dedupeCache` initialization | `pkg/engine/engine.go` | 491-493 | LRU cache with size 512 |
| `scannerWorker` | `pkg/engine/engine.go` | 777-841 | Decoder iteration and routing |
| `chunkSecretKey` | `pkg/engine/engine.go` | 882-885 | Secret + DetectorKey for overlap comparison |
| `likelyDuplicate` | `pkg/engine/engine.go` | 887-922 | Levenshtein similarity check (threshold 0.9) |
| `verificationOverlapWorker` | `pkg/engine/engine.go` | 924-1034 | Cross-detector overlap detection |
| `detectorWorker` | `pkg/engine/engine.go` | 1036-1042 | Dispatches to `detectChunk` |
| `detectChunk` | `pkg/engine/engine.go` | 1044-1124 | Detector execution and result filtering |
| `filterResults` | `pkg/engine/engine.go` | 1126-1150 | Result cleaning/filtering dispatch |
| `processResult` | `pkg/engine/engine.go` | 1152-1187 | Metadata stamping; `DecoderType` at line 1178 |
| `notifierWorker` | `pkg/engine/engine.go` | 1189-1235 | Deduplication at lines 1216-1221 |
| `Result` struct | `pkg/detectors/detectors.go` | 87-115 | `DetectorType`, `Raw`, `RawV2`, `Verified`, `verificationError` |
| `ResultWithMetadata` | `pkg/detectors/detectors.go` | 161-184 | `DecoderType` field at line 183 |
| `CopyMetadata` | `pkg/detectors/detectors.go` | 187-198 | Creates `ResultWithMetadata` from chunk + result |
| `CleanResults` | `pkg/detectors/detectors.go` | 200-225 | Filters unverified duplicates; returns `results[:1]` at line 216 |
| `FindDetectorMatches` | `pkg/engine/ahocorasick/ahocorasickcore.go` | 241-285 | Keyword matching via Aho-Corasick trie |
| AWS `idPat` | `pkg/detectors/aws/access_keys/accesskey.go` | 65 | Regex: `\b((?:AKIA\|ABIA\|ACCA)[A-Z0-9]{16})\b` |
| AWS `Keywords` | `pkg/detectors/aws/access_keys/accesskey.go` | 70-75 | `["AKIA", "ABIA", "ACCA"]` |
| AWS `SecretPat` | `pkg/detectors/aws/common.go` | 10 | 40-character secret regex |
| `--allow-verification-overlap` | `main.go` | 65 | CLI flag definition |
| `--filter-unverified` | `main.go` | 66 | CLI flag for unverified result filtering |
| Process flow docs | `docs/process_flow.md` | 1-26 | High-level architecture diagram |
