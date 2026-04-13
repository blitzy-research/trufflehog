# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Feature Objective

Based on the prompt, the Blitzy platform understands that the new feature requirement is to **create a comprehensive investigative analysis document** that traces the exact runtime behavior of three interconnected subsystems within TruffleHog v3: the decoder pipeline, the verification overlap detection mechanism, and the result deduplication cache. The document must explain the interactions among these subsystems that produce the varying output behaviors the user has observed when scanning a file containing the same AWS access key in multiple encoded forms (plain text and Base64).

The specific behavioral questions to answer are:

- **Decoder type reporting**: Which `DecoderType` values (PLAIN, BASE64, UTF16, ESCAPED_UNICODE) are attached to results when the same secret appears in raw and Base64-encoded form within a single scanned file?
- **Overlap detection trigger conditions**: Under what conditions does the engine route a decoded chunk through the `verificationOverlapChunksChan` path (the overlap detection pipeline) versus the standard `detectableChunksChan` path, and how does this affect reported results?
- **Deduplication behavior and ordering**: How does the LRU-based `dedupeCache` in the notifier worker decide which result to keep and which to suppress, and does the deduplication key include or exclude the `DecoderType`?
- **Temporal ordering of deduplication vs. overlap detection**: Whether the deduplication step (in the notifier worker) occurs before or after overlap detection (in the scanner/verification-overlap worker), and how this sequencing influences the final result count.
- **Variable result count**: Why the same logical secret sometimes produces one result and sometimes produces multiple results depending on file structure (e.g., whether raw and encoded forms appear on the same line, adjacent lines, or in separate chunks).

### 0.1.2 Special Instructions and Constraints

- **Read-only analysis**: The user explicitly requires "Do not modify any existing source files in the repository." All investigation must be performed through code reading, test execution, and controlled experiments with temporary test data only.
- **Cleanup requirement**: "Remove any test data created during the investigation." Any temporary files created for test scenarios must be deleted before concluding.
- **Output deliverable**: Per the project implementation rules (`SWE-AtlasQnA-Repo`), the deliverable is a single Markdown document named `trufflehog_e42153d44a5e.md` placed in the `blitzy/documentation` directory. This document must comprehensively answer the posed questions with rationale grounded in the actual code.
- **No code modifications**: The document must not introduce any new code into the source repository other than the analysis document itself.
- **Evidence-based answers**: All conclusions must be supported by direct reference to specific source files and line numbers in the repository, not assumptions or external documentation.

### 0.1.3 Technical Interpretation

These feature requirements translate to the following technical implementation strategy:

- To **answer the decoder pipeline question**, we will trace the `scannerWorker` function in `pkg/engine/engine.go` (lines 777–841), which iterates over `e.decoders` (default order: UTF8, Base64, UTF16, EscapedUnicode per `pkg/decoders/decoders.go` line 9–15) and sends each non-nil decoded chunk independently through the matching and detection pipeline.
- To **answer the overlap detection question**, we will analyze the conditional branch at `pkg/engine/engine.go` lines 796–805, where `len(matchingDetectors) > 1 && !e.verificationOverlap` routes chunks to the overlap worker, and the `verificationOverlapWorker` at lines 924–1034, which uses Levenshtein similarity (`likelyDuplicate`) to detect cross-detector duplicates.
- To **answer the deduplication question**, we will examine the `notifierWorker` at `pkg/engine/engine.go` lines 1189–1235, specifically the deduplication key construction at line 1216 (`fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)`) and the cache check at lines 1217–1219, which compares the stored `DecoderType` against the incoming result's `DecoderType`.
- To **answer the ordering question**, we will document the pipeline stage sequence: scanner worker → (overlap worker OR detector worker) → notifier worker, establishing that overlap detection happens before deduplication.
- To **explain variable result counts**, we will document how the Base64 decoder's `FromChunk` (in `pkg/decoders/base64.go`) modifies `chunk.Data` in place (line 67), causing the same raw secret to appear in the decoded output of both the PLAIN and BASE64 decoder passes, and how the deduplication cache's `DecoderType` comparison determines whether both or only one result survives.


## 0.2 Repository Scope Discovery

### 0.2.1 Comprehensive File Analysis

The investigation spans three primary subsystems within the TruffleHog v3 codebase. Every file listed below was retrieved and analyzed during context gathering.

**Decoder Pipeline Files (pkg/decoders/)**

| File | Purpose | Relevance |
|------|---------|-----------|
| `pkg/decoders/decoders.go` | Defines `Decoder` interface, `DecodableChunk` wrapper, `DefaultDecoders()` ordering | Central: establishes the iteration order (UTF8 → Base64 → UTF16 → EscapedUnicode) that directly controls how many decoder passes produce non-nil results |
| `pkg/decoders/utf8.go` | PLAIN decoder; sanitizes invalid UTF-8 but always returns a non-nil `DecodableChunk` for valid input | Critical: this decoder always succeeds for text files, guaranteeing at least one PLAIN-typed result per matching detector |
| `pkg/decoders/base64.go` | BASE64 decoder; scans for runs of ≥20 Base64-charset characters, decodes them, and substitutes decoded bytes in-place | Critical: when it successfully decodes a Base64 string containing an AWS key, it produces a second decoded chunk with `DecoderType_BASE64` where the plaintext secret is now embedded |
| `pkg/decoders/utf16.go` | UTF16 decoder; heuristic conversion of UTF-16 byte patterns to UTF-8 | Low relevance: returns nil for standard ASCII/UTF-8 text files, so it will not produce results for the user's scenario |
| `pkg/decoders/escaped_unicode.go` | ESCAPED_UNICODE decoder; normalizes `\uXXXX` and `U+XXXX` escape sequences | Low relevance: returns nil when no escape patterns are found, so it will not fire for plain/Base64 AWS keys |

**Engine Orchestration Files (pkg/engine/)**

| File | Purpose | Relevance |
|------|---------|-----------|
| `pkg/engine/engine.go` (lines 1–1356) | Core engine: `scannerWorker`, `detectorWorker`, `verificationOverlapWorker`, `notifierWorker`, `processResult`, result deduplication via LRU cache | Central: contains all three behaviors under investigation — decoder iteration, overlap detection routing, and deduplication |
| `pkg/engine/engine.go:777-841` | `scannerWorker`: iterates decoders, finds matching detectors via Aho-Corasick, routes to overlap or detector channels | The exact location where each decoder's output is independently matched and dispatched |
| `pkg/engine/engine.go:924-1034` | `verificationOverlapWorker`: processes chunks matched by >1 detector, uses `likelyDuplicate` with Levenshtein similarity to detect cross-detector overlap | Determines whether verification is disabled due to overlap |
| `pkg/engine/engine.go:1189-1235` | `notifierWorker`: performs final deduplication using an LRU cache keyed on `DetectorType + Raw + RawV2 + SourceMetadata`, with `DecoderType` comparison to allow/suppress duplicates | The last stage that controls final result count |
| `pkg/engine/engine.go:887-922` | `likelyDuplicate` function: compares secrets across detectors using exact match and Levenshtein distance (threshold 0.9) | Overlap detection logic that only compares secrets from different detector types |
| `pkg/engine/metrics.go` | Prometheus metrics declarations for decode latency, detector execution, chunks scanned | Supporting: provides observability into which decoders and detectors are executing |

**Aho-Corasick Matching (pkg/engine/ahocorasick/)**

| File | Purpose | Relevance |
|------|---------|-----------|
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword prefiltering using Aho-Corasick trie; `FindDetectorMatches` returns matched detectors with span extraction | Important: determines how many detectors match a given decoded chunk, which controls whether the overlap path is taken |

**Detector Framework (pkg/detectors/)**

| File | Purpose | Relevance |
|------|---------|-----------|
| `pkg/detectors/detectors.go` | `Result`, `ResultWithMetadata` structs; `CleanResults` function; `CopyMetadata` helper | Important: `Raw` and `RawV2` fields form part of the deduplication key; `CleanResults` filters unverified duplicates before they reach the notifier |
| `pkg/detectors/aws/common.go` | Shared AWS regex pattern `SecretPat` for the 40-character secret key | Relevant: the regex that actually extracts the secret bytes used in deduplication |
| `pkg/detectors/aws/access_keys/accesskey.go` | AWS access key scanner: `idPat` regex for AKIA/ABIA/ACCA prefixes, `Keywords()` returns `["AKIA", "ABIA", "ACCA"]` | Relevant: the detector that matches in the user's AWS key scenario |

**Protobuf Definitions (pkg/pb/detectorspb/)**

| File | Purpose | Relevance |
|------|---------|-----------|
| `pkg/pb/detectorspb/detectors.pb.go` | Generated protobuf types including `DecoderType` enum (UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4) | Reference: defines the decoder type labels attached to results |

**Documentation and Test Data**

| File | Purpose | Relevance |
|------|---------|-----------|
| `docs/process_flow.md` | Architecture overview of Source Decomposition → Detector Matching → Secret Detection → Result Notification pipeline | Context: confirms the high-level flow and mentions De-Dupe-Detectors stage |
| `pkg/engine/testdata/secrets.txt` | Test fixture with AWS key, generic secret, and repeated sentry tokens | Reference: shows how the existing test suite validates duplicate handling |
| `pkg/engine/testdata/verificationoverlap_secrets.txt` | Test fixture for overlap detection with a Postman API key | Reference: demonstrates the overlap detection test scenario |
| `pkg/engine/testdata/verificationoverlap_detectors.yaml` | Custom detector YAML config for overlap test | Reference: shows how two detectors can match the same secret |
| `main.go` | CLI entrypoint; defines `--allow-verification-overlap` flag (line 65) | Reference: shows how the user-facing flag maps to `Config.VerificationOverlap` |

### 0.2.2 Integration Point Discovery

The investigation touches the following integration points across the pipeline:

- **Scanner Worker → Decoder Pipeline**: `scannerWorker` (engine.go:784) calls `decoder.FromChunk(chunk)` for each decoder in sequence. The chunk's `.Data` field is mutated by decoders (Base64 modifies it in place at base64.go:67; UTF8 may sanitize it at utf8.go:24).
- **Scanner Worker → Aho-Corasick Core**: `e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` at engine.go:795 determines which detectors match the decoded content.
- **Scanner Worker → Overlap Channel**: At engine.go:796–805, chunks with >1 matching detector and `!e.verificationOverlap` are routed to `verificationOverlapChunksChan`.
- **Scanner Worker → Detector Channel**: At engine.go:807–816, chunks are sent to `detectableChunksChan` for standard detection.
- **Detector Worker → Verification Cache → Detector.FromData**: At engine.go:1070–1075, the detector's `FromData` method is called with the matched bytes.
- **Detector Worker → Notifier Channel**: At engine.go:1186, `e.results <- secret` sends the result to the notifier.
- **Notifier Worker → Deduplication Cache**: At engine.go:1216–1221, the LRU cache determines whether the result is a duplicate.

### 0.2.3 New File Requirements

- **CREATE**: `blitzy/documentation/trufflehog_e42153d44a5e.md` — The comprehensive Markdown analysis document answering all investigative questions. This is the sole deliverable.

No new source files, test files, or configuration files are required. The investigation is purely analytical with a documentation output.


## 0.3 Dependency Inventory

### 0.3.1 Key Packages Relevant to Investigation

The following packages are directly involved in the decoder pipeline, overlap detection, and deduplication subsystems being investigated. All versions are sourced from `go.mod` and `go.sum` in the repository root.

| Registry | Package | Version | Purpose |
|----------|---------|---------|---------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | v3 (module root) | The TruffleHog v3 application itself |
| Go stdlib | `encoding/base64` | (Go 1.23.1+) | Used by `pkg/decoders/base64.go` for StdEncoding and RawURLEncoding Base64 decoding |
| Go stdlib | `unicode/utf8` | (Go 1.23.1+) | Used by `pkg/decoders/utf8.go` and `pkg/decoders/escaped_unicode.go` for rune validation |
| Go stdlib | `encoding/binary` | (Go 1.23.1+) | Used by `pkg/decoders/utf16.go` for BigEndian/LittleEndian uint16 decoding |
| Go stdlib | `bytes`, `regexp`, `strconv` | (Go 1.23.1+) | Core string manipulation used across all decoders |
| go.dev | `github.com/hashicorp/golang-lru/v2` | v2.0.7 | LRU cache implementation used by `engine.dedupeCache` for result deduplication (engine.go:209, 493) |
| go.dev | `github.com/adrg/strutil` | v0.3.1 | String similarity utilities, specifically `strutil.Similarity` used in `likelyDuplicate` (engine.go:911) |
| go.dev | `github.com/adrg/strutil/metrics` | v0.3.1 | Levenshtein distance metric used as the similarity algorithm (`metrics.NewLevenshtein()` at engine.go:911) |
| go.dev | `github.com/BobuSumisu/aho-corasick` | v1.0.0 | Aho-Corasick trie for efficient multi-pattern keyword matching in `ahocorasickcore.go` |
| go.dev | `github.com/wasilibs/go-re2` | v1.8.0 | RE2-compatible regex engine used by the AWS detector (`idPat` and `SecretPat` patterns) |
| go.dev | `google.golang.org/protobuf` | v1.36.6 | Protobuf runtime; `proto.Clone` used in `processResult` for metadata copying (engine.go:1161) |
| Go toolchain | `go` | 1.23.1 (toolchain go1.24.2) | Go language version specified in `go.mod` |

### 0.3.2 Dependency Updates

No dependency additions or modifications are required for this investigation. The task is read-only analysis producing a documentation artifact. All required packages are already present in the repository's `go.mod` and `go.sum`.

### 0.3.3 Import Relationships

The critical import chain for the investigation spans:

- `pkg/engine/engine.go` imports `pkg/decoders`, `pkg/detectors`, `pkg/engine/ahocorasick`, `pkg/sources`, and `pkg/pb/detectorspb`
- `pkg/decoders/*.go` imports `pkg/pb/detectorspb` (for `DecoderType` enum) and `pkg/sources` (for `Chunk` struct)
- `pkg/engine/ahocorasick/ahocorasickcore.go` imports `pkg/detectors` and `pkg/pb/detectorspb`
- `pkg/detectors/detectors.go` imports `pkg/sources` and `pkg/pb/*`

No import updates are needed since no source files are being modified.


## 0.4 Integration Analysis

### 0.4.1 Existing Code Touchpoints

The investigation requires deep understanding of the following code touchpoints, which represent the stages through which a scanned chunk flows at runtime. No modifications are made; these are read-only analysis targets.

**Stage 1: Chunk Ingestion and Decoder Iteration**

- `pkg/engine/engine.go:777-841` — `scannerWorker` function
  - At line 784, iterates `for _, decoder := range e.decoders` which defaults to `[UTF8, Base64, UTF16, EscapedUnicode]` as set by `pkg/decoders/decoders.go:8-16`.
  - At line 786, calls `decoder.FromChunk(chunk)`. This is the critical call that may return nil (decoder not applicable) or a `DecodableChunk` with a `DecoderType` label.
  - **Key observation**: The chunk pointer is shared across decoder iterations. When `base64.FromChunk` mutates `chunk.Data` at `pkg/decoders/base64.go:67`, subsequent decoders (UTF16, EscapedUnicode) operate on the already-modified data. However, the UTF8 decoder runs first and returns the original data.

**Stage 2: Detector Matching via Aho-Corasick**

- `pkg/engine/engine.go:795` — `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)`
  - Each decoded chunk (one per successful decoder) is independently matched against the keyword trie.
  - `pkg/engine/ahocorasick/ahocorasickcore.go:241-284` — `FindDetectorMatches` lowercases the data, runs trie matching, computes spans, merges overlapping spans, and returns `[]*DetectorMatch`.

**Stage 3: Overlap Detection Routing Decision**

- `pkg/engine/engine.go:796-805` — The branch point:
  - If `len(matchingDetectors) > 1 && !e.verificationOverlap` → route to `verificationOverlapChunksChan`
  - Otherwise → route each detector match to `detectableChunksChan`
  - For the user's AWS key scenario with default detectors, typically only the AWS access key detector matches (via keywords "AKIA", "ABIA", "ACCA"), so `len(matchingDetectors) == 1` and the standard path is taken.

**Stage 4: Verification Overlap Processing**

- `pkg/engine/engine.go:924-1034` — `verificationOverlapWorker`
  - Runs `detector.FromData(ctx, false, match)` with verification disabled (second arg is `false`).
  - Constructs `chunkSecretKey{secret, detectorKey}` at line 977 and checks against previously seen secrets.
  - Calls `likelyDuplicate` at line 982 to compare secrets across different detector types using Levenshtein distance (threshold 0.9).
  - If overlap detected: sets `errOverlap` verification error, sends result directly through `processResult`, and removes the detector from the re-verification list.
  - If no overlap: the detector is re-queued to `detectableChunksChan` with verification enabled at lines 1011–1020.

**Stage 5: Detection and Result Emission**

- `pkg/engine/engine.go:1044-1124` — `detectChunk`
  - Calls `e.verificationCache.FromData(ctx, data.detector.Detector, ...)` at line 1070, which delegates to the detector's `FromData`.
  - Applies `e.filterResults` at line 1113, which may invoke `CleanResults` (retains only verified results, or the first unverified if none are verified).
  - Sends each surviving result through `e.processResult` at line 1117.

**Stage 6: Result Processing and Metadata**

- `pkg/engine/engine.go:1152-1187` — `processResult`
  - At line 1177: `secret := detectors.CopyMetadata(&data.chunk, res)` creates `ResultWithMetadata`.
  - At line 1178: `secret.DecoderType = data.decoder` — the decoder type from the originating decoder pass is stamped onto the result.
  - At line 1186: `e.results <- secret` sends to the notifier channel.

**Stage 7: Deduplication in Notifier Worker**

- `pkg/engine/engine.go:1189-1235` — `notifierWorker`
  - At line 1216: constructs deduplication key as `DetectorType + Raw + RawV2 + SourceMetadata` (notably, `DecoderType` is NOT part of the key).
  - At line 1217-1219: checks LRU cache — if the key exists AND the stored `DecoderType` differs from the current result's `DecoderType`, the result is suppressed.
  - The deduplication logic intentionally **allows** duplicate results with the **same** `DecoderType` (e.g., the same secret found multiple times by the same decoder) but **suppresses** duplicate results with **different** `DecoderType` values (e.g., the same secret found once via PLAIN and once via BASE64).
  - Special case at line 1218: Postman source type always deduplicates regardless of decoder type.

### 0.4.2 Data Flow Diagram

```mermaid
flowchart TD
    A["Source Chunk<br/>(raw file data)"] --> B["scannerWorker"]
    B --> C1["UTF8 Decoder<br/>(DecoderType_PLAIN)"]
    B --> C2["Base64 Decoder<br/>(DecoderType_BASE64)"]
    B --> C3["UTF16 Decoder<br/>(DecoderType_UTF16)"]
    B --> C4["EscapedUnicode Decoder<br/>(DecoderType_ESCAPED_UNICODE)"]
    
    C1 -->|"non-nil"| D1["FindDetectorMatches<br/>(Aho-Corasick)"]
    C2 -->|"non-nil if Base64 found"| D2["FindDetectorMatches<br/>(Aho-Corasick)"]
    C3 -->|"nil for ASCII text"| X1["Skipped"]
    C4 -->|"nil if no escapes"| X2["Skipped"]
    
    D1 -->|">1 detectors<br/>AND !overlapAllowed"| E["verificationOverlapWorker<br/>(likelyDuplicate check)"]
    D1 -->|"1 detector<br/>OR overlapAllowed"| F["detectableChunksChan"]
    D2 -->|"same routing logic"| F
    
    E -->|"overlap found"| G["processResult<br/>(errOverlap set)"]
    E -->|"no overlap"| F
    
    F --> H["detectorWorker<br/>(FromData + verify)"]
    H --> I["processResult<br/>(CopyMetadata + DecoderType stamp)"]
    
    G --> J["results channel"]
    I --> J
    
    J --> K["notifierWorker<br/>(dedupeCache check)"]
    K -->|"key new OR same DecoderType"| L["Dispatch to output"]
    K -->|"key exists AND different DecoderType"| M["Suppressed"]
```

### 0.4.3 Critical Interaction: Chunk Data Mutation

A key subtlety in the decoder pipeline is that decoders operate on a **shared chunk pointer**. The `scannerWorker` does not clone `chunk.Data` between decoder iterations (engine.go:784–786). This means:

- The UTF8 decoder (first in order) sees the original data and always returns a `DecodableChunk`.
- The Base64 decoder (second) scans the data for Base64 runs, decodes them, and **overwrites** `chunk.Data` with the substituted result (base64.go:67: `chunk.Data = result.Bytes()`).
- The UTF16 and EscapedUnicode decoders (third and fourth) see the **already-modified** data from the Base64 pass, not the original.

This mutation is why `DefaultDecoders()` includes the comment "UTF8 must be first for duplicate detection" (decoders.go:10). The PLAIN decoder captures the unmodified view, while subsequent decoders may transform the data and yield decoded views of encoded secrets.


## 0.5 Technical Implementation

### 0.5.1 File-by-File Execution Plan

Since this is a read-only investigation with a single documentation deliverable, the execution plan centers on creating the analysis document. No existing files are modified.

- **Group 1 — Deliverable Document**:
  - **CREATE**: `blitzy/documentation/trufflehog_e42153d44a5e.md` — Comprehensive Markdown analysis answering all five investigative questions, structured with sections covering the decoder pipeline mechanics, overlap detection logic, deduplication behavior, pipeline ordering, and variable result count explanation.

### 0.5.2 Implementation Approach

The analysis document must be constructed by tracing the exact code paths for three distinct scenarios and documenting the observed (or logically deduced) behavior for each:

**Scenario A: File contains only the raw AWS key (plain text)**

- UTF8 decoder returns DecodableChunk with PLAIN type and the original data.
- Base64 decoder scans for ≥20-character Base64 runs. An AKIA-prefixed key (`AKIA2OGYBAH6STMMNXNN`) is 20 characters of Base64-valid chars, so it meets the threshold (base64.go:36, threshold=20). However, decoding it as Base64 yields non-ASCII garbage, which fails the `isASCII` check (base64.go:41), so the Base64 decoder returns nil.
- UTF16 and EscapedUnicode decoders return nil for standard ASCII text.
- Result: One PLAIN result from the AWS detector. **Single result**.

**Scenario B: File contains the Base64-encoded AWS key only**

- UTF8 decoder returns the Base64-encoded string as-is (it is valid UTF-8), with PLAIN type.
- The Aho-Corasick keyword match for "AKIA" does **not** match the Base64-encoded form (since Base64 encoding transforms the character sequence), so no detector matches the PLAIN chunk.
- Base64 decoder finds the long Base64 run, decodes it successfully, substitutes the decoded bytes, and returns a BASE64-typed chunk containing the raw key.
- Aho-Corasick now finds "AKIA" in the decoded data, and the AWS detector matches.
- Result: One BASE64 result. **Single result**.

**Scenario C: File contains both raw and Base64-encoded AWS key**

- UTF8 decoder returns the full file data (both raw and encoded forms present), PLAIN type. Aho-Corasick matches "AKIA" in the raw portion. AWS detector fires and extracts the key. **One PLAIN result emitted**.
- Base64 decoder finds the Base64-encoded run, decodes it, and substitutes in the chunk data (mutating `chunk.Data`). The resulting data now contains both the original raw key AND the newly decoded key from the Base64 segment. Aho-Corasick matches "AKIA" (potentially in both locations). The AWS detector fires and extracts the key. **One BASE64 result emitted**.
- Both results have the same `DetectorType` (AWS), the same `Raw` bytes (the AKIA key), and the same `SourceMetadata` (same file). The deduplication key at engine.go:1216 is therefore **identical** for both results.
- The first result to reach the notifier is stored in the LRU cache with its `DecoderType` (e.g., PLAIN).
- The second result arrives with a **different** `DecoderType` (e.g., BASE64). The cache check at engine.go:1217 finds the key exists, and `val != result.DecoderType` evaluates to true, so the second result is **suppressed**.
- **Final count: 1 result** (whichever decoder's result reaches the notifier first).

**Why the count varies**: The race between which decoder's result reaches the notifier first depends on concurrency, channel buffering, and goroutine scheduling. With `Concurrency=1`, the processing is more deterministic — the PLAIN result from the first decoder iteration typically reaches the notifier first. With higher concurrency, the arrival order can vary.

### 0.5.3 Key Code Path Analysis

**Deduplication Key Construction (engine.go:1216)**:
```go
key := fmt.Sprintf("%s%s%s%+v",
  result.DetectorType.String(),
  result.Raw, result.RawV2,
  result.SourceMetadata)
```

Note that `DecoderType` is deliberately **excluded** from this key. This means results from different decoders that find the same raw secret with the same detector type and source metadata will collide in the cache.

**Deduplication Decision (engine.go:1217-1219)**:
```go
if val, ok := e.dedupeCache.Get(key); ok &&
  (val != result.DecoderType || result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
  continue
}
```

The logic is: if we have seen this key before AND the stored decoder type is different from the current one, skip this result. This intentionally allows the same secret found by the same decoder in different locations to be reported multiple times, while suppressing cross-decoder duplicates of the same logical secret.

**Overlap Detection vs. Deduplication Ordering**:

The pipeline stages execute in this strict order:
1. `scannerWorker` — decodes chunks, matches detectors, routes to overlap or detector channels
2. `verificationOverlapWorker` — handles multi-detector matches, may re-route to detector channel
3. `detectorWorker` — runs detector-specific extraction and verification
4. `notifierWorker` — applies deduplication and dispatches results

Overlap detection occurs at stage 2, deduplication at stage 4. They are **not** alternatives; they are complementary. Overlap detection prevents verification of secrets claimed by multiple detectors. Deduplication prevents the same logical result from being reported more than once to the user, regardless of which decoder found it.

### 0.5.4 User Interface Design

Not applicable — this is a CLI-based investigation with a documentation output. No UI changes are involved.


## 0.6 Scope Boundaries

### 0.6.1 Exhaustively In Scope

**Analysis Targets (read-only examination)**:
- `pkg/decoders/**/*.go` — All decoder implementations and the decoder interface
- `pkg/engine/engine.go` — Scanner worker, detector worker, overlap worker, notifier worker, deduplication cache
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Keyword matching and detector dispatch
- `pkg/detectors/detectors.go` — Result struct, CleanResults, CopyMetadata
- `pkg/detectors/aws/**/*.go` — AWS access key detector (idPat, SecretPat, Keywords)
- `pkg/pb/detectorspb/detectors.pb.go` — DecoderType enum definition
- `pkg/sources/sources.go` — Chunk struct definition
- `pkg/engine/testdata/**` — Existing test fixtures for overlap and deduplication scenarios
- `pkg/engine/engine_test.go` — Existing test cases (`TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, `TestLikelyDuplicate`)
- `docs/process_flow.md` — Architecture documentation
- `main.go` — CLI flag definitions (`--allow-verification-overlap`)
- `go.mod` — Module and version information

**Deliverable Output**:
- `blitzy/documentation/trufflehog_e42153d44a5e.md` — The investigation results document

**Temporary Test Data** (created and removed during investigation):
- Any temporary files created for controlled experiments to verify decoder behavior must be removed after investigation concludes

### 0.6.2 Explicitly Out of Scope

- **Source file modifications**: No existing `.go` files, test files, configuration files, or protobuf definitions will be changed.
- **New Go source code**: No new `.go` files, test files, or packages will be added to the repository.
- **Detector implementations beyond AWS**: While the analysis references the detector framework broadly, detailed investigation of individual detectors other than the AWS access key detector is not in scope.
- **Performance optimization**: No profiling, benchmarking, or performance-related changes.
- **CI/CD pipeline changes**: No modifications to `.github/workflows/`, `Makefile`, `.goreleaser.yml`, or `Dockerfile`.
- **TruffleHog Enterprise features**: The investigation is limited to the open-source engine behavior.
- **Verification against live APIs**: The investigation does not involve making actual API calls to verify secrets; it analyzes the code paths that would be traversed.
- **Handler/archive processing**: The `pkg/handlers/` subsystem for file type detection and archive traversal is not part of this investigation.
- **Source-specific scanning logic**: Individual source implementations (GitHub, GitLab, S3, etc.) are out of scope beyond understanding the generic chunk flow.


## 0.7 Rules for Feature Addition

### 0.7.1 User-Specified Rules

The following rules were explicitly provided by the user and must be strictly observed:

- **`SWE-AtlasQnA-Repo` Rule**: Create a new Markdown document named `<source_branch_name>.md` (i.e., `trufflehog_e42153d44a5e.md`) that comprehensively answers the question(s) posed in the prompt.
  - Provide thinking and rationale behind the answers.
  - Base all answers on the code as the truth; do not make assumptions.
  - Do not modify any existing files in the source repository.
  - Do not add any other code in the source repository besides the requested document.
  - Place the generated document in the `blitzy/documentation` directory in the destination repo.

- **No source modification**: "Do not modify any existing source files in the repository." This applies to all `.go` files, test files, configuration files, and documentation files already present in the repository.

- **Cleanup requirement**: "Remove any test data created during the investigation." Any temporary files (e.g., test input files with dummy AWS keys used to trace decoder behavior) must be deleted before the task is marked complete.

### 0.7.2 Repository Conventions to Follow

- The output document must follow Markdown formatting conventions consistent with the existing documentation in the `docs/` directory.
- Code references must use the format `filename:line_number` or `filename:start-end` for ranges to match the style used in code comments (e.g., `engine.go` line 1 references `docs/process_flow.md`).
- Technical explanations must be grounded in specific file paths and line numbers, not in external documentation or general descriptions.

### 0.7.3 Investigation Integrity Requirements

- All behavioral assertions in the document must be traceable to specific code in the repository at the current commit.
- Where behavior depends on concurrency or timing, the document must clearly state the nondeterministic aspects and explain the range of possible outcomes.
- The document must distinguish between: behavior that is guaranteed by the code (e.g., decoder ordering), behavior that is typical but timing-dependent (e.g., which decoder's result reaches the notifier first), and behavior that varies based on configuration (e.g., `--allow-verification-overlap` flag).


## 0.8 References

### 0.8.1 Repository Files and Folders Searched

The following files and folders were retrieved and analyzed during context gathering to derive all conclusions in this Agent Action Plan:

**Root-Level Files**:
- `go.mod` — Module definition, Go version (1.23.1), toolchain (go1.24.2), dependencies
- `main.go` — CLI entrypoint, `--allow-verification-overlap` flag definition (line 65), engine configuration wiring (line 528)

**Decoder Pipeline (`pkg/decoders/`)**:
- `pkg/decoders/decoders.go` — Decoder interface, DecodableChunk struct, DefaultDecoders() ordering, Fuzz entrypoint
- `pkg/decoders/utf8.go` — UTF8/PLAIN decoder implementation, extractSubstrings sanitizer, isPrintableByte
- `pkg/decoders/base64.go` — Base64 decoder, getSubstringsOfCharacterSet (threshold=20), in-place data mutation, isASCII filter
- `pkg/decoders/utf16.go` — UTF16 decoder, utf16ToUTF8 heuristic conversion
- `pkg/decoders/escaped_unicode.go` — EscapedUnicode decoder, codePointPat/escapePat regexes, data cloning

**Engine Orchestration (`pkg/engine/`)**:
- `pkg/engine/engine.go` — Full file (1356 lines): Config, Engine struct, NewEngine, scannerWorker, detectorWorker, verificationOverlapWorker, notifierWorker, processResult, likelyDuplicate, CleanResults filtering, LRU deduplication, errOverlap sentinel
- `pkg/engine/metrics.go` — Prometheus metrics for decode latency, detector execution, chunk scanning
- `pkg/engine/engine_test.go` — TestEngine_DuplicateSecrets (line 241), TestVerificationOverlapChunk (line 503), TestVerificationOverlapChunkFalsePositive (line 599), TestLikelyDuplicate (line 890)

**Aho-Corasick Matching (`pkg/engine/ahocorasick/`)**:
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Core struct, FindDetectorMatches, CreateDetectorKey, spanCalculator strategies, DetectorMatch with span merging

**Test Fixtures (`pkg/engine/testdata/`)**:
- `pkg/engine/testdata/secrets.txt` — AWS key, generic secret, repeated sentry tokens
- `pkg/engine/testdata/verificationoverlap_secrets.txt` — Postman API key for overlap testing
- `pkg/engine/testdata/verificationoverlap_detectors.yaml` — Two custom detector definitions for overlap testing

**Detector Framework (`pkg/detectors/`)**:
- `pkg/detectors/detectors.go` — Result struct (Raw, RawV2, Verified, verificationError), ResultWithMetadata struct (DecoderType field), CopyMetadata, CleanResults, SetVerificationError
- `pkg/detectors/aws/common.go` — SecretPat regex, RequiredIdEntropy, RequiredSecretEntropy constants
- `pkg/detectors/aws/access_keys/accesskey.go` — Scanner struct, idPat regex (`AKIA|ABIA|ACCA` + 16 chars), Keywords()

**Protobuf Definitions (`pkg/pb/`)**:
- `pkg/pb/detectorspb/detectors.pb.go` — DecoderType enum (UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4)

**Source Framework (`pkg/sources/`)**:
- `pkg/sources/sources.go` — Chunk struct (Data, SourceName, SourceMetadata, Verify fields)

**Documentation (`docs/`)**:
- `docs/process_flow.md` — Architecture diagrams for Source Decomposition, Chunk to Detector Matching, Secret Detection, Result Notification
- `docs/concurrency.md` — Referenced but not directly needed for this investigation

**Folder Structures Explored**:
- Root (`""`) — Repository overview and file listing
- `pkg/` — Core package tree overview
- `pkg/decoders/` — All decoder files
- `pkg/engine/` — Engine files and subfolders
- `pkg/engine/ahocorasick/` — Aho-Corasick implementation
- `pkg/engine/testdata/` — Test fixtures
- `pkg/detectors/` — Detector framework and provider catalog

### 0.8.2 Attachments

No external attachments were provided for this project. The investigation is based entirely on the repository source code.

### 0.8.3 External References

- TruffleHog v3 repository module path: `github.com/trufflesecurity/trufflehog/v3` (from `go.mod` line 1)
- AWS IAM Unique ID reference types (AKIA, ABIA, ACCA): referenced in `pkg/detectors/aws/access_keys/accesskey.go` line 64
- Aho-Corasick algorithm library: `github.com/BobuSumisu/aho-corasick` (from `go.mod`)
- Levenshtein distance for similarity: `github.com/adrg/strutil` with `metrics.NewLevenshtein()` (from `go.mod`)
- LRU cache: `github.com/hashicorp/golang-lru/v2` (from `go.mod`)


