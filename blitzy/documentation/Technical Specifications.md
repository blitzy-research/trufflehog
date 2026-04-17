# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Feature Objective

Based on the prompt, the Blitzy platform understands that the new feature requirement is to **conduct a behavioral investigation of TruffleHog's internal runtime pipeline** — specifically the interaction between three subsystems: the **decoder pipeline**, the **verification overlap detection** system, and the **result deduplication** layer — and to produce a comprehensive markdown analysis document capturing the findings.

- **Decoder Pipeline Investigation**: Verify how TruffleHog's ordered decoder chain (UTF-8/PLAIN → Base64 → UTF16 → EscapedUnicode) processes the same logical secret when it appears in multiple encoded forms within a single chunk. Determine which decoder types are reported in the final output and why.
- **Overlap Detection Investigation**: Determine how the `verificationOverlapWorker` (`pkg/engine/engine.go`, lines 924–1034) handles chunks matched by more than one detector, how cross-detector similarity is measured (Levenshtein distance with 0.9 threshold via `likelyDuplicate()`), and what conditions trigger the `errOverlap` error message.
- **Deduplication Investigation**: Determine how the LRU-based dedup cache in the `notifierWorker` (`pkg/engine/engine.go`, lines 1189–1235) decides which decoder-variant result to keep and which to suppress, and why the reported `DecoderName` can vary non-deterministically across runs.
- **Interaction Sequencing**: Establish the precise order of operations — dedup happens **after** overlap detection — and identify where concurrency introduces non-determinism in the final output.
- **Single-vs-Multiple Result Behavior**: Explain why the same logical secret sometimes produces one result and sometimes appears to produce multiple, depending on file structure, concurrency, and the `--allow-verification-overlap` flag.
- **No Source Modifications**: All investigation must be conducted without modifying any existing repository source files; any test data files created during investigation must be removed before completion.

Implicit requirements detected:
- The investigation requires **building and running** the TruffleHog binary from source to observe runtime behavior with crafted test inputs.
- Test scenarios must cover plain-text secrets, base64-encoded secrets, Unicode-escaped secrets, and combinations thereof.
- The analysis must trace data flow across the four pipeline stages documented in `docs/process_flow.md` and `docs/concurrency.md`.
- The deliverable is a standalone markdown document placed in `blitzy/documentation/` named `<source_branch_name>.md`.

### 0.1.2 Special Instructions and Constraints

- **Read-Only Constraint**: "Do not modify any existing source files in the repository" — all analysis is observational, accomplished through code reading, building the binary, and running it against temporary test files.
- **Cleanup Requirement**: "Remove any test data created during the investigation" — all temporary test files created under `/tmp/trufflehog_tests/` must be deleted after experiments are complete.
- **Implementation Rule `SWE-AtlasQnA-Repo`**: Create a markdown document named `trufflehog_e42153d44a5e.md` that comprehensively answers the posed questions, based on code as truth, with thinking/rationale provided. Place it in `blitzy/documentation/`.
- **No Assumptions**: All answers must be grounded in the actual source code and observed runtime behavior, not assumed patterns.

### 0.1.3 Technical Interpretation

These investigation requirements translate to the following technical implementation strategy:

- To **understand the decoder pipeline**, we will read `pkg/decoders/decoders.go`, `pkg/decoders/utf8.go`, `pkg/decoders/base64.go`, `pkg/decoders/escaped_unicode.go`, and `pkg/decoders/utf16.go`, then trace how `scannerWorker` in `pkg/engine/engine.go` iterates through decoders for each chunk and submits each non-nil decoded variant independently to downstream channels.
- To **understand overlap detection**, we will read the `verificationOverlapWorker` function in `pkg/engine/engine.go` (lines 924–1034) and the `likelyDuplicate()` function (lines 880–920), then construct scenarios where multiple detectors (e.g., AWS + Voiceflow) keyword-match on the same decoded chunk.
- To **understand deduplication**, we will read the `notifierWorker` function in `pkg/engine/engine.go` (lines 1189–1235), focusing on the LRU cache keyed by `DetectorType + Raw + RawV2 + SourceMetadata` and the conditional `val != result.DecoderType` check, then run the binary with varying concurrency to observe which decoder type wins the race.
- To **produce the deliverable**, we will create `blitzy/documentation/trufflehog_e42153d44a5e.md` containing the comprehensive analysis with code references, runtime observations, and explanatory diagrams.

## 0.2 Repository Scope Discovery

### 0.2.1 Comprehensive File Analysis

The investigation focuses on a well-defined set of source files that implement the decoder pipeline, overlap detection, result deduplication, and their orchestration within the engine. No existing files are modified; all are read for analysis purposes only.

**Core Pipeline Files (Read for Analysis)**

| File Path | Purpose | Relevance |
|-----------|---------|-----------|
| `pkg/decoders/decoders.go` | Defines the `Decoder` interface, `DecodableChunk` struct, and `DefaultDecoders()` ordering | Establishes the fixed decoder sequence: UTF8 → Base64 → UTF16 → EscapedUnicode |
| `pkg/decoders/utf8.go` | UTF-8 (PLAIN) decoder — sanitizes invalid UTF-8, always produces output | Baseline decoder that always fires for text-based input |
| `pkg/decoders/base64.go` | Base64 decoder — finds ≥20-char base64 runs, decodes via StdEncoding and RawURLEncoding | Replaces base64 substrings in-place, preserving surrounding text |
| `pkg/decoders/utf16.go` | UTF-16 decoder — heuristic byte-order detection | Only fires for actual UTF-16 binary data |
| `pkg/decoders/escaped_unicode.go` | Escaped Unicode decoder — normalizes `U+XXXX` and `\uXXXX` sequences | Only fires when unicode escape patterns are present |
| `pkg/engine/engine.go` | Central engine orchestration — scanner workers, overlap workers, detector workers, notifier workers | Contains `scannerWorker` (lines 777–841), `verificationOverlapWorker` (lines 924–1034), `detectorWorker` (lines 1036–1044), `detectChunk` (lines 1044–1188), `notifierWorker` (lines 1189–1235), `likelyDuplicate` (lines 880–920), and dedup logic (lines 1213–1221) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Aho-Corasick prefilter — keyword matching, span calculation, match merging | `FindDetectorMatches()` determines which detectors match a decoded chunk |
| `pkg/engine/metrics.go` | Prometheus metrics for decode latency, scan throughput | Observability for decoder performance |
| `pkg/detectors/detectors.go` | `Result`, `ResultWithMetadata`, `CleanResults()`, `CopyMetadata()` | Defines result structure and base dedup/cleaning logic |
| `pkg/detectors/aws/access_keys/accesskey.go` | AWS access key detector — regex, entropy, `CleanResults` override | Used as primary test detector; implements `CustomResultsCleaner` |
| `pkg/detectors/aws/utils.go` | AWS-specific `CleanResults()` — deduplicates by `Redacted` field (key ID) | Intra-detector deduplication before results reach the engine dedup |
| `pkg/detectors/aws/common.go` | AWS entropy thresholds (`RequiredIdEntropy=3.0`, `RequiredSecretEntropy=4.25`) | Governs which key/secret pairs pass entropy filtering |
| `pkg/pb/detectorspb/detectors.pb.go` | Protobuf-generated decoder type constants (`PLAIN=1`, `BASE64=2`, `UTF16=3`, `ESCAPED_UNICODE=4`) | Maps decoder enum values to string names |
| `pkg/output/json.go` | JSON output printer — serializes `ResultWithMetadata` including `DecoderName` | Produces the observable output where decoder type is visible |
| `pkg/detectors/false_positives.go` | False positive filter logic | Filters known false positive patterns |
| `pkg/detectors/fp_words.txt` | Word list including "example" | Causes AKIAIOSFODNN7EXAMPLE to be filtered |

**Test Data and Documentation Files (Read for Analysis)**

| File Path | Purpose |
|-----------|---------|
| `pkg/engine/testdata/secrets.txt` | Test fixture with AWS + Sentry secrets; used by `TestEngine_DuplicateSecrets` |
| `pkg/engine/testdata/verificationoverlap_secrets.txt` | Postman key for overlap testing |
| `pkg/engine/testdata/verificationoverlap_detectors.yaml` | Custom detector config for overlap tests |
| `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` | False positive overlap test data |
| `pkg/engine/testdata/verificationoverlap_detectors_fp.yaml` | Custom detector config for FP overlap tests |
| `pkg/engine/engine_test.go` | Engine tests including `TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, `TestLikelyDuplicate` |
| `docs/process_flow.md` | Official pipeline architecture documentation |
| `docs/concurrency.md` | Official concurrency model documentation |

**Configuration and Build Files (Read for Analysis)**

| File Path | Purpose |
|-----------|---------|
| `go.mod` | Go module definition — Go 1.23.1, toolchain go1.24.2 |
| `go.sum` | Dependency checksums |
| `Makefile` | Build targets — `make test`, `make build` |
| `main.go` | CLI entry point |

### 0.2.2 Web Search Research Conducted

No external web searches were required for this investigation. All findings are derived directly from the source code, existing test fixtures, and runtime experiments using the built binary. The official documentation in `docs/process_flow.md` and `docs/concurrency.md` provided the necessary architectural context.

### 0.2.3 New File Requirements

- **CREATE**: `blitzy/documentation/trufflehog_e42153d44a5e.md` — Comprehensive markdown analysis document answering all investigation questions regarding decoder pipeline, overlap detection, and deduplication interactions. This is the sole deliverable file.

No other new files are required. All temporary test data files created during the investigation have been cleaned up as instructed.

## 0.3 Dependency Inventory

### 0.3.1 Key Packages Relevant to This Investigation

The following packages are central to the decoder pipeline, overlap detection, and deduplication subsystems under investigation. All versions are taken directly from `go.mod` and `go.sum`.

| Registry | Package | Version | Purpose |
|----------|---------|---------|---------|
| Go Modules | `github.com/trufflesecurity/trufflehog/v3` | `e42153d4` (commit) | The TruffleHog engine itself |
| Go Modules | `github.com/BobuSumisu/aho-corasick` | `v1.0.3` | Multi-pattern keyword matching trie used by `AhoCorasickCore.FindDetectorMatches()` |
| Go Modules | `github.com/hashicorp/golang-lru/v2` | (from go.sum) | LRU cache backing the 512-entry dedup cache in `notifierWorker` |
| Go Modules | `github.com/adrg/strutil` | `v0.3.1` | Levenshtein distance calculation in `likelyDuplicate()` for overlap detection |
| Go Modules | `google.golang.org/protobuf` | (from go.sum) | Protobuf marshaling for `DecoderType` enum and `SourceMetadata` in dedup key generation |
| Go Modules | `github.com/wasilibs/go-re2` | (from go.sum) | RE2-based regex engine used by detectors (e.g., AWS `idPat`) |
| Go stdlib | `encoding/base64` | (stdlib) | Base64 StdEncoding and RawURLEncoding used by the Base64 decoder |
| Go stdlib | `unicode/utf8` | (stdlib) | UTF-8 validation and rune decoding used by the UTF-8 and UTF-16 decoders |
| Go stdlib | `sync` | (stdlib) | `sync.WaitGroup`, `sync.Map`, `sync.Mutex` for worker coordination |
| Go stdlib | `encoding/binary` | (stdlib) | Big-endian/little-endian byte-order interpretation in the UTF-16 decoder |

### 0.3.2 Runtime and Toolchain

| Component | Version | Source |
|-----------|---------|--------|
| Go Language | `1.23.1` (minimum) | `go.mod` line 3 |
| Go Toolchain | `go1.24.2` | `go.mod` line 5 |
| Build Mode | `CGO_ENABLED=0` | `Makefile` targets |

### 0.3.3 Dependency Updates

No dependency updates are required for this investigation. The task is purely analytical — reading code, building the existing binary, and running it against test inputs. No new packages need to be added, and no import paths need to be changed.

## 0.4 Integration Analysis

### 0.4.1 Existing Code Touchpoints

The investigation traces data flow across four tightly integrated subsystems. No modifications are made; all touchpoints are documented for analytical purposes.

**Decoder Pipeline → Scanner Worker Integration**

The `scannerWorker` function (`pkg/engine/engine.go`, lines 777–841) is the integration point between the decoder pipeline and the rest of the engine. For each chunk received from `ChunksChan()`:

- It iterates through `e.decoders` (the ordered `DefaultDecoders()` list) at line 786.
- Each decoder's `FromChunk(chunk)` is called. If the decoder returns non-nil, the decoded variant independently enters the Aho-Corasick matching stage.
- This means a single raw chunk containing both a plain-text secret and its base64-encoded form will produce **two separate decoded chunks** — one from the PLAIN decoder and one from the BASE64 decoder — each containing the secret in plain text.

**Scanner Worker → Overlap Detection Integration**

The routing decision at lines 796–812 determines whether a decoded chunk enters the overlap path or the direct detection path:

- If `len(matchingDetectors) > 1 && !e.verificationOverlap`: the chunk is sent to `verificationOverlapChunksChan` with all matching detectors bundled together.
- Otherwise: each matching detector receives its own `detectableChunk` on `detectableChunksChan`.

For AWS access keys, the Voiceflow detector also keyword-matches (keyword `"dm"` appears in base64-decoded data containing `"AKIAWARWQKZNHMZBLY4I"`), causing **two detectors** to match and triggering the overlap path by default.

**Overlap Worker → Detector Worker Integration**

The `verificationOverlapWorker` (`pkg/engine/engine.go`, lines 924–1034) processes each overlapping chunk by:

- Running `FromData(ctx, verify=false, matchBytes)` on each detector without verification (line 944).
- Checking cross-detector result similarity using `likelyDuplicate()` (line 985).
- For AWS + Voiceflow: Voiceflow produces 0 results (its regex `VF\.\.\..` does not match AKIA patterns), so no cross-detector duplicate is found.
- Non-duplicate detectors are re-routed to `detectableChunksChan` with verification enabled (lines 1017–1026).

**Detector Worker → Notifier Worker (Deduplication) Integration**

The `notifierWorker` (`pkg/engine/engine.go`, lines 1189–1235) applies the final deduplication layer:

- Dedup key: `fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)` (line 1217).
- The LRU cache stores the `DecoderType` of the first result for each key.
- Subsequent results with the **same key but different DecoderType** are suppressed (line 1218).
- Results with the **same key and same DecoderType** are allowed through (they represent genuine repeated findings from the same decoder).

### 0.4.2 Concurrency-Driven Non-Determinism

The critical integration point for the user's observed inconsistency is the **concurrent pipeline between overlap workers, detector workers, and the notifier**:

- With `concurrency=1`: 1 scanner worker, 1 overlap worker, 8 detector workers, 1 notifier worker. The FIFO ordering through the single overlap worker preserves the decoder iteration order (PLAIN first), so PLAIN consistently wins the dedup race.
- With `concurrency>1` (default `runtime.NumCPU()`): multiple overlap workers and notifier workers process results concurrently. The first result to arrive at a notifier worker's dedup check wins, and this is non-deterministic due to goroutine scheduling. Observed results across 15 runs showed PLAIN winning ~53%, BASE64 ~33%, and ESCAPED_UNICODE ~13% of the time.

### 0.4.3 Integration Sequence Diagram

The precise order of operations across subsystems for a chunk containing both plain-text and base64-encoded versions of the same AWS key:

```mermaid
sequenceDiagram
    participant SW as Scanner Worker
    participant DEC as Decoder Chain
    participant AC as Aho-Corasick
    participant OW as Overlap Worker
    participant DW as Detector Workers
    participant NW as Notifier Worker
    participant OUT as Output

    SW->>DEC: FromChunk(chunk) [PLAIN decoder]
    DEC-->>SW: DecodableChunk (contains plaintext AKIA)
    SW->>AC: FindDetectorMatches(decoded)
    AC-->>SW: [AWS, Voiceflow] (2 detectors)
    Note over SW: >1 detector → overlap path
    SW->>OW: verificationOverlapChunksChan

    SW->>DEC: FromChunk(chunk) [BASE64 decoder]
    DEC-->>SW: DecodableChunk (b64→plaintext AKIA)
    SW->>AC: FindDetectorMatches(decoded)
    AC-->>SW: [AWS, Voiceflow] (2 detectors)
    SW->>OW: verificationOverlapChunksChan

    OW->>OW: Process PLAIN chunk: AWS=1 result, Voiceflow=0
    Note over OW: No cross-detector dup → re-route AWS
    OW->>DW: detectableChunksChan (PLAIN, AWS)

    OW->>OW: Process BASE64 chunk: AWS=1 result, Voiceflow=0
    OW->>DW: detectableChunksChan (BASE64, AWS)

    DW->>DW: detectChunk(PLAIN) → AWS result
    DW->>NW: results chan (DecoderType=PLAIN)

    DW->>DW: detectChunk(BASE64) → AWS result
    DW->>NW: results chan (DecoderType=BASE64)

    Note over NW: Race condition: whichever arrives first wins
    NW->>NW: First result → add to dedup cache
    NW->>OUT: Dispatch first result
    NW->>NW: Second result → same key, different decoder → SKIP
```

## 0.5 Technical Implementation

### 0.5.1 File-by-File Execution Plan

Since this is a read-only investigation task, the execution plan centers on building the binary, running targeted experiments, analyzing the source code, and producing the deliverable document. Only one file is created.

**Group 1 — Build and Environment Setup**

- **READ**: `go.mod` — Confirm Go 1.23.1 minimum and go1.24.2 toolchain
- **READ**: `Makefile` — Understand build command (`CGO_ENABLED=0 go install .`)
- **BUILD**: `main.go` → `/tmp/trufflehog_bin` — Compile TruffleHog binary for experiment execution

**Group 2 — Decoder Pipeline Analysis**

- **READ**: `pkg/decoders/decoders.go` — Document the `DefaultDecoders()` order and `Decoder` interface
- **READ**: `pkg/decoders/utf8.go` — Confirm UTF-8/PLAIN decoder always returns non-nil for valid UTF-8 input
- **READ**: `pkg/decoders/base64.go` — Document the in-place substitution behavior: base64 substrings are replaced with decoded content while surrounding text is preserved
- **READ**: `pkg/decoders/escaped_unicode.go` — Document `\uXXXX` and `U+XXXX` pattern matching and replacement
- **READ**: `pkg/decoders/utf16.go` — Document heuristic byte-order detection for UTF-16

**Group 3 — Engine Pipeline Analysis**

- **READ**: `pkg/engine/engine.go` — Trace the full data path through `scannerWorker`, `verificationOverlapWorker`, `detectorWorker`/`detectChunk`, and `notifierWorker`
- **READ**: `pkg/engine/ahocorasick/ahocorasickcore.go` — Document `FindDetectorMatches()` and span merging logic
- **READ**: `pkg/engine/engine_test.go` — Study `TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, and `TestLikelyDuplicate` for expected behaviors
- **READ**: `docs/process_flow.md` and `docs/concurrency.md` — Cross-reference official documentation

**Group 4 — Runtime Experiments**

- **RUN**: Experiment A — Plain-text-only AWS key → observe PLAIN decoder reported
- **RUN**: Experiment B — Base64-only AWS key → observe BASE64 decoder reported
- **RUN**: Experiment C — Plain + Base64 combined → observe dedup selecting one decoder non-deterministically
- **RUN**: Experiment D — Plain + Base64 + Unicode-escaped → observe three decoders firing, one surviving dedup
- **RUN**: Experiment E — Concurrency=1 repeated runs → observe deterministic PLAIN selection
- **RUN**: Experiment F — Concurrency=8 repeated runs → observe non-deterministic decoder selection
- **RUN**: Experiment G — Two separate files with same secret → observe both results kept (different SourceMetadata)
- **CLEANUP**: Remove all temporary test files under `/tmp/trufflehog_tests/`

**Group 5 — Deliverable Document Creation**

- **CREATE**: `blitzy/documentation/trufflehog_e42153d44a5e.md` — Comprehensive analysis document containing:
  - Decoder pipeline mechanics with code references
  - Overlap detection algorithm and conditions
  - Deduplication logic and LRU cache behavior
  - Interaction sequence between subsystems
  - Explanation of non-deterministic behavior with concurrency
  - Runtime experiment results as evidence
  - Answers to all five user questions

### 0.5.2 Implementation Approach

The implementation follows a systematic investigation methodology:

- **Establish foundation** by reading all decoder implementations to understand the transformation each applies to chunk data, confirming through the `DefaultDecoders()` function that the order is fixed and the PLAIN decoder always fires first.
- **Trace the pipeline** by following the data flow from `scannerWorker` through the branching logic at line 796 (`len(matchingDetectors) > 1`) to either the overlap channel or the detector channel, documenting how each decoded variant is independently routed.
- **Verify overlap behavior** by examining how `verificationOverlapWorker` runs `FromData` without verification, uses `likelyDuplicate()` with a 0.9 Levenshtein similarity threshold, and either marks results with `errOverlap` or re-routes them for full detection.
- **Verify dedup behavior** by examining the LRU cache logic in `notifierWorker` where the key `DetectorType+Raw+RawV2+SourceMetadata` determines identity and the stored `DecoderType` determines whether a subsequent result is suppressed.
- **Validate with experiments** by building the binary and running it against crafted test files with varying concurrency settings to confirm the non-deterministic decoder selection under concurrent execution.
- **Document findings** in the deliverable markdown file with precise code line references, runtime evidence, and clear answers to each of the user's five questions.

## 0.6 Scope Boundaries

### 0.6.1 Exhaustively In Scope

**Source Code Files (Read for Analysis)**

- `pkg/decoders/**/*.go` — All decoder implementations and the decoder interface
- `pkg/engine/engine.go` — Core engine with scanner, overlap, detector, and notifier workers
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Aho-Corasick prefilter and match routing
- `pkg/engine/engine_test.go` — Engine tests for dedup, overlap, and false positive behaviors
- `pkg/engine/testdata/*` — Test fixtures for overlap and dedup scenarios
- `pkg/engine/metrics.go` — Decode latency and scan throughput metrics
- `pkg/detectors/detectors.go` — Result types, CleanResults, CopyMetadata
- `pkg/detectors/aws/access_keys/accesskey.go` — AWS detector used as primary test subject
- `pkg/detectors/aws/utils.go` — AWS-specific CleanResults implementation
- `pkg/detectors/aws/common.go` — Entropy thresholds for AWS credentials
- `pkg/detectors/false_positives.go` — False positive filtering logic
- `pkg/detectors/fp_*.txt` — False positive word lists
- `pkg/pb/detectorspb/detectors.pb.go` — Protobuf DecoderType enum definitions
- `pkg/output/json.go` — JSON output format including DecoderName field
- `docs/process_flow.md` — Official pipeline architecture documentation
- `docs/concurrency.md` — Official concurrency model documentation

**Build and Configuration Files (Read for Context)**

- `go.mod` — Module and toolchain version
- `Makefile` — Build and test targets
- `main.go` — CLI entry point

**Deliverable File (Created)**

- `blitzy/documentation/trufflehog_e42153d44a5e.md` — The investigation analysis document

**Runtime Experiments (Temporary, Cleaned Up)**

- Crafted test files with plain-text, base64-encoded, and unicode-escaped AWS credentials
- Binary invocations with `--no-verification`, `--concurrency=1`, `--concurrency=8`, `--allow-verification-overlap`, and `--json` flags
- Go programs to trace decoder output and detector matching at the function level

### 0.6.2 Explicitly Out of Scope

- **Modification of any existing source files** — The user explicitly prohibits this
- **Adding new Go test files** to the repository test suite
- **Performance optimization** of the decoder pipeline, overlap detection, or deduplication
- **Refactoring** of the dedup cache or overlap detection logic
- **Adding new detectors or decoders** to the pipeline
- **Verification against live APIs** — All experiments use `--no-verification`
- **Analysis of non-filesystem sources** (Git, GitHub, S3, etc.) — Investigation uses filesystem scanning only
- **UI/TUI changes** — The TUI is not relevant to this pipeline investigation
- **CI/CD pipeline modifications** — No changes to `.github/workflows/` or build processes
- **Docker image modifications** — No changes to `Dockerfile` or `Dockerfile.goreleaser`

## 0.7 Rules for Feature Addition

### 0.7.1 User-Specified Rules

The following rules are explicitly emphasized by the user and the project's implementation rules:

- **`SWE-AtlasQnA-Repo` Rule**: Create a new markdown document named `<source_branch_name>.md` (i.e., `trufflehog_e42153d44a5e.md`) that comprehensively answers the investigation questions. Place it in the `blitzy/documentation` directory.
- **Build and Run**: Build and run the source code to analyse repository behavior as needed. Do not make assumptions — base all answers on the code as truth.
- **Provide Rationale**: Include thinking and rationale behind all answers, not just conclusions.
- **No Existing File Modifications**: Do not modify any existing files in the source repository.
- **No Additional Code**: Do not add any other code in the source repository besides the requested document.
- **Cleanup Requirement**: Remove any test data created during the investigation — all temporary files under `/tmp/trufflehog_tests/` must be deleted after experiments conclude.

### 0.7.2 Investigation-Specific Conventions

- **Source of Truth**: The Go source code at commit `e42153d4` is the definitive reference. All behavioral claims must cite specific file paths and line numbers.
- **Reproducibility**: Runtime experiments must document the exact commands, flags, and input data used so findings can be independently verified.
- **Concurrency Awareness**: Since the observed behavior depends on goroutine scheduling, experiments should be run multiple times (≥10 iterations) to capture the distribution of outcomes, not just a single observation.
- **Branch Name**: The source branch is `trufflehog_e42153d44a5e`, which determines the deliverable filename.

## 0.8 References

### 0.8.1 Repository Files and Folders Searched

The following files and folders were systematically explored across the codebase to derive the conclusions documented in this Agent Action Plan:

**Decoder Subsystem**
- `pkg/decoders/decoders.go` — Decoder interface, DefaultDecoders() ordering, DecodableChunk struct
- `pkg/decoders/utf8.go` — PLAIN decoder implementation, extractSubstrings, isPrintableByte
- `pkg/decoders/base64.go` — BASE64 decoder, getSubstringsOfCharacterSet, isASCII, b64Charset
- `pkg/decoders/escaped_unicode.go` — ESCAPED_UNICODE decoder, codePointPat, escapePat regex
- `pkg/decoders/utf16.go` — UTF16 decoder, utf16ToUTF8 with LE/BE heuristic
- `pkg/decoders/base64_test.go`, `pkg/decoders/utf8_test.go`, `pkg/decoders/escaped_unicode_test.go`, `pkg/decoders/utf16_test.go` — Decoder unit tests

**Engine Core**
- `pkg/engine/engine.go` — Full engine implementation (1355 lines): Config, Engine struct, NewEngine, scannerWorker, verificationOverlapWorker, likelyDuplicate, detectorWorker, detectChunk, filterResults, processResult, notifierWorker, FragmentLineOffset, FragmentFirstLineAndLink
- `pkg/engine/engine_test.go` — TestEngine_DuplicateSecrets, TestVerificationOverlapChunk, TestVerificationOverlapChunkFalsePositive, TestRetainFalsePositives, TestLikelyDuplicate, TestEngineLineVariations
- `pkg/engine/metrics.go` — Prometheus metric definitions for decode latency, scan throughput
- `pkg/engine/testdata/secrets.txt` — AWS + Sentry test secrets
- `pkg/engine/testdata/verificationoverlap_secrets.txt` — Postman key overlap test
- `pkg/engine/testdata/verificationoverlap_detectors.yaml` — Custom detector config for overlap
- `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` — False positive overlap test
- `pkg/engine/testdata/verificationoverlap_detectors_fp.yaml` — FP detector config

**Aho-Corasick Prefilter**
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Core, DetectorKey, DetectorMatch, FindDetectorMatches, matchSpan, mergeMatches, spanCalculator implementations
- `pkg/engine/ahocorasick/ahocorasickcore_test.go` — Prefilter unit tests

**Detector Framework**
- `pkg/detectors/detectors.go` — Result, ResultWithMetadata, CleanResults, CopyMetadata, FilterKnownFalsePositives
- `pkg/detectors/aws/access_keys/accesskey.go` — AWS scanner, FromData, Keywords, CleanResults override
- `pkg/detectors/aws/utils.go` — AWS-specific CleanResults dedup by Redacted field
- `pkg/detectors/aws/common.go` — RequiredIdEntropy, RequiredSecretEntropy, SecretPat
- `pkg/detectors/voiceflow/voiceflow.go` — Keywords ["vf", "dm"], keyPat regex
- `pkg/detectors/false_positives.go` — False positive filtering pipeline
- `pkg/detectors/fp_words.txt`, `pkg/detectors/fp_badlist.txt`, `pkg/detectors/fp_programmingbooks.txt` — FP word lists
- `pkg/detectors/endpoint_customizer.go` — EndpointCustomizer interface

**Protobuf Definitions**
- `pkg/pb/detectorspb/detectors.pb.go` — DecoderType enum (UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4)

**Output Layer**
- `pkg/output/json.go` — JSONPrinter with DecoderName field serialization

**Documentation**
- `docs/process_flow.md` — Four-stage pipeline architecture, Source-Unit-Chunk decomposition
- `docs/concurrency.md` — Worker pool sequencing, channel topology

**Build and Configuration**
- `go.mod` — Go 1.23.1, toolchain go1.24.2, module path, replace directives
- `Makefile` — Build targets (CGO_ENABLED=0), test commands
- `main.go` — CLI entry point with automaxprocs

### 0.8.2 Attachments

No external attachments were provided by the user. No Figma URLs or design files were referenced.

### 0.8.3 Runtime Experiments Conducted

The following experiments were executed using the built TruffleHog binary (`/tmp/trufflehog_bin`) to validate code-derived conclusions:

| Experiment | Input | Flags | Key Finding |
|------------|-------|-------|-------------|
| Test A: Plain only | AWS key in plain text | `--no-verification --json` | Single result with `DecoderName=PLAIN` |
| Test B: Plain + Base64 | Both forms in one file | `--no-verification --json` | Single result; decoder varies by run due to concurrency |
| Test C: Base64 only | Only base64-encoded key | `--no-verification --json` | Single result with `DecoderName=BASE64` |
| Test D: Well-separated | Plain and base64 separated by filler | `--no-verification --json` | Single result; decoder varies non-deterministically |
| Test E: All three forms | Plain + Base64 + Unicode escaped | `--no-verification --json` | Single result; PLAIN, BASE64, or ESCAPED_UNICODE across runs |
| Test F: Sentry mixed | Sentry token plain + base64 | `--no-verification --json` | Single result; decoder alternates between PLAIN and BASE64 |
| Test G: Concurrency=1 | Plain + Base64, `--concurrency=1` | `--no-verification --concurrency=1 --json` | Deterministic: always PLAIN (10/10 runs) |
| Test H: Concurrency=8 | Same input, `--concurrency=8` | `--no-verification --concurrency=8 --json` | Non-deterministic: PLAIN ~53%, BASE64 ~33%, ESCAPED_UNICODE ~13% |
| Test I: Two files | Same secret in two separate files | `--no-verification --json` | Two results kept — different SourceMetadata makes dedup keys distinct |
| Test J: allow-overlap | Plain + Base64 with overlap flag | `--allow-verification-overlap --json` | Single result; bypasses overlap worker entirely |
| Go Trace: Decoder output | Programmatic decoder chain execution | N/A (Go program) | Confirmed PLAIN always fires, BASE64 fires when b64 runs present, ESCAPED_UNICODE fires when `\uXXXX` present |
| Go Trace: Detector matches | Programmatic Aho-Corasick matching | N/A (Go program) | Confirmed AWS + Voiceflow both keyword-match, but only AWS produces regex results |

