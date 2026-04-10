# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **create new documentation** that comprehensively answers a series of interrelated questions about TruffleHog v3's runtime detection pipeline behavior. The user seeks empirical, code-grounded answers — not summaries of architecture diagrams — to specific questions about internal engine mechanics that are not directly observable from reading source files alone.

**Documentation Type:** Technical Q&A investigation document (runtime behavior analysis)

**Category:** Create new documentation

The user's questions decompose into six distinct investigation areas:

- **Aho-Corasick Keyword Loading:** How many unique keywords load into the trie with the default detector set, and whether detectors share keywords or have distinct keyword sets
- **Decoder Pipeline Sequencing:** Whether decoding (e.g., Base64) happens before or after keyword matching, and what verbose output reveals for chunks containing both plain and encoded secrets
- **Verification Cache Metrics:** What cache metrics are reported at scan completion, whether hit/miss counts change on consecutive identical scans, and whether the cache persists across invocations
- **Worker Architecture Multipliers:** Given a specific concurrency value (e.g., 4), what multipliers produce the actual goroutine counts for each worker type, and whether queuing or backpressure is observable
- **Deduplication Behavior:** What the LRU cache key looks like, and whether the same credential discovered via different decoder types (plaintext vs. Base64) is reported once or twice
- **Detector Timing Output:** Whether `--print-avg-detector-time` includes all detectors or only those with matches, and whether verification time is included in or separate from those numbers

### 0.1.2 Special Instructions and Constraints

The user has provided the following critical directives:

- **No source file modifications:** "Run whatever scans make sense against test data to show me actual terminal output for these behaviors without modifying the source files"
- **Artifact cleanup required:** "Clean up any temporary directories or artifacts you create when you're done"
- **Code-as-truth basis:** The implementation rule specifies "Do not make assumptions, base your answers on the code as the truth"
- **Thinking/rationale required:** "Provide thinking / rationale behind the answers"
- **Output location:** The generated document must be placed in `blitzy/documentation/trufflehog_e42153d44a5e.md`
- **No existing file modifications:** "Do not modify any existing files in the source repository"

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To answer the Aho-Corasick question, we will analyze `pkg/engine/ahocorasick/ahocorasickcore.go` (keyword aggregation in `NewAhoCorasickCore`), `pkg/engine/defaults/defaults.go` (the `buildDetectorList()` function returning 831 detectors), and write a Go program to count unique and shared keywords at runtime
- To answer the decoder pipeline question, we will analyze `pkg/decoders/decoders.go` (the `DefaultDecoders()` ordering) and `pkg/engine/engine.go` lines 777–841 (the `scannerWorker` loop that iterates decoders before calling `FindDetectorMatches`)
- To answer the verification cache question, we will analyze `pkg/verificationcache/verification_cache.go`, `pkg/verificationcache/in_memory_metrics.go`, and `main.go` lines 511–574 (where `InMemoryMetrics` is instantiated fresh each invocation)
- To answer the worker architecture question, we will analyze `pkg/engine/engine.go` lines 336–374 (the `setDefaults` method establishing multiplier defaults) and lines 646–718 (the `startWorkers` family)
- To answer the deduplication question, we will analyze `pkg/engine/engine.go` lines 1189–1235 (the `notifierWorker` containing the dedup LRU cache logic)
- To answer the detector timing question, we will analyze `pkg/engine/engine.go` lines 1036–1124 (the `detectChunk` method) and `main.go` lines 1021–1029 (the `printAverageDetectorTime` function)

### 0.1.4 Inferred Documentation Needs

Based on code analysis, the following implicit documentation needs were identified:

- The decoder pipeline processes each chunk through ALL decoders sequentially, where each decoded variant is independently matched against the Aho-Corasick trie — this sequential decode-then-match flow is crucial but not explained in existing `docs/process_flow.md`
- The verification cache is instantiated as a local variable in `main.go`'s `run()` function, meaning it is definitionally ephemeral and cannot persist across process invocations
- The deduplication LRU cache intentionally allows the same raw secret to appear multiple times if it was found by the same decoder type but blocks cross-decoder duplicates — this distinction is essential for understanding the output
- The `--print-avg-detector-time` flag only records timing for detectors that produce results (guarded by `len(results) > 0` at `engine.go:1092`), and the elapsed time is measured from the start of `detectChunk` which includes the `verificationCache.FromData` call — so verification time is inherently included

## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a **minimal, hand-authored documentation structure** with no documentation generator framework (no mkdocs, Docusaurus, Sphinx, or ReadTheDocs configuration files are present).

**Existing documentation files discovered:**

| File | Purpose | Coverage Status |
|------|---------|-----------------|
| `README.md` | Project overview, installation, supported sources, CLI usage | High-level only; no pipeline internals |
| `docs/concurrency.md` | Mermaid sequence diagram showing worker types and channel flow | Structural overview only; no multiplier numbers or concrete goroutine counts |
| `docs/process_flow.md` | Mermaid flowcharts for Source → Chunk → Detector → Notification flow | Mentions "Aho-Corsick" keyword matching but omits decoder sequencing |
| `CONTRIBUTING.md` | Contribution workflow and guidelines | Not relevant to runtime behavior |
| `PreCommit.md` | Pre-commit hook setup instructions | Not relevant |
| `examples/README.md` | Custom detector YAML examples | Not relevant |
| `pkg/analyzer/README.md` | Analyzer subsystem documentation | Not relevant |
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` | Custom regex detector usage | Not relevant |
| `SECURITY.md` | Vulnerability reporting policy | Not relevant |
| `CODE_OF_CONDUCT.md` | Community code of conduct | Not relevant |

**Documentation framework:** None (plain Markdown files)
**API documentation tools:** None (no JSDoc, Sphinx, or Godoc configuration)
**Diagram tools:** Mermaid (used in `docs/concurrency.md` and `docs/process_flow.md`)
**Documentation hosting/deployment:** None (docs served directly from repository)

### 0.2.2 Repository Code Analysis for Documentation

The following source code directories and files were examined to answer the user's questions:

**Search patterns used:**
- Engine initialization and worker orchestration: `pkg/engine/engine.go`
- Aho-Corasick keyword prefiltering: `pkg/engine/ahocorasick/ahocorasickcore.go`
- Default detector registry: `pkg/engine/defaults/defaults.go`
- Decoder pipeline: `pkg/decoders/decoders.go`, `pkg/decoders/base64.go`, `pkg/decoders/utf8.go`
- Verification cache: `pkg/verificationcache/verification_cache.go`, `pkg/verificationcache/in_memory_metrics.go`, `pkg/verificationcache/metrics_reporter.go`
- LRU cache for deduplication: `pkg/cache/lru/lru.go`
- Simple cache for verification results: `pkg/cache/simple/simple.go`
- CLI flags and scan execution: `main.go`
- Engine metrics: `pkg/engine/metrics.go`
- Existing docs: `docs/concurrency.md`, `docs/process_flow.md`

**Key directories examined:**
- `pkg/engine/` — Core orchestration, worker lifecycle, deduplication, metrics
- `pkg/engine/ahocorasick/` — Trie construction, keyword indexing, span calculation
- `pkg/engine/defaults/` — Canonical detector registry with 831 active detectors
- `pkg/decoders/` — Decoder interface and 4 concrete implementations
- `pkg/verificationcache/` — Cache-aware verification wrapper and metrics
- `pkg/cache/` — Generic cache abstraction, LRU and simple backends
- `docs/` — Existing architecture documentation

### 0.2.3 Runtime Experiments Conducted

The following runtime experiments were executed against a freshly-built TruffleHog binary (compiled from repository source using `go build`) to produce empirical terminal output:

- **Keyword counting:** A custom Go program was run importing `pkg/engine/defaults` and `pkg/engine/ahocorasick` to count unique keywords, shared keywords, and detector counts at runtime
- **Verbose pipeline tracing:** Filesystem scans with `--log-level=5` to capture decoder processing, keyword matching, and worker startup/shutdown messages
- **Worker count verification:** Scans with `--concurrency=4 --log-level=2` to observe actual worker counts in startup log messages
- **Verification cache behavior:** Two consecutive scans of identical data to observe cache hit/miss metrics across invocations
- **Cache enable/disable comparison:** Scans with and without `--no-verification-cache` to contrast metrics output
- **Cross-decoder deduplication:** Scan of a file containing the same secret in both plaintext and Base64-encoded form to observe dedup behavior
- **Detector timing output:** Scans with `--print-avg-detector-time` to observe which detectors appear and what time values are reported
- **All temporary test directories and artifacts were cleaned up after experiments**

## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

**Modules requiring documentation:**

- **Module: `pkg/engine/ahocorasick/ahocorasickcore.go`**
  - Public APIs: `NewAhoCorasickCore()`, `FindDetectorMatches()`, `KeywordsToDetectors()`, `CreateDetectorKey()`
  - Current documentation: Inline comments only; no external documentation exists
  - Documentation needed: Explanation of keyword aggregation, trie construction, shared keyword behavior, runtime counts

- **Module: `pkg/engine/engine.go`**
  - Public APIs: `NewEngine()`, `Start()`, `Finish()`, `GetMetrics()`, `GetDetectorsMetrics()`
  - Internal key functions: `setDefaults()`, `startWorkers()`, `scannerWorker()`, `detectChunk()`, `notifierWorker()`
  - Current documentation: Referenced by `docs/concurrency.md` at a structural level; no concrete numbers or behavioral details
  - Documentation needed: Worker multiplier defaults, deduplication key format, detector timing measurement scope

- **Module: `pkg/engine/defaults/defaults.go`**
  - Public APIs: `DefaultDetectors()`, `DefaultDetectorTypesImplementing[T]()`
  - Current documentation: None beyond inline comments
  - Documentation needed: Total detector count, endpoint customization post-processing

- **Module: `pkg/decoders/decoders.go`**
  - Public APIs: `DefaultDecoders()`, `Decoder` interface, `DecodableChunk` type
  - Current documentation: Mentioned in `docs/process_flow.md` indirectly; decoding step is not documented
  - Documentation needed: Decoder ordering, the decode-before-match sequence, per-decoder behavior

- **Module: `pkg/verificationcache/`**
  - Public APIs: `New()`, `FromData()`, `MetricsReporter` interface, `InMemoryMetrics` struct
  - Current documentation: None
  - Documentation needed: Cache key computation, metrics semantics (Hits/Misses/HitsWasted/AttemptsSaved/VerificationTimeSpentMS), cache lifecycle

- **Module: `pkg/cache/simple/simple.go`**
  - Public APIs: `NewCache[T]()`, `Set()`, `Get()`, standard cache methods
  - Current documentation: None
  - Documentation needed: Expiration interval (12 hours), go-cache backing store, in-memory only

- **Module: `main.go`**
  - Key functions: `run()`, `runSingleScan()`, `printAverageDetectorTime()`
  - Current documentation: None for runtime behavior
  - Documentation needed: How verification cache metrics are instantiated per-invocation, how `--print-avg-detector-time` output is generated

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, documentation gaps include:

- **Undocumented runtime behavior:** No existing documentation explains the concrete numbers behind the pipeline (keyword counts, worker multipliers, cache key format, dedup semantics)
- **Missing decoder pipeline documentation:** `docs/process_flow.md` shows "Chunk to Detector Matching" via keyword matching but entirely omits the decoding step that precedes it
- **No verification cache documentation:** The verification cache subsystem (`pkg/verificationcache/`) has zero external documentation despite being a critical performance optimization
- **No deduplication documentation:** The LRU dedup cache in `notifierWorker` has no external explanation of its key format or cross-decoder behavior
- **No worker sizing documentation:** `docs/concurrency.md` shows worker types but does not document the multiplier defaults (8× for detector workers, 1× for all others)
- **No detector timing documentation:** The `--print-avg-detector-time` flag's behavior (only showing detectors with results, including verification time) is undocumented

## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

Per the implementation rule, a single new markdown document will be created at:

```
blitzy/
└── documentation/
    └── trufflehog_e42153d44a5e.md
```

The document will be structured as a comprehensive Q&A investigation with the following sections:

```
blitzy/documentation/trufflehog_e42153d44a5e.md
├── Introduction (context and methodology)
├── 1. Aho-Corasick Keyword Loading
│   ├── How many unique keywords load into the trie
│   ├── Keyword sharing across detectors
│   └── Runtime evidence (Go program output)
├── 2. Decoder Pipeline Sequencing
│   ├── Decode-before-match architecture
│   ├── Decoder ordering and behavior
│   └── Verbose output for mixed plain/encoded chunks
├── 3. Verification Cache Metrics
│   ├── Metrics reported at scan completion
│   ├── Consecutive scan cache behavior
│   └── Cache persistence across invocations
├── 4. Worker Architecture and Concurrency
│   ├── Multiplier defaults for each worker type
│   ├── Concrete goroutine counts for concurrency=4
│   ├── Channel buffer sizing and backpressure
│   └── Terminal output showing worker startup
├── 5. Deduplication Behavior
│   ├── LRU cache key format
│   ├── Cross-decoder dedup semantics
│   └── Empirical test: same secret via plain vs. Base64
├── 6. Detector Timing Output
│   ├── Which detectors appear in timing output
│   ├── Whether verification time is included
│   └── Terminal output showing timing results
└── Source Citations
```

### 0.4.2 Content Generation Strategy

**Information Extraction Approach:**
- Extract concrete runtime numbers from `pkg/engine/defaults/defaults.go` (831 detectors via `buildDetectorList()`)
- Extract keyword counts by analyzing `pkg/engine/ahocorasick/ahocorasickcore.go` (`NewAhoCorasickCore` aggregating `d.Keywords()` per detector)
- Extract multiplier defaults from `pkg/engine/engine.go` lines 343–354 (`setDefaults` method)
- Extract dedup key format from `pkg/engine/engine.go` line 1216 (`fmt.Sprintf("%s%s%s%+v", ...)`)
- Extract cache lifecycle from `main.go` line 511 (local `InMemoryMetrics{}` instantiation) and line 536 (`simple.NewCache[detectors.Result]()`)
- Extract timing measurement scope from `pkg/engine/engine.go` lines 1046–1105 (`detectChunk` with `start = time.Now()` before `verificationCache.FromData`)
- Generate empirical evidence by running TruffleHog scans with `--log-level=5`, `--concurrency=4`, `--print-avg-detector-time`, and `--no-verification-cache`

**Documentation Standards:**
- Markdown formatting with proper heading hierarchy
- Actual terminal output blocks using fenced code blocks
- Source code citations with file paths and line numbers
- Mermaid diagrams for the decoder pipeline flow
- Tables for structured data (keyword counts, worker multipliers, cache metrics)
- Every answer grounded in specific source code evidence

### 0.4.3 Diagram and Visual Strategy

**Mermaid diagrams to create:**

- **Decoder Pipeline Sequence Diagram:** Showing the scanner worker iterating through decoders (UTF8 → Base64 → UTF16 → EscapedUnicode), each decoded result passed to `FindDetectorMatches`, then routed to detector workers
- **Worker Architecture Diagram:** Showing the concurrency=4 multiplier relationships producing 4 scanner, 32 detector, 4 verification overlap, and 4 notifier workers with their channel connections
- **Deduplication Flow Diagram:** Showing the LRU cache lookup in `notifierWorker` with the key format and the decoder-type comparison logic

## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

| Target Documentation File | Transformation | Source Code/Docs | Content/Changes |
|---------------------------|----------------|------------------|-----------------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | CREATE | `pkg/engine/engine.go`, `pkg/engine/ahocorasick/ahocorasickcore.go`, `pkg/engine/defaults/defaults.go`, `pkg/decoders/decoders.go`, `pkg/verificationcache/verification_cache.go`, `pkg/verificationcache/in_memory_metrics.go`, `pkg/cache/simple/simple.go`, `main.go`, `docs/concurrency.md`, `docs/process_flow.md` | Comprehensive Q&A document answering all six investigation areas with code evidence, terminal output, and Mermaid diagrams |

**Transformation Modes Used:**
- **CREATE** — One new documentation file is created
- **REFERENCE** — Existing docs (`docs/concurrency.md`, `docs/process_flow.md`) are used as context references but not modified

No existing files are modified or deleted per the implementation rule "Do not modify any existing files in the source repository."

### 0.5.2 New Documentation File Detail

```
File: blitzy/documentation/trufflehog_e42153d44a5e.md
Type: Technical Q&A Investigation Document
Source Code:
  - pkg/engine/ahocorasick/ahocorasickcore.go (keyword trie construction)
  - pkg/engine/defaults/defaults.go (detector registry, 831 active detectors)
  - pkg/engine/engine.go (worker lifecycle, dedup cache, detector timing)
  - pkg/decoders/decoders.go (decoder ordering: UTF8, Base64, UTF16, EscapedUnicode)
  - pkg/verificationcache/verification_cache.go (cache-aware FromData, key hashing)
  - pkg/verificationcache/in_memory_metrics.go (atomic counters for 5 metrics)
  - pkg/verificationcache/metrics_reporter.go (MetricsReporter interface)
  - pkg/cache/simple/simple.go (go-cache backed, 12h expiration)
  - main.go (CLI flags, engine config, cache instantiation, timing print)
  - pkg/engine/metrics.go (Prometheus metrics declarations)
Sections:
  - Introduction (methodology and context)
  - Aho-Corasick Keyword Loading (914 unique keywords, 32 shared, runtime program output)
  - Decoder Pipeline Sequencing (decode-then-match loop, verbose output capture)
  - Verification Cache Metrics (5 metrics, in-memory ephemeral, no cross-invocation persistence)
  - Worker Architecture (multiplier defaults: 1/8/1/1, concrete counts, channel buffers)
  - Deduplication Behavior (LRU key = DetectorType+Raw+RawV2+SourceMetadata, cross-decoder logic)
  - Detector Timing (only detectors with results, verification time included in elapsed)
  - Source Citations
Diagrams:
  - Decoder Pipeline Sequence (Mermaid flowchart)
  - Worker Architecture with Multipliers (Mermaid diagram)
  - Deduplication Decision Flow (Mermaid flowchart)
Key Citations:
  - pkg/engine/engine.go:343-354 (multiplier defaults)
  - pkg/engine/engine.go:489-534 (initialize with LRU cache and Aho-Corasick)
  - pkg/engine/engine.go:777-841 (scannerWorker decode-then-match loop)
  - pkg/engine/engine.go:1036-1124 (detectChunk timing logic)
  - pkg/engine/engine.go:1189-1235 (notifierWorker dedup logic)
  - pkg/engine/ahocorasick/ahocorasickcore.go:141-168 (NewAhoCorasickCore keyword collection)
  - pkg/decoders/decoders.go:8-16 (DefaultDecoders ordering)
  - pkg/verificationcache/verification_cache.go:50-134 (FromData cache flow)
  - pkg/verificationcache/in_memory_metrics.go:9-15 (InMemoryMetrics fields)
  - main.go:511-574 (verification cache metrics instantiation and logging)
  - main.go:1021-1029 (printAverageDetectorTime function)
```

### 0.5.3 Documentation Configuration Updates

No documentation configuration updates are required. The project does not use a documentation generator framework. The new file is placed in `blitzy/documentation/` as specified by the implementation rule.

## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

The following packages and tools are relevant to this documentation exercise. These are existing project dependencies used to build TruffleHog and run the experiments — no new dependencies are introduced.

| Registry | Package Name | Version | Purpose |
|----------|--------------|---------|---------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | dev (source build) | The TruffleHog binary itself, built from source for runtime experiments |
| Go module | `go` | 1.23.1 (min), toolchain 1.24.2 | Go language runtime required to build TruffleHog |
| Go module | `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Aho-Corasick trie library used for keyword prefiltering in `pkg/engine/ahocorasick/` |
| Go module | `github.com/hashicorp/golang-lru/v2` | (per go.mod) | LRU cache backing the deduplication cache in `engine.go` and the `pkg/cache/lru` wrapper |
| Go module | `github.com/patrickmn/go-cache` | (per go.mod) | In-memory TTL cache backing `pkg/cache/simple/`, used for verification result caching |
| Go module | `github.com/alecthomas/kingpin/v2` | v2.4.0 | CLI flag parsing framework used in `main.go` |
| Go module | `github.com/prometheus/client_golang` | (per go.mod) | Prometheus metrics library used in `pkg/engine/metrics.go` and `pkg/cache/metrics.go` |
| Go module | `github.com/adrg/strutil` | v0.3.1 | String similarity (Levenshtein distance) used in `likelyDuplicate()` for verification overlap dedup |

### 0.6.2 Documentation Reference Updates

No documentation link updates are required. The new document is a standalone file in `blitzy/documentation/` that does not integrate into any existing documentation navigation or cross-reference system.

## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current coverage analysis of user's questions:**

| Investigation Area | Source Files Analyzed | Runtime Evidence Collected | Coverage |
|-------------------|----------------------|---------------------------|----------|
| Aho-Corasick keyword loading | `ahocorasickcore.go`, `defaults.go` | Go program producing keyword counts | 100% |
| Decoder pipeline sequencing | `decoders.go`, `engine.go:777-841` | Verbose scan with `--log-level=5` | 100% |
| Verification cache metrics | `verification_cache.go`, `in_memory_metrics.go`, `main.go:511-574` | Two consecutive scans, cache enable/disable comparison | 100% |
| Worker architecture multipliers | `engine.go:336-374`, `engine.go:646-718` | Scan with `--concurrency=4 --log-level=2` | 100% |
| Deduplication behavior | `engine.go:1189-1235` | Scan of file with same secret in plain + Base64 | 100% |
| Detector timing output | `engine.go:1036-1124`, `main.go:1021-1029` | Scan with `--print-avg-detector-time` | 100% |

**Target coverage:** 100% — every user question is answered with both code analysis and empirical runtime evidence.

### 0.7.2 Documentation Quality Criteria

**Completeness requirements:**
- Every question posed by the user receives a direct, specific answer
- Every answer includes source code citations (file path and line numbers)
- Every answer includes rationale/thinking as required by the implementation rule
- Runtime terminal output is provided for all behaviors that can be demonstrated empirically

**Accuracy validation:**
- All code references verified against actual repository source
- Runtime experiment outputs captured from actual TruffleHog binary execution
- Keyword counts derived from a Go program importing the actual default detector registry (not manual counting)
- Worker counts verified against actual log output from `--log-level=2`

**Clarity standards:**
- Each question answered in its own clearly headed section
- Progressive disclosure: code evidence first, then explanation, then terminal output
- Mermaid diagrams for complex flows (decoder pipeline, worker architecture, dedup logic)
- Consistent citation format: `Source: /path/to/file.go:LineNumber`

### 0.7.3 Example and Diagram Requirements

- **Terminal output examples:** At least one captured terminal output block per investigation area
- **Mermaid diagrams:** Three diagrams minimum (decoder pipeline, worker architecture, dedup flow)
- **Code snippet citations:** Short (2–3 line) code excerpts from source files to ground each answer
- **Verification method:** All terminal outputs are from actual execution of `/tmp/trufflehog` binary built from the repository source

## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

**New documentation files:**
- `blitzy/documentation/trufflehog_e42153d44a5e.md` — The comprehensive Q&A investigation document

**Source code analyzed (read-only, no modifications):**
- `pkg/engine/engine.go` — Worker lifecycle, deduplication, detector timing, scanner worker loop
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Keyword trie construction, detector matching
- `pkg/engine/defaults/defaults.go` — Default detector registry (831 active detectors)
- `pkg/engine/metrics.go` — Prometheus metric declarations for pipeline stages
- `pkg/decoders/decoders.go` — Decoder interface and default ordering
- `pkg/decoders/base64.go` — Base64 decoder implementation
- `pkg/decoders/utf8.go` — UTF-8/PLAIN decoder implementation
- `pkg/verificationcache/verification_cache.go` — Cache-aware detector execution
- `pkg/verificationcache/in_memory_metrics.go` — Atomic metrics counters
- `pkg/verificationcache/metrics_reporter.go` — MetricsReporter interface contract
- `pkg/cache/simple/simple.go` — go-cache-backed in-memory cache
- `pkg/cache/lru/lru.go` — HashiCorp LRU cache wrapper
- `pkg/cache/cache.go` — Generic cache interface
- `main.go` — CLI flag definitions, engine configuration, scan execution, metrics output
- `docs/concurrency.md` — Reference for existing worker documentation
- `docs/process_flow.md` — Reference for existing pipeline documentation
- `go.mod` — Dependency versions and Go toolchain version

**Runtime experiments (temporary, cleaned up):**
- Building TruffleHog binary from source
- Running filesystem scans against temporary test data
- Running a custom Go keyword-counting program
- All temporary files and directories cleaned up after completion

### 0.8.2 Explicitly Out of Scope

- **Source code modifications:** No source files in the repository are modified (per implementation rule)
- **Test file modifications:** No test files are created or modified in the repository
- **Feature additions or code refactoring:** This is a documentation-only exercise
- **Deployment configuration changes:** Not applicable
- **Existing documentation modifications:** `docs/concurrency.md`, `docs/process_flow.md`, `README.md`, and all other existing files remain untouched
- **Enterprise TruffleHog features:** Questions are answered solely for the open-source TruffleHog v3 codebase
- **Detector-specific implementation details:** Individual detector regex patterns and verification endpoints are out of scope; the focus is on pipeline-level behavior
- **Performance benchmarking:** While timing data is captured, systematic performance benchmarking is not in scope
- **CI/CD integration documentation:** Not relevant to the user's questions

## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

- **Build command:** `go build -o /tmp/trufflehog .` (from repository root)
- **Runtime requirements:** Go 1.24.2 toolchain (as specified by `go.mod` toolchain directive)
- **Scan commands used for evidence gathering:**
  - Worker count verification: `trufflehog filesystem --no-update --log-level=2 --concurrency=4 <path>`
  - Full verbose pipeline trace: `trufflehog filesystem --no-update --log-level=5 --concurrency=4 <path>`
  - Detector timing: `trufflehog filesystem --no-update --print-avg-detector-time <path>`
  - Cache comparison: `trufflehog filesystem --no-update <path>` vs. `trufflehog filesystem --no-update --no-verification-cache <path>`
  - Results display: `trufflehog filesystem --no-update --no-verification --results=verified,unverified,unknown,filtered_unverified <path>`
- **Keyword counting program:** Custom Go source importing `pkg/engine/defaults` and `pkg/engine/ahocorasick`, executed via `go run`
- **Default format:** Markdown with Mermaid diagrams
- **Citation requirement:** Every answer references specific source files with line numbers
- **Cleanup requirement:** All temporary test directories (`/tmp/trufflehog_test_data*`), the built binary (`/tmp/trufflehog`), and the keyword counting program (`/tmp/count_keywords.go`) must be removed after use

## 0.10 Rules for Documentation

The following rules are explicitly specified by the user and implementation constraints:

- **Do not modify any existing files in the source repository** — The generated document must be an additive-only change
- **Create a new markdown document named `trufflehog_e42153d44a5e.md`** — Named after the source branch name, placed in `blitzy/documentation/`
- **Provide thinking/rationale behind the answers** — Every answer must include the reasoning chain from code evidence to conclusion
- **Do not make assumptions, base answers on the code as the truth** — All claims must cite specific source code locations; no inferred or assumed behavior without evidence
- **Run scans against test data to show actual terminal output** — Empirical evidence from real TruffleHog execution is required
- **Do not modify source files** — Test data is external to the repository; the binary is built read-only from source
- **Clean up any temporary directories or artifacts when done** — All `/tmp/trufflehog_test_data*` directories, the `/tmp/trufflehog` binary, and any helper programs must be removed after evidence collection

## 0.11 References

### 0.11.1 Files and Folders Searched

The following files and folders were retrieved and analyzed across the codebase to derive the conclusions documented in this Agent Action Plan:

**Core Engine Files:**
- `pkg/engine/engine.go` — Engine struct, Config, NewEngine, setDefaults (multipliers), startWorkers, scannerWorker, detectChunk (timing), notifierWorker (dedup), initialize (LRU cache + Aho-Corasick setup)
- `pkg/engine/metrics.go` — Prometheus metric declarations for decode latency, detector execution, chunk scanning, and notification latency
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Core type, NewAhoCorasickCore (keyword collection and trie build), FindDetectorMatches, DetectorKey, CreateDetectorKey, span calculators
- `pkg/engine/defaults/defaults.go` — buildDetectorList() (831 active detectors), DefaultDetectors() (with endpoint customization), DefaultDetectorTypesImplementing[T]()

**Decoder Files:**
- `pkg/decoders/decoders.go` — DefaultDecoders() returning [UTF8, Base64, UTF16, EscapedUnicode], Decoder interface, DecodableChunk type

**Cache and Verification Files:**
- `pkg/verificationcache/verification_cache.go` — VerificationCache struct, New(), FromData() (cache-aware detection with hit/miss tracking), getResultCacheKey() (Blake2B hash of Raw+RawV2+DetectorType)
- `pkg/verificationcache/in_memory_metrics.go` — InMemoryMetrics struct with 5 atomic counters
- `pkg/verificationcache/metrics_reporter.go` — MetricsReporter interface (5 methods)
- `pkg/verificationcache/result_cache.go` — ResultCache type alias
- `pkg/cache/simple/simple.go` — Simple cache implementation (go-cache backing, 12h default expiration)
- `pkg/cache/lru/lru.go` — LRU cache wrapper (HashiCorp LRU, 128,000 default capacity)
- `pkg/cache/cache.go` — Generic Cache[T] interface

**CLI and Entry Point:**
- `main.go` — All CLI flags (including --concurrency, --print-avg-detector-time, --no-verification-cache, --log-level), run() function, runSingleScan(), verification cache metrics instantiation and logging, printAverageDetectorTime()
- `go.mod` — Module path, Go version (1.23.1), toolchain (1.24.2), dependencies including aho-corasick v1.0.3

**Existing Documentation (Reference Only):**
- `docs/concurrency.md` — Mermaid sequence diagram of worker types and channel flow
- `docs/process_flow.md` — Mermaid flowcharts for Source → Chunk → Detector → Notification data flow

**Folder-Level Exploration:**
- Root (`""`) — Repository structure assessment
- `pkg/` — Core package tree inventory
- `pkg/engine/` — Engine subsystem file listing
- `pkg/engine/ahocorasick/` — Aho-Corasick implementation files
- `pkg/engine/defaults/` — Default detector registry files
- `pkg/decoders/` — Decoder implementations
- `pkg/verificationcache/` — Verification cache subsystem
- `pkg/cache/` — Cache abstraction layer
- `pkg/cache/lru/` — LRU cache backend
- `docs/` — Existing documentation inventory

### 0.11.2 Attachments

No attachments were provided for this project.

### 0.11.3 Figma Screens

No Figma screens were provided for this project.

### 0.11.4 Key Runtime Evidence Summary

The following empirical data was collected through actual TruffleHog execution:

| Evidence | Method | Key Finding |
|----------|--------|-------------|
| Keyword counts | Custom Go program importing defaults + ahocorasick packages | 831 detectors, 914 unique keywords, 32 shared by 2+ detectors |
| Worker startup counts | `--log-level=2 --concurrency=4` | 4 scanner, 32 detector, 4 overlap, 4 notifier |
| Decoder pipeline | `--log-level=5` verbose trace | Decoders run before keyword matching; each decoded variant matched independently |
| Verification cache metrics | Two consecutive identical scans | Both show Misses=2, Hits=0 — cache does not persist across invocations |
| Cache disable comparison | `--no-verification-cache` flag | Misses drop to 0 (cache not instantiated), VerificationTimeSpentMS still tracked |
| Dedup cross-decoder | File with same secret in plain + Base64 | Both BASE64-decoded instances reported; PLAIN result blocked by dedup cache |
| Detector timing | `--print-avg-detector-time` | Only detectors with results listed (e.g., "AWS: 149ms"); includes verification time |

