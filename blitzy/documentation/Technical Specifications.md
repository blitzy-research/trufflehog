# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **create new investigation-driven documentation** that comprehensively explains how TruffleHog's decoder pipeline, overlap detection, and result deduplication subsystems interact at runtime to produce varying output behaviors when the same logical secret appears in multiple encoded forms (plain text, Base64, escaped Unicode).

- **Category**: Create new documentation
- **Documentation type**: Technical investigation / architecture deep-dive document

The user has observed inconsistent behavior when scanning a file containing an AWS access key present in both raw and Base64-encoded forms. Specifically:

- Sometimes TruffleHog reports the same secret twice with different `DecoderType` labels (e.g., `PLAIN` and `BASE64`)
- Sometimes TruffleHog reports a verification overlap error (`errOverlap`) instead of clean results
- Sometimes TruffleHog deduplicates results down to a single finding
- The behavior varies depending on how the test file is structured

These documentation requirements translate to the following five investigative questions, each of which the document must answer with full code citations:

- **Q1 — Decoder Type Reporting**: Which decoder types are reported for a given secret, and why does the same logical secret produce distinct `DecoderType` labels?
- **Q2 — Overlap Detection Triggering**: Under what conditions does the verification overlap path activate, and what error message does it produce?
- **Q3 — Deduplication Behavior**: How does the LRU deduplication cache in the notifier worker decide whether to suppress a result or emit it?
- **Q4 — Ordering of Deduplication vs. Overlap Detection**: Does deduplication happen before or after overlap detection in the pipeline?
- **Q5 — Result Count Variability**: Why does the same logical secret sometimes produce one result and sometimes produce multiple results?

### 0.1.2 Special Instructions and Constraints

The user has specified the following **critical directives** that must be honored:

- **Do not modify any existing source files** in the repository — the document is purely observational and analytical
- **Remove any test data created during the investigation** — if any temporary files are created during exploratory runs, they must be cleaned up
- **Base answers on the code as the truth** — do not make assumptions; every claim must be grounded in specific source code references
- **Provide thinking and rationale behind the answers** — the document should not merely state conclusions but explain the reasoning and code-path logic that leads to each answer

**User-specified implementation rules**:
- "Create a new markdown document named `<source_branch_name>.md` that comprehensively answers the question(s) posed in the prompt."
- "Provide thinking / rationale behind the answers."
- "Do not make assumptions, base your answers on the code as the truth."
- "Do not modify any existing files in the source repository."
- "Place the generated document in the `blitzy/documentation` directory in the destination repo."

The source branch name is `trufflehog_e42153d44a5e`, so the output document must be `blitzy/documentation/trufflehog_e42153d44a5e.md`.

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To **document decoder pipeline behavior**, we will trace the `scannerWorker` function in `pkg/engine/engine.go` (lines 777–841), which iterates over `e.decoders` (the `DefaultDecoders()` slice from `pkg/decoders/decoders.go`) and passes each chunk through every decoder in sequence: UTF8 → Base64 → UTF16 → EscapedUnicode
- To **document overlap detection**, we will trace the `verificationOverlapWorker` function in `pkg/engine/engine.go` (lines 924–1034), which uses `likelyDuplicate()` (lines 887–922) with a 0.9 Levenshtein similarity threshold to detect when the same secret is found by different detectors
- To **document result deduplication**, we will trace the `notifierWorker` function in `pkg/engine/engine.go` (lines 1189–1235), which uses an LRU cache keyed on `DetectorType + Raw + RawV2 + SourceMetadata` and compares `DecoderType` values
- To **document the ordering of pipeline stages**, we will show the channel topology: `ChunksChan` → scanner workers → `verificationOverlapChunksChan` / `detectableChunksChan` → detector workers → `results` → notifier workers, establishing that overlap detection occurs in Stage 2/3 while deduplication occurs in Stage 4
- To **explain result count variability**, we will analyze how the Base64 decoder's `FromChunk()` method in `pkg/decoders/base64.go` mutates the original chunk's `Data` field in place (line 67: `chunk.Data = result.Bytes()`), causing subsequent decoders to operate on modified data, and how the deduplication cache key incorporates `DecoderType` to permit or suppress cross-decoder duplicates

### 0.1.4 Inferred Documentation Needs

Based on code analysis, the following implicit documentation needs have been identified:

- **Decoder mutation semantics**: The UTF8 and Base64 decoders mutate `chunk.Data` in place (Base64: `pkg/decoders/base64.go`, line 67; UTF8: `pkg/decoders/utf8.go`, line 24), while the EscapedUnicode decoder clones the data before modification (`pkg/decoders/escaped_unicode.go`, line 39: `chunkData = bytes.Clone(chunk.Data)`). This inconsistency directly affects whether later decoders in the chain see the original or modified data, and must be documented.
- **Decoder ordering contract**: The comment on line 10 of `pkg/decoders/decoders.go` states "UTF8 must be first for duplicate detection." This contractual constraint and its implications for the deduplication cache must be explained.
- **Postman special case in deduplication**: The notifier worker deduplication at `pkg/engine/engine.go` line 1218 contains a Postman-specific branch (`result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN`) that deduplicates regardless of decoder type. This edge case should be called out.
- **The `errOverlap` sentinel error**: Defined at `pkg/engine/engine.go` lines 39–42, this error is set on results via `res.SetVerificationError(errOverlap)` when the overlap worker detects likely duplicates across detectors. Its user-visible message and the `--allow-verification-overlap` flag need documentation.
- **Chunk-level vs. result-level deduplication**: The pipeline performs deduplication at two distinct levels — the overlap worker deduplicates at the chunk/detector level (intra-chunk, cross-detector), while the notifier worker deduplicates at the result level (cross-decoder, same detector). Both must be documented to explain the full picture.

## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a minimal, developer-oriented documentation structure with no formal documentation generator framework (no mkdocs.yml, docusaurus.config.js, sphinx.conf.py, or .readthedocs.yml detected). The project relies on raw Markdown files distributed across the repository root and a dedicated `docs/` directory.

**Existing documentation files discovered:**

| File | Type | Coverage Status |
|------|------|-----------------|
| `docs/concurrency.md` | Architecture reference | Covers worker types and channel topology via Mermaid sequence diagram; does not detail decoder pipeline or deduplication |
| `docs/process_flow.md` | Architecture reference | Covers four-stage data flow (Source Decomposition → Detector Matching → Secret Detection → Result Notification) via Mermaid flowcharts; mentions de-duplication at a high level but does not explain the LRU cache or decoder interaction |
| `README.md` | Project overview | Covers installation, usage, source scanning, and capabilities; no mention of decoder pipeline internals |
| `CONTRIBUTING.md` | Contributor guide | Links to `docs/process_flow.md` and `docs/concurrency.md` as the primary architectural references; contains logging and contribution guidelines |
| `hack/docs/Adding_Detectors_external.md` | Detector development guide | Documents how to add new detectors; does not cover decoder or deduplication behavior |
| `hack/docs/Adding_Detectors_Internal.md` | Internal detector guide | Internal detector development documentation |
| `SECURITY.md` | Security policy | Security vulnerability reporting process |
| `PreCommit.md` | Pre-commit integration | Setup guide for pre-commit hook usage |
| `CODE_OF_CONDUCT.md` | Community policy | Standard code of conduct |

**Documentation infrastructure findings:**
- Current documentation framework: **None** (raw Markdown)
- Documentation generator configuration: **Not present**
- API documentation tools in use: **None** (no JSDoc, Sphinx, or Godoc configuration detected)
- Diagram tools detected: **Mermaid** (used in `docs/concurrency.md` and `docs/process_flow.md`)
- Documentation hosting/deployment: **GitHub-hosted** (Markdown rendered by GitHub)

### 0.2.2 Repository Code Analysis for Documentation

The following source code files were identified as critical to answering the user's questions. These files form the evidence base for the new documentation:

**Decoder Pipeline Sources:**

| Source File | Key Constructs | Relevance |
|-------------|----------------|-----------|
| `pkg/decoders/decoders.go` | `DefaultDecoders()`, `Decoder` interface, `DecodableChunk` type | Defines decoder ordering (UTF8 → Base64 → UTF16 → EscapedUnicode) and the contract for chunk decoding |
| `pkg/decoders/utf8.go` | `UTF8.FromChunk()`, `extractSubstrings()` | PLAIN decoder; mutates `chunk.Data` in place when sanitization is needed |
| `pkg/decoders/base64.go` | `Base64.FromChunk()`, `getSubstringsOfCharacterSet()` | BASE64 decoder; mutates `chunk.Data` in place with decoded content; returns nil if no valid Base64 found |
| `pkg/decoders/utf16.go` | `UTF16.FromChunk()`, `utf16ToUTF8()` | UTF16 decoder; mutates `chunk.Data` in place; returns nil for non-UTF16 data |
| `pkg/decoders/escaped_unicode.go` | `EscapedUnicode.FromChunk()`, `decodeCodePoint()`, `decodeEscaped()` | ESCAPED_UNICODE decoder; clones data before modification (uses `bytes.Clone`) |

**Engine Pipeline Sources:**

| Source File | Key Constructs | Relevance |
|-------------|----------------|-----------|
| `pkg/engine/engine.go` (lines 777–841) | `scannerWorker()` | Iterates decoders per chunk, routes to overlap or detector channels |
| `pkg/engine/engine.go` (lines 887–922) | `likelyDuplicate()` | Levenshtein-based cross-detector duplicate detection (0.9 threshold) |
| `pkg/engine/engine.go` (lines 924–1034) | `verificationOverlapWorker()` | Processes multi-detector chunks without verification, then selectively re-sends to detector workers |
| `pkg/engine/engine.go` (lines 1036–1124) | `detectChunk()` | Runs detector regex extraction, verification, and filtering pipeline |
| `pkg/engine/engine.go` (lines 1189–1235) | `notifierWorker()` | LRU-based deduplication using `DetectorType + Raw + RawV2 + SourceMetadata` key; DecoderType-aware suppression |
| `pkg/engine/engine.go` (lines 39–42) | `errOverlap` | Sentinel error message for verification overlap conflicts |
| `pkg/engine/engine.go` (lines 486–534) | `initialize()` | LRU cache creation (512 entries), channel initialization, Aho-Corasick setup |

**Supporting Sources:**

| Source File | Key Constructs | Relevance |
|-------------|----------------|-----------|
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `FindDetectorMatches()`, `DetectorMatch`, span calculation | Keyword prefiltering and detector routing logic |
| `pkg/detectors/detectors.go` | `Result`, `ResultWithMetadata`, `CleanResults()`, `CopyMetadata()` | Result types and cleaning logic |
| `pkg/detectors/falsepositives.go` | `FilterKnownFalsePositives()`, `FilterResultsWithEntropy()` | False positive filtering applied before deduplication |
| `pkg/pb/detectorspb/detectors.pb.go` | `DecoderType_PLAIN(1)`, `DecoderType_BASE64(2)`, `DecoderType_UTF16(3)`, `DecoderType_ESCAPED_UNICODE(4)` | Protobuf enum values for decoder types |

### 0.2.3 Web Search Research Conducted

No external web search is required for this investigation. All answers are derivable from the source code. The user's explicit instruction to "base your answers on the code as the truth" confirms that the documentation should rely solely on repository analysis rather than external documentation or best-practice guides.

## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

The documentation task requires deep analysis of three interrelated subsystems. Each module below requires investigation and explanation in the output document.

**Module: Decoder Pipeline (`pkg/decoders/`)**
- Public APIs: `DefaultDecoders()`, `Decoder.FromChunk()`, `Decoder.Type()`
- Concrete implementations: `UTF8`, `Base64`, `UTF16`, `EscapedUnicode`
- Current documentation: **Missing** — no existing documentation explains decoder ordering, mutation semantics, or the interaction between sequential decoder passes
- Documentation needed: Decoder chain execution model, per-decoder behavior, mutation side effects, `DecoderType` label assignment, and the implications of the "UTF8 must be first" comment

**Module: Verification Overlap Worker (`pkg/engine/engine.go`, lines 924–1034)**
- Public APIs: `verificationOverlapWorker()`, `likelyDuplicate()`
- Supporting types: `verificationOverlapChunk`, `chunkSecretKey`, `verificationOverlapTracker`
- Current documentation: `docs/concurrency.md` mentions `VerificationOverlapWorkers` with a one-line note but provides no detail on the Levenshtein similarity algorithm, the 0.9 threshold, or the `errOverlap` error path
- Documentation needed: Trigger conditions (multiple detectors match AND `!verificationOverlap`), duplicate detection algorithm, the `errOverlap` sentinel error, the re-send-to-detector-workers path for non-duplicate detectors

**Module: Result Deduplication (`pkg/engine/engine.go`, lines 1189–1235)**
- Public APIs: `notifierWorker()`, LRU deduplication cache
- Current documentation: `docs/process_flow.md` mentions "De-Dupe-Detectors" in a diagram but conflates it with detector-level overlap detection; no documentation explains the notifier-level LRU cache deduplication
- Documentation needed: LRU cache key composition, the `DecoderType` comparison logic, the Postman special case, and the distinction between same-decoder duplicates (emitted) vs. cross-decoder duplicates (suppressed)

**Module: Scanner Worker Decoder Loop (`pkg/engine/engine.go`, lines 777–841)**
- Public APIs: `scannerWorker()`
- Current documentation: `docs/concurrency.md` diagram shows the scanner worker emitting to `detectableChunksChan` and `verificationOverlapChunksChan` but does not explain the decoder loop or why each chunk is processed by all four decoders
- Documentation needed: The outer chunk loop → inner decoder loop, how each decoder produces a separate `DecodableChunk` with a distinct `DecoderType`, and the routing decision between overlap and detector channels

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, the following documentation gaps must be addressed by the new document:

- **Undocumented interaction**: No existing documentation explains how the decoder chain, overlap detection, and notifier deduplication interact as a system. Each is partially mentioned in isolation (`docs/process_flow.md` diagrams, `docs/concurrency.md` sequence) but the causal chain — "decoder A produces result X which enters deduplication and is compared against decoder B's result Y" — is entirely absent.
- **Undocumented mutation semantics**: The fact that UTF8 and Base64 decoders mutate `chunk.Data` in place while EscapedUnicode clones it is not documented anywhere. This is the root cause of the user's observed behavioral variation.
- **Undocumented decoder ordering contract**: The comment "UTF8 must be first for duplicate detection" on line 10 of `pkg/decoders/decoders.go` is the sole mention of this critical constraint, with no elaboration on what breaks if the ordering changes.
- **Undocumented deduplication key semantics**: The notifier worker's deduplication key (`DetectorType + Raw + RawV2 + SourceMetadata`) and its `DecoderType` comparison logic are not documented. The conditional behavior — suppress if same key exists with a *different* `DecoderType`, emit if same key exists with the *same* `DecoderType` — is a nuanced but critical detail.
- **Missing pipeline stage ordering documentation**: No existing document explicitly states the temporal ordering: overlap detection (Stage 2/3) happens before notifier deduplication (Stage 4). This is essential to answering the user's question about whether deduplication happens before or after overlap detection.
- **Missing explanation of result count variability**: No documentation explains why the same secret can produce 1 or 2 results depending on file structure. The answer involves Base64 decoder threshold behavior (minimum 20-character encoded substring in `getSubstringsOfCharacterSet`), chunk mutation timing, and deduplication cache key composition.

## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

The output document (`blitzy/documentation/trufflehog_e42153d44a5e.md`) will follow a structured investigation format that mirrors the user's five questions while building from foundational concepts to system-level interactions.

```
blitzy/
└── documentation/
    └── trufflehog_e42153d44a5e.md
        ├── Introduction (context and purpose)
        ├── Decoder Pipeline Mechanics
        │   ├── Decoder ordering and the DefaultDecoders() contract
        │   ├── Per-decoder behavior (UTF8, Base64, UTF16, EscapedUnicode)
        │   ├── Mutation semantics (in-place vs. clone)
        │   └── DecoderType label assignment
        ├── Scanner Worker Decoder Loop
        │   ├── Chunk-to-decoder iteration model
        │   ├── Routing decision (overlap vs. direct)
        │   └── How one chunk produces multiple DecodableChunks
        ├── Verification Overlap Detection
        │   ├── Trigger conditions
        │   ├── The likelyDuplicate() algorithm
        │   ├── The errOverlap sentinel error
        │   └── Re-send path for non-duplicates
        ├── Result Deduplication in the Notifier Worker
        │   ├── LRU cache key composition
        │   ├── DecoderType comparison logic
        │   ├── Same-decoder vs. cross-decoder behavior
        │   └── Postman special case
        ├── Pipeline Stage Ordering
        │   ├── Overlap detection: Stage 2/3
        │   ├── Deduplication: Stage 4
        │   └── Channel topology and temporal flow
        ├── Why Result Counts Vary
        │   ├── Scenario analysis: raw key only
        │   ├── Scenario analysis: raw + Base64 on same line
        │   ├── Scenario analysis: raw + Base64 on separate lines
        │   └── Scenario analysis: raw + escaped Unicode
        └── Summary of Answers
```

### 0.4.2 Content Generation Strategy

**Information Extraction Approach:**

- Extract decoder chain logic from `pkg/decoders/decoders.go:DefaultDecoders()` to document the ordering contract
- Extract per-decoder mutation behavior from `pkg/decoders/utf8.go:FromChunk()`, `pkg/decoders/base64.go:FromChunk()`, `pkg/decoders/utf16.go:FromChunk()`, and `pkg/decoders/escaped_unicode.go:FromChunk()`
- Extract scanner worker loop logic from `pkg/engine/engine.go:scannerWorker()` (lines 777–841) to map the decoder iteration and routing model
- Extract overlap detection algorithm from `pkg/engine/engine.go:verificationOverlapWorker()` (lines 924–1034) and `likelyDuplicate()` (lines 887–922)
- Extract deduplication logic from `pkg/engine/engine.go:notifierWorker()` (lines 1189–1235) to document the LRU cache behavior
- Generate scenario analyses by tracing hypothetical inputs through the full pipeline code path

**Documentation Standards:**

- Markdown formatting with proper headers (`#`, `##`, `###`)
- Mermaid diagram integration using triple-backtick mermaid blocks for pipeline flows
- Code citations as inline references (e.g., `Source: pkg/engine/engine.go:1216`)
- Tables for comparison matrices (e.g., decoder behavior comparison)
- Consistent use of code-style formatting for function names, variable names, and file paths

### 0.4.3 Diagram and Visual Strategy

The document will include the following Mermaid diagrams:

- **Decoder chain flowchart**: Shows how a single chunk flows through all four decoders, with decision nodes for nil returns and mutation arrows showing data modification
- **Scanner worker routing diagram**: Shows the branching logic between `verificationOverlapChunksChan` and `detectableChunksChan` based on detector match count and the `verificationOverlap` flag
- **Pipeline stage ordering diagram**: Shows the temporal relationship between overlap detection (Stage 2/3) and notifier deduplication (Stage 4), with channel boundaries clearly marked
- **Deduplication decision flowchart**: Shows the LRU cache lookup, DecoderType comparison, and the emit/suppress decision for each result
- **Scenario trace diagrams**: For each result-count scenario, a trace diagram showing the path of a specific input through decoders → overlap → deduplication → output

## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

| Target Documentation File | Transformation | Source Code/Docs | Content/Changes |
|---------------------------|----------------|------------------|-----------------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | CREATE | `pkg/decoders/decoders.go`, `pkg/decoders/utf8.go`, `pkg/decoders/base64.go`, `pkg/decoders/utf16.go`, `pkg/decoders/escaped_unicode.go`, `pkg/engine/engine.go`, `pkg/engine/ahocorasick/ahocorasickcore.go`, `pkg/detectors/detectors.go` | Complete investigation document answering all five questions about decoder pipeline, overlap detection, deduplication interaction, ordering, and result count variability with full code citations and Mermaid diagrams |
| `docs/concurrency.md` | REFERENCE | `docs/concurrency.md` | Use as reference for existing worker architecture documentation style and Mermaid sequence diagram conventions; do not modify |
| `docs/process_flow.md` | REFERENCE | `docs/process_flow.md` | Use as reference for existing pipeline documentation style and Mermaid flowchart conventions; do not modify |

### 0.5.2 New Documentation Files Detail

```
File: blitzy/documentation/trufflehog_e42153d44a5e.md
Type: Technical Investigation / Architecture Deep-Dive
Source Code:
    - pkg/decoders/decoders.go (DefaultDecoders ordering, Decoder interface)
    - pkg/decoders/utf8.go (PLAIN decoder, in-place mutation)
    - pkg/decoders/base64.go (BASE64 decoder, in-place mutation, 20-char threshold)
    - pkg/decoders/utf16.go (UTF16 decoder, in-place mutation)
    - pkg/decoders/escaped_unicode.go (ESCAPED_UNICODE decoder, bytes.Clone)
    - pkg/engine/engine.go:39-42 (errOverlap sentinel)
    - pkg/engine/engine.go:207-209 (dedupeCache LRU declaration)
    - pkg/engine/engine.go:486-534 (initialize, LRU cache size 512)
    - pkg/engine/engine.go:777-841 (scannerWorker decoder loop)
    - pkg/engine/engine.go:878-886 (chunkSecretKey struct)
    - pkg/engine/engine.go:887-922 (likelyDuplicate function)
    - pkg/engine/engine.go:924-1034 (verificationOverlapWorker)
    - pkg/engine/engine.go:1036-1124 (detectChunk / detectorWorker)
    - pkg/engine/engine.go:1152-1187 (processResult)
    - pkg/engine/engine.go:1189-1235 (notifierWorker deduplication)
    - pkg/engine/ahocorasick/ahocorasickcore.go (FindDetectorMatches)
    - pkg/detectors/detectors.go:87-115 (Result struct)
    - pkg/detectors/detectors.go:161-184 (ResultWithMetadata struct)
    - pkg/detectors/detectors.go:200-225 (CleanResults function)
    - pkg/pb/detectorspb/detectors.pb.go:27-30 (DecoderType enum)
Sections:
    - Introduction (context: user's observed behavior, purpose)
    - Q1: Decoder Pipeline Mechanics (ordering, mutation, type labeling)
    - Q2: Overlap Detection (trigger conditions, likelyDuplicate, errOverlap)
    - Q3: Result Deduplication (LRU cache key, DecoderType logic, Postman case)
    - Q4: Pipeline Stage Ordering (overlap = Stage 2/3, dedup = Stage 4)
    - Q5: Why Result Counts Vary (scenario traces with code paths)
    - Summary of Answers
Diagrams:
    - Decoder chain flowchart showing per-decoder mutation behavior
    - Scanner worker routing decision diagram
    - Pipeline stage ordering showing overlap → dedup temporal flow
    - Notifier deduplication decision flowchart
    - Per-scenario trace diagrams
Key Citations:
    - pkg/decoders/decoders.go:8-16 (DefaultDecoders)
    - pkg/decoders/base64.go:34-72 (Base64.FromChunk)
    - pkg/decoders/escaped_unicode.go:32-68 (EscapedUnicode.FromChunk)
    - pkg/engine/engine.go:39-42 (errOverlap)
    - pkg/engine/engine.go:784-805 (decoder loop and routing)
    - pkg/engine/engine.go:1210-1221 (deduplication logic)
```

### 0.5.3 Documentation Configuration Updates

No documentation configuration updates are required. The project does not use a documentation generator. The new file (`blitzy/documentation/trufflehog_e42153d44a5e.md`) is a standalone Markdown document placed in the designated output directory per the user's implementation rules.

### 0.5.4 Cross-Documentation Dependencies

- The new document references concepts from `docs/concurrency.md` (worker types, channel names) and `docs/process_flow.md` (four-stage pipeline model). These are read-only references; no link updates are needed in those files.
- No table-of-contents updates, index changes, or glossary modifications are required since the output is in `blitzy/documentation/` (a separate directory from the project's `docs/` folder).
- No navigation or sidebar configuration is affected since no documentation framework is in use.

## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

This is a pure documentation-creation task. No documentation generation tools or build pipelines are required. The output is a standalone Markdown file. However, the following project dependencies are relevant to the code being documented and should be referenced for version accuracy:

| Registry | Package Name | Version | Purpose |
|----------|--------------|---------|---------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | v3 (go 1.23.1, toolchain go1.24.2) | The target project being documented |
| Go module | `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Aho-Corasick trie implementation used in the keyword matching pipeline documented in the investigation |
| Go module | `github.com/adrg/strutil` | v0.3.1 | String similarity utilities; provides the Levenshtein distance metric used in `likelyDuplicate()` |
| Go module | `github.com/hashicorp/golang-lru/v2` | (from go.mod) | LRU cache implementation used for result deduplication in the notifier worker |
| Protobuf | `detectorspb.DecoderType` | Generated from `proto/` | Enum defining decoder type constants (PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4) |

No additional documentation tools (mkdocs, Sphinx, Docusaurus, typedoc, etc.) are needed because:
- The output is a single `.md` file
- Mermaid diagrams are embedded inline (rendered natively by GitHub)
- No build step is required

### 0.6.2 Documentation Reference Updates

Not applicable. Since the new document is placed in `blitzy/documentation/` (a separate directory from the project's `docs/` folder), no existing documentation links need to be updated. The user's instructions explicitly state "Do not modify any existing files in the source repository."

## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current coverage analysis:**

| Topic | Currently Documented | Where | Gap |
|-------|---------------------|-------|-----|
| Decoder pipeline ordering | One comment in `pkg/decoders/decoders.go:10` | Source code only | No prose documentation explaining the ordering contract or its implications |
| Decoder mutation semantics | Not documented | — | No documentation of in-place vs. clone behavior across decoders |
| Verification overlap detection | One-line note in `docs/concurrency.md` | Mermaid diagram label | No explanation of `likelyDuplicate()`, Levenshtein threshold, or `errOverlap` |
| Result deduplication (notifier) | Brief mention in `docs/process_flow.md` | Mermaid diagram box labeled "De-Dupe-Detectors" | Conflates detector-level overlap with result-level deduplication; no detail on LRU cache key or DecoderType logic |
| Pipeline stage ordering | Implied by `docs/concurrency.md` sequence diagram | Worker start order | No explicit documentation that overlap detection precedes notifier deduplication |
| Result count variability | Not documented | — | No documentation explaining why the same secret produces varying result counts |

**Target coverage:** 100% of the five user questions answered with code-grounded evidence

**Coverage gaps to address:**
- Decoder pipeline internals: Currently 0% documented → target 100%
- Overlap detection algorithm: Currently ~5% documented (one diagram label) → target 100%
- Notifier deduplication: Currently ~5% documented (one diagram box) → target 100%
- Inter-subsystem interaction: Currently 0% documented → target 100%
- Result count variability: Currently 0% documented → target 100%

### 0.7.2 Documentation Quality Criteria

**Completeness requirements:**
- Every question from the user's prompt must have a dedicated section with a clear, definitive answer
- Every claim must cite a specific source file, line number, and code construct
- Every behavioral assertion must be traceable to a code path in the repository
- The document must explain not just *what* happens but *why* — providing rationale behind each behavior

**Accuracy validation:**
- All function signatures and variable names must match the current codebase exactly
- All line number references must be verified against the actual file contents
- Decoder ordering must be confirmed from `DefaultDecoders()` in `pkg/decoders/decoders.go`
- Deduplication key formula must be confirmed from `notifierWorker()` in `pkg/engine/engine.go:1216`
- Levenshtein threshold must be confirmed from `likelyDuplicate()` in `pkg/engine/engine.go:888`

**Clarity standards:**
- Technical accuracy with accessible language for developers who are not TruffleHog core contributors
- Progressive disclosure: start with high-level pipeline overview, then drill into each subsystem, then synthesize with scenario traces
- Consistent terminology: use "decoder pipeline" (not "encoding chain"), "overlap detection" (not "dedup stage 1"), "result deduplication" (not "notifier filtering")

**Maintainability:**
- Source citations for every technical claim enable future maintainers to update the document when code changes
- Mermaid diagrams can be updated by editing text, not by regenerating images

### 0.7.3 Example and Diagram Requirements

- Minimum diagrams: 5 (decoder chain, scanner routing, pipeline ordering, deduplication decision, scenario traces)
- Diagram types: Mermaid flowcharts and sequence diagrams (matching existing `docs/` conventions)
- Code example testing: Not applicable (the document is explanatory, not executable); code citations reference existing source
- Scenario traces: At least 3 distinct input scenarios must be walked through the pipeline to demonstrate the different output behaviors the user observed

## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

**New documentation files:**
- `blitzy/documentation/trufflehog_e42153d44a5e.md` — the sole deliverable: a comprehensive investigation document answering all five questions about decoder pipeline, overlap detection, deduplication, ordering, and result count variability

**Source code files analyzed (read-only):**
- `pkg/decoders/decoders.go` — Decoder interface, DefaultDecoders ordering
- `pkg/decoders/utf8.go` — PLAIN decoder implementation
- `pkg/decoders/base64.go` — BASE64 decoder implementation
- `pkg/decoders/utf16.go` — UTF16 decoder implementation
- `pkg/decoders/escaped_unicode.go` — ESCAPED_UNICODE decoder implementation
- `pkg/engine/engine.go` — Core engine: scannerWorker, verificationOverlapWorker, detectorWorker, notifierWorker, dedupeCache, errOverlap, processResult, likelyDuplicate
- `pkg/engine/ahocorasick/ahocorasickcore.go` — Aho-Corasick keyword matching and span calculation
- `pkg/detectors/detectors.go` — Result, ResultWithMetadata, CleanResults
- `pkg/detectors/falsepositives.go` — FilterKnownFalsePositives, FilterResultsWithEntropy
- `pkg/pb/detectorspb/detectors.pb.go` — DecoderType protobuf enum
- `pkg/engine/engine_test.go` — Verification overlap and likelyDuplicate test cases
- `pkg/engine/testdata/*.txt`, `pkg/engine/testdata/*.yaml` — Test fixtures for overlap behavior

**Reference documentation (read-only):**
- `docs/concurrency.md` — Worker architecture reference
- `docs/process_flow.md` — Pipeline stage reference
- `CONTRIBUTING.md` — Documentation style reference

### 0.8.2 Explicitly Out of Scope

- **Source code modifications**: No Go source files will be modified. The user explicitly stated "Do not modify any existing source files in the repository."
- **Test file modifications**: No test files will be created or modified in the source repository
- **Existing documentation modifications**: No changes to `docs/concurrency.md`, `docs/process_flow.md`, `README.md`, or any other existing `.md` files
- **Feature additions or code refactoring**: This is a documentation-only task; no behavioral changes to the scanning pipeline
- **Deployment configuration changes**: No Dockerfile, Makefile, or CI/CD changes
- **Detector-specific documentation**: The document focuses on the cross-cutting decoder/overlap/dedup interaction, not on individual detector implementations (e.g., AWS, Sentry)
- **Documentation framework installation**: No mkdocs, Sphinx, or Docusaurus setup
- **Performance benchmarking**: The document explains behavioral semantics, not performance characteristics
- **Temporary test data**: Any test data created during investigation must be cleaned up per user instructions — but since the document is code-analysis-based (not run-based), no test data creation is anticipated

## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

- **Documentation build command**: Not applicable — the output is a standalone Markdown file that requires no build step
- **Documentation preview command**: View `blitzy/documentation/trufflehog_e42153d44a5e.md` directly in any Markdown renderer (GitHub, VS Code, etc.)
- **Diagram generation command**: Not applicable — Mermaid diagrams are embedded inline in the Markdown and rendered natively by GitHub
- **Documentation deployment command**: Not applicable — the file is committed to the repository
- **Default format**: Markdown with Mermaid diagrams
- **Citation requirement**: Every technical claim must reference the specific source file and line number (e.g., `Source: pkg/engine/engine.go:1216`)
- **Style guide to follow**: Match the conventions of existing architecture documentation in `docs/concurrency.md` and `docs/process_flow.md` — specifically, use Mermaid diagrams for visual explanations, use inline code formatting for function and variable names, and use headings to organize investigative sections
- **Documentation validation**: Manual review — verify that all cited line numbers correspond to the correct code constructs

### 0.9.2 Output File Specification

The single deliverable file must meet these requirements:

- **Path**: `blitzy/documentation/trufflehog_e42153d44a5e.md`
- **Format**: GitHub-Flavored Markdown (GFM)
- **Encoding**: UTF-8
- **Diagrams**: Mermaid syntax within triple-backtick fenced code blocks tagged with `mermaid`
- **Code citations**: Inline references using the pattern `Source: <file_path>:<line_range>`
- **Structure**: Investigation-oriented with one section per user question, plus introduction and summary
- **Tone**: Technical and precise, with rationale and reasoning behind each answer — not merely stating conclusions but explaining the code-path logic

## 0.10 Rules for Documentation

The following rules are explicitly specified by the user and must be strictly followed:

- **"Do not modify any existing source files in the repository"** — No Go files, test files, configuration files, or existing Markdown files may be changed. The only file creation permitted is the new document at `blitzy/documentation/trufflehog_e42153d44a5e.md`.

- **"Remove any test data created during the investigation"** — If any temporary test files (e.g., files containing AWS keys in various encoded forms) are created during the investigation phase, they must be deleted before the task is marked complete. The investigation should rely on static code analysis rather than runtime testing where possible.

- **"Do not make assumptions, base your answers on the code as the truth"** — Every behavioral claim in the output document must cite a specific source file and code construct. Statements like "TruffleHog likely does X" are prohibited; instead use "TruffleHog does X, as implemented in `pkg/engine/engine.go` at line Y."

- **"Provide thinking / rationale behind the answers"** — The document must not merely list conclusions. Each answer must include the reasoning chain: which code paths were examined, how the logic flows from input to output, and why the observed behavior follows from the implementation.

- **"Create a new markdown document named `<source_branch_name>.md`"** — The file must be named exactly `trufflehog_e42153d44a5e.md` (matching the source branch name `trufflehog_e42153d44a5e`).

- **"Place the generated document in the `blitzy/documentation` directory"** — The directory must be created if it does not exist. The full path is `blitzy/documentation/trufflehog_e42153d44a5e.md`.

- **"Comprehensively answer the question(s) posed in the prompt"** — All five investigative questions must be addressed:
  - Which decoder types are reported and why
  - Whether and when overlap detection occurs
  - How deduplication affects the final result count
  - Whether deduplication happens before or after overlap detection
  - Why the same logical secret sometimes produces one result and sometimes produces multiple

## 0.11 References

### 0.11.1 Files and Folders Searched

The following files were retrieved and analyzed during the context-gathering phase to derive the conclusions documented in this Agent Action Plan:

**Decoder Pipeline Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `pkg/decoders/decoders.go` | Decoder interface and ordering | `DefaultDecoders()` returns [UTF8, Base64, UTF16, EscapedUnicode]; comment "UTF8 must be first for duplicate detection" on line 10 |
| `pkg/decoders/utf8.go` | PLAIN decoder | Returns `DecoderType_PLAIN`; mutates `chunk.Data` in place when sanitization needed (line 24) |
| `pkg/decoders/base64.go` | BASE64 decoder | Returns `DecoderType_BASE64`; mutates `chunk.Data` in place (line 67); 20-character minimum for Base64 candidate substrings; returns nil if no valid Base64 found |
| `pkg/decoders/utf16.go` | UTF16 decoder | Returns `DecoderType_UTF16`; mutates `chunk.Data` in place (line 28); returns nil for non-UTF16 input |
| `pkg/decoders/escaped_unicode.go` | ESCAPED_UNICODE decoder | Returns `DecoderType_ESCAPED_UNICODE`; clones data with `bytes.Clone` before modification (line 39); returns nil if no escape patterns matched |

**Engine Pipeline Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `pkg/engine/engine.go` | Core engine orchestration | Contains scannerWorker (lines 777–841), verificationOverlapWorker (lines 924–1034), likelyDuplicate (lines 887–922), notifierWorker (lines 1189–1235), errOverlap (lines 39–42), dedupeCache LRU initialization (lines 486–534), processResult (lines 1152–1187) |
| `pkg/engine/engine_test.go` | Engine tests | Contains TestVerificationOverlap* tests (lines 510–556), TestVerificationOverlapChunkFalsePositive (lines 599–641), likelyDuplicate test cases (lines 900–965) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword matching | FindDetectorMatches, DetectorMatch, span calculation and merging logic |
| `pkg/engine/metrics.go` | Prometheus metrics | Decode latency, detector execution, bytes/chunks scanned metrics |

**Detector and Protobuf Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `pkg/detectors/detectors.go` | Detector types and results | Result struct (lines 87–115), ResultWithMetadata (lines 161–184), CleanResults (lines 200–225), CopyMetadata (lines 187–198) |
| `pkg/detectors/falsepositives.go` | False positive filtering | FilterKnownFalsePositives (line 177), FilterResultsWithEntropy (line 154) |
| `pkg/pb/detectorspb/detectors.pb.go` | Protobuf enums | DecoderType_PLAIN=1, DecoderType_BASE64=2, DecoderType_UTF16=3, DecoderType_ESCAPED_UNICODE=4 |

**Existing Documentation Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `docs/concurrency.md` | Worker architecture | Mermaid sequence diagram of ScannerWorkers → VerificationOverlapWorkers → DetectorWorkers → NotifierWorkers; one-line note about overlap handling |
| `docs/process_flow.md` | Pipeline data flow | Four-stage flow: Source Decomposition → Detector Matching → Secret Detection → Result Notification; mentions De-Dupe-Detectors in a diagram box |
| `CONTRIBUTING.md` | Contributor guide | Links to docs/process_flow.md and docs/concurrency.md; logging level conventions |
| `README.md` | Project overview | Product capabilities (Discovery, Classification, Validation, Analysis); no decoder/dedup internals |

**Test Data Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `pkg/engine/testdata/secrets.txt` | Engine test fixture | Contains AWS key, generic secret, and 4 repeated sentry tokens for deduplication testing |
| `pkg/engine/testdata/verificationoverlap_secrets.txt` | Overlap test fixture | Contains POSTMAN_API_KEY with PMAK- prefix |
| `pkg/engine/testdata/verificationoverlap_detectors.yaml` | Overlap detector config | Two custom regex detectors with overlapping keyword/regex patterns |
| `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` | False positive test fixture | POSTMAN_API_KEY with ssample- prefix for false positive testing |
| `pkg/engine/testdata/verificationoverlap_detectors_fp.yaml` | FP detector config | Two custom regex detectors for false positive overlap scenario |

**Build and Dependency Files:**

| File Path | Purpose | Key Findings |
|-----------|---------|--------------|
| `go.mod` | Go module manifest | Module `github.com/trufflesecurity/trufflehog/v3`, Go 1.23.1, toolchain go1.24.2; dependencies include aho-corasick v1.0.3, strutil v0.3.1, golang-lru/v2 |

**Folders Explored:**

| Folder Path | Purpose |
|-------------|---------|
| (root) | Repository root structure, governance files, build automation |
| `pkg/` | Core reusable Go packages |
| `pkg/decoders/` | Decoder implementations and tests |
| `pkg/engine/` | Engine orchestration, source adapters, tests |
| `pkg/engine/ahocorasick/` | Aho-Corasick keyword matching core |
| `pkg/engine/testdata/` | Static test fixtures for engine tests |
| `docs/` | Architecture documentation (concurrency.md, process_flow.md) |

### 0.11.2 Attachments

No attachments were provided by the user for this task.

### 0.11.3 Figma Screens

No Figma URLs or design screens were provided for this task.

