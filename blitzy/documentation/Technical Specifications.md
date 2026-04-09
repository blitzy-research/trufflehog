# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **create new documentation** that provides a comprehensive, code-grounded exploration of TruffleHog v3's internal detection architecture for an engineer onboarding to the project.

- **Documentation Category:** Create new documentation
- **Documentation Type:** Architecture exploration guide / Technical Q&A reference
- **Target Audience:** A developer onboarding to the TruffleHog codebase who wants to understand how the system works from the inside before contributing to it

The user has posed five interconnected architectural questions, each requiring answers derived exclusively from the source code:

- **Detection Architecture & Startup:** What happens when TruffleHog is built from source and a scan is started? Are detector configurations loaded from files, or are they compiled in? What initialization messages appear about detector registration?
- **Verification Setup:** Do build dependencies include HTTP client libraries for network verification? Does the architecture show verification happening in parallel or sequentially?
- **Output Structure:** What is the actual JSON output schema for a finding? Are there fields for verification status, confidence scores, or metadata about secret location?
- **Repository Traversal:** How does TruffleHog decide which files to scan versus skip? What do verbose logs reveal about this decision process?
- **Detector Architecture:** Are detectors separate plugins or embedded modules? What does the binary's help output show about available detection capabilities?

### 0.1.2 Special Instructions and Constraints

- **CRITICAL: Repository must remain unchanged.** The user explicitly states: "the repository itself should remain unchanged and anything temporary should be cleaned up afterward." No source code modifications of any kind are permitted.
- **CRITICAL: Implementation rule `SWE-AtlasQnA-Repo`** mandates:
  - Create a new markdown document named `<source_branch_name>.md`
  - Comprehensively answer the questions posed in the prompt
  - Provide thinking/rationale behind the answers
  - Do not make assumptions — base answers on the code as truth
  - Do not modify any existing files in the source repository
  - Place the generated document in the `blitzy/documentation` directory in the destination repo
- **Temporary scripts** may be used for observation during analysis but must be cleaned up afterward
- **Answers must be code-grounded:** Every claim must be traceable to specific source files and line numbers
- **No assumptions:** All conclusions must derive from direct code evidence, not inferred behavior

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To **document the detection architecture and startup behavior**, we will create a reference section analyzing `main.go` (init function, CLI flag parsing, engine initialization flow at line 330+), `pkg/engine/engine.go` (NewEngine at line 226, setDefaults at line 336, initialize at line 489, startWorkers at line 646), and `pkg/engine/defaults/defaults.go` (the compiled-in detector registry built by `buildDetectorList()` and exposed by `DefaultDetectors()`)
- To **document the verification setup**, we will create a reference section analyzing `pkg/detectors/http.go` (the HTTP client infrastructure including `DetectorHttpClientWithNoLocalAddresses`, `DetectorHttpClientWithLocalAddresses`, custom transport with User-Agent injection, and the configurable `DefaultResponseTimeout` of 10 seconds), and `pkg/engine/engine.go` (the concurrent worker architecture showing `startDetectorWorkers` at line 675 spawning `concurrency * detectorWorkerMultiplier` goroutines for parallel verification)
- To **document the output structure**, we will create a reference section analyzing `pkg/output/json.go` (the `JSONPrinter.Print` method and its anonymous struct defining the exact JSON schema at lines 27-74), and `pkg/detectors/detectors.go` (the `Result` and `ResultWithMetadata` structs at lines 87-184)
- To **document repository traversal**, we will create a reference section analyzing `pkg/handlers/handlers.go` (MIME type detection, `selectHandler` routing, the `skipArchiverMimeTypes` set at line 266), `pkg/handlers/default.go` (binary/MIME skip heuristics), and `pkg/handlers/archive.go` (recursive archive traversal with depth/size/timeout limits)
- To **document the detector architecture**, we will create a reference section analyzing `pkg/detectors/detectors.go` (the `Detector` interface at line 19), `pkg/engine/defaults/defaults.go` (the statically compiled detector list), `pkg/engine/ahocorasick/ahocorasickcore.go` (the keyword-based prefiltering trie), and `main.go` (CLI flag definitions for `--include-detectors`, `--exclude-detectors`)

### 0.1.4 Inferred Documentation Needs

Based on code analysis, the following implicit documentation needs have been identified:

- **Decoder pipeline documentation:** The detection pipeline includes a multi-stage decoding step (UTF-8 → Base64 → UTF-16 → EscapedUnicode, per `pkg/decoders/decoders.go`) that is integral to understanding how raw source data becomes scannable chunks, which is relevant to the user's question about file scanning
- **Aho-Corasick keyword prefiltering:** The chunk-to-detector matching step (`pkg/engine/ahocorasick/ahocorasickcore.go`) is a critical performance optimization that determines which detectors evaluate which chunks — this directly answers the user's question about how detectors are invoked
- **Custom detector YAML configuration:** While default detectors are compiled in, the user should also understand the `--config` flag path (`pkg/config/config.go`) that loads additional detectors from YAML at runtime, and how custom detectors defined in `examples/generic.yml` and `examples/generic_with_filters.yml` complement the built-in set
- **Verification caching:** The verification cache system (`pkg/verificationcache/`) adds a layer of efficiency that affects observed verification behavior, relevant to the user's question about verification architecture
- **Feature flags:** Runtime feature flags in `pkg/feature/feature.go` (ForceSkipBinaries, ForceSkipArchives, SkipAdditionalRefs, EnableAPKHandler) control file-handling behavior and are essential context for the traversal question
- **Concurrency model documentation:** The existing docs (`docs/concurrency.md`, `docs/process_flow.md`) should be cross-referenced in the new document since they provide authoritative Mermaid diagrams of the pipeline

## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a **minimal but focused documentation structure** with two architecture-level Markdown files in `docs/`, several governance and community Markdown files at the root, contributor guides in `hack/docs/`, and a custom detector guide in `pkg/custom_detectors/`. There is no documentation generator (no mkdocs.yml, docusaurus.config.js, or sphinx/conf.py detected). Documentation is authored as standalone Markdown files with embedded Mermaid diagrams.

**Existing documentation files discovered:**

| File Path | Type | Coverage Status |
|-----------|------|-----------------|
| `README.md` | Project overview, capabilities, installation, usage | Covers CLI usage at a high level; no architectural depth |
| `CONTRIBUTING.md` | Contributor workflow, logging guidelines, process flow references | Brief; links to docs/ for architecture |
| `SECURITY.md` | Security reporting policy | Governance only |
| `CODE_OF_CONDUCT.md` | Community conduct policy | Governance only |
| `PreCommit.md` | Pre-commit hook setup | Integration-focused |
| `docs/concurrency.md` | Worker concurrency architecture (Mermaid sequence diagram) | Covers worker startup, channel flow; no detector detail |
| `docs/process_flow.md` | End-to-end scanning pipeline (Mermaid flowcharts) | Covers Source→Chunk→Detect→Notify; limited on verification |
| `hack/docs/Adding_Detectors_external.md` | External contributor guide for adding detectors | Focused on scaffolding workflow |
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` | Custom regex detector authoring guide | Covers YAML config, verification endpoints |
| `examples/README.md` | Example detector config usage | Narrow scope: generic detector usage only |

**Documentation framework:** None. Raw Markdown files with Mermaid diagrams (rendered by GitHub).

**API documentation tools in use:** None. No JSDoc, GoDoc site generation, or Swagger/OpenAPI detected.

**Diagram tools detected:** Mermaid (used in `docs/concurrency.md` and `docs/process_flow.md`).

**Documentation hosting/deployment:** None. Documentation is served directly from the GitHub repository viewer.

### 0.2.2 Repository Code Analysis for Documentation

Search patterns used for code to document:

- **Detection architecture:** `main.go` (CLI entrypoint, init/run functions), `pkg/engine/engine.go` (Engine struct, NewEngine, Start, startWorkers), `pkg/engine/defaults/defaults.go` (DefaultDetectors, buildDetectorList)
- **Detector interfaces:** `pkg/detectors/detectors.go` (Detector interface, Result/ResultWithMetadata structs, optional interfaces), `pkg/detectors/http.go` (HTTP client infrastructure)
- **Output schema:** `pkg/output/json.go` (JSONPrinter struct definition), `pkg/output/plain.go`, `pkg/output/github_actions.go`, `pkg/output/legacy_json.go`
- **File handling:** `pkg/handlers/handlers.go` (HandleFile, selectHandler, MIME types, file extension routing), `pkg/handlers/default.go`, `pkg/handlers/archive.go`, `pkg/handlers/apk.go`, `pkg/handlers/ar.go`, `pkg/handlers/rpm.go`
- **Configuration:** `pkg/config/config.go` (Config.Read, NewYAML), `pkg/config/detectors.go` (ParseDetectors, DetectorID)
- **Decoders:** `pkg/decoders/decoders.go` (DefaultDecoders ordering), `pkg/decoders/utf8.go`, `pkg/decoders/base64.go`, `pkg/decoders/utf16.go`, `pkg/decoders/escaped_unicode.go`
- **Ahocorasick:** `pkg/engine/ahocorasick/ahocorasickcore.go` (keyword trie construction, FindDetectorMatches)
- **Sources:** `pkg/sources/sources.go` (Source interface, Chunk model), `pkg/sources/source_manager.go`
- **Feature flags:** `pkg/feature/feature.go` (ForceSkipBinaries, ForceSkipArchives, EnableAPKHandler)
- **Proto schemas:** `proto/detectors.proto` (DetectorType enum, Result message), `proto/source_metadata.proto` (MetaData dispatcher), `proto/custom_detectors.proto` (CustomRegex definitions)

Key directories examined: `pkg/engine/`, `pkg/detectors/`, `pkg/output/`, `pkg/handlers/`, `pkg/config/`, `pkg/decoders/`, `pkg/sources/`, `pkg/feature/`, `proto/`, `docs/`, `examples/`, `hack/docs/`

Related documentation found: `docs/concurrency.md` and `docs/process_flow.md` provide Mermaid diagrams that should be cross-referenced but are not sufficient to answer the user's questions in depth.

### 0.2.3 Web Search Research Conducted

No web search was necessary for this task. All documentation will be derived exclusively from the source code per the user's explicit instruction: "Do not make assumptions, base your answers on the code as truth." The project's internal documentation and source code provide complete coverage for all five architectural questions posed.

## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

The following modules require documentation to answer the user's five architectural questions:

**Module: `main.go` (CLI Entrypoint)**
- Public APIs: `init()`, `main()`, `run()`, `runSingleScan()`, `parseResults()`
- Current documentation: Inline comments only; no external documentation
- Documentation needed: Startup sequence walkthrough, CLI flag catalog, engine initialization narrative

**Module: `pkg/engine/engine.go` (Scan Engine Core)**
- Public APIs: `NewEngine()`, `Start()`, `Finish()`, `Engine.Config`, `startWorkers()`, `startDetectorWorkers()`, `startScannerWorkers()`, `startVerificationOverlapWorkers()`, `startNotifierWorkers()`
- Current documentation: Partially covered by `docs/concurrency.md`; no standalone reference
- Documentation needed: Engine lifecycle, worker concurrency model, detector filtering, verification pipeline

**Module: `pkg/engine/defaults/defaults.go` (Default Detector Registry)**
- Public APIs: `DefaultDetectors()`, `DefaultDetectorTypesImplementing[T]()`
- Current documentation: None
- Documentation needed: How detectors are compiled in, runtime post-processing (endpoint customization), detector count and catalog

**Module: `pkg/detectors/detectors.go` (Detector Framework)**
- Public APIs: `Detector` interface, `Result` struct, `ResultWithMetadata` struct, optional interfaces (`Versioner`, `EndpointCustomizer`, `MultiPartCredentialProvider`, `MaxSecretSizeProvider`, `StartOffsetProvider`, `CustomResultsCleaner`)
- Current documentation: GoDoc comments only
- Documentation needed: Interface contract explanation, result fields glossary, verification error handling

**Module: `pkg/detectors/http.go` (HTTP Verification Infrastructure)**
- Public APIs: `DetectorHttpClientWithNoLocalAddresses`, `DetectorHttpClientWithLocalAddresses`, `NewDetectorHttpClient()`, `NewDetectorTransport()`, `OverrideDetectorTimeout()`
- Current documentation: None
- Documentation needed: HTTP client configuration, timeout behavior, User-Agent injection, local IP blocking

**Module: `pkg/output/json.go` (JSON Output Schema)**
- Public APIs: `JSONPrinter.Print()`
- Current documentation: None
- Documentation needed: Complete JSON field schema with types and descriptions

**Module: `pkg/handlers/handlers.go` (File Handling & MIME Routing)**
- Public APIs: `HandleFile()`, `selectHandler()`, MIME type constants, `skipArchiverMimeTypes`
- Current documentation: None
- Documentation needed: MIME detection flow, handler selection logic, archive vs default handler routing

**Module: `pkg/engine/ahocorasick/ahocorasickcore.go` (Keyword Prefiltering)**
- Public APIs: `NewAhoCorasickCore()`, `Core.FindDetectorMatches()`, `CreateDetectorKey()`
- Current documentation: None
- Documentation needed: How keywords route chunks to detectors, span calculation strategies

**Module: `pkg/config/config.go` (Custom Detector Configuration)**
- Public APIs: `Read()`, `NewYAML()`
- Current documentation: `pkg/custom_detectors/CUSTOM_DETECTORS.md` covers custom detector authoring
- Documentation needed: How `--config` flag loads YAML detectors at runtime alongside compiled-in defaults

**Module: `pkg/decoders/decoders.go` (Decoder Pipeline)**
- Public APIs: `DefaultDecoders()`, `Decoder` interface
- Current documentation: None
- Documentation needed: Decoder ordering and behavior in the scanning pipeline

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, documentation gaps include:

- **No dedicated architecture deep-dive document exists** that answers "what happens when I build and run TruffleHog?" from first principles
- **The detector registration mechanism is undocumented** — no existing doc explains that detectors are compiled-in via `pkg/engine/defaults/defaults.go` rather than loaded from external files
- **The JSON output schema is undocumented** — the exact field names, types, and semantics of `--json` output are only discoverable by reading `pkg/output/json.go` source code
- **File traversal/skip logic is undocumented** — MIME-based handler selection, binary file skipping, and archive recursion are entirely internal knowledge
- **Verification concurrency model is underexplained** — `docs/concurrency.md` mentions DetectorWorkers but does not explain the 8x multiplier, HTTP client pooling, or timeout configuration
- **The Aho-Corasick prefiltering step is not documented** for external consumers — it is a critical performance characteristic that chunks are only sent to detectors whose keywords match
- **Feature flags affecting file handling** (`ForceSkipBinaries`, `ForceSkipArchives`, `EnableAPKHandler`) are undocumented outside of CLI `--help` output

## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

The output document will be a single comprehensive Markdown file placed at `blitzy/documentation/<source_branch_name>.md`. Its internal structure will be organized to mirror the five architectural questions posed by the user, with each section providing code-grounded answers, rationale, and source citations.

```
blitzy/documentation/<source_branch_name>.md
├── Introduction (context and methodology)
├── 1. Detection Architecture & Startup Behavior
│   ├── Build Process
│   ├── Startup Sequence (init → main → run)
│   ├── Detector Loading: Compiled-In vs Configuration Files
│   ├── Initialization Messages and Logging
│   └── Mermaid: Engine startup flow
├── 2. Verification Setup
│   ├── HTTP Client Libraries in Dependencies
│   ├── HTTP Client Architecture (dual-client model)
│   ├── Parallel vs Sequential Verification
│   ├── Worker Concurrency Model
│   └── Mermaid: Verification concurrency flow
├── 3. Output Structure
│   ├── JSON Output Schema (complete field reference)
│   ├── Verification Status Fields
│   ├── Confidence and Metadata Fields
│   ├── Source Metadata Structure
│   └── Sample JSON output skeleton
├── 4. Repository Traversal
│   ├── Source Decomposition (Source → Unit → Chunk)
│   ├── MIME Detection and Handler Selection
│   ├── Files Scanned vs Skipped
│   ├── Archive Handling and Recursion
│   ├── Feature Flags for Skip Control
│   └── Mermaid: File handling decision flow
├── 5. Detector Architecture
│   ├── Plugin vs Embedded Module Design
│   ├── Detector Interface Contract
│   ├── Aho-Corasick Keyword Prefiltering
│   ├── Detector Count and Catalog
│   ├── Custom Detector Extension (--config)
│   ├── CLI Help Output Information
│   └── Mermaid: Chunk-to-detector matching
└── Summary and Cross-References
```

### 0.4.2 Content Generation Strategy

**Information Extraction Approach:**
- Extract startup sequence from `main.go` (lines 259-328 for init, 330-368 for main, 381-580 for run)
- Extract engine initialization from `pkg/engine/engine.go` (lines 226-534 for NewEngine through initialize)
- Extract JSON schema from `pkg/output/json.go` (lines 27-74 anonymous struct definition)
- Extract handler routing from `pkg/handlers/handlers.go` (lines 308-321 selectHandler, 266-297 skipArchiverMimeTypes)
- Extract detector interface from `pkg/detectors/detectors.go` (lines 19-29 Detector interface)
- Extract HTTP client from `pkg/detectors/http.go` (lines 27-39 init function, lines 167-177 NewDetectorHttpClient)
- Derive detector count from `pkg/engine/defaults/defaults.go` import list and build function

**Documentation Standards:**
- Markdown formatting with proper headers (# ## ###)
- Mermaid diagram integration using fenced code blocks
- Source citations as inline references: `Source: /path/to/file.go:LineNumber`
- Tables for field schemas and parameter descriptions
- Consistent terminology matching the codebase (e.g., "chunk" not "fragment", "detector" not "scanner")

### 0.4.3 Diagram and Visual Strategy

The following Mermaid diagrams will be created within the documentation file:

- **Engine Startup Flow:** Flowchart showing `init()` → `main()` → `run()` → `NewEngine()` → `Start()` → `startWorkers()`
- **Verification Concurrency Model:** Sequence diagram showing ScannerWorkers → DetectorWorkers (8x multiplier) → NotifierWorkers with parallel HTTP verification
- **File Handling Decision Tree:** Flowchart showing MIME detection → handler selection (archive/AR/RPM/APK/default) → skip-or-process decisions
- **Chunk-to-Detector Matching:** Flowchart showing raw data → decoders → Aho-Corasick keyword matching → detector dispatch → verification
- **JSON Output Schema:** No diagram; a structured field reference table will be used instead

All diagrams will use Mermaid syntax compatible with GitHub Markdown rendering, matching the style established by `docs/concurrency.md` and `docs/process_flow.md`.

## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

| Target Documentation File | Transformation | Source Code/Docs | Content/Changes |
|---------------------------|----------------|------------------|-----------------|
| `blitzy/documentation/<source_branch_name>.md` | CREATE | `main.go`, `pkg/engine/engine.go`, `pkg/engine/defaults/defaults.go`, `pkg/detectors/detectors.go`, `pkg/detectors/http.go`, `pkg/output/json.go`, `pkg/handlers/handlers.go`, `pkg/engine/ahocorasick/ahocorasickcore.go`, `pkg/config/config.go`, `pkg/decoders/decoders.go`, `pkg/feature/feature.go`, `pkg/sources/sources.go`, `docs/concurrency.md`, `docs/process_flow.md` | Comprehensive architecture exploration document answering five questions about detection, verification, output, traversal, and detector design. Includes Mermaid diagrams, JSON schema tables, source citations, and rationale for every conclusion. |

**Note:** The `<source_branch_name>` placeholder in the filename must be resolved at generation time to the actual source branch name of the repository. If no branch name is determinable, a descriptive fallback name should be used based on the task context (e.g., `detection-architecture-exploration`).

### 0.5.2 New Documentation File Detail

```
File: blitzy/documentation/<source_branch_name>.md
Type: Architecture Exploration Guide / Technical Q&A
Source Code: main.go, pkg/engine/**, pkg/detectors/**, pkg/output/json.go,
             pkg/handlers/**, pkg/config/**, pkg/decoders/**, pkg/feature/**
Sections:
    - Introduction (purpose, methodology, codebase version context)
    - Detection Architecture & Startup Behavior
        - Build process (CGO_ENABLED=0, go build)
        - init() function: maxprocs, arg normalization, CLI parsing, log config
        - main() function: logger setup, overseer config, update fetcher
        - run() function: signal handling, config loading, engine creation
        - NewEngine(): detector filtering, Aho-Corasick trie construction
        - DefaultDetectors(): compiled-in registry, endpoint customization
        - Initialization logging: V(2) worker count messages, V(4) engine init
    - Verification Setup
        - go.mod HTTP dependencies (net/http stdlib, aws-sdk-go, etc.)
        - DetectorHttpClientWithNoLocalAddresses / WithLocalAddresses
        - DetectorTransport with User-Agent injection
        - Parallel verification via DetectorWorkers (concurrency * 8 multiplier)
        - Timeout configuration (DefaultResponseTimeout = 10s)
        - Verification caching (pkg/verificationcache/)
    - Output Structure
        - JSONPrinter struct fields (SourceMetadata, SourceID, SourceType, SourceName,
          DetectorType, DetectorName, DetectorDescription, DecoderName, Verified,
          VerificationError, VerificationFromCache, Raw, RawV2, Redacted,
          ExtraData, StructuredData)
        - Verification status: boolean Verified field (no confidence score)
        - Source metadata: protobuf MetaData oneof with Git, GitHub, Filesystem, etc.
    - Repository Traversal
        - Source → Unit → Chunk decomposition
        - HandleFile() MIME detection via github.com/gabriel-vasile/mimetype
        - selectHandler() routing: AR/RPM/APK/archive/default
        - skipArchiverMimeTypes bypass set
        - Binary file detection and skip behavior
        - Archive recursion with depth/size/timeout limits
        - Feature flags: ForceSkipBinaries, ForceSkipArchives, EnableAPKHandler
    - Detector Architecture
        - Embedded modules (not plugins) compiled into single binary
        - Detector interface: FromData, Keywords, Type, Description
        - Optional interfaces: Versioner, EndpointCustomizer, CloudProvider
        - Aho-Corasick keyword prefiltering with span calculation
        - 800+ detector types in pkg/detectors/* subfolders
        - Custom detectors via --config YAML (pkg/config/config.go)
        - CLI help: --include-detectors, --exclude-detectors, subcommands
    - Summary and Cross-References to docs/concurrency.md, docs/process_flow.md
Diagrams:
    - Mermaid flowchart: Engine startup sequence
    - Mermaid sequence diagram: Verification concurrency
    - Mermaid flowchart: File handling decision tree
    - Mermaid flowchart: Chunk-to-detector matching pipeline
Key Citations:
    main.go, pkg/engine/engine.go, pkg/engine/defaults/defaults.go,
    pkg/detectors/detectors.go, pkg/detectors/http.go, pkg/output/json.go,
    pkg/handlers/handlers.go, pkg/engine/ahocorasick/ahocorasickcore.go,
    pkg/config/config.go, pkg/decoders/decoders.go, pkg/feature/feature.go,
    docs/concurrency.md, docs/process_flow.md
```

### 0.5.3 Documentation Configuration Updates

No documentation configuration updates are required because:
- The repository uses no documentation generator (no mkdocs.yml, docusaurus.config.js, or .readthedocs.yml)
- The new document is placed in `blitzy/documentation/` which is a standalone output directory external to the repository's native documentation structure
- No navigation, sidebar, or index files need updating

### 0.5.4 Cross-Documentation Dependencies

- **Cross-reference to `docs/concurrency.md`:** The new document will reference the existing Mermaid sequence diagram showing ScannerWorkers → DetectorWorkers → NotifierWorkers pipeline
- **Cross-reference to `docs/process_flow.md`:** The new document will reference the existing Source Decomposition, Chunk-to-Detector Matching, Secret Detection, and Result Notification flowcharts
- **Cross-reference to `CONTRIBUTING.md`:** Logging verbosity levels (0-5) documented there will be cited when explaining initialization messages
- **Cross-reference to `pkg/custom_detectors/CUSTOM_DETECTORS.md`:** The custom detector configuration path will reference this existing guide
- **Cross-reference to `examples/README.md`:** The generic detector YAML example will be referenced when explaining runtime-loaded detectors

## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

Since this is a documentation-creation task with no documentation site generator involved, the relevant dependencies are the tools and libraries referenced in the source code that the documentation will describe. The project itself is a Go module with no separate documentation toolchain.

| Registry | Package Name | Version | Purpose |
|----------|--------------|---------|---------|
| Go module | `go` | 1.23.1 | Go language version specified in `go.mod` |
| Go toolchain | `go` | 1.24.2 | Toolchain directive in `go.mod` line 5 |
| Go module | `github.com/alecthomas/kingpin/v2` | v2.4.0 | CLI flag parsing framework used in `main.go` |
| Go module | `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Aho-Corasick trie for keyword prefiltering in `pkg/engine/ahocorasick/` |
| Go module | `github.com/gabriel-vasile/mimetype` | (per go.mod) | MIME type detection in `pkg/handlers/handlers.go` |
| Go module | `github.com/mholt/archives` | (per go.mod) | Archive format identification and extraction in `pkg/handlers/archive.go` |
| Go module | `github.com/jpillora/overseer` | (forked) | Process supervision and binary self-updating in `main.go` |
| Go module | `github.com/hashicorp/golang-lru/v2` | (per go.mod) | LRU cache for result deduplication in `pkg/engine/engine.go` |
| Go module | `go.uber.org/automaxprocs/maxprocs` | (per go.mod) | Automatic GOMAXPROCS configuration in `main.go` init() |
| Go module | `github.com/fatih/color` | (per go.mod) | Colorized terminal output in `main.go` and `pkg/output/plain.go` |
| Go stdlib | `net/http` | (stdlib) | HTTP client for detector verification in `pkg/detectors/http.go` |
| Go stdlib | `encoding/json` | (stdlib) | JSON marshaling for `--json` output in `pkg/output/json.go` |
| Protobuf | `google.golang.org/protobuf` | (per go.mod) | Protobuf generated types for detectors, sources, metadata |

### 0.6.2 Documentation Reference Updates

Not applicable. This task creates a new standalone document and does not modify any existing files or documentation links within the repository.

## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current coverage analysis (before this task):**

| Area | Status | Coverage |
|------|--------|----------|
| Startup/initialization behavior | Undocumented externally | 0% |
| Detector loading mechanism (compiled-in vs file) | Undocumented | 0% |
| Verification HTTP architecture | Undocumented | 0% |
| Verification concurrency model | Partially documented in `docs/concurrency.md` | ~25% |
| JSON output schema | Undocumented | 0% |
| File traversal/skip logic | Undocumented | 0% |
| Detector architecture (plugin vs embedded) | Undocumented | 0% |
| Aho-Corasick prefiltering | Undocumented | 0% |
| Decoder pipeline | Undocumented | 0% |
| Custom detector extension | Documented in `pkg/custom_detectors/CUSTOM_DETECTORS.md` | ~80% |

**Target coverage after this task:** 100% for all five user-posed questions, with comprehensive source citations.

**Coverage gaps to address:**
- Startup sequence: Currently 0% documented, target 100% — full walkthrough from `init()` through engine start
- Detector loading: Currently 0% documented, target 100% — definitive answer that detectors are compiled in
- Verification setup: Currently ~25% documented, target 100% — HTTP client details, concurrency multiplier, timeout config
- JSON output: Currently 0% documented, target 100% — complete field-by-field schema
- File traversal: Currently 0% documented, target 100% — MIME routing, skip logic, feature flags

### 0.7.2 Documentation Quality Criteria

**Completeness requirements:**
- Every architectural question posed by the user must be answered with specific code evidence
- Each answer must cite the exact file path and line number range that supports the conclusion
- Thinking/rationale must be provided for each answer per the `SWE-AtlasQnA-Repo` rule
- No assumptions permitted — all claims must be verifiable against the source code

**Accuracy validation:**
- All file paths and line references must correspond to actual code in the repository
- All Go type names, function names, and field names must match the codebase exactly
- JSON schema fields must match the anonymous struct in `pkg/output/json.go` lines 27-74 precisely
- Detector interface methods must match `pkg/detectors/detectors.go` lines 19-29 precisely
- Worker multiplier values must match `pkg/engine/engine.go` line 345 (detectorWorkerMultiplier = 8)

**Clarity standards:**
- Technical accuracy with accessible language for an onboarding engineer
- Progressive disclosure: start with the high-level answer, then dive into code details
- Consistent terminology matching the codebase (chunk, detector, source, unit, scanner worker, etc.)
- Each section should be independently readable while forming a coherent narrative

**Maintainability:**
- Source citations use `Source: filepath:LineRange` format for easy cross-referencing
- Mermaid diagrams use simple syntax that renders in GitHub Markdown
- Document is self-contained with no external dependencies

### 0.7.3 Example and Diagram Requirements

- **Minimum diagrams:** 4 Mermaid diagrams (startup flow, verification concurrency, file handling, detector matching)
- **JSON output example:** One annotated skeleton JSON object showing all fields
- **Code citations per section:** Minimum 2 source file references per major answer section
- **Diagram style:** Consistent with existing `docs/concurrency.md` Mermaid conventions

## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

**New documentation files:**
- `blitzy/documentation/<source_branch_name>.md` — the sole deliverable: a comprehensive architecture exploration Q&A document

**Source code files to analyze and cite (read-only — no modifications):**
- `main.go` — CLI entrypoint, startup sequence, flag definitions
- `pkg/engine/engine.go` — Engine struct, NewEngine, Start, workers, metrics
- `pkg/engine/defaults/defaults.go` — DefaultDetectors compiled registry
- `pkg/engine/ahocorasick/ahocorasickcore.go` — keyword prefiltering trie
- `pkg/detectors/detectors.go` — Detector interface, Result, ResultWithMetadata
- `pkg/detectors/http.go` — HTTP client infrastructure for verification
- `pkg/detectors/falsepositives.go` — false-positive filtering (fp_badlist.txt, fp_words.txt, etc.)
- `pkg/output/json.go` — JSON output schema definition
- `pkg/output/plain.go` — plain text output format
- `pkg/handlers/handlers.go` — MIME routing, handler selection, file handling
- `pkg/handlers/default.go` — default non-archive handler
- `pkg/handlers/archive.go` — recursive archive traversal
- `pkg/handlers/apk.go` — APK-specific handler
- `pkg/handlers/ar.go` — AR archive handler
- `pkg/handlers/rpm.go` — RPM package handler
- `pkg/config/config.go` — custom detector YAML loading
- `pkg/config/detectors.go` — DetectorID parsing, include/exclude logic
- `pkg/decoders/decoders.go` — DefaultDecoders ordering
- `pkg/decoders/utf8.go`, `pkg/decoders/base64.go`, `pkg/decoders/utf16.go`, `pkg/decoders/escaped_unicode.go`
- `pkg/feature/feature.go` — runtime feature flags
- `pkg/sources/sources.go` — Source interface, Chunk model
- `pkg/sources/source_manager.go` — source orchestration
- `pkg/verificationcache/` — verification result caching
- `proto/detectors.proto` — DetectorType enum, Result message
- `proto/source_metadata.proto` — MetaData oneof structure
- `proto/custom_detectors.proto` — CustomRegex schema
- `docs/concurrency.md` — existing concurrency documentation (cross-reference)
- `docs/process_flow.md` — existing process flow documentation (cross-reference)
- `go.mod` — Go version, toolchain, dependency list
- `Makefile` — build commands
- `CONTRIBUTING.md` — logging level documentation
- `examples/generic.yml`, `examples/generic_with_filters.yml` — custom detector examples
- `pkg/custom_detectors/CUSTOM_DETECTORS.md` — custom detector guide

### 0.8.2 Explicitly Out of Scope

- **Source code modifications** — No files in the repository may be modified per user instruction
- **Existing documentation updates** — The documents in `docs/`, `README.md`, `CONTRIBUTING.md`, etc. must remain untouched
- **Test file modifications** — No test files will be created, modified, or executed
- **Feature additions or code refactoring** — This is a pure documentation task
- **Deployment configuration changes** — No CI/CD, Docker, or Goreleaser changes
- **Building or running the binary** — The documentation is based on source code analysis, not runtime observation (the user's questions about "building and running" are answered via static code analysis per the code-truth constraint)
- **Individual detector documentation** — The 800+ individual detector implementations in `pkg/detectors/*/` subfolders are not individually documented; they are referenced as a catalog
- **Performance benchmarking documentation** — The `hack/bench/` tooling is not in scope
- **Enterprise features** — TruffleHog Enterprise capabilities are out of scope

## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

- **Documentation build command:** Not applicable — the repository uses plain Markdown without a documentation site generator (no mkdocs, Sphinx, Docusaurus, or Hugo detected)
- **Documentation preview command:** Any Markdown previewer can render the output file; for Mermaid diagrams, use a Mermaid-capable renderer (e.g., GitHub natively renders fenced `mermaid` blocks)
- **Diagram generation command:** Not applicable — all diagrams are embedded as fenced Mermaid blocks in Markdown; no CLI generation step is needed
- **Documentation deployment command:** Not applicable — the file is placed in `blitzy/documentation/` and committed alongside the repository
- **Default format:** Markdown (`.md`) with Mermaid diagram blocks (consistent with existing `docs/concurrency.md` and `docs/process_flow.md` conventions)
- **Citation requirement:** Every technical claim in the output document must include a source file path reference (e.g., `Source: pkg/engine/engine.go:336`) to enable readers to trace assertions back to the codebase
- **Style guide:** Follow the existing repository documentation style observed in `docs/concurrency.md` and `docs/process_flow.md`:
  - Use `#` / `##` / `###` heading hierarchy
  - Use fenced code blocks with language identifiers (` ```go `, ` ```mermaid `)
  - Bullet-point lists for structured enumerations
  - Mermaid `sequenceDiagram` and `flowchart` types for architectural diagrams
- **Documentation validation:** Verify all referenced file paths and line numbers match the current repository state; confirm Mermaid syntax is valid by visual check against the Mermaid live editor grammar

### 0.9.2 Output File Naming

Because no git branch name is determinable from the current environment (all standard git commands returned empty), the output filename will use a descriptive fallback:

- **Target path:** `blitzy/documentation/trufflehog-detection-architecture-qna.md`
- **Rationale:** The user's implementation rule specifies `<source_branch_name>.md`, but with no branch available, a meaningful descriptive name ensures discoverability and aligns with the document's content

### 0.9.3 Temporary Script Policy

The user explicitly stated: "Temporary scripts may be used for observation, but the repository itself should remain unchanged and anything temporary should be cleaned up afterward."

- All analysis is performed via read-only repository inspection (no temporary scripts were needed)
- If any temporary files are created during the documentation generation phase, they must be removed before marking the task complete
- The only file created in the repository tree is the output document at `blitzy/documentation/trufflehog-detection-architecture-qna.md`

## 0.10 Rules for Documentation

### 0.10.1 User-Specified Rules

The following rules are derived directly from the user's instructions and the implementation rule `SWE-AtlasQnA-Repo`:

- **Do not modify any existing files in the source repository** — The entire codebase is read-only; the only writable path is `blitzy/documentation/`
- **Do not make assumptions, base your answers on the code as the truth** — Every architectural claim must be traceable to a specific source file, function, struct, or constant in the repository; speculation and inference from convention are not permitted
- **Provide thinking / rationale behind the answers** — Each answer must include not just the "what" but the "why," showing the reasoning chain from code evidence to conclusion
- **Create a new markdown document** — Output is a single `.md` file placed in `blitzy/documentation/` in the destination repo
- **Temporary scripts may be used for observation, but the repository itself should remain unchanged and anything temporary should be cleaned up afterward** — No persistent artifacts beyond the output document

### 0.10.2 Derived Documentation Rules

Based on the user's questions and the repository conventions:

- **Answer structure mirrors the questions** — The document must address each of the user's five question areas as distinct sections: (1) detection startup and registration, (2) verification HTTP infrastructure, (3) JSON output schema, (4) repository traversal and file handling, (5) detector architecture (plugin vs embedded)
- **Include source citations for all technical details** — Every function, struct, constant, or behavioral claim must reference its file path and line number (e.g., `pkg/engine/engine.go:336`)
- **Use Mermaid diagrams for architectural flows** — The existing repo documentation (`docs/concurrency.md`, `docs/process_flow.md`) uses Mermaid; the output document should follow this convention for consistency
- **Include code snippets sparingly** — Short Go code excerpts (2–3 lines) to illustrate key structures (e.g., the Detector interface signature, the JSON output struct fields) but not full function bodies
- **Maintain accessible technical language** — The user described themselves as "onboarding" to TruffleHog; the document should explain architecture clearly to a newcomer while maintaining technical precision
- **No confidence scores or invented metrics** — The code explicitly does not include confidence scoring (verification is binary); the document must not imply otherwise

## 0.11 References

### 0.11.1 Repository Files and Folders Searched

The following files and folders were inspected during context gathering to derive the conclusions in this Agent Action Plan:

| File / Folder Path | Purpose of Inspection |
|---|---|
| `""` (repository root) | Root structure discovery — identified all top-level directories and files |
| `main.go` | CLI entrypoint, startup sequence, all subcommands, global flags, `init()` and `run()` functions |
| `go.mod` | Go module path, Go version (1.23.1), toolchain (go1.24.2), dependency list |
| `Makefile` | Build commands, test targets, proto generation |
| `README.md` | Project overview, feature summary |
| `CONTRIBUTING.md` | Contribution guidelines, logging level conventions |
| `pkg/` | Top-level package directory — 32+ subpackages enumerated |
| `pkg/engine/` | Engine orchestration layer — scan adapters, core engine, metrics |
| `pkg/engine/engine.go` | Engine struct, NewEngine(), setDefaults(), initialize(), startWorkers(), worker pipeline |
| `pkg/engine/defaults/` | Compiled-in detector registry |
| `pkg/engine/defaults/defaults.go` | DefaultDetectors(), buildDetectorList(), EndpointCustomizer/CloudProvider post-processing |
| `pkg/engine/ahocorasick/` | Aho-Corasick keyword prefiltering subsystem |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Trie construction, FindDetectorMatches(), span calculation |
| `pkg/detectors/` | Central detection framework — interface, results, HTTP, false positives, 800+ providers |
| `pkg/detectors/detectors.go` | Detector interface, optional interfaces, Result struct, ResultWithMetadata struct |
| `pkg/detectors/http.go` | HTTP client initialization, transport configuration, WithNoLocalIP, User-Agent injection |
| `pkg/output/` | Output formatting subsystem — four printer implementations |
| `pkg/output/json.go` | JSONPrinter, exact JSON output schema struct definition |
| `pkg/handlers/` | File handling subsystem — MIME detection, handler routing, archive traversal |
| `pkg/handlers/handlers.go` | HandleFile(), selectHandler(), newFileReader(), skipArchiverMimeTypes |
| `pkg/config/` | Configuration loading subsystem |
| `pkg/config/config.go` | Config struct, Read(), NewYAML() for custom detector YAML |
| `pkg/config/detectors.go` | ParseDetectors(), ParseVerifierEndpoints(), DetectorID resolution |
| `pkg/decoders/` | Decoder pipeline — UTF8, Base64, UTF16, EscapedUnicode |
| `pkg/feature/` | Runtime feature flags |
| `pkg/feature/feature.go` | ForceSkipBinaries, ForceSkipArchives, SkipAdditionalRefs, EnableAPKHandler |
| `pkg/sources/` | Source framework — 15 provider implementations |
| `pkg/custom_detectors/` | Custom detector framework — CustomRegexWebhook |
| `proto/` | Protobuf definitions — detectors, sources, metadata, custom detectors, credentials |
| `docs/` | Existing documentation directory |
| `docs/concurrency.md` | Worker startup Mermaid sequence diagram |
| `docs/process_flow.md` | Source → Chunk → Detect → Notify Mermaid flowcharts |
| `examples/` | Custom detector YAML examples |
| `examples/generic.yml` | Basic custom detector configuration example |
| `examples/generic_with_filters.yml` | Custom detector with filter configuration example |
| `hack/` | Benchmarking, detector generation, semgrep rules, snifftest |

### 0.11.2 Tech Spec Sections Retrieved

| Section Heading | Purpose |
|---|---|
| 1.1 EXECUTIVE SUMMARY | Background context on TruffleHog v3 system overview and capabilities |

### 0.11.3 Attachments

No attachments were provided for this project. No Figma URLs or external design files were referenced.

### 0.11.4 External URLs

No external URLs were referenced in the user's requirements. No web searches were conducted; all analysis is based exclusively on the source code repository as the single source of truth, consistent with the user's rule "Do not make assumptions, base your answers on the code as the truth."

