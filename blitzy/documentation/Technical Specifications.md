# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **create a new investigative analysis document** that explains the root cause of a finding-count discrepancy between TruffleHog's CLI filesystem scan and a minimal Go program that invokes TruffleHog's scanning API directly on the same directory.

- **Category:** Create new documentation
- **Documentation Type:** Technical investigation / root-cause analysis document

The specific documentation requirements are:

- **Explain the behavioral divergence:** Why does `trufflehog filesystem <dir>` (CLI) report more secret findings than an equivalent Go program that constructs an `engine.Config`, calls `engine.NewEngine`, and invokes `eng.ScanFileSystem` against the same directory?
- **Identify the detector-selection component:** Document which component decides which detectors participate in a scan (`pkg/engine/defaults/defaults.go` via `DefaultDetectors()`) and how their configuration is derived (endpoint customization, include/exclude filtering, feature flags).
- **Trace configuration differences at runtime:** Show what conditions, configuration values, environment variables, or built-in defaults cause the CLI and a minimal API program to produce different detector sets or scanning behavior.
- **Ground the analysis in code evidence:** Every claim must reference specific source files, functions, and line numbers from the TruffleHog v3 repository rather than speculation.
- **Leave the repository unmodified:** No existing source files may be changed; any temporary helper code must be cleaned up.

### 0.1.2 Special Instructions and Constraints

- **Read-only requirement:** "Do not modify any existing source files in the repository. If you create temporary helper code or configuration for debugging, ensure it is removed before you finish so the repo is left in its original state."
- **Implementation rule — SWE-AtlasQnA-Repo:** Create a new markdown document named `trufflehog_e42153d44a5e.md` in the `blitzy/documentation` directory that comprehensively answers the investigation question with rationale grounded in the codebase.
- **No assumptions allowed:** "Do not make assumptions, base your answers on the code as the truth."
- **Markdown output only:** The deliverable is a single `.md` file; no other file types are expected.
- **No Figma, no design system, no UI components** are relevant to this task.

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To **explain the CLI-vs-API finding-count discrepancy**, we will create `blitzy/documentation/trufflehog_e42153d44a5e.md` containing a structured analysis that traces both execution paths through the codebase, pinpointing every divergence point.
- To **identify the detector-selection component**, we will document the role of `pkg/engine/defaults/defaults.go:DefaultDetectors()` (which builds the canonical ~800-detector list and applies `EndpointCustomizer` / `CloudProvider` initialization), `pkg/engine/engine.go:setDefaults()` (fallback when `Config.Detectors` is empty), and `pkg/engine/engine.go:NewEngine()` (which applies include/exclude filters via `buildDetectorSets`).
- To **trace runtime configuration differences**, we will document how `main.go` sets `--include-detectors` to `"all"` by default (line 81), explicitly populates `Config.Detectors` with `defaults.DefaultDetectors()` (line 519), enables `feature.EnableAPKHandler` (line 458), and applies multiple feature flags — none of which a minimal API caller would do unless it replicates the same setup.

### 0.1.4 Inferred Documentation Needs

Based on code analysis, the following implicit documentation needs have been identified:

- **Feature-flag initialization gap:** `main.go:458` sets `feature.EnableAPKHandler.Store(true)` unconditionally for OSS builds. A minimal Go program bypassing `main.go` would never set this flag, causing the APK handler (`pkg/handlers/handlers.go:537`) to skip APK files — potentially reducing the number of chunks scanned and thus the number of findings.
- **Detector list vs. detector filtering interaction:** The CLI always supplies `IncludeDetectors: "all"` (line 81 and 521 of `main.go`), which feeds into `config.ParseDetectors("all")` and generates the full protobuf-enum-based include set. A minimal API caller that leaves `IncludeDetectors` as `""` produces a zero-length include set, causing the include filter to be skipped entirely in `engine.go:263`. While skipping the filter means "include everything already in the list," the distinction matters if the caller also omits `Config.Detectors` entirely — in that case, `setDefaults` populates it with `DefaultDetectors()`, which is the same list, yielding identical behavior. However, if the caller provides only a partial detector list or omits `DefaultDetectors()`, the difference becomes material.
- **Endpoint customization dependency:** `DefaultDetectors()` enables `UseFoundEndpoints(true)` and `UseCloudEndpoint(true)` for every detector implementing `EndpointCustomizer`. If a caller constructs detectors manually without calling `DefaultDetectors()`, those endpoint behaviors remain disabled, altering verification reach and potentially affecting which results are reported.
- **Decoder defaults:** Both paths receive the same `DefaultDecoders()` (UTF8, Base64, UTF16, EscapedUnicode) from `engine.go:357-359` when `Config.Decoders` is nil, so decoders are unlikely to be a source of divergence unless explicitly overridden.


## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a **minimal documentation structure** with two architecture-focused markdown files and several governance/community documents at the root.

**Documentation files discovered:**

| Path | Type | Coverage Status |
|------|------|-----------------|
| `docs/concurrency.md` | Architecture doc | Mermaid sequence diagram of worker concurrency model |
| `docs/process_flow.md` | Architecture doc | Mermaid flowchart of source → chunk → detect → notify pipeline |
| `README.md` | Project overview | Comprehensive CLI usage; minimal library-usage guidance ("Use as a library" section at line 676 says "no guarantees on the stability of the public APIs") |
| `CONTRIBUTING.md` | Contributor guide | Development workflow, logging conventions |
| `SECURITY.md` | Security policy | Vulnerability reporting |
| `CODE_OF_CONDUCT.md` | Community policy | Contributor covenant |
| `PreCommit.md` | Integration guide | Pre-commit hook setup |
| `examples/README.md` | Custom detector guide | YAML-based custom regex detector configuration |

**Documentation tooling:**
- No documentation generator (mkdocs, docusaurus, sphinx) is configured in the repository
- Diagrams are authored using Mermaid inline within markdown files
- No automated documentation build or deployment pipeline exists
- No JSDoc/Godoc generation pipeline is configured despite Go being the primary language

**Key finding:** There is no existing document that explains the behavioral differences between the CLI and API code paths, making this documentation a net-new creation.

### 0.2.2 Repository Code Analysis for Documentation

The investigation focused on the following code paths to understand the CLI-vs-API discrepancy:

**CLI entry point — `main.go`:**
- Defines all CLI flags including `--include-detectors` (default: `"all"`, line 81) and `--exclude-detectors` (no default, line 82)
- Builds `engine.Config` at lines 513–533, explicitly setting `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)`
- Sets feature flags at lines 441–458: `ForceSkipBinaries`, `ForceSkipArchives`, `SkipAdditionalRefs`, `EnableAPKHandler`
- Configures `SourceManager` with concurrency, unit support, and buffered output at lines 673–686

**Engine initialization — `pkg/engine/engine.go`:**
- `NewEngine()` (line 226) applies `setDefaults()`, `buildDetectorSets()`, and `applyFilters()`
- `setDefaults()` (line 336) only populates `e.detectors` with `DefaultDetectors()` if `len(e.detectors) == 0`
- `buildDetectorSets()` (line 376) parses `IncludeDetectors` and `ExcludeDetectors` strings into filter maps

**Default detectors — `pkg/engine/defaults/defaults.go`:**
- `buildDetectorList()` (line 839) assembles a manually ordered slice of ~800+ detector instances
- `DefaultDetectors()` (line 1704) wraps `buildDetectorList()` and applies `EndpointCustomizer` initialization: `UseFoundEndpoints(true)`, `UseCloudEndpoint(true)`, and `SetCloudEndpoint()` for `CloudProvider` detectors

**Feature flags — `pkg/feature/feature.go`:**
- Global atomic booleans: `ForceSkipBinaries`, `ForceSkipArchives`, `SkipAdditionalRefs`, `EnableAPKHandler`
- `EnableAPKHandler` is consumed by `pkg/handlers/handlers.go:537` in `shouldHandleAsAPK()`

**Config parsing — `pkg/config/detectors.go`:**
- `ParseDetectors("all")` returns the full protobuf enum set via `allDetectors()` (line 131)
- `ParseDetectors("")` returns an empty slice, which causes the include filter to be skipped entirely

### 0.2.3 Web Search Research Conducted

No external web search was required for this task. The investigation is entirely grounded in the repository source code, which is the authoritative source of truth per the user's explicit instruction: "Do not make assumptions, base your answers on the code as the truth."


## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

The following modules require documentation to explain the CLI-vs-API behavioral divergence:

- **Module: `main.go` (CLI entry point)**
  - Public APIs: `run()`, `runSingleScan()`, `init()`, `parseResults()`
  - Current documentation: Inline comments only; no standalone doc
  - Documentation needed: Explanation of how the CLI assembles `engine.Config` with defaults, feature flags, and filter settings

- **Module: `pkg/engine/engine.go` (Engine orchestration)**
  - Public APIs: `NewEngine()`, `Config` struct, `Start()`, `Finish()`, `ScanFileSystem()`, `SetDetectorTimeout()`
  - Current documentation: Inline comments; `docs/concurrency.md` and `docs/process_flow.md` cover high-level architecture
  - Documentation needed: Explanation of `setDefaults()` behavior, `buildDetectorSets()` include/exclude logic, and `applyFilters()` pipeline

- **Module: `pkg/engine/defaults/defaults.go` (Detector registry)**
  - Public APIs: `DefaultDetectors()`, `DefaultDetectorTypesImplementing[T]()`
  - Current documentation: None beyond code comments
  - Documentation needed: How the detector list is built, how `EndpointCustomizer` initialization works, and the significance of calling `DefaultDetectors()` vs. manually constructing detectors

- **Module: `pkg/feature/feature.go` (Feature flags)**
  - Public APIs: `ForceSkipBinaries`, `ForceSkipArchives`, `SkipAdditionalRefs`, `EnableAPKHandler`
  - Current documentation: None
  - Documentation needed: Which flags the CLI sets and what happens when they are not set by an API caller

- **Module: `pkg/config/detectors.go` (Detector parsing)**
  - Public APIs: `ParseDetectors()`, `ParseDetector()`, `GetDetectorID()`, `DetectorID`
  - Current documentation: Inline comments
  - Documentation needed: How `"all"` vs `""` input affects include filter construction

- **Module: `pkg/handlers/handlers.go` (File handler routing)**
  - Public APIs: `shouldHandleAsAPK()`
  - Current documentation: Inline comments
  - Documentation needed: How `EnableAPKHandler` gates APK processing

- **Module: `pkg/decoders/decoders.go` (Decoder pipeline)**
  - Public APIs: `DefaultDecoders()`
  - Current documentation: Inline comments
  - Documentation needed: Confirmation that decoder behavior is identical in both paths

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, documentation gaps include:

- **No existing document** explains the interaction between CLI flag defaults and `engine.Config` assembly, which is the root cause of the user's observed discrepancy.
- **No library usage guide** exists beyond the one-line caveat in `README.md` (line 676–679) that public APIs are unstable.
- **No document** maps the feature-flag initialization sequence that the CLI performs but a direct API caller would not.
- **No document** catalogs which detectors implement `EndpointCustomizer` / `CloudProvider` and how `DefaultDetectors()` configures them at call time.
- **Undocumented public APIs:** `engine.Config` struct fields are commented in code but not documented in any standalone reference material.


## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

The deliverable is a single markdown document placed at:

```text
blitzy/
└── documentation/
    └── trufflehog_e42153d44a5e.md
```

The document will follow this outline:

```text
trufflehog_e42153d44a5e.md
├── Title and Summary
├── 1. Background and Problem Statement
├── 2. Architecture of the Scan Pipeline
├── 3. CLI Code Path Analysis
├── 4. API Code Path Analysis
├── 5. Root Cause: Divergence Points
├── 6. The Detector Selection Component
├── 7. Conditions Producing Different Behavior
├── 8. Recommendations
└── References
```

### 0.4.2 Content Generation Strategy

**Information Extraction Approach:**
- Extract `engine.Config` field initialization from `main.go` lines 513–533 using direct code citation
- Extract `setDefaults()` logic from `pkg/engine/engine.go` lines 336–374
- Extract `DefaultDetectors()` endpoint initialization from `pkg/engine/defaults/defaults.go` lines 1704–1723
- Extract feature-flag gating from `pkg/feature/feature.go` and `pkg/handlers/handlers.go:537`
- Generate comparison tables by tracing both execution paths side-by-side

**Documentation Standards:**
- Markdown formatting with `#`, `##`, `###` headers
- Mermaid diagrams for data flow and comparison visualization
- Code examples using fenced code blocks with syntax highlighting
- Source citations as inline references: `Source: /path/to/file.go:LineNumber`
- Tables for side-by-side comparisons of CLI vs API behavior

### 0.4.3 Diagram and Visual Strategy

Mermaid diagrams to create within the document:

- **Flowchart:** CLI code path from `main.go:init()` through `run()` and `runSingleScan()` to `engine.NewEngine()` and `engine.Start()`, showing all configuration assembly steps
- **Flowchart:** API code path from user program to `engine.NewEngine()` and `engine.Start()`, showing the abbreviated configuration assembly
- **Comparison table:** Side-by-side table of `engine.Config` fields and their values under each path


## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

| Target Documentation File | Transformation | Source Code/Docs | Content/Changes |
|---------------------------|----------------|------------------|-----------------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | CREATE | `main.go`, `pkg/engine/engine.go`, `pkg/engine/defaults/defaults.go`, `pkg/engine/filesystem.go`, `pkg/feature/feature.go`, `pkg/config/detectors.go`, `pkg/decoders/decoders.go`, `pkg/handlers/handlers.go`, `pkg/detectors/detectors.go`, `pkg/detectors/endpoint_customizer.go`, `docs/process_flow.md`, `docs/concurrency.md` | Complete investigative analysis document explaining CLI-vs-API finding-count discrepancy, detector selection component, divergence root causes, and runtime configuration differences |

**Transformation Modes Used:**
- **CREATE** — One new documentation file

No existing documentation files require UPDATE or DELETE. No REFERENCE files are needed since the document style is freestanding investigative analysis rather than API reference that must follow an existing template.

### 0.5.2 New Documentation File Detail

```text
File: blitzy/documentation/trufflehog_e42153d44a5e.md
Type: Technical investigation / root-cause analysis
Source Code:
  - main.go (CLI entry, flag defaults, engine.Config assembly, feature flags)
  - pkg/engine/engine.go (NewEngine, setDefaults, buildDetectorSets, applyFilters)
  - pkg/engine/defaults/defaults.go (DefaultDetectors, EndpointCustomizer init)
  - pkg/engine/filesystem.go (ScanFileSystem entry point)
  - pkg/feature/feature.go (atomic feature flags)
  - pkg/config/detectors.go (ParseDetectors, allDetectors, DetectorID)
  - pkg/decoders/decoders.go (DefaultDecoders)
  - pkg/handlers/handlers.go (shouldHandleAsAPK, EnableAPKHandler gate)
  - pkg/detectors/detectors.go (Detector interface, EndpointCustomizer interface)
  - pkg/detectors/endpoint_customizer.go (EndpointSetter implementation)
Sections:
  - Background and problem statement
  - Architecture overview of the scan pipeline (with Mermaid diagram)
  - CLI code path analysis (flag defaults, Config assembly, feature flags)
  - API code path analysis (minimal program, setDefaults fallback)
  - Root cause divergence points (5 identified causes)
  - Detector selection component deep dive
  - Conditions producing different behavior (env vars, flags, defaults)
  - Recommendations for achieving CLI parity from Go API code
  - References with file paths and line numbers
Diagrams:
  - Mermaid flowchart: CLI initialization path
  - Mermaid flowchart: API initialization path
  - Mermaid flowchart: detector selection pipeline
Key Citations:
  main.go:81, main.go:458, main.go:513-533
  pkg/engine/engine.go:226-328, pkg/engine/engine.go:336-374, pkg/engine/engine.go:376-400
  pkg/engine/defaults/defaults.go:839-1723
  pkg/feature/feature.go:6-11
  pkg/handlers/handlers.go:536-539
  pkg/config/detectors.go:15-17, 56-86, 130-138
  pkg/decoders/decoders.go:8-16
```

### 0.5.3 Documentation Configuration Updates

No documentation configuration files need updating. The repository does not use mkdocs, docusaurus, sphinx, or any other documentation generator. The new file is placed in `blitzy/documentation/` as specified by the implementation rule.

### 0.5.4 Cross-Documentation Dependencies

- The new document references concepts described in `docs/process_flow.md` (source → chunk → detect → notify pipeline) and `docs/concurrency.md` (worker model), but does not modify them.
- No shared includes, navigation updates, or table-of-contents changes are required.
- No index or glossary updates are needed.


## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

No additional documentation tooling or packages are required for this task. The deliverable is a plain Markdown file authored directly. The repository does not use any documentation generator.

For reference, the following runtime dependencies of TruffleHog are relevant to the analysis documented:

| Registry | Package Name | Version | Purpose (relevant to this investigation) |
|----------|-------------|---------|------------------------------------------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | v3 (HEAD at `e42153d4`) | Root module; contains all analyzed packages |
| Go stdlib | `sync/atomic` | (Go 1.23.1) | Implements feature flag atomics in `pkg/feature/feature.go` |
| Go module | `github.com/alecthomas/kingpin/v2` | (per go.mod) | CLI flag parsing with default values; drives `--include-detectors "all"` |
| Go module | `google.golang.org/protobuf` | (per go.mod) | Protobuf enum definitions for `DetectorType` used in `ParseDetectors()` |

The Go version specified in `go.mod` is:
- **Go directive:** 1.23.1
- **Toolchain:** go1.24.2

### 0.6.2 Documentation Reference Updates

No documentation link updates are required. The new file at `blitzy/documentation/trufflehog_e42153d44a5e.md` is a standalone document that does not replace or redirect any existing links.


## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current coverage analysis (before this task):**
- CLI-vs-API behavioral differences documented: 0/5 identified divergence points (0%)
- Detector selection component documented: 0/3 key functions (0%)
- Feature flag initialization documented: 0/4 flags (0%)

**Target coverage (after this task):**
- CLI-vs-API behavioral differences documented: 5/5 identified divergence points (100%)
- Detector selection component documented: 3/3 key functions (100%)
- Feature flag initialization documented: 4/4 flags (100%)

**Coverage gaps to address:**

| Topic | Current | Target | Focus Areas |
|-------|---------|--------|-------------|
| CLI config assembly | 0% | 100% | `main.go` flag defaults, `engine.Config` construction, feature flag init |
| API config assembly | 0% | 100% | `setDefaults()` fallback, missing feature flags, empty include filter |
| Detector registry | 0% | 100% | `DefaultDetectors()`, `EndpointCustomizer` init, `buildDetectorList()` |
| Include/exclude filtering | 0% | 100% | `ParseDetectors()`, `buildDetectorSets()`, `applyFilters()` |
| APK handler feature flag | 0% | 100% | `EnableAPKHandler`, `shouldHandleAsAPK()` |

### 0.7.2 Documentation Quality Criteria

**Completeness requirements:**
- Every divergence point between CLI and API paths must be identified, explained, and traced to specific source code lines
- The analysis must cover detector selection, feature flags, decoder defaults, endpoint customization, and source-manager configuration
- Each claim must cite a specific file path and line number as evidence

**Accuracy validation:**
- All code references must be verified against the actual source at commit `e42153d4`
- Behavioral assertions must be grounded in control flow analysis of the source code, not in speculation
- The document must not assert behaviors that contradict the source

**Clarity standards:**
- Technical accuracy with accessible language suitable for a Go developer using TruffleHog as a library
- Progressive disclosure: symptom → architecture → analysis → root causes → recommendations
- Consistent use of full qualified paths (e.g., `pkg/engine/engine.go`) for all file references

**Maintainability:**
- Source citations at the section level for traceability
- File and line references enable future readers to verify claims against the codebase
- Modular section structure allows individual sections to be updated independently

### 0.7.3 Example and Diagram Requirements

- Minimum 1 Mermaid diagram showing the scanning pipeline architecture
- Minimum 1 Mermaid diagram showing the detector-selection flow
- Minimum 1 comparison table showing CLI vs API `engine.Config` field values
- Short code snippets (2–3 lines each) illustrating the critical differences, such as how the CLI sets feature flags and how `setDefaults()` populates detectors


## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

**New documentation files:**
- `blitzy/documentation/trufflehog_e42153d44a5e.md` — the sole deliverable

**Source code analyzed (read-only, for documentation purposes):**
- `main.go` — CLI entry point, flag defaults, `engine.Config` assembly, feature flag initialization
- `pkg/engine/engine.go` — `NewEngine()`, `setDefaults()`, `buildDetectorSets()`, `applyFilters()`, `initialize()`
- `pkg/engine/defaults/defaults.go` — `DefaultDetectors()`, `buildDetectorList()`, `DefaultDetectorTypesImplementing()`
- `pkg/engine/filesystem.go` — `ScanFileSystem()` entry point
- `pkg/feature/feature.go` — `EnableAPKHandler`, `ForceSkipBinaries`, `ForceSkipArchives`, `SkipAdditionalRefs`
- `pkg/config/detectors.go` — `ParseDetectors()`, `allDetectors()`, `DetectorID`, `GetDetectorID()`
- `pkg/config/config.go` — `Config` struct, `Read()`, `NewYAML()` for custom detector loading
- `pkg/decoders/decoders.go` — `DefaultDecoders()`
- `pkg/handlers/handlers.go` — `shouldHandleAsAPK()` and its feature flag gate
- `pkg/detectors/detectors.go` — `Detector` interface, `EndpointCustomizer` interface, `CloudProvider` interface
- `pkg/detectors/endpoint_customizer.go` — `EndpointSetter` implementation, `Endpoints()`, `UseFoundEndpoints()`, `UseCloudEndpoint()`
- `docs/process_flow.md` — existing pipeline architecture documentation
- `docs/concurrency.md` — existing concurrency model documentation
- `go.mod` — Go version and module path

**Investigation topics in scope:**
- Detector set construction and filtering pipeline
- Feature flag initialization differences between CLI and API paths
- `EndpointCustomizer` / `CloudProvider` initialization in `DefaultDetectors()`
- `SourceManager` configuration differences
- Decoder pipeline defaults
- `IncludeDetectors` / `ExcludeDetectors` filter mechanics
- APK handler gating via `EnableAPKHandler`

### 0.8.2 Explicitly Out of Scope

- **Source code modifications:** No existing files in the repository may be modified (per user directive)
- **Test file modifications:** No test files are to be created or changed
- **Feature additions or code refactoring:** This is a documentation-only task
- **Detector-specific analysis:** The document will not analyze individual detector implementations (e.g., the AWS detector's verification logic) — only the detector selection and configuration pipeline
- **Performance benchmarking:** The document will not measure scan performance, only explain behavioral divergence
- **Enterprise-only features:** TruffleHog Enterprise features (continuous monitoring, GUI, Jira/Slack scanning) are not relevant
- **Deployment configuration changes:** No Dockerfile, CI/CD, or build changes
- **Custom detector YAML configuration:** The user's scenario involves built-in detectors, not custom regex detectors
- **Temporary helper code:** While the user mentions the possibility of temporary debugging code, the documentation task does not require writing or running such code — the analysis is conducted by reading the source


## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

- **Documentation build command:** Not applicable — the output is a standalone Markdown file, not a generated documentation site
- **Documentation preview command:** Any Markdown viewer or `cat blitzy/documentation/trufflehog_e42153d44a5e.md`
- **Diagram generation command:** Mermaid diagrams are embedded inline in the Markdown and render in GitHub, GitLab, and compatible viewers
- **Documentation deployment command:** Not applicable — the file is committed directly to the repository
- **Default format:** Markdown with Mermaid diagrams
- **Citation requirement:** Every section must reference source files with paths and line numbers
- **Style guide:** Follow the existing documentation style observed in `docs/process_flow.md` and `docs/concurrency.md` — use Mermaid diagrams, clear section headers, and concise prose
- **Documentation validation:** Manual review; verify all file path and line number references against commit `e42153d4`
- **Output location:** `blitzy/documentation/trufflehog_e42153d44a5e.md` as required by the SWE-AtlasQnA-Repo implementation rule


## 0.10 Rules for Documentation

The following rules are explicitly required by the user or derived from the user's instructions:

- **Do not modify any existing source files in the repository.** The analysis document is the only file to be created.
- **Do not make assumptions; base answers on the code as the truth.** Every behavioral claim must be traceable to specific source code.
- **Create the output document as `<source_branch_name>.md` in `blitzy/documentation/`.** The branch name is `trufflehog_e42153d44a5e`, so the file is `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- **Provide thinking and rationale behind the answers.** The document must explain *why* each divergence point causes the CLI to report more findings, not just *that* it does.
- **If temporary helper code is created for debugging, it must be removed before finishing.** The repository must be left in its original state.
- **Include source code citations for all technical details.** Use `Source: <file>:<line>` notation throughout.
- **Use Mermaid diagrams for architectural and workflow visualization** — consistent with the existing documentation style in `docs/`.


## 0.11 References

### 0.11.1 Files and Folders Searched

The following files were retrieved and analyzed to derive the conclusions in this Agent Action Plan:

| File Path | Lines Examined | Purpose |
|-----------|---------------|---------|
| `main.go` | 1–1030 (full file) | CLI entry point; flag defaults, `engine.Config` assembly, feature flag initialization, `runSingleScan()` |
| `pkg/engine/engine.go` | 1–550, 621–700 | Engine initialization (`NewEngine`, `setDefaults`, `buildDetectorSets`, `applyFilters`), worker startup |
| `pkg/engine/defaults/defaults.go` | 1–1734 (full file) | Default detector registry (`buildDetectorList`, `DefaultDetectors`, `DefaultDetectorTypesImplementing`) |
| `pkg/engine/filesystem.go` | 1–37 (full file) | `ScanFileSystem()` entry point for filesystem source scanning |
| `pkg/feature/feature.go` | 1–36 (full file) | Global atomic feature flags (`EnableAPKHandler`, `ForceSkipBinaries`, etc.) |
| `pkg/config/detectors.go` | 1–200 | Detector ID parsing (`ParseDetectors`, `allDetectors`, `asRange`, `asDetectorID`, `DetectorID`) |
| `pkg/config/config.go` | (via summary) | Config loading for custom detectors (`Read`, `NewYAML`) |
| `pkg/decoders/decoders.go` | 1–50 (full file) | Default decoder list (`DefaultDecoders`: UTF8, Base64, UTF16, EscapedUnicode) |
| `pkg/handlers/handlers.go` | 525–555 | APK handler gating (`shouldHandleAsAPK`, `isAPKFile`) |
| `pkg/detectors/detectors.go` | 1–100 | Detector interface, `EndpointCustomizer` interface, `CloudProvider` interface |
| `pkg/detectors/endpoint_customizer.go` | 1–53 (full file) | `EndpointSetter` implementation (`Endpoints`, `UseFoundEndpoints`, `UseCloudEndpoint`, `SetCloudEndpoint`) |
| `docs/process_flow.md` | 1–50 | Existing pipeline architecture documentation (Mermaid flowcharts) |
| `docs/concurrency.md` | 1–50 | Existing concurrency model documentation (Mermaid sequence diagrams) |
| `go.mod` | 1–10 | Go version (1.23.1), toolchain (go1.24.2), module path |
| `README.md` | 675–685 | "Use as a library" section; public API stability caveat |
| `examples/README.md` | (via folder listing) | Custom detector YAML configuration examples |

**Folders traversed:**

| Folder Path | Purpose |
|-------------|---------|
| (root) | Repository structure; top-level files and folders |
| `pkg/` | Core Go package tree |
| `pkg/engine/` | Engine orchestration, scan entry points, tests |
| `pkg/engine/defaults/` | Default detector registry |
| `pkg/config/` | Configuration parsing |
| `pkg/decoders/` | Decoder pipeline |
| `pkg/feature/` | Feature flag definitions |
| `pkg/detectors/` | Detector interfaces and endpoint customization |
| `pkg/handlers/` | File handler routing (APK, archive, etc.) |
| `docs/` | Existing architecture documentation |
| `examples/` | Custom detector examples |

### 0.11.2 Attachments

No attachments were provided by the user. No Figma screens were referenced.

### 0.11.3 Key Findings Summary

The analysis identified **five primary divergence points** between the CLI and API code paths that collectively explain why the CLI reports more findings than a minimal API-based Go program:

| # | Divergence Point | CLI Behavior | Minimal API Default | Impact on Finding Count |
|---|-----------------|--------------|---------------------|------------------------|
| 1 | `feature.EnableAPKHandler` | Set to `true` (`main.go:458`) | `false` (zero-value of `atomic.Bool`) | CLI processes APK files, extracting additional chunks for scanning; API skips them |
| 2 | `Config.Detectors` population | Explicitly set to `defaults.DefaultDetectors()` with `EndpointCustomizer` init (`main.go:519`) | If omitted, `setDefaults()` calls `DefaultDetectors()` — same list. If partially provided, subset is used | If API caller provides its own partial list, fewer detectors run |
| 3 | `IncludeDetectors` flag | Defaults to `"all"` (`main.go:81`) | Empty string `""` if not set | Empty string means no include filter is applied (all detectors pass through); `"all"` also means all detectors pass through. Net effect is identical unless combined with manual detector list differences |
| 4 | `EndpointCustomizer` initialization | `DefaultDetectors()` enables `UseFoundEndpoints(true)` and `UseCloudEndpoint(true)` for GitHub, GitLab, Datadog, Artifactory, Sumo Logic detectors | Same if `DefaultDetectors()` is called; different if detectors are manually constructed | If API caller constructs detectors without calling `DefaultDetectors()`, those detectors won't verify against cloud endpoints, potentially missing verified findings |
| 5 | `SourceManager` configuration | CLI creates `SourceManager` with `WithSourceUnits()`, `WithConcurrentSources(N)`, `WithConcurrentUnits(N)`, `WithBufferedOutput(64)` (`main.go:673–686`) | API caller must create its own `SourceManager` or `NewEngine` returns an error (`engine.go:248–249`) | Missing `WithSourceUnits()` could affect how sources are decomposed into scannable units |


