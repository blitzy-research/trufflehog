# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Feature Objective

Based on the prompt, the Blitzy platform understands that the new feature requirement is to **produce a comprehensive investigation document** explaining why TruffleHog's CLI filesystem scan reports more secret findings than an equivalent scan launched through the Go engine API on the same test directory. Specifically:

- **Primary goal:** Trace both the CLI code path (`main.go` → `engine.NewEngine` → `eng.ScanFileSystem`) and the minimal-API code path (`engine.NewEngine` directly) to identify every configuration difference that affects finding counts at runtime.
- **Deliverable:** A single Markdown document named `trufflehog_e42153d44a5e.md` placed in `blitzy/documentation/` in the destination repository.
- **Key analysis target:** Identify the component that determines which detectors participate in a scan, how their configuration is derived, and what conditions, configuration values, environment variables, or defaults cause the CLI and the API to produce different detector sets or behavior.
- **Implicit requirement — evidence-based conclusions:** Every root cause cited must be traceable to specific lines of Go source code in the repository at commit `e42153d4`.
- **Implicit requirement — no repository mutation:** No existing source files may be modified. If any temporary helper code or configuration is created during debugging, it must be removed before completion so the repository is left in its original state.
- **Implicit requirement — static analysis only:** The investigation relies on source code reading and structural understanding rather than runtime instrumentation, since the goal is to explain *why* the divergence occurs at the code level.

### 0.1.2 Special Instructions and Constraints

- **Read-only constraint (critical):** "Do not modify any existing source files in the repository. If you create temporary helper code or configuration for debugging, ensure it is removed before you finish so the repo is left in its original state." — User Prompt
- **Documentation-only output:** Per the project's implementation rule (`SWE-AtlasQnA-Repo`): "Create a new markdown document named `<source_branch_name>.md` that comprehensively answers the question(s) posed in the prompt. Do not modify any existing files in the source repository. Do not add any other code in the source repository (besides the above requested document). Place the generated document in the `blitzy/documentation` directory in the destination repo."
- **Architectural requirement:** The document must follow the repository's existing conventions — Go module at `github.com/trufflesecurity/trufflehog/v3`, Go 1.23.1 with toolchain go1.24.2, AGPL-3.0 license.
- **Scope of analysis:** The investigation is bounded to the filesystem scan path; other source types (Git, GitHub, S3, etc.) are referenced only where they share infrastructure with the filesystem scan.

### 0.1.3 Technical Interpretation

These feature requirements translate to the following technical implementation strategy:

- To **explain the finding-count discrepancy**, we will trace the complete initialization sequence in `main.go` (lines 450–540) and compare it against the engine's `setDefaults()` in `pkg/engine/engine.go` (lines 336–374), documenting every parameter where the CLI sets a value that the engine does not default to.
- To **identify the detector participation component**, we will map the four-layer filtering chain: `defaults.DefaultDetectors()` → `Config.Detectors` → `buildDetectorSets` (include/exclude) → `applyFilters` → final detector set fed to `AhoCorasickCore`.
- To **document conditions causing divergence**, we will catalog every feature flag (`pkg/feature/feature.go`), engine config field (`pkg/engine/engine.go:97–155`), and `SourceManager` option (`pkg/sources/source_manager.go:62–100`) that behaves differently between the CLI and API code paths.
- To **produce the deliverable**, we will create `blitzy/documentation/trufflehog_e42153d44a5e.md` containing an executive summary, architecture overview, root cause analysis with code-line evidence, a detailed comparison table, and API-parity recommendations.

## 0.2 Repository Scope Discovery

### 0.2.1 Comprehensive File Analysis

The TruffleHog v3 repository (`github.com/trufflesecurity/trufflehog/v3`) is a large Go project with 845+ detector subfolders. The following files and directories were identified as directly relevant to the CLI-vs-API finding-count investigation:

**CLI Entry Point and Configuration:**

| File | Purpose | Key Lines |
|------|---------|-----------|
| `main.go` | Full CLI entry point — all flag definitions, feature flag setup, `engConf` construction, `runSingleScan` orchestration | 458 (APK flag), 513–533 (engine config), 673–678 (SourceManager) |
| `pkg/config/config.go` | `Config` struct for custom detectors loaded from YAML | Full file — `protoyaml.UnmarshalStrict` parsing |
| `pkg/config/detectors.go` | `ParseDetectors()` — comma-separated selectors with "all" expansion, range support, name resolution | Lines 1–120 |

**Engine Core (Initialization, Defaults, Filtering, Worker Pipeline):**

| File | Purpose | Key Lines |
|------|---------|-----------|
| `pkg/engine/engine.go` | `Config` struct, `NewEngine`, `setDefaults`, `buildDetectorSets`, `filterDetectors`, `applyFilters`, `initialize`, `Start`, worker pipeline, `notifierWorker` | 97–155 (Config), 226–328 (NewEngine), 336–374 (setDefaults), 489–534 (initialize), 1188–1237 (notifier) |
| `pkg/engine/filesystem.go` | `ScanFileSystem` — thin wrapper that creates a `sourcespb.Filesystem` protobuf and dispatches to the filesystem source | Full file |
| `pkg/engine/defaults/defaults.go` | `buildDetectorList()` (~860 detectors), `DefaultDetectors()` with endpoint customizer configuration | 11–1702 (detector list), 1704–1723 (endpoint config) |

**Source and Handler Infrastructure:**

| File | Purpose | Key Lines |
|------|---------|-----------|
| `pkg/sources/filesystem/filesystem.go` | Filesystem source — `Chunks`, `scanDir`, `scanFile`, `Enumerate`, `ChunkUnit` | 43 (interface impl), 95–159 (legacy path), 199–290 (unit path) |
| `pkg/sources/source_manager.go` | `SourceManager` — `WithSourceUnits()`, `WithBufferedOutput()`, `runWithUnits` vs `runWithoutUnits` | 62–100 (options), 361–365 (branch logic) |
| `pkg/handlers/handlers.go` | `HandleFile` — file processing entry, MIME detection, APK gate, archive identification | 139 (APK check), 344 (HandleFile entry), 536–538 (shouldHandleAsAPK) |
| `pkg/handlers/apk.go` | APK-specific handler — decomposition, keyword extraction using `defaults.DefaultDetectors()` | Full file |

**Feature Flags and Detector Infrastructure:**

| File | Purpose | Key Lines |
|------|---------|-----------|
| `pkg/feature/feature.go` | 4 global `atomic.Bool` feature flags + `AtomicString` | Full file |
| `pkg/detectors/detectors.go` | `Detector` interface (`FromData`, `Keywords`, `Type`), optional interfaces (`Versioner`, `EndpointCustomizer`, etc.) | Lines 1–80 |
| `pkg/detectors/endpoint_customizer.go` | `EndpointSetter` embed struct — `Endpoints()` merges configured/cloud/found endpoints | Full file |
| `pkg/decoders/decoders.go` | `DefaultDecoders()` — UTF8, Base64, UTF16, EscapedUnicode | Full file |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `AhoCorasickCore` — trie construction, `DetectorKey`, span calculation (default ±512 bytes) | 155–160 (default span) |

**Existing API-Usage Reference:**

| File | Purpose |
|------|---------|
| `hack/snifftest/main.go` | Only existing program using the scanning API — uses `defaults.DefaultDetectors()` directly, does NOT use `engine.NewEngine` | 

**Integration Point Discovery:**

- **API endpoint connection to the feature:** The filesystem scan is initiated via `eng.ScanFileSystem()` in `pkg/engine/filesystem.go`, which creates a `filesystem.Source` and calls `sourceManager.EnumerateAndScan()`.
- **Database models/migrations:** Not applicable — TruffleHog has no persistent database; all findings are emitted as streaming results.
- **Service classes requiring updates:** None — this is a read-only investigation producing only a documentation artifact.
- **Controllers/handlers to modify:** None — no code modifications are in scope.
- **Middleware/interceptors impacted:** The `pkg/handlers/` package is a key analysis target but is not being modified.

### 0.2.2 Web Search Research Conducted

No external web searches were required for this investigation. All conclusions are derived from static source code analysis at commit `e42153d4`. The TruffleHog codebase is self-documenting through its Go source, and the investigation's scope is entirely internal to the repository.

### 0.2.3 New File Requirements

**New source files to create:**

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | Investigation document — comprehensive analysis of CLI vs API finding-count discrepancy with root cause analysis, code-path comparison, and API-parity recommendations |

**No new test files, configuration files, or infrastructure changes are required.** The deliverable is a single Markdown document per the `SWE-AtlasQnA-Repo` implementation rule.

## 0.3 Dependency Inventory

### 0.3.1 Private and Public Packages

The following packages from the TruffleHog repository are directly relevant to understanding the CLI-vs-API scan path divergence. No dependency changes are required — this inventory catalogs the key internal packages analyzed during the investigation.

| Registry | Package | Version | Purpose |
|----------|---------|---------|---------|
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/engine` | v3 (at `e42153d4`) | Core scanning engine — `Config`, `NewEngine`, `setDefaults`, worker pipeline |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults` | v3 (at `e42153d4`) | Default detector registry — `DefaultDetectors()`, `buildDetectorList()` |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick` | v3 (at `e42153d4`) | Aho-Corasick trie for keyword matching — `AhoCorasickCore`, span calculators |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/sources` | v3 (at `e42153d4`) | Source management — `SourceManager`, `WithSourceUnits()`, `EnumerateAndScan` |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem` | v3 (at `e42153d4`) | Filesystem source — `Chunks`, `Enumerate`, `ChunkUnit`, `scanDir`, `scanFile` |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/handlers` | v3 (at `e42153d4`) | File handlers — `HandleFile`, `shouldHandleAsAPK`, MIME detection |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/feature` | v3 (at `e42153d4`) | Feature flags — `EnableAPKHandler`, `ForceSkipBinaries`, etc. |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/detectors` | v3 (at `e42153d4`) | Detector interfaces — `Detector`, `EndpointCustomizer`, `Versioner` |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/decoders` | v3 (at `e42153d4`) | Default decoders — UTF8, Base64, UTF16, EscapedUnicode |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/config` | v3 (at `e42153d4`) | Config parsing — `ParseDetectors`, `DetectorID`, YAML custom detector loading |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/output` | v3 (at `e42153d4`) | Output printers — `PlainPrinter`, `JSONPrinter`, `LegacyJSONPrinter` |
| Go module (internal) | `github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache/simple` | v3 (at `e42153d4`) | Simple verification result cache |
| Go module (external) | `github.com/alecthomas/kingpin/v2` | v2 (per `go.mod`) | CLI flag parsing framework used by `main.go` |

**Key external dependencies from `go.mod`:**

| Package | Version | Relevance |
|---------|---------|-----------|
| `go` | 1.23.1 | Go language version |
| `toolchain` | go1.24.2 | Build toolchain version |

### 0.3.2 Dependency Updates

No dependency updates are required. This investigation produces only a Markdown documentation file and does not modify any Go source, build configuration, or dependency manifest.

**Import transformation rules:** Not applicable — no source files are being created or modified that require imports.

**External reference updates:** Not applicable — no configuration, documentation (beyond the deliverable), build, or CI/CD files require changes.

## 0.4 Integration Analysis

### 0.4.1 Existing Code Touchpoints

Since this task produces only a documentation artifact and does not modify any source files, the integration analysis focuses on the **code-path touchpoints that were analyzed** to derive the investigation's conclusions. These represent the critical junctions where CLI and API behavior diverges.

**Touchpoint 1 — Feature Flag Initialization (`main.go:454–458`)**

The CLI sets four process-global atomic boolean flags before engine construction:

- `feature.ForceSkipBinaries.Store(*scanBinaryFiles)` — line 454
- `feature.ForceSkipArchives.Store(*scanArchives)` — line 455
- `feature.SkipAdditionalRefs.Store(*gitScanSkipAdditionalRefs)` — line 456
- `feature.EnableAPKHandler.Store(true)` — line 458 (hardcoded to `true`)

These flags live in `pkg/feature/feature.go` as package-level `atomic.Bool` variables. The engine (`pkg/engine/`) never reads or writes them. They are consumed downstream by `pkg/handlers/handlers.go` (APK gate at line 537) and `pkg/sources/` (binary/archive skip logic). An API caller that omits these stores gets the Go zero-value `false` for all four.

**Touchpoint 2 — Engine Config Assembly (`main.go:513–533`)**

The `engConf` struct literal is the single integration point between the CLI and the engine:

- `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` — always explicit, never nil
- `Verify: !*noVerification` — defaults to `true`
- `IncludeDetectors: *includeDetectors` — defaults to `"all"`
- `Dispatcher: engine.NewPrinterDispatcher(printer)` — explicit printer
- `VerificationResultCache: simple.NewCache[...]()` — conditional on `!*noVerificationCache`
- `SourceManager` — constructed separately at lines 673–678 and assigned to `cfg.SourceManager`

**Touchpoint 3 — SourceManager Construction (`main.go:673–678`)**

The `SourceManager` bridges the engine's worker pipeline to source implementations. The CLI constructs it with:

- `sources.WithConcurrentSources(cfg.Concurrency)`
- `sources.WithConcurrentUnits(cfg.Concurrency)`
- `sources.WithSourceUnits()` — enables the unit-based scanning path
- `sources.WithBufferedOutput(64)` — increases the output channel buffer

The engine requires a non-nil `SourceManager` (`engine.go:248–250` returns an error if nil). The choice of `WithSourceUnits()` determines whether the filesystem source uses `Enumerate`+`ChunkUnit` (unit path) or `Chunks` (legacy path) at `source_manager.go:361–362`.

**Touchpoint 4 — Engine Initialization Chain (`pkg/engine/engine.go:226–534`)**

Inside `NewEngine`, the following sequence executes:

1. Field assignment from `Config` (line 226–247)
2. `setDefaults()` — fills missing detectors, decoders, dispatcher, concurrency (lines 336–374)
3. `buildDetectorSets()` — parses include/exclude strings via `config.ParseDetectors` (lines 254–260)
4. Filter construction and `applyFilters()` — include filter, exclude filter, custom verifier endpoint filter (lines 261–306)
5. Result notification override from `cfg.Results` (lines 308–320)
6. `initialize()` — LRU dedup cache (512 entries), buffered channels, Aho-Corasick trie from final detector set (lines 489–534)

**Touchpoint 5 — Filesystem Source Dispatch (`pkg/engine/filesystem.go` → `pkg/sources/filesystem/filesystem.go`)**

`eng.ScanFileSystem()` creates a `sourcespb.Filesystem` protobuf with the scan paths and calls `sourceManager.EnumerateAndScan()`. The filesystem source's `Enumerate` method walks directories and emits source units; `ChunkUnit` processes each file through `handlers.HandleFile`, which is where the `EnableAPKHandler` gate lives.

### 0.4.2 Dependency Injections

No dependency injection changes are required. The investigation identified the following existing DI patterns:

- `engine.Config.SourceManager` — injected by the caller; no default created in `setDefaults`
- `engine.Config.Dispatcher` — injected by the caller; defaults to `PlainPrinter` in `setDefaults`
- `engine.Config.VerificationResultCache` — injected by the caller; defaults to `nil` (no cache)

### 0.4.3 Database/Schema Updates

Not applicable. TruffleHog v3 has no persistent database. All scan results are streaming — emitted through channels and dispatched via the `ResultsDispatcher` interface. The only stateful component is the in-memory LRU deduplication cache (512 entries, created in `engine.initialize()` at line 516).

## 0.5 Technical Implementation

### 0.5.1 File-by-File Execution Plan

This task produces a single documentation artifact. No existing files are modified. The execution plan consists of analysis actions that produce the deliverable document.

**Group 1 — Deliverable:**

| Action | File | Purpose |
|--------|------|---------|
| CREATE | `blitzy/documentation/trufflehog_e42153d44a5e.md` | Investigation document — CLI vs API finding-count discrepancy analysis |

**Group 2 — Source Files Analyzed (Read-Only):**

| File | Analysis Action |
|------|-----------------|
| `main.go` | Trace CLI initialization: feature flags (line 458), engine config (lines 513–533), SourceManager (lines 673–678), filesystem scan dispatch (lines 774–787) |
| `pkg/engine/engine.go` | Trace engine initialization: `NewEngine` (lines 226–328), `setDefaults` (lines 336–374), `buildDetectorSets` (lines 254–260), `initialize` (lines 489–534), `notifierWorker` (lines 1188–1237) |
| `pkg/engine/defaults/defaults.go` | Analyze detector registry: `buildDetectorList()` (lines 11–1702), `DefaultDetectors()` endpoint customizer loop (lines 1704–1723) |
| `pkg/engine/filesystem.go` | Verify filesystem scan entry point: `ScanFileSystem` creates source, calls `sourceManager.EnumerateAndScan` |
| `pkg/sources/filesystem/filesystem.go` | Compare scanning paths: `Chunks`/`scanDir` (legacy, lines 95–159) vs `Enumerate`/`ChunkUnit` (unit-based, lines 199–290) |
| `pkg/sources/source_manager.go` | Analyze `WithSourceUnits()` branching at line 361: `runWithUnits` vs `runWithoutUnits` |
| `pkg/handlers/handlers.go` | Verify APK handler gate: `shouldHandleAsAPK` (lines 536–538) depends on `feature.EnableAPKHandler.Load()` |
| `pkg/feature/feature.go` | Catalog feature flags: 4 `atomic.Bool` — all default `false` |
| `pkg/detectors/endpoint_customizer.go` | Understand `EndpointSetter.Endpoints()` — merges configured, cloud, and found endpoints |
| `pkg/decoders/decoders.go` | Confirm `DefaultDecoders()` returns UTF8, Base64, UTF16, EscapedUnicode |
| `pkg/config/detectors.go` | Verify `ParseDetectors("")` returns empty set (no filter) vs `ParseDetectors("all")` returns full set |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Confirm default span calculator: `adjustableSpanCalculator` with ±512 byte radius |
| `hack/snifftest/main.go` | Reference existing API-based program — uses `DefaultDetectors()`, bypasses `engine` package entirely |

### 0.5.2 Implementation Approach

The implementation follows a structured analysis methodology:

- **Establish the CLI baseline** by reading `main.go` in its entirety to catalog every configuration step that occurs before `engine.NewEngine` is called. This includes feature flag stores, config file parsing, engine config struct assembly, and SourceManager construction.
- **Map the engine's defaults** by reading `pkg/engine/engine.go`'s `setDefaults()` to understand exactly which gaps the engine fills when an API caller provides a minimal config.
- **Diff the two configuration sets** parameter by parameter, creating a comprehensive comparison table that marks each parameter as matching or divergent between CLI and API paths.
- **Trace each divergence downstream** to its effect on finding counts, verification status, or file processing to determine whether it is a root cause of the observed discrepancy.
- **Synthesize findings** into a structured Markdown document with executive summary, architecture overview, numbered root causes with code-line evidence, detailed comparison table, detector participation explanation, and API-parity recommendations.
- **Validate the deliverable** by confirming all code references are accurate, the document is well-formatted Markdown, and the repository is left in its original state (only `blitzy/documentation/trufflehog_e42153d44a5e.md` added).

### 0.5.3 Root Causes Identified

The investigation identified seven root causes, ranked by impact:

| # | Root Cause | Severity | Evidence Location |
|---|-----------|----------|-------------------|
| 1 | `feature.EnableAPKHandler` set to `true` only by CLI | **High** — APK files silently skipped by API | `main.go:458`, `pkg/handlers/handlers.go:536–538` |
| 2 | Detector endpoint customization only via `DefaultDetectors()` | **Medium** — affects API callers who construct detectors manually | `pkg/engine/defaults/defaults.go:1704–1723` |
| 3 | `SourceManager` options (`WithSourceUnits()`, `WithBufferedOutput(64)`) | **Low-Medium** — affects file enumeration path and throughput | `main.go:673–678`, `pkg/sources/source_manager.go:361–365` |
| 4 | `VerificationResultCache` not created by engine defaults | **Low** — affects verification under rate-limit conditions | `main.go:535–537` |
| 5 | `Config.Detectors` bypass of `setDefaults` when non-empty | **Conditional** — only if API caller provides partial list | `pkg/engine/engine.go:362–364` |
| 6 | `Config.Verify` defaults to `false` (Go zero-value) vs CLI `true` | **Low** — affects verification status, not finding count | `main.go:521` vs Go zero-value |
| 7 | Other feature flags match defaults | **None** — both CLI and API use `false` | `main.go:454–456`, `pkg/feature/feature.go` |

## 0.6 Scope Boundaries

### 0.6.1 Exhaustively In Scope

**Deliverable file:**

- `blitzy/documentation/trufflehog_e42153d44a5e.md` — the complete investigation document

**Analysis targets (read-only, not modified):**

- CLI entry point: `main.go` (all 1030 lines — flag definitions, feature flag stores, engine config, scan dispatch)
- Engine core: `pkg/engine/engine.go` (Config struct, NewEngine, setDefaults, buildDetectorSets, applyFilters, initialize, Start, worker pipeline, notifierWorker)
- Engine filesystem bridge: `pkg/engine/filesystem.go`
- Default detector registry: `pkg/engine/defaults/defaults.go` (~1734 lines — buildDetectorList, DefaultDetectors endpoint config)
- Aho-Corasick core: `pkg/engine/ahocorasick/ahocorasickcore.go` (span calculators, DetectorKey)
- Filesystem source: `pkg/sources/filesystem/filesystem.go` (Chunks, scanDir, scanFile, Enumerate, ChunkUnit)
- Source manager: `pkg/sources/source_manager.go` (WithSourceUnits, WithBufferedOutput, runWithUnits vs runWithoutUnits)
- File handlers: `pkg/handlers/handlers.go` (HandleFile, shouldHandleAsAPK, MIME detection)
- APK handler: `pkg/handlers/apk.go` (APK decomposition, keyword extraction)
- Feature flags: `pkg/feature/feature.go` (EnableAPKHandler, ForceSkipBinaries, ForceSkipArchives, SkipAdditionalRefs)
- Detector interfaces: `pkg/detectors/detectors.go` (Detector, EndpointCustomizer, Versioner)
- Endpoint customizer: `pkg/detectors/endpoint_customizer.go` (EndpointSetter, Endpoints method)
- Decoders: `pkg/decoders/decoders.go` (DefaultDecoders)
- Config parsing: `pkg/config/detectors.go` (ParseDetectors, DetectorID)
- Config struct: `pkg/config/config.go` (YAML custom detector loading)
- Existing API reference: `hack/snifftest/main.go`
- Output printers: `pkg/output/` directory (PlainPrinter, JSONPrinter)
- Dependency manifest: `go.mod` (Go version, toolchain version)

### 0.6.2 Explicitly Out of Scope

- **Modifying any existing source files** — per explicit user instruction and `SWE-AtlasQnA-Repo` rule
- **Creating temporary helper programs or test scripts** — not needed; analysis is purely static
- **Non-filesystem scan paths** — Git, GitHub, GitLab, S3, Docker, Postman, Jira, Confluence, etc. source types are not analyzed beyond shared infrastructure
- **Detector implementation internals** — individual detector `FromData` logic across 845+ detectors is not examined; only the registration and filtering mechanisms
- **Performance optimization** — throughput differences between CLI and API are noted but not benchmarked
- **Refactoring suggestions** — the document explains the discrepancy but does not propose engine API changes
- **CI/CD pipeline changes** — no build or deployment modifications
- **Enterprise-only features** — TruffleHog Enterprise extensions are not analyzed
- **Runtime instrumentation or debugging** — no execution of scan code against test data; all conclusions derived from source code reading

## 0.7 Rules for Feature Addition

The following rules are explicitly emphasized by the user and govern the execution of this task:

- **No modification of existing source files:** "Do not modify any existing source files in the repository." The repository must remain at its original state (commit `e42153d4`) with zero diffs to tracked files. Only the new `blitzy/documentation/trufflehog_e42153d44a5e.md` document may be added.
- **Cleanup of temporary artifacts:** "If you create temporary helper code or configuration for debugging, ensure it is removed before you finish so the repo is left in its original state." Any ephemeral files created during investigation must be deleted before completion.
- **Documentation-only output (SWE-AtlasQnA-Repo rule):** "Create a new markdown document named `<source_branch_name>.md` that comprehensively answers the question(s) posed in the prompt. Do not modify any existing files in the source repository. Do not add any other code in the source repository (besides the above requested document). Place the generated document in the `blitzy/documentation` directory in the destination repo."
- **Evidence-based analysis:** All conclusions about the CLI-vs-API discrepancy must be traceable to specific file paths and line numbers in the codebase. No assumptions or speculation without source-code evidence.
- **Comprehensive coverage:** The investigation must identify *all* conditions, configuration values, environment variables, or defaults that lead to the CLI and the API producing different detector sets or behavior at runtime — not just the most obvious ones.
- **Thinking and rationale:** The document must provide the reasoning behind each conclusion, not merely state findings.

## 0.8 References

### 0.8.1 Files and Folders Searched

The following files were read in full or in targeted ranges during the codebase investigation:

| File Path | Search Purpose |
|-----------|---------------|
| `go.mod` | Identify Go version (1.23.1), toolchain (go1.24.2), module path |
| `main.go` | Full CLI entry point — flag definitions, feature flag setup, engine config, SourceManager, scan dispatch |
| `pkg/engine/engine.go` | Engine core — Config struct, NewEngine, setDefaults, buildDetectorSets, applyFilters, initialize, Start, notifierWorker |
| `pkg/engine/defaults/defaults.go` | Default detector registry — buildDetectorList (~860 detectors), DefaultDetectors endpoint customizer loop |
| `pkg/engine/filesystem.go` | Filesystem scan entry point — ScanFileSystem wrapper |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Aho-Corasick trie — span calculators, DetectorKey structure |
| `pkg/sources/filesystem/filesystem.go` | Filesystem source — Chunks, scanDir, scanFile, Enumerate, ChunkUnit |
| `pkg/sources/source_manager.go` | SourceManager — WithSourceUnits, WithBufferedOutput, runWithUnits vs runWithoutUnits |
| `pkg/handlers/handlers.go` | File handlers — HandleFile, shouldHandleAsAPK, MIME detection, archive identification |
| `pkg/handlers/apk.go` | APK handler — decomposition logic, keyword extraction via DefaultDetectors |
| `pkg/feature/feature.go` | Feature flags — EnableAPKHandler, ForceSkipBinaries, ForceSkipArchives, SkipAdditionalRefs |
| `pkg/detectors/detectors.go` | Detector interface — FromData, Keywords, Type, optional interfaces |
| `pkg/detectors/endpoint_customizer.go` | EndpointSetter — Endpoints method, UseFoundEndpoints, UseCloudEndpoint |
| `pkg/decoders/decoders.go` | Default decoders — UTF8, Base64, UTF16, EscapedUnicode |
| `pkg/config/config.go` | Config struct — YAML parsing for custom detectors |
| `pkg/config/detectors.go` | ParseDetectors — comma-separated selectors, "all" expansion, range support |
| `hack/snifftest/main.go` | Existing API-based program reference — uses DefaultDetectors directly |

The following directories were explored for structure:

| Directory Path | Exploration Purpose |
|---------------|---------------------|
| Repository root (`/`) | Overall project structure — Go module, CLI, packages |
| `pkg/engine/` | Engine package — core, defaults, filesystem, ahocorasick subpackages |
| `pkg/engine/defaults/` | Default detector registry location |
| `pkg/detectors/` | Detector implementations — 845+ subfolders identified |
| `pkg/sources/filesystem/` | Filesystem source implementation |
| `pkg/sources/` | Source abstractions — SourceManager, interfaces |
| `pkg/handlers/` | File handler implementations |
| `pkg/feature/` | Feature flag definitions |
| `pkg/decoders/` | Decoder implementations |
| `pkg/config/` | Configuration parsing |

### 0.8.2 Attachments

No attachments were provided with this project. No Figma URLs, design files, or external documents were referenced.

### 0.8.3 Tech Spec Sections Referenced

| Section | Purpose |
|---------|---------|
| 1.1 EXECUTIVE SUMMARY | Context on TruffleHog v3's architecture, purpose, and capabilities |
| 5.2 COMPONENT DETAILS | Engine pipeline architecture (Scanner → Decoder → Aho-Corasick → Overlap → Detector → Notifier) |

### 0.8.4 Deliverable Location

The investigation document was created at:

```
blitzy/documentation/trufflehog_e42153d44a5e.md
```

This follows the `SWE-AtlasQnA-Repo` naming convention using the source branch name `trufflehog_e42153d44a5e` and is placed in the `blitzy/documentation` directory as specified.

