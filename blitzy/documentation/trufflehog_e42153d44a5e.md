# TruffleHog CLI vs. Go Engine API: Filesystem Scan Finding-Count Discrepancy Investigation

| Field              | Value                                              |
|--------------------|----------------------------------------------------|
| **Commit**         | `e42153d4`                                         |
| **Go Module**      | `github.com/trufflesecurity/trufflehog/v3`         |
| **Go Version**     | 1.23.1                                             |
| **Toolchain**      | go1.24.2                                           |
| **License**        | AGPL-3.0                                           |
| **Investigation**  | Static source-code analysis only (no runtime data) |

---

## 1. Executive Summary

When the TruffleHog CLI executes a filesystem scan (`trufflehog filesystem <path>`) and a minimal Go program performs the equivalent scan through the engine API (`engine.NewEngine` followed by `eng.ScanFileSystem`), the two scans on the **same directory** produce **different finding counts**. The CLI consistently reports **more** findings than the API.

This discrepancy is **not a bug in the scanning engine**. It is a consequence of the CLI performing several additional configuration steps — feature-flag stores, `SourceManager` option selection, verification cache construction — that the engine's internal `setDefaults()` method (at `pkg/engine/engine.go:336-374`) does not replicate. The engine is deliberately designed for flexibility: it provides sensible defaults for fields it controls (decoders, detectors, dispatcher, concurrency, worker multipliers, result notification) but leaves process-global state and caller-constructed objects to the caller.

This investigation identifies **seven root causes**, ranked by impact on finding counts. The highest-impact root cause is that the CLI unconditionally enables APK file handling by storing `true` into the process-global `feature.EnableAPKHandler` atomic boolean at `main.go:458`. An API caller that omits this store inherits the Go zero-value `false`, causing **all `.apk` files to be silently skipped** — no decomposition, no keyword extraction, no secret detection from APK contents. The remaining root causes range from detector endpoint customization (medium impact on verification accuracy) to `SourceManager` construction differences (low-medium impact on file enumeration path) to verification cache absence (low impact on verification status under rate limits).

---

## 2. Architecture Overview

### 2.1 Scanning Pipeline Stages

TruffleHog v3's scanning pipeline consists of seven sequential stages. Understanding each stage is essential because the CLI-vs-API divergence can affect behavior at multiple points.

**Stage 1 — Source Dispatch**

`ScanFileSystem` at `pkg/engine/filesystem.go:16-37` creates a `sourcespb.Filesystem` protobuf containing the scan paths (lines 17-21), marshals it via `anypb.MarshalFrom` (line 23), initializes a `filesystem.Source` (line 33), and dispatches the scan through `sourceManager.EnumerateAndScan` (line 36).

**Stage 2 — SourceManager Routing**

The `SourceManager` at `pkg/sources/source_manager.go:360-371` decides between two scanning strategies:

- **Unit-based path** (`runWithUnits`): When `WithSourceUnits()` was provided during construction, `useSourceUnitsFunc` is non-nil. The source's `Enumerate` method walks directories and emits individual file paths as source units; `ChunkUnit` processes each file independently. This is the path the CLI takes.
- **Legacy path** (`runWithoutUnits`): When `useSourceUnitsFunc` is `nil`, the manager falls back to calling the source's `Chunks` method directly. This is the path a bare API caller takes unless they explicitly provide `WithSourceUnits()`.

The branching logic at line 361-362:
```go
canUseSourceUnits := len(targets) == 0 && s.useSourceUnitsFunc != nil
if enumChunker, ok := source.(SourceUnitEnumChunker); ok && canUseSourceUnits && s.useSourceUnitsFunc() {
    return s.runWithUnits(ctx, enumChunker, report)
}
```

The filesystem source declares `SourceUnitEnumChunker` compliance at `pkg/sources/filesystem/filesystem.go:43`:
```go
var _ sources.SourceUnitEnumChunker = (*Source)(nil)
```

**Stage 3 — File Handlers**

`HandleFile` in `pkg/handlers/handlers.go` processes each file chunk. At line 139, the APK gate is the first specialized check:
```go
if shouldHandleAsAPK(cfg, fReader) {
```
This gate reads the process-global `feature.EnableAPKHandler` flag (line 537). If the flag is `false`, APK files fall through to the generic archive identification path or are returned as raw bytes.

**Stage 4 — Decoders**

`DefaultDecoders()` at `pkg/decoders/decoders.go:8-16` returns four decoders:
1. `UTF8` (must be first for duplicate detection)
2. `Base64`
3. `UTF16`
4. `EscapedUnicode`

Both CLI and API use the same decoder set (populated by `setDefaults` at `engine.go:357-359` when none are provided).

**Stage 5 — Aho-Corasick Keyword Matching**

`AhoCorasickCore` at `pkg/engine/ahocorasick/ahocorasickcore.go:155-161` builds a trie from all detector keywords. The default span calculator uses a ±512-byte radius around each keyword match:
```go
const defaultOffsetRadius int64 = 512
// ...
spanCalculator: newAdjustableSpanCalculator(defaultOffsetRadius),
```

**Stage 6 — Detectors**

Approximately 860 detectors are registered by `defaults.DefaultDetectors()` at `pkg/engine/defaults/defaults.go:1704-1723`. Each implements the `Detector` interface (`pkg/detectors/detectors.go:19-29`): `FromData` for secret extraction, `Keywords` for Aho-Corasick trie construction, `Type` for identification, and `Description` for result metadata.

**Stage 7 — Notifier**

The `notifierWorker` at `pkg/engine/engine.go:1189-1235` filters results based on three flags: `notifyVerifiedResults`, `notifyUnverifiedResults`, and `notifyUnknownResults`. It deduplicates findings via an LRU cache of 512 entries (initialized at `engine.go:491-496`) and dispatches surviving results through the `ResultsDispatcher`.

### 2.2 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CLI (main.go)                                                          │
│  ┌──────────────────┐  ┌────────────────────┐  ┌─────────────────────┐ │
│  │ Feature Flags     │  │ Config Assembly     │  │ SourceManager       │ │
│  │ (lines 441-458)   │  │ (lines 513-533)     │  │ (lines 673-686)    │ │
│  └────────┬─────────┘  └─────────┬──────────┘  └──────────┬──────────┘ │
└───────────┼──────────────────────┼─────────────────────────┼────────────┘
            │                      │                         │
            ▼                      ▼                         ▼
┌───────────────────────────────────────────────────────────────────┐
│  engine.NewEngine (engine.go:226-328)                             │
│  ┌──────────┐  ┌────────────────┐  ┌────────────┐  ┌───────────┐│
│  │setDefaults│→│buildDetectorSets│→│applyFilters │→│initialize  ││
│  │(line 252) │ │(line 255)       │ │(line 305)   │ │(line 323)  ││
│  └──────────┘  └────────────────┘  └────────────┘  └───────────┘│
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
┌───────────────────────────────────────────────────────────────────┐
│  eng.Start → ScanFileSystem (filesystem.go:16-37)                 │
│  → SourceManager.EnumerateAndScan                                 │
│    → filesystem.Source (Enumerate + ChunkUnit  OR  Chunks)        │
│      → handlers.HandleFile (APK gate at line 139)                 │
│        → Decoders → AhoCorasick → Detectors → notifierWorker     │
│          → Dispatcher                                             │
└───────────────────────────────────────────────────────────────────┘
```

---

## 3. Root Cause Analysis

Seven root causes were identified, ranked from highest to lowest impact on finding counts.

### Root Cause 1 — `feature.EnableAPKHandler` Not Set by Engine (HIGH Severity)

**What the CLI does:**

At `main.go:458`, the CLI unconditionally stores `true` into the process-global atomic boolean:
```go
// OSS Default APK handling on
feature.EnableAPKHandler.Store(true)
```

This flag is defined at `pkg/feature/feature.go:9`:
```go
EnableAPKHandler   atomic.Bool
```

The comment on line 457 ("OSS Default APK handling on") confirms this is intentional for all open-source CLI scans.

**What the API defaults to:**

An API caller that does not explicitly call `feature.EnableAPKHandler.Store(true)` gets the Go zero-value for `atomic.Bool`, which is `false`. The engine's `setDefaults()` method at `pkg/engine/engine.go:336-374` does **not** touch any feature flags — they are process-global state outside the engine's configuration scope.

**Impact on finding count:**

In `pkg/handlers/handlers.go:536-539`, the `shouldHandleAsAPK` function gates all APK processing:
```go
func shouldHandleAsAPK(cfg readerConfig, fReader fileReader) bool {
	return feature.EnableAPKHandler.Load() &&
		cfg.fileExtension == apkExt &&
		(fReader.mime.String() == string(zipMime) || fReader.mime.String() == string(jarMime))
}
```

When `EnableAPKHandler` is `false`, this function returns `false` for **every** `.apk` file. The file falls through the handler without APK-specific decomposition. No APK manifest parsing, no DEX file analysis, no resource scanning occurs.

The APK handler at `pkg/handlers/apk.go:39-63` builds a keyword matcher using `defaults.DefaultDetectors()` to search within APK manifests, DEX bytecode, and resource files for credential-related keywords. When this handler is disabled, all secrets embedded in APK files are invisible to the scanner.

**Finding count effect:** **DIRECT** — any secrets inside `.apk` files are found by the CLI but completely invisible to an API caller that omits the feature flag store. This is the highest-impact root cause for filesystem scans containing Android application packages.

---

### Root Cause 2 — Detector Endpoint Customization (MEDIUM Severity)

**What the CLI does:**

At `main.go:519`, the CLI passes `defaults.DefaultDetectors()` as the detector list. The `DefaultDetectors()` function at `pkg/engine/defaults/defaults.go:1704-1723` not only returns the ~860-detector list from `buildDetectorList()` but also configures every detector that implements `EndpointCustomizer`:

```go
func DefaultDetectors() []detectors.Detector {
	detectorList := buildDetectorList()

	for _, d := range detectorList {
		customizer, ok := d.(detectors.EndpointCustomizer)
		if !ok {
			continue
		}
		customizer.UseFoundEndpoints(true)
		customizer.UseCloudEndpoint(true)
		if cloudProvider, ok := d.(detectors.CloudProvider); ok {
			customizer.SetCloudEndpoint(cloudProvider.CloudEndpoint())
		}
	}

	return detectorList
}
```

**What the API defaults to:**

If an API caller constructs detectors manually (e.g., instantiating individual scanner structs) rather than calling `defaults.DefaultDetectors()`, the `EndpointSetter` fields remain at their Go zero-values:
- `useFoundEndpoints` = `false`
- `useCloudEndpoint` = `false`
- `cloudEndpoint` = `""`

The `Endpoints()` method at `pkg/detectors/endpoint_customizer.go:43-52` only includes cloud and found endpoints when the respective boolean flags are `true`:
```go
func (e *EndpointSetter) Endpoints(foundEndpoints ...string) []string {
	endpoints := e.configuredEndpoints
	if e.useCloudEndpoint && e.cloudEndpoint != "" {
		endpoints = append(endpoints, e.cloudEndpoint)
	}
	if e.useFoundEndpoints {
		endpoints = append(endpoints, foundEndpoints...)
	}
	return endpoints
}
```

**Mitigation:** If the API caller uses `defaults.DefaultDetectors()` directly (the recommended approach), this root cause is fully eliminated. The engine's `setDefaults()` at `engine.go:362-364` calls `defaults.DefaultDetectors()` when `len(e.detectors) == 0`, so endpoint customization **is** applied for callers who provide zero detectors.

**Finding count effect:** **INDIRECT** — does not change raw detection but affects verification status. Detectors verifying against self-hosted services (e.g., GitLab, Jira, Confluence) may fail verification without the correct endpoints, causing results to be classified as "unverified" instead of "verified". This only affects apparent finding counts when result filtering by verification status is active (e.g., `--results verified`).

---

### Root Cause 3 — SourceManager Construction Options (LOW-MEDIUM Severity)

**What the CLI does:**

At `main.go:672-678`, the CLI constructs the `SourceManager` with four explicit options:
```go
const defaultOutputBufferSize = 64
opts := []func(*sources.SourceManager){
	sources.WithConcurrentSources(cfg.Concurrency),
	sources.WithConcurrentUnits(cfg.Concurrency),
	sources.WithSourceUnits(),
	sources.WithBufferedOutput(defaultOutputBufferSize),
}
```

And assigns it at line 686:
```go
cfg.SourceManager = sources.NewManager(opts...)
```

**What the API must do:**

The engine requires a non-nil `SourceManager` (`pkg/engine/engine.go:248-249`):
```go
if engine.sourceManager == nil {
	return nil, fmt.Errorf("source manager is required")
}
```

An API caller that constructs `sources.NewManager()` without options gets different behavior in three areas:

1. **`WithSourceUnits()` (most significant):** Without this option, `useSourceUnitsFunc` is `nil` in the manager (see `pkg/sources/source_manager.go:83-86`). At `source_manager.go:361`, `canUseSourceUnits` evaluates to `false`, forcing the legacy `Chunks` path (`source_manager.go:371`) instead of the unit-based `Enumerate`+`ChunkUnit` path. While both paths ultimately call the same `scanDir`/`scanFile`/`HandleFile` functions, their error handling differs:
   - **Unit path** (`filesystem.go:242-282`): Reports errors per-unit via `reporter.ChunkErr` (line 279). Error in one unit doesn't affect other units.
   - **Legacy path** (`filesystem.go:85-119`): Logs errors and continues (`logger.Error(err, ...)` at line 113). Error in one path iteration continues to the next.

2. **`WithConcurrentSources`/`WithConcurrentUnits`:** These set semaphore limits. Without them, the `NewManager` constructor at `source_manager.go:107-115` defaults to `runtime.NumCPU()`:
   ```go
   sem:          semaphore.New(runtime.NumCPU()),
   prioritySem:  semaphore.New(runtime.NumCPU()),
   ```
   This matches the CLI's behavior when `cfg.Concurrency` equals `runtime.NumCPU()` (the default at `main.go:58`), so there is no divergence for the default case.

3. **`WithBufferedOutput(64)`:** Sets the output channel buffer size to 64. The default `NewManager` constructor also creates a channel with `defaultChannelSize` which is 64 (`source_manager.go:104,113`). This option is effectively a **no-op** for the default case.

**Finding count effect:** The legacy `Chunks` path and the unit-based path should produce equivalent results for correctly readable files. However, edge cases in error propagation (particularly for files that fail to open or read) could cause one path to skip files that the other processes. This is a **LOW-MEDIUM** impact because the core file processing logic (`scanDir`, `scanFile`, `HandleFile`) is shared between both paths.

---

### Root Cause 4 — VerificationResultCache (LOW Severity)

**What the CLI does:**

At `main.go:535-537`:
```go
if !*noVerificationCache {
	engConf.VerificationResultCache = simple.NewCache[detectors.Result]()
}
```

By default, the `noVerificationCache` flag is `false` (defined at `main.go:85`), so the cache **is** created.

**What the API defaults to:**

`engine.Config.VerificationResultCache` defaults to `nil` (Go zero-value for an interface). The `setDefaults()` method does **not** create a default cache. At `engine.go:227`, `verificationcache.New(nil, nil)` is called, which produces a no-op cache wrapper when the underlying cache is `nil`.

**Impact:**

Without a verification cache, every detection that involves an external verification call (HTTP request to a third-party service) is made independently, even for identical credentials found in multiple locations. Under rate-limiting conditions, later verification attempts may fail (receiving HTTP 429 responses), causing findings to be classified as "unverified" or "unknown" instead of "verified".

**Finding count effect:** **INDIRECT** — does not change whether a finding is detected, only its verification status. This affects apparent finding counts only when filtering by verification status (e.g., `--results verified`).

---

### Root Cause 5 — `Config.Detectors` Bypass of `setDefaults` (CONDITIONAL Severity)

**Mechanism:**

The `setDefaults()` method at `pkg/engine/engine.go:362-364` only populates the detector list when **none** are provided:
```go
if len(e.detectors) == 0 {
	e.detectors = defaults.DefaultDetectors()
}
```

**CLI behavior:**

At `main.go:519`, the CLI always sets a non-empty detector list:
```go
Detectors: append(defaults.DefaultDetectors(), conf.Detectors...),
```

Since `defaults.DefaultDetectors()` returns ~860 detectors, the slice is always non-empty. The `conf.Detectors` field appends any custom detectors from the YAML configuration file (parsed at `main.go:460-467` via `pkg/config/config.go:17-24`).

**API risk:**

If an API caller provides a **partial** list of detectors (e.g., only 10 specific ones), `setDefaults` will **not** supplement them with the remaining ~850 defaults. The engine uses exactly what was provided. This is by design — the engine respects explicit configuration — but may surprise callers who expect partial lists to be merged with defaults.

**Finding count effect:** **CONDITIONAL** — only relevant if the API caller explicitly provides a non-empty but incomplete detector list. If the API caller provides zero detectors (relying on `setDefaults`) or uses `defaults.DefaultDetectors()`, this root cause does not apply.

---

### Root Cause 6 — `Config.Verify` Default Value (LOW Severity)

**What the CLI does:**

At `main.go:520`:
```go
Verify: !*noVerification,
```

The `noVerification` flag defaults to `false` (defined at `main.go:59`), so `Verify` defaults to `true`.

**What the API defaults to:**

`Config.Verify` is a `bool` that defaults to Go's zero-value `false`. The engine's `setDefaults()` does **not** override this field.

**Impact:**

When `Verify` is `false`, the engine skips all external verification attempts. Findings are still detected — the Aho-Corasick keyword matching and detector `FromData` pipeline runs regardless — but none are verified against external services.

**Finding count effect:** **NONE** on raw detection count. All findings are still reported. However, their `Verified` field will be `false` for all results. The `setDefaults()` at `engine.go:369-371` sets:
```go
e.notifyVerifiedResults = true
e.notifyUnverifiedResults = true
e.notifyUnknownResults = true
```

This means **all** results are notified regardless of verification status by default. The finding count is only affected when the caller explicitly overrides `Config.Results` to filter by verification status.

---

### Root Cause 7 — Other Feature Flags (NO Impact)

**Three conditional feature flags** at `main.go:441-451`:
```go
if *forceSkipBinaries {
	feature.ForceSkipBinaries.Store(true)
}

if *forceSkipArchives {
	feature.ForceSkipArchives.Store(true)
}

if *skipAdditionalRefs {
	feature.SkipAdditionalRefs.Store(true)
}
```

All three are guarded by their corresponding CLI flags, which default to `false` (defined at `main.go:88-90`). The flags are **only stored when explicitly enabled by the user**. Since the `atomic.Bool` zero-value is `false` (at `pkg/feature/feature.go:6-8`), both CLI (with default flags) and API produce the same value.

**`UserAgentSuffix`** at `main.go:453-455`:
```go
if *userAgentSuffix != "" {
	feature.UserAgentSuffix.Store(*userAgentSuffix)
}
```

Only stored when the CLI flag is non-empty. The `AtomicString` zero-value is `""` (at `feature.go:10`). Both paths produce `""` by default.

**Finding count effect:** **NONE** — all four flags match between CLI (with default arguments) and API. No divergence exists.

---

## 4. Detailed Parameter-by-Parameter Comparison

### 4.1 `engine.Config` Fields

The complete `Config` struct is defined at `pkg/engine/engine.go:97-155`. Every field is compared below.

| Parameter | CLI Value | API Default (zero-value) | Engine `setDefaults` Override | Divergent? | Impact |
|-----------|-----------|--------------------------|-------------------------------|------------|--------|
| `Concurrency` | `runtime.NumCPU()` (flag default, `main.go:58`) | `0` | Yes — defaults to `runtime.NumCPU()` (`engine.go:337-341`) | **No** | None |
| `Decoders` | `nil` (not set by CLI) | `nil` | Yes — `DefaultDecoders()` (`engine.go:357-359`) | **No** | None |
| `Detectors` | `defaults.DefaultDetectors() + conf.Detectors` (`main.go:519`) | `nil` | Yes — `DefaultDetectors()` if empty (`engine.go:362-364`) | **No** (if API uses empty slice) / **Conditional** (if partial list) | See Root Cause 5 |
| `DetectorVerificationOverrides` | `nil` | `nil` | No | **No** | None |
| `IncludeDetectors` | `"all"` (flag default, `main.go:81`) | `""` | No | **Functionally No** | `ParseDetectors("")` returns empty; empty include = include all (`engine.go:263`) |
| `ExcludeDetectors` | `""` (flag default) | `""` | No | **No** | None |
| `CustomVerifiersOnly` | `false` | `false` | No | **No** | None |
| `VerifierEndpoints` | `nil` (unless `--verifier` flag) | `nil` | No | **No** | None |
| `Verify` | `true` (`main.go:520`) | `false` | No | **Yes** | See Root Cause 6 |
| `Results` | `nil` (unless `--results` flag) | `nil` | `setDefaults` sets all 3 notify flags to `true` (`engine.go:369-371`) | **No** | None |
| `LogFilteredUnverified` | `false` | `false` | No | **No** | None |
| `FilterEntropy` | `0` (unless `--filter-entropy` flag) | `0` | No | **No** | None |
| `FilterUnverified` | `false` | `false` | No | **No** | None |
| `ShouldScanEntireChunk` | `false` (`main.go:68`) | `false` | No | **No** | None |
| `Dispatcher` | `NewPrinterDispatcher(PlainPrinter)` (`main.go:525`) | `nil` | Yes — `NewPrinterDispatcher(PlainPrinter)` (`engine.go:366-368`) | **No** | None |
| `SourceManager` | Constructed with 4 options (`main.go:673-686`) | Caller-provided (**required**, non-nil) | No — returns error if `nil` (`engine.go:248-249`) | **Yes** | See Root Cause 3 |
| `PrintAvgDetectorTime` | `false` | `false` | No | **No** | None |
| `VerificationOverlap` | `false` | `false` | No | **No** | None |
| `DetectorWorkerMultiplier` | `0` | `0` | Yes — defaults to `8` (`engine.go:343-346`) | **No** | None |
| `NotificationWorkerMultiplier` | `0` | `0` | Yes — defaults to `1` (`engine.go:348-350`) | **No** | None |
| `VerificationOverlapWorkerMultiplier` | `0` | `0` | Yes — defaults to `1` (`engine.go:352-354`) | **No** | None |
| `VerificationResultCache` | `simple.NewCache[detectors.Result]()` (`main.go:535-537`) | `nil` | No | **Yes** | See Root Cause 4 |
| `VerificationCacheMetrics` | `&verificationCacheMetrics{}` (`main.go:511,532`) | `nil` | No | **Yes** (metrics only) | Negligible |

### 4.2 Process-Global Feature Flags

Feature flags are defined at `pkg/feature/feature.go:5-11` and are **outside** the engine's `Config` struct. They affect behavior in handlers, sources, and other packages that read them directly.

| Flag | Type | CLI Value | API Default | Set At | Divergent? | Impact |
|------|------|-----------|-------------|--------|------------|--------|
| `EnableAPKHandler` | `atomic.Bool` | `true` (unconditional, `main.go:458`) | `false` (Go zero-value) | `pkg/feature/feature.go:9` | **YES — HIGH IMPACT** | See Root Cause 1 |
| `ForceSkipBinaries` | `atomic.Bool` | `false` (default, `main.go:441-443`) | `false` (Go zero-value) | `pkg/feature/feature.go:6` | **No** | None |
| `ForceSkipArchives` | `atomic.Bool` | `false` (default, `main.go:445-447`) | `false` (Go zero-value) | `pkg/feature/feature.go:7` | **No** | None |
| `SkipAdditionalRefs` | `atomic.Bool` | `false` (default, `main.go:449-451`) | `false` (Go zero-value) | `pkg/feature/feature.go:8` | **No** | None |
| `UserAgentSuffix` | `AtomicString` | `""` (default, `main.go:453-455`) | `""` (Go zero-value) | `pkg/feature/feature.go:10` | **No** | None |

---

## 5. Detector Participation Analysis

### 5.1 Four-Layer Filtering Chain

The detectors that actually participate in a scan are determined by a four-layer filtering chain:

**Layer 1 — Detector Registry (`defaults.DefaultDetectors`)**

`DefaultDetectors()` at `pkg/engine/defaults/defaults.go:1704-1723` calls `buildDetectorList()` (lines 839-1702), which returns approximately 860 detector instances. It then iterates over the list and configures every detector implementing the `EndpointCustomizer` interface (lines 1709-1720):
- `UseFoundEndpoints(true)` — enables discovery-based endpoints
- `UseCloudEndpoint(true)` — enables cloud-provider endpoints
- `SetCloudEndpoint(cloudProvider.CloudEndpoint())` — sets the actual cloud URL for detectors that are also `CloudProvider`s

**Layer 2 — `Config.Detectors` Assignment**

The `Config.Detectors` field is the input to the engine. The CLI always sets it explicitly at `main.go:519`:
```go
Detectors: append(defaults.DefaultDetectors(), conf.Detectors...),
```

If the API caller leaves `Config.Detectors` as `nil` (or an empty slice), `setDefaults` at `engine.go:362-364` populates it with `defaults.DefaultDetectors()`. If the API caller provides any non-empty list, `setDefaults` does **not** override it.

**Layer 3 — `buildDetectorSets` + `applyFilters`**

At `engine.go:255`, `buildDetectorSets(cfg)` parses the `IncludeDetectors` and `ExcludeDetectors` strings via `config.ParseDetectors` (`pkg/config/detectors.go:61-86`).

The include filter is applied at `engine.go:263-268`:
```go
if len(includeDetectorSet) > 0 {
	filters = append(filters, func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, includeDetectorSet)
		return ok
	})
}
```

The exclude filter is applied at `engine.go:270-275`:
```go
if len(excludeDetectorSet) > 0 {
	filters = append(filters, func(d detectors.Detector) bool {
		_, ok := getWithDetectorID(d, excludeDetectorSet)
		return !ok
	})
}
```

Custom verifier endpoint filters are applied at lines 277-304. All filters are composed via `applyFilters` at line 305.

**Layer 4 — `AhoCorasickCore` Construction**

At `engine.go:530`, `initialize()` creates the Aho-Corasick trie from the surviving detector set:
```go
e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)
```

Only detectors that passed all filters in Layer 3 contribute keywords to the trie. A finding can only occur if a keyword match triggers the corresponding detector's `FromData` method.

### 5.2 `ParseDetectors("all")` vs `ParseDetectors("")`

The `IncludeDetectors` field defaults to `"all"` in the CLI (`main.go:81`) but `""` (Go zero-value) in the API. These are **functionally equivalent** because of how the filtering logic works:

- `ParseDetectors("all")` at `pkg/config/detectors.go:61-86`: The `"all"` keyword matches the `specialGroups` map (line 15-17), which calls `allDetectors()` to return every known detector type. This produces a full include set.
- `ParseDetectors("")`: The input is split by commas. The single empty string is trimmed and skipped at line 66-67 (`if item == "" { continue }`). The function returns an **empty** slice.

At `engine.go:263`, the include filter is **only applied when non-empty**: `if len(includeDetectorSet) > 0`. An empty include set means "include everything" — no filter is added. A full include set explicitly includes everything. The result is identical: all detectors pass.

### 5.3 Existing API Usage Reference

The `hack/snifftest/main.go` program (lines 248-256) is the only existing program in the repository that uses the scanning API outside the CLI. It uses `defaults.DefaultDetectors()` directly:
```go
func getAllScanners() map[string]detectors.Detector {
	allScanners := map[string]detectors.Detector{}
	for _, s := range defaults.DefaultDetectors() {
		// ...
	}
	return allScanners
}
```

However, it does **not** use `engine.NewEngine` at all. Instead, it manually iterates chunks and detectors (lines 116-172), bypassing the engine's filtering, notification, deduplication, and worker pipeline entirely. It also does **not** set any feature flags, meaning APK handling is disabled in snifftest scans.

---

## 6. API-Parity Recommendations

### 6.1 CLI-Equivalent API Configuration Template

To achieve full parity with the CLI's filesystem scan behavior, an API caller should configure the engine as follows:

```go
import (
	"runtime"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Step 1: Set process-global feature flags BEFORE engine creation.
// CRITICAL — without this, APK files are silently skipped.
feature.EnableAPKHandler.Store(true)

// Step 2: Construct SourceManager with CLI-equivalent options.
mgr := sources.NewManager(
	sources.WithConcurrentSources(runtime.NumCPU()),
	sources.WithConcurrentUnits(runtime.NumCPU()),
	sources.WithSourceUnits(),          // Enables unit-based scanning
	sources.WithBufferedOutput(64),     // Output channel buffer
)

// Step 3: Build engine config with all CLI defaults.
cfg := engine.Config{
	Concurrency:             runtime.NumCPU(),
	Detectors:               defaults.DefaultDetectors(), // Full set with endpoint customization
	Verify:                  true,                        // Enable verification
	IncludeDetectors:        "all",                       // Include all detectors
	Dispatcher:              engine.NewPrinterDispatcher(new(output.PlainPrinter)),
	SourceManager:           mgr,
	VerificationResultCache: simple.NewCache[detectors.Result](), // Enable caching
}

// Step 4: Create engine and scan.
eng, err := engine.NewEngine(ctx, &cfg)
if err != nil {
	// handle error
}
eng.Start(ctx)

ref, err := eng.ScanFileSystem(ctx, sources.FilesystemConfig{
	Paths: []string{"/path/to/scan"},
})
```

### 6.2 Minimum Required Changes for API Parity

Listed in order of impact, from most critical to least:

| Priority | Action | Reason |
|----------|--------|--------|
| **MUST** | `feature.EnableAPKHandler.Store(true)` before engine creation | Without this, all APK files are skipped (Root Cause 1) |
| **MUST** | Provide `SourceManager` with `WithSourceUnits()` | Enables unit-based scanning path for consistent behavior (Root Cause 3) |
| **SHOULD** | Set `Verify: true` in `Config` | Enables credential verification against external services (Root Cause 6) |
| **SHOULD** | Use `defaults.DefaultDetectors()` for detector list | Ensures endpoint customization is applied (Root Cause 2) |
| **SHOULD** | Provide `VerificationResultCache: simple.NewCache[detectors.Result]()` | Consistent verification under rate limits (Root Cause 4) |
| **MAY** | Set `IncludeDetectors: "all"` | Functionally equivalent to `""` but explicit (Section 5.2) |

---

## 7. Conclusion

The CLI's finding-count advantage over a minimal API scan stems from a fundamental architectural decision: the engine's `setDefaults()` method at `pkg/engine/engine.go:336-374` handles most configuration gaps (decoders, detectors, dispatcher, concurrency, worker multipliers, result notification flags) but deliberately **cannot** address:

1. **Process-global feature flags** (`pkg/feature/feature.go`) — These are `atomic.Bool` package-level variables that exist outside the engine's `Config` struct. The engine has no mechanism to set them, and their zero-values (`false`) differ from the CLI's intended behavior for `EnableAPKHandler`.

2. **Caller-constructed objects** — The `SourceManager` must be provided by the caller (the engine enforces this with a nil check at `engine.go:248-249`). The `VerificationResultCache` is optional but not defaulted.

3. **Boolean fields with meaningful `true` defaults** — Go's zero-value for `bool` is `false`. The `Config.Verify` field defaults to `false`, while the CLI's intent is `true`.

The engine API is **not broken** — it is designed for flexibility. The discrepancy exists because the CLI adds configuration layers that the engine deliberately leaves to the caller. An API consumer who follows the recommendations in Section 6 will achieve full parity with the CLI's filesystem scan behavior.

The single most impactful fix for any API caller experiencing fewer findings than the CLI is:

```go
feature.EnableAPKHandler.Store(true)
```

This one line, placed before engine construction, restores APK file processing and is the primary driver of the finding-count gap for filesystem scans containing Android application packages.
