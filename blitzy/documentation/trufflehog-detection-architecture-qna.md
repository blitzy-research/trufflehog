# TruffleHog v3 — Internal Detection Architecture Exploration

## Introduction

This document provides a comprehensive, code-grounded exploration of TruffleHog v3's internal detection architecture. It is designed for a developer onboarding to the TruffleHog codebase who wants to understand how the system works from the inside before contributing to it.

### Purpose

Five interconnected architectural questions are answered here:

1. **Detection Architecture & Startup** — What happens when TruffleHog is built and a scan begins?
2. **Verification Setup** — How is HTTP verification infrastructure organized?
3. **Output Structure** — What is the exact JSON output schema for findings?
4. **Repository Traversal** — How does TruffleHog decide which files to scan vs. skip?
5. **Detector Architecture** — Are detectors plugins or embedded modules?

### Methodology

Every answer in this document is derived exclusively from **static source code analysis** of the TruffleHog v3 repository. No assumptions are made; all claims are traceable to specific source files and line numbers.

- **Module path:** `github.com/trufflesecurity/trufflehog/v3` (`Source: go.mod:1`)
- **Go version:** `1.23.1` (`Source: go.mod:3`)
- **Toolchain:** `go1.24.2` (`Source: go.mod:5`)

The project uses no documentation site generator. Existing architecture documentation lives in `docs/concurrency.md` and `docs/process_flow.md` as standalone Markdown with Mermaid diagrams. This document follows the same conventions and cross-references those files where appropriate.

### Conventions

- **Source citations** use the format `Source: filepath:LineRange`
- **Terminology** matches the codebase: "chunk" (not "fragment"), "detector" (not "scanner" in prose), "source" (not "target")
- **Mermaid diagrams** use syntax compatible with GitHub Markdown rendering
- **Verbosity levels** follow the project's logging scale documented in `CONTRIBUTING.md:31-37`:
  - V(0): logs always shown
  - V(2): debugging logs
  - V(4): extremely verbose / sensitive
  - V(5): ultimate verbosity

---

## 1. Detection Architecture & Startup Behavior

> **Questions answered:**
> - What happens when TruffleHog is built from source and a scan is started?
> - Are detector configurations loaded from files, or are they compiled in?
> - What initialization messages appear about detector registration?

### 1.1 Build Process

TruffleHog compiles to a **single self-contained Go binary**. The `Makefile` provides standard build targets:

- `make install` runs `CGO_ENABLED=0 go install .` (`Source: Makefile:18`)
- `make run` runs `CGO_ENABLED=0 go run . git file://. --json` (`Source: Makefile:49`)
- `make test` runs `CGO_ENABLED=0 go test -timeout=5m ...` (`Source: Makefile:31`)

**Thinking/Rationale:** The `CGO_ENABLED=0` flag means the binary is statically linked with no C dependencies required for the base build. This enables simple cross-platform distribution as a single binary. The Go module path is `github.com/trufflesecurity/trufflehog/v3` (`Source: go.mod:1`).

### 1.2 Startup Sequence: `init()` → `main()` → `run()`

The startup sequence flows through three key functions in `main.go`:

#### 1.2.1 The `init()` Function

`Source: main.go:259-328`

The `init()` function executes before `main()` and performs the following steps:

1. **GOMAXPROCS auto-tuning** (line 260): `maxprocs.Set()` from `go.uber.org/automaxprocs/maxprocs` (`Source: main.go:24`) automatically adjusts `GOMAXPROCS` based on container CPU quotas. This ensures correct CPU allocation when running inside cgroups/containers.

2. **Argument normalization** (lines 262-268): A loop converts underscores to hyphens in CLI flags (e.g., `--no_verification` becomes `--no-verification`), ensuring backward-compatible flag parsing.

3. **Version string** (line 270): `cli.Version("trufflehog " + version.BuildVersion)` registers the version for `--version` output.

4. **TUI check** (lines 280-299): If stdout is a terminal and either no subcommand is provided or the `analyze` subcommand is invoked, `tui.Run()` launches an interactive terminal UI. The exact condition is `isatty.IsTerminal(os.Stdout.Fd()) && (len(os.Args) <= 1 || os.Args[1] == analyzeCmd.FullCommand())` (`Source: main.go:280`). This allows users who invoke `trufflehog` with no arguments (or with `analyze`) to get a guided experience.

5. **CLI parsing** (line 301): `cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))` parses all command-line flags using the Kingpin CLI framework (`Source: main.go:18`, `github.com/alecthomas/kingpin/v2`).

6. **Log level configuration** (lines 304-323): Supports multiple ways to set log verbosity:
   - `--trace` sets level 5
   - `--debug` sets level 2
   - `--log-level N` sets level 0-5, or `-1` to disable logging entirely

7. **Color disabling** (lines 325-327): `--no-color` / `--no-colour` sets `color.NoColor = true`.

#### 1.2.2 The `main()` Function

`Source: main.go:330-368`

1. **Logger setup** (lines 332-338): Creates a structured logger with either a console or JSON sink depending on the `--json` flag. Sets it as the default logger via `context.SetDefaultLogger(logger)`.

2. **Local dev mode** (lines 340-343): If `--local-dev` is set, directly calls `run()` bypassing the overseer supervisor. This is used for development.

3. **Overseer configuration** (lines 348-362): Configures the `overseer` process supervisor for automatic binary self-updating:
   - `Program: run` — the supervised function
   - `RestartSignal: syscall.SIGTERM` — signal to restart on update
   - Update fetcher is disabled if `BuildVersion == "dev"` (line 360-362)

4. **Supervised execution** (line 364): `overseer.RunErr(updateCfg)` starts the supervised process.

#### 1.2.3 The `run()` Function

`Source: main.go:381-580`

This is the core scanning execution function:

1. **Context with cancellation** (line 383): Creates a cancellable context for the entire scan.

2. **Signal handling** (lines 395-408): Listens for `SIGINT`, `SIGTERM`, `SIGQUIT` to trigger graceful shutdown including temporary artifact cleanup.

3. **Version logging** (line 410): `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` logs the version at debug verbosity.

4. **Feature flag configuration** (lines 440-458):
   - `feature.ForceSkipBinaries.Store(true)` if `--force-skip-binaries` (`Source: main.go:441-443`)
   - `feature.ForceSkipArchives.Store(true)` if `--force-skip-archives` (`Source: main.go:445-447`)
   - `feature.SkipAdditionalRefs.Store(true)` if `--skip-additional-refs` (`Source: main.go:449-451`)
   - `feature.EnableAPKHandler.Store(true)` **always** for OSS builds (`Source: main.go:458`)

5. **Config file loading** (lines 460-467): If `--config` is provided, `config.Read(*configFilename)` reads custom detector YAML.

6. **Detector timeout override** (lines 469-473): If `--detector-timeout` is set, applies it to both the engine timeout and the HTTP client timeout.

7. **Archive limits** (lines 474-482): Configures `--archive-max-size`, `--archive-max-depth`, and `--archive-timeout`.

8. **Printer selection** (lines 484-495):

   | Flag | Printer |
   |------|---------|
   | `--json-legacy` | `LegacyJSONPrinter` |
   | `--json` | `JSONPrinter` |
   | `--github-actions` | `GitHubActionsPrinter` |
   | (default) | `PlainPrinter` |

9. **Engine configuration assembly** (lines 513-533):
   ```go
   engConf := engine.Config{
       Detectors: append(defaults.DefaultDetectors(), conf.Detectors...),
       // ... other fields
   }
   ```
   **This is the critical line** (`Source: main.go:519`): `defaults.DefaultDetectors()` returns the compiled-in detector list, and `conf.Detectors` (from `--config` YAML) is appended. **Detectors are compiled in, not loaded from files.**

10. **Verification cache** (lines 535-537): If `--no-verification-cache` is not set, creates an LRU cache for verification results via `simple.NewCache[detectors.Result]()`.

11. **Scan execution** (line 546): `runSingleScan(ctx, cmd, engConf)` creates the engine and starts scanning.

### 1.3 Engine Initialization

#### 1.3.1 `NewEngine()`

`Source: pkg/engine/engine.go:226-328`

1. **Verification cache** (line 227): Wraps the cache and metrics reporter.
2. **Engine struct population** (lines 229-247): Copies all configuration values into the engine.
3. **`setDefaults(ctx)`** (line 252): Sets default values for unspecified options (see below).
4. **Detector include/exclude filtering** (lines 254-275): `buildDetectorSets()` parses `--include-detectors` and `--exclude-detectors` into filter sets. The filters are applied subtractively via `engine.applyFilters()` (line 305).
5. **Custom verifier endpoints** (lines 277-304): Applies `--verifier` endpoints to detectors that implement `EndpointCustomizer`.
6. **Result type configuration** (lines 307-321): Configures which result types to notify (verified, unverified, unknown, filtered_unverified).
7. **`initialize(ctx)`** (line 323): Prepares internal data structures.

#### 1.3.2 `setDefaults()`

`Source: pkg/engine/engine.go:336-374`

| Default | Value | Source |
|---------|-------|--------|
| `concurrency` | `runtime.NumCPU()` if 0 | `engine.go:337-341` |
| `detectorWorkerMultiplier` | **8** (comment: "bound by net i/o so it's higher than other workers") | `engine.go:343-346` |
| `notificationWorkerMultiplier` | **1** | `engine.go:348-350` |
| `verificationOverlapWorkerMultiplier` | **1** | `engine.go:352-354` |
| `decoders` | `decoders.DefaultDecoders()` (UTF8, Base64, UTF16, EscapedUnicode) | `engine.go:357-359` |
| `detectors` | `defaults.DefaultDetectors()` | `engine.go:362-364` |
| `dispatcher` | `PlainPrinter` | `engine.go:366-368` |

After setting defaults: `ctx.Logger().V(4).Info("default engine options set")` (`Source: pkg/engine/engine.go:373`)

#### 1.3.3 `defaults.DefaultDetectors()`

`Source: pkg/engine/defaults/defaults.go`

The `buildDetectorList()` function (internal to this file) returns a slice of **857** concrete `&scanner.Scanner{}` instances. Each detector is a **statically imported Go package** — compiled directly into the binary. There is no file-based loading, no plugin system, and no `.so` dynamic linking.

After building the list, `DefaultDetectors()` post-processes each detector:
- If it implements `EndpointCustomizer`, sets `UseFoundEndpoints(true)` and `UseCloudEndpoint(true)`
- If it also implements `CloudProvider`, calls `SetCloudEndpoint(cloudProvider.CloudEndpoint())`

The generic function `DefaultDetectorTypesImplementing[T]()` provides introspection capabilities.

#### 1.3.4 `initialize()`

`Source: pkg/engine/engine.go:489-533`

1. **LRU deduplication cache** (lines 491-496): 512-entry cache prevents duplicate result processing.
2. **Channel initialization** (lines 497-519): Buffered channels with multipliers:
   - `detectableChunksChan`: buffer = `defaultChannelBuffer × 50`
   - `verificationOverlapChunksChan`: buffer = `defaultChannelBuffer × 25`
   - `results`: buffer = `defaultChannelBuffer × 50`
   - where `defaultChannelBuffer = runtime.NumCPU()` (`Source: pkg/engine/engine.go:627`)
3. **Aho-Corasick trie construction** (line 530): `ahocorasick.NewAhoCorasickCore(e.detectors)` builds a keyword search trie from all detector keywords.

Log messages emitted:
- `V(4).Info("engine initialized")` (`Source: pkg/engine/engine.go:521`)
- `V(4).Info("setting up aho-corasick core")` (`Source: pkg/engine/engine.go:529`)
- `V(4).Info("set up aho-corasick core")` (`Source: pkg/engine/engine.go:531`)

### 1.4 Worker Startup

`Source: pkg/engine/engine.go:621-625, 646-718`

`Engine.Start()` calls `e.startWorkers(ctx)` which spawns four worker pools:

```go
func (e *Engine) startWorkers(ctx context.Context) {
    e.startScannerWorkers(ctx)
    e.startDetectorWorkers(ctx)
    e.startVerificationOverlapWorkers(ctx)
    e.startNotifierWorkers(ctx)
}
```

### 1.5 Initialization Messages Summary

| Verbosity | Message | Source |
|-----------|---------|--------|
| V(0)/Info | `"No concurrency specified, defaulting to max"` with `"cpu"` count | `engine.go:339` |
| V(2) | `"trufflehog <version>"` | `main.go:410` |
| V(2) | `"starting scanner workers"` with `"count"` | `engine.go:663` |
| V(2) | `"starting detector workers"` with `"count"` | `engine.go:678` |
| V(2) | `"starting verificationOverlap workers"` with `"count"` | `engine.go:693` |
| V(2) | `"starting notifier workers"` with `"count"` | `engine.go:708` |
| V(4) | `"default engine options set"` | `engine.go:373` |
| V(4) | `"engine initialized"` | `engine.go:521` |
| V(4) | `"setting up aho-corasick core"` | `engine.go:529` |
| V(4) | `"set up aho-corasick core"` | `engine.go:531` |
| Info | `"finished scanning"` with metrics (chunks, bytes, secrets found, duration) | `main.go:566-574` |

**Thinking/Rationale:** There are **no log messages about individual detector registration**. Detectors are compiled in as a static list — there is no dynamic loading that would warrant per-detector registration logs. The engine logs aggregate counts (worker counts, final metrics) rather than itemizing detectors.

### 1.6 Startup Flow Diagram

```mermaid
flowchart TD
    Init["init()
    • maxprocs.Set()
    • arg normalization
    • CLI parsing
    • log level config"]
    Main["main()
    • logger setup
    • overseer config"]
    Run["run()
    • signal handling
    • feature flags
    • config loading
    • printer selection"]
    NewEngine["NewEngine()
    • setDefaults()
    • include/exclude filtering
    • custom verifier endpoints"]
    SetDefaults["setDefaults()
    • concurrency = NumCPU
    • detectorWorkerMultiplier = 8
    • DefaultDecoders()
    • DefaultDetectors()"]
    Initialize["initialize()
    • LRU cache (512 entries)
    • channel creation
    • Aho-Corasick trie"]
    Start["Start()
    • startWorkers()"]
    Workers["startWorkers()
    • scannerWorkers (N)
    • detectorWorkers (N×8)
    • overlapWorkers (N×1)
    • notifierWorkers (N×1)"]

    Init --> Main
    Main --> |"overseer.RunErr()"| Run
    Run --> |"engine.NewEngine()"| NewEngine
    NewEngine --> SetDefaults
    NewEngine --> Initialize
    Run --> |"eng.Start()"| Start
    Start --> Workers
```

### 1.7 Key Answer: Detectors Are Compiled In

**Direct answer:** Detector configurations are **compiled into the binary**, not loaded from files.

**Evidence:**
1. `pkg/engine/defaults/defaults.go` statically imports ~857 detector packages and instantiates them as concrete Go structs in `buildDetectorList()` (`Source: pkg/engine/defaults/defaults.go:1-1733`)
2. `defaults.DefaultDetectors()` is called at `main.go:519` to populate the engine configuration
3. There is no `plugin.Open()`, no dynamic `.so` loading, no file-based detector discovery anywhere in the codebase

**Rationale:** Compiling detectors in provides:
- **Performance:** No runtime parsing overhead or reflection
- **Type safety:** Compile-time verification that all detectors implement the `Detector` interface
- **Single binary distribution:** No external files to manage or distribute
- **The exception:** Custom detectors can be loaded at runtime via `--config` YAML (`Source: pkg/config/config.go:17-45`), but these supplement — not replace — the compiled-in defaults

---

## 2. Verification Setup

> **Questions answered:**
> - Do build dependencies include HTTP client libraries for network verification?
> - Does the architecture show verification happening in parallel or sequentially?

### 2.1 HTTP Dependencies

Verification uses Go's **standard library `net/http`** (`Source: pkg/detectors/http.go:7`). No external HTTP client library is needed for the core verification infrastructure.

Additional cloud-specific dependencies in `go.mod` support individual detector verifications:
- `cloud.google.com/go/secretmanager` and `cloud.google.com/go/storage` for GCP (`Source: go.mod:15-16`)
- `github.com/aws/aws-sdk-go` for AWS (`Source: go.mod:22`)
- `github.com/elastic/go-elasticsearch/v8` for Elasticsearch (`Source: go.mod:43`)

**Thinking/Rationale:** The core HTTP verification infrastructure is built on Go's stdlib, which provides a production-grade HTTP client with connection pooling, TLS, and proxy support. Cloud SDKs are only needed for detector-specific API calls (e.g., verifying an AWS key by calling STS).

### 2.2 Dual HTTP Client Model

`Source: pkg/detectors/http.go:14-15, 27-39`

TruffleHog initializes two global HTTP clients in its `init()` function:

```go
var DetectorHttpClientWithNoLocalAddresses *http.Client  // SSRF-protected
var DetectorHttpClientWithLocalAddresses *http.Client     // Allows local connections
```

- **`DetectorHttpClientWithLocalAddresses`** (line 28-32): Created with `NewDetectorTransport(nil)`, `DefaultResponseTimeout`, and `WithNoFollowRedirects()`. Allows connections to local/private IP addresses.

- **`DetectorHttpClientWithNoLocalAddresses`** (line 33-38): Same as above but adds `WithNoLocalIP()` which blocks connections to loopback, link-local, and private IP addresses. This provides **SSRF protection** — preventing a malicious secret from tricking verification into connecting to internal services.

### 2.3 HTTP Client Configuration

#### Transport Layer

`Source: pkg/detectors/http.go:67-94`

The `detectorTransport` is a custom `http.RoundTripper` wrapper that injects a `User-Agent: TruffleHog` header on every request (line 72). If `feature.UserAgentSuffix` is set, it appends the suffix (lines 20-25).

Default transport settings (`Source: pkg/detectors/http.go:81-91`):

| Setting | Value |
|---------|-------|
| `Proxy` | `http.ProxyFromEnvironment` |
| `MaxIdleConns` | 100 |
| `MaxIdleConnsPerHost` | 5 |
| `IdleConnTimeout` | 90 seconds |
| `TLSHandshakeTimeout` | 3 seconds |
| `ExpectContinueTimeout` | 1 second |
| Dial `Timeout` | 2 seconds |
| Dial `KeepAlive` | 5 seconds |

#### Response Timeout

`Source: pkg/detectors/http.go:18`

```go
const DefaultResponseTimeout = 10 * time.Second
```

#### Timeout Override

`Source: pkg/detectors/http.go:46-51`

`OverrideDetectorTimeout()` allows a one-time override of the default timeout via `sync.Once`. This is triggered by the `--detector-timeout` CLI flag (`Source: main.go:469-472`).

#### Local IP Blocking

`Source: pkg/detectors/http.go:96-151`

`WithNoLocalIP()` wraps the transport's `DialContext` to resolve hostnames and check each IP with `isLocalIP()`. Blocked addresses include:
- Loopback addresses (`127.0.0.0/8`, `::1`)
- Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
- Private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)

### 2.4 Parallel Verification — The Definitive Answer

**Direct answer:** Verification happens **in parallel**, not sequentially.

**Evidence:**

`Source: pkg/engine/engine.go:675-688`

```go
func (e *Engine) startDetectorWorkers(ctx context.Context) {
    numWorkers := e.concurrency * e.detectorWorkerMultiplier
    ctx.Logger().V(2).Info("starting detector workers", "count", numWorkers)
    for worker := 0; worker < numWorkers; worker++ {
        e.wgDetectorWorkers.Add(1)
        go func() { /* ... */ e.detectorWorker(ctx) }()
    }
}
```

- `detectorWorkerMultiplier` defaults to **8** (`Source: pkg/engine/engine.go:345`) with the comment: "bound by net i/o so it's higher than other workers"
- So with N CPU cores: **N × 8 detector workers** run concurrently
- On an 8-core machine: **64 parallel detector workers** each performing independent HTTP verification requests
- Each worker reads from `e.detectableChunksChan` and calls `FromData(ctx, verify, data)` which performs HTTP verification

### 2.5 Worker Count Table

For a system with **N** CPUs:

| Worker Type | Count | Multiplier | Source |
|-------------|-------|------------|--------|
| Scanner workers | N | ×1 | `engine.go:663-664` |
| Detector workers | N × 8 | ×8 | `engine.go:675-676` |
| Verification overlap workers | N × 1 | ×1 | `engine.go:690-691` |
| Notifier workers | N × 1 | ×1 | `engine.go:705-706` |

**Thinking/Rationale:** The 8× multiplier for detector workers is deliberate. Verification involves network I/O (HTTP requests to external APIs), which is orders of magnitude slower than CPU-bound operations. Having 8× the number of detector workers compared to scanner workers ensures the pipeline doesn't bottleneck on I/O-bound verification. The scanner workers are CPU-bound (decoding, keyword matching) so they scale 1:1 with CPUs.

### 2.6 Verification Caching

`Source: main.go:535-537`

```go
if !*noVerificationCache {
    engConf.VerificationResultCache = simple.NewCache[detectors.Result]()
}
```

An LRU cache stores verification results to avoid redundant HTTP requests for the same credential across multiple scan chunks. Metrics are tracked: cache hits, misses, wasted hits, and saved verification attempts (`Source: main.go:551-563`).

### 2.7 Verification Concurrency Diagram

```mermaid
sequenceDiagram
    participant Main
    participant ScannerWorkers as ScannerWorkers (N)
    participant DetectorWorkers as DetectorWorkers (N×8)
    participant NotifierWorkers as NotifierWorkers (N)

    Note over Main: e.startWorkers()
    Main->>ScannerWorkers: start N scanner workers
    Main->>DetectorWorkers: start N×8 detector workers
    Main->>NotifierWorkers: start N notifier workers

    par Scanner workers decode and match
        ScannerWorkers->>ScannerWorkers: decode chunks (UTF8/Base64/UTF16/EscapedUnicode)
        ScannerWorkers->>ScannerWorkers: Aho-Corasick keyword matching
        ScannerWorkers->>DetectorWorkers: detectableChunksChan <- matched chunks
    and Detector workers verify in parallel
        DetectorWorkers->>DetectorWorkers: detector.FromData(ctx, verify, data)
        Note over DetectorWorkers: Each goroutine independently<br/>performs HTTP verification<br/>(N×8 parallel HTTP requests)
        DetectorWorkers->>NotifierWorkers: e.results <- ResultWithMetadata
    and Notifier workers emit results
        NotifierWorkers->>NotifierWorkers: dispatcher.Dispatch(result)
    end
```

*See also: `docs/concurrency.md` for the existing Mermaid sequence diagram of this pipeline.*

---

## 3. Output Structure

> **Questions answered:**
> - What is the actual JSON output schema for a finding?
> - Are there fields for verification status, confidence scores, or metadata about secret location?

### 3.1 JSON Output Schema

`Source: pkg/output/json.go:27-74`

When `--json` is used, the `JSONPrinter.Print()` method marshals an anonymous struct with the following exact fields:

| # | Field | Go Type | JSON Key | Description |
|---|-------|---------|----------|-------------|
| 1 | `SourceMetadata` | `*source_metadatapb.MetaData` | `"SourceMetadata"` | Source-specific contextual information (protobuf oneof) |
| 2 | `SourceID` | `sources.SourceID` (int64) | `"SourceID"` | ID mapping secrets to specific sources |
| 3 | `SourceType` | `sourcespb.SourceType` (int32 enum) | `"SourceType"` | Numeric source type enum (`Source: proto/sources.proto:14-55`); e.g., AzureStorage=0, Bitbucket=1, GitHub=7, Filesystem=15, Git=16 |
| 4 | `SourceName` | `string` | `"SourceName"` | Name of the source |
| 5 | `DetectorType` | `detectorspb.DetectorType` (int32 enum) | `"DetectorType"` | Numeric detector type from protobuf enum |
| 6 | `DetectorName` | `string` | `"DetectorName"` | String name of `DetectorType` (e.g., `"AWS"`, `"GitHub"`) |
| 7 | `DetectorDescription` | `string` | `"DetectorDescription"` | Human-readable description of the detector |
| 8 | `DecoderName` | `string` | `"DecoderName"` | Decoder used: `"PLAIN"`, `"BASE64"`, `"UTF16"`, or `"ESCAPED_UNICODE"` |
| 9 | `Verified` | `bool` | `"Verified"` | Whether the secret was verified as active — **boolean** |
| 10 | `VerificationError` | `string` | `"VerificationError"` | Error message if verification failed (omitted if empty via `omitempty`) |
| 11 | `VerificationFromCache` | `bool` | `"VerificationFromCache"` | Whether verification result came from cache |
| 12 | `Raw` | `string` | `"Raw"` | Raw secret data |
| 13 | `RawV2` | `string` | `"RawV2"` | Combined ID + secret for multi-part credentials (e.g., AWS key ID + secret) |
| 14 | `Redacted` | `string` | `"Redacted"` | Redacted version of the secret for safe display |
| 15 | `ExtraData` | `map[string]string` | `"ExtraData"` | Detector-specific key-value metadata |
| 16 | `StructuredData` | `*detectorspb.StructuredData` | `"StructuredData"` | Structured data from protobuf (e.g., TLS certificates) |

### 3.2 Verification Status: Boolean, No Confidence Score

**Direct answer:** There are **no confidence scores** anywhere in the TruffleHog codebase. Verification is **binary**: `Verified: true` (secret confirmed active) or `Verified: false` (not confirmed).

**Evidence:**
- The `Result` struct defines `Verified bool` (`Source: pkg/detectors/detectors.go:92`)
- The JSON output maps this directly: `Verified: r.Verified` (`Source: pkg/output/json.go:66`)
- The `VerificationError` field (`Source: pkg/output/json.go:45`) captures **why** verification could not be completed (e.g., timeout, network error, DNS failure) — but it is not a confidence metric

**Thinking/Rationale:** TruffleHog's design philosophy is that a secret is either verified or it isn't. There is no probability score. The `VerificationError` field exists to distinguish between "we checked and it's not active" (Verified=false, no error) and "we couldn't check" (Verified=false, error present). This maps to the `--results` flag which accepts `verified`, `unverified`, and `unknown` as distinct categories.

### 3.3 Result Struct

`Source: pkg/detectors/detectors.go:87-115`

The internal `Result` struct contains:

| Field | Type | Exported | Description |
|-------|------|----------|-------------|
| `DetectorType` | `detectorspb.DetectorType` | Yes | Type of detector |
| `DetectorName` | `string` | Yes | Name (for custom detectors) |
| `Verified` | `bool` | Yes | Verification status |
| `VerificationFromCache` | `bool` | Yes | Cache hit indicator |
| `Raw` | `[]byte` | Yes | Raw secret bytes |
| `RawV2` | `[]byte` | Yes | Combined ID+secret bytes |
| `Redacted` | `string` | Yes | Display-safe redacted form |
| `ExtraData` | `map[string]string` | Yes | Extra key-value data |
| `StructuredData` | `*detectorspb.StructuredData` | Yes | Protobuf structured data |
| `verificationError` | `error` | **No** | Error during verification (unexported to prevent leaking sensitive info) |
| `AnalysisInfo` | `map[string]string` | Yes | Data for credential analysis |

### 3.4 ResultWithMetadata Struct

`Source: pkg/detectors/detectors.go:161-184`

Wraps `Result` with additional source context:

| Field | Type | Description |
|-------|------|-------------|
| `IsWordlistFalsePositive` | `bool` | Flagged as false positive by wordlist check |
| `SourceMetadata` | `*source_metadatapb.MetaData` | Source-specific context |
| `SourceID` | `sources.SourceID` | Source identifier |
| `JobID` | `sources.JobID` | Job identifier |
| `SecretID` | `int64` | Secret ID for reverification |
| `SourceType` | `sourcespb.SourceType` | Source type enum |
| `SourceName` | `string` | Source name |
| `Result` | (embedded) | The detection result |
| `Data` | `[]byte` | Original chunk data |
| `DetectorDescription` | `string` | Detector description |
| `DecoderType` | `detectorspb.DecoderType` | Decoder type enum |

### 3.5 Source Metadata

The `SourceMetadata` field is a protobuf `oneof` (`Source: proto/source_metadata.proto`) containing source-specific contextual information. For example:

- **Git:** file path, commit hash, email, repository URL, timestamp, line number
- **GitHub:** link, username, repository, commit, email, file, timestamp, visibility, line
- **Filesystem:** file path, link, email, line number
- Other source types include: GitLab, S3, GCS, Syslog, CircleCI, Docker, Postman, Elasticsearch, Jenkins, HuggingFace, and more (20+ source metadata types)

### 3.6 Sample JSON Output Skeleton

```json
{
  "SourceMetadata": {
    "Data": {
      "Git": {
        "commit": "abc123def456...",
        "file": "config/secrets.yml",
        "email": "developer@example.com",
        "repository": "https://github.com/org/repo",
        "timestamp": "2024-01-15T10:30:00Z",
        "line": 42
      }
    }
  },
  "SourceID": 0,
  "SourceType": 16,
  "SourceName": "trufflehog - git",
  "DetectorType": 2,
  "DetectorName": "AWS",
  "DetectorDescription": "AWS (Amazon Web Services) is a comprehensive cloud computing platform... (truncated for brevity; actual value is the full string returned by the detector's Description() method)",
  "DecoderName": "PLAIN",
  "Verified": true,
  "VerificationFromCache": false,
  "Raw": "AKIAIOSFODNN7EXAMPLE",
  "RawV2": "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Redacted": "AKIAIOSFODNN7EXAMPLE",
  "ExtraData": {
    "account": "123456789012",
    "arn": "arn:aws:iam::123456789012:user/example"
  },
  "StructuredData": null
}
```

*Note: `VerificationError` is omitted when empty (due to `json:",omitempty"` tag).*

### 3.7 Default Output Format

When no `--json` flag is provided, the default output uses `PlainPrinter` (`Source: pkg/engine/engine.go:367`), which renders a human-friendly colorized view to the terminal via the `github.com/fatih/color` package (`Source: go.mod:45`).

---

## 4. Repository Traversal

> **Questions answered:**
> - How does TruffleHog decide which files to scan versus skip?
> - What do verbose logs reveal about this decision process?

### 4.1 Source → Unit → Chunk Decomposition

TruffleHog's data pipeline follows a three-tier decomposition model documented in `docs/process_flow.md`:

1. **Source** — Top-level data locations (Git repository, GitHub org, filesystem path, S3 bucket, etc.)
2. **Unit** — Natural subdivisions of sources (individual git repos, directories)
3. **Chunk** — The smallest data blocks passed to detection (file contents, git diff hunks)

The `Source` interface (`Source: pkg/sources/sources.go:61-78`) defines six methods:
- `Type()` — returns the source type (`sourcespb.SourceType`)
- `SourceID()` — returns the initialized source ID for DB relationship tracking
- `JobID()` — returns the initialized job ID for DB relationship tracking
- `Init(aCtx, name, jobId, sourceId, verify, connection, concurrency)` — initializes the source
- `Chunks(ctx, chunksChan, targets...)` — emits data over a channel for decoding and scanning
- `GetProgress()` — returns the completion progress (percentage) for the scanned source

The `Chunk` struct (`Source: pkg/sources/sources.go:25-46`) contains the data bytes, source metadata, and a `Verify` flag.

### 4.2 File Handling Entry Point: `HandleFile()`

`Source: pkg/handlers/handlers.go:344-391`

The `HandleFile()` function orchestrates the complete file handling process:

1. **Nil check** (line 351): Returns error if reader is nil
2. **File reader creation** (line 356): `newFileReader(ctx, reader, readerOption)` — detects MIME type and archive format
3. **Empty file check** (lines 358-361): If `ErrEmptyReader`, logs at V(5) and returns nil
4. **MIME type logging** (line 375): Adds `"mime"` to the log context
5. **Archive skip** (lines 379-382): If `skipArchives` option is set and file is an archive, logs at V(5) `"skipping archive file"` and returns nil
6. **Processing context with timeout** (line 384): Creates a context with `maxTimeout`
7. **Handler selection** (line 387): `selectHandler(mimeT, rdr.isGenericArchive)` chooses the appropriate handler

### 4.3 MIME Detection: `newFileReader()`

`Source: pkg/handlers/handlers.go:105-176`

This function performs multi-stage file type detection:

1. **Seekable wrapper** (line 114): Wraps the input in `iobuf.NewBufferedReaderSeeker` for random access
2. **MIME type detection** (line 127): `mimetype.DetectReader()` from `github.com/gabriel-vasile/mimetype` (`Source: go.mod:47`) examines magic bytes
3. **APK check** (lines 139-147): If `feature.EnableAPKHandler` is true AND the file extension is `.apk` AND the MIME is zip/jar, treats it as an APK
4. **skipArchiverMimeTypes bypass** (lines 151-153): If the MIME type is in the known-text-type set, returns immediately without calling the archiver library (I/O optimization)
5. **Archive format identification** (line 156): `archives.Identify()` from `github.com/mholt/archives` (`Source: go.mod:76`) attempts to identify archive formats (zip, tar, gz, etc.)

### 4.4 Handler Selection: `selectHandler()`

`Source: pkg/handlers/handlers.go:308-321`

```
selectHandler(mimeType, isGenericArchive) → FileHandler
```

| MIME Type | Handler | Description |
|-----------|---------|-------------|
| `application/x-archive`, `application/x-unix-archive`, `application/vnd.debian.binary-package` | `arHandler` | Unix AR archives, Debian packages |
| `application/x-rpm`, `application/cpio` | `rpmHandler` | RPM packages, CPIO archives |
| `application/vnd.android.package-archive` | `apkHandler` | Android APK files |
| Any with `isGenericArchive=true` | `archiveHandler` | Generic archives (zip, tar, gz, bz2, xz, etc.) |
| Everything else | `defaultHandler` | Non-archive files (text, binary, etc.) |

### 4.5 MIME Types That Bypass the Archiver

`Source: pkg/handlers/handlers.go:266-297`

The `skipArchiverMimeTypes` set contains **30 MIME types** that skip the `archives.Identify()` call because they are known to be either text-based content or handled by specialized handlers:

**Text/Data formats:**
- `text/plain; charset=utf-8`
- `text/xml`
- `application/json`
- `text/csv`
- `text/tab-separated-values`
- `application/vnd.geo+json`
- `application/x-ndjson`
- `text/html`

**Programming languages:**
- `text/x-python`, `application/x-python`, `application/x-script.python`
- `text/x-lua`
- `text/x-perl`
- `text/x-tcl`, `application/x-tcl`
- `text/x-php`
- `application/javascript`, `text/javascript`, `application/x-javascript`

**Other:**
- `text/rtf`
- `application/x-subrip`, `application/x-srt`, `text/x-srt`, `text/vtt` (subtitle formats)

**Handled by specialized handlers (also in the skip set):**
- `application/x-archive`, `application/x-unix-archive`, `application/vnd.debian.binary-package` (AR handler)
- `application/x-rpm`, `application/cpio` (RPM handler)
- `application/vnd.android.package-archive` (APK handler)

### 4.6 Feature Flags Controlling File Handling

`Source: pkg/feature/feature.go:5-10`

Four feature flags are `atomic.Bool` variables; `UserAgentSuffix` is a custom `AtomicString` type wrapping `atomic.Value` (also thread-safe) (`Source: pkg/feature/feature.go:10,13-15`):

| Flag | CLI Flag | Effect | Default |
|------|----------|--------|---------|
| `ForceSkipBinaries` | `--force-skip-binaries` | Skip binary files entirely | `false` |
| `ForceSkipArchives` | `--force-skip-archives` | Skip archive files entirely | `false` |
| `SkipAdditionalRefs` | `--skip-additional-refs` | Skip additional git references | `false` |
| `EnableAPKHandler` | (always on for OSS) | Enable Android APK handling | `true` (OSS, `main.go:458`) |
| `UserAgentSuffix` | `--user-agent-suffix` | Custom suffix for HTTP User-Agent | `""` |

### 4.7 Archive Handling

The `archiveHandler` (`Source: pkg/handlers/archive.go`) performs recursive archive extraction. Configurable limits are set via CLI flags:

| CLI Flag | Purpose | Source |
|----------|---------|--------|
| `--archive-max-size` | Maximum size of archive to scan | `main.go:78` |
| `--archive-max-depth` | Maximum recursion depth for nested archives | `main.go:79` |
| `--archive-timeout` | Maximum time to spend extracting an archive | `main.go:80` |

### 4.8 Verbose Log Messages for File Handling

| Verbosity | Message | Context | Source |
|-----------|---------|---------|--------|
| V(5) | `"empty reader, skipping file"` | Empty input reader | `handlers.go:359` |
| V(5) | `"skipping archive file"` | `"mime"` = detected MIME type | `handlers.go:380` |
| V(5) | `"dataErrChan closed, all chunks processed"` | Processing complete | `handlers.go:413` |
| (context) | (all logs in HandleFile scope) | `"mime"` added to log context | `handlers.go:375` |

**Thinking/Rationale:** The file handling verbosity is set to V(5) — the "ultimate verbosity" level per `CONTRIBUTING.md:37`. This means file scan/skip decisions are only visible when running with `--log-level=5` or `--trace`. At normal verbosity, file handling is silent. This is by design: scanning may process millions of files, so per-file logging would be overwhelming at lower levels.

### 4.9 Decoder Pipeline

`Source: pkg/decoders/decoders.go:8-16`

Before detection, each chunk passes through the decoder pipeline:

```go
func DefaultDecoders() []Decoder {
    return []Decoder{
        &UTF8{},       // Must be first for duplicate detection
        &Base64{},
        &UTF16{},
        &EscapedUnicode{},
    }
}
```

1. **UTF8** — Effectively a pass-through decoder; must be first so the original data is available for deduplication
2. **Base64** — Attempts Base64 decoding to reveal encoded secrets
3. **UTF16** — Decodes UTF-16 encoded content (common in Windows files)
4. **EscapedUnicode** — Decodes Unicode escape sequences (e.g., `\u0041` → `A`)

Each decoder produces a `DecodableChunk` with the decoded data and a `DecoderType` tag. The scanner worker runs all decoders on each chunk, and each successful decoding produces a separate `detectableChunk` that gets sent to detector workers.

### 4.10 File Handling Decision Flow

```mermaid
flowchart TD
    Input["Input Reader"]
    MIME["MIME Detection
    (mimetype.DetectReader)"]
    Empty{"Empty
    reader?"}
    APK{"APK file?
    (.apk extension +
    zip/jar MIME +
    EnableAPKHandler)"}
    Skip{"In
    skipArchiverMimeTypes?"}
    Archive["Archive Identification
    (archives.Identify)"]
    IsArchive{"Is generic
    archive?"}
    SkipArchiveFlag{"skipArchives
    option set?"}

    ARHandler["AR Handler
    (ar, deb)"]
    RPMHandler["RPM Handler
    (rpm, cpio)"]
    APKHandler["APK Handler
    (apk)"]
    ArchiveHandler["Archive Handler
    (zip, tar, gz, etc.)"]
    DefaultHandler["Default Handler
    (text, binary, etc.)"]
    SkipFile["Skip File
    (return nil)"]

    Input --> MIME
    MIME --> Empty
    Empty -- Yes --> SkipFile
    Empty -- No --> APK
    APK -- Yes --> APKHandler
    APK -- No --> Skip
    Skip -- "Yes, AR/Deb MIME" --> ARHandler
    Skip -- "Yes, RPM/CPIO MIME" --> RPMHandler
    Skip -- "Yes, other (text types)" --> DefaultHandler
    Skip -- No --> Archive
    Archive --> IsArchive
    IsArchive -- Yes --> SkipArchiveFlag
    IsArchive -- No --> DefaultHandler
    SkipArchiveFlag -- Yes --> SkipFile
    SkipArchiveFlag -- No --> ArchiveHandler
```

> **Note on diagram routing:** Files matching `skipArchiverMimeTypes` return early from `newFileReader()` (line 151-153) with `isGenericArchive=false`, so they **bypass** both the `archives.Identify()` call and the `skipArchives` flag check (line 379). They proceed directly to `selectHandler()` which routes by MIME type to their respective handlers. The `skipArchives` option only affects files identified as generic archives via `archives.Identify()`.

---

## 5. Detector Architecture

> **Questions answered:**
> - Are detectors separate plugins or embedded modules?
> - What does the binary's help output show about available detection capabilities?

### 5.1 Embedded Modules — Not Plugins

**Direct answer:** Detectors are **embedded Go modules compiled into the binary**. They are NOT separate plugins.

**Evidence:**

1. **Static imports** (`Source: pkg/engine/defaults/defaults.go:1-100+`): The file imports ~857 detector packages directly:
   ```go
   import (
       "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/abuseipdb"
       "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/abyssale"
       // ... 855 more imports
   )
   ```

2. **Concrete instantiation**: `buildDetectorList()` returns a slice of concrete `&scanner.Scanner{}` instances — no reflection, no interface assertions, no dynamic dispatch.

3. **No plugin loading**: There is no `plugin.Open()`, no `.so` file loading, no dynamic library discovery anywhere in the codebase.

4. **Single module**: All detector packages live under `pkg/detectors/` within the same Go module (`github.com/trufflesecurity/trufflehog/v3`), compiled into one binary.

**Thinking/Rationale:** Go's plugin system (`plugin.Open`) has significant limitations: it requires matching Go versions, shared libraries, and Linux-only support. By compiling detectors statically, TruffleHog achieves:
- Cross-platform compatibility (single static binary)
- No runtime dependency management
- Compile-time type safety for all detector implementations
- Optimal performance (no reflection overhead)

### 5.2 The Detector Interface

`Source: pkg/detectors/detectors.go:19-29`

Every detector must implement this interface:

```go
type Detector interface {
    FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
    Keywords() []string
    Type() detectorspb.DetectorType
    Description() string
}
```

| Method | Purpose |
|--------|---------|
| `FromData` | Core scanning + optional verification. Receives a data chunk and returns matched secrets. If `verify` is true, attempts to verify each finding via API calls. |
| `Keywords` | Returns keyword strings used for Aho-Corasick prefiltering. Only chunks containing these keywords will be sent to this detector. |
| `Type` | Returns the protobuf `DetectorType` enum value (numeric ID). |
| `Description` | Returns a human-readable description of what the detector looks for. |

### 5.3 Optional Interfaces

`Source: pkg/detectors/detectors.go:31-85`

Detectors may optionally implement these interfaces for enhanced behavior:

| Interface | Methods | Purpose | Source |
|-----------|---------|---------|--------|
| `CustomResultsCleaner` | `CleanResults()`, `ShouldCleanResultsIrrespectiveOfConfiguration()` | Custom deduplication logic for removing superfluous results | Lines 37-45 |
| `Versioner` | `Version() int` | Differentiate instances of the same detector type (e.g., `atlassian/v1` vs `atlassian/v2`) | Lines 49-51 |
| `MaxSecretSizeProvider` | `MaxSecretSize() int64` | Custom maximum size for the secret pattern match | Lines 55-57 |
| `StartOffsetProvider` | `StartOffset() int64` | Custom start offset for the keyword match span | Lines 61-63 |
| `MultiPartCredentialProvider` | `MaxCredentialSpan() int64` | Custom span for multi-part credentials (e.g., AWS key ID + secret key) | Lines 67-72 |
| `EndpointCustomizer` | `SetConfiguredEndpoints()`, `SetCloudEndpoint()`, `UseCloudEndpoint()`, `UseFoundEndpoints()` | Support for user-supplied verification endpoints via `--verifier` flag | Lines 76-81 |
| `CloudProvider` | `CloudEndpoint() string` | Provides a cloud endpoint URL for verification | Lines 83-85 |

### 5.4 Aho-Corasick Keyword Prefiltering

`Source: pkg/engine/ahocorasick/ahocorasickcore.go`

This is a critical performance optimization: **not all detectors run on every chunk**. Instead:

1. **Trie construction** (`NewAhoCorasickCore`, lines 141-168):
   - Collects all `Keywords()` from all detectors (lowercased)
   - Builds an Aho-Corasick trie using `github.com/BobuSumisu/aho-corasick` (`Source: go.mod:17`)
   - Default offset radius: **512 bytes** (line 155)

2. **Chunk matching** (`FindDetectorMatches`, lines 241-285):
   - The trie scans the chunk data for all keyword matches simultaneously (O(n) with n = chunk length)
   - Each match maps to one or more detectors via `keywordsToDetectors`
   - Match spans are calculated based on the keyword position ± offset radius
   - Overlapping/adjacent spans are merged
   - Only **matched detectors** receive the chunk for scanning

3. **Span calculation strategies**:
   - `adjustableSpanCalculator` (default): uses ±512 byte offset from keyword position, adjusted by `MaxSecretSizeProvider`, `StartOffsetProvider`, and `MultiPartCredentialProvider`
   - `EntireChunkSpanCalculator`: uses the entire chunk (enabled by `--scan-entire-chunk` flag)

**Thinking/Rationale:** With 857 detectors, running every detector on every chunk would be prohibitively expensive. The Aho-Corasick algorithm provides O(n) multi-pattern matching, effectively pre-filtering chunks so only relevant detectors run. For example, a chunk containing the string "AKIA" (an AWS access key prefix) will only be sent to the AWS detector, not to all 857 detectors.

### 5.5 Detector Count and Catalog

`Source: pkg/engine/defaults/defaults.go`

There are **857** `Scanner{}` entries in `buildDetectorList()`. These cover a wide range of services including:

- **Cloud providers:** AWS (access keys, session keys), Azure (Entra, Storage, CosmosDB, OpenAI, Batch), GCP (Secret Manager, Storage)
- **Code platforms:** GitHub, GitLab, Bitbucket
- **Communication:** Slack, Twilio, Discord, Telegram
- **Payment:** Stripe, Square, PayPal
- **AI/ML:** OpenAI, Anthropic, HuggingFace
- **Infrastructure:** Datadog, New Relic, PagerDuty, Grafana
- **And hundreds more:** Each service with its own regex patterns and verification logic

### 5.6 Custom Detectors via `--config`

`Source: pkg/config/config.go:17-45`

While the 857 default detectors are compiled in, users can add custom detectors at runtime:

1. `config.Read(filename)` reads a YAML file (`Source: pkg/config/config.go:18-24`)
2. `NewYAML(input)` parses `custom_detectorspb.CustomDetectors` protobuf messages (`Source: pkg/config/config.go:27-45`)
3. Each config entry creates a `custom_detectors.NewWebhookCustomRegex` instance (line 36)
4. These are **appended** to the default list at `main.go:519`:
   ```go
   Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)
   ```

See `pkg/custom_detectors/CUSTOM_DETECTORS.md` for the custom detector authoring guide and `examples/generic.yml` for example YAML configurations.

### 5.7 CLI Help: Detection Capabilities

Key flags related to detection capabilities:

| Flag | Description | Default | Source |
|------|-------------|---------|--------|
| `--include-detectors` | Comma-separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges. | `"all"` | `main.go:81` |
| `--exclude-detectors` | Comma-separated list of detector types to exclude. IDs here take precedence over include list. | (none) | `main.go:82` |
| `--config` | Path to configuration file for custom YAML detectors. | (none) | `main.go:70` |
| `--no-verification` | Don't verify the results. | `false` | `main.go:59` |
| `--results` | Specifies which result types to output: `verified`, `unknown`, `unverified`, `filtered_unverified`. | `verified,unverified,unknown` | `main.go:61` |
| `--filter-unverified` | Only output first unverified result per chunk per detector. | `false` | `main.go:66` |
| `--filter-entropy` | Filter unverified results using Shannon entropy. | (none) | `main.go:67` |

Available scan subcommands (`Source: main.go:93-254`):

| Subcommand | Description |
|------------|-------------|
| `git` | Find credentials in git repositories |
| `github` | Find credentials in GitHub repositories |
| `github-experimental` | Experimental GitHub scan (object discovery) |
| `gitlab` | Find credentials in GitLab repositories |
| `filesystem` | Find credentials in a filesystem |
| `s3` | Find credentials in S3 buckets |
| `gcs` | Find credentials in GCS buckets |
| `syslog` | Scan syslog |
| `circleci` | Scan CircleCI |
| `docker` | Scan Docker Image |
| `travisci` | Scan TravisCI |
| `postman` | Scan Postman |
| `elasticsearch` | Scan Elasticsearch |
| `jenkins` | Scan Jenkins |
| `huggingface` | Find credentials in HuggingFace datasets, models, and spaces |

### 5.8 Detection Pipeline Diagram

```mermaid
flowchart TD
    RawChunk["Raw Chunk Data
    (from Source)"]
    Decoders["DefaultDecoders()
    UTF8 → Base64 → UTF16 → EscapedUnicode"]
    AhoCorasick["Aho-Corasick
    Keyword Matching"]
    MatchedDetectors["Matched Detectors Only
    (not all 857)"]
    FromData["detector.FromData(ctx, verify, data)
    • Regex pattern matching
    • Secret extraction"]
    Verify{"verify
    enabled?"}
    HTTPVerify["HTTP Verification
    • API call to service
    • Check if secret is active"]
    Result["Result
    {Verified, Raw, Redacted, ExtraData}"]
    ResultWithMetadata["ResultWithMetadata
    + SourceMetadata
    + SourceType/Name
    + DecoderType"]

    RawChunk --> Decoders
    Decoders --> |"DecodableChunks
    (one per decoder)"| AhoCorasick
    AhoCorasick --> |"keyword match found"| MatchedDetectors
    AhoCorasick --> |"no keyword match"| Discard["Chunk discarded
    (no matching detectors)"]
    MatchedDetectors --> FromData
    FromData --> Result
    Result --> Verify
    Verify -- Yes --> HTTPVerify
    HTTPVerify --> |"set Verified=true/false"| ResultWithMetadata
    Verify -- No --> |"Verified=false"| ResultWithMetadata
```

---

## Summary

| # | Question | Answer |
|---|----------|--------|
| 1 | Are detectors loaded from files or compiled in? | **Compiled in.** 857 detectors are statically imported in `pkg/engine/defaults/defaults.go`. Custom detectors can be appended via `--config` YAML. |
| 2 | Is verification parallel or sequential? | **Parallel.** `N × 8` detector worker goroutines perform HTTP verification concurrently (`Source: pkg/engine/engine.go:675-688`). |
| 3 | Does the JSON output have confidence scores? | **No.** `Verified` is a boolean. There are no confidence scores. `VerificationError` captures why verification failed. |
| 4 | How does TruffleHog decide which files to scan? | **MIME-based routing.** `HandleFile()` detects MIME types, routes to specialized handlers (AR, RPM, APK, archive, default), and skips files based on feature flags and `skipArchiverMimeTypes`. |
| 5 | Are detectors plugins or embedded? | **Embedded modules.** All detectors are Go packages compiled into a single binary. No plugin system exists. |

## Cross-References

- **`docs/concurrency.md`** — Worker startup Mermaid sequence diagram showing ScannerWorkers → DetectorWorkers → NotifierWorkers pipeline
- **`docs/process_flow.md`** — End-to-end Mermaid flowcharts for Source Decomposition → Chunk-to-Detector Matching → Secret Detection → Result Notification
- **`CONTRIBUTING.md`** — Logging level conventions (verbosity scale 0-5) and contribution guidelines
- **`pkg/custom_detectors/CUSTOM_DETECTORS.md`** — Custom detector authoring guide for YAML-defined regex detectors
- **`examples/generic.yml`** and **`examples/generic_with_filters.yml`** — Example custom detector YAML configurations

---

*This document was generated from static source code analysis. Line numbers reference the repository state at the time of analysis and may shift as the codebase evolves.*
