# TruffleHog Detection Architecture — Onboarding Q&A

A code-grounded walkthrough of how TruffleHog discovers, verifies, and reports secrets. This document answers five onboarding question clusters about the detection architecture. Every factual claim is backed by a citation in the form `[<path>:<locator>]` pointing at the actual source code, and — where useful — by output captured from a binary built and run from this exact source tree.

---

## Methodology & Environment

- **Commit pinned.** All analysis is pinned to commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch `trufflehog_e42153d44a5e`). Line numbers in citations are valid at this commit.
- **Built from source.** TruffleHog was compiled with Go toolchain **`go1.24.2`**. `go.mod` declares `go 1.23.1` and `toolchain go1.24.2` `[go.mod:L3-L5]`. The build (`CGO_ENABLED=0 go build -o /tmp/trufflehog .`) produced a single statically-linked binary of **194,308,498 bytes (~186 MiB / ~194 MB)**, and `--version` reports `trufflehog dev`.
- **Observation method.** Answers rest on **reading the code** and on **observation scans** against a *throwaway* git repository (`/tmp/testrepo`) containing mixed file types: a text file with a fake AWS key (`creds.txt`), a binary `image.png`, a plain `README.md`, and an `example`-laden token file (`example-token.txt`). Three kinds of runs were captured: a verbose `--log-level=5` git scan, a `--json` filesystem scan, and `--help` / `--help-long`.
- **Repository left unchanged.** The TruffleHog source tree is treated as read-only. The compiled binary lives outside the module (`/tmp/trufflehog`), and all temporary artifacts (binary, test repo, captured logs) were removed after evidence capture. `git status --porcelain` was clean (zero lines) at the start and at the end of the investigation.
- **Authority.** **Code is the authoritative source of truth; runtime output is corroborating evidence.** Where a measured value is environment-specific (for example, worker-pool sizes derived from the host CPU count), this is called out explicitly.

### Pipeline orientation

TruffleHog runs a four-stage pipeline `[docs/process_flow.md]`:

1. **Source Decomposition** — a *Source* (git, GitHub, filesystem, …) is broken into *Units*, which are further broken into *Chunks*, the smallest unit passed on to detection `[docs/process_flow.md]`.
2. **Chunk-to-Detector Matching** — an Aho-Corasick keyword prefilter maps each chunk to the detectors whose keywords appear in it `[docs/process_flow.md]`.
3. **Secret Detection** — detectors check chunks for secrets and *optionally* verify whether they are live `[docs/process_flow.md]`.
4. **Result Notification** — results are reported to the configured output `[docs/process_flow.md]`.

---

## 1. Startup & Detector Registration

### Question

> "If I build it from source and run a basic scan, what happens during startup? Does it load detector configurations from files, or are they compiled in? What initialization messages appear about which detectors get registered?"

### Findings

**Conclusion: the built-in detectors are COMPILED IN (statically, via Go imports). They are NOT loaded from configuration files at runtime.**

- The default detector set is assembled by a **hardcoded Go slice**, not a file read. `buildDetectorList()` returns a literal `[]detectors.Detector{ ... }` `[pkg/engine/defaults/defaults.go:L839]`, and `DefaultDetectors()` wraps that list (and auto-initializes endpoint/cloud-aware detectors) `[pkg/engine/defaults/defaults.go:L1704]`.
- Each detector is wired in by a **compile-time import**. `pkg/engine/defaults/defaults.go` contains **831 import lines** referencing `github.com/trufflesecurity/trufflehog/v3/pkg/detectors/…`, against **845 detector subdirectories** under `pkg/detectors/` `[pkg/engine/defaults/defaults.go:L1-L60]`. The first few imports illustrate the one-import-per-detector pattern (`abuseipdb`, `abyssale`, `accuweather`, …) `[pkg/engine/defaults/defaults.go:L1-L60]`.
- The engine never reads built-in detectors from disk. When no detectors are explicitly supplied, it **falls back to the compiled-in defaults**: `if len(e.detectors) == 0 { e.detectors = defaults.DefaultDetectors() }` `[pkg/engine/engine.go:L362]` (the preceding comment reads "Only use the default detectors if none are provided."). Decoders default the same way just above, via `decoders.DefaultDecoders()` `[pkg/engine/engine.go:L358]`.
- **Only CUSTOM detectors are file-loaded**, via the optional `--config=CONFIG` YAML flag, which is declared with `.ExistingFile()` `[main.go:L70]`. Built-in detectors require no runtime configuration file.
- **Captured startup log sequence** (verbose `--log-level=5`, JSON log format). These bootstrap messages are emitted at verbosity 4 (`info-4`):

```json
{"level":"info-4","logger":"trufflehog","msg":"default engine options set"}
{"level":"info-4","logger":"trufflehog","msg":"engine initialized"}
{"level":"info-4","logger":"trufflehog","msg":"setting up aho-corasick core"}
{"level":"info-4","logger":"trufflehog","msg":"set up aho-corasick core"}
```

  with citations `[pkg/engine/engine.go:L373]` (`default engine options set`), `[pkg/engine/engine.go:L521]` (`engine initialized`), `[pkg/engine/engine.go:L529]` (`setting up aho-corasick core`), and `[pkg/engine/engine.go:L531]` (`set up aho-corasick core`).
- **Banner.** A normal (non-JSON) scan prints a banner to stderr: `🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷` `[main.go:L498]`. **Caveat:** the banner is gated by `if !*jsonLegacy && !*jsonOut` `[main.go:L497-L499]`, so it appears in a normal scan but is **suppressed when `--json` is used**.
- There is **no per-detector "registered X" log line**. Registration is implicit in the compiled import graph and the `DefaultDetectors()` slice; the observable startup messages are the engine/aho-corasick bootstrap lines above plus the worker-start lines (see Section 2). The startup output does **not** enumerate each detector by name.

### Rationale

Because the detector list is a Go function returning a compiled slice (`buildDetectorList()` → `DefaultDetectors()`) and every detector is bound by a static `import`, the detector set is fixed at **build time**. The runtime `len(e.detectors) == 0` branch only *chooses* whether to use that compiled-in set — it never reads detector definitions from a file. The single file-based mechanism (`--config`) exists exclusively for *custom*, user-defined detectors. Hence the built-in detectors are compiled in, not file-loaded. The 831 imports ↔ 845 directories ratio is direct structural proof: nearly every detector directory contributes a compile-time import to the defaults list.

---

## 2. Verification Setup & Concurrency

### Question

> "When I examine the build dependencies, are there HTTP client libraries suggesting network verification? If I run a scan and watch the process activity, does the architecture show verification happening in parallel or sequentially?"

### Findings

**Conclusion: yes — HTTP client libraries are present (network verification), and verification runs in PARALLEL via a dedicated, intentionally oversized detector-worker pool.**

**HTTP client libraries (from `go.mod`):**

- `github.com/hashicorp/go-retryablehttp v0.7.7` `[go.mod:L63]` — an HTTP client with automatic retry, the hallmark of network-based verification.
- Indirect HTTP helpers: `github.com/felixge/httpsnoop v1.0.4` `[go.mod:L200]`, `github.com/hashicorp/go-cleanhttp v0.5.2` `[go.mod:L231]`, and `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0` `[go.mod:L309]`.
- Plus the Go standard library `net/http`. Detector verification uses a shared client, `DetectorHttpClientWithNoLocalAddresses` `[pkg/detectors/http.go:L14]`, with a default `DefaultResponseTimeout = 10 * time.Second` `[pkg/detectors/http.go:L18]`.

**Parallelism (from `pkg/engine/engine.go`):**

- The detector pool is **intentionally oversized** because verification is network-I/O bound:

```go
if e.detectorWorkerMultiplier < 1 {
    // bound by net i/o so it's higher than other workers
    e.detectorWorkerMultiplier = 8
}
```

  `[pkg/engine/engine.go:L343-L345]` (the comment "bound by net i/o so it's higher than other workers" is at L344).
- Workers are spawned as concurrent goroutines: `numWorkers := e.concurrency * e.detectorWorkerMultiplier` `[pkg/engine/engine.go:L676]`, followed by a loop that launches `numWorkers` goroutines each running `e.detectorWorker(ctx)` `[pkg/engine/engine.go:L678-L688]` — i.e., many detector workers run in parallel.
- Each detector worker performs verification through `e.verificationCache.FromData(ctx, data.detector.Detector, data.chunk.Verify, …)` `[pkg/engine/engine.go:L1070]`; the chunk's `Verify` boolean gates whether a live verification call is actually made.
- The engine runs **four parallel worker pools** (corroborated by `docs/concurrency.md`): ScannerWorkers `[pkg/engine/engine.go:L663]`, DetectorWorkers `[pkg/engine/engine.go:L678]`, VerificationOverlapWorkers `[pkg/engine/engine.go:L693]`, and NotifierWorkers `[pkg/engine/engine.go:L708]`. The DetectorWorkers pool is described as running detection, optionally verifying, and doing filtering and enrichment `[docs/concurrency.md]`.
- **Captured runtime proof** (verbose scan; worker-start lines are emitted at verbosity 2, `info-2`):

```json
{"level":"info-2","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

  Note that `1024 = 128 × 8`, directly confirming the `detectorWorkerMultiplier = 8`.

**Where the `128` comes from (it is NOT a hardcoded constant):** the `--concurrency` default is `runtime.NumCPU()`, set as `cli.Flag("concurrency", …).Default(strconv.Itoa(runtime.NumCPU()))` `[main.go:L58]`. On the observation host, Go's `runtime.NumCPU()` returns **128** (`/proc/cpuinfo` and `getconf _NPROCESSORS_ONLN` also report 128), so `--help` renders `--concurrency=128`, the scanner pool is 128, and the detector pool is `128 × 8 = 1024`. These numbers are **environment-specific** and scale with `NumCPU()`; on a host with a different CPU count they would differ proportionally. (As an aside, the cgroup-aware `nproc` shell utility reported `4` on the same host, but TruffleHog uses `runtime.NumCPU()`, not `nproc`, which is why the pools are sized from 128.)

### Rationale

The presence of a retrying HTTP client (plus stdlib `net/http`, and a per-detector 10-second response timeout) shows that verification reaches out to live provider APIs over the network. Architecturally, verification is not a sequential post-pass: it runs *inside* the DetectorWorkers pool, which is deliberately sized at `8 ×` the base concurrency precisely because each verification blocks on network I/O. The captured `detector workers count=1024` (versus `scanner workers count=128`) is direct runtime proof of parallel, oversubscribed verification.

### Four-pool data flow

```mermaid
graph LR
    A[Sources] -->|chunks| B[Scanner Workers]
    B -->|detectable chunks| C[Detector Workers x8 - parallel verification]
    B -->|multi-detector chunks| D[VerificationOverlap Workers]
    D --> C
    C -->|results| E[Notifier Workers]
    C -.->|live API call via net/http + go-retryablehttp| F[(Provider API)]
```


---

## 3. JSON Output Schema

### Question

> "If I run a scan with JSON output, what's the actual schema for a finding? Are there fields for verification status, confidence scores, or metadata about where secrets were found?"

### Findings

**Conclusion: the `--json` printer marshals an anonymous struct built from `*detectors.ResultWithMetadata`. It HAS verification-status fields (`Verified`, `VerificationFromCache`, and an optional `VerificationError`) and rich location metadata (`SourceMetadata`), but it has NO confidence-score field anywhere.**

- `JSONPrinter.Print` `[pkg/output/json.go:L19]` builds an anonymous struct `[pkg/output/json.go:L27-L56]` and `json.Marshal`s it. The fields, in declaration order, are: `SourceMetadata` `[pkg/output/json.go:L29]`, `SourceID`, `SourceType`, `SourceName`, `DetectorType`, `DetectorName` `[pkg/output/json.go:L39]` (populated from `r.DetectorType.String()` `[pkg/output/json.go:L63]`), `DetectorDescription` `[pkg/output/json.go:L41]`, `DecoderName` (from `r.DecoderType.String()` `[pkg/output/json.go:L65]`), `Verified` `[pkg/output/json.go:L44]`, `VerificationError string` with `json:",omitempty"` `[pkg/output/json.go:L45]` (omitted when empty), `VerificationFromCache` `[pkg/output/json.go:L46]`, `Raw`, `RawV2`, `Redacted`, `ExtraData`, and `StructuredData`.
- The Go struct backing the result is `type Result struct { … }` `[pkg/detectors/detectors.go:L87]`, whose fields include `DetectorType`, `DetectorName`, `Verified`, `VerificationFromCache`, `Raw`, `RawV2`, `Redacted`, `ExtraData`, `StructuredData`, an unexported `verificationError`, and `AnalysisInfo`.
- The protobuf result message is `message Result` `[proto/detectors.proto:L1038]`.
- **Captured `--json` finding** (filesystem scan of the test repo; verbatim):

```json
{
  "SourceMetadata": { "Data": { "Filesystem": { "file": "/tmp/testrepo/creds.txt", "line": 1 } } },
  "SourceID": 1,
  "SourceType": 15,
  "SourceName": "trufflehog - filesystem",
  "DetectorType": 2,
  "DetectorName": "AWS",
  "DetectorDescription": "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.",
  "DecoderName": "PLAIN",
  "Verified": false,
  "VerificationFromCache": false,
  "Raw": "AKIAI136580GT7ZIQ2WP",
  "RawV2": "AKIAI136580GT7ZIQ2WP:h8PcopRiorHfddHdLSHVY9QSDZgszKHe5mdlkKx9",
  "Redacted": "AKIAI136580GT7ZIQ2WP",
  "ExtraData": { "resource_type": "Access key" },
  "StructuredData": null
}
```

  (The `VerificationError` key is absent here precisely because of `json:",omitempty"` `[pkg/output/json.go:L45]` and an empty error. The captured key set — all 15 fields, in this exact order — matches the anonymous struct one-to-one.)

**Answering the three explicit sub-questions:**

- **Verification status?** YES — `Verified` (bool) `[pkg/output/json.go:L44]`, `VerificationFromCache` (bool) `[pkg/output/json.go:L46]`, and an optional `VerificationError` (string, `omitempty`) `[pkg/output/json.go:L45]`.
- **Confidence score?** **NO — there is no confidence field anywhere.** A case-insensitive search for `confidence` returns **0 matches** in the JSON printer `[pkg/output/json.go]`, in the Go `Result` struct `[pkg/detectors/detectors.go:L87]`, and in the protobuf `Result` message `[proto/detectors.proto:L1038]`. TruffleHog expresses confidence solely through the **boolean verification model** (verified / unverified / unknown), not a numeric score.
- **Location / provenance metadata?** YES — carried in `SourceMetadata`, which is a `oneof` over many source types: `message MetaData` `[proto/source_metadata.proto:L367]` with `oneof data` `[proto/source_metadata.proto:L368]`. For Git, `message Git` `[proto/source_metadata.proto:L94]` carries `commit`, `file`, `email`, `repository`, `timestamp`, and `line`. For the filesystem source, `message Filesystem` `[proto/source_metadata.proto:L87]` carries `file`, `link`, `email`, and `line`.
- **Captured Git-source provenance** (verbatim, from a git scan of the same test repo), showing commit-level metadata:

```json
"SourceMetadata": { "Data": { "Git": {
  "commit": "400b240f153c4ab88372b9864d5d3eac9b6d7908",
  "file": "creds.txt",
  "email": "t <t@t.t>",
  "timestamp": "2026-06-26 20:17:53 +0000",
  "line": 1
} } }
```

  Filesystem findings carry `SourceType: 15`; Git findings carry `SourceType: 16`.

### Rationale

The JSON shape is defined entirely by the anonymous struct in `json.go`, so the captured finding's keys map 1:1 to that struct (the field order and names line up exactly). The deliberate absence of any `confidence` token across the printer, the Go result type, and the protobuf schema is strong, triangulated evidence that confidence is modeled as a boolean verification state rather than a numeric score. Location is always present via the source-specific `SourceMetadata.oneof`, which is why a filesystem finding reports `file` + `line` while a git finding reports `commit` / `file` / `email` / `timestamp` / `line`.


---

## 4. Repository Traversal & File Filtering

### Question

> "If I scan a test repo with mixed file types and check verbose logs, what does it reveal about how TruffleHog decides which files to scan versus skip?"

### Findings

**Conclusion: TruffleHog classifies files by extension/binary type and skips binary / ignored-extension files (and, separately, known false-positive matches) before or around content scanning. These decisions are visible in the verbose logs.**

**Skip helpers (`pkg/common/vars.go`) — two distinct maps, do not conflate them:**

- `ignoredExtensions` map `[pkg/common/vars.go:L10]` is consulted by `func SkipFile(filename string) bool` `[pkg/common/vars.go:L122]`, which returns true when the lower-cased extension is in `ignoredExtensions` (this set includes `gif`, `jpg`, `jpeg`, `png`, …).
- `binaryExtensions` map `[pkg/common/vars.go:L80]` is consulted by `func IsBinary(filename string) bool` `[pkg/common/vars.go:L129]`.
- In short: `SkipFile` → `ignoredExtensions`; `IsBinary` → `binaryExtensions`. They are separate maps serving separate checks.

**Git traversal (`pkg/sources/git/git.go`):**

- When the git diff marks a blob binary (`if diff.IsBinary` `[pkg/sources/git/git.go:L644]`): if `skipBinaries` (or the force flag) is set, it logs `skipping binary file` and continues `[pkg/sources/git/git.go:L648]`; otherwise the blob is routed through `HandleBinary` `[pkg/sources/git/git.go:L1232]`.
- Inside `HandleBinary`, the decision is logged at verbosity 5: it logs `handling binary file` `[pkg/sources/git/git.go:L1242]`, then if `common.SkipFile(path)` is true it logs `file contains ignored extension` and returns (skipping the file) `[pkg/sources/git/git.go:L1245]`.
- **Captured runtime proof** (`--log-level=5` git scan of the repo containing `image.png`; emitted at `info-5`):

```json
{"level":"info-5","logger":"trufflehog","msg":"handling binary file","commit":"400b240","path":"image.png"}
{"level":"info-5","logger":"trufflehog","msg":"file contains ignored extension","commit":"400b240","path":"image.png"}
```

**False-positive filtering (`pkg/detectors/falsepositives.go`):**

- Separately from *file* skipping, *result* filtering removes known false positives. `filterResults` calls `detectors.FilterKnownFalsePositives(...)` when false positives are not retained `[pkg/engine/engine.go:L1142]`.
- `FilterKnownFalsePositives` `[pkg/detectors/falsepositives.go:L177]` **never filters verified results** — they are appended unconditionally and the loop continues `[pkg/detectors/falsepositives.go:L188-L190]`. For *unverified* results, it logs at verbosity 4: `ctx.Logger().V(4).Info("Skipping result: false positive", "result", …, "reason", reason)` `[pkg/detectors/falsepositives.go:L194]`.
- The default term set `DefaultFalsePositives` = `{example, xxxxxx, aaaaaa, abcde, 00000, sample, *****}` `[pkg/detectors/falsepositives.go:L17]`; `IsKnownFalsePositive` returns the reason `"contains term: " + fp` when the secret contains such a term `[pkg/detectors/falsepositives.go:L98]`. So a seeded *unverified* secret whose value contains `example` yields a skip with `reason: contains term: example`.
- **Captured runtime proof** (the seeded `example-token.txt` value; emitted at `info-4`):

```json
{"level":"info-4","logger":"trufflehog","msg":"Skipping result: false positive","result":"ghp_exampleexampleexampleexampleexample1234","reason":"contains term: example"}
```

- **Caveat:** this default term-check does not apply to every detector. Some detectors override it via a `CustomFalsePositiveChecker` (interface defined at `[pkg/detectors/falsepositives.go:L25]`, selected by `GetFalsePositiveCheck` `[pkg/detectors/falsepositives.go:L70]`); for example, the URI detector implements its own `IsFalsePositive` `[pkg/detectors/uri/uri.go:L141]`. The primary, robust traversal evidence is the binary / ignored-extension skip above.

### Rationale

TruffleHog makes a cheap, deterministic *pre-scan* decision based on file extension / binary classification (`SkipFile` / `IsBinary`), so it never wastes detector work on non-text blobs like images — visible as the two `V(5)` log lines for `image.png`. A second, *post-detection* filter discards known false-positive matches at `V(4)` while always preserving verified results. Together these two mechanisms explain which files (and which results) are scanned versus skipped.


---

## 5. Detector Architecture & CLI Help

### Question

> "When I compile the project, are the detectors separate plugins or embedded modules? If I run the binary with a help flag, what information does it show about available detection capabilities?"

### Findings

**Conclusion: detectors are EMBEDDED, COMPILED modules implementing a common Go interface — NOT separate or dynamically-loaded plugins.**

- Every detector implements the `Detector` interface `[pkg/detectors/detectors.go:L19-L29]`:

```go
type Detector interface {
    FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) // L21
    Keywords() []string                                                       // L24
    Type() detectorspb.DetectorType                                           // L26
    Description() string                                                      // L28
}
```

- Optional companion interfaces let detectors opt into extra behavior: `CustomResultsCleaner` `[pkg/detectors/detectors.go:L37]`, `Versioner` `[pkg/detectors/detectors.go:L49]`, `EndpointCustomizer` `[pkg/detectors/detectors.go:L76]`, and `CloudProvider` `[pkg/detectors/detectors.go:L83]`.
- **No Go plugin system.** A tree-wide search for `plugin.Open` / `plugin.Lookup` across `pkg/` and `main.go` returns **0 matches**, and there is no `import "plugin"` anywhere in the Go sources. (The only textual occurrence of the bare string `"plugin"` is inside a MySQL analyzer test fixture, `pkg/analyzer/analyzers/mysql/expected_output.json`, which is data, not an import.) Combined with the 831 compile-time imports ↔ 845 detector directories from Section 1 and a single ~194 MB statically-linked binary, this proves detectors are embedded at build time, not loaded dynamically.

**CLI help (`main.go`, corroborated by captured `--help` / `--help-long`):**

- Source subcommands are kingpin `cli.Command(...)` definitions: `git` `[main.go:L93]`, `github` `[main.go:L106]`, `github-experimental` `[main.go:L124]`, `gitlab` `[main.go:L133]`, `filesystem` `[main.go:L143]`, `s3` `[main.go:L152]`, `gcs` `[main.go:L162]`, `syslog` `[main.go:L174]`, `circleci` `[main.go:L181]`, `docker` `[main.go:L184]`, `travisci` `[main.go:L188]`, `postman` `[main.go:L192]`, `elasticsearch` `[main.go:L216]`, `jenkins` `[main.go:L228]`, `huggingface` `[main.go:L234]`, plus `analyze` (registered via `analyzer.Command(cli)` `[main.go:L255]`, described in help as "Analyze API keys for fine-grained permissions information.").
- Detection-relevant **global flags** (`main.go`): `--json` / `-j` `[main.go:L55]`; `--concurrency` defaulting to `runtime.NumCPU()` `[main.go:L58]`; `--no-verification` `[main.go:L59]`; `--results` (accepts `verified, unknown, unverified, filtered_unverified`; defaults to `verified,unverified,unknown`) `[main.go:L61]`; `--allow-verification-overlap` `[main.go:L65]`; `--filter-unverified` `[main.go:L66]`; `--filter-entropy` ("Filter unverified results with Shannon entropy. Start with 3.0.") `[main.go:L67]`; `--config` `[main.go:L70]`; `--fail` ("Exit with code 183 if results are found.") `[main.go:L74]`; `--detector-timeout` `[main.go:L77]`; `--include-detectors` defaulting to `"all"` `[main.go:L81]`; `--exclude-detectors` `[main.go:L82]`.
- **Captured `--help-long` excerpt** (the Commands section, abbreviated):

```text
Commands:
  git [<flags>] <uri>
      Find credentials in git repositories.
  github [<flags>]
      Find credentials in GitHub repositories.
  filesystem [<flags>] [<path>...]
      Find credentials in a filesystem.
  s3 [<flags>]
      Find credentials in S3 buckets.
  ...
  analyze
      Analyze API keys for fine-grained permissions information.
```

  And `--help` renders the concurrency default for this host as `--concurrency=128  Number of concurrent workers.` (see Section 2 for why `128`).

### Rationale

"Plugin" implies dynamic loading at runtime (for example, Go's `plugin.Open`). The complete absence of any plugin import or call, the interface-based detector design compiled into a single binary, and the static import graph all show that detectors are *embedded modules*, not plugins. The `--help` / `--help-long` surface advertises detection capabilities through (a) the set of source subcommands and (b) the global detection flags — verification toggles, result-status selection, detector include/exclude, and entropy / false-positive filters — which is exactly what an operator uses to control the available detection capabilities.

---

## Summary

| # | Question (abbreviated) | One-line answer |
|---|------------------------|-----------------|
| 1 | Startup — detectors from files or compiled in? | **Compiled in** via static Go imports (`buildDetectorList()` / `DefaultDetectors()`); only *custom* detectors load from `--config`. Startup logs the engine/aho-corasick bootstrap at `V(4)`; there is no per-detector "registered" line. |
| 2 | HTTP client libs? Verification parallel or sequential? | **Yes** (`go-retryablehttp` + `net/http`); verification runs **in parallel** in an oversized DetectorWorkers pool (`concurrency × 8`), proven by `detector workers count=1024` vs `scanner workers count=128`. |
| 3 | JSON finding schema — verification, confidence, location? | Anonymous struct from `*ResultWithMetadata`: **has** `Verified` / `VerificationFromCache` / optional `VerificationError` and `SourceMetadata` location; **no confidence-score field** anywhere. |
| 4 | How are files chosen to scan vs skip? | Extension/binary classification (`SkipFile`→`ignoredExtensions`, `IsBinary`→`binaryExtensions`) skips binaries/ignored extensions at `V(5)`; known false positives are filtered post-detection at `V(4)` (verified results never filtered). |
| 5 | Plugins or embedded modules? What does help show? | **Embedded compiled modules** implementing the `Detector` interface (no `plugin.Open`); `--help`/`--help-long` lists 16 source subcommands plus global detection flags. |

