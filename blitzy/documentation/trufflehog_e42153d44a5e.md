# How TruffleHog Behaves Once the Go Binary Starts Up

> **What this document is.** A runtime walkthrough of what the `trufflehog` binary *does once it starts executing* during a minimal filesystem scan &mdash; **not** a file-by-file tour of the source tree. Every behavioral claim is backed by **actual, unedited log output** and the exact command that produced it; every code-level claim cites `file:line` at repository HEAD `e42153d44a5e5c37c1bd0c70e074781e9edcb760`. Anything not directly visible in the output is explicitly labeled **(inferred)**.
>
> **How the evidence was produced.** The binary was built from source and run under `--trace` (and, for contrast, `--debug`) against a tiny throwaway directory outside the repository. The complete captured logs appear verbatim below and are the basis for every answer.

## 1. Overview, Environment, and Exact Commands

### 1.1 The short answer (observed)

Once the binary starts, a single filesystem scan moves through six visible stages, all captured in the `--trace` log in section 1.6:

1. **Parse CLI flags** and select the `filesystem` sub-command &mdash; *configuration* (section 2).
2. **Assemble an `engine.Config`** whose detector list is the built-in default set (section 2).
3. **Construct the engine** &mdash; `NewEngine` then `setDefaults` then `initialize` &mdash; emitting `default engine options set` then `engine initialized` (section 3).
4. **Build the Aho-Corasick keyword prefilter** over the default detectors &mdash; `setting up aho-corasick core` then `set up aho-corasick core` (section 4).
5. **Start four worker pools** &mdash; scanner (128), detector (1024), verificationOverlap (128), notifier (128) &mdash; wired together by buffered channels (section 5).
6. **Stream the source through the pipeline** &mdash; `running source`, `enumerating source`, `chunking unit`, `scanning file` &mdash; then print a final `finished scanning` summary (section 5).

The four subsystems the reader asked about map directly onto these stages and are answered, observation-first, in sections 2 through 5.

### 1.2 Environment (for reproducibility)

| Property | Value | Note |
|---|---|---|
| Repository HEAD | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` | all `file:line` citations are pinned here |
| Platform | `linux/amd64` | |
| `runtime.NumCPU()` | **128** | Go-runtime CPU count on the investigation host; **it sizes every worker pool and channel buffer** below |
| Go toolchain | **go1.24.2** | validated as a real, canonical release (2025-04-01); matches `toolchain go1.24.2` [go.mod:5]; the module `go` directive is `go 1.23.1` [go.mod:3] (line 4 is blank) |

> **(observed)** `runtime.NumCPU() = 128` is not printed as a standalone line, but it is directly corroborated by the worker counts in section 1.6 &mdash; scanner `128`, detector `1024 = 128 x 8`, verificationOverlap `128`, notifier `128`. It is the single environment fact that makes every magnitude in this document reproducible.

### 1.3 Build command (observed)

The binary was built exactly as the Dockerfile does:

```bash
CGO_ENABLED=0 go build -o trufflehog .
```

- The Dockerfile sets `ENV CGO_ENABLED=0` [Dockerfile:5] and builds with `go build -o trufflehog .` [Dockerfile:9]. The Makefile dev recipes corroborate the same invocation style: `run` is `CGO_ENABLED=0 go run . git file://. --json` [Makefile:48-49] and `run-debug` adds `--log-level=2` [Makefile:51-52].
- **Result (observed):** exit code 0; a ~193 MB static binary named `trufflehog`.
- `./trufflehog --version` prints `trufflehog dev`. That `dev` string is the canonical default build identity, produced by the `--version` handler `cli.Version("trufflehog " + version.BuildVersion)` [main.go:270]. (As shown in section 7, the `dev` identity also causes the self-updater's fetcher to be nil'd.)
- The built binary is **git-ignored** (`.gitignore` contains a `trufflehog` entry), so building it does not dirty the working tree.

### 1.4 The two invocation commands (observed)

Canonical verbose run (the one this document is built around):

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

Contrast run (used only to demonstrate log-level gating in section 6):

```bash
./trufflehog --debug --no-update filesystem /tmp/scan_target
```

- `/tmp/scan_target` is a throwaway directory **outside the repository** holding two files: `a.txt` (41 bytes &mdash; it contains the well-known **AWS documentation example key** `AKIAIOSFODNN7EXAMPLE`, a public, non-functional placeholder that AWS publishes in its own documentation) and `b.txt` (39 bytes, benign). 41 + 39 = **80 bytes**, matching the final summary's `"bytes": 80`.
- `--no-update` keeps the run offline-safe (see section 7); `filesystem` is the minimal source command that needs only a local path &mdash; `filesystemScan = cli.Command("filesystem", "Find credentials in a filesystem.")` [main.go:143].

### 1.5 Empty stdout is *expected*, not a failure (observed)

**Observed:** `stdout` was **empty &mdash; zero findings.** The only content TruffleHog writes to `stdout` is secret findings; there were none here because the sole candidate, the AWS *documentation example* key, is filtered as a **known false positive**. Do **not** misread empty stdout as a crash or a misconfiguration: the run succeeded, as the final summary confirms (`"verified_secrets": 0, "unverified_secrets": 0`). All of the runtime signal lives on **stderr** (the structured log), shown next.

### 1.6 The complete observed `--trace` startup log (verbatim)

Command:

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

Structural skeleton of the captured `stderr` (the 20 distinct lines &mdash; 19 shown here plus the final summary further down):

```text
2026-07-13T15:40:55Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T15:40:55Z	info-4	trufflehog	default engine options set
2026-07-13T15:40:55Z	info-4	trufflehog	engine initialized
2026-07-13T15:40:55Z	info-4	trufflehog	setting up aho-corasick core
2026-07-13T15:40:55Z	info-4	trufflehog	set up aho-corasick core
2026-07-13T15:40:55Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T15:40:55Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T15:40:55Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T15:40:55Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T15:40:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "u6cEr", "with_units": true}
2026-07-13T15:40:55Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "u6cEr"}
2026-07-13T15:40:55Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/a.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/b.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/a.txt", "path": "/tmp/scan_target/a.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/b.txt", "path": "/tmp/scan_target/b.txt"}
2026-07-13T15:40:55Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/b.txt", "path": "/tmp/scan_target/b.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T15:40:55Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/a.txt", "path": "/tmp/scan_target/a.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

Immediately after, **exactly 128** identically-formatted lines follow &mdash; one per scanner worker &mdash; differing only by a random 5-character `scanner_worker_id` (from `common.RandomID(5)`). Three verbatim samples:

```text
2026-07-13T15:40:55Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OdVmX"}
2026-07-13T15:40:55Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "LMtWR"}
2026-07-13T15:40:55Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ejMYV"}
```

...and finally the summary line:

```text
2026-07-13T15:40:55Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 80, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.552437ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Total `stderr` = 148 lines = 20 distinct skeleton lines + 128 scanner `finished scanning chunks` lines.** Note the built-in corroboration: the count **128** of those scanner lines equals the scanner-worker pool size &mdash; an independent, observed confirmation of the scanner count.

> **Reading the log format.** Each structured line is tab-separated as `timestamp`, `info-N`, `trufflehog`, `message`, and an optional trailing `{json fields}` object. The `info-N` number is the go-logr verbosity `V(N)`; section 6 explains why `--trace` surfaces `info-0` through `info-5` while `--debug` stops at `info-2`. Note the first two lines are produced differently: the `trufflehog dev` identity is the structured version log emitted at `V(2)` by `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` [main.go:410], whereas the pig/key banner on the next line is **not** a structured entry at all &mdash; it is written straight to stderr by `fmt.Fprintf(os.Stderr, ...)` [main.go:498] (which is also why it carries no timestamp or `info-N` prefix).

## 2. (a) How configuration is handled

**Observed answer (lead):** Configuration is **CLI-flag-driven**. This run required **no config file**, and none was silently loaded &mdash; there is **no config-related log line** anywhere in section 1.6 because `--config` was not passed. The `filesystem` sub-command plus a directory path were the entire configuration.

**Command (observed):**

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

**Observed signal** &mdash; the first structured line reports the built binary's identity, and the source is then run with the parsed arguments (excerpt from section 1.6):

```text
2026-07-13T15:40:55Z	info-2	trufflehog	trufflehog dev
2026-07-13T15:40:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "u6cEr", "with_units": true}
2026-07-13T15:40:55Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "u6cEr"}
```

**Evidence and citations (code):**

- The CLI is a `kingpin` application created as `cli = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")` [main.go:47] and parsed by `cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))` [main.go:301]. The resulting `cmd` string routes execution to the filesystem scan.
- `filesystem` is a **peer** of the other source commands (`git`, `github`, `gitlab`, `s3`, and so on); it is declared as `filesystemScan = cli.Command("filesystem", "Find credentials in a filesystem.")` [main.go:143].
- The scan is assembled into an `engine.Config` value, `engConf := engine.Config{ ... }` [main.go:513]. Its detector list is set to **the defaults plus any user-supplied detectors**: `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` [main.go:519]. An in-code comment states this is deliberate &mdash; the engine is *always* configured with the default detector list, and user filters are *"only subtractive"* [main.go:514-517].
- The optional YAML custom-detector path is `func Read(filename string) (*Config, error)` [pkg/config/config.go:18], which parses input via `func NewYAML(input []byte) (*Config, error)` [pkg/config/config.go:27]. This path is only reached when `--config <file>` is supplied.

**Interpretation (observed to inferred):**

- **(observed)** No `--config` was passed and, correspondingly, the log is silent about configuration &mdash; the first meaningful line is the version identity, after which the source begins running and enumerating.
- **(inferred, from [main.go:513-519])** Because `Detectors` is built with `append(defaults.DefaultDetectors(), ...)`, a `--config` YAML can only **add** custom detectors on top of the always-present defaults; it cannot replace them. The absence of a config file therefore changes nothing about which default detectors load.

## 3. (b) How the scanning engine initializes

**Observed answer (lead):** Engine setup is bracketed by two `--trace` lines &mdash; `default engine options set` then `engine initialized` (both at `info-4`). Between choosing defaults and finishing initialization, the engine fixes its concurrency from `runtime.NumCPU()`, chooses its worker multipliers, allocates a small dedup cache, and creates the buffered channels that connect the pipeline.

**Command (observed):**

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

**Observed signal** (verbatim excerpt from section 1.6):

```text
2026-07-13T15:40:55Z	info-4	trufflehog	default engine options set
2026-07-13T15:40:55Z	info-4	trufflehog	engine initialized
```

**Flow and citations (code):** `NewEngine` [pkg/engine/engine.go:226] then `setDefaults` [pkg/engine/engine.go:336] then `initialize` [pkg/engine/engine.go:489].

- **`setDefaults` [engine.go:336]** resolves the runtime knobs and emits the first line:
  - Concurrency defaults to the host CPU count when unset: `numCPU := runtime.NumCPU()` [engine.go:338], assigned via `e.concurrency = numCPU` [engine.go:340]. **This is why every worker count below is a multiple of 128 (observed).**
  - `detectorWorkerMultiplier` defaults to **8** [engine.go:345]; `notificationWorkerMultiplier` defaults to **1** [engine.go:349]; `verificationOverlapWorkerMultiplier` defaults to **1** [engine.go:353].
  - Decoders default to the built-in chain when unset: guarded by `if len(e.decoders) == 0` [engine.go:357], it assigns `e.decoders = decoders.DefaultDecoders()` [engine.go:358] (4 decoders &mdash; see section 8.2).
  - It then emits `ctx.Logger().V(4).Info("default engine options set")` [engine.go:373] &mdash; the observed `info-4` line `default engine options set`.
- **`initialize` [engine.go:489]** allocates state and channels, then emits the second line:
  - A small **512-entry LRU** dedup cache: `const cacheSize = 512` [engine.go:491], then `cache, err := lru.New[...](cacheSize)` [engine.go:493].
  - Buffered channels sized from `var defaultChannelBuffer = runtime.NumCPU()` [engine.go:627], using multipliers defined in a `const` block inside `initialize` [engine.go:495-514]: `detectableChunksChan` is `defaultChannelBuffer x 50`, `verificationOverlapChunksChan` is `x 25`, and `results` is `x 50` (`resultsChanMultiplier = detectableChunksChanMultiplier`).
  - It then emits `ctx.Logger().V(4).Info("engine initialized")` [engine.go:521] &mdash; the observed `info-4` line `engine initialized`.

**Interpretation (observed to inferred):**

- **(observed)** The two `info-4` lines appear in order and only under `--trace`; they are hidden under `--debug` (section 6).
- **(inferred, from the initialization path)** TruffleHog is a **stateless batch engine** &mdash; there is no persistent database; the only in-run state is the transient 512-entry LRU cache used for decoder-type dedup [engine.go:491-493]. The absence of persistence is not logged, so this statement is inferred from the code path rather than directly observed.

## 4. (c) How detectors prepare themselves

**Observed answer (lead):** Detector preparation is the construction of an **Aho-Corasick keyword prefilter** over the default detector set. It is bracketed by two `--trace` lines &mdash; `setting up aho-corasick core` then `set up aho-corasick core` (both at `info-4`).

**Command (observed):**

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

**Observed signal** (verbatim excerpt from section 1.6):

```text
2026-07-13T15:40:55Z	info-4	trufflehog	setting up aho-corasick core
2026-07-13T15:40:55Z	info-4	trufflehog	set up aho-corasick core
```

**Evidence and citations (code):** those two lines are emitted at [engine.go:529] and [engine.go:531], bracketing the call `e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)` [engine.go:530].

- `func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core` [pkg/engine/ahocorasick/ahocorasickcore.go:141] builds two lookup maps &mdash; `keywordsToDetectors` and `detectorsByKey` (struct fields at [ahocorasickcore.go:133-134]) &mdash; by iterating each detector's `d.Keywords()` and lower-casing every keyword [ahocorasickcore.go:147-152].
- It then constructs the **Aho-Corasick trie** used as the prefilter: `prefilter: *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()` [ahocorasickcore.go:159], backed by the third-party library imported as `ahocorasick "github.com/BobuSumisu/aho-corasick"` [ahocorasickcore.go:7].
- The detectors passed in are the built-in default registry `func DefaultDetectors() []detectors.Detector` [pkg/engine/defaults/defaults.go:1704], assembled by `func buildDetectorList()` [pkg/engine/defaults/defaults.go:839-1702]. **Observed count: 831 default detectors** (see the note in section 8.2).

**Purpose (observed to inferred):**

- **(inferred, from [ahocorasickcore.go:242])** At scan time the prefilter runs first: `matches := ac.prefilter.Match(bytes.ToLower(chunkData))` [ahocorasickcore.go:242] cheaply decides *which* detectors' keywords are present in a chunk, so that only those detectors run their comparatively expensive regexes and verification. Building the trie once at startup is what makes that per-chunk shortcut possible. The `setting up` / `set up` bracket is observed; the per-chunk `Match` cost-avoidance is inferred from the code, because this benign two-file input prints no per-chunk prefilter line.

## 5. (d) How the components communicate during a basic run

**Observed answer (lead):** Four worker pools start up, and then work flows **source -> scanner -> detector -> notifier** over buffered channels. The pool sizes are printed directly:

```text
2026-07-13T15:40:55Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T15:40:55Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T15:40:55Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T15:40:55Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

followed by the source-side signals as the two files move through the pipeline:

```text
2026-07-13T15:40:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "u6cEr", "with_units": true}
2026-07-13T15:40:55Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "u6cEr"}
2026-07-13T15:40:55Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/a.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/b.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/a.txt", "path": "/tmp/scan_target/a.txt"}
2026-07-13T15:40:55Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "u6cEr", "unit_kind": "unit", "unit": "/tmp/scan_target/b.txt", "path": "/tmp/scan_target/b.txt"}
```

**Command (observed):**

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

**Evidence and citations (code):**

- The pools are launched by `func (e *Engine) startWorkers(ctx context.Context)` [pkg/engine/engine.go:646], which starts four kinds of workers, each logging its size at `V(2)`:
  - **scanner** &mdash; `ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)` [engine.go:663], giving `count: 128`.
  - **detector** &mdash; `numWorkers := e.concurrency * e.detectorWorkerMultiplier` [engine.go:676], logged at [engine.go:678], giving `count: 1024` (= 128 x 8).
  - **verificationOverlap** &mdash; `numWorkers := e.concurrency * e.verificationOverlapWorkerMultiplier` [engine.go:691], logged at [engine.go:693], giving `count: 128`.
  - **notifier** &mdash; `numWorkers := e.notificationWorkerMultiplier * e.concurrency` [engine.go:706], logged at [engine.go:708], giving `count: 128`.
- The pools are bridged by the buffered channels `detectableChunksChan`, `verificationOverlapChunksChan`, and `results`, all sized from `runtime.NumCPU` via `defaultChannelBuffer` [engine.go:627] (see section 3).
- **Source side:** the engine reads chunks from `func (s *SourceManager) Chunks() <-chan *Chunk` [pkg/sources/source_manager.go:259], the channel the scanner workers consume, while `func (s *SourceManager) Wait() error` [source_manager.go:267] blocks until the source completes. The observed source-manager lines map to: `running source ... "with_units": true` at `.Info` / info-0 [source_manager.go:402], `enumerating source` at `V(2)` [source_manager.go:531], and `chunking unit` at `V(3)` [source_manager.go:557] and [source_manager.go:603].
- **Filesystem source:** enumeration and chunking are driven by `func (s *Source) Chunks(...)` [pkg/sources/filesystem/filesystem.go:85], `func (s *Source) Enumerate(...)` [filesystem.go:202], and `func (s *Source) ChunkUnit(...)` [filesystem.go:242]; the observed `scanning file` line is emitted at `V(3)` by `fileCtx.Logger().V(3).Info("scanning file")` [filesystem.go:179].
- **End of pipeline:** the notifier workers hand results to the printer, which emits the final `info-0` `finished scanning` summary via `logger.Info("finished scanning", ...)` [main.go:566].

**Pipeline (observed structure):**

```mermaid
graph LR
    A[CLI parse + engine.Config<br/>main.go:301,513-519] --> B[NewEngine / setDefaults / initialize<br/>engine.go:226,336,489]
    B --> C[Build Aho-Corasick prefilter<br/>ahocorasickcore.go:141,159]
    C --> D[Start 4 worker pools<br/>engine.go:646-708]
    D --> E[SourceManager.Chunks<br/>source_manager.go:259]
    E --> F[Scanner workers: decode + keyword prefilter]
    F --> G[detectableChunksChan<br/>NumCPU x 50]
    G --> H[Detector workers x8<br/>FromData + verify]
    H --> I[results chan<br/>NumCPU x 50]
    I --> J[Notifier workers to printer<br/>finished scanning]
```

**Cross-check (observed against in-repo docs):** `docs/concurrency.md` diagrams `e.startWorkers()` fanning into `startScannerWorkers`, `startVerificationOverlapWorkers`, `startDetectorWorkers`, and `startNotifierWorkers` with the `e.detectableChunksChan` fan-out, and `docs/process_flow.md` diagrams the four-stage *Source Decomposition -> Detector Matching -> Secret Detection -> Result Notification* flow. Both match the observed log sequence exactly.

## 6. Why `--trace` reveals more than `--debug` (log-level gating)

**Observed answer (lead):** `--debug` prints only `info-0` through `info-2`. It **hides** the `info-4` engine-init / Aho-Corasick lines, the `info-3` chunking / scanning-file lines, and the `info-5` `dataErrChan` lines. That is precisely why **`--trace`, not `--debug`, is required** to observe engine initialization and detector preparation.

**Command (observed):**

```bash
./trufflehog --debug --no-update filesystem /tmp/scan_target
```

**Complete, unedited `--debug` `stderr` (15 lines):**

```text
2026/07/13 15:41:20 [updater parent] run
2026/07/13 15:41:20 [updater parent] starting /tmp/blitzy/trufflehog/trufflehog_e42153d44a5e_d5780a/trufflehog
2026/07/13 15:41:21 [updater child#1] run
2026/07/13 15:41:21 [updater child#1] start program
2026-07-13T15:41:21Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T15:41:21Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T15:41:21Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T15:41:21Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T15:41:21Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T15:41:21Z	info-0	trufflehog	running source	{"source_manager_worker_id": "JNDXP", "with_units": true}
2026-07-13T15:41:21Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "JNDXP"}
2026-07-13T15:41:21Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 80, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.560255ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
2026/07/13 15:41:21 [updater parent] prog exited with 0
```

Compared with section 1.6, this `--debug` run has **no** `default engine options set`, `engine initialized`, `setting up aho-corasick core`, `set up aho-corasick core`, `chunking unit`, `scanning file`, or `dataErrChan closed` lines. The engine still performs all of that work &mdash; those lines simply sit below the visible verbosity threshold.

**Mechanism and citations (code):**

- `--trace` maps to `log.SetLevel(5)` [main.go:305-306] and `--debug` maps to `log.SetLevel(2)` [main.go:307-308]; both flags are declared hidden &mdash; `debug` [main.go:51] and `trace` [main.go:52] &mdash; and parsed by `kingpin.MustParse` [main.go:301].
- `func SetLevel(level int8)` [pkg/log/level.go:21] delegates to `SetLevelForControl` [pkg/log/level.go:26], which **negates** the level: `control.SetLevel(zapcore.Level(-level))` [pkg/log/level.go:30]. So `SetLevel(5)` produces an enabled zap level of `-5` (surfacing `V(0)` through `V(5)`, i.e. `info-0` through `info-5`), while `SetLevel(2)` produces enabled level `-2` (surfacing only `info-0` through `info-2`). **This single negation is the entire gating mechanism.**
- The logger itself is built by `func New(service string, configs ...logConfig)` &mdash; `log.New("trufflehog", ...)` [pkg/log/log.go:28] &mdash; a Zap backend wrapped by go-logr, with global redaction via `WithGlobalRedaction()` [pkg/log/log.go:183]; the console sink is used unless `--json` is passed.

**Tie-out (observed levels to emitting code):**

- `info-0` &mdash; `running source` [source_manager.go:402] and `finished scanning` [main.go:566].
- `info-2` &mdash; the version line [main.go:410], the four `starting ... workers` lines [engine.go:663, 678, 693, 708], and `enumerating source` [source_manager.go:531].
- `info-3` &mdash; `chunking unit` [source_manager.go:557, 603] and `scanning file` [filesystem.go:179].
- `info-4` &mdash; `default engine options set` [engine.go:373], `engine initialized` [engine.go:521], `setting up` / `set up aho-corasick core` [engine.go:529, 531], and `finished scanning chunks` [engine.go:840].
- `info-5` &mdash; `dataErrChan closed, all chunks processed` [pkg/handlers/handlers.go:413].

Everything at `info-3` and above is exactly what `--debug` drops.

## 7. Overseer / self-update nuance (observed &mdash; corrects a common misconception)

**Observed:** the `--debug` output (section 6) shows overseer `[updater parent]` and `[updater child#1]` fork lines, whereas the `--trace` output (section 1.6) does not. The precise, cited explanation:

- `overseer.RunErr(updateCfg)` [main.go:364] runs the parent-to-child supervisor **unconditionally** &mdash; the only thing that skips it entirely is the hidden `--local-dev` flag [main.go:54], checked at `if *localDev` [main.go:340].
- Both the `dev` build (`if version.BuildVersion == "dev" { updateCfg.Fetcher = nil }` [main.go:360-361]) and `--no-update` (`if !*noUpdate { ... }` [main.go:356]) only set `updateCfg.Fetcher = nil`. They disable the actual update **download** &mdash; **not** the supervisor process itself.
- Overseer's own debug prints are gated by `Debug: *debug` [main.go:350], so they appear under `--debug` (in the standard-library `log` format, e.g. `2026/07/13 ... [updater parent] run`) and are silent under `--trace`.

**Therefore (precise):** it is **incorrect** to say the `dev` build "disables overseer." The supervisor still runs and still forks a child (visible in the `--debug` log); the `dev` and `--no-update` conditions merely **nil the fetcher** so that no update is downloaded.

## 8. Stability, Determinism, and Observed Magnitudes

### 8.1 Stability across at least two runs (observed)

- **Three** `--trace` runs each produced the **identical 148-line skeleton**; **two** `--debug` runs each produced the **identical 15-line output**. The startup *structure* is deterministic.
- Only volatile fields differ from run to run:
  - **Random worker IDs** &mdash; the `source_manager_worker_id` and the 128 `scanner_worker_id` values, from `common.RandomID(5)`.
  - **`scan_duration`** &mdash; observed `3.552437ms`, `3.710438ms`, and `3.533323ms` (sub-millisecond scale).
  - **File processing order** &mdash; `a.txt` versus `b.txt` may be chunked / scanned in either order, a concurrency artifact of the worker pools.

### 8.2 Observed magnitudes (host `runtime.NumCPU() = 128`)

| Quantity | Observed value | Source of value (cite) |
|---|---|---|
| Scanner workers | 128 | `= e.concurrency`, which defaults to `runtime.NumCPU()`; log [engine.go:663]; default set in `setDefaults` [engine.go:338, 340] |
| Detector workers | 1024 | `= e.concurrency x e.detectorWorkerMultiplier`, multiplier defaults to **8**; `numWorkers` [engine.go:676]; default [engine.go:345]; log [engine.go:678] |
| verificationOverlap workers | 128 | `= e.concurrency x e.verificationOverlapWorkerMultiplier` (multiplier = 1) [engine.go:691]; default [engine.go:353]; log [engine.go:693] |
| Notifier workers | 128 | `= e.notificationWorkerMultiplier x e.concurrency` (multiplier = 1) [engine.go:706]; default [engine.go:349]; log [engine.go:708] |
| Default detectors loaded | **831** | `len(DefaultDetectors())` [pkg/engine/defaults/defaults.go:1704] &mdash; measured at runtime (see note) |
| Default decoders | 4 | `len(DefaultDecoders())`, assigned in `setDefaults` [engine.go:358] |
| chunks / bytes | 2 / 80 | final `finished scanning` line |
| scan_duration | ~3.5 ms | final line (varies run to run, sub-millisecond) |
| verified / unverified secrets | 0 / 0 | final line (AWS documentation example key filtered) |

> **Detector-count note (observed).** `len(DefaultDetectors())` measured **831** at runtime with go1.24.2 at this HEAD. Report **831** as the authoritative *loaded-default* count. A broader "845+" figure that appears in project material is a **catalog** count, not the loaded-default count; a static count of the entries in `buildDetectorList()` [pkg/engine/defaults/defaults.go:839-1702] brackets and corroborates 831.

## Appendix &mdash; Citation Index (pinned to HEAD `e42153d44a5e...`)

- **Startup / CLI (`main.go`):** kingpin app [47]; hidden flags `debug` [51], `trace` [52], `local-dev` [54]; `filesystem` command [143]; `--version` handler [270]; parse [301]; trace/debug level mapping [305-308]; overseer block [340, 350, 356, 360-361, 364]; version log line [410]; banner [498]; `engConf` [513] with the subtractive-filters comment [514-517] and detectors append [519]; final summary [566].
- **Engine (`pkg/engine/engine.go`):** `NewEngine` [226]; `setDefaults` [336] (NumCPU [338, 340]; multipliers [345, 349, 353]; decoders guard/assign [357, 358]; log [373]); `initialize` [489] (LRU [491, 493]; channel const block [495-514]; log [521]); Aho-Corasick bracket [529-531]; `defaultChannelBuffer` [627]; `startWorkers` [646] with per-pool logs [663, 678, 693, 708] and counts [676, 691, 706]; `finished scanning chunks` [840].
- **Detectors:** `pkg/engine/ahocorasick/ahocorasickcore.go` &mdash; import [7], maps [133-134], `NewAhoCorasickCore` [141], keyword loop [147-152], prefilter trie [159], `Match` [242]; `pkg/engine/defaults/defaults.go` &mdash; `buildDetectorList` [839-1702], `DefaultDetectors` [1704].
- **Config (`pkg/config/config.go`):** `Read` [18], `NewYAML` [27].
- **Sources:** `pkg/sources/source_manager.go` &mdash; `Chunks` [259], `Wait` [267], `running source` [402], `enumerating source` [531], `chunking unit` [557, 603]; `pkg/sources/filesystem/filesystem.go` &mdash; `Chunks` [85], `scanning file` [179], `Enumerate` [202], `ChunkUnit` [242].
- **Logging:** `pkg/log/level.go` &mdash; `SetLevel` [21], `SetLevelForControl` [26], negation [30]; `pkg/log/log.go` &mdash; `New` [28], `WithGlobalRedaction` [183]; `pkg/handlers/handlers.go` &mdash; `dataErrChan closed` [413].
- **Build / toolchain:** `Dockerfile` [5, 9]; `Makefile` [48-49, 51-52]; `go.mod` [3, 5].
