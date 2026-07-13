# How TruffleHog Behaves Once the Go Binary Starts Up

> **What this document is.** A runtime walkthrough of what the `trufflehog` binary *does once it starts executing* during a minimal filesystem scan &mdash; **not** a file-by-file tour of the source tree. Every behavioral claim is backed by **actual, unedited log output** and the exact command that produced it; every code-level claim cites `file:line` at repository HEAD `e42153d44a5e5c37c1bd0c70e074781e9edcb760`. Three labels are used precisely throughout: **(observed)** = present in the captured log output (or an architect runtime measurement); **(derived)** = read directly from the cited source at this HEAD but **not** surfaced as a log line in this run; **(inferred)** = reasoned from the code path but neither logged nor a direct source quote. Anything not visible in the captured output is therefore marked **(derived)** or **(inferred)** &mdash; never **(observed)**.
>
> **How the evidence was produced.** The binary was built from source and run under `--trace` (and, for contrast, `--debug`) against a tiny throwaway directory outside the repository. The captured logs are reproduced verbatim below and are the basis for every answer: the `--debug` transcript is shown **complete** (all 15 lines), while the higher-volume `--trace` evidence is supplied as its **complete structural block**, **three exact scanner-worker samples**, the **exact scanner-line count**, and the **exact final summary line** &mdash; the 128 per-worker `finished scanning chunks` lines are byte-identical apart from a random ID, so three representative lines are shown rather than reproducing all 128.

## 1. Overview, Environment, and Exact Commands

### 1.1 The short answer

Once the binary starts, a single filesystem scan moves through six stages. Stages 3&ndash;6 are **(observed)** &mdash; each corresponds to a specific log line in the `--trace` transcript of section 1.6. Stages 1&ndash;2 are **(derived)** setup work that runs *before* any subsystem log line and therefore has no dedicated entry of its own:

1. **Parse CLI flags** and select the `filesystem` sub-command &mdash; *configuration* (section 2). **(derived)** &mdash; the parse itself emits no dedicated line, though the `trufflehog dev` version line (`info-2`) that follows it is **(observed)**.
2. **Assemble an `engine.Config`** whose detector list is the built-in default set (section 2). **(derived, from [main.go:513-519])** &mdash; config assembly emits no log line of its own.
3. **Construct the engine** &mdash; `NewEngine` then `setDefaults` then `initialize` &mdash; emitting `default engine options set` then `engine initialized` (section 3). **(observed)**
4. **Build the Aho-Corasick keyword prefilter** over the default detectors &mdash; `setting up aho-corasick core` then `set up aho-corasick core` (section 4). **(observed)**
5. **Start four worker pools** &mdash; scanner (128), detector (1024), verificationOverlap (128), notifier (128) &mdash; wired together by buffered channels (section 5). **(observed)**
6. **Stream the source through the pipeline** &mdash; `running source`, `enumerating source`, `chunking unit`, `scanning file` &mdash; then a final `finished scanning` summary is logged (section 5). **(observed)**

The four subsystems the reader asked about map directly onto these stages and are answered, observation-first, in sections 2 through 5.

### 1.2 Environment (for reproducibility)

| Property | Value | Note |
|---|---|---|
| Repository HEAD | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` | all `file:line` citations are pinned here |
| Platform | `linux/amd64` | |
| `runtime.NumCPU()` | **128** | Go-runtime logical-CPU count on the investigation host &mdash; the **authoritative** value that **sizes every worker pool and channel buffer** below |
| `nproc --all` | **128** | Full logical-CPU count on the investigation host, matching `runtime.NumCPU()`, `/proc/cpuinfo` (128 processors), and `Cpus_allowed_list=0-127`. **Plain `nproc` may report a smaller, cgroup-capped value** (e.g. `4` in a CPU-limited container) even though `nproc --all` / `runtime.NumCPU()` report **128**; the Go-runtime value &mdash; not plain `nproc` &mdash; governs the magnitudes below |
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
- The built binary is **git-ignored** &mdash; `.gitignore` lists a `trufflehog` entry at [.gitignore:7] &mdash; so building it does not dirty the working tree.

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
- `--no-update` disables **only** the self-updater's binary **download** &mdash; it is **not** an offline guarantee. Secret **verification remains enabled by default** in this run (`Verify: !*noVerification` [main.go:520], where the `--no-verification` flag defaults to false [main.go:59]), and filesystem chunks are a verifiable source (`fileSystemSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU())` [pkg/engine/filesystem.go:33]). This particular benign target simply never produced a live verification candidate (see section 1.5), and the exact updater mechanism is dissected in section 7. `filesystem` is the minimal source command that needs only a local path &mdash; `filesystemScan = cli.Command("filesystem", "Find credentials in a filesystem.")` [main.go:143].

### 1.5 Empty stdout is *expected*, not a failure (observed)

**Observed:** `stdout` was **empty &mdash; zero findings.** **In this plain-output `filesystem` scan**, the only thing written to `stdout` is secret findings (other modes of the binary &mdash; e.g. `--version` or `--help` &mdash; print their output to **stderr**, not `stdout`, as observed: `--version` yields empty stdout with `trufflehog dev` on stderr, and `--help` yields empty stdout with 4976 bytes on stderr; but this run invoked neither). There were none here because `a.txt` holds an AWS access-key **ID** (`AKIAIOSFODNN7EXAMPLE`, matched by `idPat` [pkg/detectors/aws/access_keys/accesskey.go:65]) with **no accompanying 40-character secret**. The AWS detector appends a result &mdash; `results = append(results, s1)` [pkg/detectors/aws/access_keys/accesskey.go:207] &mdash; *only from inside* the `for secretMatch := range secretMatches` loop [accesskey.go:131], and `secretMatches` is built from `aws.SecretPat` [accesskey.go:115-116], which requires a 40-char `[A-Za-z0-9+/]` run [pkg/detectors/aws/common.go:10]. That run is absent from `a.txt`, so `secretMatches` is empty, the inner loop body never executes, and no `(id, secret)` verification candidate is ever formed **(derived)**. (The hash-shaped false-positive filter `FalsePositiveSecretPat` [pkg/detectors/aws/utils.go:47] is checked at [accesskey.go:202] *inside* that same loop and operates on a matched **secret**, so it is never reached for this input; and the literal `AKIAIOSFODNN7EXAMPLE` appears in **no** false-positive list anywhere in the tree at this HEAD &mdash; `git grep` returns no matches.) Do **not** misread empty stdout as a crash or a misconfiguration: the run succeeded, as the final summary confirms (`"verified_secrets": 0, "unverified_secrets": 0`). All of the runtime signal lives on **stderr** (the structured log), shown next.

> **Operational-safety nuance (derived, from [main.go:59], [main.go:520], [pkg/engine/filesystem.go:33], and [engine.go:1070-1113]).** Verification is on by default and runs *before* false-positive filtering &mdash; `e.verificationCache.FromData(ctx, data.detector.Detector, data.chunk.Verify, ...)` [engine.go:1070] executes ahead of `results = e.filterResults(ctx, data.detector, results)` [engine.go:1113]. So a real, unfiltered credential in a scan target *could* trigger a live provider request **even under `--no-update`**. The switch that actually guarantees provider-offline scanning is the separate `--no-verification` (which sets `Verify` to false); it was **not** used in the captured runs. `--no-update` and `--no-verification` are independent flags.

### 1.6 The supplied `--trace` startup evidence (verbatim)

Command:

```bash
./trufflehog --trace --no-update filesystem /tmp/scan_target
```

The **complete structural block** of the captured `stderr` (all 20 distinct lines &mdash; 19 shown here, plus the final summary line reproduced further down). This is the full skeleton; only the 128 near-identical per-scanner lines that follow it are sampled rather than reproduced in full:

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

Immediately after, **exactly 128** identically-formatted lines follow &mdash; one per scanner worker &mdash; differing only by a random 5-character `scanner_worker_id` (from `common.RandomID(5)` [engine.go:667]). The 125 not shown carry no information beyond their random IDs; **three exact samples** are reproduced here, with the exact count and the final summary line following:

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

### 1.7 Provenance, reproducibility, and cleanup

- **Provenance (observed).** Every log block in this document was captured during the investigation run of the binary built at HEAD `e42153d44a5e5c37c1bd0c70e074781e9edcb760` on `linux/amd64` with go1.24.2, and is reproduced verbatim; no output was re-derived, re-formatted, or edited.
- **Exit status (observed).** Both the `--trace` and the `--debug` invocations exited `0`.
- **Cleanup and final clean state (observed).** The `/tmp/scan_target` directory and any temporary measurement harness were created **outside** the repository tree and removed after the investigation; the compiled `trufflehog` binary is git-ignored [.gitignore:7]. A final `git status --porcelain` was **empty** &mdash; the source tree was left byte-for-byte unchanged, as the read-only mandate requires.
- **Detector-count methods (observed).** `len(DefaultDetectors())` = **831** was confirmed two independent ways plus a static cross-check; the methods are itemized in the section 8.2 note.
- **Non-secret path note (observed).** The `/tmp/blitzy/trufflehog/trufflehog_e42153d44a5e_d5780a/trufflehog` path shown in the `--debug` transcript (section 6) is a volatile, environment-specific working-directory path printed by the overseer supervisor. It contains **no secret** and is expected to differ across environments and runs.


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
- The scan is assembled into an `engine.Config` value, `engConf := engine.Config{ ... }` [main.go:513]. Its detector list is set to **the defaults plus any user-supplied detectors**: `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` [main.go:519]. An in-code comment states this is deliberate &mdash; the engine is *always* configured with the default detector list, and user filters are *"only subtractive"* [main.go:515-518] (that comment sits between `Concurrency: *concurrency` [main.go:514] and the `Detectors:` append [main.go:519]).
- The optional YAML custom-detector path is `func Read(filename string) (*Config, error)` [pkg/config/config.go:18], which parses input via `func NewYAML(input []byte) (*Config, error)` [pkg/config/config.go:27]. This path is only reached when `--config <file>` is supplied.

**Interpretation (observed to derived):**

- **(observed)** No config-related log line appears anywhere in section 1.6 &mdash; the first meaningful line is the version identity, after which the source begins running and enumerating.
- **(derived, from [main.go:460-463])** That silence reflects the code path: a config file is read **only** when `--config` is supplied &mdash; `conf := &config.Config{}` then `if *configFilename != "" { conf, err = config.Read(*configFilename) }` [main.go:460-463]. Because `--config` was not passed, the YAML path (`config.Read` [pkg/config/config.go:18] &rarr; `config.NewYAML` [pkg/config/config.go:27]) is never entered; no config is *implicitly* loaded. (The absence of a log line is observed; the conclusion that no implicit load occurred is read from this code path, hence derived.)
- **(derived, from [main.go:519])** Because `Detectors` is built with `append(defaults.DefaultDetectors(), conf.Detectors...)`, a `--config` YAML can only **add** custom detectors on top of the always-present defaults; it cannot replace them. The absence of a config file therefore changes nothing about which default detectors load.

## 3. (b) How the scanning engine initializes

**Observed answer (lead):** Engine setup is bracketed by two `--trace` lines &mdash; `default engine options set` then `engine initialized` (both at `info-4`). Between filling in defaults and finishing initialization, the engine confirms its concurrency (already supplied as **128** by the CLI flag &mdash; see below), chooses its worker multipliers, allocates a small dedup cache, and creates the buffered channels that connect the pipeline.

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
  - **Concurrency = 128 comes from the CLI flag, not the engine fallback (observed + derived).** The canonical source is the `--concurrency` flag, whose default is the host CPU count: `concurrency = cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()` [main.go:58]. That value is passed straight into the engine config as `Concurrency: *concurrency` [main.go:514], so `e.concurrency` is already **128** before `setDefaults` runs. The `setDefaults` block `if e.concurrency == 0 { numCPU := runtime.NumCPU(); ...; e.concurrency = numCPU }` [engine.go:337-340] is therefore only a **fallback for zero-valued (programmatic) configurations** and is **not executed on the CLI path**. **Observed proof:** that fallback would log `ctx.Logger().Info("No concurrency specified, defaulting to max", "cpu", numCPU)` [engine.go:339] at `info-0`, and **no such line appears** anywhere in section 1.6 &mdash; confirming the value came from the flag default, not the fallback. Either way the number resolves to `runtime.NumCPU()` = 128, which is why every worker count below is a multiple of 128.
  - `detectorWorkerMultiplier` defaults to **8** [engine.go:345]; `notificationWorkerMultiplier` defaults to **1** [engine.go:349]; `verificationOverlapWorkerMultiplier` defaults to **1** [engine.go:353].
  - Decoders default to the built-in chain when unset: guarded by `if len(e.decoders) == 0` [engine.go:357], it assigns `e.decoders = decoders.DefaultDecoders()` [engine.go:358]. `DefaultDecoders()` returns exactly **4** decoders &mdash; `UTF8`, `Base64`, `UTF16`, `EscapedUnicode` [pkg/decoders/decoders.go:8-15] (see section 8.2).
  - It then emits `ctx.Logger().V(4).Info("default engine options set")` [engine.go:373] &mdash; the observed `info-4` line `default engine options set`.
- **`initialize` [engine.go:489]** allocates state and channels, then emits the second line:
  - A small **512-entry LRU** dedup cache: `const cacheSize = 512` [engine.go:491], then `cache, err := lru.New[...](cacheSize)` [engine.go:493].
  - Buffered channels sized from `var defaultChannelBuffer = runtime.NumCPU()` [engine.go:627], using multipliers defined in a `const` block inside `initialize` [engine.go:495-514]: `detectableChunksChan` is `defaultChannelBuffer x 50`, `verificationOverlapChunksChan` is `x 25`, and `results` is `x 50` (`resultsChanMultiplier = detectableChunksChanMultiplier`).
  - It then emits `ctx.Logger().V(4).Info("engine initialized")` [engine.go:521] &mdash; the observed `info-4` line `engine initialized`.

**Interpretation (observed to derived):**

- **(observed)** The two `info-4` lines appear in order and only under `--trace`; they are hidden under `--debug` (section 6).
- **(derived, from the initialization path)** TruffleHog is a **stateless batch tool** &mdash; there is **no persistent database or on-disk state** in this path. That does not mean the engine holds only one thing in memory: the `Engine` struct [engine.go:161-223] carries substantial *transient* runtime state &mdash; the three buffered channels `results` / `detectableChunksChan` / `verificationOverlapChunksChan` [engine.go:191-193], four `sync.WaitGroup`s (`workersWg`, `verificationOverlapWg`, `wgDetectorWorkers`, `WgNotifier`), run metrics and result counters, the results dispatcher, the detector/decoder slices, a verification cache, and the source manager. The **512-entry LRU** [engine.go:491-493] is just **one** of those transient structures &mdash; specifically the decoder-type dedup cache. The claim being made is narrow: no *persistent* store is used (that absence is not logged, hence derived from the code path), while the LRU size 512 is a direct source constant.

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

**Evidence and citations (code):** those two lines are emitted at [engine.go:529] and [engine.go:531], bracketing the call `e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)` [engine.go:530]. (The two bracket lines are **observed**; the internal construction steps below are **derived** from the cited source, since they are not individually logged.)

- `func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core` [pkg/engine/ahocorasick/ahocorasickcore.go:141] builds two lookup maps &mdash; `keywordsToDetectors` and `detectorsByKey` (struct fields at [ahocorasickcore.go:133-134]) &mdash; by iterating each detector's `d.Keywords()` and lower-casing every keyword [ahocorasickcore.go:147-152].
- It then constructs the **Aho-Corasick trie** used as the prefilter: `prefilter: *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()` [ahocorasickcore.go:159], backed by the third-party library imported as `ahocorasick "github.com/BobuSumisu/aho-corasick"` [ahocorasickcore.go:7].
- The detectors passed in are the built-in default registry `func DefaultDetectors() []detectors.Detector` [pkg/engine/defaults/defaults.go:1704], assembled by `func buildDetectorList()` [pkg/engine/defaults/defaults.go:839-1702]. **Measured count: 831 default detectors** &mdash; a runtime measurement of `len(DefaultDetectors())`, confirmed two independent ways plus a static cross-check (see the note in section 8.2).

**Purpose (observed to inferred):**

- **(inferred, from [ahocorasickcore.go:242])** At scan time the prefilter runs first: `matches := ac.prefilter.Match(bytes.ToLower(chunkData))` [ahocorasickcore.go:242] cheaply decides *which* detectors' keywords are present in a chunk, so that only those detectors run their comparatively expensive regexes and verification. Building the trie once at startup is what makes that per-chunk shortcut possible. The `setting up` / `set up` bracket is observed; the per-chunk `Match` cost-avoidance is inferred from the code, because this benign two-file input prints no per-chunk prefilter line.

## 5. (d) How the components communicate during a basic run

**Observed answer (lead):** Four worker pools start up (observed &mdash; the four count lines below), then work flows over buffered channels. The common path is **source -> scanner -> detector -> notifier**; additionally the scanner has **two** outgoing paths (derived from the source and traced below &mdash; the single-file target here does not exercise the overlap branch): single-detector chunks go **directly** to the detector pool, while chunks matched by **multiple** detectors detour through the **verificationOverlap** pool first, which then feeds them back into the detector pool. The pool sizes are printed directly:

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
- **Scanner workers &mdash; two outgoing paths (derived).** Each scanner worker `func (e *Engine) scannerWorker(ctx context.Context)` [engine.go:777] ranges over `e.ChunksChan()` [engine.go:781], decodes each chunk, and runs the Aho-Corasick prefilter `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(...)` [engine.go:795]. It then **branches**:
  - *Multi-detector chunks* (`if len(matchingDetectors) > 1 && !e.verificationOverlap` [engine.go:796]) are sent to `e.verificationOverlapChunksChan` [engine.go:798], then `continue` skips the direct path &mdash; this decides *which* single detector will own verification when several detectors match one chunk.
  - *The direct path* (the `for _, detector := range matchingDetectors` loop [engine.go:807]) sets the per-chunk verify flag via `e.shouldVerifyChunk(...)` [engine.go:808] and sends to `e.detectableChunksChan` [engine.go:810].
  Each scanner worker logs `finished scanning chunks` at `V(4)` [engine.go:840] as its input drains &mdash; these are the 128 sampled `finished scanning chunks` lines noted in section 1.6.
- **verificationOverlap workers (derived).** `func (e *Engine) verificationOverlapWorker(ctx context.Context)` [engine.go:924] ranges over `e.verificationOverlapChunksChan` [engine.go:932], resolves the detector overlap, and **feeds the chunk back** into `e.detectableChunksChan` [engine.go:1014]. The overlap pool is therefore a *branch that rejoins the direct path*, not a separate pipeline exit.
- **Detector workers (derived).** `func (e *Engine) detectorWorker(ctx context.Context)` [engine.go:1036] ranges over `e.detectableChunksChan` [engine.go:1037], runs detection/verification via `e.verificationCache.FromData(...)` [engine.go:1070] and false-positive filtering via `e.filterResults(...)` [engine.go:1113], then emits any findings onto the `results` channel.
- **Per-result output vs the final summary &mdash; two distinct sinks (derived).** The notifier workers `func (e *Engine) notifierWorker(ctx context.Context)` [engine.go:1189] range over `e.ResultsChan()` [engine.go:1190] and dispatch **each individual finding** via `e.dispatcher.Dispatch(ctx, result)` [engine.go:1229]; the default dispatcher is a `PrinterDispatcher` [engine.go:86-94] that prints findings to **stdout**. In this run there were zero results, so the printer emitted **nothing** (empty stdout, section 1.5). The final `info-0` `finished scanning` line is **not** produced by the notifier/printer &mdash; it is logged by `run()`'s main logger on **stderr** via `logger.Info("finished scanning", ...)` [main.go:566-574], **after** `runSingleScan` [main.go:546] (which calls `eng.Finish` [main.go:950]) has returned. So even with zero findings the printer is silent while the summary is still logged.
- **Ordered shutdown &mdash; `Finish` [engine.go:723] (derived).** Channels are closed in dependency order so no worker writes to a closed channel: `e.sourceManager.Wait()` [engine.go:726] (source done), `e.workersWg.Wait()` [engine.go:728] (scanners done), then `close(e.verificationOverlapChunksChan)` [engine.go:730] + `e.verificationOverlapWg.Wait()` [engine.go:731], then `close(e.detectableChunksChan)` [engine.go:733] + `e.wgDetectorWorkers.Wait()` [engine.go:734], then `close(e.results)` [engine.go:736] + `e.WgNotifier.Wait()` [engine.go:737].

**Pipeline (derived structure, from the cited source):**

```mermaid
graph LR
    A[CLI parse + engine.Config<br/>main.go:301,513-519] --> B[NewEngine / setDefaults / initialize<br/>engine.go:226,336,489]
    B --> C[Build Aho-Corasick prefilter<br/>ahocorasickcore.go:141,159]
    C --> D[Start 4 worker pools<br/>engine.go:646-708]
    D --> E[SourceManager.Chunks<br/>source_manager.go:259]
    E --> F[Scanner workers: decode +<br/>FindDetectorMatches prefilter<br/>engine.go:777,795]
    F -->|"single detector: engine.go:810"| G[detectableChunksChan<br/>NumCPU x 50]
    F -->|"multiple detectors: engine.go:798"| K[verificationOverlapChunksChan<br/>NumCPU x 25]
    K --> L[verificationOverlap workers<br/>engine.go:924]
    L -->|"feeds back: engine.go:1014"| G
    G --> H[Detector workers x8:<br/>FromData verify + filterResults<br/>engine.go:1036,1070,1113]
    H --> I[results chan<br/>NumCPU x 50]
    I --> J[Notifier workers to PrinterDispatcher:<br/>per-result findings to stdout<br/>engine.go:1189,1229]
    D --> N[Finish: ordered close/wait<br/>engine.go:723-737]
    N -.->|"after runSingleScan returns"| M[main logger on stderr:<br/>finished scanning summary<br/>main.go:566-574]
```

**Cross-check (derived, against in-repo docs).** `docs/concurrency.md` is a **conceptual** model, not a line-for-line trace. Its sequence diagram creates `VerificationOverlapWorkers` *before* `DetectorWorkers` [docs/concurrency.md:13-18], whereas the current code &mdash; and the observed log order in section 1.6 (scanner, detector, verificationOverlap, notifier) &mdash; starts **detector before verificationOverlap**: `startDetectorWorkers` [engine.go:651] precedes `startVerificationOverlapWorkers` [engine.go:655] inside `startWorkers` [engine.go:646]. So the doc's *setup order* is illustrative only; this document follows the current code and observed logs for exact ordering. The doc's **data-flow**, however, matches what is traced above: it shows the scanner's direct path to `e.detectableChunksChan`, the multi-detector path to `e.verificationOverlapChunksChan`, and the overlap worker rejoining `e.detectableChunksChan` [docs/concurrency.md:28-39]. `docs/process_flow.md` diagrams the four conceptual stages *Source Decomposition -> Detector Matching -> Secret Detection -> Result Notification*, which the observed source/scan/detect/notify log sequence follows.

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

Compared with section 1.6, this `--debug` run has **no** `default engine options set`, `engine initialized`, `setting up aho-corasick core`, `set up aho-corasick core`, `chunking unit`, `scanning file`, or `dataErrChan closed` lines. The engine still performs all of that work (**derived** &mdash; corroborated by the `--trace` run in section 1.6, where those same lines *do* appear); under `--debug` they simply sit below the visible verbosity threshold.

**Mechanism (derived from source) and citations:**

- `--trace` maps to `log.SetLevel(5)` [main.go:305-306] and `--debug` maps to `log.SetLevel(2)` [main.go:307-308]; both flags are declared hidden &mdash; `debug` [main.go:51] and `trace` [main.go:52] &mdash; and parsed by `kingpin.MustParse` [main.go:301].
- `func SetLevel(level int8)` [pkg/log/level.go:21] delegates to `SetLevelForControl` [pkg/log/level.go:26], which **negates** the level: `control.SetLevel(zapcore.Level(-level))` [pkg/log/level.go:30]. So `SetLevel(5)` produces an enabled zap level of `-5` (surfacing `V(0)` through `V(5)`, i.e. `info-0` through `info-5`), while `SetLevel(2)` produces enabled level `-2` (surfacing only `info-0` through `info-2`). **This single negation is the entire gating mechanism.**
- The logger is wired up in `main()`: the sink is selected (`logFormat := log.WithConsoleSink`, switched to `log.WithJSONSink` when `*jsonOut` is set) and then `logger, sync := log.New("trufflehog", logFormat(os.Stderr, log.WithGlobalRedaction()))` is called [main.go:332-336]. `func New(service string, configs ...logConfig)` [pkg/log/log.go:28] builds a Zap backend wrapped by go-logr; global redaction comes from `WithGlobalRedaction()` [pkg/log/log.go:183]. The console sink is used unless `--json` is passed.

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

- **Three** `--trace` runs each produced the **same 148-line structure** (the same events, in the same order, with the same line count); **two** `--debug` runs each produced the **same 15-line structure**. The runs are **not byte-identical** &mdash; only the volatile fields below differ &mdash; but the startup *structure* is deterministic.
- Only volatile fields differ from run to run:
  - **Random worker IDs** &mdash; the `source_manager_worker_id` and the 128 `scanner_worker_id` values, from `common.RandomID(5)` [engine.go:667, source_manager.go:242].
  - **`scan_duration`** &mdash; observed `3.552437ms`, `3.710438ms`, and `3.533323ms`: each is **~3.5 ms**, and the run-to-run **spread is sub-millisecond** (`0.177115 ms` between the fastest and slowest of these three).
  - **File processing order** &mdash; `a.txt` versus `b.txt` may be chunked / scanned in either order, a concurrency artifact of the worker pools.

### 8.2 Magnitudes and their provenance (host `runtime.NumCPU() = 128`)

The **Kind** column distinguishes an **observed** value (read straight from a captured log line), a **derived** value (read from the cited source at this HEAD but not itself a log line, e.g. a multiplier constant), and a **measured** value (established by a separate measurement rather than by this scan's log).

| Quantity | Value | Kind | Source of value (cite) |
|---|---|---|---|
| Scanner workers | 128 | observed value; source derived | log line [engine.go:663]. The value **128** is the `--concurrency` flag default `runtime.NumCPU()` [main.go:58], passed to the engine as `Concurrency: *concurrency` [main.go:514]. The `setDefaults` zero-value fallback [engine.go:337-340] is **not** taken on the CLI path &mdash; proof: the `No concurrency specified` line [engine.go:339] is **absent** from the trace. |
| Detector workers | 1024 | observed value; multiplier derived | log line [engine.go:678]; `= e.concurrency x e.detectorWorkerMultiplier`, multiplier defaults to **8** [engine.go:345]; `numWorkers` [engine.go:676] (= 128 x 8). |
| verificationOverlap workers | 128 | observed value; multiplier derived | log line [engine.go:693]; `= e.concurrency x e.verificationOverlapWorkerMultiplier` (multiplier = 1) [engine.go:353, 691]. |
| Notifier workers | 128 | observed value; multiplier derived | log line [engine.go:708]; `= e.notificationWorkerMultiplier x e.concurrency` (multiplier = 1) [engine.go:349, 706]. |
| Default detectors loaded | **831** | measured (not from this scan's log) | `len(DefaultDetectors())` [pkg/engine/defaults/defaults.go:1704] &mdash; established by two independent measurements plus a static cross-check (see note). |
| Default decoders | 4 | derived / measured | `DefaultDecoders()` returns `UTF8, Base64, UTF16, EscapedUnicode` [pkg/decoders/decoders.go:8-15]; assigned in `setDefaults` [engine.go:358]. |
| chunks / bytes | 2 / 80 | observed | final `finished scanning` line. |
| scan_duration | ~3.5 ms | observed | final line; varies run to run with a **sub-millisecond spread** (see section 8.1). |
| verified / unverified secrets | 0 / 0 | observed | final line. Zero because `a.txt` holds an AWS access-key **ID** with no paired 40-char secret, so the detector forms no `(id, secret)` candidate and appends nothing [accesskey.go:131, 207] (see section 1.5) **(derived)**. |

> **Detector-count note (measured).** The **831** loaded-default count was established by **two independent runtime measurements** of `len(DefaultDetectors())` [pkg/engine/defaults/defaults.go:1704] at this HEAD with go1.24.2 &mdash; (1) from an **external Go module** that imports the package through a local `replace` directive, and (2) from a **temporary in-module harness** run with `-mod=readonly` (removed afterward, leaving the source tree unchanged) &mdash; both returning 831. A **static** count of the detector entries assembled in `buildDetectorList()` [pkg/engine/defaults/defaults.go:839-1702] independently corroborates the same value. Report **831** as the authoritative *loaded-default* count; the broader "845+" figure that appears in project material is a **catalog** count, not the loaded-default count.

## Appendix &mdash; Citation Index (pinned to HEAD `e42153d44a5e...`)

- **Startup / CLI (`main.go`):** kingpin app [47]; hidden flags `debug` [51], `trace` [52], `local-dev` [54]; `--concurrency` default `NumCPU()` [58]; `--no-verification` flag [59]; `filesystem` command [143]; `--version` handler [270]; parse [301]; trace/debug level mapping [305-308]; logger sink/redaction selection [332-336]; overseer block [340, 350, 356, 360-361, 364]; version log line [410]; optional config conditional `config.Read` [460-463]; banner [498]; `engConf` [513] with `Concurrency: *concurrency` [514], the subtractive-filters comment [515-518], and detectors append [519]; `runSingleScan` [546]; `eng.Finish` [950]; final summary [566-574].
- **Engine (`pkg/engine/engine.go`):** `PrinterDispatcher` [86-94]; `NewEngine` [226]; `setDefaults` [336] (concurrency zero-value fallback [337-340], **not** taken on the CLI path; multiplier defaults [345, 349, 353]; decoders guard/assign [357, 358]; log [373]); `initialize` [489] (LRU `cacheSize` [491], `lru.New` [493]; channel multiplier consts [497-509]; channel makes [515-519]; log [521]); Aho-Corasick bracket [529-531]; `defaultChannelBuffer` [627]; `startWorkers` [646] (scanner [648], detector [651], overlap [655], notifier [659]) with per-pool logs [663, 678, 693, 708], counts [676, 691, 706], and scanner `RandomID` [667]; `scannerWorker` [777] (`ChunksChan` [781], `FindDetectorMatches` [795], overlap branch [796, 798], direct branch [807, 808, 810], `finished scanning chunks` [840]); `verificationOverlapWorker` [924] (read [932], feed back [1014]); `detectorWorker` [1036] (read [1037], `FromData` [1070], `filterResults` [1113]); `notifierWorker` [1189] (`ResultsChan` [1190], `Dispatch` [1229]); `Finish` ordered shutdown [723-737].
- **Detectors:** `pkg/engine/ahocorasick/ahocorasickcore.go` &mdash; import [7], maps [133-134], `NewAhoCorasickCore` [141], keyword loop [147-152], prefilter trie [159], `Match` [242]; `pkg/engine/defaults/defaults.go` &mdash; `buildDetectorList` [839-1702], `DefaultDetectors` [1704].
- **AWS detector (zero-findings causality, section 1.5 / section 8.2):** `pkg/detectors/aws/access_keys/accesskey.go` &mdash; `idPat` [65], `secretMatches` from `aws.SecretPat` [115-116], secret loop `for secretMatch := range secretMatches` [131], `FalsePositiveSecretPat` check [202], `results = append(results, s1)` [207]; `pkg/detectors/aws/common.go` &mdash; `SecretPat` (40-char `[A-Za-z0-9+/]` run) [10]; `pkg/detectors/aws/utils.go` &mdash; `FalsePositiveSecretPat` (`[a-f0-9]{40}`) [47].
- **Decoders (`pkg/decoders/decoders.go`):** `DefaultDecoders` &mdash; `UTF8`, `Base64`, `UTF16`, `EscapedUnicode` [8-15].
- **Config (`pkg/config/config.go`):** `Read` [18], `NewYAML` [27].
- **Sources:** `pkg/sources/source_manager.go` &mdash; worker `RandomID` [242], `Chunks` [259], `Wait` [267], `running source` [402], `enumerating source` [531], `chunking unit` [557, 603]; `pkg/sources/filesystem/filesystem.go` &mdash; `Chunks` [85], `scanning file` [179], `Enumerate` [202], `ChunkUnit` [242].
- **Logging:** `pkg/log/level.go` &mdash; `SetLevel` [21], `SetLevelForControl` [26], negation [30]; `pkg/log/log.go` &mdash; `New` [28], `WithGlobalRedaction` [183]; `pkg/handlers/handlers.go` &mdash; `dataErrChan closed` [413].
- **Build / toolchain:** `Dockerfile` [5, 9]; `Makefile` [48-49, 51-52]; `go.mod` [3, 5].
