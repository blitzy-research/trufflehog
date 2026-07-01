# How TruffleHog Behaves When the Go Binary Starts Up

> An **empirically-observed, run-grounded** walkthrough of what TruffleHog actually *does* from the moment its Go binary is invoked through the printing of a scan result. Every claim below is anchored either to a **verbatim line of captured output** (shown with the exact command that produced it) or to an exact **`file:line`** source reference.
>
> This document is a *behavioral* narrative, **not** a file-by-file code summary. It complements — and deliberately does **not** duplicate — the maintainer-authored architecture overviews in [`docs/process_flow.md`](../../docs/process_flow.md) and [`docs/concurrency.md`](../../docs/concurrency.md); those describe the intended design, while this document shows the design *as observed at runtime*.

It answers four questions, each in its own section, and closes with a **coverage-pass table**:

- **(a) Configuration handling** — how CLI flags + the chosen subcommand are parsed, how logging verbosity is applied, and how the `engine.Config` object is assembled before a scan.
- **(b) Engine initialization** — how the engine is constructed and started, including worker-pool sizing and inter-stage channel allocation.
- **(c) Detector preparation** — how the default detector set is assembled, optionally filtered, and compiled into the Aho-Corasick keyword-matching structure that routes data.
- **(d) Component communication** — how a source decomposes input into chunks and how those chunks flow through the concurrent worker pools to the result printer.

---

## 0. Overview, environment, and methodology (run first, then write)

### 0.1 Environment

| Property | Value | How it was established |
|----------|-------|------------------------|
| Go toolchain | `go1.24.2` | `go version` → `go version go1.24.2 linux/amd64`; matches `toolchain go1.24.2` at `go.mod:5` (module declares `go 1.23.1` at `go.mod:3`) |
| Module | `github.com/trufflesecurity/trufflehog/v3` | `go.mod:1` |
| CPU count seen by the Go runtime | `runtime.NumCPU()` = **128** | measured at runtime (see note below) |
| Build version | `dev` | `var BuildVersion = "dev"` in `pkg/version`; surfaces as `trufflehog dev` |

> **Why the worker counts are 128 (an exact, grounded detail).** The engine's default concurrency is `runtime.NumCPU()` (`pkg/engine/engine.go:337-340`). On this host the shell's `nproc` reports `4` (it honors the cgroup CPU quota), **but the Go runtime's `runtime.NumCPU()` returns `128`** (the machine's logical-CPU count), and that is the value the engine actually uses. This is why every worker-pool count below is a multiple of **128**. On a host where `runtime.NumCPU()` is different, all four counts scale proportionally — they are not hard-coded.

### 0.2 The two safe dry-run commands

Both runs are **safe dry runs**: `--no-verification` sets `Verify` to `false` in the engine config (`main.go:520`), so detectors extract candidates but **never** make outbound credential-verification network calls. Scan inputs are created under `/tmp` (outside the repository), and the built `trufflehog` binary is gitignored (`.gitignore:7` == `trufflehog`), so building and running leave the tracked repository pristine (`git status --porcelain` is empty).

```bash
# Build (binary is gitignored -> tracked repo stays pristine):
CGO_ENABLED=0 go build -o trufflehog .        # exit 0
./trufflehog --version                        # prints: trufflehog dev   (cli.Version, main.go:270)

# RUN A — safe dry-run, debug logging (the repo's own debug convention, --log-level=2):
mkdir -p /tmp/th_scan_demo
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' \
  > /tmp/th_scan_demo/creds.txt
./trufflehog filesystem /tmp/th_scan_demo --no-verification --log-level=2

# RUN B — max verbosity + a (fake) non-example token, to surface the deep V(3)/V(4)/V(5) trace and a printed result:
mkdir -p /tmp/th_scan_demo3
printf 'token: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n' > /tmp/th_scan_demo3/secrets.yaml
./trufflehog filesystem /tmp/th_scan_demo3 --no-verification --results=verified,unverified,unknown --log-level=5
```

**Why these flags.** `--no-verification` provides the "safe dry-run" property described above (documented at `README.md:431` — `--no-verification     Don't verify the results.`). `--log-level=2` is the repository's own debug convention: the `Makefile` `dogfood` (`:14-15`) and `run-debug` (`:51-52`) targets both invoke the tool with `--log-level=2`, and `CONTRIBUTING.md:33` defines level `2` as "logs that are useful for debugging". `--log-level=5` is "ultimate verbosity" (`CONTRIBUTING.md:36`) and is used only in Run B to reveal the deeper `V(3)`/`V(4)`/`V(5)` lines. The `log-level` flag itself is declared at `main.go:50` ("Logging verbosity on a scale of 0 (info) to 5 (trace).").

> The tokens above are throwaway test values: `AKIAIOSFODNN7EXAMPLE` is AWS's *public documentation* example key, and the `ghp_…` string is syntactically valid but **fake / non-live**. No real credential appears in this document or the repository.

### 0.3 Captured evidence

**Run A** — `./trufflehog filesystem /tmp/th_scan_demo --no-verification --log-level=2` → **exit code `0`**, stderr (verbatim; timestamps/worker-ids/durations are per-run and will differ):

```text
2026-07-01T05:15:02Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-01T05:15:02Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-01T05:15:02Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-01T05:15:02Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-01T05:15:02Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-01T05:15:02Z	info-0	trufflehog	running source	{"source_manager_worker_id": "g6wpv", "with_units": true}
2026-07-01T05:15:02Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "g6wpv"}
2026-07-01T05:15:02Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.189939ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Run A's input held the canonical AWS documentation key `AKIAIOSFODNN7EXAMPLE`, which the tool recognizes as a **false positive** → `"unverified_secrets": 0`. `"bytes": 106` is exactly the size of the scanned `creds.txt` (`wc -c` = 106).

**Run B** — `./trufflehog filesystem /tmp/th_scan_demo3 --no-verification --results=verified,unverified,unknown --log-level=5` → **exit code `0`**.

STDOUT (the `PlainPrinter` result, verbatim):

```text
Found unverified result 🐷🔑❓
Detector Type: Github
Decoder Type: PLAIN
Raw result: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
Rotation_guide: https://howtorotate.com/docs/tutorials/github/
Version: 2
File: /tmp/th_scan_demo3/secrets.yaml
Line: 1
```

STDERR — ordered level-5 trace (verbatim key lines; the 128 identical `finished scanning chunks` lines are shown once):

```text
2026-07-01T05:15:14Z	info-2	trufflehog	trufflehog dev
2026-07-01T05:15:14Z	info-4	trufflehog	default engine options set
2026-07-01T05:15:14Z	info-4	trufflehog	engine initialized
2026-07-01T05:15:14Z	info-4	trufflehog	setting up aho-corasick core
2026-07-01T05:15:14Z	info-4	trufflehog	set up aho-corasick core
2026-07-01T05:15:14Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-01T05:15:14Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-01T05:15:14Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-01T05:15:14Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-01T05:15:14Z	info-0	trufflehog	running source	{"source_manager_worker_id": "aecqL", "with_units": true}
2026-07-01T05:15:14Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "aecqL"}
2026-07-01T05:15:14Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "aecqL", "unit_kind": "unit", "unit": "/tmp/th_scan_demo3/secrets.yaml"}
2026-07-01T05:15:14Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "aecqL", "unit_kind": "unit", "unit": "/tmp/th_scan_demo3/secrets.yaml", "path": "/tmp/th_scan_demo3/secrets.yaml"}
2026-07-01T05:15:14Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "aecqL", "unit_kind": "unit", "unit": "/tmp/th_scan_demo3/secrets.yaml", "path": "/tmp/th_scan_demo3/secrets.yaml", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-01T05:15:14Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Jfkz8"}
2026-07-01T05:15:14Z	info-4	trufflehog	link is empty, skipping update	{"detector_worker_id": "5bkSP", "detector": {"type":"Github","version":2}, "timeout": 10}
2026-07-01T05:15:14Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 48, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "7.321475ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The fake GitHub token is extracted but, because `--no-verification` disables live checks, it is reported as an **unverified** finding → `"unverified_secrets": 1`.

Two properties of this safe dry run are confirmed by re-grepping Run B's captured standard error (Run B was re-run with its stderr redirected to a file — `./trufflehog filesystem /tmp/th_scan_demo3 --no-verification --results=verified,unverified,unknown --log-level=5 2> runB.stderr`):

```console
$ grep -c 'finished scanning chunks' runB.stderr
128
$ grep -Eic 'verifying|http request|dialing|api.github' runB.stderr
0
$ grep -c 'No concurrency specified' runB.stderr
0
```

- **`finished scanning chunks` was emitted exactly 128 times** — one per scanner worker. The line is logged at the tail of each scanner worker's loop (`pkg/engine/engine.go:840`), so the count `128` directly confirms the 128-worker scanner pool sized in section (b).
- **Zero outbound-verification markers** (`verifying` / `http request` / `dialing` / `api.github`) appear, empirically confirming the dry run made no live verification calls. This matches the source: `--no-verification` sets `Verify` to `false` (`main.go:520`), and the engine's `shouldVerifyChunk` returns `false` whenever `!e.verify` (`pkg/engine/engine.go:843-850`) — detectors extract candidates but never verify them.
- **The engine's concurrency-fallback log is absent** (`No concurrency specified` count `0`); section (b) explains why the CLI path never triggers that fallback.

---

## (a) Configuration handling

**What happens, in order.** From process start, TruffleHog parses flags and the chosen subcommand, translates the verbosity request into a global log level, constructs the logger, and assembles an `engine.Config` — all before any scanning begins.

**1. The CLI app and flag/subcommand parsing.** The command tree is defined with `alecthomas/kingpin/v2`:

- `main.go:47` — `cli = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")`
- `main.go:50` — the verbosity flag: `logLevel = cli.Flag("log-level", ...).Default("0").Int()`
- `main.go:270` — `cli.Version("trufflehog " + version.BuildVersion)` — this is the source of `./trufflehog --version` → **`trufflehog dev`** (observed, exit `0`).
- `main.go:301` — `cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))` parses the flags **and** resolves which subcommand was selected (`cmd` later drives dispatch). For our runs `cmd` resolves to the `filesystem` command, dispatched at `main.go:774` (`case filesystemScan.FullCommand():`) which calls `eng.ScanFileSystem(ctx, cfg)` at `main.go:786`.

**2. Verbosity is applied to a global log level.** Immediately after parsing, a `switch` maps the request to a level (`main.go:304-323`):

```go
// main.go:304-323 (Configure logging)
switch {
case *trace:
    log.SetLevel(5)
case *debug:
    log.SetLevel(2)
default:
    l := int8(*logLevel)
    ...
    log.SetLevel(l)
}
```

- `main.go:305-306` — `--trace` → `log.SetLevel(5)`
- `main.go:307-308` — `--debug` → `log.SetLevel(2)`
- `main.go:309-322` — otherwise the numeric `--log-level` value is applied via `log.SetLevel` (`pkg/log/level.go:21` `func SetLevel(level int8)`).

**Therefore `--log-level=2` is exactly equivalent to `--debug` — both call `log.SetLevel(2)`.** This is the repo's documented debug convention (`Makefile:14-15`, `Makefile:51-52`, `CONTRIBUTING.md:33`).

**3. Why the log prefix reads `info-N` (the observed verbosity signal).** The logger is a `go.uber.org/zap` backend behind a `go-logr/logr` facade, accessed through `ctx.Logger()` (`pkg/context/context.go:42` `func (l logCtx) Logger() logr.Logger`). The distinctive `info-N` prefix on every observed line comes from a single line in the encoder:

- `pkg/log/log.go:123` — `enc.AppendString(fmt.Sprintf("info-%d", -int8(level)))`

`logr`'s `V(n)` verbosity is stored by zap as a **negated** level, so a call to `ctx.Logger().V(n).Info(...)` prints with the prefix `info-n`. This is *why* the runtime evidence is self-describing: the number after `info-` is the `V(n)` level of the call site. A plain `.Info(...)` (no `V`) is `V(0)` → `info-0`.

**4. Logger construction and the two startup banners.** The concrete logger is built at:

- `main.go:336` — `logger, sync := log.New("trufflehog", logFormat(os.Stderr, log.WithGlobalRedaction()))` (`pkg/log/log.go:28` `func New(...)`). Note the redaction option — findings are redaction-aware from the start.

Two banners are then emitted (both visible in Run A):

- `main.go:410` — `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` → the observed `info-2  trufflehog  trufflehog dev` line. Because it is a `V(2)` call, it appears at `--log-level=2` and above.
- `main.go:498` — `fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")` → the emoji banner. This is written **directly to stderr**, not through the logger, which is why it carries **no** timestamp and **no** `info-N` prefix in the captured output.

**5. Assembling `engine.Config`.** The scan is configured by building an `engine.Config` struct (`main.go:513-533`). The observed-relevant fields:

- `main.go:519` — `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` — the default detector set (plus any from an optional config file) is composed here. The in-code comment at `main.go:515-518` states the user filters "are applied by the engine and are only **subtractive**."
- `main.go:520` — `Verify: !*noVerification` — with `--no-verification` this evaluates to **`false`**, which is what makes both runs safe dry runs (extraction without live verification).
- `main.go:521` / `main.go:522` — `IncludeDetectors` / `ExcludeDetectors` — feed the subtractive detector filter (see section (c)).
- `main.go:525` — `Dispatcher: engine.NewPrinterDispatcher(printer)` — wires the result printer that ultimately renders `Found unverified result`.
- `main.go:529` — `Results: parsedResults` — the parsed `--results=verified,unverified,unknown` selection used in Run B.

**6. Optional YAML config file.** If `--config` is supplied, it is loaded via `pkg/config/config.go:18` `func Read(filename string)` → `pkg/config/config.go:27` `func NewYAML(input []byte)`, contributing `conf.Detectors` into the `append(...)` at `main.go:519`. Neither run used `--config`, so only the defaults were composed.

**Grounded confirmation.** Every **logger-produced** stderr line in Run A carries the `info-2` prefix (or `info-0` for the two `V(0)` lines), which is the runtime signature of `--log-level=2`. (The emoji banner is the sole exception: it is written directly to stderr at `main.go:498`, not through the logger, so it carries no timestamp and no `info-N` prefix — see §(a).4.) The verbosity mapping, the logger, and the config assembly are therefore observable directly in the output rather than inferred.


---

## (b) Engine initialization

**What happens, in order.** Once the config is assembled, the engine is constructed, its defaults are filled in, its inter-stage channels are allocated, and its worker pools are started. The call chain is:

```
NewEngine (pkg/engine/engine.go:226)
  └─ setDefaults   (engine.go:336)  → logs "default engine options set" (engine.go:373, V4)
  └─ initialize    (engine.go:489)  → allocates channels, logs "engine initialized" (engine.go:521, V4)
Start (engine.go:621)
  └─ startWorkers  (engine.go:646)  → starts 4 pools, each logging "starting … workers" (V2)
```

The two `V(4)` lifecycle lines are visible in Run B (`--log-level=5`):

```text
info-4	trufflehog	default engine options set
info-4	trufflehog	engine initialized
```

**1. Defaults — `setDefaults` (`engine.go:336`).** This is where the worker-pool sizing constants originate:

- `engine.go:337-341` — an engine-level **fallback**: *only if* `e.concurrency == 0` does the engine set `e.concurrency = runtime.NumCPU()` and log `No concurrency specified, defaulting to max` (the log call is at `engine.go:339`). **In the CLI path this branch is not taken.** The `--concurrency` flag already defaults to `runtime.NumCPU()` — `main.go:58` (`cli.Flag("concurrency", ...).Default(strconv.Itoa(runtime.NumCPU())).Int()`) — and that non-zero value is copied into `engine.Config.Concurrency` at `main.go:514`. So `e.concurrency` is already **128** (see §0.1) when `setDefaults` runs, the `if e.concurrency == 0` guard is false, and the `No concurrency specified…` line is **not** emitted. This is confirmed at runtime: `grep -c 'No concurrency specified'` returns `0` for both documented runs (see the evidence block in §0.3). The fallback exists only for programmatic callers of `NewEngine` that leave `Concurrency` at its zero value.
- `engine.go:343-345` — `e.detectorWorkerMultiplier = 8`; the in-code comment (`engine.go:344`) explains it is "bound by net i/o so it's higher than other workers."
- `engine.go:348-349` — `e.notificationWorkerMultiplier = 1`.
- `engine.go:352-353` — `e.verificationOverlapWorkerMultiplier = 1`.
- `engine.go:373` — `ctx.Logger().V(4).Info("default engine options set")` → observed `info-4 default engine options set`.

**2. Channel allocation — `initialize` (`engine.go:489`).** The inter-stage buffered channels are sized as `defaultChannelBuffer × multiplier`, where `var defaultChannelBuffer = runtime.NumCPU()` (`engine.go:627`) = **128** here:

| Channel | Multiplier (constant) | Buffer size on this host |
|---------|-----------------------|--------------------------|
| `detectableChunksChan` | `detectableChunksChanMultiplier = 50` (`engine.go:503`) | `128 × 50 = 6400` |
| `verificationOverlapChunksChan` | `verificationOverlapChunksChanMultiplier = 25` (`engine.go:507`) | `128 × 25 = 3200` |
| `results` | `resultsChanMultiplier = detectableChunksChanMultiplier` = 50 (`engine.go:508`) | `128 × 50 = 6400` |

The `make(...)` calls are at `engine.go:515`, `engine.go:517`, and `engine.go:519`; the block finishes with `ctx.Logger().V(4).Info("engine initialized")` at `engine.go:521` → observed `info-4 engine initialized`. Buffering channels as multiples of `NumCPU` lets the many producer goroutines hand off work without blocking each other.

**3. Starting the worker pools — `Start` → `startWorkers` (`engine.go:621`, `engine.go:646`).** `Start` records the scan start time, runs `sanityChecks`, then calls `startWorkers`, which starts the four pools **in a fixed order** (`engine.go:646-660`) — the same order in which the four `starting … workers` lines appear in the output:

| Pool | Start func | Count formula | `file:line` of the log | Observed count |
|------|------------|---------------|------------------------|----------------|
| Scanner | `startScannerWorkers` (`:662`) | `e.concurrency` | `engine.go:663` | **128** |
| Detector | `startDetectorWorkers` (`:675`) | `e.concurrency * e.detectorWorkerMultiplier` (`:676`) | `engine.go:678` | **1024** (= 128 × 8) |
| verificationOverlap | `startVerificationOverlapWorkers` (`:690`) | `e.concurrency * e.verificationOverlapWorkerMultiplier` (`:691`) | `engine.go:693` | **128** (= 128 × 1) |
| notifier | `startNotifierWorkers` (`:705`) | `e.notificationWorkerMultiplier * e.concurrency` (`:706`) | `engine.go:708` | **128** (= 128 × 1) |

The corresponding verbatim evidence (identical in both runs):

```text
info-2	trufflehog	starting scanner workers	{"count": 128}
info-2	trufflehog	starting detector workers	{"count": 1024}
info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
info-2	trufflehog	starting notifier workers	{"count": 128}
```

**Reasoning (why these numbers).** The counts are not magic constants: they are `concurrency × multiplier` with `concurrency = runtime.NumCPU() = 128`. The detector pool is intentionally **8×** larger than the scanner pool because detector work is network-I/O bound (verification), so more goroutines keep the CPU busy while others wait on I/O (`engine.go:344`). The exact `1024 = 128 × 8` relationship observed in the logs is the empirical proof of `detectorWorkerMultiplier = 8`. On a machine with a different `runtime.NumCPU()`, all four counts change proportionally.


---

## (c) Detector preparation

**What happens, in order.** The default detector set is assembled, optionally narrowed by subtractive filters, and then compiled into an Aho-Corasick automaton that is used at scan time to route each chunk only to the detectors that could possibly match it.

**1. The default detector set.** The canonical list is produced by:

- `pkg/engine/defaults/defaults.go:1704` — `func DefaultDetectors() []detectors.Detector`

It is composed into the engine config at `main.go:519` (`Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)`), so by default the engine is armed with the full built-in detector catalog.

**2. Optional subtractive filtering.** The `--include-detectors` / `--exclude-detectors` flags (config fields `IncludeDetectors`/`ExcludeDetectors`, `main.go:521-522`) are parsed and applied by the engine using the machinery in `pkg/config/detectors.go` (`func ParseDetectors` at `:61`, `func GetDetectorID` at `:45`, and the `allDetectors()` group at `:16`). Per the comment at `main.go:515-518`, these filters are **only subtractive** — they can remove detectors from the default set but cannot add new ones. Neither observed run passed these flags, so the full default set was used.

**3. Every detector implements one interface.** The uniform contract that lets the engine treat all detectors identically is in `pkg/detectors/detectors.go`:

- `:19` — `type Detector interface`
- `:21` — `FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)` — extraction (and, when `verify` is `true`, verification). Note the `verify` parameter: it receives the `Verify` value from `engine.Config` (`false` under `--no-verification`).
- `:24` — `Keywords() []string` — the strings that feed the Aho-Corasick automaton.
- `:26` — `Type() detectorspb.DetectorType` — e.g. the `Github` type shown in Run B's output.

**4. Compiling the keyword-matching structure (Aho-Corasick).** The engine builds a keyword→detector prefilter from the keywords of the (filtered) detector set:

- `pkg/engine/engine.go:529` — `ctx.Logger().V(4).Info("setting up aho-corasick core")`
- `pkg/engine/engine.go:530` — `e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)` (constructor at `pkg/engine/ahocorasick/ahocorasickcore.go:141` — `func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core`)
- `pkg/engine/engine.go:531` — `ctx.Logger().V(4).Info("set up aho-corasick core")`

Observed verbatim in Run B (`--log-level=5`):

```text
info-4	trufflehog	setting up aho-corasick core
info-4	trufflehog	set up aho-corasick core
```

**Reasoning (why an automaton).** Running every detector's regexes against every chunk would be prohibitively expensive. Instead the automaton is built once from the *keywords* of the full detector set (`Keywords()`), so at scan time a single cheap multi-string pass over a chunk finds which keywords are present and routes the chunk only to the detectors whose keywords appeared. This is the runtime meaning of the "setting up … / set up …" pair: the routing structure is being compiled *before* any data flows. This corresponds to the maintainer-described "Chunk to Detector Matching (Aho-Corasick)" stage in [`docs/process_flow.md`](../../docs/process_flow.md) (heading at `docs/process_flow.md:74`).


---

## (d) Component communication during a basic run

**What happens, in order.** A source decomposes its input into progressively finer units — **Source → Unit → Chunk** — and those chunks flow through the buffered channels connecting the four worker pools, ending at the result printer. The ordered Run B trace lets us follow a single file end-to-end.

**1. Source decomposition (the `SourceManager`).** In `pkg/sources/source_manager.go`:

- `:402` — `ctx.Logger().Info("running source", "with_units", true)` — a plain `.Info` (i.e. `V(0)`) → observed **`info-0 running source {"with_units": true}`**. `with_units: true` means this source enumerates discrete *units* (here, files) before chunking.
- `:531` — `ctx.Logger().V(2).Info("enumerating source")` → **`info-2 enumerating source`**.
- `:557` / `:603` — `ctx.Logger().V(3).Info("chunking unit")` → **`info-3 chunking unit`**, carrying `"unit": "/tmp/th_scan_demo3/secrets.yaml"`.

Then the `filesystem` source scans each file:

- `pkg/sources/filesystem/filesystem.go:179` — `fileCtx.Logger().V(3).Info("scanning file")` → **`info-3 scanning file {"path": "/tmp/th_scan_demo3/secrets.yaml"}`**.

**2. Reading & MIME detection (handlers).** As the file's bytes are read and emitted as chunks, the handler layer detects the content type and signals end-of-data:

- `pkg/handlers/handlers.go:413` — `ctx.Logger().V(5).Info("dataErrChan closed, all chunks processed")` → **`info-5 dataErrChan closed, all chunks processed`**, carrying `"mime": "text/plain; charset=utf-8"` (MIME via `github.com/gabriel-vasile/mimetype`) and `"timeout": 60`.

**3. Through the worker pipeline.** Chunks then travel the channel-connected pools that were started in section (b). The scanner pool decodes each chunk and runs the Aho-Corasick prefilter; each scanner worker logs completion:

- `pkg/engine/engine.go:840` — `ctx.Logger().V(4).Info("finished scanning chunks")` → **`info-4 finished scanning chunks`**, tagged with a `scanner_worker_id`. This line appeared **exactly 128 times** in Run B — once per scanner worker — which is the empirical confirmation of the 128-worker scanner pool.

The full observed path, mapped to code:

```
SourceManager (running → enumerating → chunking)         source_manager.go:402/531/557
        │  ChunksChan()
        ▼
Scanner Workers (128)  decode + Aho-Corasick match        engine.go:662-663, :840
        │  detectableChunksChan  (buffer NumCPU×50)        engine.go:503, :515
        ▼
Detector Workers (1024 = 128×8)  FromData(...)            engine.go:675-678
        │  (verification SKIPPED — Verify=false via --no-verification, main.go:520)
        │  results  (buffer NumCPU×50)                     engine.go:508, :519
        ▼
Notifier Workers (128)                                    engine.go:705-708
        │  PrinterDispatcher                               main.go:525
        ▼
PlainPrinter output  "Found unverified result 🐷🔑❓"      plain.go:55

Overlap branch:  Scanner ──verificationOverlapChunksChan (NumCPU×25)──▶ Verification-Overlap Workers ──▶ detectableChunksChan
                          engine.go:507/:517                                 engine.go:690-693
```

**4. Detection and result rendering.** A detector worker matches the fake token as a `Github` credential. Because `Verify` is `false`, no live check is made; the worker even notes there is no repository link to enrich:

```text
info-4	trufflehog	link is empty, skipping update	{"detector_worker_id": "5bkSP", "detector": {"type":"Github","version":2}, "timeout": 10}
```

The result is dispatched to the printer. `pkg/output/plain.go` chooses between two variants — the verified path at `:52` (`✅ Found verified result 🐷🔑`) and the **unverified** path at `:55` (`Found unverified result 🐷🔑❓`). Because verification was disabled, Run B took the `:55` branch, producing the observed STDOUT:

```text
Found unverified result 🐷🔑❓
Detector Type: Github
...
Line: 1
```

**5. Final summary.** When all sources finish, the CLI prints the summary at `main.go:566` (`logger.Info("finished scanning", ...)`, a `V(0)` call → `info-0`), whose fields (`main.go:567-573`, including `"trufflehog_version"` at `main.go:572`) are exactly the observed:

```text
info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 48, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "7.321475ms", "trufflehog_version": "dev", ...}
```

**Reasoning (why channels + pools).** Decoupling the stages with buffered channels lets each stage run at its own pace: the single source goroutine can enumerate/chunk while 128 scanners prefilter and 1024 detectors do the (normally I/O-bound) matching, all without lock-step coordination. This is the runtime realization of the maintainer overview's four stages — *Source Decomposition → Chunk-to-Detector Matching → Secret Detection → Result Notification* ([`docs/process_flow.md`](../../docs/process_flow.md), headings at `:28/:74/:88/:126`) — and of the per-worker-type threading model in [`docs/concurrency.md`](../../docs/concurrency.md) (`## Concurrency`, `:3`).

### Verbosity → prefix map (why Run A and Run B differ)

The number after `info-` is the `V(n)` level of the emitting call (root cause: the negated zap level at `pkg/log/log.go:123`). This is exactly why raising `--log-level` reveals more lines:

| `V(n)` → prefix | Example observed lines | Appears at `--log-level` ≥ |
|-----------------|------------------------|----------------------------|
| `V(0)` → `info-0` | `running source`; `finished scanning` | 0 |
| `V(2)` → `info-2` | version banner; the four `starting … workers`; `enumerating source` | 2 |
| `V(3)` → `info-3` | `chunking unit`; `scanning file` | 3 |
| `V(4)` → `info-4` | `default engine options set`; `engine initialized`; `setting up`/`set up aho-corasick core`; `finished scanning chunks` | 4 |
| `V(5)` → `info-5` | `dataErrChan closed, all chunks processed` | 5 |

Run A used `--log-level=2`, so only `info-0` and `info-2` lines appear. Run B used `--log-level=5`, so the deeper `info-3`/`info-4`/`info-5` lines are additionally shown — which is why the full engine-initialization and per-file trace is visible only in Run B.


---

## Coverage pass — every observed line mapped to its source

| Observed log line (verbatim) | Verbosity | `file:line` | Sub-question |
|------------------------------|-----------|-------------|--------------|
| `trufflehog dev` (version banner) | `info-2` | `main.go:410` (value from `main.go:270`) | (a) |
| `🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷` | *(no prefix — direct stderr)* | `main.go:498` | (a) |
| `starting scanner workers {"count": 128}` | `info-2` | `engine.go:663` | (b) |
| `starting detector workers {"count": 1024}` | `info-2` | `engine.go:678` | (b) |
| `starting verificationOverlap workers {"count": 128}` | `info-2` | `engine.go:693` | (b) |
| `starting notifier workers {"count": 128}` | `info-2` | `engine.go:708` | (b) |
| `default engine options set` | `info-4` | `engine.go:373` | (b) |
| `engine initialized` | `info-4` | `engine.go:521` | (b) |
| `setting up aho-corasick core` | `info-4` | `engine.go:529` | (c) |
| `set up aho-corasick core` | `info-4` | `engine.go:531` | (c) |
| `running source {"with_units": true}` | `info-0` | `source_manager.go:402` | (d) |
| `enumerating source` | `info-2` | `source_manager.go:531` | (d) |
| `chunking unit {"unit": "…secrets.yaml"}` | `info-3` | `source_manager.go:557` / `:603` | (d) |
| `scanning file {"path": "…secrets.yaml"}` | `info-3` | `filesystem.go:179` | (d) |
| `dataErrChan closed, all chunks processed {"mime": "text/plain; charset=utf-8"}` | `info-5` | `handlers.go:413` | (d) |
| `finished scanning chunks` (128×) | `info-4` | `engine.go:840` | (b)/(d) |
| `link is empty, skipping update {"detector":{"type":"Github",…}}` | `info-4` | `engine.go:1334` | (d) |
| `Found unverified result 🐷🔑❓` | *(STDOUT)* | `plain.go:55` (verified variant `:52`) | (d) |
| `finished scanning {"chunks":1,"unverified_secrets":1,…}` | `info-0` | `main.go:566` (fields `:567-573`) | (d) |

**Config/verbosity plumbing (not a log line, but grounding the above):** flag/subcommand parse `main.go:301`; `--log-level=2` ≡ `--debug` `main.go:304-323`; `info-N` prefix from negated zap level `pkg/log/log.go:123`; logger `main.go:336`; `engine.Config` assembly `main.go:513-533` with `Verify: !*noVerification` at **`main.go:520`**; default detectors `defaults.go:1704`; `Detector` interface `detectors.go:19-26`.

### Closing statement

All four sub-questions have been answered from observed runtime behavior, each grounded in verbatim captured output and exact `file:line` references:

- **(a) Configuration handling** — flags and the `filesystem` subcommand are parsed by kingpin (`main.go:301`); `--log-level=2` maps to level 2 identically to `--debug` (`main.go:304-323`), evidenced by the `info-2` prefix (`pkg/log/log.go:123`); the logger is built at `main.go:336`; and `engine.Config` is assembled at `main.go:513-533`, with `--no-verification` setting `Verify=false` at `main.go:520`.
- **(b) Engine initialization** — `NewEngine → setDefaults → initialize → Start → startWorkers` (`engine.go:226/336/489/621/646`), evidenced by `default engine options set`, `engine initialized`, and the four `starting … workers` lines with observed counts **128 / 1024 / 128 / 128** (= `runtime.NumCPU()=128` × the multipliers 1/8/1/1), plus channel buffers of `NumCPU × {50,25,50}`.
- **(c) Detector preparation** — the default set `DefaultDetectors()` (`defaults.go:1704`) is composed at `main.go:519`, narrowed by subtractive filters (`pkg/config/detectors.go`), and compiled into the Aho-Corasick core (`engine.go:529-531`), evidenced by `setting up`/`set up aho-corasick core`.
- **(d) Component communication** — the `Source → Unit → Chunk` decomposition (`source_manager.go:402/531/557`, `filesystem.go:179`) feeds the buffered-channel worker pipeline to the `PlainPrinter` (`plain.go:55`), evidenced by the ordered Run B trace and the final `finished scanning` summary (`main.go:566`) reporting `unverified_secrets: 1`.

No sub-part is left unaddressed. All evidence was produced by building the binary (`CGO_ENABLED=0 go build -o trufflehog .`, exit `0`) and executing the two safe dry-run commands above; the tracked repository was left pristine (the binary is gitignored at `.gitignore:7`, and scan inputs lived under `/tmp`).

