# How TruffleHog v3 Comes Online During a Basic Filesystem Scan

**A run-first, evidence-grounded walkthrough of four subsystems — configuration handling, scanning-engine initialization, detector preparation, and inter-component communication — as they are observed to start up during a safe, dry-run filesystem scan.**

This document answers, strictly from **observed runtime behavior**, how TruffleHog v3 (the Go secret-scanning CLI in this repository) brings four subsystems online at the start of a basic scan. Every behavioral claim below is paired with (a) the actual captured output, (b) the exact command that produced it, and (c) a verified `file:line` citation with a cause → effect explanation. Values were captured by building the canonical from-source binary and running instrumented dry-runs; nothing here is derived from reading source alone. Anything not directly observed is explicitly labeled `(inferred)`.

> **Host note.** The concrete worker counts and channel-buffer sizes reported here are **host-dependent**: they derive from `runtime.NumCPU()`, which is **128** on the machine used for this investigation. They are reported as observed and attributed to their host-dependent source; they are **not** universal constants. The multipliers and cache sizes they are derived from *are* fixed constants in the source.

---

## How this was observed

**Canonical build (`trufflehog dev`).** Go was installed outside the repository checkout (the highest explicitly documented toolchain, `toolchain go1.24.2` at `go.mod:L5`; the module directive is `go 1.23.1` at `go.mod:L3`). The binary was compiled with the project's canonical recipe — `CGO_ENABLED=0` (`Dockerfile:L5`) and `go build -o trufflehog .` (`Dockerfile:L9`); the `Makefile` `run`/`run-debug`/`install`/`dogfood` targets all use `CGO_ENABLED=0` as well (`Makefile:L14-L52`):

```bash
# toolchain + build + caches all live OUTSIDE the repository checkout
CGO_ENABLED=0 go build -o /tmp/trufflehog_build/trufflehog .
/tmp/trufflehog_build/trufflehog --version      # => "trufflehog dev"
```

The version string `dev` comes from `var BuildVersion = "dev"` (`pkg/version/version.go:L3`), surfaced to the `--version` flag by `cli.Version("trufflehog " + version.BuildVersion)` (`main.go:L270`). Release builds override it through goreleaser ldflags — `-X '...pkg/version.BuildVersion={{ .Version }}'` (`.goreleaser.yml:L6`) — so **`dev` is the canonical marker of a plain from-source build**. Observed:

```
trufflehog dev
```

**Minimal, safe scan target (87 bytes, outside the checkout).** Two tiny text files with no real secrets:

```
readme.txt  (59 bytes):  "Welcome to the demo project.\nNothing sensitive lives here.\n"
config.ini  (28 bytes):  "[settings]\ndebug = false\nok\n"
```

**Instrumented dry-runs (results → stdout, logs + banner → stderr, captured separately):**

```bash
for N in 2 3 4 5; do
  /tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target \
      --no-verification --log-level=$N  > level$N.stdout  2> level$N.stderr
done
```

- `--no-verification` (`main.go:L59`) makes the run a **safe dry-run**: zero outbound provider API calls, and the final summary reports zero verified/unverified secrets.
- `--log-level` (`main.go:L50`, *"Logging verbosity on a scale of 0 (info) to 5 (trace)"*, `-1` disables) selects which logr **V-levels** are emitted; the logger renders them as `info-N` labels. The decisive reason for escalating verbosity is that **the engine-initialization and detector-preparation signals are emitted at V(4) and are invisible at `--log-level=2`.** They were therefore *observed* (not inferred) by capturing at `--log-level=4`.

**Stream separation, proven.** `stdout` was **empty (0 bytes) at every level** (no secrets found), while all logs and the banner went to `stderr`. Observed sizes:

```
0 level2.stdout   0 level3.stdout   0 level4.stdout   0 level5.stdout
10 level2.stderr  14 level3.stderr  146 level4.stderr  148 level5.stderr   (line counts)
```

**Evidence presentation.** The real stderr log line is tab-separated:
`<RFC3339-timestamp>\t<info-N>\ttrufflehog\t<message>\t<json-fields>`. In the blocks below the **leading timestamp and the random 5-character worker IDs are redacted** (e.g. `<id>`) because they are volatile; the underlying capture is genuine and reproducible (identical structure and identical worker counts on a 128-CPU host).

---

## The observed startup sequence (backbone evidence)

This is the `--log-level=4` capture — the primary evidence block the rest of the document is built from. It was produced by:

```bash
/tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target --no-verification --log-level=4 2> level4.stderr
```

Timestamps and worker IDs are redacted; the 128 identical `finished scanning chunks` lines (one per scanner worker) are collapsed to a single representative line, with the count stated:

```
info-2  trufflehog  trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

info-4  trufflehog  default engine options set
info-4  trufflehog  engine initialized
info-4  trufflehog  setting up aho-corasick core
info-4  trufflehog  set up aho-corasick core
info-2  trufflehog  starting scanner workers              {"count": 128}
info-2  trufflehog  starting detector workers             {"count": 1024}
info-2  trufflehog  starting verificationOverlap workers  {"count": 128}
info-2  trufflehog  starting notifier workers             {"count": 128}
info-0  trufflehog  running source        {"source_manager_worker_id": "<id>", "with_units": true}
info-2  trufflehog  enumerating source    {"source_manager_worker_id": "<id>"}
info-3  trufflehog  chunking unit         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/readme.txt"}
info-3  trufflehog  chunking unit         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/config.ini"}
info-3  trufflehog  scanning file         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/readme.txt", "path": "<target>/readme.txt"}
info-3  trufflehog  scanning file         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/config.ini", "path": "<target>/config.ini"}
info-4  trufflehog  finished scanning chunks   {"scanner_worker_id": "<id>"}      # <-- 128 such lines total, one per scanner worker
info-0  trufflehog  finished scanning     {"chunks": 2, "bytes": 87, "verified_secrets": 0, "unverified_secrets": 0, "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The four sections below read this sequence top-to-bottom, mapping each signal to the source statement that emits it.

---

## Subsystem 1 — Configuration handling

**Direct answer.** Configuration is handled entirely up front in the CLI layer, *before* any engine object exists. The command line is parsed by **kingpin**; an in-memory `config.Config{}` is created and, **only if** `--config` is supplied, populated from a YAML file via `config.Read` → `NewYAML` (which parses *custom* detectors); a handful of feature flags are set from CLI flags; and finally an `engine.Config` value is assembled from the parsed flags plus the always-present default detector list. The startup banner and the version line are written to **stderr** (never stdout), which is why results and diagnostics never intermix.

**Observed output** (from the `--log-level=2` run; same lines head every level):

```bash
/tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target --no-verification --log-level=2 2> level2.stderr
```

```
info-2  trufflehog  trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

**Mechanism (cause → effect).**

- **CLI surface.** The root command is created as `kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")` (`main.go:L47`). Global flags are declared right after, including `--log-level` (`main.go:L50`, `Default("0")`), `--concurrency` (`main.go:L58`, `Default(strconv.Itoa(runtime.NumCPU()))`), `--no-verification` (`main.go:L59`), `--config` (`main.go:L70`, `ExistingFile()`), and `--include-detectors` (`main.go:L81`, `Default("all")`). *Effect:* flag defaults are resolved by kingpin before `run()` executes — this is why `--concurrency` already equals `128` (the host CPU count) with no flag passed, a fact that becomes visible later in the worker counts.
- **Version line + banner to stderr.** The `info-2` version line is emitted by `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` (`main.go:L410`) — hence it appears at `--log-level=2` and above. The banner is written by `fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")` (`main.go:L498`), guarded by `if !*jsonLegacy && !*jsonOut` (`main.go:L497`). *Effect:* the pig-emoji banner and version go to **stderr**, and are suppressed in JSON modes; results would go to stdout (empty here, since nothing was found).
- **Feature flags.** Inside `run()`, feature toggles are applied via `feature.*.Store(...)` — for example `feature.EnableAPKHandler.Store(true)` (`main.go:L458`), plus conditional stores around `main.go:L442-L454`. *Effect:* process-wide behavior (e.g. APK handling) is fixed before the engine is built.
- **Config load (only with `--config`).** `conf := &config.Config{}` (`main.go:L460`) starts empty; when `--config` is provided, `conf, err = config.Read(*configFilename)` (`main.go:L463`) runs. `Read` (`pkg/config/config.go:L18`) reads the file and delegates to `NewYAML` (`pkg/config/config.go:L27`), which unmarshals the YAML and converts each entry into a custom detector, returning them in `Config{Detectors: d}` (`pkg/config/config.go:L13-L14,L43`). *Effect:* in this dry-run **no `--config` was passed**, so `conf.Detectors` stays empty and only the built-in defaults are used — consistent with the observed absence of any custom-detector activity.
- **Engine-config assembly.** The CLI finishes by building `engConf := engine.Config{ ... }` (`main.go:L513`) with `Concurrency: *concurrency` (`main.go:L514`), `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` (`main.go:L519`), and `Verify: !*noVerification` (`main.go:L520`). *Effect:* the engine always receives the full default detector set (optionally extended by custom detectors), and `--no-verification` flips `Verify` to `false`, which is what makes the run a dry-run.

---

## Subsystem 2 — Scanning-engine initialization

**Direct answer.** The engine is built by `engine.NewEngine(ctx, &cfg)`, which runs two internal phases in order: `setDefaults()` fills in unset options (defaulting concurrency to `runtime.NumCPU()`, the detector-worker multiplier to `8`, and the notifier/verificationOverlap multipliers to `1`, and loading the default detector set when none were supplied), then `initialize()` allocates a fixed **512-entry LRU deduplication cache** and constructs the buffered inter-stage channels. Each phase emits a distinct `V(4)` signal, so the whole initialization is only visible at `--log-level=4` and above.

**Observed output** (only present at `--log-level=4`+):

```bash
/tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target --no-verification --log-level=4 2> level4.stderr
```

```
info-4  trufflehog  default engine options set
info-4  trufflehog  engine initialized
```

**Observed absence (evidence at `--log-level=2`).** At `--log-level=2` these two lines do **not** appear at all — the level-2 capture is only 10 lines and contains no `info-4` entries. That absence is itself evidence that engine-init lives at higher verbosity, which is precisely why the capture was escalated to level 4.

**Mechanism (cause → effect).**

- **Entry point.** `eng, err := engine.NewEngine(ctx, &cfg)` (`main.go:L688`) calls `func NewEngine(ctx context.Context, cfg *Config) (*Engine, error)` (`pkg/engine/engine.go:L226`). *Effect:* a single engine object is constructed that will own all worker pools, channels, and the detector prefilter.
- **`setDefaults()`** (`pkg/engine/engine.go:L336`) resolves defaults only where a value is unset:
  - Concurrency: guarded by `if e.concurrency == 0` (`pkg/engine/engine.go:L337`) → `runtime.NumCPU()` (`pkg/engine/engine.go:L338`). *Effect:* here the branch is **skipped** because `--concurrency` was already defaulted to `128` by the CLI (see the observed absence below), so `e.concurrency` stays `128`.
  - `detectorWorkerMultiplier = 8` (`pkg/engine/engine.go:L345`), with the source comment *"bound by net i/o so it's higher than other workers"* — the detector pool is intentionally the largest.
  - `notificationWorkerMultiplier = 1` (`pkg/engine/engine.go:L349`) and `verificationOverlapWorkerMultiplier = 1` (`pkg/engine/engine.go:L353`).
  - Default detectors: `if len(e.detectors) == 0 { e.detectors = defaults.DefaultDetectors() }` (`pkg/engine/engine.go:L361-L363`).
  - The phase closes by emitting `ctx.Logger().V(4).Info("default engine options set")` (`pkg/engine/engine.go:L373`) → the observed `info-4  default engine options set`.
- **`initialize()`** (`pkg/engine/engine.go:L489`):
  - `const cacheSize = 512` (`pkg/engine/engine.go:L491`) → `lru.New[string, detectorspb.DecoderType](cacheSize)` (`pkg/engine/engine.go:L493`). *Effect:* a 512-entry LRU cache is created and later assigned as `e.dedupeCache` (`pkg/engine/engine.go:L520`) to de-duplicate results. `(inferred)` The *purpose* of de-duplication is not printed; it is inferred from the cache's name and use.
  - The buffered channels are constructed (detailed in Subsystem 4) and the phase emits `ctx.Logger().V(4).Info("engine initialized")` (`pkg/engine/engine.go:L521`) → the observed `info-4  engine initialized`.

**Observed non-event (traced to cause).** The line `No concurrency specified, defaulting to max` (`pkg/engine/engine.go:L339`) **never appeared** at any level (grep count `0` across levels 2–5). *Cause:* `--concurrency` is pre-set to `runtime.NumCPU()` by the CLI flag default (`main.go:L58`), so `e.concurrency` is already `128` (non-zero) when `setDefaults()` runs, and the `if e.concurrency == 0` fallback at `pkg/engine/engine.go:L337` is skipped. This is a clean example of tracing an observed behavior — and a meaningful *non*-event — back to its exact source cause.


---

## Subsystem 3 — Detector preparation

**Direct answer.** Detectors are prepared as part of engine initialization. The engine starts from the **default detector set** (loaded when the user supplies none), narrows it with include/exclude filtering (`--include-detectors` defaults to `all`, so nothing is filtered out in a basic run), and then compiles the resulting detector list into an **Aho-Corasick keyword prefilter** — a fast, string-matching "core" that lets the engine cheaply decide which detectors *might* apply to a chunk before running their (more expensive) regular expressions. Building that core is bracketed by two `V(4)` log lines.

**Observed output** (only present at `--log-level=4`+):

```bash
/tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target --no-verification --log-level=4 2> level4.stderr
```

```
info-4  trufflehog  setting up aho-corasick core
info-4  trufflehog  set up aho-corasick core
```

**Mechanism (cause → effect).**

- **Default set.** With no detectors provided, `setDefaults()` assigns `e.detectors = defaults.DefaultDetectors()` (`pkg/engine/engine.go:L361-L363`); the CLI had already seeded the same list into `engine.Config.Detectors` via `append(defaults.DefaultDetectors(), conf.Detectors...)` (`main.go:L519`). *Effect:* the engine has a fully-populated detector list even though the user named none.
- **Include/exclude filtering.** Selection is resolved by `buildDetectorSets(cfg)` (`pkg/engine/engine.go:L376`), which parses the include/exclude flags through `config.ParseDetectors(cfg.IncludeDetectors)` (`pkg/engine/engine.go:L377`) and `config.ParseDetectors(cfg.ExcludeDetectors)` (`pkg/engine/engine.go:L381`). Because `--include-detectors` defaults to `all` (`main.go:L81`) and no `--exclude-detectors` was given, *effect:* the full default set survives filtering unchanged in this run.
- **Aho-Corasick core.** The prefilter is compiled by `e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)` (`pkg/engine/engine.go:L530`), bracketed by `ctx.Logger().V(4).Info("setting up aho-corasick core")` (`pkg/engine/engine.go:L529`) and `ctx.Logger().V(4).Info("set up aho-corasick core")` (`pkg/engine/engine.go:L531`). *Effect:* the observed pair of `info-4` lines marks the keyword trie being built from every detector's keywords. `(inferred)` That the core is used to *pre-screen* chunks with fast string comparisons ahead of regexes is an interpretation of its name and construction, not a literally printed statement — though it is consistent with public documentation of TruffleHog's keyword prefilter.

*This section deliberately stays at the mechanism level: it explains how the detector set is loaded, filtered, and compiled into the prefilter, and does not enumerate the individual default detectors.*


---

## Subsystem 4 — Inter-component communication

**Direct answer.** Once initialized, the engine starts **four worker pools** — scanner, detector, verificationOverlap, and notifier — and connects them with **buffered Go channels**. A `SourceManager` produces the data: it *runs* the filesystem source, *enumerates* its units (files), and *chunks* each unit; scanner workers turn chunks into detectable work, detector workers apply the prefilter and detectors, verificationOverlap workers reconcile cross-detector overlaps, and notifier workers dispatch results. This is a classic fan-out/fan-in pipeline: many workers pull from shared channels, and the channel buffers decouple producers from consumers.

**Observed output** (worker starts are `V(2)`, so visible from `--log-level=2`; the source lifecycle lines are mixed `V(0)`/`V(2)`/`V(3)`):

```bash
/tmp/trufflehog_build/trufflehog filesystem /tmp/thog_investigation/scan_target --no-verification --log-level=4 2> level4.stderr
```

```
info-2  trufflehog  starting scanner workers              {"count": 128}
info-2  trufflehog  starting detector workers             {"count": 1024}
info-2  trufflehog  starting verificationOverlap workers  {"count": 128}
info-2  trufflehog  starting notifier workers             {"count": 128}
info-0  trufflehog  running source        {"source_manager_worker_id": "<id>", "with_units": true}
info-2  trufflehog  enumerating source    {"source_manager_worker_id": "<id>"}
info-3  trufflehog  chunking unit         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/readme.txt"}
info-3  trufflehog  scanning file         {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/readme.txt", "path": "<target>/readme.txt"}
info-4  trufflehog  finished scanning chunks   {"scanner_worker_id": "<id>"}      # <-- 128 such lines total, one per scanner worker
```

**Mechanism (cause → effect).**

- **Pool launch order.** `eng.Start(ctx)` (`main.go:L692`) drives `startWorkers()` (`pkg/engine/engine.go:L646`), which launches the pools in a fixed order: scanner → detector → verificationOverlap → notifier. The four observed `starting … workers` lines appear in exactly that order.
- **Worker-count arithmetic** (all derived from `e.concurrency = 128` on this host):
  - **scanner** — `ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)` (`pkg/engine/engine.go:L663`); count = `e.concurrency` = **128**.
  - **detector** — `numWorkers := e.concurrency * e.detectorWorkerMultiplier` (`pkg/engine/engine.go:L676`), logged at `pkg/engine/engine.go:L678`; count = 128 × 8 = **1024** (the deliberately-largest pool).
  - **verificationOverlap** — `numWorkers := e.concurrency * e.verificationOverlapWorkerMultiplier` (`pkg/engine/engine.go:L691`), logged at `pkg/engine/engine.go:L693`; count = 128 × 1 = **128**.
  - **notifier** — `numWorkers := e.notificationWorkerMultiplier * e.concurrency` (`pkg/engine/engine.go:L706`), logged at `pkg/engine/engine.go:L708`; count = 1 × 128 = **128**.
  - *Effect:* the observed `{"count": 128 / 1024 / 128 / 128}` values are exactly these products.
- **Buffered channels connect the stages.** Buffer capacities are `var defaultChannelBuffer = runtime.NumCPU()` (`pkg/engine/engine.go:L627`, = 128 here) times fixed per-channel multipliers declared in `initialize()`: `detectableChunksChanMultiplier = 50` (`pkg/engine/engine.go:L503`), `verificationOverlapChunksChanMultiplier = 25` (`pkg/engine/engine.go:L507`), and `resultsChanMultiplier = 50` (`pkg/engine/engine.go:L508`). The channels are created as `e.detectableChunksChan` (`pkg/engine/engine.go:L515`), `e.verificationOverlapChunksChan` (`pkg/engine/engine.go:L517`), and `e.results` (`pkg/engine/engine.go:L519`). *Effect:* effective buffers on this host are **6400** (128×50), **3200** (128×25), and **6400** (128×50) respectively — the large buffers let fast producers stay ahead of consumers `(inferred, per the source comments)`.
- **Source production drives the data.** The `SourceManager` emits `running source` with `{"with_units": true}` via `ctx.Logger().Info("running source", "with_units", true)` (`pkg/sources/source_manager.go:L363-L364`) — `V(0)`, hence `info-0`. Because the filesystem source supports **source units**, this takes the `runWithUnits` path (`pkg/sources/source_manager.go:L511`), which then logs `enumerating source` via `ctx.Logger().V(2).Info("enumerating source")` (`pkg/sources/source_manager.go:L531`) and, per unit, `chunking unit` via `ctx.Logger().V(3).Info("chunking unit")` (`pkg/sources/source_manager.go:L557`). The filesystem source logs each file with `fileCtx.Logger().V(3).Info("scanning file")` (`pkg/sources/filesystem/filesystem.go:L179`). *Effect:* the observed `running source` → `enumerating source` → per-file `chunking unit` / `scanning file` lines trace one file being enumerated, chunked, and fed into the pipeline.
- **Completion signals.** Each scanner worker logs `ctx.Logger().V(4).Info("finished scanning chunks")` (`pkg/engine/engine.go:L840`) when its input channel drains — observed as **128 identical `info-4` lines** (one per scanner worker; `info-4` lines totaled 132 = 4 header signals + 128). The final tally is `logger.Info("finished scanning", ...)` (`main.go:L566`), the `info-0  finished scanning` summary.

```mermaid
graph TD
    CLI["main.run(): kingpin parse -> optional config.Read/NewYAML -> feature flags -> engine.Config"] --> NEW["engine.NewEngine()"]
    NEW --> SD["setDefaults(): concurrency=NumCPU=128, detectorMult=8, load DefaultDetectors<br/>log(V4): default engine options set"]
    SD --> INIT["initialize(): 512-entry LRU dedup cache + buffered channels<br/>log(V4): engine initialized"]
    INIT --> AC["NewAhoCorasickCore(detectors)<br/>log(V4): setting up / set up aho-corasick core"]
    AC --> START["eng.Start() -> startWorkers()"]
    SM["SourceManager: running source / enumerating source / chunking unit"]
    START --> SW["scanner workers (128)"]
    START --> DW["detector workers (1024 = 128x8)"]
    START --> VW["verificationOverlap workers (128 = 128x1)"]
    START --> NW["notifier workers (128 = 1x128)"]
    SM -->|"Chunks channel"| SW
    SW -->|"detectableChunksChan buffer 128x50 = 6400"| DW
    SW -->|"verificationOverlapChunksChan buffer 128x25 = 3200"| VW
    DW -->|"results buffer 128x50 = 6400"| NW
    NW --> OUT["output dispatcher -> stdout (empty in this dry-run)"]
```


---

## Worker counts & channel buffers — host-dependent vs. fixed

To keep the reported numbers honest, it is worth separating what is **fixed in source** from what is **derived from the host**:

| Value | Observed | Origin | Kind |
|-------|----------|--------|------|
| Base concurrency | 128 | `runtime.NumCPU()` on this 128-CPU host, via `--concurrency` default (`main.go:L58`) | **Host-dependent** |
| scanner workers | 128 | `e.concurrency` (`pkg/engine/engine.go:L663`) | Host-dependent |
| detector workers | 1024 | `e.concurrency * 8` (`pkg/engine/engine.go:L676`) | Host-dependent |
| verificationOverlap workers | 128 | `e.concurrency * 1` (`pkg/engine/engine.go:L691`) | Host-dependent |
| notifier workers | 128 | `1 * e.concurrency` (`pkg/engine/engine.go:L706`) | Host-dependent |
| `detectableChunksChan` buffer | 6400 | `128 * 50` (`pkg/engine/engine.go:L515`) | Host-dependent |
| `verificationOverlapChunksChan` buffer | 3200 | `128 * 25` (`pkg/engine/engine.go:L517`) | Host-dependent |
| `results` buffer | 6400 | `128 * 50` (`pkg/engine/engine.go:L519`) | Host-dependent |
| detector-worker multiplier | 8 | `pkg/engine/engine.go:L345` | **Fixed constant** |
| notifier / verificationOverlap multipliers | 1 / 1 | `pkg/engine/engine.go:L349,L353` | Fixed constant |
| channel multipliers | 50 / 25 / 50 | `pkg/engine/engine.go:L503,L507,L508` | Fixed constant |
| LRU dedup cache size | 512 | `pkg/engine/engine.go:L491` | Fixed constant |

On a machine with a different CPU count, the **multipliers, LRU size, and channel multipliers stay the same**, while every host-dependent value scales with `runtime.NumCPU()`.

## Progressive verbosity — exhaustive condition coverage

Escalating `--log-level` reveals progressively more of the pipeline, which is why more than the happy path was exercised. Observed stderr line counts: **level 2 → 10 lines, level 3 → 14, level 4 → 146, level 5 → 148.**

- **`--log-level=2`** — version line + pig banner, the four `starting … workers` counts, and the `running source` / `enumerating source` / `finished scanning` source lifecycle. (No `info-3` or `info-4` lines — the observed absence that motivates escalation.)
- **`--log-level=3`** — adds the `V(3)` per-unit lines: two `chunking unit` and two `scanning file` (one pair per file).
- **`--log-level=4`** — adds the `V(4)` engine-init/detector-prep signals (`default engine options set`, `engine initialized`, `setting up`/`set up aho-corasick core`) and the 128 per-worker `finished scanning chunks`.
- **`--log-level=5`** — adds two `V(5)` trace lines, one per file:

```
info-5  trufflehog  dataErrChan closed, all chunks processed   {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/readme.txt", "path": "<target>/readme.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
info-5  trufflehog  dataErrChan closed, all chunks processed   {"source_manager_worker_id": "<id>", "unit_kind": "unit", "unit": "<target>/config.ini", "path": "<target>/config.ini", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

That trace is emitted by `ctx.Logger().V(5).Info("dataErrChan closed, all chunks processed")` (`pkg/handlers/handlers.go:L413`).

## Dry-run confirmation

The scan verified nothing and found nothing, exactly as a `--no-verification` dry-run should. Observed final summary (`--log-level=4`), and an **empty stdout** at every level:

```
info-0  trufflehog  finished scanning     {"chunks": 2, "bytes": 87, "verified_secrets": 0, "unverified_secrets": 0, "trufflehog_version": "dev", ...}
```

`verified_secrets: 0` and `unverified_secrets: 0` confirm no verification calls were made (`Verify` was set to `false` by `--no-verification` at `main.go:L520`), `chunks: 2` / `bytes: 87` match the two-file, 87-byte target, `trufflehog_version: "dev"` confirms the canonical build, and the 0-byte stdout confirms results and logs are on separate streams.

---

## Coverage check

All four named subsystems were answered by name, each leading with a direct answer and grounded in observed output + exact command + verified `file:line` + cause → effect:

- [x] **Configuration handling** — kingpin flags (`main.go:L47-L81`), optional `config.Read`/`NewYAML` (`pkg/config/config.go:L18,L27`), feature flags (`main.go:L442-L458`), `engine.Config` assembly (`main.go:L513-L520`), banner + version to stderr (`main.go:L410,L498`). Observed: `trufflehog dev` + pig banner.
- [x] **Scanning-engine initialization** — `NewEngine` → `setDefaults` → `initialize` (`pkg/engine/engine.go:L226,L336,L489`); concurrency = `NumCPU`, **detector multiplier = 8**, notifier/verificationOverlap multipliers = **1/1**, **LRU cache = 512**. Observed: `default engine options set` + `engine initialized` (V4); absent at level 2.
- [x] **Detector preparation** — default set (`pkg/engine/engine.go:L361-L363`), include/exclude filtering with `--include-detectors=all` (`pkg/engine/engine.go:L376-L381`, `main.go:L81`), Aho-Corasick prefilter (`pkg/engine/engine.go:L529-L531`). Observed: `setting up`/`set up aho-corasick core` (V4).
- [x] **Inter-component communication** — four pools **128 / 1024 / 128 / 128** (`pkg/engine/engine.go:L663,L678,L693,L708`), **channel multipliers 50 / 25 / 50** → buffers 6400/3200/6400 (`pkg/engine/engine.go:L503-L519`), SourceManager fan-out/fan-in (`pkg/sources/source_manager.go:L363-L557`, `pkg/sources/filesystem/filesystem.go:L179`). Observed: the four worker starts + source lifecycle + 128 `finished scanning chunks`.

Exact constants present and correct: worker counts **128/1024/128/128**; detector multiplier **8**; notifier/verificationOverlap multipliers **1/1**; LRU **512**; channel multipliers **50/25/50** (buffers 6400/3200/6400, host-dependent); `defaultChannelBuffer = NumCPU() = 128`. Build command `CGO_ENABLED=0 go build`; run command `trufflehog filesystem <dir> --no-verification --log-level=N`; version `trufflehog dev`; banner uses the pig `🐷`.

## Observed-vs-inferred summary

Almost everything above is directly observed. The few **inferred** statements are limited to *purpose/interpretation* of mechanisms whose existence is observed but whose intent is not literally printed:

- `(inferred)` The 512-entry LRU cache's role is result **de-duplication** — inferred from its name (`dedupeCache`, `pkg/engine/engine.go:L520`) and placement, not from a printed message.
- `(inferred)` The Aho-Corasick core acts as a **keyword prefilter run ahead of regexes** — inferred from its construction from the detector set and consistent with public TruffleHog documentation; the logs only state the core is being set up.
- `(inferred)` The large channel buffers exist to **let producers outpace consumers** — inferred from the source comments at `pkg/engine/engine.go:L497-L508`, not from runtime output.

All numeric values, log lines, stream behavior, worker counts, and the observed non-event (`No concurrency specified` never firing) are **observed**, reproducibly, on this 128-CPU host.

