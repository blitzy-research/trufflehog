# How TruffleHog "Comes Online" During a Basic Filesystem Scan

> **Runtime‑grounded investigation.** Every behavioral claim below is paired with a **verbatim log line that I observed by building and running the tool myself**, together with the exact `file:line` in the source that emits it. Statements I know only from reading source (and did **not** observe at runtime in the safe default run) are explicitly labelled **`inferred`**. Nothing in the repository was modified — this document is the only artifact.

---

## 1. The question, decomposed

The investigation answers *how does TruffleHog start up and run a basic `filesystem` scan*, broken into the four named subsystems plus the two cross‑cutting mechanisms that make them observable:

- **(a) Configuration handling** — how the engine gets its options and detector set.
- **(b) Scanning‑engine initialization** — how the `Engine` object is constructed and prepared.
- **(c) Detector preparation** — how detectors are indexed for matching.
- **(d) Component communication** — how the worker pools, source manager and channels move data.
- **Cross‑cutting 1: the `--log-level` → verbosity mapping** — *why a single `--debug` run is not enough* to see (b) and (c).
- **Cross‑cutting 2: version stamping** — why the build reports `dev`.

### Methodology (binding rule set `SWE-AtlasQnA-Repo`)

1. **Built first, then wrote.** I compiled a dev binary and ran the real entry point — the `filesystem` subcommand, which drives the real `Engine` pipeline — before writing a single claim.
2. **Dual verbosity, each repeated ≥ 2×.** I ran once at `--log-level=2` (the debug band) and once at `--log-level=5` (trace), twice each. As proven in §3, the initialization lines for (b) and (c) log at `V(4)` and are **absent at level 2** — a plain `--debug` run cannot answer them.
3. **One claim, one piece of evidence.** Each claim carries its own verbatim observed line and `file:line`.
4. **Safe.** Every run used `--no-verification` (no outbound API calls) and `--no-update`, against a 12‑byte throwaway directory created **outside** the repository.
5. **Read‑only.** `git status --porcelain` was **empty before and after** the investigation; the binary, scan directory and logs all lived under `/tmp`.

### Run scale and stability

The scanned input was a single 12‑byte file (`hello world\n`), producing **1 chunk / 12 bytes** on every run. Worker counts were **identical and stable across all four runs**; `scan_duration` is therefore reported as an observed **range**, not a single value. (Details in §4d and §8.)

---

## 2. Exact build & invocation commands (canonical default build)

These are the commands I ran; the document's values come from their output. The build is the **canonical default** — a plain `go build` with **no ldflags** and **no `--config`**, so version/banner/worker values are what a normal user of a source build sees.

```bash
# 0) Toolchain on PATH (matches go.mod:5 `toolchain go1.24.2`)
export PATH=/usr/local/go/bin:$PATH
go version                                  # observed: go version go1.24.2 linux/amd64

# 1) Canonical dev build (no ldflags) — binary OUTSIDE the repo
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o /tmp/trufflehog .
/tmp/trufflehog --version                   # observed: trufflehog dev

# 2) Minimal throwaway directory OUTSIDE the repo (12 bytes)
mkdir -p /tmp/th_min && printf 'hello world\n' > /tmp/th_min/sample.txt

# 3) Dual-verbosity runs, each repeated >=2x, safe (no verification, no update)
/tmp/trufflehog filesystem /tmp/th_min --log-level=2 --no-verification --no-update
/tmp/trufflehog filesystem /tmp/th_min --log-level=5 --no-verification --no-update

# 4) Read-only proof (prints nothing)
git status --porcelain

# 5) Cleanup (leave the machine as found)
rm -rf /tmp/trufflehog /tmp/th_min
```

**Observed build facts (this host):**

- `go version` → `go version go1.24.2 linux/amd64`.
- Build time: **~159 s cold** (measured after `go clean -cache`) and **~3 s warm** (relink only). The produced binary is a **194 MB statically‑linked ELF** at `/tmp/trufflehog`.
- Host CPU: **`nproc` = 4** — but see §4d/§9, because this is *not* the number TruffleHog uses.

**Version output — observed verbatim** (written to **stderr**):

```
trufflehog dev
```

This is emitted by `cli.Version("trufflehog " + version.BuildVersion)` [main.go:270], where `var BuildVersion = "dev"` [pkg/version/version.go:3]. `dev` is the **non‑canonical, default (non‑release) value** — see §9 for how release builds override it.

> **Note on log capture.** TruffleHog writes all structured logs to **stderr**; I captured each run with `2> file.log`. The console fields are **tab‑separated**: `TIMESTAMP <tab> info-<V> <tab> trufflehog <tab> MESSAGE <tab> {JSON fields}`. The `info-<V>` token encodes the verbosity level `V` at which the line was logged — this token is the key to the whole investigation (§3).

---

## 3. Cross‑cutting mechanism #1 — `--log-level` → verbosity, and **why `V(4)` needs trace** (the crux)

This is the single most important nuance in the whole investigation: **the engine/detector initialization lines are always emitted by the program, but they log at `V(4)`, which is above the `--log-level=2` (debug) threshold.** A `--debug`/level‑2 run therefore *silently omits* them — they are **below the verbosity threshold, not skipped**.

### The flag and its aliases (the "named items")

- **`--log-level`** — help string, observed verbatim in source: `` `Logging verbosity on a scale of 0 (info) to 5 (trace). Can be disabled with "-1".` `` with `.Default("0")` [main.go:50]. The convention it points at is documented in `CONTRIBUTING.md` [main.go:49].
- **`--debug`** — hidden alias [main.go:51].
- **`--trace`** — hidden alias [main.go:52].
- **`-1` ("disabled")** — the `default` branch maps a `-1` request to `log.SetLevel(-5)` (zap's fatal band) [main.go:316-319].

The flags resolve to a numeric level in a single switch [main.go:304-322]:

```go
switch {
case *trace:
    log.SetLevel(5)          // --trace  == level 5
case *debug:
    log.SetLevel(2)          // --debug  == level 2
default:
    l := int8(*logLevel)
    // validates -1..5, maps -1 -> SetLevel(-5), else SetLevel(l)
}
```

So **`--debug` is exactly `--log-level=2`** and **`--trace` is exactly `--log-level=5`** — which is why I ran the numeric levels 2 and 5 directly.

### The negation that decides what `V(n)` is visible

`SetLevel` [pkg/log/level.go:21] forwards to `SetLevelForControl`, whose body **negates** the level before handing it to zap [pkg/log/level.go:30]:

```go
// For example setting the level to -2 below, means log.V(2) will be enabled.   // pkg/log/level.go:29
control.SetLevel(zapcore.Level(-level))                                          // pkg/log/level.go:30
```

Cause → effect: `SetLevel(2)` configures zap at level `-2`, which enables `V(0)`, `V(1)`, `V(2)` **but not `V(4)`**. `SetLevel(5)` enables `V(0)..V(5)`. Therefore the `V(4)` engine/detector init lines require `--log-level=4`, `--log-level=5`, or `--trace`.

### What `CONTRIBUTING.md` actually documents (reported exactly)

`CONTRIBUTING.md` [CONTRIBUTING.md:21, "## Logging in TruffleHog"] documents levels **0–5** (not 0–3), verbatim in substance:

```
0. — logs we always want to see
1. — logs we could possibly want to turn off
2. — logs that are useful for debugging
3. — frequently called logs that may produce a lot of output
4. — extremely verbose logs or logs containing sensitive information
5. — ultimate verbosity
```

So `V(4)` **is** documented — as "extremely verbose logs or logs containing sensitive information" — but it sits **above** the debug (level 2) threshold. That is precisely why a plain `--debug` run omits the init lines.

### Evidence: the init/pipeline lines are **absent at level 2** and **present at level 5**

I captured each run to a log under `/tmp` (redirecting stderr, `2> l<level>_run<N>.log`) and ran `grep -c` over run #1 of each level. **The exact commands and their raw output, verbatim:**

```console
$ grep -c 'default engine options set' l2_run1.log l5_run1.log
l2_run1.log:0
l5_run1.log:1
$ grep -c 'engine initialized' l2_run1.log l5_run1.log
l2_run1.log:0
l5_run1.log:1
$ grep -c 'aho-corasick' l2_run1.log l5_run1.log
l2_run1.log:0
l5_run1.log:2
$ grep -c 'chunking unit' l2_run1.log l5_run1.log
l2_run1.log:0
l5_run1.log:1
$ grep -c 'scanning file' l2_run1.log l5_run1.log
l2_run1.log:0
l5_run1.log:1
```

Every initialization/pipeline pattern is `0` at level 2 and non-zero at level 5 (the `aho-corasick` pattern matches **2** lines — `setting up` + `set up`). The total output size confirms the same, verbatim:

```console
$ wc -l l2_run1.log l5_run1.log
   10 l2_run1.log
  145 l5_run1.log
  155 total
```

The whole level-2 run is only **10 lines** of output; the level-5 run is **145 lines**. The extra **135 lines** are exactly the `V(3)`/`V(4)`/`V(5)` traffic that the negation mechanism gates out at level 2. This is the proof that (b) and (c) are answerable **only** from the trace run.

---

## 4. The four subsystems, grounded in observed output

The observed emission **order** at `--log-level=5` narrates the startup causally:
`default engine options set` → `engine initialized` → `setting up aho-corasick core` → `set up aho-corasick core` → the four worker‑pool lines → the source‑manager pipeline → `finished scanning`. Each subsystem below is anchored to its own verbatim line from that sequence.

### (a) Configuration handling

**Claim.** In the default run (no `--config`), the CLI hands the engine the full default detector set and the engine then applies its remaining option defaults, logging when that is done. **Observed at `--log-level=5`:**

```
2026-07-03T00:07:39Z	info-4	trufflehog	default engine options set
```

**How/why (cause → effect).** The observed line is emitted at the very end of `setDefaults` [pkg/engine/engine.go:373]; it marks that the engine's option defaults have been applied. **What supplies the detectors is the CLI, not the `setDefaults` fallback** — a source-grounded point, since no single runtime line prints the detector set. `main.go` builds the engine config with `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)` [main.go:519], under the explicit in-code comment that the engine must always be configured with the list of default detectors and that the user filters are *only subtractive* [main.go:515-518]. `NewEngine` copies that slice straight into the engine — `detectors: cfg.Detectors` [pkg/engine/engine.go:232] (in the struct literal at [pkg/engine/engine.go:229-233]). Consequently, when `setDefaults` runs [pkg/engine/engine.go:336] `e.detectors` is **already non-empty**, so the fallback guard `if len(e.detectors) == 0` [pkg/engine/engine.go:362] is **false** and `e.detectors = defaults.DefaultDetectors()` [pkg/engine/engine.go:363] **does not execute in the normal CLI run** — that branch is a safety net for an engine built *without* detectors (an incomplete / non-CLI configuration). The default detector set is therefore the CLI-supplied "all" set (`--include-detectors` defaults to `"all"` [main.go:81], `--exclude-detectors` empty [main.go:82]), which the engine then filters **subtractively** during construction (`buildDetectorSets` [pkg/engine/engine.go:254-255] → `filterDetectors` [pkg/engine/engine.go:472]). The same `setDefaults` also fixes the worker multipliers that later determine the pool sizes in (d): detector `8` [pkg/engine/engine.go:345], notification `1` [pkg/engine/engine.go:349], verificationOverlap `1` [pkg/engine/engine.go:353].

**A default that did *not* fire (reported because it is unexpected‑adjacent).** `setDefaults` also contains a `if e.concurrency == 0 { … "No concurrency specified, defaulting to max" … }` branch [pkg/engine/engine.go:337-341]. That log was **absent from all my runs** (it is not in the 145‑line level‑5 output) because the CLI already presets concurrency to `runtime.NumCPU()` via the flag default `.Default(strconv.Itoa(runtime.NumCPU()))` [main.go:58]; `e.concurrency` is therefore non‑zero and the branch is skipped. The base‑concurrency origin to cite is thus **main.go:58**, not the engine default.

**`inferred` (the `--config` path — not exercised in the safe default run).** When a user passes `--config <file>`, the YAML is read by `Read` [pkg/config/config.go:18], which delegates to `NewYAML` [pkg/config/config.go:27], which parses it with `protoyaml.UnmarshalStrict` [pkg/config/config.go:30]. I ran **without** `--config`, so this path produced no output; the mechanism is stated here as `inferred` from reading.

### (b) Scanning‑engine initialization

**Claim.** After options are set, the engine constructs its internal state — a bounded dedup cache and its inter‑stage channels — and logs that it is initialized. **Observed at `--log-level=5`:**

```
2026-07-03T00:07:39Z	info-4	trufflehog	engine initialized
```

**How/why (cause → effect).** The engine is created by `NewEngine` [pkg/engine/engine.go:226], wired from the CLI at `engine.NewEngine(ctx, &cfg)` [main.go:688]. `NewEngine` calls `initialize` [pkg/engine/engine.go:489], which:

- allocates an **LRU dedup cache** of `const cacheSize = 512` entries [pkg/engine/engine.go:491] via `lru.New[...](cacheSize)` [pkg/engine/engine.go:493];
- allocates the engine's **communication channels** — `detectableChunksChan`, `verificationOverlapChunksChan`, and `results` [pkg/engine/engine.go:515-519] (these are the channels the worker pools in (d) exchange work over);
- stores the cache (`e.dedupeCache = cache` [pkg/engine/engine.go:520]) and then logs `engine initialized` [pkg/engine/engine.go:521].

Because this line logs at `V(4)`, it is one of the two subsystems invisible at `--debug` (proven in §3).

### (c) Detector preparation

**Claim.** With detectors chosen (a) and the engine initialized (b), the engine builds the **Aho‑Corasick keyword prefilter** that maps chunk keywords to candidate detectors, bracketed by two log lines. **Observed at `--log-level=5`:**

```
2026-07-03T00:07:39Z	info-4	trufflehog	setting up aho-corasick core
2026-07-03T00:07:39Z	info-4	trufflehog	set up aho-corasick core
```

**How/why (cause → effect).** The two lines bracket the construction call: `setting up aho-corasick core` [pkg/engine/engine.go:529] → `e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)` [pkg/engine/engine.go:530] → `set up aho-corasick core` [pkg/engine/engine.go:531]. Inside `NewAhoCorasickCore` [pkg/engine/ahocorasick/ahocorasickcore.go:141] the engine builds a **keyword → detector index**: it creates `keywordsToDetectors := make(map[string][]DetectorKey)` [pkg/engine/ahocorasick/ahocorasickcore.go:142], iterates every detector, and for each of the detector's `Keywords()` lower‑cases the keyword and appends the detector's key to the map [pkg/engine/ahocorasick/ahocorasickcore.go:145-151], finally building the trie prefilter from those keywords [pkg/engine/ahocorasick/ahocorasickcore.go:159]. The detector set fed in is exactly the default set from (a) — `DefaultDetectors()` [pkg/engine/defaults/defaults.go:1704]. Each detector satisfies the `Detector` interface [pkg/detectors/detectors.go:19], contributing `Keywords() []string` [pkg/detectors/detectors.go:24] for this prefilter and `FromData(ctx, verify, data)` [pkg/detectors/detectors.go:21] for later detection. At scan time the prefilter is queried by `FindDetectorMatches` [pkg/engine/ahocorasick/ahocorasickcore.go:241] to pick candidate detectors per chunk.


### (d) Component communication

TruffleHog's runtime is a **four‑worker‑class concurrent pipeline** wired together by channels. The model is documented in‑repo (`docs/concurrency.md`, `docs/process_flow.md`); below, every *claim* is tied to an observed line.

**Claim 1 — four worker pools start, with host‑derived counts.** **Observed at `--log-level=2` (and 5); identical and stable across all four runs:**

```
2026-07-03T00:07:39Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-03T00:07:39Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-03T00:07:39Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-03T00:07:39Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

**How/why (cause → effect).** `startWorkers` [pkg/engine/engine.go:646] launches the four pools, each logging its size at `V(2)`:

- **scanner** — `count = e.concurrency` (**1×**) [pkg/engine/engine.go:663]. Scanner workers enumerate and chunk the source (`docs/concurrency.md`).
- **detector** — `numWorkers = e.concurrency * e.detectorWorkerMultiplier` (**8×**) [pkg/engine/engine.go:676-678]; the 8× multiplier is the `detectorWorkerMultiplier = 8` set in `setDefaults` [pkg/engine/engine.go:345], because detector work is network‑I/O bound.
- **verificationOverlap** — `numWorkers = e.concurrency * e.verificationOverlapWorkerMultiplier` (**1×**) [pkg/engine/engine.go:691-693]; handles chunks matched by multiple detectors.
- **notifier** — `numWorkers = e.notificationWorkerMultiplier * e.concurrency` (**1×**) [pkg/engine/engine.go:706-708]; reports results to output.

So the derivation is **1× / 8× / 1× / 1×** of `e.concurrency`, and `e.concurrency = runtime.NumCPU()` via the flag default [main.go:58]. On this host `runtime.NumCPU()` = **128** (see §9 — note that `nproc` = 4 here, but Go does **not** use the cgroup quota), giving **128 / 1024 / 128 / 128**. These counts are **host‑derived**, not a fixed constant.

**Claim 2 — the source is driven through enumerate → chunk.** **Observed** (`running source` and `enumerating source` at level 2+; `chunking unit` and `scanning file` only at level 5):

```
2026-07-03T00:07:39Z	info-0	trufflehog	running source	{"source_manager_worker_id": "I27x0", "with_units": true}
2026-07-03T00:07:39Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "I27x0"}
2026-07-03T00:07:39Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "I27x0", "unit_kind": "unit", "unit": "/tmp/th_min/sample.txt"}
2026-07-03T00:07:39Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "I27x0", "unit_kind": "unit", "unit": "/tmp/th_min/sample.txt", "path": "/tmp/th_min/sample.txt"}
```

**How/why (cause → effect).** The Source Manager runs the source with units (the filesystem source supports them) and logs `running source` with `"with_units": true` at `V(0)` [pkg/sources/source_manager.go:363]. It then logs `enumerating source` at `V(2)` [pkg/sources/source_manager.go:531] and, per unit, `chunking unit` at `V(3)` [pkg/sources/source_manager.go:557] — `V(3)`, so it is **absent at level 2** and present at level 5, consistent with §3. The `scanning file` line is emitted by the **filesystem source itself** at `V(3)` [pkg/sources/filesystem/filesystem.go:179]. The filesystem `Source` implements `sources.SourceUnitEnumChunker` [pkg/sources/filesystem/filesystem.go:43]; its `Enumerate` [pkg/sources/filesystem/filesystem.go:202] discovers the directory's files and its `ChunkUnit` [pkg/sources/filesystem/filesystem.go:242] / `Chunks` [pkg/sources/filesystem/filesystem.go:85] produce the file‑content chunks. This matches `docs/process_flow.md`'s `FilesystemSource → FilesystemUnit(Directory) → FilesystemChunk(file contents)`. The scan is entered from the CLI at `eng.ScanFileSystem(ctx, cfg)` [main.go:786].

**Claim 3 — chunks and results flow over named channels (`inferred from source/docs` — not a runtime-observed line).** *No log line in any of my four runs prints the channel names,* so this claim is grounded in reading the source and the in-repo docs, not in observed output, and is labelled accordingly. The engine exposes the two ends of the pipeline: `ChunksChan()` returns the source manager's chunk stream [pkg/engine/engine.go:744] and `ResultsChan()` returns `e.results` [pkg/engine/engine.go:748]. Per `docs/concurrency.md`, scanner workers read from `ChunksChan()`, forward to `detectableChunksChan` / `verificationOverlapChunksChan`, and detector workers publish `detectors.ResultWithMetadata` to `ResultsChan()` (`e.results`) for the notifier workers — the exact channels allocated in `initialize` (b) [pkg/engine/engine.go:515-519]. The *effects* of this wiring are what I observed (worker counts in Claim 1, source enumeration in Claim 2, the per-worker `finished scanning chunks` in Claim 4); only the channel **names** themselves are source-derived.

**Claim 4 — the scanner-worker count is corroborated by a second, independent signal.** **Observed at `--log-level=5`, one line per scanner worker** — emitted by `ctx.Logger().V(4).Info("finished scanning chunks")` [pkg/engine/engine.go:840]:

```
2026-07-03T00:07:39Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "PfrwW"}
```

Because that line is emitted once per scanner worker, its count equals the scanner-pool size. **Verbatim:**

```console
$ grep -c 'finished scanning chunks' l5_run1.log l5_run2.log
l5_run1.log:128
l5_run2.log:128
```

**128** on *both* level-5 runs — exactly the scanner-pool `count` of 128 from Claim 1: an independent cross-check that the 1× scanner pool is host-derived from `runtime.NumCPU()` = 128. A trace-only `V(5)` line also marks the end of chunk production for the unit — emitted by `ctx.Logger().V(5).Info("dataErrChan closed, all chunks processed")` at [pkg/handlers/handlers.go:413] (an *additional* emitting source surfaced by the run, beyond the reference anchors enumerated in the plan; it belongs to the input-handling layer that feeds the filesystem chunk stream):

```
2026-07-03T00:07:39Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "I27x0", "unit_kind": "unit", "unit": "/tmp/th_min/sample.txt", "path": "/tmp/th_min/sample.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

---

## 5. Terminal summary (observed at every verbosity, `V(0)`)

The run ends with a single summary line. **Observed verbatim (level‑5, run #1):**

```
2026-07-03T00:07:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 12, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.486305ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Emitted by `logger.Info("finished scanning", …)` [main.go:566], whose fields are `chunks` [main.go:567], `bytes` [main.go:568], `verified_secrets` [main.go:569], `unverified_secrets` [main.go:570], `scan_duration` [main.go:571], `trufflehog_version` = `version.BuildVersion` [main.go:572], and `verification_caching` [main.go:573]. For this 12‑byte input the observed scale was **`chunks` = 1, `bytes` = 12** on all four runs, `verified_secrets`/`unverified_secrets` = 0 (nothing to find, and `--no-verification` anyway), and `trufflehog_version` = `dev` (matching the `--version` output in §2).

---

## 6. Startup banner (level 2+)

Before the worker lines, at level 2+, TruffleHog prints a version log line and its ASCII banner. **Observed verbatim:**

```
2026-07-03T00:07:39Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

The `info-2 … trufflehog dev` line is `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` [main.go:410] (so it is absent at level 0/1); the emoji banner is `fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")` [main.go:498], printed unless a JSON output mode is selected.

---

## 7. Cross‑cutting mechanism #2 — version stamping (`dev` is non‑canonical)

**Observed:** `/tmp/trufflehog --version` → `trufflehog dev`, and `"trufflehog_version": "dev"` in the summary (§5). The value comes from `var BuildVersion = "dev"` [pkg/version/version.go:3], surfaced via `cli.Version("trufflehog " + version.BuildVersion)` [main.go:270].

- **`dev` is the non‑canonical, default (non‑release) value.** It is what a plain `go build` yields because nothing overrides the variable.
- **`inferred` (release behavior — not exercised).** Tagged releases stamp a real version through goreleaser ldflags: `-X 'github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion={{ .Version }}'` [.goreleaser.yml:18-19] (the same override also appears for the UPX build variant at .goreleaser.yml:6). My canonical build passed **no** ldflags, so this is stated as `inferred` from reading. (Aside: `dev` also disables the auto‑updater — `if version.BuildVersion == "dev" { updateCfg.Fetcher = nil }` [main.go:360-361].)

---

## 8. Labeled notes: non‑canonical & host‑dependent values, and stability

- **(i) `dev` version — non‑canonical.** As in §7, `dev` is the default dev‑build value [pkg/version/version.go:3]; release builds override it via ldflags [.goreleaser.yml:18-19] (`inferred`).
- **(ii) Worker counts — host‑derived.** 128 / 1024 / 128 / 128 are derived from `runtime.NumCPU()` [main.go:58], **not** a fixed constant. On this host the shell `nproc` reports **4** (a cgroup CPU quota), yet TruffleHog started **128** scanner workers — because Go's `runtime.NumCPU()` reads the host's CPU count, not the cgroup quota. A direct throwaway probe (a one‑file `go run` outside the repo, offered only as **corroboration**, non‑canonical) printed `runtime.NumCPU()=128 GOMAXPROCS=128`, matching the observed scanner count. **Report exactly what is observed:** on a host where `runtime.NumCPU()` differs, these counts will differ.
- **(iii) `scan_duration` — a range; counts — stable.** The four `finished scanning` summary lines are the auditable source of the timing; **verbatim** (the `scan_duration` field extracted from each run's captured log, in run order — two level-2 runs then two level-5 runs):

```console
$ grep -hP 'finished scanning\t' l2_run1.log l2_run2.log l5_run1.log l5_run2.log | grep -oP '"scan_duration": "[^"]*"'
"scan_duration": "4.160324ms"
"scan_duration": "4.212889ms"
"scan_duration": "3.486305ms"
"scan_duration": "4.26542ms"
```

That is an observed **range of ≈ 3.49 – 4.27 ms** for the 12-byte / 1-chunk input. The durations vary run-to-run within that tight band with **no consistent ordering by verbosity level** — here the fastest run (`3.486305ms`) was in fact a `--log-level=5` run — reported exactly as observed. Worker counts, `chunks` (1) and `bytes` (12) were **identical across all four runs**; the distinct random `source_manager_worker_id` per run (`jrqGQ`, `ZPkng`, `I27x0`, `ypYmV`) confirms these were four genuinely separate runs.

---

## 9. Coverage pass

- **(a) Configuration handling** — ✅ evidence `default engine options set` [pkg/engine/engine.go:373]; the full default detector set is **supplied by the CLI** via `append(defaults.DefaultDetectors(), conf.Detectors...)` [main.go:519] and copied into the engine at [pkg/engine/engine.go:232], so the `if len(e.detectors)==0` fallback [pkg/engine/engine.go:361-363] does **not** fire in the CLI run; include/exclude filters apply subtractively [pkg/engine/engine.go:254-255,472] with `--include-detectors` default `"all"` [main.go:81]; multipliers 8/1/1 [pkg/engine/engine.go:345,349,353]; the non-firing "No concurrency specified" branch explained [pkg/engine/engine.go:337-341] with base concurrency at [main.go:58]; **`--config` YAML path labelled `inferred`** [pkg/config/config.go:18-30].
- **(b) Scanning‑engine initialization** — ✅ evidence `engine initialized` [pkg/engine/engine.go:521]; `NewEngine` [pkg/engine/engine.go:226] wired at [main.go:688]; **LRU dedup cache** (`cacheSize = 512`) [pkg/engine/engine.go:491-493] and channel allocation [pkg/engine/engine.go:515-519] inside `initialize` [pkg/engine/engine.go:489].
- **(c) Detector preparation** — ✅ evidence `setting up aho-corasick core` / `set up aho-corasick core` [pkg/engine/engine.go:529-531]; **keyword → detector index** built by `NewAhoCorasickCore` [pkg/engine/ahocorasick/ahocorasickcore.go:141-151] from `DefaultDetectors()` [pkg/engine/defaults/defaults.go:1704]; each detector's `Keywords()` [pkg/detectors/detectors.go:24] and `FromData` [pkg/detectors/detectors.go:21]; queried by `FindDetectorMatches` [pkg/engine/ahocorasick/ahocorasickcore.go:241].
- **(d) Component communication** — ✅ evidence the four `starting … workers` lines [pkg/engine/engine.go:663,678,693,708] with the **1×/8×/1×/1×** derivation; the pipeline lines `running source`/`enumerating source`/`chunking unit`/`scanning file` [pkg/sources/source_manager.go:363,531,557; pkg/sources/filesystem/filesystem.go:179]; the `ChunksChan()`/`ResultsChan()` channels [pkg/engine/engine.go:744,748]; the per‑worker `finished scanning chunks` cross‑check (= 128). The **four worker classes**, the **channels**, `ScanFileSystem` [main.go:786], and the filesystem `Enumerate`/`ChunkUnit`/`Chunks` [pkg/sources/filesystem/filesystem.go:202,242,85] are all addressed.
- **Cross‑cutting #1 (`--log-level` → verbosity)** — ✅ the flag [main.go:50], the **`--debug`/`--trace` aliases** [main.go:51-52], the **`-1` disable** [main.go:316-319], the switch [main.go:304-322], the **negation** [pkg/log/level.go:29-30], and the `CONTRIBUTING.md` **0–5** table [CONTRIBUTING.md:21]; the `V(4)`‑needs‑trace crux **proven by grep** (absent at level 2, present at level 5).
- **Cross‑cutting #2 (version stamping)** — ✅ observed `dev` [pkg/version/version.go:3, main.go:270]; **release ldflags labelled `inferred`** [.goreleaser.yml:18-19].
- **Terminal summary** — ✅ `finished scanning` with `chunks`/`bytes`/`scan_duration`/`trufflehog_version: "dev"` [main.go:566-572].
- **Every "e.g./such as/including/like" named item** — ✅ log‑level flag + `--debug`/`--trace` + `-1` disable; the four worker classes (scanner/detector/verificationOverlap/notifier); the channels (`ChunksChan`/`ResultsChan`/`detectableChunksChan`/`verificationOverlapChunksChan`/`results`); default‑detectors = "all"; the `--config` inferred path; `dev` vs release version; the LRU dedup cache; the Aho‑Corasick keyword index.
- **Inferred‑vs‑observed labeling** — ✅ applied throughout (the `--config` YAML path and release‑ldflags behavior are the only `inferred` items; all else is observed).
- **Read‑only proof** — ✅ `git status --porcelain` was **empty before and after**; the binary, `/tmp/th_min`, logs and the throwaway NumCPU probe all lived under `/tmp` and were removed; **no existing repository file was modified**.

