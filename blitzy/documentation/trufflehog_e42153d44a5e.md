# How TruffleHog Comes Online During a Basic Run — A Runtime Startup Narrative

> **What this document is.** An evidence-grounded explanation of how the [TruffleHog](https://github.com/trufflesecurity/trufflehog) secrets‑detection tool (Go module `github.com/trufflesecurity/trufflehog/v3`) is *structured* and how it *behaves* during a basic run. Every behavioral claim below is paired with (a) a **real log line I captured by running the built binary** and (b) a **`file:line` citation** naming the exact function/method/struct that produces the behavior. It is deliberately a **runtime startup narrative, not a file‑by‑file catalogue** of the repository.
>
> **Methodology in one sentence.** I built the canonical binary from source, ran a safe dry‑run (`--no-verification`) over a minimal directory at two verbosity levels (`--log-level=2` and `--log-level=5`), captured the complete unedited output, then mapped each observed log line back to the function that emits it. **Running was the first step, not the last.**

---

## Metadata

| Field | Value |
|-------|-------|
| Module | `github.com/trufflesecurity/trufflehog/v3` (`go.mod:1`) |
| Declared toolchain | `toolchain go1.24.2` (`go.mod:5`); minimum `go 1.23.1` (`go.mod:3`) |
| Binary version observed | `trufflehog dev` (canonical default build; `pkg/version/version.go:3`) |
| Host CPU count (authoritative) | **128** — `runtime.NumCPU()` (drives every worker magnitude below) |
| Build recipe | `CGO_ENABLED=0 go build -o /tmp/trufflehog .` (mirrors `Dockerfile:9` `go build -o trufflehog .`; `CGO_ENABLED=0` at `Dockerfile:5`) |
| Scan source used | `filesystem` (local files/dirs; `README.md:257`) |
| Verification | Disabled via `--no-verification` → `Verify=false` (`main.go:520`) |
| Run stability | Worker counts + line counts identical across **4 runs** (2× level 2, 2× level 5) |

---

## Direct answer (lead) — the observed startup flow

A basic `filesystem` dry‑run brings the tool online in this exact, observed order (each arrow is a real log line reproduced later in this document):

```text
main(): build Zap logger, SetDefaultLogger              [main.go:336-338]
  → run(state): version banner  "trufflehog dev" (info-2) [main.go:410]
  → ASCII banner "🐷🔑🐷 …" printed to stderr             [main.go:498]
  → NewEngine → setDefaults:  "default engine options set" (info-4)  [engine.go:373]
  → initialize: 512-entry LRU + 3 buffered channels; "engine initialized" (info-4)  [engine.go:521]
  → "setting up aho-corasick core" / "set up aho-corasick core" (info-4)  [engine.go:529,531]
  → Start → startWorkers: 4 goroutine pools (scanner/detector/verificationOverlap/notifier)  [engine.go:646]
      "starting scanner workers"          {"count": 128}  (info-2)  [engine.go:663]
      "starting detector workers"         {"count": 1024} (info-2)  [engine.go:678]
      "starting verificationOverlap workers" {"count": 128} (info-2) [engine.go:693]
      "starting notifier workers"         {"count": 128}  (info-2)  [engine.go:708]
  → "running source" {"with_units": true} (info-0)        [source_manager.go:402]
  → "enumerating source" (info-2)                          [source_manager.go:531]
  → "chunking unit" → "scanning file" (info-3)
  → "dataErrChan closed, all chunks processed" (info-5)    ← terminator / boundary state
  → 128× "finished scanning chunks" (info-4)               [engine.go:840]  ← one per scanner worker
  → single terminal "finished scanning" summary (info-0)
```

The four subsystems the question names map onto this spine as follows, and each has its own section below:

1. **Configuration handling** → the banner + flag parsing at the top (`main.go`). — *Section 2*
2. **Engine initialization** → `NewEngine → setDefaults → initialize` (`default engine options set`, `engine initialized`). — *Section 3*
3. **Detector preparation** → the Aho‑Corasick core setup (`setting up`/`set up aho-corasick core`). — *Section 4*
4. **Component communication** → the four worker pools + buffered channels + the source manager feeding them. — *Section 5*

Plus the cross‑cutting **logging subsystem** that makes all of the above observable (the `info-N` suffix). — *Section 6*

---

## Section 1 — Build & run methodology

### 1.1 The exact commands

**Toolchain.** The repository pins `toolchain go1.24.2` (`go.mod:5`). Go **1.24.2** was already present on this host and matches that pin, so it was used directly (verified, observed):

```console
$ go version
go version go1.24.2 linux/amd64
```

> *Reproducibility note (for a host where Go is absent):* install the pinned toolchain into an isolated prefix under `/tmp` so the repository stays byte‑for‑byte clean, e.g. `curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go1.24.2.linux-amd64.tar.gz && mkdir -p /tmp/goroot && tar -C /tmp/goroot --strip-components=1 -xzf /tmp/go.tgz && export GOROOT=/tmp/goroot PATH=/tmp/goroot/bin:$PATH`. On this host that step was unnecessary.

**Build (canonical — mirrors the `Dockerfile` recipe: `go build -o trufflehog .` at `Dockerfile:9`, with `CGO_ENABLED=0` set at `Dockerfile:5`).** The binary is written to `/tmp` so nothing lands inside the repository:

```console
$ cd <repo-root>
$ CGO_ENABLED=0 go build -o /tmp/trufflehog .
```

**Confirm the version — it is `dev` (this is the canonical default‑build value, not a placeholder I chose):**

```console
$ /tmp/trufflehog --version
trufflehog dev
```

The version is `dev` because `var BuildVersion = "dev"` (`pkg/version/version.go:3`) and a plain `go build` injects no `-ldflags "-X …BuildVersion=…"` stamp. The CLI surfaces this string via `cli.Version("trufflehog " + version.BuildVersion)` (`main.go:270`), and `main.go` even branches on it: `if version.BuildVersion == "dev" { … }` (`main.go:360`).

**Seed a minimal scan directory with FAKE, non‑live example credentials** (these are the canonical AWS documentation example keys — deliberately not real):

```console
$ mkdir -p /tmp/th_scan
$ printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /tmp/th_scan/creds.txt
$ wc -c /tmp/th_scan/creds.txt
106 /tmp/th_scan/creds.txt
```

**Run the safe dry‑run at two verbosity levels** (`--no-verification` guarantees no live‑API traffic):

```console
$ /tmp/trufflehog filesystem /tmp/th_scan --no-verification --log-level=2
$ /tmp/trufflehog filesystem /tmp/th_scan --no-verification --log-level=5
```

### 1.2 Why these are the canonical, documented choices

- **`filesystem`** is the documented source for scanning "local files/dirs" — `trufflehog filesystem path/to/file1.txt path/to/file2.txt path/to/dir` (`README.md:257`; also listed under supported sources at `README.md:406`, "filesystem (files and directories)").
- **`--log-level`** is documented as *"Logging verbosity on a scale of 0 (info) to 5 (trace). Can be disabled with \"-1\"."* (`README.md:425`), defined in code as `cli.Flag("log-level", …).Default("0").Int()` (`main.go:50`). The project's own convention marks **level 2** as *"logs that are useful for debugging"* (`CONTRIBUTING.md:33`) and **level 5** as *"ultimate verbosity"* (`CONTRIBUTING.md:36`). The `Makefile` `run-debug` and `dogfood` targets likewise pass `--log-level=2` (`Makefile:52`, `Makefile:15`).
- **`--no-verification`** is documented as *"Don't verify the results."* (`README.md:431`), defined as `cli.Flag("no-verification", "Don't verify the results.").Bool()` (`main.go:59`).

### 1.3 Scale used and run‑to‑run stability

Every magnitude in this document is driven by the host CPU count. **The authoritative CPU count on this host is `128`**, and that is the value TruffleHog actually reads, because concurrency defaults to `runtime.NumCPU()` (see `main.go:58` in Section 2). This was confirmed directly:

```console
$ # tiny probe compiled with the same Go toolchain
$ cat /tmp/numcpu.go
package main
import ("fmt"; "runtime")
func main() { fmt.Printf("runtime.NumCPU()=%d\n", runtime.NumCPU()); fmt.Printf("GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0)) }
$ go run /tmp/numcpu.go
runtime.NumCPU()=128
GOMAXPROCS=128
```

> **Reporting exactly what is observed (a deliberate nuance).** The `nproc` command on this host prints `4`, which is *misleading*: it is an artifact of the **uutils (Rust) coreutils 0.2.2** reimplementation shipped on Ubuntu 25.10, **not** the value Go uses. Every other authoritative source agrees the machine has **128** logical CPUs available to the process: `nproc --all` → `128`; `getconf _NPROCESSORS_ONLN` → `128`; `getconf _NPROCESSORS_CONF` → `128`; `grep -c ^processor /proc/cpuinfo` → `128`; `/sys/devices/system/cpu/online` → `0-127`; `python3 -c 'import os;print(len(os.sched_getaffinity(0)))'` → `128`; and the process CPU‑affinity mask is `0-127`. Since `runtime.NumCPU()` (which is what the code reads) returns **128**, that is the number reported throughout. I lead with the observed value and do not adjust it toward the `nproc` reading.

Across **four runs** (2× at `--log-level=2`, 2× at `--log-level=5`) the following were **identical every time**:

| Magnitude | Observed value | Stable across 4 runs? |
|-----------|----------------|-----------------------|
| scanner workers | 128 | ✅ |
| detector workers | 1024 | ✅ |
| verificationOverlap workers | 128 | ✅ |
| notifier workers | 128 | ✅ |
| `finished scanning chunks` lines (at `--log-level=5`) | 128 (128 distinct worker ids) | ✅ |
| `chunks` / `bytes` in the summary | `1` / `106` | ✅ |

Only the timestamps and the random 5‑character worker ids vary between runs — which is expected.

---

## Section 2 — Configuration handling

**Direct answer.** TruffleHog builds its configuration almost entirely from **CLI flags**, parsed by the **kingpin** library (`github.com/alecthomas/kingpin/v2 v2.4.0`). A YAML configuration file is read **only when `--config` is supplied**; in a basic dry‑run it is *not* supplied, so the tool runs on **built‑in defaults**. The resulting settings are packed into an `engine.Config` struct and handed to the engine.

### 2.1 Flag & command parsing (kingpin)

The single kingpin application is created at the top of `main.go`:

```go
// main.go:47
cli = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
```

The flags exercised by the dry‑run are declared as package‑level vars on that `cli`:

- `--log-level` — defined as `cli.Flag("log-level", …).Default("0").Int()` (`main.go:50`), whose help text is *"Logging verbosity on a scale of 0 (info) to 5 (trace). Can be disabled with \"-1\"."*; it has hidden companions `--debug` (`main.go:51`) and `--trace` (`main.go:52`).
- `--concurrency` — `cli.Flag("concurrency", "Number of concurrent workers.").Default(strconv.Itoa(runtime.NumCPU())).Int()` (`main.go:58`). **This is the origin of every worker magnitude in this document:** its default is `runtime.NumCPU()` → **128** on this host.
- `--no-verification` — `cli.Flag("no-verification", "Don't verify the results.").Bool()` (`main.go:59`).

Parsing itself happens once, near the end of the var/`init` block:

```go
// main.go:301
cmd = kingpin.MustParse(cli.Parse(os.Args[1:]))
```

**Observed signal (configuration is live).** The very first log line proves the parsed configuration and version are in hand — the version banner, emitted at verbosity 2 by `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` (`main.go:410`):

```text
2026-07-06T23:13:39Z	info-2	trufflehog	trufflehog dev
```

Immediately after, `main.go` writes the ASCII banner **to stderr** (not through the structured logger, so it appears even in non‑JSON mode) via `fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")` (`main.go:498`):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

The output printer for results is chosen in the same region; for a plain (non‑JSON) run it is `printer = new(output.PlainPrinter)` (`main.go:494`).

### 2.2 Optional YAML configuration (the road not taken in a dry‑run)

When `--config` *is* provided, `main.go` reads it:

```go
// main.go:463
conf, err = config.Read(*configFilename)
```

`config.Read` opens the file and delegates parsing to `NewYAML`:

```go
// pkg/config/config.go:18
func Read(filename string) (*Config, error) {
    // …reads the file…
    return NewYAML(input)   // pkg/config/config.go:23
}
// pkg/config/config.go:27
func NewYAML(input []byte) (*Config, error) {
    var messages custom_detectorspb.CustomDetectors
    if err := protoyaml.UnmarshalStrict(input, &messages); err != nil { // pkg/config/config.go:30
        return nil, err
    }
    var d []detectors.Detector
    for _, detectorConfig := range messages.Detectors {
        detector, err := custom_detectors.NewWebhookCustomRegex(detectorConfig) // pkg/config/config.go:36
        if err != nil {
            return nil, err
        }
        d = append(d, detector)
    }
    return &Config{Detectors: d}, nil // pkg/config/config.go:42
}
```

**In the basic dry‑run `--config` is absent**, so `conf` remains empty and only defaults apply. *(This is the observed default path: no `config.Read` work is reflected in the run output because the flag was never set.)*

### 2.3 Assembling `engine.Config`

`main.go` assembles the engine configuration, merging built‑in detectors with any from the (here empty) YAML, and — crucially for a safe dry‑run — deriving `Verify` from the negation of `--no-verification`:

```go
// main.go:519
Detectors:                append(defaults.DefaultDetectors(), conf.Detectors...),
// main.go:520
Verify:                   !*noVerification,
```

Because `--no-verification` was passed, `Verify` resolves to **`false`**. The authoritative built‑in detector set is `DefaultDetectors()` (`pkg/engine/defaults/defaults.go:1704`).

### 2.4 The fixed, ordered decoder chain

Decoding is not configurable in a basic run — it is a fixed, ordered chain returned by `DefaultDecoders()`:

```go
// pkg/decoders/decoders.go:8
func DefaultDecoders() []Decoder {
    return []Decoder{
        // UTF8 must be first for duplicate detection   // pkg/decoders/decoders.go:10
        &UTF8{},           // :11
        &Base64{},         // :12
        &UTF16{},          // :13
        &EscapedUnicode{}, // :14
    }
}
```

The ordering matters: the comment at `pkg/decoders/decoders.go:10` states **"UTF8 must be first for duplicate detection."**

**Causal reasoning.** Configuration in a basic run is essentially *"parse flags → apply defaults."* The dry‑run's safety is a direct, provable consequence of one configuration value: `Verify=false` (`main.go:520`) — corroborated at the end of the scan by the all‑zero `verification_caching` block and `verified_secrets: 0` in the observed summary (Section 5.4 and Section 7).

---

## Section 3 — Engine initialization

**Direct answer.** The engine is built by `engine.NewEngine(ctx, &cfg)` (`main.go:688`). During construction, `NewEngine` calls **`setDefaults`** (`engine.go:252`) and then **`initialize`** (`engine.go:323`) — so *both* run inside `NewEngine`, before the separate `eng.Start(ctx)` call (which only performs `sanityChecks` + `startWorkers`, `engine.go:621`). Two observed log lines bracket this init work: **`default engine options set`** (from `setDefaults`) and **`engine initialized`** (from `initialize`), both at verbosity 4.

### 3.1 Construction: `NewEngine` → `setDefaults`

```go
// main.go:688
eng, err := engine.NewEngine(ctx, &cfg)
```

```go
// pkg/engine/engine.go:226
func NewEngine(ctx context.Context, cfg *Config) (*Engine, error) {
    engine := &Engine{
        concurrency: cfg.Concurrency, // pkg/engine/engine.go:230
        decoders:    cfg.Decoders,
        detectors:   cfg.Detectors,
        verify:      cfg.Verify, // pkg/engine/engine.go:235
        // …the remaining cfg fields are copied here (pkg/engine/engine.go:229-247)…
    }
    if engine.sourceManager == nil {
        return nil, fmt.Errorf("source manager is required")
    }
    engine.setDefaults(ctx) // pkg/engine/engine.go:252
    // …build and apply the include/exclude detector filters (pkg/engine/engine.go:255-321)…
    if err := engine.initialize(ctx); err != nil { // pkg/engine/engine.go:323
        return nil, err
    }
    return engine, nil // pkg/engine/engine.go:327
}
```

`setDefaults` fills in the tuning knobs that later determine the worker‑pool sizes, then announces completion:

```go
// pkg/engine/engine.go:336
func (e *Engine) setDefaults(ctx context.Context) {
    // …
    e.detectorWorkerMultiplier = 8            // pkg/engine/engine.go:345
    e.notificationWorkerMultiplier = 1        // pkg/engine/engine.go:349
    e.verificationOverlapWorkerMultiplier = 1 // pkg/engine/engine.go:353
    // …defaults decoders/detectors if empty…
    ctx.Logger().V(4).Info("default engine options set") // pkg/engine/engine.go:373
}
```

**Observed signal** (only visible at `--log-level ≥ 4`, hence it appears in the `--log-level=5` capture, not the level‑2 one):

```text
2026-07-06T23:13:43Z	info-4	trufflehog	default engine options set
```

These three multipliers are the arithmetic behind Section 5's worker counts: `detectorWorkerMultiplier = 8` (→ 128 × 8 = 1024 detector workers), and the two `= 1` multipliers (→ 128 each for verificationOverlap and notifier).

### 3.2 Initialization: `initialize` (LRU cache + channels)

`initialize` is invoked from within `NewEngine` at `engine.go:323`; its body (defined at `engine.go:489`) builds the dedup cache and the channels:

```go
// pkg/engine/engine.go:489
func (e *Engine) initialize(ctx context.Context) error {
    const cacheSize = 512 // number of entries in the LRU cache          // pkg/engine/engine.go:491
    cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)   // pkg/engine/engine.go:493
    // …
    // Three buffered channels (capacities derived from defaultChannelBuffer × per-channel multipliers):
    e.detectableChunksChan = make(chan detectableChunk, defaultChannelBuffer*detectableChunksChanMultiplier)                 // :515
    e.verificationOverlapChunksChan = make(chan verificationOverlapChunk, defaultChannelBuffer*verificationOverlapChunksChanMultiplier) // :517
    e.results = make(chan detectors.ResultWithMetadata, defaultChannelBuffer*resultsChanMultiplier)                          // :519
    ctx.Logger().V(4).Info("engine initialized") // pkg/engine/engine.go:521
}
```

**Observed signal:**

```text
2026-07-06T23:13:43Z	info-4	trufflehog	engine initialized
```

The LRU is a **512‑entry** dedup cache — `const cacheSize = 512` (`pkg/engine/engine.go:491`) instantiated by `lru.New[string, detectorspb.DecoderType](cacheSize)` (`pkg/engine/engine.go:493`) and stored as `e.dedupeCache` (`pkg/engine/engine.go:520`), backed by `github.com/hashicorp/golang-lru/v2 v2.0.7`. It maps a `string` key to a `detectorspb.DecoderType` **value**, which shows its purpose: **deduplicate chunks by decoder type** so the same bytes are not re‑scanned under multiple decoders.

The **three buffered channels** created here (`pkg/engine/engine.go:515,517,519`) are the wiring that decouples the worker pools (see Section 5.3). Their capacities are computed from `defaultChannelBuffer` (`pkg/engine/engine.go:627`, `= runtime.NumCPU()`) times per‑channel multipliers.

**Causal reasoning.** The Aho‑Corasick setup of Section 4 is the *final step of `initialize` itself* (`engine.go:529–531`, immediately before its `return nil` at `engine.go:533`) — which is why the `engine initialized` and `setting up aho-corasick core` lines appear back‑to‑back in the capture. So by the time `NewEngine` returns, the engine is fully wired (cache + channels + prefilter); only later does `eng.Start(ctx)` spin up the worker pools.

---

## Section 4 — Detector preparation

**Direct answer.** "Preparing the detectors" means building **one shared Aho‑Corasick keyword prefilter** out of *every* detector's keywords. This is done by `NewAhoCorasickCore`, invoked from `initialize`, and it is bracketed by two observed log lines: **`setting up aho-corasick core`** and **`set up aho-corasick core`**.

### 4.1 The bracketing log lines and the call between them

```go
// pkg/engine/engine.go:529
ctx.Logger().V(4).Info("setting up aho-corasick core")
// pkg/engine/engine.go:530
e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)
// pkg/engine/engine.go:531
ctx.Logger().V(4).Info("set up aho-corasick core")
```

**Observed signals (both at verbosity 4):**

```text
2026-07-06T23:13:43Z	info-4	trufflehog	setting up aho-corasick core
2026-07-06T23:13:43Z	info-4	trufflehog	set up aho-corasick core
```

### 4.2 What `NewAhoCorasickCore` actually does

```go
// pkg/engine/ahocorasick/ahocorasickcore.go:141
func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core {
    // …
    for _, kw := range d.Keywords() {         // pkg/engine/ahocorasick/ahocorasickcore.go:148
        kwLower := strings.ToLower(kw)         // pkg/engine/ahocorasick/ahocorasickcore.go:149
        // …populate keywordsToDetectors…
    }
    return &Core{
        // …
        prefilter: *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(), // pkg/engine/ahocorasick/ahocorasickcore.go:159
    }
}
```

It iterates **all** detectors, calls each detector's `d.Keywords()` (`ahocorasickcore.go:148`), lowercases each keyword via `strings.ToLower(kw)` (`ahocorasickcore.go:149`), records the keyword→detector mapping, and finally builds **one** trie: `*ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()` (`ahocorasickcore.go:159`), backed by `github.com/BobuSumisu/aho-corasick v1.0.3`.

The result is stored on the `Core` struct (`ahocorasickcore.go:124`):

```go
// pkg/engine/ahocorasick/ahocorasickcore.go:127
prefilter ahocorasick.Trie
// pkg/engine/ahocorasick/ahocorasickcore.go:133
keywordsToDetectors map[string][]DetectorKey
```

### 4.3 How the prefilter is used per chunk (*inferred from source*)

The prefilter is consulted for each scanned chunk inside `FindDetectorMatches`:

```go
// pkg/engine/ahocorasick/ahocorasickcore.go:241
func (ac *Core) FindDetectorMatches(chunkData []byte) []*DetectorMatch {
    matches := ac.prefilter.Match(bytes.ToLower(chunkData)) // pkg/engine/ahocorasick/ahocorasickcore.go:242
    // …
}
```

> *Labeled inference.* I did not directly observe a per‑chunk log line for `FindDetectorMatches` in this run; the `Match` path (`ahocorasickcore.go:242`) is **inferred from reading the source**. What *is* observed is that a matching detector actually ran on the chunk — the AWS detector's `trufflehog.aws` log lines appear (Section 5.4), which is only possible if the prefilter matched the chunk to the AWS detector.

### 4.4 The detector set (no exact count asserted)

The detectors fed into the core are the built‑ins from `DefaultDetectors()` (`pkg/engine/defaults/defaults.go:1704`). **This document deliberately does not assert an exact detector count** — `DefaultDetectors()` is the authoritative source of truth, and any number derived by counting subdirectories would be a proxy, not a runtime‑verified figure.

**Causal reasoning.** Building a single shared trie from all detector keywords lets each chunk be matched against every detector's keywords in one cheap pass; only detectors whose keywords are present proceed to run their (expensive) regexes. That is why detector preparation is a one‑time startup cost paid before the worker pools spin up.

---

## Section 5 — Component communication (worker pools + channels)

**Direct answer.** `eng.Start(ctx)` (`main.go:692`) calls `Start` → `startWorkers`, which spawns **four goroutine pools** — *scanner*, *detector*, *verificationOverlap*, and *notifier* — that communicate through **buffered channels**. A separate **source manager** feeds them by enumerating and chunking the source. On this host (`runtime.NumCPU()=128`) the observed pool sizes are **128 / 1024 / 128 / 128**.

### 5.1 `Start` → `startWorkers`

```go
// main.go:692
eng.Start(ctx)
```

```go
// pkg/engine/engine.go:621
func (e *Engine) Start(ctx context.Context) {
    e.metrics = runtimeMetrics{Metrics: Metrics{scanStartTime: time.Now()}}
    e.sanityChecks(ctx) // pkg/engine/engine.go:623
    e.startWorkers(ctx) // pkg/engine/engine.go:624
}
// pkg/engine/engine.go:646
func (e *Engine) startWorkers(ctx context.Context) {
    e.startScannerWorkers(ctx)             // pkg/engine/engine.go:648
    e.startDetectorWorkers(ctx)            // pkg/engine/engine.go:651
    e.startVerificationOverlapWorkers(ctx) // pkg/engine/engine.go:655
    e.startNotifierWorkers(ctx)            // pkg/engine/engine.go:659
}
```

### 5.2 The four pools and their observed counts

Each pool logs its size at verbosity 2 as it starts. **These are my captured `--log-level=2` lines, placed next to the code that emits each:**

**Scanner pool** — size = `e.concurrency` (= 128):

```go
// pkg/engine/engine.go:663
ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)
```
```text
2026-07-06T23:13:39Z	info-2	trufflehog	starting scanner workers	{"count": 128}
```

**Detector pool** — size = `e.concurrency * e.detectorWorkerMultiplier` = 128 × 8 = 1024:

```go
// pkg/engine/engine.go:676
numWorkers := e.concurrency * e.detectorWorkerMultiplier
// pkg/engine/engine.go:678
ctx.Logger().V(2).Info("starting detector workers", "count", numWorkers)
```
```text
2026-07-06T23:13:39Z	info-2	trufflehog	starting detector workers	{"count": 1024}
```

**VerificationOverlap pool** — size = `e.concurrency * e.verificationOverlapWorkerMultiplier` = 128 × 1 = 128:

```go
// pkg/engine/engine.go:691
numWorkers := e.concurrency * e.verificationOverlapWorkerMultiplier
// pkg/engine/engine.go:693
ctx.Logger().V(2).Info("starting verificationOverlap workers", "count", numWorkers)
```
```text
2026-07-06T23:13:39Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
```

**Notifier pool** — size = `e.notificationWorkerMultiplier * e.concurrency` = 1 × 128 = 128:

```go
// pkg/engine/engine.go:706
numWorkers := e.notificationWorkerMultiplier * e.concurrency
// pkg/engine/engine.go:708
ctx.Logger().V(2).Info("starting notifier workers", "count", numWorkers)
```
```text
2026-07-06T23:13:39Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

Every worker goroutine is tagged with a random 5‑character id (via `common.RandomID(5)`); those ids are visible as `scanner_worker_id`, `detector_worker_id`, and `source_manager_worker_id` in the logs.

### 5.3 The channels that connect the pools

The channels are fields on the `Engine` struct:

```go
// pkg/engine/engine.go:191
results                       chan detectors.ResultWithMetadata
// pkg/engine/engine.go:192
detectableChunksChan          chan detectableChunk
// pkg/engine/engine.go:193
verificationOverlapChunksChan chan verificationOverlapChunk
```

Their buffer capacities are `defaultChannelBuffer` (`= runtime.NumCPU()`, `pkg/engine/engine.go:627`) multiplied by per‑channel constants: `detectableChunksChanMultiplier = 50` (`:503`), `verificationOverlapChunksChanMultiplier = 25` (`:507`), and `resultsChanMultiplier = detectableChunksChanMultiplier` (i.e. 50, `:508`).

> *Labeled inference.* Combining these constants with `defaultChannelBuffer = 128` yields buffered capacities of **6400 / 3200 / 6400** for `detectableChunksChan` / `verificationOverlapChunksChan` / `results` respectively. These capacities are **inferred from the constants** (`engine.go:503,507,508,515–519,627`); the run does not print channel capacities, so I label the arithmetic as inferred while the multipliers and `defaultChannelBuffer` are read directly from source.

**Corroborating in‑repo diagrams (references, not runtime).** The repo's own `docs/concurrency.md` sequence diagram shows exactly this topology: `e.startWorkers()` creating `ScannerWorkers`, `VerificationOverlapWorkers`, `DetectorWorkers`, and `NotifierWorkers`, wired by `e.detectableChunksChan`, `e.verificationOverlapChunksChan`, and `e.ResultsChan()`/`e.results`. `docs/process_flow.md` shows the higher‑level data flow: **Source Decomposition → Chunk‑to‑Detector Matching → Secret Detection → Result Notification.** These are in‑repo documentation and are cited as corroboration of the observed behavior, not as runtime evidence.

### 5.4 The source manager feeds the pipeline

The `filesystem` source is driven by the source manager, which emits the enumeration signals I observed:

```go
// pkg/sources/source_manager.go:402
ctx.Logger().Info("running source", "with_units", true)
// pkg/sources/source_manager.go:531
ctx.Logger().V(2).Info("enumerating source")
```

**Observed signals** (`running source` at info‑0, so it appears even at `--log-level=2`; `enumerating source` at info‑2):

```text
2026-07-06T23:13:39Z	info-0	trufflehog	running source	{"source_manager_worker_id": "E2BDe", "with_units": true}
2026-07-06T23:13:39Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "E2BDe"}
```

At `--log-level=5` the finer‑grained feeding steps become visible — the unit is chunked, the file is scanned, and then the **terminator / boundary state** fires when the data channel closes:

```text
2026-07-06T23:13:43Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt"}
2026-07-06T23:13:43Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt", "path": "/tmp/th_scan/creds.txt"}
2026-07-06T23:13:43Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt", "path": "/tmp/th_scan/creds.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

### 5.5 Before/after boundary: per‑worker completion vs. the single terminal summary

This before/after distinction is important and was explicitly exercised:

- **Per‑scanner‑worker completion** — each scanner worker logs `finished scanning chunks` at verbosity 4 as it drains, from `ctx.Logger().V(4).Info("finished scanning chunks")` (`pkg/engine/engine.go:840`). In my `--log-level=5` capture this line appeared **exactly 128 times — one per scanner worker — each with a distinct 5‑character `scanner_worker_id`** (verified: 128 unique ids). At `--log-level=2` this line does **not** appear at all (it is a `V(4)` message, below the level‑2 threshold — an observed boundary of the logging level itself).

```text
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "r8im0"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "MRb4R"}
   ... (repeats 128× total, each a distinct 5-char id from common.RandomID(5)) ...
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AuKp3"}
```

- **Single terminal summary** — after all pools finish, exactly **one** `finished scanning` summary is printed at info‑0:

```text
2026-07-06T23:13:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.362495ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed concurrency evidence (interleaving).** In the `--log-level=5` capture the 128 `finished scanning chunks` lines actually span 130 output lines, because the two `trufflehog.aws` detector lines (below) interleave *between* chunk‑completion lines. That interleaving is direct, observed proof that the scanner and detector pools run concurrently; their relative ordering varies run‑to‑run while the counts stay fixed.

**Causal reasoning.** The buffered channels implement a classic **fan‑out / fan‑in**: the source manager enumerates and chunks a source, scanner workers decode chunks and match detectors (pushing onto `detectableChunksChan`/`verificationOverlapChunksChan`), detector workers run detection and push results onto `results`, and notifier workers write output. The buffers let each stage proceed without lock‑stepping the others.

---

## Section 6 — Cross‑cutting logging / observability (why every line ends in `info-N`)

**Direct answer.** Everything above is externally observable because TruffleHog logs through a **`logr` facade over a Zap backend** whose console sink writes to **stderr** with **RFC3339 timestamps**. The `info-N` suffix on every line is the leveled‑verbosity indicator: `N` equals the `V(n)` level of the call site, implemented by mapping verbosity onto a **negative** Zap level.

### 6.1 Logger construction

The logger is built in `main()` and installed as the default:

```go
// main.go:336
logger, sync := log.New("trufflehog", logFormat(os.Stderr, log.WithGlobalRedaction()))
// main.go:338
context.SetDefaultLogger(logger)
```

`log.New` constructs the Zap logger:

```go
// pkg/log/log.go:28
func New(service string, configs ...logConfig) (logr.Logger, func() error) { … }
```

Its encoder is a **console encoder by default** (`zapcore.NewConsoleEncoder(defaultEncoderConfig())`, `pkg/log/log.go:107`) or a **JSON encoder** when `--json` is set (`zapcore.NewJSONEncoder(defaultEncoderConfig())`, `pkg/log/log.go:97`); timestamps are RFC3339 via `conf.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)` (`pkg/log/log.go:117`). This is exactly the shape observed: tab‑separated columns `TIMESTAMP  info-N  service  message  {json fields}`, with an RFC3339 timestamp such as `2026-07-06T23:13:39Z`.

The `service` name passed here is `"trufflehog"`, which is why every line's third column reads `trufflehog`; child loggers append a suffix, e.g. the AWS detector logs under `trufflehog.aws` (observed in Section 6.3).

### 6.2 The `info-N` render — verbosity as a negative Zap level

```go
// pkg/log/level.go:30
control.SetLevel(zapcore.Level(-level))
```

`logr`'s `V(n)` verbosity is translated to a **negative** Zap level (`pkg/log/level.go:30`, inside `SetLevelForControl`; the public entry point is `SetLevel`, `pkg/log/level.go:21`). Zap renders that as `info` plus the magnitude — so `V(2)` prints `info-2`, `V(4)` prints `info-4`, and `V(5)` prints `info-5`. **This is precisely why raising `--log-level` surfaces more lines:** a higher `--log-level` admits higher‑`N` (more negative Zap‑level) messages. It is the observable mechanism the rest of this document relies on:

| `V(n)` level | Rendered as | Example message | Visible at `--log-level=2`? | Visible at `--log-level=5`? |
|---|---|---|---|---|
| 0 | `info-0` | `running source`, `finished scanning` | ✅ | ✅ |
| 2 | `info-2` | version banner, `starting … workers`, `enumerating source` | ✅ | ✅ |
| 3 | `info-3` | `chunking unit`, `scanning file` | ❌ | ✅ |
| 4 | `info-4` | `default engine options set`, `engine initialized`, `set up aho-corasick core`, `finished scanning chunks` | ❌ | ✅ |
| 5 | `info-5` | `dataErrChan closed, all chunks processed` | ❌ | ✅ |

This table is itself an observed result: at `--log-level=2` the engine‑init and per‑worker lines are absent, and they appear only when I raised the level to 5 — which is exactly the "before/after" difference between my two captures.

### 6.3 The run executes under the overseer supervisor

The `filesystem` command path executes inside `run(state overseer.State)` (`main.go:381`), which runs under the overseer process supervisor (`github.com/jpillora/overseer`, replaced by `github.com/trufflesecurity/overseer v1.2.8` per `go.mod`) that also powers self‑update/restart. The child‑logger behavior is observable in the AWS detector lines captured at `--log-level=5`:

```text
2026-07-06T23:13:43Z	info-3	trufflehog.aws	Failed to decode account number	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"}
2026-07-06T23:13:43Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

**Causal reasoning.** Leveled logging *is* the observability surface for startup. Because each subsystem announces itself at a specific `V(n)`, choosing `--log-level=5` turns the internal `main → engine → aho‑corasick → workers → source` sequence into an externally visible, timestamped trace — which is exactly what this investigation depends on.

---

## Section 7 — Complete unedited output appendix

### 7.1 `--log-level=2` — complete, unedited

**Command:**

```console
$ /tmp/trufflehog filesystem /tmp/th_scan --no-verification --log-level=2
```

**Output (captured 2026-07-06T23:13:39Z; the columns are literal tab‑separated: `TIMESTAMP<TAB>info-N<TAB>service<TAB>message<TAB>{fields}`):**

```text
2026-07-06T23:13:39Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:13:39Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-06T23:13:39Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-06T23:13:39Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-06T23:13:39Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-06T23:13:39Z	info-0	trufflehog	running source	{"source_manager_worker_id": "E2BDe", "with_units": true}
2026-07-06T23:13:39Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "E2BDe"}
2026-07-06T23:13:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.362495ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

At this level the engine‑initialization (`info-4`), chunking (`info-3`), and per‑worker (`info-4`) lines are intentionally suppressed — they are above the level‑2 threshold (Section 6.2).

### 7.2 `--log-level=5` — complete, unedited output

**Command:**

```console
$ /tmp/trufflehog filesystem /tmp/th_scan --no-verification --log-level=5
```

**Output (captured 2026-07-06T23:13:43Z).** This is the **complete, unedited** output — **all 147 lines in their observed order, nothing collapsed or elided**. It includes every one of the **128** `finished scanning chunks` lines (each carrying a distinct 5-character `scanner_worker_id` from `common.RandomID(5)`), plus the two `trufflehog.aws` detector lines that **interleave** among the chunk-completion lines:

```text
2026-07-06T23:13:43Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-06T23:13:43Z	info-4	trufflehog	default engine options set
2026-07-06T23:13:43Z	info-4	trufflehog	engine initialized
2026-07-06T23:13:43Z	info-4	trufflehog	setting up aho-corasick core
2026-07-06T23:13:43Z	info-4	trufflehog	set up aho-corasick core
2026-07-06T23:13:43Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-06T23:13:43Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-06T23:13:43Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-06T23:13:43Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-06T23:13:43Z	info-0	trufflehog	running source	{"source_manager_worker_id": "69lqK", "with_units": true}
2026-07-06T23:13:43Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "69lqK"}
2026-07-06T23:13:43Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt"}
2026-07-06T23:13:43Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt", "path": "/tmp/th_scan/creds.txt"}
2026-07-06T23:13:43Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "69lqK", "unit_kind": "unit", "unit": "/tmp/th_scan/creds.txt", "path": "/tmp/th_scan/creds.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "r8im0"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "MRb4R"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "fadMX"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XyzW7"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "PGF71"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "6KuFv"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CVVrL"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "9M6oy"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "7ywnb"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "woPyy"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "YWlKw"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "SqLpQ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "VQ9Tx"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "iV3H0"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xaGB4"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "1FmCV"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pc3xK"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5LQBk"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xJ8US"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZsGHX"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "J8W2V"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0m8Kg"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HaQ5e"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "SQI5E"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "8wFZD"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "MsFWv"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CagJ6"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tghbJ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZEYkw"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "3P2nl"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "LLgy0"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "8GIcM"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "wKQzy"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xRGaA"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tvSXS"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QM5sF"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "gqsHu"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "f5lEh"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QCpVF"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "NpDJg"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "82WQB"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "b0bIm"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Pdd3m"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "WUAAX"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "I71Sp"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZQPy8"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Ijwvz"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "73udn"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "mcqca"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "SbrA1"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Mjk1U"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vpwn5"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eOVYg"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tNt3Z"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "056x3"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "aXDnh"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Yyy8U"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "4yDo3"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EiAXW"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AgxUG"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zPrSl"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CYUAA"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "FEbAR"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XWbs6"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "e50rL"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HYhwO"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "JXoL3"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "e18NH"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dHBNf"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pTQQN"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "JCM2S"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "MBrwR"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Zs68X"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "yvGpB"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IFKq4"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Hv6qC"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "4VDFX"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "BTAU0"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IvWEA"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zWpsi"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EvADB"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "GcUnp"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "fwLw5"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "intL4"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZCgP9"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "NTKYS"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EBsmt"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "uQ3Iv"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "cZ2hJ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "RRlW4"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "kak68"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EPSJ4"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zrEUJ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HCoQf"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "B2kHz"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "cMsV3"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pDAwU"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "x8BLF"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZoTHT"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OpKwj"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vBqoi"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CAPO5"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eJO6v"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "thmYg"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "wTUJK"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "oYkHK"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tMDJq"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bRsP7"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Ts3Ra"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QkXxc"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "n9hNG"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CvI9A"}
2026-07-06T23:13:43Z	info-3	trufflehog.aws	Failed to decode account number	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eRDxH"}
2026-07-06T23:13:43Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "w4ua5"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eXewB"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "S2OoQ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0xX2f"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XqqNf"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "2p45I"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ULPFP"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "x0hFY"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eT7s8"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Z4w5L"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "H3o1P"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bAXqJ"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "gmlE9"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "9NKki"}
2026-07-06T23:13:43Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AuKp3"}
2026-07-06T23:13:43Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "6.06214ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

---

## Appendix A — Key insights & edge findings

### A.1 Dry‑run safety proof (a boundary case)

The seeded AWS key produces **both** `verified_secrets: 0` **and** `unverified_secrets: 0`. That is not merely because verification was disabled — it is because the AWS detector **filters the fake key out as a false positive before it ever becomes a result**. Observed at `--log-level=5`, from the `trufflehog.aws` child logger:

```text
2026-07-06T23:13:43Z	info-3	trufflehog.aws	Failed to decode account number	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"}
2026-07-06T23:13:43Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "mDQPq", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

Combined with `Verify: !*noVerification` → **false** (`main.go:520`) and the all‑zero `verification_caching` block in the summary (`{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}`), this proves the dry‑run emitted **no** live‑API verification traffic.

### A.2 Transitional / terminator states

- `dataErrChan closed, all chunks processed` (info‑5, carrying `"mime": "text/plain; charset=utf-8", "timeout": 60`) marks the **end of chunk feeding** for the unit.
- The **128 per‑worker** `finished scanning chunks` lines (info‑4) precede the **single terminal** `finished scanning` summary (info‑0). Reporting this before/after distinction — many per‑worker completions vs. one aggregate summary — was an explicit goal of the investigation.

### A.3 The version is `dev`

The canonical default build reports `trufflehog dev`. This is *not* a release number and was deliberately **not** stamped to look like one — it is the honest default‑build value (`pkg/version/version.go:3`).

### A.4 What I inferred vs. observed

For transparency, the only claims **inferred from reading source** (rather than observed at runtime) are: (a) the per‑chunk `prefilter.Match` path in `FindDetectorMatches` (`ahocorasickcore.go:242`, Section 4.3), and (b) the numeric channel buffer capacities 6400 / 3200 / 6400 (derived from the constants at `engine.go:503,507,508,627`, Section 5.3). Everything else in Sections 2–6 sits next to a log line I captured.

---

## Appendix B — Coverage matrix (every named item, answered)

| Question item | Section | Exact function/struct | `file:line` | Adjacent observed evidence |
|---------------|---------|-----------------------|-------------|----------------------------|
| **Configuration** | §2 | `kingpin.New`; flag vars; `config.Read`→`NewYAML`; `engine.Config` assembly; `DefaultDecoders` | `main.go:47,50,58,59,301,463,494,498,519,520`; `config.go:18,23,27`; `decoders.go:8-14` | `trufflehog dev` banner (info‑2); ASCII banner |
| **Engine initialization** | §3 | `NewEngine`→`setDefaults`→`initialize`; 512‑LRU; 3 channels | `engine.go:226,336,345,349,353,373,489,491,493,515-519,521` | `default engine options set`; `engine initialized` (info‑4) |
| **Detector preparation** | §4 | `NewAhoCorasickCore`; `Core.prefilter`; `keywordsToDetectors`; `DefaultDetectors` | `ahocorasickcore.go:124,127,133,141,148,149,159,241,242`; `defaults.go:1704`; `engine.go:529-531` | `setting up aho-corasick core`; `set up aho-corasick core` (info‑4) |
| **Component communication** | §5 | `Start`→`startWorkers`; 4 pools; 3 channels; source manager | `engine.go:191-193,621,646,663,676,678,691,693,706,708,840,627,503,507,508`; `source_manager.go:402,531` | `starting {scanner=128, detector=1024, verificationOverlap=128, notifier=128} workers`; `running source`/`enumerating source`; 128× `finished scanning chunks` |
| **Logging (cross‑cutting)** | §6 | `log.New` (Zap); `SetLevelForControl` | `log.go:28,97,107,117`; `level.go:21,30`; `main.go:336,338,381` | every line's `info-N` suffix; `trufflehog.aws` child logger |

**Stability restated:** host CPU count = **128** (`runtime.NumCPU()`); worker counts **128 / 1024 / 128 / 128**; **128** `finished scanning chunks` lines; `chunks=1`, `bytes=106` — all identical across **4 runs** (2× level 2, 2× level 5). Version = `dev`.






