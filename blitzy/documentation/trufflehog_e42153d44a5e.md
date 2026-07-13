# TruffleHog Secret-Detection Architecture — Runtime-Grounded Onboarding Answers

This document answers five onboarding questions about TruffleHog's secret-detection
architecture. Per the governing `SWE-AtlasQnA-Repo` methodology, **every behavioral claim
was produced by building the binary from source and running it**, and each claim is paired
with the exact command that produced it and the complete, unedited output. Statements
derived from reading source (rather than from a run) are explicitly labelled **INFERRED**;
everything else is **OBSERVED**. Each observed behavior is additionally correlated to the
specific function/struct and `file:line` in the source that implements it.

- **Subject:** TruffleHog, Go module `github.com/trufflesecurity/trufflehog/v3`.
- **Commit under investigation (verified):** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`

```text
$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760
```

---

## Environment & Methodology

### Build (canonical, default configuration)

The binary was built with the project's canonical build recipe. The project's own build
entry points all use `CGO_ENABLED=0` and a plain `go build`/`go install` of the module root:
`Makefile:L18` (`CGO_ENABLED=0 go install .`), `Dockerfile:L5` (`ENV CGO_ENABLED=0`) +
`Dockerfile:L9` (`go build -o trufflehog .`), and `README.md:L119-L123` ("Compile from
source" → `git clone … ; cd trufflehog; go install`). All artifacts were placed **outside**
the source checkout (under `/tmp/thog_investigation/`) so the tracked tree stays byte-for-byte
unchanged.

```text
$ go version
go version go1.24.2 linux/amd64

$ CGO_ENABLED=0 go build -o /tmp/thog_investigation/trufflehog_bin .
$ echo "build exit=$?"
build exit=0

$ /tmp/thog_investigation/trufflehog_bin --version
trufflehog dev

$ ldd /tmp/thog_investigation/trufflehog_bin
	not a dynamic executable

$ ls -l /tmp/thog_investigation/trufflehog_bin
-rwxr-xr-x 1 root root 194311322 Jul 13 17:14 /tmp/thog_investigation/trufflehog_bin
```

- The default build reports the version string **`trufflehog dev`**. This is the literal
  default: `var BuildVersion = "dev"` (`pkg/version/version.go:L3`), assembled into the CLI
  version by `cli.Version("trufflehog " + version.BuildVersion)` (`main.go:L270`). A default
  build performs no VCS/ldflags stamping, so the version is literally `dev`. This is
  corroborated below by `go version -m`, which reports the main module as `(devel)`.
- Go toolchain **1.24.2** is the highest explicitly documented version (`go.mod:L3` `go 1.23.1`,
  `go.mod:L5` `toolchain go1.24.2`; CI pins `1.24`).
- `ldd` reports **`not a dynamic executable`** — a single static binary (core Q5 evidence).
- Binary size on this host: **194311322 bytes** (~194 MB). Host/toolchain-dependent.

### Host CPU count — and why it matters for every worker/finding count

TruffleHog's `--concurrency` flag **defaults to `runtime.NumCPU()`**
(`main.go:L58` — `cli.Flag("concurrency", …).Default(strconv.Itoa(runtime.NumCPU()))`), and all
worker-pool sizes are derived from it. **Absolute worker counts are therefore host-specific.**

There is a subtlety on this host worth stating explicitly, because it changes every count in
this document: the shell's `nproc` reports `4`, but that is **not** the value Go uses. Go's
`runtime.NumCPU()` uses the process CPU-affinity mask, which here spans all 128 logical CPUs
(no cgroup CPU cap is set), so the TruffleHog process sees **128** CPUs:

```text
$ nproc
4
$ nproc --all
128
$ getconf _NPROCESSORS_ONLN
128
$ grep -c ^processor /proc/cpuinfo
128
$ taskset -cp $$
pid 152456's current affinity list: 0-127
$ cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo "no cpu.max"
no cpu.max
```

A throwaway program built with the same toolchain confirms the value the runtime actually uses:

```text
$ cat > /tmp/thog_investigation/numcpu.go <<'EOF'
package main
import ("fmt"; "runtime")
func main(){ fmt.Println("runtime.NumCPU()=", runtime.NumCPU(), " GOMAXPROCS=", runtime.GOMAXPROCS(0)) }
EOF
$ go run /tmp/thog_investigation/numcpu.go
runtime.NumCPU()= 128  GOMAXPROCS= 128
```

**This host: `runtime.NumCPU()` = 128.** Consequently `--concurrency` defaults to 128 (also
visible as `--concurrency=128` in the `--help` output in Q5), scanner/verificationOverlap/notifier
worker pools are 128 each, and the detector pool is `128 × 8 = 1024`. On a machine where
`runtime.NumCPU()` differs, all of these numbers scale proportionally.

### The fixture (created outside the checkout)

A throwaway git repository was created at `/tmp/thog_investigation/thog_testrepo` (single
commit `71d455a32d1587c20e35f6484230b8ab6112d0da`, committed with a local identity
`t <t@t.com>` via `git -c` flags so global config is untouched). It deliberately mixes
file types:

| File | Bytes / kind (`file`) | Purpose |
|------|-----------------------|---------|
| `aws_creds.ini` | ASCII text | A **detectable AWS credential** (forces an AWS finding for Q3). |
| `config.env` | ASCII text | Plain `KEY=VALUE` env lines, no secret. |
| `testkey.pem` | PEM RSA private key | A synthetic (non-functional) PEM block — a text file for diversity. |
| `notes.txt` | ASCII text | Plain prose, no secret. |
| `logo.png` | PNG image data, 1×1 | A **real PNG** — content sniffs `image/png` → expected **skip** (Q4). |
| `data.mp4` | ASCII text | Plain-text bytes with a `.mp4` name → content sniffs `text/plain` → expected **scan** (Q4 crux). |
| `archive.tar.gz` | gzip compressed data | Small tarball (contains `inside.txt`) → exercises the archive handler (Q4). |

> **Note on the AWS credential used in the fixture (secret hygiene).** The Access Key ID
> `AKIAYVP4CIPPERUVIFXG` is a **public canarytokens.org detection identifier** — a tripwire
> value that is published for detection testing and grants no real access (TruffleHog itself
> labels it `"This is an AWS canary token generated at canarytokens.org."`). It is paired with
> a **fabricated, random 40-character secret** (`qUGtRtqlJNUCoY5SBly3QymVf33zOXxHcEuS7VxA`)
> that is likewise non-functional. All Q3 scans were run with `--no-verification` so **no live
> network request is sent**. These exact values are reproduced verbatim only because the
> methodology requires unedited output; they are **not real, working credentials** and unlock
> nothing. If a secret scanner flags the `AKIA…` string in this document, that is a
> true-positive *pattern* match on an intentionally-included, published canary token — not a
> disclosure of any real AWS credential.

### stdout / stderr separation convention

TruffleHog writes **findings to stdout** and **logs plus the startup banner to stderr**. Every
capture below redirects them separately (`… >stdout 2>stderr`) so the evidence stays clean.

---

## Q1 — Startup & Detector Loading

**Question items covered by name:** what happens during startup; whether detector
configurations are loaded **from files** or are **compiled in**; what **initialization
messages** appear about which detectors get **registered**.

### 1. Direct answer

Detectors are **compiled into the binary — they are NOT loaded from any external configuration
file at runtime.** They come from a hard-coded Go slice returned by `DefaultDetectors()`, which
is wired into the engine configuration at `main.go:L519`
(`Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)`). For a basic scan the
observable startup signals are (a) the version line `trufflehog dev`, (b) four **worker-pool
"starting … workers" count** log lines, and (c) the **ASCII banner** (plain-text mode only).
**There is no per-detector "registered" log line at any log level** — registration happens at
compile time, so there is nothing to announce per detector. This is stated as an *observed
absence*, not as an omission.

### 2. Exact commands executed

```text
# worker-pool startup logs on stderr (JSON mode)
/tmp/thog_investigation/trufflehog_bin git file:///tmp/thog_investigation/thog_testrepo --json --log-level=2 --no-verification

# the banner + human-readable startup on stderr (plain mode)
/tmp/thog_investigation/trufflehog_bin git file:///tmp/thog_investigation/thog_testrepo --log-level=2 --no-verification
```

### 3. Complete, unedited captured output

**Run 1 — startup stderr (JSON, `--log-level=2 --no-verification`):**

```text
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
{"level":"info-1","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"cloned repo","path":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-0","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"odVPH","with_units":true}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"enumerating source","source_manager_worker_id":"odVPH"}
{"level":"info-0","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"scanning repo","source_manager_worker_id":"odVPH","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"odVPH","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"/tmp/thog_investigation/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"scanning staged changes","source_manager_worker_id":"odVPH","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","path":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"odVPH","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"scanning git repo complete","source_manager_worker_id":"odVPH","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"Could not get remote for repo","path":"/tmp/thog_investigation/thog_testrepo","time_seconds":0,"commits_scanned":1}
{"level":"info-0","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"finished scanning","chunks":7,"bytes":859,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"13.410752ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Run 2 — startup stderr (JSON, `--log-level=2 --no-verification`) — for run-to-run stability:**

```text
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
{"level":"info-1","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"cloned repo","path":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-0","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"RZFIg","with_units":true}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"enumerating source","source_manager_worker_id":"RZFIg"}
{"level":"info-0","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"scanning repo","source_manager_worker_id":"RZFIg","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"RZFIg","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"/tmp/thog_investigation/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"scanning staged changes","source_manager_worker_id":"RZFIg","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","path":"/tmp/thog_investigation/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"RZFIg","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"scanning git repo complete","source_manager_worker_id":"RZFIg","unit_kind":"dir","unit":"/tmp/thog_investigation/thog_testrepo","repo":"Could not get remote for repo","path":"/tmp/thog_investigation/thog_testrepo","time_seconds":0,"commits_scanned":1}
{"level":"info-0","ts":"2026-07-13T17:25:11Z","logger":"trufflehog","msg":"finished scanning","chunks":7,"bytes":859,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"15.139814ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The four worker-pool counts are **identical across both runs** — `scanner=128`,
`detector=1024`, `verificationOverlap=128`, `notifier=128` — i.e. stable (they depend only on
`runtime.NumCPU()`, not on run-to-run randomness).

**Banner (plain-text mode only) — full stderr of `--log-level=2 --no-verification` without `--json`:**

```text
2026-07-13T17:25:13Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T17:25:13Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T17:25:13Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T17:25:13Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T17:25:13Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T17:25:13Z	info-1	trufflehog	cloned repo	{"path": "/tmp/thog_investigation/thog_testrepo"}
2026-07-13T17:25:13Z	info-0	trufflehog	running source	{"source_manager_worker_id": "B5usf", "with_units": true}
2026-07-13T17:25:13Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "B5usf"}
2026-07-13T17:25:13Z	info-0	trufflehog	scanning repo	{"source_manager_worker_id": "B5usf", "unit_kind": "dir", "unit": "/tmp/thog_investigation/thog_testrepo", "repo": "/tmp/thog_investigation/thog_testrepo"}
2026-07-13T17:25:13Z	info-2	trufflehog	finished parsing git log.	{"source_manager_worker_id": "B5usf", "unit_kind": "dir", "unit": "/tmp/thog_investigation/thog_testrepo", "repo": "/tmp/thog_investigation/thog_testrepo", "total_log_size": 0}
2026-07-13T17:25:13Z	info-1	trufflehog	scanning staged changes	{"source_manager_worker_id": "B5usf", "unit_kind": "dir", "unit": "/tmp/thog_investigation/thog_testrepo", "path": "/tmp/thog_investigation/thog_testrepo"}
2026-07-13T17:25:13Z	info-2	trufflehog	finished parsing git log.	{"source_manager_worker_id": "B5usf", "unit_kind": "dir", "unit": "/tmp/thog_investigation/thog_testrepo", "total_log_size": 0}
2026-07-13T17:25:13Z	info-1	trufflehog	scanning git repo complete	{"source_manager_worker_id": "B5usf", "unit_kind": "dir", "unit": "/tmp/thog_investigation/thog_testrepo", "repo": "Could not get remote for repo", "path": "/tmp/thog_investigation/thog_testrepo", "time_seconds": 0, "commits_scanned": 1}
2026-07-13T17:25:13Z	info-0	trufflehog	finished scanning	{"chunks": 7, "bytes": 859, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "11.876192ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The banner appears **only** in plain mode (immediately after the `trufflehog dev` version line).
Under `--json` it is absent (compare the two captures above). The engine-initialization detail
lines (`default engine options set`, `engine initialized`, `setting up aho-corasick core`,
`set up aho-corasick core`) are emitted at log level ≥ 4 (they are `V(4)` calls) and so do not
appear at `--log-level=2`; they are shown in the Q4 `--log-level=5` trace below.

### 4. Correlating source `file:line`

- `pkg/engine/defaults/defaults.go:L1704` — `func DefaultDetectors() []detectors.Detector`: the
  compiled-in registration entry point. It calls `buildDetectorList()` and returns the slice.
- `pkg/engine/defaults/defaults.go:L839` — `func buildDetectorList() []detectors.Detector`: the
  hard-coded list of detector structs (e.g. `&abyssale.Scanner{}`, `&abuseipdb.Scanner{}`, …),
  compiled directly into the binary. There is no file read or plugin load here.
- `main.go:L519` — `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)`: the
  detectors are placed into `engine.Config` at process start. (Any user-supplied `conf.Detectors`
  come from an optional `--config` file for *custom regex* detectors, not for the built-in ones.)
- `pkg/engine/engine.go:L226` — `func NewEngine(...)`: builds the engine (and its Aho-Corasick
  keyword prefilter core) from the detector slice.
- `pkg/engine/engine.go:L646` — `func (e *Engine) startWorkers(...)`: launches the four pools.
  The four count log lines are: `engine.go:L663` scanner (`count = e.concurrency`),
  `engine.go:L678` detector, `engine.go:L693` verificationOverlap, `engine.go:L708` notifier.
- `pkg/detectors/detectors.go:L19` — `type Detector interface` (with `FromData` at L21,
  `Keywords()` L24, `Type()` L26, `Description()` L28): the contract every compiled-in detector
  implements.
- `pkg/version/version.go:L3` — `var BuildVersion = "dev"`: the `trufflehog dev` startup line.
- Context corroboration (not a substitute for the run): `docs/concurrency.md` documents these
  exact four worker pools started by `e.startWorkers()`.

### 5. Reasoning

Because detectors are ordinary Go structs appended into a slice at compile time — there is no
config-file parse and no plugin discovery — there is nothing to "load from a file" at startup
and no per-detector registration event to log. The only startup evidence a user can observe is
therefore the version line, the four worker-pool count lines, and (in plain mode) the banner.

### 6. Label

**OBSERVED** (version line, four worker-pool count lines, banner present in plain / absent in
JSON, run-to-run stability, and the *absence* of any per-detector "registered" line) **+
SOURCE-CONFIRMED** (the compiled-in registration mechanism at `defaults.DefaultDetectors` +
`main.go:L519`).

---

## Q2 — Verification Setup (HTTP libraries + parallel vs. sequential)

**Question items covered by name:** whether the build dependencies include **HTTP client
libraries** that suggest **network verification**; whether the architecture shows verification
happening **in parallel or sequentially**.

### 1. Direct answer

**Yes** — the build dependencies include a resilient HTTP client library used for network
verification: **`github.com/hashicorp/go-retryablehttp v0.7.7`** (`go.mod:L63`), alongside
**`github.com/hashicorp/golang-lru/v2 v2.0.7`** (`go.mod:L64`, used for the verification/dedup
caches) and the indirect transport dependency **`github.com/hashicorp/go-cleanhttp v0.5.2`**
(`go.mod:L231`). Verification runs **in parallel**, not sequentially: each detector runs in a
worker pool sized **`concurrency × 8`** (here `128 × 8 = 1024`), and every worker independently
performs the verification call. The parallel dispatch and the live-network HTTP path are
distinct claims and are labelled separately below.

### 2. Exact commands executed

```text
# dependency evidence, read from the manifest
grep -nE 'go-retryablehttp|golang-lru/v2|go-cleanhttp' go.mod

# proof the HTTP client is compiled into the built binary
go version -m /tmp/thog_investigation/trufflehog_bin | grep -iE 'retryablehttp|golang-lru|cleanhttp'

# the parallel detector-pool size (reuse the Q1 startup stderr)
/tmp/thog_investigation/trufflehog_bin git file:///tmp/thog_investigation/thog_testrepo --json --log-level=2 --no-verification
```

### 3. Complete, unedited captured output

**Dependencies declared in `go.mod`:**

```text
$ grep -nE 'go-retryablehttp|golang-lru/v2|go-cleanhttp' go.mod
63:	github.com/hashicorp/go-retryablehttp v0.7.7
64:	github.com/hashicorp/golang-lru/v2 v2.0.7
231:	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
```

**HTTP client compiled into the built binary (`go version -m`):**

```text
$ go version -m /tmp/thog_investigation/trufflehog_bin | grep -iE 'retryablehttp|golang-lru|cleanhttp'
	dep	github.com/hashicorp/go-cleanhttp	v0.5.2	h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ=
	dep	github.com/hashicorp/go-retryablehttp	v0.7.7	h1:C8hUCYzor8PIfXHa4UrZkU4VvK8o9ISHxT2Q8+VepXU=
	dep	github.com/hashicorp/golang-lru/v2	v2.0.7	h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k=
```

**Parallel detector-pool size (from the same startup stderr shown in Q1):**

```text
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T17:25:09Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

`detector workers = 1024 = 128 × 8` — a 1024-way parallel detector pool on this 128-CPU host.
The multiplier is `8`; on a host with a different `runtime.NumCPU()` the count scales
proportionally. The count was identical across both Q1 runs.

### 4. Correlating source `file:line`

- `go.mod:L63` `github.com/hashicorp/go-retryablehttp v0.7.7`; `go.mod:L64`
  `github.com/hashicorp/golang-lru/v2 v2.0.7`; `go.mod:L231`
  `github.com/hashicorp/go-cleanhttp v0.5.2 // indirect` — the verification HTTP + cache libraries.
- `pkg/common/http.go:L12` imports `go-retryablehttp`; the shared clients detectors use for live
  verification are `PinnedRetryableHttpClient()` (`pkg/common/http.go:L159`),
  `RetryableHTTPClient(...)` (`pkg/common/http.go:L180`), and `SaneHttpClient()`
  (`pkg/common/http.go:L223`) — each builds a `*http.Client` on top of `retryablehttp.NewClient()`.
- `pkg/engine/engine.go:L675` `func (e *Engine) startDetectorWorkers(...)`, with
  `pkg/engine/engine.go:L676` `numWorkers := e.concurrency * e.detectorWorkerMultiplier`; the
  multiplier default is `8` (`pkg/engine/engine.go:L343-345`). This is what makes the pool
  `concurrency × 8`.
- `pkg/engine/engine.go:L1036` `func (e *Engine) detectorWorker(...)` — the per-worker loop;
  `pkg/engine/engine.go:L1070` `results, err := e.verificationCache.FromData(...)` — the
  per-worker verification call, executed concurrently across the pool.
- `pkg/detectors/detectors.go:L21` `FromData(ctx, verify bool, data []byte) ([]Result, error)`
  — the `verify` boolean is what drives the live network check inside each detector.

### 5. Reasoning

The detector pool is explicitly sized `concurrency × 8`, and each worker independently invokes
`FromData` (via the verification cache) on the candidates routed to it, so distinct candidates
are verified concurrently rather than one at a time — i.e. parallel, not sequential. At the
dependency level, the presence of a *resilient/retrying* HTTP client (`go-retryablehttp`) plus
an LRU cache (`golang-lru/v2`) is the architectural signal that verification performs live,
cache-backed API calls to credential providers.

### 6. Label

**OBSERVED** (the three HashiCorp dependencies are declared in `go.mod` and are compiled into
the binary per `go version -m`; the detector-worker pool is `concurrency × 8 = 1024`, stable
across ≥ 2 runs) **+ SOURCE-CONFIRMED** (the parallel per-worker `FromData` dispatch at
`engine.go:L1036/L1070` and the `× 8` multiplier at `engine.go:L676`).

> **Explicit scope note.** A genuinely *verified* finding (`Verified:true`) was **not** forced,
> because that would require real, active credentials and a live provider request. Parallelism
> is therefore demonstrated via the observed worker-pool count plus the source dispatch path;
> the live HTTP verification round-trip itself (the actual network call inside
> `PinnedRetryableHttpClient`/`RetryableHTTPClient` reached from `FromData`) is labelled
> **INFERRED** from source. `docs/concurrency.md` corroborates the pool architecture (context only).


---

## Q3 — JSON Output Schema

**Question items covered by name:** the actual **schema** for a finding under JSON output;
whether there are fields for **verification status**, **confidence scores**, or **metadata
about where secrets were found**.

### 1. Direct answer

The per-finding JSON schema is the anonymous struct marshalled by `JSONPrinter.Print`. It **has
verification-status fields** — `Verified` (bool), `VerificationFromCache` (bool), and an
omit-empty `VerificationError` (string, tag `json:",omitempty"`) — and **rich "where found"
metadata** under `SourceMetadata.Data.Git` (or `…Filesystem`, depending on source). It has **no
confidence-score field**: there is no `confidence` and no `score` key anywhere in the object.
For a git finding with no verification error, **15 top-level keys** are emitted (the 16th,
`VerificationError`, is omitted because it is empty).

### 2. Exact command executed

```text
/tmp/thog_investigation/trufflehog_bin git file:///tmp/thog_investigation/thog_testrepo --json --no-verification
```

### 3. Complete, unedited captured output

**Raw finding object (one compact JSON object per finding, verbatim from stdout):**

```text
{"SourceMetadata":{"Data":{"Git":{"commit":"71d455a32d1587c20e35f6484230b8ab6112d0da","file":"aws_creds.ini","email":"t \u003ct@t.com\u003e","timestamp":"2026-07-13 17:23:49 +0000","line":2}}},"SourceID":1,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAYVP4CIPPERUVIFXG","RawV2":"AKIAYVP4CIPPERUVIFXG:qUGtRtqlJNUCoY5SBly3QymVf33zOXxHcEuS7VxA","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

**Pretty-printed for readability (`python3 -m json.tool`; `jq` is not installed in this
environment, so the standard-library JSON pretty-printer was used):**

```text
$ python3 -m json.tool /tmp/thog_investigation/q3_stdout.json
{
    "SourceMetadata": {
        "Data": {
            "Git": {
                "commit": "71d455a32d1587c20e35f6484230b8ab6112d0da",
                "file": "aws_creds.ini",
                "email": "t <t@t.com>",
                "timestamp": "2026-07-13 17:23:49 +0000",
                "line": 2
            }
        }
    },
    "SourceID": 1,
    "SourceType": 16,
    "SourceName": "trufflehog - git",
    "DetectorType": 2,
    "DetectorName": "AWS",
    "DetectorDescription": "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.",
    "DecoderName": "PLAIN",
    "Verified": false,
    "VerificationFromCache": false,
    "Raw": "AKIAYVP4CIPPERUVIFXG",
    "RawV2": "AKIAYVP4CIPPERUVIFXG:qUGtRtqlJNUCoY5SBly3QymVf33zOXxHcEuS7VxA",
    "Redacted": "AKIAYVP4CIPPERUVIFXG",
    "ExtraData": {
        "account": "595918472158",
        "is_canary": "true",
        "message": "This is an AWS canary token generated at canarytokens.org.",
        "resource_type": "Access key"
    },
    "StructuredData": null
}
```

**Key enumeration + proof there is no confidence/score field:**

```text
$ python3 -c "import json;d=json.load(open('/tmp/thog_investigation/q3_stdout.json'));print('count=',len(d));print('fields=',list(d.keys()));print('ExtraData keys=',list(d['ExtraData'].keys()));print('Git keys=',list(d['SourceMetadata']['Data']['Git'].keys()))"
count= 15
fields= ['SourceMetadata', 'SourceID', 'SourceType', 'SourceName', 'DetectorType', 'DetectorName', 'DetectorDescription', 'DecoderName', 'Verified', 'VerificationFromCache', 'Raw', 'RawV2', 'Redacted', 'ExtraData', 'StructuredData']
ExtraData keys= ['account', 'is_canary', 'message', 'resource_type']
Git keys= ['commit', 'file', 'email', 'timestamp', 'line']

$ grep -ioE 'confidence|score' /tmp/thog_investigation/q3_stdout.json || echo "(none found)"
(none found)
```

### 4. Field-by-field schema, correlated to source `file:line`

The object is serialized by `func (p *JSONPrinter) Print(...)` at `pkg/output/json.go:L19`; the
anonymous struct is defined at `pkg/output/json.go:L27` with the following fields (16 defined;
`VerificationError` is `omitempty`, hence 15 visible above):

| # | JSON key | Go field / type | `json.go` line | Category |
|---|----------|-----------------|----------------|----------|
| 1 | `SourceMetadata` | `*source_metadatapb.MetaData` | L29 | **where found** |
| 2 | `SourceID` | `sources.SourceID` | L31 | source id |
| 3 | `SourceType` | `sourcespb.SourceType` | L33 | source type |
| 4 | `SourceName` | `string` | L35 | source name |
| 5 | `DetectorType` | `detectorspb.DetectorType` | L37 | detector id |
| 6 | `DetectorName` | `string` (`= r.DetectorType.String()`, L63) | L39 | detector name |
| 7 | `DetectorDescription` | `string` | L41 | detector description |
| 8 | `DecoderName` | `string` (`= r.DecoderType.String()`, L65) | L43 | decoder name |
| 9 | `Verified` | `bool` | L44 | **verification status** |
| 10 | `VerificationError` | `string` `json:",omitempty"` | L45 | **verification status** |
| 11 | `VerificationFromCache` | `bool` | L46 | **verification status** |
| 12 | `Raw` | `string` | L48 | secret payload |
| 13 | `RawV2` | `string` | L51 | secret payload |
| 14 | `Redacted` | `string` | L54 | secret payload |
| 15 | `ExtraData` | `map[string]string` | L55 | detector extras |
| 16 | `StructuredData` | `*detectorspb.StructuredData` | L56 | structured extras |

- **Verification status:** fields 9–11 (`Verified`, `VerificationError`, `VerificationFromCache`).
- **Where-found metadata:** `SourceMetadata.Data.Git` maps to `proto/source_metadata.proto:L94`
  `message Git { string commit=1; string file=2; string email=3; string repository=4; string
  timestamp=5; int64 line=6; }`. For filesystem scans it is `message Filesystem`
  (`proto/source_metadata.proto:L87`) instead. Both are held in the `oneof data` wrapper
  `message MetaData` (`proto/source_metadata.proto:L367`).
- **Confidence score:** **absent** — there is no such field in the struct at
  `pkg/output/json.go:L27-L56`, confirmed by the `grep` above returning no matches.
- Upstream shape: the struct mirrors `type Result struct` at `pkg/detectors/detectors.go:L87`
  (`DetectorType`, `Verified`, `Raw`, `RawV2`, `Redacted`, `ExtraData`, `StructuredData`, and an
  unexported `verificationError`) — again, no confidence/score member.

### 5. Reasoning

TruffleHog models a result's trust as a **binary/tri-state verification outcome** (verified /
unverified / errored-during-verification), not as a probabilistic confidence score — which is
why there is no confidence field. The "where found" data is *source-typed* (Git vs Filesystem
vs …) through the `SourceMetadata.Data` protobuf `oneof`, so a git finding carries commit/file/
email/timestamp/line, while a filesystem finding would carry file/line instead.

### 6. Label

**OBSERVED** (the real serialized finding, the 15-key enumeration, and the `grep` proving no
confidence/score key) **+ SOURCE-CONFIRMED** (the `json.go` struct field-by-field and the proto
messages). The finding was captured on the **unverified path** (`Verified:false`,
`VerificationFromCache:false`); the `ExtraData` (`account`, `is_canary`, `resource_type`,
`message`) is populated **offline** by the AWS detector from the key id, so it appears even with
`--no-verification`. The semantics of the fields on a *verified* result (e.g. `Verified:true`,
a populated `VerificationError` on a failed check) are described from source and labelled
**INFERRED**, since no live verification was performed.


---

## Q4 — Repository Traversal / File Filtering (scan vs. skip)

**Question items covered by name:** how TruffleHog decides **which files to scan versus skip**,
as revealed by **verbose logs** on a **mixed file type** repository.

### 1. Direct answer

The scan-vs-skip decision is driven by **content-based MIME-type detection**, followed by an
ignored/binary-extension check performed on the **content-derived** extension — *not* on the
filename's own extension. A file whose *bytes* sniff to an ignored/binary MIME is skipped; a file
whose *bytes* sniff to text is scanned. The decisive contrast in the fixture: `logo.png` (real
PNG bytes → MIME `image/png` → ext `.png`) is **skipped**, while `data.mp4` (plain-text bytes with
a `.mp4` name → MIME `text/plain` → ext `.txt`) is **scanned** — even though **both** `png` and
`mp4` literally appear in the ignored-extensions list. This isolates the effective decision key as
the **content MIME type**, not the filename.

### 2. Exact command executed

```text
/tmp/thog_investigation/trufflehog_bin filesystem /tmp/thog_investigation/thog_files --no-verification --log-level=5
```

(The `thog_files` directory is a copy of the fixture's working tree — i.e. no `.git` — so the
filesystem source scans the real files directly. The full trace is 172 lines; it is presented as
three complete, unedited slices below, each with the command that extracts it.)

### 3. Complete, unedited captured output

**Slice A — the head of the trace (lines 1–42): engine init, worker pools, and every per-file
scan/skip decision. Verbatim, unedited:**

```text
2026-07-13T17:26:13Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T17:26:13Z	info-4	trufflehog	default engine options set
2026-07-13T17:26:13Z	info-4	trufflehog	engine initialized
2026-07-13T17:26:13Z	info-4	trufflehog	setting up aho-corasick core
2026-07-13T17:26:13Z	info-4	trufflehog	set up aho-corasick core
2026-07-13T17:26:13Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T17:26:13Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T17:26:13Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T17:26:13Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T17:26:13Z	info-0	trufflehog	running source	{"source_manager_worker_id": "OTPjk", "with_units": true}
2026-07-13T17:26:13Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "OTPjk"}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/config.env"}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/aws_creds.ini"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/config.env", "path": "/tmp/thog_investigation/thog_files/config.env"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/aws_creds.ini", "path": "/tmp/thog_investigation/thog_files/aws_creds.ini"}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz"}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/data.mp4"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/data.mp4", "path": "/tmp/thog_investigation/thog_files/data.mp4"}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/aws_creds.ini", "path": "/tmp/thog_investigation/thog_files/aws_creds.ini", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/config.env", "path": "/tmp/thog_investigation/thog_files/config.env", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/data.mp4", "path": "/tmp/thog_investigation/thog_files/data.mp4", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:26:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/logo.png"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/logo.png", "path": "/tmp/thog_investigation/thog_files/logo.png"}
2026-07-13T17:26:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
2026-07-13T17:26:13Z	info-4	trufflehog	Opened file successfully	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 37, "filename": "inside.txt", "size": 37}
2026-07-13T17:26:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 37, "depth": 2}
2026-07-13T17:26:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 37, "depth": 2}
2026-07-13T17:26:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
2026-07-13T17:26:13Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/logo.png", "path": "/tmp/thog_investigation/thog_files/logo.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
2026-07-13T17:26:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/logo.png", "path": "/tmp/thog_investigation/thog_files/logo.png", "mime": "image/png", "timeout": 60}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/notes.txt"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/notes.txt", "path": "/tmp/thog_investigation/thog_files/notes.txt"}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/notes.txt", "path": "/tmp/thog_investigation/thog_files/notes.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:26:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/testkey.pem"}
2026-07-13T17:26:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/testkey.pem", "path": "/tmp/thog_investigation/thog_files/testkey.pem"}
2026-07-13T17:26:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "OTPjk", "unit_kind": "unit", "unit": "/tmp/thog_investigation/thog_files/testkey.pem", "path": "/tmp/thog_investigation/thog_files/testkey.pem", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

**Slice B — lines 43–171 are 128 near-identical per-scanner-worker completion lines** (one per
scanner worker in the 128-way pool), interleaved with a single AWS detector line at line 142.
Their count and the lone non-worker line are shown verbatim by these commands (complete, unedited):

```text
$ grep -c 'finished scanning chunks' q4_files_trace.log
128

$ sed -n '43p;44p;171p' q4_files_trace.log        # first two + last of the 128 worker lines
2026-07-13T17:26:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "onrpY"}
2026-07-13T17:26:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5rbWo"}
2026-07-13T17:26:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0UNTx"}

$ sed -n '142p' q4_files_trace.log                # the single non-worker line in that block
2026-07-13T17:26:13Z	info-4	trufflehog	link is empty, skipping update	{"detector_worker_id": "ZLNn7", "detector": {"type":"AWS"}, "timeout": 10}
```

**Slice C — the final scan summary (line 172, verbatim):**

```text
2026-07-13T17:26:13Z	info-0	trufflehog	finished scanning	{"chunks": 6, "bytes": 781, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "8.516335ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**The corresponding finding on stdout** (confirming `aws_creds.ini` was scanned and matched;
plain-text output from the same `--no-verification` filesystem run):

```text
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAYVP4CIPPERUVIFXG
Resource_type: Access key
Account: 595918472158
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/thog_investigation/thog_files/aws_creds.ini
Line: 2
```

### Interpretation of the decisive lines

- `logo.png` → the log line **`skipping file: extension is ignored`** carries `"mime":"image/png"`
  and `"ext":".png"`. The `ext` is the **content-detected** extension (derived from the sniffed
  `image/png` MIME), and `.png` is in the ignored list → **skipped**.
- `data.mp4` → **no** skip line; instead it reaches `scanning file` and then
  `dataErrChan closed, all chunks processed` with `"mime":"text/plain; charset=utf-8"`. Its bytes
  sniffed to text, so the content-derived extension is `.txt` (not ignored) → **scanned**.
- Both `png` (`pkg/common/vars.go:L23`) and `mp4` (`pkg/common/vars.go:L50`) are present in
  `ignoredExtensions`, yet `data.mp4` was still scanned — proving the check does **not** use the
  filename extension. Reported scanned units: `config.env`, `aws_creds.ini`, `data.mp4`,
  `notes.txt`, `testkey.pem`, and the archive member `inside.txt`; skipped: `logo.png`.
- The archive `archive.tar.gz` (MIME `application/gzip`) was **descended into** (nested
  `Starting/Finished archive processing` at `depth` 0→1→2), and its text member `inside.txt`
  (37 bytes) was extracted and scanned.

### 4. Correlating source `file:line`

- `pkg/handlers/default.go:L94` `func (h *defaultHandler) handleNonArchiveContent(...)`;
  `pkg/handlers/default.go:L99` `mimeExt := reader.mimeExt`;
  `pkg/handlers/default.go:L101` `if common.SkipFile(mimeExt) || common.IsBinary(mimeExt) {`;
  `pkg/handlers/default.go:L102`
  `ctx.Logger().V(3).Info("skipping file: extension is ignored", "ext", mimeExt)` — the exact line
  observed for `logo.png` (a `V(3)` call, hence `info-3`).
- `pkg/handlers/handlers.go:L98` `mime := mimetype.Detect(buffer)` and
  `pkg/handlers/handlers.go:L127` `mime, err = mimetype.DetectReader(fReader)` — **content-based**
  MIME detection (library `github.com/gabriel-vasile/mimetype`, `go.mod:L47`);
  `pkg/handlers/handlers.go:L76` sets `mimeExt: r.mime.Extension()` — the extension is **derived
  from content**, not from the filename.
- `pkg/common/vars.go:L122` `func SkipFile(filename string) bool` (looks up `ignoredExtensions`,
  `pkg/common/vars.go:L10`) and `pkg/common/vars.go:L129` `func IsBinary(filename string) bool`
  (looks up `binaryExtensions`, `pkg/common/vars.go:L80`); both compute
  `strings.ToLower(strings.TrimPrefix(filepath.Ext(filename), "."))` on whatever string they are
  passed — here the content-derived `mimeExt`.
- `pkg/common/vars.go:L23` `"png"` and `pkg/common/vars.go:L50` `"mp4"` — both present in
  `ignoredExtensions` (the point of the contrast).
- Archive limits: `pkg/handlers/archive.go:L26` `maxDepth = 5 * 2` (=10),
  `pkg/handlers/archive.go:L27` `maxSize = 2 << 30` (2 GB),
  `pkg/handlers/archive.go:L188` `V(4).Info("skipping directory or symlink")`,
  `pkg/handlers/archive.go:L199` size-exceeds-max skip, `pkg/handlers/archive.go:L205`
  extension-ignored skip. The observed archive descent matches the `V(4)` "archive processing" path.
- Git-source binary handling (relevant when scanning via the `git` source):
  `pkg/sources/git/git.go:L648` and `pkg/sources/git/git.go:L877`
  `logger.V(5).Info("skipping binary file", …)`; exclude-globs at
  `pkg/sources/git/git.go:L185-187` (`ScanOptionExcludeGlobs`).
- Context corroboration (not a substitute): `docs/process_flow.md` documents the
  Source→Unit→Chunk decomposition visible as the `enumerating source` / `chunking unit` /
  `scanning file` lines.

### 5. Reasoning

Filenames are unreliable (a `.mp4` can hold text; a `.txt` can hold a PNG), so TruffleHog sniffs
the actual leading bytes with `mimetype` and decides from the **content-derived** type. This
maximizes recall on mislabeled files (the text-bearing `data.mp4` is still scanned) while still
skipping genuinely binary/media content (the real `logo.png`). Archives are a separate route:
they are opened and descended (up to `maxDepth`/`maxSize`) so secrets inside them are still found.

### 6. Label

**OBSERVED** (the trace lines showing the `logo.png` skip with `mime=image/png ext=.png`, the
`data.mp4` scan with `mime=text/plain`, the archive descent, and the finding on stdout) **+
SOURCE-CONFIRMED** (`default.go:L101-102`, `handlers.go:L98/L127/L76`, `vars.go`). The
archive-**limit** thresholds (`maxDepth=10`, `maxSize=2 GB`) were **not** hit by the tiny fixture
archive, so those specific thresholds are **INFERRED** from `archive.go:L26-27`; the archive
*descent* itself is OBSERVED. Git-source binary-skip lines are **INFERRED** from source (this run
used the `filesystem` source).


---

## Q5 — Detector Architecture & Help

**Question items covered by name:** whether, when compiled, detectors are **separate plugins**
or **embedded modules**; what the **help flag** shows about **available detection capabilities**.

### 1. Direct answer

Detectors are **embedded / compiled-in modules — NOT separate plugins.** The built artifact is a
**single static binary** with no dynamic linking and no plugin-loading mechanism: `ldd` reports
`not a dynamic executable`, and the module list baked into the binary (`go version -m`) contains
no plugin module. The detectors are ordinary Go structs referenced by the compiled-in
`DefaultDetectors()` slice. `--help` lists the scannable **source commands** (`git`, `github`,
`filesystem`, `s3`, `docker`, …) and the top-level flags; `--help-long` additionally expands the
per-command flags. The detector-selection and verification flags appear in the shared global
Flags block (present in both `--help` and `--help-long`).

### 2. Exact commands executed

```text
ldd /tmp/thog_investigation/trufflehog_bin
go version -m /tmp/thog_investigation/trufflehog_bin | head -8
go version -m /tmp/thog_investigation/trufflehog_bin | grep -ic plugin
ls -d pkg/detectors/*/ | wc -l
/tmp/thog_investigation/trufflehog_bin --help
/tmp/thog_investigation/trufflehog_bin --help-long
```

### 3. Complete, unedited captured output

**Static-binary proof (`ldd`; exit code 1 because it is not dynamically linked):**

```text
$ ldd /tmp/thog_investigation/trufflehog_bin
	not a dynamic executable
$ echo "ldd exit=$?"
ldd exit=1
```

**Build settings + module header baked into the binary (`go version -m`):**

```text
$ go version -m /tmp/thog_investigation/trufflehog_bin | head -8
/tmp/thog_investigation/trufflehog_bin: go1.24.2
	path	github.com/trufflesecurity/trufflehog/v3
	mod	github.com/trufflesecurity/trufflehog/v3	(devel)	
	dep	cel.dev/expr	v0.19.2	h1:V354PbqIXr9IQdwy4SYA4xa0HXaWq1BUPAGzugBY5V4=
	dep	cloud.google.com/go	v0.120.0	h1:wc6bgG9DHyKqF5/vQvX1CiZrtHnxJjBlKUyF9nP6meA=
	dep	cloud.google.com/go/auth	v0.16.0	h1:Pd8P1s9WkcrBE2n/PhAwKsdrR35V3Sg2II9B+ndM3CU=
	dep	cloud.google.com/go/auth/oauth2adapt	v0.2.8	h1:keo8NaayQZ6wimpNSmW5OPc283g65QNIiLpZnkHRbnc=
	dep	cloud.google.com/go/compute/metadata	v0.6.0	h1:A6hENjEsCDtC1k8byVsgwvVcioamEHvZ4j01OwKxG9I=

$ go version -m /tmp/thog_investigation/trufflehog_bin | grep -E 'build\s+(CGO_ENABLED|GOARCH|GOOS)'
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux
```

The main module is reported as `(devel)` — consistent with the default build's `trufflehog dev`
version — and the build was `CGO_ENABLED=0` (a pure-Go static link).

**No plugin module in the compiled-in dependency list:**

```text
$ go version -m /tmp/thog_investigation/trufflehog_bin | grep -ic plugin
0
```

**Detector count (derived at runtime; host/commit-specific — shown with the command that produced it):**

```text
$ ls -d pkg/detectors/*/ | wc -l
845
$ sed -n '839,1703p' pkg/engine/defaults/defaults.go | grep -cE '^\s*&[a-zA-Z0-9_]+\.Scanner\{\}'
829
$ sed -n '839,1703p' pkg/engine/defaults/defaults.go | grep -cE '^\s*//\s*&[a-zA-Z0-9_]+\.Scanner\{\}'
28
```

There are **845** detector directories under `pkg/detectors/`; `buildDetectorList()` compiles
**829** active (`&pkg.Scanner{}`) detector structs into the binary, with **28** entries
commented out. These counts are derived from the tree/source at commit `e42153d44a5e…`; the
important, non-numeric fact is that every one of them is a Go struct linked into the single
binary — there is no per-detector plugin file.

**Complete `--help` output (124 lines, verbatim):**

```text
usage: TruffleHog [<flags>] <command> [<args> ...]

TruffleHog is a tool for finding credentials.


Flags:
  -h, --[no-]help                Show context-sensitive help (also try
                                 --help-long and --help-man).
      --log-level=0              Logging verbosity on a scale of 0 (info) to 5
                                 (trace). Can be disabled with "-1".
      --[no-]profile             Enables profiling and sets a pprof and fgprof
                                 server on :18066.
  -j, --[no-]json                Output in JSON format.
      --[no-]json-legacy         Use the pre-v3.0 JSON format. Only works with
                                 git, gitlab, and github sources.
      --[no-]github-actions      Output in GitHub Actions format.
      --concurrency=128          Number of concurrent workers.
      --[no-]no-verification     Don't verify the results.
      --results=RESULTS          Specifies which type(s) of results to
                                 output: verified, unknown, unverified,
                                 filtered_unverified. Defaults to
                                 verified,unverified,unknown.
      --[no-]no-color            Disable colorized output
      --[no-]allow-verification-overlap  
                                 Allow verification of similar credentials
                                 across detectors
      --[no-]filter-unverified   Only output first unverified result per
                                 chunk per detector if there are more than one
                                 results.
      --filter-entropy=FILTER-ENTROPY  
                                 Filter unverified results with Shannon entropy.
                                 Start with 3.0.
      --config=CONFIG            Path to configuration file.
      --[no-]print-avg-detector-time  
                                 Print the average time spent on each detector.
      --[no-]no-update           Don't check for updates.
      --[no-]fail                Exit with code 183 if results are found.
      --verifier=VERIFIER ...    Set custom verification endpoints.
      --[no-]custom-verifiers-only  
                                 Only use custom verification endpoints.
      --detector-timeout=DETECTOR-TIMEOUT  
                                 Maximum time to spend scanning chunks per
                                 detector (e.g., 30s).
      --archive-max-size=ARCHIVE-MAX-SIZE  
                                 Maximum size of archive to scan. (Byte units
                                 eg. 512B, 2KB, 4MB)
      --archive-max-depth=ARCHIVE-MAX-DEPTH  
                                 Maximum depth of archive to scan.
      --archive-timeout=ARCHIVE-TIMEOUT  
                                 Maximum time to spend extracting an archive.
      --include-detectors="all"  Comma separated list of detector types to
                                 include. Protobuf name or IDs may be used,
                                 as well as ranges.
      --exclude-detectors=EXCLUDE-DETECTORS  
                                 Comma separated list of detector types to
                                 exclude. Protobuf name or IDs may be used,
                                 as well as ranges. IDs defined here take
                                 precedence over the include list.
      --[no-]no-verification-cache  
                                 Disable verification caching
      --[no-]force-skip-binaries  
                                 Force skipping binaries.
      --[no-]force-skip-archives  
                                 Force skipping archives.
      --[no-]skip-additional-refs  
                                 Skip additional references.
      --user-agent-suffix=USER-AGENT-SUFFIX  
                                 Suffix to add to User-Agent.
      --[no-]version             Show application version.

Commands:
help [<command>...]
    Show help.

git [<flags>] <uri>
    Find credentials in git repositories.

github [<flags>]
    Find credentials in GitHub repositories.

github-experimental --repo=REPO [<flags>]
    Run an experimental GitHub scan. Must specify at least one experimental
    sub-module to run: object-discovery.

gitlab --token=TOKEN [<flags>]
    Find credentials in GitLab repositories.

filesystem [<flags>] [<path>...]
    Find credentials in a filesystem.

s3 [<flags>]
    Find credentials in S3 buckets.

gcs [<flags>]
    Find credentials in GCS buckets.

syslog [<flags>]
    Scan syslog

circleci --token=TOKEN
    Scan CircleCI

docker --image=IMAGE [<flags>]
    Scan Docker Image

travisci --token=TOKEN
    Scan TravisCI

postman [<flags>]
    Scan Postman

elasticsearch [<flags>]
    Scan Elasticsearch

jenkins --url=URL [<flags>]
    Scan Jenkins

huggingface [<flags>]
    Find credentials in HuggingFace datasets, models and spaces.

analyze
    Analyze API keys for fine-grained permissions information.
```

The `--help` output enumerates **17 commands**: `help`, `git`, `github`,
`github-experimental`, `gitlab`, `filesystem`, `s3`, `gcs`, `syslog`, `circleci`, `docker`,
`travisci`, `postman`, `elasticsearch`, `jenkins`, `huggingface`, and `analyze` — i.e. the
sources TruffleHog can scan plus the built-in `help` and the `analyze` sub-tool. (Note that
`--concurrency=128` in the flags block is this host's `runtime.NumCPU()` default.)

**`--help-long` (416 lines): its global Flags block is the same as `--help` above; it adds a
per-command flag expansion. Command-section map (complete output of the extracting grep):**

```text
$ grep -nE '^(help|git|github|github-experimental|gitlab|filesystem|s3|gcs|syslog|circleci|docker|travisci|postman|elasticsearch|jenkins|huggingface|analyze) ' /tmp/thog_investigation/help_long.txt
71:help [<command>...]
75:git [<flags>] <uri>
98:github [<flags>]
140:github-experimental --repo=REPO [<flags>]
155:gitlab --token=TOKEN [<flags>]
182:filesystem [<flags>] [<path>...]
194:s3 [<flags>]
220:gcs [<flags>]
255:syslog [<flags>]
265:circleci --token=TOKEN
271:docker --image=IMAGE [<flags>]
279:travisci --token=TOKEN
285:postman [<flags>]
317:elasticsearch [<flags>]
345:jenkins --url=URL [<flags>]
355:huggingface [<flags>]
```

**Representative expanded command section from `--help-long` — the `git` command (lines 75–97,
verbatim), showing the per-command flags including `--exclude-globs`:**

```text
git [<flags>] <uri>
    Find credentials in git repositories.

    -i, --include-paths=INCLUDE-PATHS  
                               Path to file with newline separated regexes for
                               files to include in scan.
    -x, --exclude-paths=EXCLUDE-PATHS  
                               Path to file with newline separated regexes for
                               files to exclude in scan.
        --exclude-globs=EXCLUDE-GLOBS  
                               Comma separated list of globs to exclude in scan.
                               This option filters at the `git log` level,
                               resulting in faster scans.
        --since-commit=SINCE-COMMIT  
                               Commit to start scan from.
        --branch=BRANCH        Branch to scan.
        --max-depth=MAX-DEPTH  Maximum depth of commits to scan.
        --[no-]bare            Scan bare repository (e.g. useful while using in
                               pre-receive hooks)
        --[no-]allow           No-op flag for backwards compat.
        --[no-]entropy         No-op flag for backwards compat.
        --[no-]regex           No-op flag for backwards compat.
```

### Detection-capability flags shown by `--help` (all present in the block above)

**Detector-selection flags** (correlated to `main.go`):

| Flag (as shown) | `main.go` line |
|-----------------|----------------|
| `--concurrency=128` (Default `runtime.NumCPU()`) | `main.go:L58` |
| `--print-avg-detector-time` | `main.go:L72` |
| `--detector-timeout` | `main.go:L77` |
| `--include-detectors="all"` (Default `"all"`) | `main.go:L81` |
| `--exclude-detectors` | `main.go:L82` |

**Verification flags** (correlated to `main.go`):

| Flag (as shown) | `main.go` line |
|-----------------|----------------|
| `--no-verification` | `main.go:L59` |
| `--results` ("Defaults to verified,unverified,unknown") | `main.go:L61` |
| `--allow-verification-overlap` | `main.go:L65` |
| `--filter-unverified` | `main.go:L66` |
| `--filter-entropy` | `main.go:L67` |
| `--verifier` | `main.go:L75` |
| `--custom-verifiers-only` | `main.go:L76` |
| `--no-verification-cache` | `main.go:L85` |

### 4. Correlating source `file:line`

- Compiled-in registration: `pkg/engine/defaults/defaults.go:L839` `buildDetectorList()` (the
  829 active `&pkg.Scanner{}` structs) and `pkg/engine/defaults/defaults.go:L1704`
  `DefaultDetectors()` (wraps `buildDetectorList()` and initializes endpoint/cloud detectors) —
  detectors are Go structs baked into the binary, not plugins.
- CLI command/flag definitions: the `kingpin` `cli.Command(...)`/`cli.Flag(...)` declarations in
  `main.go` — commands at `main.go:L93` (git), `L106` (github), `L124` (github-experimental),
  `L133` (gitlab), `L143` (filesystem), `L152` (s3), `L162` (gcs), `L174` (syslog), `L181`
  (circleci), `L184` (docker), `L188` (travisci), `L192` (postman), `L216` (elasticsearch),
  `L228` (jenkins), `L234` (huggingface), and `analyzeCmd = analyzer.Command(cli)` at
  `main.go:L255`; detector-selection and verification flags per the two tables above.
- Static binary: the `ldd` result (`not a dynamic executable`) and the `CGO_ENABLED=0` build
  setting from `go version -m` (OBSERVED).

### 5. Reasoning

A `CGO_ENABLED=0` Go build statically links everything into one executable. Detectors are plain
Go types collected by `DefaultDetectors()`, so there is no runtime plugin discovery or dynamic
loading — which is exactly what `ldd` (`not a dynamic executable`) and the absence of any plugin
module in `go version -m` confirm. The help surface therefore advertises *which sources* can be
scanned (the commands) and *how detection is tuned* (the include/exclude-detector and
verification flags), rather than any notion of loadable detector plugins.

### 6. Label

**OBSERVED** (`ldd`, `go version -m` build settings and module list, the detector-directory
count, and the complete `--help` / `--help-long` output) **+ SOURCE-CONFIRMED** (the compiled-in
registration at `defaults.go:L839/L1704` and the `kingpin` command/flag definitions in `main.go`).


---

## Coverage Pass — every named item addressed

Each item named in the five questions is confirmed addressed, with its locator:

- [x] **Q1: "startup" behavior described** — OBSERVED version line + four worker-pool count lines
  + banner (Q1 §3); source `engine.go:L646` `startWorkers`.
- [x] **Q1: "detector configurations from files" vs "compiled in"** — answered: **compiled in**
  (`defaults.DefaultDetectors()` `defaults.go:L1704`, wired at `main.go:L519`); no file load.
- [x] **Q1: "initialization messages … which detectors get registered"** — answered: worker-pool
  count logs are the startup messages; there is **no per-detector "registered" log line** at any
  level (observed absence at `--log-level=2` and `--log-level=5`); registration is compile-time.
- [x] **Q2: "HTTP client libraries"** — `github.com/hashicorp/go-retryablehttp v0.7.7` (`go.mod:L63`),
  `golang-lru/v2 v2.0.7` (`go.mod:L64`), `go-cleanhttp v0.5.2` (`go.mod:L231`); OBSERVED compiled
  into the binary via `go version -m`.
- [x] **Q2: "verification … in parallel or sequentially"** — **parallel**: detector pool
  `concurrency × 8` = 1024 (`engine.go:L676`), each worker calls `FromData` (`engine.go:L1070`).
- [x] **Q3: JSON "schema for a finding"** — 16-field struct enumerated field-by-field
  (`json.go:L27-L56`), 15 visible when `VerificationError` is empty (OBSERVED key list).
- [x] **Q3: "verification status" fields** — `Verified` (`json.go:L44`), `VerificationError`
  (`json.go:L45`, omitempty), `VerificationFromCache` (`json.go:L46`).
- [x] **Q3: "confidence scores"** — **ABSENT**, proven by `grep -ioE 'confidence|score'` returning
  no matches and by the struct having no such field.
- [x] **Q3: "metadata about where secrets were found"** — `SourceMetadata.Data.Git`
  (`source_metadata.proto:L94`) / `Filesystem` (`source_metadata.proto:L87`); observed
  `commit/file/email/timestamp/line`.
- [x] **Q4: "which files to scan versus skip"** — content-MIME decision (`default.go:L101-102`,
  `handlers.go:L98/L127/L76`, `vars.go:L122/L129`); OBSERVED skip vs scan lines.
- [x] **Q4: mixed file types exercised** — text (`config.env`, `notes.txt`, `testkey.pem`
  scanned), image (`logo.png` → `image/png` → **skipped**), video-named-text (`data.mp4` →
  `text/plain` → **scanned**), PEM (text), and an archive (`archive.tar.gz` → descended,
  `inside.txt` extracted & scanned).
- [x] **Q5: "plugins or embedded modules"** — **embedded/static single binary**; `ldd` →
  `not a dynamic executable`; no plugin module in `go version -m`; `CGO_ENABLED=0`.
- [x] **Q5: "help flag"** — complete `--help` (17 commands + global flags) and `--help-long`
  (command-section map + expanded `git` section) pasted verbatim; detector-selection +
  verification flags tabulated to `main.go` lines.
- [x] Every code block is complete and unedited, paired with the exact command that produced it.
- [x] Every Q section carries an explicit OBSERVED / INFERRED (+ SOURCE-CONFIRMED) label.
- [x] Host CPU count stated (`runtime.NumCPU()` = 128; shell `nproc` = 4 noted as misleading);
  host-dependence of worker/finding counts noted; worker counts confirmed **stable across 2 runs**.
- [x] Build identity `trufflehog dev` reported with the exact build command
  (`CGO_ENABLED=0 go build -o /tmp/thog_investigation/trufflehog_bin .`).

---

## OBSERVED vs. INFERRED — summary

- **OBSERVED** (built and ran, saw the output): the `trufflehog dev` version; `ldd` static-binary
  result; binary size; worker-pool counts (128 / 1024 / 128 / 128) stable across two runs; the
  banner present in plain mode and absent in JSON mode; the absence of any per-detector
  registration log; the `go.mod` HTTP dependencies and their presence in the compiled binary; the
  real JSON finding and its 15-key set with no confidence/score; the `logo.png` skip
  (`image/png`) vs `data.mp4` scan (`text/plain`) and the archive descent; the complete `--help`
  and `--help-long` output; the detector-directory (845) and active-struct (829) counts.
- **INFERRED** (read in source, not exercised at runtime): the live HTTP verification round-trip
  itself (no `Verified:true` was forced, as that needs real active credentials) — the parallel
  *dispatch* is observed, the network call is inferred from `FromData` + `pkg/common/http.go`; the
  semantics of a *verified* result's fields; the archive **limit** thresholds (`maxDepth=10`,
  `maxSize=2 GB`) which the tiny fixture did not reach; and the git-source binary-skip lines
  (this run used the `filesystem` source).

---

## Final integrity statement

- **Commit under investigation (verified at authoring time):**

```text
$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760
```

- **Read-only guarantee:** all build/run artifacts (binary, fixture, captured logs, scripts) were
  created under `/tmp/thog_investigation/` — **outside** the source checkout — and are removed
  after authoring. The canonical build uses Go's default `-mod=readonly`, so `go.mod`/`go.sum`
  are untouched. On completion, `git status --porcelain` shows **only** the single new answer
  document `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- **Host note:** observations were captured on an x86_64 Linux host where Go's
  `runtime.NumCPU()` = 128. Absolute worker counts, finding counts, scan durations, and the
  binary size are host/toolchain-specific; the *mechanisms, fields, flags, decision logic, and
  `file:line` references* are not.

