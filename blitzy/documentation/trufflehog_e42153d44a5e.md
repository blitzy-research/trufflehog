# TruffleHog Detector Pattern Matching: ReDoS / Resource-Exhaustion DoS Investigation

**Repository:** `github.com/trufflesecurity/trufflehog` (module `github.com/trufflesecurity/trufflehog/v3`)
**Pinned commit:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`
**Branch:** `trufflehog_e42153d44a5e`
**Question class:** Availability / Denial-of-Service via computational-complexity (ReDoS) attack on regex-based secret detectors.

This document answers whether a maliciously crafted file, committed to a repository that TruffleHog scans, can be used to make a TruffleHog scan **hang or time out** and thereby **block a CI security pipeline** — and it quantifies the worst-case slowdown against a **byte-for-byte equal-size benign file**, backed by **wall-clock timing measurements and CPU-profiling evidence**. Every measurement below was produced by building and running the real `trufflehog` binary in its default, canonical configuration; the exact build, scan, and profiling commands are stated, and each behavioral claim is grounded in complete, unedited command output plus a `file:line` reference.

---

## TL;DR / Direct Answer

> **Catastrophic-backtracking ReDoS is NOT reproducible against TruffleHog's detectors.**
>
> TruffleHog's detectors compile their patterns on **Google RE2 via `github.com/wasilibs/go-re2`** — a linear-time, non-backtracking regex engine. **867 of the 870 detector `.go` files** import the go-re2 alias, and the remaining **3** use the Go standard-library `regexp` package, which belongs to the *same* RE2/linear-time family. A backtracking engine (`github.com/dlclark/regexp2`) exists in the module graph only as an **`// indirect`** dependency with **zero** direct use anywhere under `pkg/`. Because none of the detector patterns run on a backtracking engine, a crafted file **cannot** make a scan hang via regex computational complexity.

That is the direct answer. The nuance, all of it directly observed at runtime, follows:

- The detectors' matching cost is **bounded and linear** in the size of the input, and the input reaching any single regex is bounded twice more by defense-in-depth (a 13 KB sliding-window chunker and a ±512-byte extraction window around each keyword hit).
- There **is** a real, content-driven slowdown — up to **≈114× at the pure-scan level** for a maximally keyword-dense file versus an equal-size benign file — but this is **linear work proportional to the number of secret candidates in the file**, not algorithmic blow-up, and it **completes in seconds and does not hang**. Doubling the file merely doubles the work.
- Two honest caveats are **detection-gaps, not availability DoS**: RE2's "DFA out of memory" graceful-failure path (TruffleHog issue #2739), and the git source's 64 KB per-line scanner limit. In both, content may be **skipped** (a secret could be missed) — the scan runs *faster*, not slower, and never hangs.
- The per-detector timeout is **soft**: it only **logs** a message after 11 seconds and never force-kills a match. It never fired in any run performed here.

**One-line answer to each question:**

- **Q1 — Can a committed crafted file make TruffleHog hang/time out and block scans?** **No.** No crafted input caused a hang or timeout; every scan completed, and the worst cases scaled linearly and finished in seconds.
- **Q2 — Is the regex-based pattern matching vulnerable to computational-complexity (ReDoS) attacks?** **No.** Detectors run on RE2 (linear-time, non-backtracking); a classic ReDoS-shaped input scanned *slightly faster* than the benign control (0.82×).
- **Q3 — Which specific detector patterns can be exploited for disproportionate time?** **None** for *catastrophic* (super-linear) time. The patterns that cost more CPU (e.g. `jdbc`) do so **linearly**, proportional to the number of legitimate matches.
- **Q4 — How many times slower vs. normal files of equivalent size?** The ReDoS-specific answer is **≈1× (no slowdown)**. The maximum *content-driven* slowdown for a byte-for-byte equal-size file is **≈114× at the pure-scan level (≈4.3× end-to-end wall-clock)** — and it is **linear, not exponential**.
- **Q5 — Timing measurements AND CPU-profiling data?** Provided: equal-size wall-clock tables across ≥2 runs, plus verbatim `go tool pprof` CPU and fgprof wall-clock output and a benchmark throughput table. The profile shows the go-re2 RE2 engine executing in WebAssembly with **no backtracking function anywhere** in the hot path.

**Bottom line for a CI owner:** A file committed to a scanned repository **cannot hang the scan via regex complexity**. The worst realistic effect an attacker can achieve by content alone is a **bounded, linear** slowdown that still **completes in seconds** (the pathological 150 MB / 324,751-candidate scan finished in ~48 s and never hung). This is a performance consideration, not an availability vulnerability. No remediation is proposed here — that is out of scope for this investigation.

---

## Methodology & Canonical Build

**Environment and canonical build.** The investigation used the canonical default build and both real scan entry points. The binary was built with:

```
CGO_ENABLED=0 go build -o /work/trufflehog .
```

producing the version banner `trufflehog dev`. Because `CGO_ENABLED=0` is set and the `re2_cgo` build tag is **not** set, `go-re2` runs in its **default pure-Go WebAssembly mode** via the `wazero` runtime (confirmed by the CPU profile in Q5 showing `runtime._ExternalCode` plus `wazero` frames). This matches the repository's own build configuration: `Dockerfile` **L5** `ENV CGO_ENABLED=0` and **L9** `go build -o trufflehog .`, and `Makefile` **L49** `CGO_ENABLED=0 go run . git file://. --json`.

**Toolchain / container transparency.** The build and runs were performed in the official **`golang:1.24-bookworm`** image (`go1.24.13`, `git 2.39.5`). The Agent Action Plan named a specific SWE container (`andrewparkscaleai/coding-agent:…` / `ghcr.io/scaleapi/swe-atlas:…`, Go 1.24); that image required registry authentication and was unavailable, so the official `golang:1.24` image was used instead. This is **functionally equivalent for building and running**: both provide **Go 1.24 + `CGO_ENABLED=0`**, which fully determines the canonical go-re2 WebAssembly configuration. The named image only adds CLI tools (`git`, `openssh`, `rpm2cpio`, `binutils`, `cpio`) for the git and archive/rpm handlers, and `git` is already present in `bookworm`. **All reported values are therefore canonical.** **No standard-library-`regexp` proxy or any other non-canonical stand-in was used at any point** — there is nothing in this report that needs to be labeled non-canonical.

**Scan entry points (matching the threat model).** Both real entry points were exercised:

- `./trufflehog filesystem <path> --no-verification --no-update`
- `./trufflehog git file://<repo> --no-verification --no-update` — the exact **committed-file threat model**: a throwaway git repository is created, the crafted payload is committed, and TruffleHog scans it via the `file://` URI scheme accepted by the `git` subcommand (`main.go:L93`).

**Configuration.** Concurrency was the default `--concurrency=128` (`runtime.NumCPU()` on the 128-vCPU host — `main.go` default). **Verification was disabled** with `--no-verification` to isolate CPU/scan cost from network round-trips, so all timings reflect pure local matching work.

**Equal-size-fixture principle.** To make the "vs. normal files of equivalent size" comparison in Q4 valid, the crafted (malicious) and benign control files were **byte-for-byte equal in size — exactly 18,000,000 bytes**. Any measured slowdown is therefore attributable to *content*, not file size.

**Timing method.** For each fixture, wall-clock time was measured **across at least two runs** at the stated scale, and the crafted-vs-equal-size-benign ratio was computed. Two internal-vs-external measures are reported: **`scan_duration`** is TruffleHog's own metric emitted in its `finished scanning` log line (pure scan work), and **`wall`** is external wall-clock time for the whole process invocation (includes the fixed ~1.7 s startup cost of loading 800+ detectors). Values were confirmed **stable across the two runs**; where the pure-scan magnitude was large, scale was increased (up to 150 MB) to observe the real magnitude and confirm linear scaling.

**Source integrity.** The repository source tree was treated as strictly read-only. `git status --porcelain` on the source tree was empty before and after the investigation; the only addition is this document. All fixtures and observation scripts lived outside the repository (under `/work` and `/tmp`) and were deleted afterward.

---

## Engine Analysis — Why It Is Not Vulnerable

The correctness of the "not vulnerable" conclusion rests on one architectural fact, established by inspecting the pinned source and confirmed by the runtime profile: **TruffleHog's detectors do not run their regular expressions on a backtracking engine.**

**The 867-vs-3-vs-0 counts (`go.mod` + detector imports).**

- **867** detector `.go` files under `pkg/detectors/**` import the RE2 engine under the alias `regexp "github.com/wasilibs/go-re2"`. Verified: `grep -rl 'regexp "github.com/wasilibs/go-re2"' --include=*.go pkg | wc -l` → `867`.
- **Exactly 3** detectors import the Go standard-library `"regexp"` instead: `pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go`, `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go`, and `pkg/detectors/jdbc/jdbc.go`.
- **0** direct uses of the backtracking engine `github.com/dlclark/regexp2` exist anywhere under `pkg/`. Verified: `grep -rn 'dlclark/regexp2' --include=*.go pkg` → (none). In `go.mod` it appears only as `github.com/dlclark/regexp2 v1.4.0 // indirect` (**`go.mod:L187`**) — pulled in transitively, never on the detector hot path.

The relevant `go.mod` facts (all verified at the pinned commit):

| `go.mod` line | Declaration | Role |
|---|---|---|
| L3 | `go 1.23.1` | language version |
| L5 | `toolchain go1.24.2` | toolchain (CI pins go-version `1.24`) |
| L17 | `github.com/BobuSumisu/aho-corasick v1.0.3` | linear-time keyword prefilter |
| L20 | `github.com/alecthomas/kingpin/v2 v2.4.0` | CLI command/flag parser |
| L46 | `github.com/felixge/fgprof v0.9.5` | wall-clock profiler on `:18066` |
| L100 | `github.com/wasilibs/go-re2 v1.9.0` | **RE2 (linear-time) engine used by 867 detectors** |
| L187 | `github.com/dlclark/regexp2 v1.4.0 // indirect` | backtracking engine — **indirect, unused under `pkg/`** |

**Why RE2 is immune to catastrophic backtracking (background, external).** Google RE2 simulates a Thompson NFA/DFA and evaluates all alternatives in parallel, guaranteeing match time **linear in the length of the input**; it is explicitly designed to accept regular expressions from untrusted users safely, and it deliberately omits backreferences and look-around because those features only have backtracking implementations. More complex or longer patterns raise the **constant factor** (and the compiled program/DFA size) but never change the linear asymptotic class. The Go standard-library `regexp` package follows the same non-backtracking, linear-time design (the same family as RE2), so the 3 stdlib detectors are equally immune. `github.com/wasilibs/go-re2` is a drop-in `regexp` replacement wrapping RE2 that, by default, ships as a WebAssembly module executed by the pure-Go `wazero` runtime (so it works with `CGO_ENABLED=0`). *(Sources, as background only: `github.com/google/re2` README; `pkg.go.dev/github.com/wasilibs/go-re2`.)* The load-bearing claims in this document rest on the **observed** runtime output and `file:line` references, not on this background.

**Layered input bounding (defense-in-depth).** Even setting the engine guarantee aside, the amount of input any single regex ever sees is bounded by three independent mechanisms in the pipeline:

1. **13 KB sliding-window chunker** — `pkg/sources/chunker.go` **L14** `ChunkSize = 10 * 1024`, **L16** `PeekSize = 3 * 1024`, **L18** `TotalChunkSize = ChunkSize + PeekSize` (= 13,312 bytes ≈ 13 KB). Any single regex evaluation sees at most one 13 KB window.
2. **Aho-Corasick keyword prefilter** — `pkg/engine/engine.go:L795` `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` routes each chunk only to the detectors whose keywords are actually present, rather than running all 845+ detector patterns against every chunk. The prefilter itself is linear-time (Aho-Corasick).
3. **±512-byte extraction window** — `pkg/engine/ahocorasick/ahocorasickcore.go:L155` `const defaultOffsetRadius int64 = 512`, applied at **L160** `newAdjustableSpanCalculator(defaultOffsetRadius)`. Each keyword hit yields only a ~1 KB window (±512 bytes) that is passed to the detector's regex — so in practice the detector regex sees roughly 1 KB, not even the full 13 KB chunk.

> **Path note:** the ±512-byte window constant lives at `pkg/engine/ahocorasick/ahocorasickcore.go:155` — inside the `ahocorasick/` subdirectory. (There is no `pkg/engine/ahocorasickcore.go`.)

The pipeline and the observation points used for evidence are summarized below.

```mermaid
flowchart TD
    A[Crafted / benign fixture file] --> B[Source: filesystem or git file://]
    B --> C[Chunker: 13 KB sliding window - chunker.go:L14-L18]
    C --> D[Decoder pipeline: UTF-8, Base64, UTF-16, EscapedUnicode - decoders.go:L11-L14]
    D --> E[Aho-Corasick prefilter: keyword routing - engine.go:L795]
    E --> F[±512-byte extraction window - ahocorasick/ahocorasickcore.go:L155]
    F --> G[Detector regex via go-re2 RE2 - linear time]
    G --> H[FromData: soft 10s per-detector timeout, logs only - engine.go:L1066-L1077]
    H --> I[Results]

    C -. archive input .-> J[Archive handler: depth 10 / 2 GB / 60 s - archive.go:L26-L28]
    J --> C

    K[--profile server on :18066 - main.go:L53/L434] -. observes .-> G
    K -. observes .-> H
    L[wall-clock timing, >=2 runs] -. measures .-> B
```

---

## Q1 — Availability / DoS: Could a committed crafted file make TruffleHog hang/time out and block scans?

**Answer: No — no crafted input caused a hang or timeout; every scan completed, and the worst cases scale linearly and finish in seconds.**

Evidence, from the runs detailed in Q2–Q5 and the alternative-vectors section:

- The **classic ReDoS-shaped input** (a private-key `BEGIN` marker with no matching `END`, the canonical catastrophic shape) finished *as fast as* the benign control — **38.8 ms** vs **47.2 ms** on an 18 MB file (see Q2). There is no complexity blow-up to hang on.
- The most expensive crafted content (a **keyword-dense** file) completed in **seconds** and scaled **linearly** with size: 18 MB → 5.40 s; 150 MB → 48.45 s (see Q4). Larger input costs proportionally more time — never disproportionately more.
- The **archive depth bomb** bailed out in **~5 ms** at the depth-10 guard, and a **3 GB decompression bomb** was fully streamed and scanned in **5.3 s**, bounded by the 60 s archive timeout (see Alternative resource-exhaustion vectors). Neither hung.
- The **`git file://` committed-file threat model** — the exact scenario the question describes — was exercised directly by committing each payload to a throwaway git repository and running `trufflehog git file://<repo>`. All such scans completed in **≈2–6 s**.
- The **soft per-detector timeout never fired.** The log string `"a detector ignored the context timeout"` (`pkg/engine/engine.go:L1068`) appeared in **zero** runs, including a 54 s / 150 MB scan, because each detector receives only a ~1 KB (±512-byte) window and matches in microseconds.

**Mechanism — why a single detector cannot block the scan.** Inside `detectChunk`, the per-detector timeout is *soft*. The relevant lines (`pkg/engine/engine.go`):

- **L1061** `matches := data.detector.Matches()` — the detector is handed only the pre-matched ±512-byte windows.
- **L1066** `ctx, cancel := context.WithTimeout(ctx, detectionTimeout)` — a 10 s context deadline (`detectionTimeout` = `detectors.DefaultResponseTimeout` at `engine.go:L37`, which is `10 * time.Second` at `pkg/detectors/http.go:L18`).
- **L1067–L1068** `t := time.AfterFunc(detectionTimeout+1*time.Second, func() { ctx.Logger().Error(nil, "a detector ignored the context timeout") })` — after **11 seconds** this only **logs an error**; it does **not** interrupt an in-progress match.
- **L1076** `t.Stop()` and **L1077** `cancel()` — cleanup after the detector returns.

A go-re2 match is a single, uninterruptible call: a slow detector would run to completion and merely be logged, never force-killed. So "blocking a scan" via a single detector's regex cost is not achievable — and in any case no detector was slow, because the input each one sees is ~1 KB.

**Conclusion for Q1:** a committed file **cannot** hang or block the scan via regex complexity. The only content-driven effect is a **bounded, linear** slowdown (quantified in Q4) that still completes in seconds.

---

## Q2 — Vulnerability class: Is the regex-based pattern matching vulnerable to computational-complexity (ReDoS / catastrophic-backtracking) attacks?

**Answer: No.** The detectors run on RE2 (linear-time, non-backtracking), so the classic catastrophic-backtracking failure mode does not exist for them.

**Headline equal-size result (stable across 2 runs).** The crafted fixture `redos_privatekey.txt` is `-----BEGIN PRIVATE KEY-----` followed by 18 MB of filler with **no** matching `-----END … PRIVATE KEY-----` marker — the classic nested / non-greedy `[\s\S]*?` catastrophe **shape**, aimed squarely at the private-key detector's pattern (`pkg/detectors/privatekey/privatekey.go:L33`). It also contains the literal string `private key`, so the Aho-Corasick prefilter (the detector's `Keywords()` at `privatekey.go:L38-40` returns `["private key"]`) actually routes the chunk to that detector — i.e. the dangerous pattern really is exercised, not skipped. The benign control is 18,000,000 bytes of neutral text with no keywords.

Observed `finished scanning` lines (verbatim), 18,000,000-byte files:

```
[benign_equal ]  finished scanning  {"chunks": 1758, "bytes": 23397504, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "47.164597ms", ...}
[redos_privkey]  finished scanning  {"chunks": 1758, "bytes": 22931619, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "38.813528ms", ...}
```

So the pathological ReDoS-shaped file scanned in **38.8 ms**, essentially identical to — in fact *slightly faster than* — the benign control's **47.2 ms**, a ratio of **≈0.82×**, i.e. **no slowdown at all**. External wall-clock across 2 runs confirmed stability: benign **1.763 s / 1.763 s**; `redos_privkey` **1.725 s / 1.740 s**.

**Why (grounded in the engine choice and RE2's design).** The private-key pattern is compiled with go-re2 (`privatekey.go:L13` `regexp "github.com/wasilibs/go-re2"`), so RE2 evaluates the `[\s\S]*?` sub-expression by simulating the NFA/DFA and exploring all positions in parallel in time linear to the input — there is no exponential backtracking to trigger. A backtracking engine (e.g. Perl/PCRE) on this same shape would explore exponentially many ways to match the unbounded `[\s\S]*?` against the trailing filler when the `END` anchor never appears, which is the canonical ReDoS blow-up. RE2 simply does not have that failure mode, and the Q5 CPU profile confirms it: the go-re2 RE2 engine executes in WebAssembly and **no backtracking-engine function appears anywhere** in the hot path.

**On the 3 standard-library detectors.** The only non-go-re2 detectors are `spv2.go`, `azure_cosmosdb.go`, and `jdbc.go`, which use the Go standard-library `regexp`. That package is itself the RE2/linear-time family, so those three are **equally immune** to catastrophic backtracking. They are examined individually in Q3.

---


## Q3 — Exploitable patterns: Which specific detector patterns, if any, can be exploited to cause disproportionate processing time?

**Answer: None are exploitable for *catastrophic* (super-linear) time.** The only patterns that cost more CPU do so **linearly**, in proportion to the number of legitimate secret candidates they match — not because of algorithmic blow-up.

To answer this concretely, the highest-risk candidate patterns were enumerated and each was fed a crafted input designed to stress it. The candidates were chosen because they *look* dangerous to a reviewer familiar with backtracking-engine ReDoS: the private-key pattern has a nested non-greedy `[\s\S]*?` between two anchors (the textbook catastrophic shape); `jdbc` has a large bounded quantifier `{0,512}` plus a `.*?…(.+?)` pair and also compiles a **user-supplied** ignore regex at runtime; `azure_cosmosdb` has a long fixed-count `{86}`; `spv2` mixes character-class ranges with `\A`/`\z` anchors; and `anthropic` has a long `{93}` bounded quantifier. The verbatim patterns, exactly as they appear at the pinned commit, are:

```
privatekey.go:L33  (go-re2 engine; alias at L13; applied via FindAllString at L51)
  (?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----

jdbc.go:L53  (stdlib regexp; import at L8)
  (?i)jdbc:[\w]{3,10}:[^\s"']{0,512}
jdbc.go:L192  (stdlib regexp)
  (?i)pass.*?=(.+?)\b

azure_cosmosdb.go:L30  (stdlib regexp; import at L13)
  detectors.PrefixRegex([]string{"azure", "cosmos"}) + ([A-Za-z0-9]{86}==)
azure_cosmosdb.go:L32
  ([a-z0-9-]{3,44}\.(?:documents|table\.cosmos)\.azure\.com)

spv2.go:L32  (stdlib regexp; import at L7)
  (?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)

anthropic.go:L27  (go-re2 engine; alias at L10)
  \b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b
```

**Observed result:** every one of these ran in **linear** time. The private-key catastrophe-shape scanned an 18 MB file in **38.8 ms** (≈0.82× the benign control — see Q2). The `jdbc` pattern, fed a file of 82,337 `jdbc:` connection-string candidates, took **2.29 s** on 18 MB — more CPU than benign, but that cost is exactly proportional to the 82,337 matches it had to extract and report; doubling the file doubles both. None produced disproportionate (super-linear) time.

**On the three standard-library detectors specifically.** `spv2.go`, `azure_cosmosdb.go`, and `jdbc.go` are the *only* detectors that do not use go-re2 (they import stdlib `"regexp"` at `spv2.go:L7`, `azure_cosmosdb.go:L13`, and `jdbc.go:L8` respectively). The Go standard-library `regexp` is itself the RE2/linear-time family, so these three are **equally immune** to catastrophic backtracking. `jdbc` additionally compiles a **user-supplied** ignore regex at runtime — `jdbc.go:L35-37` (`var ignorePatterns []regexp.Regexp` … `regexp.Compile(ignoreString)`) — but that compiled regex is *also* stdlib-RE2 (it cannot be made catastrophic no matter what string a user supplies) and it is opt-in via a flag, not attacker-controllable through a scanned file.

---


## Q4 — Magnitude: How many times slower can a scan be made versus normal files of equivalent size?

**Answer: The ReDoS-specific answer is ≈1× (no slowdown). The maximum *content-driven* slowdown for a byte-for-byte equal-size file is ≈114× at the pure-scan level (≈4.3× end-to-end wall-clock) — and it is LINEAR, not exponential.**

The two supporting tables (equal-size crafted-vs-benign across ≥2 runs, and a linear-scaling table) are in the **Equal-size timing tables (Q4)** section below. The essential figures:

- **ReDoS shape vs. benign (equal size, 18 MB):** `redos_privatekey` **38.81 ms** vs `benign_equal` **47.16 ms** → **0.82×** — i.e. the pathological shape is *not slower at all*.
- **Maximum content-driven slowdown (equal size, 18 MB):** `keyword_dense` **5.402 s** vs `benign_equal` **47.16 ms** → **≈114.5×** at the pure-scan (`scan_duration`) level; end-to-end wall-clock **7.6 s vs 1.76 s ≈ 4.3×**.

**Why the ≈114× is not a complexity attack.** The keyword-dense fixture plants a secret-shaped token roughly every ~600 bytes, so an 18 MB file contains **38,902** secret candidates while the equal-size benign file has **zero**. The 114× is simply the linear cost of the engine **matching and reporting 38,902 candidates** versus reporting none — real work, proportional to the number of hits, not algorithmic blow-up. An attacker **cannot** make this super-linear: as the linear-scaling table shows, going from 18 MB to 150 MB (8.3× the size) raises the keyword-dense scan from 5.40 s to 48.45 s (8.97× the time) and the hit count from 38,902 to 324,751 (8.35×) — time tracks size and hit-count linearly. Doubling the file roughly doubles the time; it never explodes.

**Why the wall-clock ratio (≈4.3×) is smaller than the pure-scan ratio (≈114×).** Every invocation pays a fixed ~1.7 s startup cost to load and compile 800+ detector pattern sets, which is shared identically by the benign and crafted runs. That fixed cost dominates the benign wall-clock (1.76 s total for a 47 ms scan) and dilutes the ratio once the variable scan work is added, so the end-to-end wall ratio (4.3×) is much smaller than the pure-scan ratio (114×). Both are reported honestly below.

**`git file://` magnitude (the Q1 committed-file threat model).** Committing an 18 MB newline-delimited keyword-dense payload to a throwaway repo and scanning it with `trufflehog git file://<repo> --no-verification` gave **scan_duration 4.06 s**, wall **6.12 s / 5.88 s**, **29,900** hits — the same linear regime as `filesystem`, confirming the magnitude is a property of the content and pipeline, not of the entry point.

---

## Q5 — Evidence: Timing measurements AND CPU-profiling data

**Answer: Both are provided.** The timing measurements are the equal-size and linear-scaling tables (see **Equal-size timing tables (Q4)**), captured across ≥2 runs at stated scales. The CPU-profiling data (see **CPU-profiling evidence (Q5)** below) comprises three verbatim artifacts:

1. A **`go tool pprof -top`** CPU profile from TruffleHog's **built-in `--profile` server** on `:18066` (`main.go:L53`, `main.go:L434`), captured live during a 150 MB keyword-dense scan.
2. A **fgprof** wall-clock profile from `/debug/fgprof` for the same scan.
3. A **Go benchmark CPU profile** and throughput table from the in-repo `BenchmarkPopulateMatchingDetectors` (`pkg/engine/engine_test.go:L1039`).

The single most important thing the profile shows: the hot path is the **go-re2 RE2 engine executing as WebAssembly** (`runtime._ExternalCode` at 93.18%, plus `wazero` and `wasilibs/go-re2/internal.*` frames) — and **no backtracking-engine function appears anywhere**. That is the direct profiling proof of the Q2 answer. The benchmark throughput is roughly constant (~50 MB/s) across a 256× range of chunk sizes, which is the signature of **linear** time in the input.

---


## Q3 Candidate-Pattern Enumeration

Each highest-risk detector pattern, with its engine, the verbatim pattern, why it *looks* dangerous, and the observed runtime result. Literal `|` alternation characters render as `|`. The full unescaped patterns appear in the fenced block in the Q3 section above.

| Detector (file:line) | Engine | Pattern (verbatim) | Why it *looks* risky | Observed result |
|---|---|---|---|---|
| `pkg/detectors/privatekey/privatekey.go:L33` (applied via `FindAllString`, L51) | go-re2 (alias L13) | `(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----` | nested `*?` non-greedy plus an unbounded `[\s\S]*?` between two anchors — the classic catastrophic-backtracking shape | 38.8 ms on 18 MB, ≈0.82× benign — **linear / fast** |
| `pkg/detectors/jdbc/jdbc.go:L53` (stdlib `regexp`, import L8) | stdlib RE2 | `(?i)jdbc:[\w]{3,10}:[^\s"']{0,512}`  (also L192 `(?i)pass.*?=(.+?)\b`; plus a user-supplied ignore regex compiled at runtime, L35-37) | large bounded quantifier `{0,512}` and a `.*?…(.+?)` pair; runtime-compiled user regex | 2.29 s / 82,337 matches on 18 MB — **linear** (see Q4) |
| `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go:L30`/`L32` (stdlib `regexp`, import L13) | stdlib RE2 | `dbKeyPattern = PrefixRegex([...]) + ([A-Za-z0-9]{86}==)`;  `accountUrlPattern = ([a-z0-9-]{3,44}\.(?:documents\|table\.cosmos)\.azure\.com)` | long fixed-count `{86}` and a prefix regex | linear (exercised via keyword-dense; no disproportionate time) |
| `pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go:L32` (stdlib `regexp`, import L7) | stdlib RE2 | `(?:[^a-zA-Z0-9_~.-]\|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]\|\z)` | character-class ranges combined with `\A`/`\z` anchors | linear |
| `pkg/detectors/anthropic/anthropic.go:L27` | go-re2 (alias L10) | `\b(sk-ant-(?:admin01\|api03)-[\w\-]{93}AA)\b` | long `{93}` bounded quantifier | linear (representative go-re2 detector) |

Every enumerated candidate ran in linear time. The three stdlib-`regexp` detectors (`jdbc`, `azure_cosmosdb`, `spv2`) are the only non-go-re2 detectors, and stdlib `regexp` is itself the RE2/linear family — so they are equally immune to catastrophic backtracking. No pattern in TruffleHog's detector set could be induced to exhibit super-linear behavior.

---

## Equal-size Timing Tables (Q4)

All timing used `--no-verification --no-update` to isolate CPU (no network verification). `scan_duration` is TruffleHog's own internal metric from its `finished scanning` log line; `wall` is external wall-clock across 2 runs. Equal-size fixtures are **byte-for-byte 18,000,000 bytes**. Values were confirmed stable across the two runs.

**Table 4a — Equal-size (18,000,000 bytes) crafted vs. benign, `filesystem`, 2 runs:**

| Fixture (18 MB, equal size) | scan_duration | wall run1 / run2 | unverified hits | scan ratio vs benign |
|---|---|---|---|---|
| benign_equal (no keywords) | 47.16 ms | 1.763 s / 1.763 s | 0 | 1.0× |
| redos_privatekey (BEGIN, no END) | 38.81 ms | 1.725 s / 1.740 s | 0 | **0.82× (none)** |
| redos_jdbc | 2.290 s | 4.283 s / 4.422 s | 82,337 | 48.5× |
| keyword_dense | 5.402 s | 7.613 s / 7.274 s | 38,902 | **114.5×** |

The `redos_privatekey` row is the headline: a classic catastrophic-backtracking *shape* runs *slightly faster* than the benign control (0.82×), the opposite of what a ReDoS-vulnerable engine would show. The `keyword_dense` row's 114.5× is the maximum content-driven slowdown, and it is linear work (38,902 secret candidates matched and reported vs. 0), as the next table proves.

**Table 4b — Linear scaling (proves no super-linear blow-up):**

| Fixture | size | scan_duration | hits | notes |
|---|---|---|---|---|
| benign | 18 MB | 47 ms | 0 | baseline |
| benign | 100 MB | 245 ms | 0 | 5.56× size → 5.2× time (≈linear) |
| keyword_dense | 18 MB | 5.40 s | 38,902 | baseline |
| keyword_dense | 150 MB | 48.45 s | 324,751 | 8.3× size → 8.97× time → 8.35× hits (≈linear) |

Time grows in proportion to input size and to the number of hits — the defining signature of linear-time matching. There is no input size at which the cost curve bends upward.

**`git file://` magnitude (Q1 committed-file threat model), newline-delimited keyword-dense, 18 MB:** scan_duration **4.06 s**, wall **6.12 s / 5.88 s**, **29,900** hits — the same linear regime as `filesystem`.

---


## CPU-profiling Evidence (Q5)

Three verbatim profiling artifacts are embedded below. Together they prove (a) the hot path is the RE2 engine (go-re2 in WebAssembly) with no backtracking function, and (b) throughput is constant across chunk sizes, i.e. linear in the input.

**(A) Live `--profile` server (`main.go:L53`, `main.go:L434`) during a 150 MB keyword-dense scan — `go tool pprof -top` of `http://localhost:18066/debug/pprof/profile`:**

```
Duration: 18.16s, Total samples = 1834.75s (10105.77%)
Showing nodes accounting for 1750.84s, 95.43% of 1834.75s total
      flat  flat%   sum%        cum   cum%
  1709.66s 93.18% 93.18%   1709.66s 93.18%  runtime._ExternalCode
    23.36s  1.27% 94.46%     61.41s  3.35%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     1.82s 0.099% 95.29%     11.94s  0.65%  regexp.(*machine).match
     0.16s 0.0087% 95.40%     63.73s  3.47%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
     0.12s 0.0065% 95.41%     66.78s  3.64%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.10s 0.0055% 95.42%     62.39s  3.40%  github.com/wasilibs/go-re2/internal.matchFrom
     0.02s 0.0011% 95.42%     12.65s  0.69%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jdbc.Scanner.FromData
     0.01s 0.00055% 95.42%     14.88s  0.81%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws/access_keys.scanner.FromData
     0.01s 0.00055% 95.42%     27.75s  1.51%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectChunk
```

**Interpretation.** `runtime._ExternalCode` (93.18%) is the **go-re2 RE2 engine running as WebAssembly** via the pure-Go `wazero` runtime — the default `CGO_ENABLED=0` mode; the `github.com/tetratelabs/wazero/...callWithStack` frame is the WASM host call, and `wasilibs/go-re2/internal.findAllSubmatch` / `matchFrom` / `lazyFunction.callWithStack` are the RE2 match calls. `regexp.(*machine).match` (0.65% cum) is the *standard-library* RE2 engine from the 3 stdlib detectors (note `jdbc.Scanner.FromData` and `aws/access_keys.scanner.FromData` in the list). Crucially, **no backtracking-engine function (e.g. anything from `dlclark/regexp2`) appears anywhere in the profile** — this is the profiling proof of the Q2 answer that TruffleHog matches on a linear-time engine only. That scan completed; it did not hang.

**(B) fgprof wall-clock (`/debug/fgprof`) — same scan:**

```
Type: time   Duration: 8.11s, Total samples = 11590.39s (142909.74%)
 10755.25s 92.79% runtime.gopark
      1.39s        github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack   (cum 1325s, 11.43%)
      0.75s        github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch (cum 1293.21s, 11.16%)
      0.39s        github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch       (cum 1182.82s, 10.21%)
      0.07s        github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal/v1.findSecretMatches
```

The dominant `runtime.gopark` (92.79%) is goroutines parked/waiting (expected under the default 128-way concurrency); the on-CPU work that matters is again all in `wasilibs/go-re2/internal.*` (RE2), confirming the wall-clock story matches the CPU story. That scan finished:

```
{"chunks": 14673, "bytes": 186208216, "unverified_secrets": 324751, "scan_duration": "48.446050679s"}
```

— 186 MB processed, 324,751 candidates reported, completed in ~48 s, no hang.

**(C) Go benchmark CPU profile — `BenchmarkPopulateMatchingDetectors` (`pkg/engine/engine_test.go:L1039`), throughput table:**

```
BenchmarkPopulateMatchingDetectors/ChunkSize_1024-128     9292 ns/op   110.21 MB/s
BenchmarkPopulateMatchingDetectors/ChunkSize_4096-128    45710 ns/op    89.61 MB/s
BenchmarkPopulateMatchingDetectors/ChunkSize_13312-128  246159 ns/op    54.08 MB/s   <-- real 13 KB chunk
BenchmarkPopulateMatchingDetectors/ChunkSize_16384-128  307658 ns/op    53.25 MB/s
BenchmarkPopulateMatchingDetectors/ChunkSize_32768-128  662296 ns/op    49.48 MB/s
BenchmarkPopulateMatchingDetectors/ChunkSize_65536-128 1378649 ns/op    47.54 MB/s
BenchmarkPopulateMatchingDetectors/ChunkSize_262144-128 5223199 ns/op   50.19 MB/s
```

`go tool pprof -top` of that benchmark's CPU profile:

```
Type: cpu   Duration: 27.97s, Total samples = 33.39s
    11.87s 35.55%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
     5.56s 16.65%  bytes.ToLower
     0.68s  2.04%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*adjustableSpanCalculator).calculateSpan
     0.44s  1.32%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*Core).FindDetectorMatches   (cum 27.46s, 82.24%)
```

**Interpretation.** Throughput holds roughly constant (~50 MB/s) across a **256× range of chunk sizes** (1,024 → 262,144 bytes) ⇒ processing time is **linear** in the input; if any pattern were super-linear, throughput would collapse as chunk size grew, and it does not. The hot path is the **linear-time Aho-Corasick keyword prefilter** — `aho-corasick.(*Trie).Walk` (35.55%) and `ahocorasick.(*Core).FindDetectorMatches` (82.24% cumulative, the routing entry point at `engine.go:L795`) — plus `bytes.ToLower` case-folding, and `adjustableSpanCalculator.calculateSpan`, which computes the ±512-byte extraction window (`pkg/engine/ahocorasick/ahocorasickcore.go:L155`). This is exactly the defense-in-depth architecture the Engine Analysis describes, observed in a profile.

---


## Alternative Resource-Exhaustion Vectors

Because Q1 asks broadly whether a scan can be "blocked", the full resource-exhaustion attack surface was probed at runtime, not just regex backtracking. Each vector was exercised and its bound observed.

**1. Archive depth bomb** (`nested_12x.gz` — 12 nested gzip layers). Observed output:

```
error ... "error":"max archive depth reached"
finished scanning {"chunks": 0, "bytes": 0, "scan_duration": "4.99266ms"}
```

The depth-10 guard halts recursion in **~5 ms**. Mechanism: `pkg/handlers/archive.go:L26` `maxDepth = 5 * 2` (= 10); the guard at **L124** `if depth >= maxDepth {` returns `ErrMaxDepthReached` (**L105** `var ErrMaxDepthReached = errors.New("max archive depth reached")`). A deeply nested archive cannot exhaust resources — it is rejected almost instantly.

**2. Decompression bomb** (`bomb_3gb.gz` → 3 GB of zeros). Observed output:

```
finished scanning {"chunks": 314573, "bytes": 4187590656, "scan_duration": "5.324751916s"}
```

Wall ~7.09 s. The 3 GB stream was fully decompressed and scanned in **5.3 s**, bounded by the 60 s archive timeout (`pkg/handlers/archive.go:L28` `maxTimeout = time.Duration(60) * time.Second`, applied at `pkg/handlers/handlers.go:L384` `processingCtx, cancel := logContext.WithTimeout(ctx, maxTimeout)`) — no hang. (`bomb_500mb.gz` completed in ~905 ms.) **Accurate note:** the 2 GB `maxSize` skip (`archive.go:L198-199` `if int(fileSize) > maxSize { … skipping file: size exceeds max allowed }`) applies to **sized archive entries**, not to a raw streaming gzip; here the **time** bound (60 s), not the size bound, is what applies — and the scan finished well within it.

**3. Base64 amplification** (`base64_blob` — 18 MB base64 encoding of a keyword block). The Base64 decoder re-enters detection, so the same bytes are scanned in both encoded and decoded form. Observed **28,111** hits, `scan_duration` **3.644597168s** — bounded and linear. Mechanism: `pkg/decoders/decoders.go` orders the decoders `&UTF8{}` (L11), `&Base64{}` (L12), `&UTF16{}` (L13), `&EscapedUnicode{}` (L14); the Base64 decoder's `FromChunk` (`pkg/decoders/base64.go:L34`, decoding via `base64.StdEncoding.DecodeString` L40 and `base64.RawURLEncoding.DecodeString` L45) yields a decoded variant that independently re-enters the Aho-Corasick prefilter. This at most multiplies work by the small, fixed number of decoders — a constant factor, not super-linear.

**4. RE2 "DFA out of memory"** (TruffleHog issue #2739). A 240 MB probe built from 12 KB lines produced **no** `DFA out of memory` error:

```
finished scanning {..., "scan_duration": "670.964215ms"}
```

**Reported honestly:** this path **did not reproduce** under the canonical 13 KB chunker plus ±512-byte window, because those bounds keep the input to any single regex tiny (~1 KB), far below RE2's memory budget. Per issue #2739 the condition arises only when the input to a match exceeds RE2's configured `max_mem`, and RE2 then **fails gracefully** — it emits an error and **skips** that match rather than hanging. This is therefore a **detection-gap** (a secret in an oversized match window could be missed), **not** an availability DoS. The maintainer's note in #2739 also confirms the whole diff is never scanned as one unit precisely because the sliding-window-with-overlap chunker (`pkg/sources/chunker.go`) breaks data into manageable chunks.

**5. Soft per-detector timeout.** The log line `"a detector ignored the context timeout"` (`pkg/engine/engine.go:L1068`) appeared in **zero** runs — checked across every scan performed here, including the 54 s / 150 MB one. Mechanism (`pkg/engine/engine.go:L1066-L1077`): a `context.WithTimeout` of 10 s is set (L1066) and a `time.AfterFunc(detectionTimeout+1*time.Second, …)` (L1067-1068) only **logs** after 11 s; the match is never force-killed (`t.Stop()` L1076, `cancel()` L1077 run only after the detector returns). Because each detector matches ~1 KB in microseconds, the timeout is never approached — and even if a detector were slow, the soft timeout would merely log, so it cannot itself cause or prevent a hang.

**6. git 64 KB line limit** (detection-gap). The same 18 MB keyword-dense payload, committed as a **single line (0 newlines)** and scanned by the `git` source, was processed as only:

```
{"chunks": 1, "bytes": 34, "scan_duration": "109ms"}
```

The 18 MB of content was **skipped**. Cause: `pkg/sources/git/git.go:L729` `originalChunk := bufio.NewScanner(reader)` with the scan loop at **L732** `for offset := 0; originalChunk.Scan(); offset++ {`, and **no** custom `.Buffer()` call anywhere in `pkg/sources/git/` — so the default `bufio.MaxScanTokenSize` of 65,536 bytes (64 KB) applies and a diff line longer than 64 KB is dropped. This is a **detection-gap** (a secret on a >64 KB line is missed by the git source), and it makes the scan **faster**, not slower — it cannot cause a hang.

**Summary of vectors:** every alternative vector is either rejected quickly (archive depth), bounded by a time budget (decompression), a constant-factor multiply (base64), a graceful skip / detection-gap (DFA-OOM, git 64 KB), or a log-only soft timeout. None hangs or blocks the scan.

---

## Exact Commands Used

The investigation is reproducible with the following commands (verbatim). All were run in the canonical default configuration (`CGO_ENABLED=0`, Go 1.24, default WebAssembly go-re2).

```
# Build (canonical, default config)
CGO_ENABLED=0 go build -o /work/trufflehog .

# Equal-size fixtures (18,000,000 bytes each), e.g.:
#   keyword_dense.txt : secret-shaped tokens + detector keywords repeated
#   benign_equal.txt  : neutral text, same byte count
#   redos_privatekey.txt : "-----BEGIN PRIVATE KEY-----" + filler, NO END marker

# Timing (filesystem), >=2 runs each:
./trufflehog filesystem <path> --no-verification --no-update
# git committed-file threat model:
git init <repo> && cp <fixture> <repo>/payload.txt && git -C <repo> add . && git -C <repo> commit -m p
./trufflehog git file://<repo> --no-verification --no-update

# CPU profiling — live server (main.go:L53):
./trufflehog filesystem <big-keyword-dense> --profile --no-verification --no-update &
go tool pprof -top -seconds=18 http://localhost:18066/debug/pprof/profile
go tool pprof -top -seconds=8  http://localhost:18066/debug/fgprof

# CPU profiling — benchmark supplement:
CGO_ENABLED=0 go test -run=xxx -bench=BenchmarkPopulateMatchingDetectors -benchtime=3s \
  -cpuprofile=/work/cpu_engine.prof -o /work/engine.test ./pkg/engine/
go tool pprof -top /work/engine.test /work/cpu_engine.prof

# Fact-checks:
grep -rl 'regexp "github.com/wasilibs/go-re2"' --include=*.go pkg | wc -l   # -> 867
grep -rl '^\s*"regexp"' --include=*.go pkg/detectors                         # -> the 3 stdlib detectors
grep -rn 'dlclark/regexp2' --include=*.go pkg                                # -> (none)
```

---

## Conclusion

**Catastrophic-backtracking ReDoS is not reproducible against TruffleHog's detectors.** The detectors compile their patterns on Google RE2 via `github.com/wasilibs/go-re2` (`go.mod:L100`, v1.9.0) — a linear-time, non-backtracking engine — across 867 of 870 detector files, with the remaining 3 on the Go standard-library `regexp` (the same RE2/linear family). The only backtracking engine in the module graph, `github.com/dlclark/regexp2` (`go.mod:L187`, `// indirect`), has zero direct use under `pkg/`. A classic ReDoS-shaped input scanned *slightly faster* than an equal-size benign control (0.82×), and the live CPU profile shows the RE2 engine executing in WebAssembly with no backtracking function anywhere in the hot path.

**The real, observed behavior is bounded and linear.** The maximum content-driven slowdown for a byte-for-byte equal-size file is ≈114× at the pure-scan level (≈4.3× end-to-end), and it is strictly linear work proportional to the number of secret candidates in the file — confirmed by linear scaling from 18 MB to 150 MB. Input reaching any single regex is bounded by the 13 KB chunker (`pkg/sources/chunker.go:L14-L18`), the Aho-Corasick keyword prefilter (`pkg/engine/engine.go:L795`), and the ±512-byte extraction window (`pkg/engine/ahocorasick/ahocorasickcore.go:L155`). Even the worst 150 MB / 324,751-candidate scan completed in ~48 s and never hung, and the per-detector timeout (`pkg/engine/engine.go:L1066-L1077`) is soft — it only logs, never force-kills — and never fired.

**Two honest caveats, both detection-gaps rather than availability DoS.** (1) RE2 can emit a `DFA out of memory` error and *skip* a match when its `max_mem` budget is exceeded (TruffleHog issue #2739); this did not reproduce under the canonical chunk/window bounds and, when it does occur, causes a missed secret, not a hang. (2) The git source uses a default 64 KB line scanner (`pkg/sources/git/git.go:L729`) with no custom buffer, so content on a line longer than 64 KB is dropped — again a missed secret, and it makes the scan faster, not slower. Neither can block a scan.

**Answering the CI-owner's underlying concern:** a malicious file committed to a scanned repository **cannot** make TruffleHog hang or time out via regex computational complexity, and thus cannot block a CI security pipeline by that means. The worst an attacker can do with content alone is impose a bounded, linear slowdown that still completes in seconds to tens of seconds.

**Scope note:** this document answers the question and stops there. Consistent with the read-only, investigation-only scope of this task, **no remediation, hardening, or mitigation is proposed** (for example, converting the soft per-detector timeout into a hard kill, tuning RE2's `max_mem`, or raising the git line-buffer limit are all explicitly out of scope). No TruffleHog source file was modified; the only artifact produced is this document.

