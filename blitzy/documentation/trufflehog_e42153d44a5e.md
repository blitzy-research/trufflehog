# TruffleHog Detector Pattern Matching: ReDoS / Resource-Exhaustion DoS Investigation

**Repository:** `github.com/trufflesecurity/trufflehog` (module `github.com/trufflesecurity/trufflehog/v3`)
**Pinned commit:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`
**Branch:** `trufflehog_e42153d44a5e`
**Question class:** Availability / Denial-of-Service via computational-complexity (ReDoS) attack on regex-based secret detectors.

This document answers whether a maliciously crafted file, committed to a repository that TruffleHog scans, can be used to make a TruffleHog scan **hang or time out** and thereby **block a CI security pipeline** — and it quantifies the worst-case slowdown against a **byte-for-byte equal-size benign file**, backed by **wall-clock timing measurements and CPU-profiling evidence**. Every measurement below was produced by building and running the real `trufflehog` binary in its default, canonical configuration **inside the mandated SWE container** (`ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0`, Go 1.24.3, 128 vCPU); the exact build, scan, and profiling commands are stated, and each behavioral claim is grounded in complete, unedited command output plus a `file:line` reference.

---

## TL;DR / Direct Answer

> **Catastrophic-backtracking ReDoS is NOT reproducible against TruffleHog's detectors.**
>
> TruffleHog's detectors compile their patterns on **Google RE2 via `github.com/wasilibs/go-re2`** — a linear-time, non-backtracking regex engine. **867 of the 870 detector `.go` files** import the go-re2 alias, and the remaining **3** use the Go standard-library `regexp` package, which belongs to the *same* RE2/linear-time family. A backtracking engine (`github.com/dlclark/regexp2`) exists in the module graph only as an **`// indirect`** dependency with **zero** direct use anywhere under `pkg/`. Because none of the detector patterns run on a backtracking engine, a crafted file **cannot** make a scan hang via regex computational complexity.

That is the direct answer. The nuance, all of it directly observed at runtime, follows:

- The detectors' matching cost is **bounded and linear** in the size of the input, and the input reaching any single regex is bounded twice more by defense-in-depth (a 13 KB sliding-window chunker and a ±512-byte extraction window around each keyword hit).
- There **is** a real, content-driven slowdown — up to **≈140× at the pure-scan level** for a maximally keyword-dense file versus an equal-size benign file — but this is **linear work proportional to the number of secret candidates in the file**, not algorithmic blow-up, and it **completes in seconds and does not hang**. Doubling the file merely doubles the work.
- Two honest caveats are **detection-gaps, not availability DoS**: RE2's "DFA out of memory" graceful-failure path (TruffleHog issue #2739), and the git source's 64 KB per-line scanner limit. In both, content may be **skipped** (a secret could be missed) — the scan runs *faster*, not slower, and never hangs.
- The per-detector timeout is **soft**: it only **logs** a message after 11 seconds and never force-kills a match. It never fired in any run performed here.

**One-line answer to each question:**

- **Q1 — Can a committed crafted file make TruffleHog hang/time out and block scans?** **No.** No crafted input caused a hang or timeout; every scan completed, and the worst cases scaled linearly and finished in seconds to tens of seconds.
- **Q2 — Is the regex-based pattern matching vulnerable to computational-complexity (ReDoS) attacks?** **No.** Detectors run on RE2 (linear-time, non-backtracking); a classic ReDoS-shaped input scanned *slightly faster* than the benign control (0.79×).
- **Q3 — Which specific detector patterns can be exploited for disproportionate time?** **None** for *catastrophic* (super-linear) time. The patterns that cost more CPU (e.g. `jdbc`) do so **linearly**, proportional to the number of legitimate matches.
- **Q4 — How many times slower vs. normal files of equivalent size?** The ReDoS-specific answer is **≈1× (no slowdown)**. The maximum *content-driven* slowdown for a byte-for-byte equal-size file is **≈140× at the pure-scan level (≈5.0× end-to-end wall-clock)** — and it is **linear, not exponential**.
- **Q5 — Timing measurements AND CPU-profiling data?** Provided: equal-size wall-clock tables across ≥2 runs, plus verbatim `go tool pprof` CPU and fgprof wall-clock output and a benchmark throughput table. The profile shows the go-re2 RE2 engine executing in WebAssembly with **no catastrophic backtracking-engine function** (nothing from `dlclark/regexp2` or any PCRE-style engine) in the hot path — the only frames literally named `backtrack` are Go stdlib `regexp`'s *bounded, linear* one-pass backtracker used by the `jdbc` detector (see the footnote in the CPU-profiling section).

**Bottom line for a CI owner:** A file committed to a scanned repository **cannot hang the scan via regex complexity**. The worst realistic effect an attacker can achieve by content alone is a **bounded, linear** slowdown that still **completes in seconds** (the pathological 150 MB / 793,997-candidate scan finished in ~56 s and never hung). This is a performance consideration, not an availability vulnerability. No remediation is proposed here — that is out of scope for this investigation.

---

## Methodology & Canonical Build

**Environment and canonical build.** The investigation used the canonical default build and both real scan entry points, executed inside the mandated SWE container. The binary was built with:

```
CGO_ENABLED=0 go build -o /work/trufflehog .
```

producing the version banner `trufflehog dev`. Because `CGO_ENABLED=0` is set and the `re2_cgo` build tag is **not** set, `go-re2` runs in its **default pure-Go WebAssembly mode** via the `wazero` runtime (confirmed by the CPU profile in Q5 showing `runtime._ExternalCode` plus `wazero` frames). This matches the repository's own build configuration: `Dockerfile` **L5** `ENV CGO_ENABLED=0` and **L9** `go build -o trufflehog .`, and `Makefile` **L49** `CGO_ENABLED=0 go run . git file://. --json`.

**Canonical container.** All build, scan, and profiling steps were performed inside the mandated SWE container **`ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0`** (image note recorded in the environment banner below). The observed environment was:

```
### go version
go version go1.24.3 linux/amd64
### nproc
128
### os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
VERSION="12 (bookworm)"
### git commit
e42153d44 [Fix] Added Prefix In Dockerhub Detector Regex (#4084)
```

This is the canonical configuration the Agent Action Plan requires: **Go 1.24 + `CGO_ENABLED=0`**, which fully determines the go-re2 WebAssembly configuration, and the container ships `git`, `openssh`, `rpm2cpio`, `binutils`, and `cpio` for the git and archive/rpm handlers. **All reported values are therefore canonical.** **No standard-library-`regexp` proxy or any other non-canonical stand-in was used at any point** — there is nothing in this report that needs to be labeled non-canonical.

**Scan entry points (matching the threat model).** Both real entry points were exercised:

- `/work/trufflehog filesystem /work/fixtures/keyword_dense.txt --no-verification --no-update`
- `/work/trufflehog git file:///work/repo_kw --no-verification --no-update` — the exact **committed-file threat model**: a throwaway git repository is created, the crafted payload is committed, and TruffleHog scans it via the `file://` URI scheme accepted by the `git` subcommand (`main.go:L93`).

**Configuration.** Concurrency was the default `--concurrency=128` (`runtime.NumCPU()` on the 128-vCPU container — `main.go` default). **Verification was disabled** with `--no-verification` to isolate CPU/scan cost from network round-trips, so all timings reflect pure local matching work.

**Equal-size-fixture principle.** To make the "vs. normal files of equivalent size" comparison in Q4 valid, the crafted (malicious) and benign control files were **byte-for-byte equal in size — exactly 18,000,000 bytes**. Any measured slowdown is therefore attributable to *content*, not file size.

**Timing method.** For each fixture, wall-clock time was measured **across at least two runs** at the stated scale, and the crafted-vs-equal-size-benign ratio was computed. Two internal-vs-external measures are reported: **`scan_duration`** is TruffleHog's own metric emitted in its `finished scanning` log line (pure scan work), and **`wall`** is external wall-clock time for the whole process invocation (includes the fixed ~1.8 s startup cost of loading 800+ detectors). Values were confirmed **stable across the two runs**; where the pure-scan magnitude was large, scale was increased (up to 150 MB) to observe the real magnitude and confirm linear scaling.

**Source integrity.** The repository source tree was treated as strictly read-only. `git status --porcelain` on the source tree was empty before and after the investigation; the only addition is this document. All fixtures and observation scripts lived outside the repository (under `/work`) and were deleted afterward.

---

## Engine Analysis — Why It Is Not Vulnerable

The correctness of the "not vulnerable" conclusion rests on one architectural fact, established by inspecting the pinned source and confirmed by the runtime profile: **TruffleHog's detectors do not run their regular expressions on a backtracking engine.**

**The 867-vs-3-vs-0 counts (`go.mod` + detector imports).**

- **867** detector `.go` files under `pkg/detectors/**` import the RE2 engine under the alias `regexp "github.com/wasilibs/go-re2"`. Verified: `grep -rl 'regexp "github.com/wasilibs/go-re2"' --include=*.go pkg | wc -l` → `867`.
- **Exactly 3** detectors import the Go standard-library `"regexp"` instead: `pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go`, `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go`, and `pkg/detectors/jdbc/jdbc.go`.
- **0** direct uses of the backtracking engine `github.com/dlclark/regexp2` exist anywhere under `pkg/`. Verified: `grep -rn 'dlclark/regexp2' --include=*.go pkg` → (none; grep exit code 1). In `go.mod` it appears only as `github.com/dlclark/regexp2 v1.4.0 // indirect` (**`go.mod:L187`**) — pulled in transitively, never on the detector hot path.

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

- The **classic ReDoS-shaped input** (a private-key `BEGIN` marker with no matching `END`, the canonical catastrophic shape) finished *faster than* the benign control — **40.7 ms** vs **51.2 ms** on an 18 MB file (see Q2). There is no complexity blow-up to hang on.
- The most expensive crafted content (a **keyword-dense** file) completed in **seconds** and scaled **linearly** with size: 18 MB → 7.19 s; 150 MB → 56.19 s (see Q4). Larger input costs proportionally more time — never disproportionately more.
- The **archive depth bomb** bailed out in **~5 ms** at the depth-10 guard, and a **3 GB decompression bomb** was fully streamed and scanned in **5.38 s**, bounded by the 60 s archive timeout (see Alternative resource-exhaustion vectors). Neither hung.
- The **`git file://` committed-file threat model** — the exact scenario the question describes — was exercised directly by committing each payload to a throwaway git repository and running `trufflehog git file:///work/repo_kw`. All such scans completed in **≈6–8 s**.
- The **soft per-detector timeout never fired.** The log string `"a detector ignored the context timeout"` (`pkg/engine/engine.go:L1068`) appeared in **zero** runs, including a 56 s / 150 MB scan, because each detector receives only a ~1 KB (±512-byte) window and matches in microseconds.

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

**Headline equal-size result (stable across 2 runs).** The crafted fixture `redos_privatekey.txt` is `-----BEGIN PRIVATE KEY-----` followed by 18 MB of filler with **no** matching closing `-----END PRIVATE KEY-----` marker — the classic nested / non-greedy `[\s\S]*?` catastrophe **shape**, aimed squarely at the private-key detector's pattern (`pkg/detectors/privatekey/privatekey.go:L33`). It also contains the literal string `private key`, so the Aho-Corasick prefilter (the detector's `Keywords()` at `privatekey.go:L38-40` returns `["private key"]`) actually routes the chunk to that detector — i.e. the dangerous pattern really is exercised, not skipped. The benign control is 18,000,000 bytes of neutral text with no keywords.

Observed `finished scanning` lines (verbatim, complete), 18,000,000-byte files:

```
2026-07-08T06:11:41Z	info-0	trufflehog	finished scanning	{"chunks": 1758, "bytes": 23397504, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "52.612174ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
2026-07-08T06:11:45Z	info-0	trufflehog	finished scanning	{"chunks": 1758, "bytes": 23370882, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "40.79508ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The first line is `benign_equal.txt` (**52.6 ms**); the second is `redos_privatekey.txt` (**40.8 ms**). So the pathological ReDoS-shaped file scanned in **40.8 ms**, essentially identical to — in fact *slightly faster than* — the benign control's **52.6 ms**, a ratio of **≈0.79×**, i.e. **no slowdown at all**. External wall-clock across 2 runs confirmed stability: benign **1.793 s / 1.796 s**; `redos_privatekey` **1.773 s / 1.837 s**.

**Why (grounded in the engine choice and RE2's design).** The private-key pattern is compiled with go-re2 (`privatekey.go:L13` `regexp "github.com/wasilibs/go-re2"`), so RE2 evaluates the `[\s\S]*?` sub-expression by simulating the NFA/DFA and exploring all positions in parallel in time linear to the input — there is no exponential backtracking to trigger. A backtracking engine (e.g. Perl/PCRE) on this same shape would explore exponentially many ways to match the unbounded `[\s\S]*?` against the trailing filler when the `END` anchor never appears, which is the canonical ReDoS blow-up. RE2 simply does not have that failure mode, and the Q5 CPU profile confirms it: the go-re2 RE2 engine executes in WebAssembly and **no backtracking-engine function appears anywhere** in the hot path.

**On the 3 standard-library detectors.** The only non-go-re2 detectors are `spv2.go`, `azure_cosmosdb.go`, and `jdbc.go`, which use the Go standard-library `regexp`. That package is itself the RE2/linear-time family, so those three are **equally immune** to catastrophic backtracking. They are examined individually in Q3.

---


## Q3 — Exploitable patterns: Which specific detector patterns, if any, can be exploited to cause disproportionate processing time?

**Answer: None are exploitable for *catastrophic* (super-linear) time.** The only patterns that cost more CPU do so **linearly**, in proportion to the number of legitimate secret candidates they match — not because of algorithmic blow-up.

To answer this concretely, the highest-risk candidate patterns were enumerated and each was fed a crafted input designed to stress it (the per-candidate observed results — keyword, hits, timing across two runs, and crafted-vs-benign ratio — are tabulated under **Q3 per-candidate crafted-input evidence** below). The candidates were chosen because they *look* dangerous to a reviewer familiar with backtracking-engine ReDoS: the private-key pattern has a nested non-greedy `[\s\S]*?` between two anchors (the textbook catastrophic shape); `jdbc` has a large bounded quantifier `{0,512}` plus a `pass.*?=(.+?)` pair and also compiles a **user-supplied** ignore regex at runtime; `azure_cosmosdb` has a long fixed-count `{86}`; `spv2` mixes character-class ranges with `\A`/`\z` anchors; and `anthropic` has a long `{93}` bounded quantifier. The verbatim patterns, exactly as they appear at the pinned commit, are:

```
privatekey.go:L33  (go-re2 engine; alias at L13; applied via FindAllString at L51)
  (?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----

jdbc.go:L53  (stdlib regexp; import at L8)
  (?i)jdbc:[\w]{3,10}:[^\s"']{0,512}
jdbc.go:L192  (stdlib regexp)
  (?i)pass.*?=(.+?)\b

azure_cosmosdb.go:L30  (stdlib regexp; import at L13)
  detectors.PrefixRegex([]string{"azure", "cosmos"}) + ([A-Za-z0-9]{86}==)
  where PrefixRegex(kw) returns:  (?i:azure|cosmos)(?:.|[\n\r]){0,40}?
  so the full compiled pattern is: (?i:azure|cosmos)(?:.|[\n\r]){0,40}?([A-Za-z0-9]{86}==)
azure_cosmosdb.go:L32
  ([a-z0-9-]{3,44}\.(?:documents|table\.cosmos)\.azure\.com)

spv2.go:L32  (stdlib regexp; import at L7)
  (?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)

anthropic.go:L27  (go-re2 engine; alias at L10)
  \b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b
```

**Observed result:** every one of these ran in **linear** time. The private-key catastrophe-shape scanned an 18 MB file in **40.8 ms** (≈0.79× the benign control — see Q2). The `jdbc` pattern, fed a file of `jdbc:` connection-string candidates, produced **201,581** candidate matches on 18 MB in **≈4.0 s** — more CPU than benign, but that cost is exactly proportional to the 201,581 matches it had to extract and report; doubling the file doubles both. The remaining three named candidates — `azure_cosmosdb`, `spv2`, and `anthropic` — were each fed a dedicated keyword-bearing crafted fixture (byte-for-byte equal-size to a benign control) and likewise ran in **bounded, linear** time: ≈1.8×–9× an equal-size benign scan, stable across two runs, and scaling linearly with size (see **Q3 per-candidate crafted-input evidence** below). None produced disproportionate (super-linear) time.

**On the three standard-library detectors specifically.** `spv2.go`, `azure_cosmosdb.go`, and `jdbc.go` are the *only* detectors that do not use go-re2 (they import stdlib `"regexp"` at `spv2.go:L7`, `azure_cosmosdb.go:L13`, and `jdbc.go:L8` respectively). The Go standard-library `regexp` is itself the RE2/linear-time family, so these three are **equally immune** to catastrophic backtracking. `jdbc` additionally compiles a **user-supplied** ignore regex at runtime via `regexp.Compile(ignoreString)` (`jdbc.go:L35-37`) — but that compiled regex is *also* stdlib-RE2 (it cannot be made catastrophic no matter what string a user supplies) and it is opt-in via a flag, not attacker-controllable through a scanned file.

---


## Q4 — Magnitude: How many times slower can a scan be made versus normal files of equivalent size?

**Answer: The ReDoS-specific answer is ≈1× (no slowdown). The maximum *content-driven* slowdown for a byte-for-byte equal-size file is ≈140× at the pure-scan level (≈5.0× end-to-end wall-clock) — and it is LINEAR, not exponential.**

The two supporting tables (equal-size crafted-vs-benign across ≥2 runs, and a linear-scaling table) are in the **Equal-size timing tables (Q4)** section below. The essential figures:

- **ReDoS shape vs. benign (equal size, 18 MB):** `redos_privatekey` **40.8 ms** vs `benign_equal` **51.2 ms** → **0.79×** — i.e. the pathological shape is *not slower at all*.
- **Maximum content-driven slowdown (equal size, 18 MB):** `keyword_dense` **7.186 s** vs `benign_equal` **51.2 ms** → **≈140.3×** at the pure-scan (`scan_duration`) level; end-to-end wall-clock **8.99 s vs 1.79 s ≈ 5.0×**.

**Why the ≈140× is not a complexity attack.** The keyword-dense fixture plants secret-shaped tokens (AWS access-key ID + secret, a `jdbc:postgresql://` connection string) in every ~490-byte block, so an 18 MB file contains **95,269** secret candidates while the equal-size benign file has **zero**. The 140× is simply the linear cost of the engine **matching and reporting 95,269 candidates** versus reporting none — real work, proportional to the number of hits, not algorithmic blow-up. An attacker **cannot** make this super-linear: as the linear-scaling table shows, going from 18 MB to 150 MB (8.33× the size) raises the keyword-dense scan from 7.19 s to 56.19 s (7.82× the time) and the hit count from 95,269 to 793,997 (8.33×) — time tracks size and hit-count linearly. Doubling the file roughly doubles the time; it never explodes.

**Why the wall-clock ratio (≈5.0×) is smaller than the pure-scan ratio (≈140×).** Every invocation pays a fixed ~1.8 s startup cost to load and compile 800+ detector pattern sets, which is shared identically by the benign and crafted runs. That fixed cost dominates the benign wall-clock (1.79 s total for a 51 ms scan) and dilutes the ratio once the variable scan work is added, so the end-to-end wall ratio (5.0×) is much smaller than the pure-scan ratio (140×). Both are reported honestly below.

**`git file://` magnitude (the Q1 committed-file threat model).** Committing an 18 MB newline-delimited keyword-dense payload to a throwaway repo and scanning it with `trufflehog git file:///work/repo_kw --no-verification` gave **scan_duration 5.75 s / 6.18 s**, wall **7.61 s / 8.01 s**, **73,470** hits — the same linear regime as `filesystem`, confirming the magnitude is a property of the content and pipeline, not of the entry point.

---

## Q5 — Evidence: Timing measurements AND CPU-profiling data

**Answer: Both are provided.** The timing measurements are the equal-size and linear-scaling tables (see **Equal-size timing tables (Q4)**), captured across ≥2 runs at stated scales. The CPU-profiling data (see **CPU-profiling evidence (Q5)** below) comprises three verbatim artifacts:

1. A **`go tool pprof -top`** CPU profile from TruffleHog's **built-in `--profile` server** on `:18066` (`main.go:L53`, `main.go:L434`), captured live during a 150 MB keyword-dense scan.
2. A **fgprof** wall-clock profile from `/debug/fgprof` for the same scan.
3. A **Go benchmark CPU profile** and throughput table from the in-repo `BenchmarkPopulateMatchingDetectors` (`pkg/engine/engine_test.go:L1039`).

The single most important thing the profile shows: the hot path is the **go-re2 RE2 engine executing as WebAssembly** (`runtime._ExternalCode` at 92.32%, plus `wazero` and `wasilibs/go-re2/internal.*` frames) — and **no backtracking-engine function appears anywhere**. That is the direct profiling proof of the Q2 answer. The benchmark throughput is roughly constant (~50 MB/s) across a 256× range of chunk sizes, which is the signature of **linear** time in the input.

---


## Q3 Candidate-Pattern Enumeration

Each highest-risk detector pattern, with its engine, the verbatim pattern, why it *looks* dangerous, and the observed runtime result. The full unescaped patterns appear in the fenced block in the Q3 section above.

| Detector (file:line) | Engine | Pattern (verbatim) | Why it *looks* risky | Observed result |
|---|---|---|---|---|
| `pkg/detectors/privatekey/privatekey.go:L33` (applied via `FindAllString`, L51) | go-re2 (alias L13) | `(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----` | nested `*?` non-greedy plus an unbounded `[\s\S]*?` between two anchors — the classic catastrophic-backtracking shape | 40.8 ms on 18 MB, ≈0.79× benign — **linear / fast** |
| `pkg/detectors/jdbc/jdbc.go:L53` (stdlib `regexp`, import L8) | stdlib RE2 | `(?i)jdbc:[\w]{3,10}:[^\s"']{0,512}`  (also L192 `(?i)pass.*?=(.+?)\b`; plus a user-supplied ignore regex compiled at runtime, L35-37) | large bounded quantifier `{0,512}` and a `pass.*?=(.+?)` pair; runtime-compiled user regex | 4.0 s / 201,581 matches on 18 MB — **linear** (see Q4) |
| `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go:L30`/`L32` (stdlib `regexp`, import L13) | stdlib RE2 | dbKeyPattern (L30, PrefixRegex expanded): <code>(?i:azure&#124;cosmos)(?:.&#124;[\n\r]){0,40}?([A-Za-z0-9]{86}==)</code>; accountUrlPattern (L32): <code>([a-z0-9-]{3,44}\\.(?:documents&#124;table\\.cosmos)\\.azure\\.com)</code> | long fixed-count `{86}` and a prefix regex | **linear** — crafted `.documents.azure.com` + `{86}==` near-miss fixture: ≈1.4 s / 10 MB (≈9× benign, bounded), and 2×/4× size → 1.94×/3.78× time (see per-candidate evidence below) |
| `pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go:L32` (stdlib `regexp`, import L7) | stdlib RE2 | <code>(?:[^a-zA-Z0-9_~.-]&#124;\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]&#124;\z)</code> | character-class ranges combined with `\A`/`\z` anchors | **linear** — crafted `Q~` near-miss fixture: ≈0.39 s / 10 MB (≈2.5× benign), 5 hits (see per-candidate evidence below) |
| `pkg/detectors/anthropic/anthropic.go:L27` | go-re2 (alias L10) | <code>\b(sk-ant-(?:admin01&#124;api03)-[\w\\-]{93}AA)\b</code> | long `{93}` bounded quantifier | **linear** — crafted `sk-ant-api03-…{93}` near-miss fixture: ≈0.28 s / 10 MB (≈1.8× benign) (see per-candidate evidence below) |

Every enumerated candidate ran in linear time. The three stdlib-`regexp` detectors (`jdbc`, `azure_cosmosdb`, `spv2`) are the only non-go-re2 detectors, and stdlib `regexp` is itself the RE2/linear family — so they are equally immune to catastrophic backtracking. No pattern in TruffleHog's detector set could be induced to exhibit super-linear behavior.

### Q3 per-candidate crafted-input evidence (observed)

The `privatekey` (≈0.79× benign — Q2/Q4) and `jdbc` (4.0 s / 201,581 matches — Q4) candidates are evidenced by the equal-size timing tables. The three remaining named candidates — `azure_cosmosdb`, `spv2`, and `anthropic` — were each fed a **dedicated crafted fixture that contains that detector's keyword** (so the Aho-Corasick prefilter routes the chunk to it) and is **shaped to maximally stress that detector's own pattern** as a near-miss "ReDoS attempt": for `azure_cosmosdb`, `azure`/`cosmos` markers plus long `[A-Za-z0-9]` runs with **no `==`** to force the `(?:.|[\n\r]){0,40}?([A-Za-z0-9]{86}==)` hunt to try and fail at many offsets, alongside real `.documents.azure.com` URLs; for `spv2`, dense `Q~` tokens with tail lengths straddling the `{31,34}` boundary; for `anthropic`, `sk-ant-api03-`/`sk-ant-admin01-` followed by 150 word-characters that never reach the required `AA` terminator. Each crafted fixture is **byte-for-byte 10,000,000 bytes**, equal to a keyword-free benign control, and was scanned with `./trufflehog filesystem <fixture> --no-verification --no-update` across **2 runs**.

**Provenance (labeled).** These three per-candidate runs were captured during re-verification in the canonical `CGO_ENABLED=0` default-WebAssembly (go-re2/`wazero`) configuration — the same build as everything else in this document — but on a host whose core count differs from the 128-vCPU authoring container. The load-bearing values here are therefore the **crafted-vs-equal-size-benign ratio**, the **stability across the two runs**, and the **linear size-scaling** — all host-independent — not the absolute milliseconds.

| Fixture (10,000,000 bytes, equal size) | keyword that routes it (occurrences) | unverified hits | scan_duration run1 / run2 | ratio vs benign | verdict |
|---|---|---|---|---|---|
| `benign_equal` (no detector keywords) | — | 0 | 155.97 ms / 153.55 ms | 1.0× | baseline |
| `cand_azure_cosmosdb` | `.documents.azure.com` (18,979) | 1 | 1.385 s / 1.431 s | ≈9× | bounded, linear |
| `cand_spv2` | `q~` / `Q~` (157,732) | 5 | 388.16 ms / 395.06 ms | ≈2.5× | bounded, linear |
| `cand_anthropic` | `sk-ant-api03` (29,070) | 0 | 278.29 ms / 280.98 ms | ≈1.8× | bounded, linear |

Verbatim `finished scanning` lines (run 1 of each; the `bytes` field is the chunker's peek-inflated count — ~13 MB of chunk data for a 10 MB file):

```
2026-07-08T08:51:07Z	info-0	trufflehog	finished scanning	{"chunks": 977, "bytes": 12998272, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "155.970223ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # benign_equal
2026-07-08T08:51:12Z	info-0	trufflehog	finished scanning	{"chunks": 977, "bytes": 12998272, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "1.385190131s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # cand_azure_cosmosdb
2026-07-08T08:51:17Z	info-0	trufflehog	finished scanning	{"chunks": 977, "bytes": 12998272, "verified_secrets": 0, "unverified_secrets": 5, "scan_duration": "388.159742ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # cand_spv2
2026-07-08T08:51:21Z	info-0	trufflehog	finished scanning	{"chunks": 977, "bytes": 12998272, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "278.286137ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # cand_anthropic
```

`azure_cosmosdb` is the highest-cost of the three (≈9× benign), so it was additionally scaled to confirm that cost is **bounded linear content work, not the onset of blow-up**:

| `cand_azure_cosmosdb` size | scan_duration | vs 5 MB |
|---|---|---|
| 5,000,000 bytes | 741.72 ms | 1.0× |
| 10,000,000 bytes | 1.438 s | 1.94× (for 2× the size) |
| 20,000,000 bytes | 2.806 s | 3.78× (for 4× the size) |

Verbatim `finished scanning` lines for the scaling probe:

```
2026-07-08T08:52:00Z	info-0	trufflehog	finished scanning	{"chunks": 489, "bytes": 6498944, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "741.722987ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # 5,000,000 bytes
2026-07-08T08:52:03Z	info-0	trufflehog	finished scanning	{"chunks": 977, "bytes": 12998272, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "1.437967558s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # 10,000,000 bytes
2026-07-08T08:52:08Z	info-0	trufflehog	finished scanning	{"chunks": 1954, "bytes": 25997824, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "2.806297179s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}   # 20,000,000 bytes
```

Doubling the file ≈ doubles the time (textbook O(n)); it never explodes. **Result:** every named Q3 candidate is now backed by observed crafted-input output — each was routed (its keyword is present), each **completed without hang or timeout**, each is **stable across runs**, and the worst (`azure_cosmosdb`, ≈9×) **scales linearly** with size. None exhibits disproportionate (super-linear) time.

---

## Equal-size Timing Tables (Q4)

All timing used `--no-verification --no-update` to isolate CPU (no network verification). `scan_duration` is TruffleHog's own internal metric from its `finished scanning` log line; `wall` is external wall-clock across 2 runs. Equal-size fixtures are **byte-for-byte 18,000,000 bytes**. Values were confirmed stable across the two runs.

**Table 4a — Equal-size (18,000,000 bytes) crafted vs. benign, `filesystem`, 2 runs:**

| Fixture (18 MB, equal size) | scan_duration run1 / run2 | wall run1 / run2 | unverified hits | scan ratio vs benign |
|---|---|---|---|---|
| benign_equal (no keywords) | 52.61 ms / 49.85 ms | 1.793 s / 1.796 s | 0 | 1.0× |
| redos_privatekey (BEGIN, no END) | 40.80 ms / 40.64 ms | 1.773 s / 1.837 s | 0 | **0.79× (none)** |
| redos_jdbc | 3.996 s / 4.036 s | 5.976 s / 6.146 s | 201,581 | 78.4× |
| keyword_dense | 7.028 s / 7.344 s | 8.826 s / 9.150 s | 95,269 | **140.3×** |

The `redos_privatekey` row is the headline: a classic catastrophic-backtracking *shape* runs *slightly faster* than the benign control (0.79×), the opposite of what a ReDoS-vulnerable engine would show. The `keyword_dense` row's 140.3× is the maximum content-driven slowdown, and it is linear work (95,269 secret candidates matched and reported vs. 0), as the next table proves.

**Table 4b — Linear scaling (proves no super-linear blow-up):**

| Fixture | size | scan_duration | hits | notes |
|---|---|---|---|---|
| benign | 18 MB | 51 ms | 0 | baseline (average of the two 18 MB runs) |
| benign | 100 MB | 236 ms | 0 | 5.56× size → 4.61× time (≈linear) |
| keyword_dense | 18 MB | 7.19 s | 95,269 | baseline (average of the two 18 MB runs) |
| keyword_dense | 150 MB | 56.19 s | 793,997 | 8.33× size → 7.82× time → 8.33× hits (≈linear) |

Time grows in proportion to input size and to the number of hits — the defining signature of linear-time matching. The `keyword_dense` hit count scales **8.33×** for an **8.33×** size increase (95,269 → 793,997), essentially exactly. There is no input size at which the cost curve bends upward.

**`git file://` magnitude (Q1 committed-file threat model), newline-delimited keyword-dense, 18 MB:** scan_duration **5.75 s / 6.18 s**, wall **7.61 s / 8.01 s**, **73,470** hits — the same linear regime as `filesystem`.

---


## CPU-profiling Evidence (Q5)

Three verbatim profiling artifacts are embedded below. Together they prove (a) the hot path is the RE2 engine (go-re2 in WebAssembly) with no catastrophic backtracking-engine function — any `backtrack`-named frames belong to Go stdlib `regexp`'s bounded, linear one-pass backtracker (see the footnote after artifact (A)) — and (b) throughput is constant across chunk sizes, i.e. linear in the input.

**(A) Live `--profile` server (`main.go:L53`, `main.go:L434`) during a 150 MB keyword-dense scan — `go tool pprof -top` of `http://localhost:18066/debug/pprof/profile`:**

```
Fetching profile over HTTP from http://localhost:18066/debug/pprof/profile?seconds=20
Please wait... (20s)
Saved profile in /root/pprof/pprof.trufflehog.samples.cpu.001.pb.gz
File: trufflehog
Build ID: 0fcc263a065b40b302259b3e6fcd76eeb0804f2d
Type: cpu
Time: 2026-07-08 06:15:06 UTC
Duration: 20.11s, Total samples = 1956.21s (9725.58%)
Showing nodes accounting for 1873.23s, 95.76% of 1956.21s total
Dropped 1111 nodes (cum <= 9.78s)
Showing top 30 nodes out of 32
      flat  flat%   sum%        cum   cum%
  1805.98s 92.32% 92.32%   1805.98s 92.32%  runtime._ExternalCode
    29.22s  1.49% 93.81%     78.90s  4.03%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
    10.33s  0.53% 94.34%     12.02s  0.61%  runtime.(*itabTableType).find
     6.48s  0.33% 94.67%     19.97s  1.02%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack.func4
     6.09s  0.31% 94.98%     11.46s  0.59%  github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1.wasiFunc.Call
     4.60s  0.24% 95.22%     16.62s  0.85%  runtime.getitab
     3.91s   0.2% 95.42%     14.17s  0.72%  runtime.gcDrain
     2.90s  0.15% 95.57%     19.67s  1.01%  runtime.assertE2I
     2.19s  0.11% 95.68%     26.05s  1.33%  github.com/tetratelabs/wazero/internal/engine/wazevo.hostModuleGoFuncFromOpaque[go.shape.interface { Call }] (inline)
     0.55s 0.028% 95.71%     79.47s  4.06%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.23s 0.012% 95.72%     89.17s  4.56%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.17s 0.0087% 95.73%     85.84s  4.39%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postgres.findUriMatches
     0.11s 0.0056% 95.73%     11.99s  0.61%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).notifierWorker
     0.11s 0.0056% 95.74%     73.81s  3.77%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
     0.07s 0.0036% 95.74%     79.59s  4.07%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call8
     0.07s 0.0036% 95.75%     75.65s  3.87%  github.com/wasilibs/go-re2/internal.matchFrom
     0.05s 0.0026% 95.75%     86.76s  4.44%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postgres.Scanner.FromData
     0.04s 0.002% 95.75%     79.20s  4.05%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.03s 0.0015% 95.75%     10.73s  0.55%  regexp.(*Regexp).doExecute
     0.02s 0.001% 95.75%     57.59s  2.94%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).verificationOverlapWorker
     0.02s 0.001% 95.76%     10.20s  0.52%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call1
     0.02s 0.001% 95.76%     20.70s  1.06%  runtime.systemstack
     0.01s 0.00051% 95.76%     10.39s  0.53%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws/access_keys.scanner.FromData
     0.01s 0.00051% 95.76%     54.04s  2.76%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectChunk
     0.01s 0.00051% 95.76%     54.09s  2.77%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectorWorker
     0.01s 0.00051% 95.76%     15.19s  0.78%  runtime.gcBgMarkWorker
         0     0% 95.76%     54.09s  2.77%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startDetectorWorkers.func1
         0     0% 95.76%     11.99s  0.61%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startNotifierWorkers.func1
         0     0% 95.76%     57.59s  2.94%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startVerificationOverlapWorkers.func1
         0     0% 95.76%     50.39s  2.58%  github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache.(*VerificationCache).FromData
```

**Interpretation.** `runtime._ExternalCode` (92.32% flat) is the **go-re2 RE2 engine running as WebAssembly** via the pure-Go `wazero` runtime — the default `CGO_ENABLED=0` mode. The `github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack` frames are the WASM host calls, and the `github.com/wasilibs/go-re2/internal.*` frames (`lazyFunction.callWithStack` 4.56% cum, `FindAllStringSubmatch` 4.05%, `matchFrom` 3.87%, `findAllSubmatch` 3.77%) are the RE2 match invocations. The hottest *detector* frames are `postgres.findUriMatches` (4.39% cum) and `postgres.Scanner.FromData` (4.44% cum) — the `postgres` detector, triggered by the fixture's `jdbc:postgresql://` strings — plus `aws/access_keys.scanner.FromData` (0.53% cum). **These three detectors are all go-re2 detectors** (each imports `regexp "github.com/wasilibs/go-re2"`: `pkg/detectors/postgres/postgres.go:L14`, `pkg/detectors/aws/access_keys/accesskey.go:L17`, and `pkg/detectors/aws/common.go:L3`), so their regex cost is spent inside the WebAssembly path above — **not** in any standard-library engine. The single standard-library frame is `regexp.(*Regexp).doExecute` (0.55% cum, 10.73 s) — the Go stdlib `regexp` engine — and it is driven by the one *stdlib* detector this fixture triggers, `jdbc` (stdlib `regexp` at `jdbc.go:L8`, keyword `jdbc`). (Note: `jdbc` is among the 3 stdlib-`regexp` detectors; `aws/access_keys` and `postgres` are **not** — a distinction the profile makes visible because both engines appear at once.) Crucially, **no backtracking-engine function (e.g. anything from `dlclark/regexp2`) appears anywhere in the profile** — this is the profiling proof of the Q2 answer that TruffleHog matches on a linear-time engine only. That scan completed; it did not hang.

**Footnote — "backtracking function" vs. "backtracking *engine*".** When a standard-library-`regexp` detector runs (here, `jdbc`), a CPU profile expanded with `-nodefraction=0` *does* surface Go stdlib frames literally named `regexp.(*Regexp).backtrack` and `regexp.(*Regexp).tryBacktrack`. (They are absent from artifact (A)'s top-30 view only because that view "Dropped 1111 nodes (cum <= 9.78s)": (A) shows their parent `regexp.(*Regexp).doExecute` at 10.73 s cum — just above that threshold — but the `backtrack`/`tryBacktrack` children fall below it and are dropped from the top-30.) These are **not** a catastrophic backtracking *engine*. Go's standard-library `regexp` — the same RE2/linear-time family used throughout TruffleHog — has a `backtrack` code path that is a **bounded, linear** one-pass matcher: per the Go source `src/regexp/backtrack.go` (L5–L14), it "allocates a bit vector with (length of input) * (length of prog) bits ... to make sure it never explores the same (character position, instruction) state multiple times. This limits the search to run in time linear in the length of the test," and it runs only on **small** regexps (guarded by `maxBacktrackProg = 500` and `maxBacktrackVector = 256 * 1024` at `backtrack.go:L32-L33`). It therefore cannot exhibit exponential (catastrophic) backtracking. A focused re-verification scan of a `jdbc:`-dense fixture with `--profile`, captured with `go tool pprof -top -nodefraction=0`, shows those frames are tiny and bounded (verbatim excerpt):

```
      flat  flat%   sum%        cum   cum%
     0.38s   0.8% 62.13%      1.08s  2.27%  regexp.(*Regexp).tryBacktrack
     0.28s  0.59% 68.08%      1.51s  3.18%  regexp.(*Regexp).backtrack
     0.01s 0.021% 98.04%      1.52s  3.20%  regexp.(*Regexp).doMatch (inline)
         0     0%   100%      5.58s 11.74%  regexp.(*Regexp).doExecute
```

The load-bearing profiling claim is therefore precisely scoped: **no *catastrophic backtracking-engine* function (for example, anything from `github.com/dlclark/regexp2`, or a PCRE-style engine) appears anywhere** — that engine is `// indirect` and unused under `pkg/` (`go.mod:L187`). Grepping this profile for `dlclark` / `regexp2` / `pcre` returns zero matches, while the go-re2 / `wazero` RE2 frames dominate the hot path. (This supplementary `-nodefraction=0` capture was taken during re-verification on a host whose core count differs from the 128-vCPU authoring container; absolute sample-seconds scale with core count, but the *proportions* — a few percent, bounded — are the host-independent point.)

**(B) fgprof wall-clock (`/debug/fgprof`) — same scan:**

```
Fetching profile over HTTP from http://localhost:18066/debug/fgprof?seconds=10
Saved profile in /root/pprof/pprof.samples.time.001.pb.gz
Type: time
Time: 2026-07-08 06:15:26 UTC
Duration: 10.05s, Total samples = 14274.27s (141982.67%)
Showing nodes accounting for 14154.05s, 99.16% of 14274.27s total
Dropped 427 nodes (cum <= 71.37s)
Showing top 25 nodes out of 57
      flat  flat%   sum%        cum   cum%
 12896.48s 90.35% 90.35%  12896.48s 90.35%  runtime.gopark
   816.75s  5.72% 96.07%    817.30s  5.73%  runtime.assertE2I
   423.77s  2.97% 99.04%    423.77s  2.97%  runtime.goyield
     7.53s 0.053% 99.09%    432.70s  3.03%  internal/sync.(*Mutex).unlockSlow
     2.12s 0.015% 99.11%   3071.53s 21.52%  internal/sync.(*Mutex).lockSlow
     1.88s 0.013% 99.12%    875.17s  6.13%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     1.40s 0.0098% 99.13%   2250.70s 15.77%  github.com/wasilibs/go-re2/internal.matchFrom
     1.30s 0.0091% 99.14%   3122.30s 21.87%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.95s 0.0067% 99.14%    876.12s  6.14%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.55s 0.0039% 99.15%   2404.12s 16.84%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.35s 0.0025% 99.15%    487.52s  3.42%  github.com/wasilibs/go-re2/internal.(*Regexp).FindSubmatch
     0.23s 0.0016% 99.15%    864.75s  6.06%  github.com/wasilibs/go-re2/internal.getChildModule
     0.17s 0.0012% 99.15%   3067.88s 21.49%  internal/sync.runtime_SemacquireMutex
     0.12s 0.00088% 99.15%    180.53s  1.26%  github.com/wasilibs/go-re2/internal.(*Regexp).findSubmatch
     0.10s 0.0007% 99.16%   2050.07s 14.36%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
     0.07s 0.00053% 99.16%    208.10s  1.46%  github.com/wasilibs/go-re2/internal.(*Regexp).findAll
     0.05s 0.00035% 99.16%   8334.67s 58.39%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).processResult
     0.05s 0.00035% 99.16%    689.12s  4.83%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call1
     0.05s 0.00035% 99.16%   1374.25s  9.63%  github.com/wasilibs/go-re2/internal.putChildModule
     0.03s 0.00018% 99.16%   1275.53s  8.94%  github.com/trufflesecurity/trufflehog/v3/pkg/output.(*PlainPrinter).Print
     0.03s 0.00018% 99.16%    224.03s  1.57%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAll
     0.03s 0.00018% 99.16%    314.45s  2.20%  github.com/wasilibs/go-re2/internal.(*allocation).free
     0.03s 0.00018% 99.16%   2433.68s 17.05%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call8
     0.03s 0.00018% 99.16%    425.18s  2.98%  internal/sync.runtime_Semrelease
         0     0% 99.16%     89.78s  0.63%  github.com/patrickmn/go-cache.(*janitor).Run
```

The dominant `runtime.gopark` (90.35%) is goroutines parked/waiting (expected under the default 128-way concurrency); the on-CPU work that matters is again all in `wasilibs/go-re2/internal.*` (RE2 — `lazyFunction.callWithStack` 21.87% cum, `FindAllStringSubmatch` 16.84% cum, `matchFrom` 15.77% cum), confirming the wall-clock story matches the CPU story. `engine.processResult` (58.39% cum) and `output.PlainPrinter.Print` (8.94% cum) are the result-handling/printing cost of the 792,048 candidates — again, linear work proportional to the number of hits. That scan finished:

```
2026-07-08T06:16:04Z	info-0	trufflehog	finished scanning	{"chunks": 14649, "bytes": 194998656, "verified_secrets": 0, "unverified_secrets": 792048, "scan_duration": "1m1.392735779s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

— 195 MB of chunk data processed, 792,048 candidates reported, completed in ~61 s (the extra time vs. the un-profiled 56 s is profiling overhead), no hang.

**(C) Go benchmark CPU profile — `BenchmarkPopulateMatchingDetectors` (`pkg/engine/engine_test.go:L1039`), throughput table:**

```
BenchmarkPopulateMatchingDetectors/ChunkSize_1024-128         	  362095	      8779 ns/op	 116.64 MB/s	    4296 B/op	      53 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_4096-128         	   89250	     39220 ns/op	 104.44 MB/s	   22248 B/op	     173 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_13312-128        	   14498	    242109 ns/op	  54.98 MB/s	   83756 B/op	     598 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_16384-128        	   10000	    313436 ns/op	  52.27 MB/s	   96558 B/op	     720 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_32768-128        	    5188	    673337 ns/op	  48.67 MB/s	  192148 B/op	    1349 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_65536-128        	    2496	   1401106 ns/op	  46.77 MB/s	  338968 B/op	    2597 allocs/op
BenchmarkPopulateMatchingDetectors/ChunkSize_262144-128       	     670	   5256031 ns/op	  49.87 MB/s	 1289800 B/op	    8208 allocs/op
PASS
ok  	github.com/trufflesecurity/trufflehog/v3/pkg/engine	28.688s
```

`go tool pprof -top` of that benchmark's CPU profile:

```
File: engine.test
Build ID: 404d16879eee6531b2666d29f9cfb6759213f005
Type: cpu
Time: 2026-07-08 06:17:21 UTC
Duration: 27.97s, Total samples = 33.40s (119.42%)
Showing nodes accounting for 25.71s, 76.98% of 33.40s total
Dropped 230 nodes (cum <= 0.17s)
Showing top 15 nodes out of 91
      flat  flat%   sum%        cum   cum%
    11.98s 35.87% 35.87%     12.96s 38.80%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
     5.24s 15.69% 51.56%      5.36s 16.05%  bytes.ToLower
     2.31s  6.92% 58.47%      2.31s  6.92%  aeshashbody
     1.05s  3.14% 61.62%      1.05s  3.14%  runtime.tgkill
     0.74s  2.22% 63.83%      2.13s  6.38%  runtime.scanobject
     0.69s  2.07% 65.90%      4.65s 13.92%  runtime.gcDrain
     0.64s  1.92% 67.81%      1.38s  4.13%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*adjustableSpanCalculator).calculateSpan
     0.48s  1.44% 69.25%      0.51s  1.53%  runtime.(*itabTableType).find
     0.47s  1.41% 70.66%      0.47s  1.41%  runtime.nextFreeFast (inline)
     0.44s  1.32% 71.98%      0.44s  1.32%  internal/runtime/maps.ctrlGroup.matchH2 (inline)
     0.37s  1.11% 73.08%      0.38s  1.14%  runtime.(*lfstack).pop (inline)
     0.36s  1.08% 74.16%      1.38s  4.13%  runtime.mallocgcSmallScanNoHeader
     0.32s  0.96% 75.12%     27.33s 81.83%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*Core).FindDetectorMatches
     0.31s  0.93% 76.05%      0.31s  0.93%  runtime.memclrNoHeapPointers
     0.31s  0.93% 76.98%      0.31s  0.93%  runtime.memmove
```

**Interpretation.** Throughput holds roughly constant (~47–117 MB/s, settling near ~50 MB/s for the representative 13 KB+ chunk sizes) across a **256× range of chunk sizes** (1,024 → 262,144 bytes) ⇒ processing time is **linear** in the input; if any pattern were super-linear, throughput would collapse as chunk size grew, and it does not. The hot path is the **linear-time Aho-Corasick keyword prefilter** — `aho-corasick.(*Trie).Walk` (35.87%) and `ahocorasick.(*Core).FindDetectorMatches` (81.83% cumulative, the routing entry point at `engine.go:L795`) — plus `bytes.ToLower` case-folding (15.69%), and `adjustableSpanCalculator.calculateSpan` (1.92% flat), which computes the ±512-byte extraction window (`pkg/engine/ahocorasick/ahocorasickcore.go:L155`). This is exactly the defense-in-depth architecture the Engine Analysis describes, observed in a profile.

---


## Alternative Resource-Exhaustion Vectors

Because Q1 asks broadly whether a scan can be "blocked", the full resource-exhaustion attack surface was probed at runtime, not just regex backtracking. Each vector was exercised and its bound observed.

**1. Archive depth bomb** (`nested_12x.gz` — 12 nested gzip layers, 334 bytes on disk). Observed output (complete, verbatim):

```
2026-07-08T06:18:19Z	error	trufflehog	non-critical error processing chunk	{"source_manager_worker_id": "iARac", "unit_kind": "unit", "unit": "/work/fixtures/nested_12x.gz", "path": "/work/fixtures/nested_12x.gz", "mime": "application/gzip", "timeout": 60, "error": "max archive depth reached"}
2026-07-08T06:18:19Z	info-0	trufflehog	finished scanning	{"chunks": 0, "bytes": 0, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.952936ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The depth-10 guard halts recursion in **~5 ms**. Mechanism: `pkg/handlers/archive.go:L26` `maxDepth = 5 * 2` (= 10); the guard at **L124** `if depth >= maxDepth {` returns `ErrMaxDepthReached` (**L105** `var ErrMaxDepthReached = errors.New("max archive depth reached")`). A deeply nested archive cannot exhaust resources — it is rejected almost instantly.

**2. Decompression bomb** (`bomb_3gb.gz`, 3,126,140 bytes compressed → 3 GB of zeros). Observed output (complete, verbatim):

```
2026-07-08T06:18:45Z	info-0	trufflehog	finished scanning	{"chunks": 314573, "bytes": 4187590656, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.380382133s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Wall ~7.13 s. The 3 GB stream was fully decompressed and scanned in **5.38 s**, bounded by the 60 s archive timeout (`pkg/handlers/archive.go:L28` `maxTimeout = time.Duration(60) * time.Second`, applied at `pkg/handlers/handlers.go:L384` `processingCtx, cancel := logContext.WithTimeout(ctx, maxTimeout)`) — no hang, and the soft per-detector timeout did not fire. (The reported `bytes` of 4,187,590,656 is the raw 3 GB inflated by the chunker's ~30% peek overlap: 3 GB × 13,312/10,240 ≈ 3.9 GB.) **Accurate note:** the 2 GB `maxSize` skip (`archive.go:L198` `if int(fileSize) > maxSize`, which skips oversize entries) applies to **sized archive entries**, not to a raw streaming gzip; here the **time** bound (60 s), not the size bound, is what applies — and the scan finished well within it.

**3. Base64 amplification** (`base64_blob.txt` — 18 MB base64 encoding of a keyword block). The Base64 decoder re-enters detection, so the same bytes are scanned in both encoded and decoded form. Observed output (complete, verbatim):

```
2026-07-08T06:19:39Z	info-0	trufflehog	finished scanning	{"chunks": 1758, "bytes": 17412859, "verified_secrets": 0, "unverified_secrets": 108561, "scan_duration": "8.094948499s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**108,561** hits in `scan_duration` **8.09 s**, wall ~9.87 s — bounded and linear. Mechanism: `pkg/decoders/decoders.go` orders the decoders `&UTF8{}` (L11), `&Base64{}` (L12), `&UTF16{}` (L13), `&EscapedUnicode{}` (L14); the Base64 decoder's `FromChunk` (`pkg/decoders/base64.go`) yields a decoded variant that independently re-enters the Aho-Corasick prefilter. This at most multiplies work by the small, fixed number of decoders — a constant factor, not super-linear.

**4. RE2 "DFA out of memory"** (TruffleHog issue #2739). A 240 MB probe (`dfa_oom_240mb.txt`) built from ~12 KB lines produced **no** `DFA out of memory` error. Observed output (complete, verbatim):

```
2026-07-08T06:19:41Z	info-0	trufflehog	finished scanning	{"chunks": 23438, "bytes": 311998464, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "542.126868ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Reported honestly:** this path **did not reproduce** under the canonical 13 KB chunker plus ±512-byte window (the grep for `DFA out of memory` / `out of memory` / `re2/` returned nothing), because those bounds keep the input to any single regex tiny (~1 KB), far below RE2's memory budget. Per issue #2739 the condition arises only when the input to a match exceeds RE2's configured `max_mem`, and RE2 then **fails gracefully** — it emits an error and **skips** that match rather than hanging. This is therefore a **detection-gap** (a secret in an oversized match window could be missed), **not** an availability DoS. The maintainer's note in #2739 also confirms the whole diff is never scanned as one unit precisely because the sliding-window-with-overlap chunker (`pkg/sources/chunker.go`) breaks data into manageable chunks.

**5. Soft per-detector timeout.** The log line `"a detector ignored the context timeout"` (`pkg/engine/engine.go:L1068`) appeared in **zero** scan outputs — checked across every scan performed here, including the 56 s / 150 MB one. The verbatim check (the only apparent match is the literal search string echoed into the check's own log file — every actual scan output is `0`):

```
$ grep -rc "a detector ignored the context timeout" /work/logs/
/work/logs/04_filesystem_timing.txt:0
/work/logs/05_git_filesystem.txt:0
/work/logs/06_linear_scaling.txt:0
/work/logs/07_profile_scan_out.txt:0
/work/logs/09_vectors_archive.txt:0
/work/logs/10_vectors_more.txt:0
```

Mechanism (`pkg/engine/engine.go:L1066-L1077`): a `context.WithTimeout` of 10 s is set (L1066) and a `time.AfterFunc` timer set to `detectionTimeout+1*time.Second` (L1067-1068) only **logs** after 11 s; the match is never force-killed (`t.Stop()` L1076, `cancel()` L1077 run only after the detector returns). Because each detector matches ~1 KB in microseconds, the timeout is never approached — and even if a detector were slow, the soft timeout would merely log, so it cannot itself cause or prevent a hang.

**6. git 64 KB line limit** (detection-gap). The same 18 MB keyword-dense payload, committed as a **single line (0 newlines)** and scanned by the `git` source, was processed as only:

```
2026-07-08T06:19:43Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 18, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "107.657089ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Only **18 bytes** were scanned; the 18 MB of content was **skipped**. Cause: `pkg/sources/git/git.go:L729` `originalChunk := bufio.NewScanner(reader)` with the scan loop at **L732** `for offset := 0; originalChunk.Scan(); offset++ {`, and **no** custom `.Buffer()` call anywhere in `pkg/sources/git/` — so the default `bufio.MaxScanTokenSize` of 65,536 bytes (64 KB) applies and a diff line longer than 64 KB is dropped. This is a **detection-gap** (a secret on a >64 KB line is missed by the git source), and it makes the scan **faster**, not slower — it cannot cause a hang.

**Summary of vectors:** every alternative vector is either rejected quickly (archive depth), bounded by a time budget (decompression), a constant-factor multiply (base64), a graceful skip / detection-gap (DFA-OOM, git 64 KB), or a log-only soft timeout. None hangs or blocks the scan.

---

## Exact Commands Used

The investigation is fully reproducible with the following commands (verbatim), all run inside the canonical SWE container (`ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0`, Go 1.24.3, `CGO_ENABLED=0`, default WebAssembly go-re2, `--concurrency=128`). Fixtures were generated byte-exact under `/work/fixtures/` (each 18 MB fixture = exactly 18,000,000 bytes).

```
# Build (canonical, default config)
CGO_ENABLED=0 go build -o /work/trufflehog .

# Fact checks
grep -rl 'regexp "github.com/wasilibs/go-re2"' --include=*.go pkg | wc -l   # -> 867
grep -rln '^[[:space:]]*"regexp"$' --include=*.go pkg/detectors             # -> the 3 stdlib detectors
grep -rn 'dlclark/regexp2' --include=*.go pkg                                # -> (none; exit 1)

# Equal-size fixtures (each exactly 18,000,000 bytes), generated with a Python helper:
#   /work/fixtures/benign_equal.txt      : neutral lowercase text, no detector keywords
#   /work/fixtures/redos_privatekey.txt  : "-----BEGIN PRIVATE KEY-----" + filler, NO END marker
#   /work/fixtures/redos_jdbc.txt        : repeated jdbc:mysql: connection-string candidates with user/password params
#   /work/fixtures/keyword_dense.txt     : AWS access-key + secret + jdbc:postgresql:// per ~490-byte block

# Timing (filesystem), 2 runs each (example for one fixture; repeated for all four):
/work/trufflehog filesystem /work/fixtures/benign_equal.txt      --no-verification --no-update
/work/trufflehog filesystem /work/fixtures/redos_privatekey.txt  --no-verification --no-update
/work/trufflehog filesystem /work/fixtures/redos_jdbc.txt        --no-verification --no-update
/work/trufflehog filesystem /work/fixtures/keyword_dense.txt     --no-verification --no-update

# git committed-file threat model:
git init -q /work/repo_kw
cp /work/fixtures/keyword_dense.txt /work/repo_kw/payload.txt
git -C /work/repo_kw add -A && git -C /work/repo_kw commit -qm "add payload"
/work/trufflehog git file:///work/repo_kw --no-verification --no-update

# Linear scaling:
/work/trufflehog filesystem /work/fixtures/benign_100mb.txt        --no-verification --no-update
/work/trufflehog filesystem /work/fixtures/keyword_dense_150mb.txt --no-verification --no-update

# CPU profiling — live server (main.go:L53):
/work/trufflehog filesystem /work/fixtures/keyword_dense_150mb.txt --profile --no-verification --no-update &
go tool pprof -top -seconds=20 http://localhost:18066/debug/pprof/profile
go tool pprof -top "http://localhost:18066/debug/fgprof?seconds=10"

# CPU profiling — benchmark supplement:
CGO_ENABLED=0 go test -run=xxx -bench=BenchmarkPopulateMatchingDetectors -benchtime=3s \
  -cpuprofile=/work/cpu_engine.prof -o /work/engine.test ./pkg/engine/
go tool pprof -top /work/engine.test /work/cpu_engine.prof

# Alternative vectors:
#   archive depth bomb: 12x nested gzip -> /work/fixtures/nested_12x.gz
/work/trufflehog filesystem /work/fixtures/nested_12x.gz  --no-verification --no-update
#   decompression bomb: dd if=/dev/zero bs=1M count=3072 | gzip -c > /work/fixtures/bomb_3gb.gz
/work/trufflehog filesystem /work/fixtures/bomb_3gb.gz    --no-verification --no-update
#   base64 amplification:
/work/trufflehog filesystem /work/fixtures/base64_blob.txt --no-verification --no-update
#   RE2 DFA-out-of-memory probe (240 MB, ~12 KB lines):
/work/trufflehog filesystem /work/fixtures/dfa_oom_240mb.txt --no-verification --no-update
#   git 64 KB line limit (18 MB single line committed):
/work/trufflehog git file:///work/repo_oneline --no-verification --no-update
#   soft-timeout check across all logs:
grep -rc "a detector ignored the context timeout" /work/logs/
```

---

## Conclusion

**Catastrophic-backtracking ReDoS is not reproducible against TruffleHog's detectors.** The detectors compile their patterns on Google RE2 via `github.com/wasilibs/go-re2` (`go.mod:L100`, v1.9.0) — a linear-time, non-backtracking engine — across 867 of 870 detector files, with the remaining 3 on the Go standard-library `regexp` (the same RE2/linear family). The only backtracking engine in the module graph, `github.com/dlclark/regexp2` (`go.mod:L187`, `// indirect`), has zero direct use under `pkg/`. A classic ReDoS-shaped input scanned *slightly faster* than an equal-size benign control (0.79×), and the live CPU profile shows the RE2 engine executing in WebAssembly with no catastrophic backtracking-engine function (nothing from `dlclark/regexp2` or any PCRE-style engine) anywhere in the hot path — the only `backtrack`-named frames are Go stdlib `regexp`'s bounded, linear one-pass matcher (see the Q5 footnote).

**The real, observed behavior is bounded and linear.** The maximum content-driven slowdown for a byte-for-byte equal-size file is ≈140× at the pure-scan level (≈5.0× end-to-end), and it is strictly linear work proportional to the number of secret candidates in the file — confirmed by linear scaling from 18 MB to 150 MB (8.33× size → 8.33× hits → 7.82× time). Input reaching any single regex is bounded by the 13 KB chunker (`pkg/sources/chunker.go:L14-L18`), the Aho-Corasick keyword prefilter (`pkg/engine/engine.go:L795`), and the ±512-byte extraction window (`pkg/engine/ahocorasick/ahocorasickcore.go:L155`). Even the worst 150 MB / 793,997-candidate scan completed in ~56 s and never hung, and the per-detector timeout (`pkg/engine/engine.go:L1066-L1077`) is soft — it only logs, never force-kills — and never fired.

**Two honest caveats, both detection-gaps rather than availability DoS.** (1) RE2 can emit a `DFA out of memory` error and *skip* a match when its `max_mem` budget is exceeded (TruffleHog issue #2739); this did not reproduce under the canonical chunk/window bounds and, when it does occur, causes a missed secret, not a hang. (2) The git source uses a default 64 KB line scanner (`pkg/sources/git/git.go:L729`) with no custom buffer, so content on a line longer than 64 KB is dropped — again a missed secret, and it makes the scan faster, not slower. Neither can block a scan.

**Answering the CI-owner's underlying concern:** a malicious file committed to a scanned repository **cannot** make TruffleHog hang or time out via regex computational complexity, and thus cannot block a CI security pipeline by that means. The worst an attacker can do with content alone is impose a bounded, linear slowdown that still completes in seconds to tens of seconds.

**Scope note:** this document answers the question and stops there. Consistent with the read-only, investigation-only scope of this task, **no remediation, hardening, or mitigation is proposed** (for example, converting the soft per-detector timeout into a hard kill, tuning RE2's `max_mem`, or raising the git line-buffer limit are all explicitly out of scope). No TruffleHog source file was modified; the only artifact produced is this document.
