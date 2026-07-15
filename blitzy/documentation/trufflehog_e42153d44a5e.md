# TruffleHog ReDoS / Computational‑Complexity Attack Assessment

**Target:** TruffleHog v3 — Go module `github.com/trufflesecurity/trufflehog/v3` ([go.mod:L1]), source HEAD `e42153d4`.
**Question:** Can a malicious actor commit a specially crafted file that makes TruffleHog *hang* or *time out* during a CI scan (a Regular‑Expression Denial‑of‑Service / computational‑complexity attack)?
**Answer (one line):** **No — TruffleHog's detector pattern matching is *not* vulnerable to catastrophic‑backtracking ReDoS.** Every detector regex is compiled by an RE2‑lineage, non‑backtracking engine whose match time is *linear* in the input length. A crafted file can only make a scan *linearly* (not exponentially) slower, and the practically largest amplification comes from *flooding the scanner with matches*, not from any regex blow‑up.

> **Scope & constraints honoured.** This is a **read‑only** investigation. No TruffleHog source file was created, modified, or deleted (see the `git status` proof in §9.6). All crafted inputs, helper programs, and the compiled binary live outside the repository under `/tmp/` and are removed at the end. Every conclusion below is written from **observed runtime output** captured by building and running the **real binary** through its **canonical entry point** (`trufflehog filesystem … --no-verification --no-update`), never a synthetic regex‑only stand‑in. The one out‑of‑tree engine‑contrast micro‑benchmark (§7.6) is explicitly labelled **corroboration**, not the canonical path.

---

## 1. TL;DR — Executive Verdict

- **ReDoS (catastrophic backtracking): NOT VULNERABLE.** TruffleHog's detector patterns are compiled by RE2‑lineage engines: **865 production detector `.go` files import** `regexp "github.com/wasilibs/go-re2"` ([go.mod:L100]) — plus 2 test files, 867 imports total (§4.1) — and the remaining **3 production** detectors use Go's standard‑library `regexp`. (The count is of importing *files*, not of distinct compiled patterns; a file may compile several patterns.) Both are **RE2‑lineage engines that do not do unbounded backtracking**, so the "nested quantifier" constructs (`(x+)+`, overlapping alternation, `.*` around quantified groups) that are catastrophic under PCRE‑style engines cannot blow up here. This is confirmed three ways: (a) a size sweep showing **clean linear scaling** (§7.4); (b) maximally‑adversarial nested‑quantifier inputs completing in **sub‑second** time even at 8 MiB (§7.1–7.2); and (c) an engine‑contrast benchmark in which the two engines TruffleHog uses stay in the **microsecond** range while a genuine backtracking engine explodes exponentially (§7.6).

- **Residual, *linear* (non‑catastrophic) degradation: YES, and worth noting for CI.** Because a scan's cost grows with the number of *matches* it must extract and report, an attacker who commits a large file of **unique, synthetic, credential‑shaped strings** (no real secret required — verification is off) can force TruffleHog to do a lot of match‑extraction and finding‑emission work. Measured: an **8 MiB** such file produced **201,431 findings** in **~5.6 s**, and **16 MiB → 402,901 findings in ~10.3 s** — i.e. **~0.66 s/MiB, growing linearly**. That is **~62×** slower than an equivalent‑size file that misses the keyword prefilter (§6). This is *bounded and linear*, not a hang; but on a large enough committed file it could push a fixed CI step past its timeout, and it floods the findings output. Note the de‑duplication mechanics: within each chunk the MongoDB detector collapses identical matches through a **local, per‑`FromData`‑call `uniqueMatches` map** ([mongodb.go:L48], [mongodb.go:L81]) — this bounds *emitted findings per chunk*, **not** cost, because `url.Parse` runs on **every raw match** *before* that map ([mongodb.go:L49], [mongodb.go:L58]). So even naïve repetition of one string already amplifies (**~34×** baseline, **~3.0 s** at 8 MiB; §3, §6.2). Making each match *unique* amplifies *further* (~62×) simply because distinct strings **cannot** be merged by that per‑chunk map — **not** because any cache is "defeated" (the engine's separate cross‑result `dedupeCache` is an LRU keyed partly on per‑line source metadata that **deliberately preserves same‑decoder duplicates**, [engine.go:L1216]–[engine.go:L1218]). Neither path is *required* to force a large (still linear, bounded) slowdown.

- **Which patterns are exploitable for catastrophic blow‑up: NONE** (§5). The nested‑quantifier patterns an attacker would target — MongoDB `connStrPat` ([pkg/detectors/mongodb/mongodb.go:L32]), URI `keyPat` ([pkg/detectors/uri/uri.go:L33]), `databrickstoken` ([pkg/detectors/databrickstoken/databrickstoken.go:L27]), `azuresastoken` ([pkg/detectors/azuresastoken/azuresastoken.go:L32]) — all complete in **≤ ~1.1 s on 8 MiB** of purpose‑built adversarial input, whether the payload matches or fails, and whether or not the per‑keyword span window is bypassed with `--scan-entire-chunk`.

### The five questions, answered

| # | Question | Verdict |
|---|----------|---------|
| **Q1** | Can a crafted committed file **hang or time out** TruffleHog and block CI? | **No indefinite hang.** Pattern matching is linear‑time. The only achievable effect is a **linear, bounded** slowdown; a sufficiently large *unique‑match‑dense* file could exceed a fixed CI step timeout (~0.66 s/MiB) and flood findings — a linear resource cost, backstopped by per‑detector cooperative timeouts. Two *unrelated* CLI caveats also bear on CI reliability — fatal filesystem‑source errors exit `0` even with `--fail`, and invalid `--concurrency` (0 / negative) hangs or panics — see §3.1. |
| **Q2** | Is pattern matching **vulnerable to computational‑complexity (ReDoS)** attacks? | **No.** Detectors run on RE2‑lineage engines (`go-re2` WASM + stdlib `regexp`) with a documented **linear‑time** guarantee and no unbounded backtracking. Confirmed empirically. |
| **Q3** | **Which detector patterns**, if any, are exploitable? | **None** for catastrophic blow‑up. Only a handful of detectors (6 of 845) even contain a genuine group‑repetition shape; the highest‑risk of them were measured directly and none blows up, and the engine‑level RE2 linear‑time guarantee covers the rest. |
| **Q4** | **How much slower** vs. normal files of equivalent size? | A ReDoS‑*structured* (non‑matching) file is only **~1.2×** an equivalent‑size prefilter‑miss baseline. The maximum amplification — a **unique synthetic match‑dense** file — is **~62×** at 8 MiB, and it is **linear and bounded**. |
| **Q5** | **Evidence** (timing + CPU profiling)? | Timing tables across 3+ runs (§7.1–7.4), a `go tool pprof` CPU profile of the real scan (§7.5), and the engine‑contrast corroboration (§7.6). |

---

## 2. Threat Model & Methodology

**Attacker capability.** The attacker can commit an arbitrary file to a repository that TruffleHog scans in CI. They control the file's *bytes* but not TruffleHog's configuration. Their goal is to make a scan hang or run long enough to block the pipeline.

**What "pattern matching cost" means here.** A file flows through TruffleHog's pipeline: chunker → **Aho‑Corasick keyword prefilter** → detector regex (`FromData`) → result dispatch. To isolate *pattern‑matching* cost from network credential verification, every scan below uses `--no-verification` (and `--no-update` to avoid self‑update). This is the exact surface the question targets.

**Canonical build & invocation (reproduced verbatim in §9).**

```
# Build exactly as the project Dockerfile does (forces the WASM RE2 variant of go-re2)
CGO_ENABLED=0 go build -o /tmp/trufflehog .

# Canonical scan (pattern-matching cost isolated)
/tmp/trufflehog filesystem <dir> --no-verification --no-update
```

**Measurement discipline (addresses the run‑first rule and stability):**

- **Metric.** `scan_duration` is TruffleHog's *own* reported figure, emitted on the `finished scanning` log line ([main.go:L566] logs "finished scanning"; the `scan_duration` field is populated at [main.go:L571]). We report it verbatim.
- **Aggregation.** Each condition is run **≥ 3 times**; we report the **median** and the **dispersion** = (max − min)/median. Any point whose dispersion exceeded **25 %** was **re‑run at n = 7** and is reported as such. Match‑dense workloads are inherently noisier (garbage collection and output writing dominated by hundreds of thousands of findings); this is documented, not hidden.
- **Units.** All file sizes are exact powers of two (e.g. 8 MiB = 8,388,608 bytes) and all derived rates are therefore expressed in **MiB / KiB** (binary units), not MB/KB.
- **Environment.** Go `go1.24.3`; the host reports `nproc = 4`, **but** `runtime.NumCPU() = 128`, and TruffleHog's default `filesystem` concurrency is `runtime.NumCPU()` ([main.go:L58] defaults concurrency to `runtime.NumCPU()`). Absolute wall‑clock numbers **and the exact between‑condition ratios are environment‑dependent** (they shift with core count, memory bandwidth, and output/terminal speed) and are **not** claimed to be host‑independent. The only **portable** conclusions are the *complexity class* (linear vs. super‑linear) and the *qualitative trend* (e.g. "a finding‑flood is roughly one to two orders of magnitude slower than a keyword‑miss; a non‑matching evil‑regex file is near‑baseline"); the specific multipliers reported here (e.g. 62.2×) are representative of this host, not universal constants.

**Proven keyword‑free baseline (why "random text" is not a valid control).** TruffleHog routes each chunk through an Aho‑Corasick prefilter built from every detector's keywords; a chunk that contains no keyword never reaches any detector regex. Some keywords are only **two characters** (e.g. `"az"`, `"gh"` — [pkg/detectors/azure_entra/serviceprincipal/v1/spv1.go:L45] lists `"az"`), so ordinary random alphanumeric text almost always *hits* the prefilter and is **not** a clean "regex never runs" control. To build a *provably* keyword‑free baseline, we wrote a tiny out‑of‑tree helper (full source in §9.2) that imports TruffleHog's **own** `defaults.DefaultDetectors()` ([pkg/engine/defaults/defaults.go:L1704]) and its **own** `ahocorasick.NewAhoCorasickCore(...)` and reports how many detectors a candidate file would trigger. Our baseline file registered **0 detector hits** — a verified prefilter MISS (§7.1).

**Span awareness (what actually reaches each regex).** The prefilter does not hand a detector the whole chunk. By default TruffleHog computes a per‑keyword *span* of **±512 bytes** around the keyword offset (a 1 KiB window) via `adjustableSpanCalculator` (`defaultOffsetRadius = 512` in [pkg/engine/ahocorasick/ahocorasickcore.go:L155]); detectors that implement `DefaultMultiPartCredentialProvider` (e.g. `databrickstoken` [pkg/detectors/databrickstoken/databrickstoken.go:L17], `azuresastoken` [pkg/detectors/azuresastoken/azuresastoken.go:L22]) get a **±1024** window (`MaxCredentialSpan = 1024`). The full ~13 KiB chunk only reaches a regex under the hidden `--scan-entire-chunk` flag ([main.go:L68], default `false`). We therefore (a) size adversarial constructs to fit the *real* default window, **and** (b) additionally run every adversarial input with `--scan-entire-chunk` to exercise the absolute worst‑case single regex call (§7.3). Span‑limiting is thus a *defense‑in‑depth*, not the primary protection — the primary protection is RE2's linear‑time guarantee, which holds even with the span limit removed.

---

## 3. Q1 — Can a crafted committed file hang or time out TruffleHog and block CI?

**Direct answer: No indefinite hang is achievable through pattern matching, and no *exponential* time explosion exists.** The only achievable effect is a **linear, bounded** increase in scan time. On a sufficiently large committed file, that linear cost *could* exceed a fixed CI‑step timeout, so it is worth understanding precisely.

**Why there is no hang.** Detector regexes run on RE2‑lineage engines whose match time is linear in the input length (§4). A single regex call therefore cannot spin forever on a ~1–13 KiB span the way a backtracking engine can on `(a+)+`. The size sweep in §7.4 confirms strictly linear growth for every input class, including the maximally‑adversarial nested‑quantifier ones.

**The realistic residual risk — a *linear* finding‑flood.** A scan's cost is dominated by how many *matches* it extracts and reports, not by regex execution. An attacker does **not** need a real secret: with `--no-verification` (the norm for a fast CI pass), every credential‑*shaped* string becomes an `unverified_secrets` finding. Two facts shape the attack:

1. **Identical matches collapse *per chunk*, but cost is not saved.** A file repeating the *same* connection string 131,072 times produces only **~820** *emitted* findings — roughly **one per chunk**, because the MongoDB detector's **local, per‑`FromData`‑call `uniqueMatches` map** ([mongodb.go:L48], [mongodb.go:L81]) merges identical strings *within* each chunk, after which each of the ~820 chunks emits its one result. Yet the file still scans in **~3.0 s** at 8 MiB (n = 7 median; §7.2), because `url.Parse` runs on *every* raw match *before* that map ([mongodb.go:L49], [mongodb.go:L58]). So naïve repetition is **not** cheap (~34× baseline); the attacker does **not** need unique matches to force a large — but still linear and bounded — slowdown.
2. **Unique matches cannot be merged by the per‑chunk map.** A file of **unique** synthetic strings (each with a distinct username/host counter) produced **201,431** findings at 8 MiB and scanned in **~5.6 s** — and **402,901 findings / ~10.3 s** at 16 MiB (§7.4). Because every string is distinct, the per‑chunk `uniqueMatches` map cannot collapse any of them, so each becomes its own emitted finding (≈ one per input line); nothing about a cache is "defeated." The cost is **~0.66 s/MiB and grows linearly**.

At **~62×** the equivalent‑size prefilter‑miss baseline (§6), this is the largest slowdown we could manufacture. It is a **linear resource‑consumption** effect: bounded, proportional to file size, and — because verification is off — composed entirely of *fabricated* findings. On a CI runner with a fixed per‑step timeout, a large enough committed file (tens of MiB of unique credential‑shaped lines) could plausibly push a scan past that timeout and would certainly flood the findings stream. This is a *degradation‑of‑service via linear amplification and output volume*, **not** a catastrophic‑backtracking hang.

**Defense‑in‑depth (and its real limits).** TruffleHog wraps detector execution in cooperative deadlines:

- On the **normal** detection path, `detectorWorker` ([pkg/engine/engine.go:L1036]) → `detectChunk` ([pkg/engine/engine.go:L1044]) wraps each detector call in `context.WithTimeout(ctx, detectionTimeout)` ([pkg/engine/engine.go:L1066]), where `detectionTimeout` defaults to `DefaultResponseTimeout = 10 * time.Second` ([pkg/detectors/http.go:L18]; wired in at [pkg/engine/engine.go:L37]). A watchdog `time.AfterFunc(...)` ([pkg/engine/engine.go:L1067]) only **logs** `"a detector ignored the context timeout"` ([pkg/engine/engine.go:L1068]) — it does not kill the work — before the call proceeds through `e.verificationCache.FromData(...)` ([pkg/engine/engine.go:L1070]).
- On the **verification‑overlap** path, `verificationOverlapWorker` ([pkg/engine/engine.go:L924]) wraps `detector.FromData(...)` ([pkg/engine/engine.go:L940]) in a shorter `context.WithTimeout(ctx, time.Second*2)` ([pkg/engine/engine.go:L939]).

Both deadlines are **cooperative**: the detector's regex call, `FindAllStringSubmatch`, takes **no context** ([pkg/detectors/uri/uri.go:L61], [pkg/detectors/mongodb/mongodb.go:L49]), so a single in‑flight regex match cannot be interrupted mid‑call, and the watchdog only emits a log line. This is precisely why **RE2's linear‑time guarantee — not the timeout — is the true protection**: the timeouts primarily bound slow *network verification*, and they do not (and need not) forcibly abort CPU‑bound matching, because matching cannot run away in the first place.

### 3.1 Operational CI caveats — unchanged product behavior, disclosed for triage

Two behaviours of the TruffleHog CLI *itself* (not attacker‑controlled, and **not** modified by this read‑only investigation) matter to anyone wiring it into a CI gate. They are unrelated to ReDoS but bear directly on Q1's "block our security scans" concern, so they are disclosed here for separate triage. Both were re‑confirmed on the canonical `/tmp/trufflehog` build.

- **A fatal filesystem‑source error still exits `0` — even with `--fail`.** If the scan target cannot be read (e.g. a bad path, or a file the process cannot `lstat`), TruffleHog logs the error but the process still returns success. Observed:

  ```
  $ /tmp/trufflehog filesystem /tmp/does-not-exist --no-verification --no-update ; echo "exit=$?"
  … error … encountered errors during scan  {"errors":["lstat /tmp/does-not-exist: no such file or directory"]}
  … info-0 … finished scanning  {"chunks":0,"bytes":0,"verified_secrets":0,"unverified_secrets":0,…}
  exit=0
  $ /tmp/trufflehog filesystem /tmp/does-not-exist --no-verification --no-update --fail ; echo "exit=$?"
  …                                       # same errors logged
  exit=0                                  # --fail does NOT change this; --fail only flips exit on *findings*
  ```

  The filesystem source's run summary is returned unconditionally as success (`return metrics{…}, nil` after the errors are only *logged*, near [main.go:L968]); `--fail` governs the "verified/allowed findings" exit code, not source‑level scan errors. **Implication for CI:** an exit code of `0` does **not** prove the target was actually scanned. A malicious commit that makes the target unreadable (or a misconfigured path) would let a scan "pass" while scanning nothing. Gate on the `finished scanning` summary — assert `chunks > 0` / `bytes > 0` for a target you know is non‑empty — rather than on exit status alone.

- **Invalid `--concurrency` values hang or panic.** `--concurrency` is wired to `runtime.NumCPU()` by default with **no lower‑bound validation** ([main.go:L58]). Observed on a trivial 24‑byte target:

  ```
  $ /tmp/trufflehog filesystem <dir> --concurrency=0  --no-verification --no-update
  … info-0 … No concurrency specified, defaulting to max  {"cpu":128}
  # …then never reaches "finished scanning"; the process HANGS and must be killed.
  # Under a CI `timeout` wrapper this surfaces as a non‑zero timeout exit (124).

  $ /tmp/trufflehog filesystem <dir> --concurrency=-1 --no-verification --no-update ; echo "exit=$?"
  panic: semaphore limit must not be negative
    github.com/marusama/semaphore/v2.(*semaphore).SetLimit  …/semaphore/v2@v2.5.0/semaphore.go:193
  exit=2
  ```

  This is a self‑inflicted misconfiguration (the attacker does not control CI flags), but it is a sharp edge: a `0` or negative value does not fall back to a safe default. **Use a positive `--concurrency`** (omit the flag to accept the default). Every measurement in this report was taken with a valid positive concurrency and with the `finished scanning` summary showing non‑zero `chunks`, so these caveats do not affect any number herein.

---

## 4. Q2 — Is TruffleHog's pattern matching vulnerable to computational‑complexity (ReDoS) attacks?

**Direct answer: No.** ReDoS feasibility is decided almost entirely by the regex *engine*: catastrophic backtracking is only possible on an engine that backtracks. TruffleHog's detectors run exclusively on **RE2‑lineage, linear‑time engines**, so the vulnerability does not exist regardless of pattern shape.

### 4.1 What this repository actually does (observations)

The following are facts observed **in this checkout**, kept separate from the external engine guarantees in §4.2:

- **Primary engine — `go-re2`.** **865 production** detector `.go` files import `regexp "github.com/wasilibs/go-re2"` (plus **2 test** files: `pkg/detectors/azure_storage/storage_integration_test.go` and `pkg/detectors/detectors_test.go`) — **867 total**. The dependency is pinned at `github.com/wasilibs/go-re2 v1.9.0` ([go.mod:L100]).
- **Secondary engine — Go stdlib `regexp`.** Exactly **3 production** detectors use the standard library instead: `pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go` ([spv2.go:L7]), `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go` ([azure_cosmosdb.go:L13]), and `pkg/detectors/jdbc/jdbc.go` ([jdbc.go:L8]).
- **The WASM RE2 variant is what runs.** The project `Dockerfile` builds with `CGO_ENABLED=0`; with cgo disabled, `go-re2` runs RE2 as a **WebAssembly module** hosted by the pure‑Go `wazero` runtime (`github.com/tetratelabs/wazero v1.9.0`, [go.mod:L285]). This is visible in the CPU profile as `runtime._ExternalCode` (the WASM sandbox is opaque to Go's profiler — §7.5).
- **A backtracking engine is present, but it never compiles a detector pattern.** `github.com/dlclark/regexp2 v1.4.0` appears as an **`// indirect`** dependency ([go.mod:L187]) and is imported by **0 files under `pkg/detectors/` or `pkg/engine/`** — it never compiles a detector pattern and **never appears in the CPU profile** of a real scan (§7.5). It is **not**, however, confined to our test harness: it is **linked into the production binary** and is *reachable* through the terminal‑UI dependency chain `pkg/tui/common` → `charmbracelet/glamour` → `alecthomas/chroma/v2` → `dlclark/regexp2` (confirmed by `go mod why` and `go version -m`). Our out‑of‑tree engine‑contrast harness (§7.6) additionally drives it directly to show what a vulnerable engine looks like. **Neither fact changes the filesystem‑scan verdict** — the mechanism and the associated advisory are detailed in §4.2.1.

### 4.2 Why that is ReDoS‑safe (engine safety contracts — external)

These are the documented guarantees of the engines above, cited to primary sources and kept distinct from the repo observations:

- **RE2** is explicitly designed to accept regular expressions from untrusted input without risk of blow‑up: it forbids backtracking and simulates a finite automaton, guaranteeing that a search runs in time **linear** in the length of the input. (Google RE2 project documentation — <https://github.com/google/re2/wiki/WhyRE2>.)
- **`go-re2`** is a drop‑in replacement for the standard `regexp` package that, by default, packages RE2 as a WebAssembly module executed by the pure‑Go `wazero` runtime — usable regardless of cgo availability. Its documentation also notes that for *small* inputs/expressions it is *slower* than the standard library (a constant‑factor overhead from the WASM boundary), which explains the scan's constant factor but has nothing to do with algorithmic complexity. (Library documentation — <https://github.com/wasilibs/go-re2>, <https://pkg.go.dev/github.com/wasilibs/go-re2>.)
- **Go's standard‑library `regexp`** is RE2‑derived and carries the same linear‑time guarantee: its documentation states matching runs in time linear in the size of the input, and it deliberately does **not** implement backtracking. (Go package documentation — <https://pkg.go.dev/regexp>; background: <https://swtch.com/~rsc/regexp/>.)

**On "backtracking" in the Go standard library — a precise correction.** Go's `regexp` *does* contain a routine literally named `backtrack` (`regexp.(*Regexp).backtrack` / `tryBacktrack`), and it appears — at **~1.5 % cumulative** — in our CPU profile (§7.5). This is **not** PCRE‑style catastrophic backtracking. It is a **bounded bit‑state backtracker**: before using it, the engine checks `shouldBacktrack(prog)`, which only permits it for small programs (`maxBacktrackProg = 500` instructions), and it allocates a *visited* bit‑vector of `(len input) × (len prog)` bits capped at `maxBacktrackVector = 256 * 1024`, guaranteeing it **never revisits a (position, instruction) state** and therefore still runs in **time linear in the input** (Go source `src/regexp/backtrack.go`). So the accurate statement is: **Go's engine performs *no unbounded/catastrophic* backtracking and retains a linear‑time guarantee** — not the looser "it never backtracks," and not the earlier mischaracterisation of these frames as a "one‑pass executor" (the one‑pass executor is a *separate* code path).

### 4.2.1 The bundled `regexp2` and advisory GHSA‑wq9v‑j77v‑qr26 (does *not* change the filesystem verdict)

For completeness — and because a naïve dependency scan will flag it — the **backtracking** engine `github.com/dlclark/regexp2 v1.4.0` is present in the module graph and **compiled into the production binary**. Its reachability, the associated advisory, and the reason it is nonetheless irrelevant to this assessment:

- **Reachability (observed).** `go mod why -m github.com/dlclark/regexp2` resolves the chain `…/pkg/tui/common` → `github.com/charmbracelet/glamour/ansi` → `github.com/alecthomas/chroma/v2` → `github.com/dlclark/regexp2`, and `go version -m /tmp/trufflehog` lists `dep github.com/dlclark/regexp2 v1.4.0`, `github.com/alecthomas/chroma/v2 v2.8.0`, and `github.com/charmbracelet/glamour v0.7.0`. So it is a real, linked, production dependency — **not** a test‑only import.
- **Known advisory.** `regexp2 < 2.3.0` is subject to **GHSA‑wq9v‑j77v‑qr26** (HIGH, CVSS 7.5): a crafted pattern using a large repetition count `{m}` over a zero‑width subexpression can force excessive memory allocation, and `regexp2`'s `MatchTimeout` does **not** bound that allocation. The bundled **v1.4.0** predates the **2.3.0** fix, so the *library* is technically affected.
- **Why it does not change the filesystem‑scan verdict (mechanism).** The advisory — like ReDoS generally — requires the attacker to control the **pattern**. On the scan path, attacker‑committed bytes are the **haystack**, never the pattern: every detector pattern is a trusted compile‑time constant compiled by RE2‑lineage engines (§4.1). `regexp2` is reached **only** through Chroma's syntax‑highlighting lexers inside the interactive TUI, where Chroma compiles its own **trusted, fixed lexer patterns** — and it does so in **`regexp2.RE2` (non‑backtracking) mode** (`alecthomas/chroma/v2@v2.8.0/regexp.go:333` → `regexp2.Compile(pattern, regexp2.RE2)`), not the vulnerable default. Moreover the `filesystem` subcommand **never invokes the TUI**: the TUI is gated on `isatty.IsTerminal(os.Stdout.Fd()) && (len(os.Args) <= 1 || os.Args[1] == analyzeCmd.FullCommand())` ([main.go:L280]), which `trufflehog filesystem …` does not satisfy. So on the code path this assessment measures, `regexp2` is never constructed and never runs — consistent with its total absence from the CPU profile (§7.5).
- **Recommendation (operational, not a code change).** Independently of ReDoS, upgrading the transitive `regexp2` to ≥ 2.3.0 (via a newer `chroma`/`glamour`) would clear the advisory from a dependency scan. This is recorded as an observation only; per the read‑only scope, no source is modified here.

### 4.3 Empirical confirmation

- **Linear size sweep (§7.4):** every input class — including the nested‑quantifier adversarial ones — doubles in time when the input doubles (measured doubling ratios cluster at ~2.0). No polynomial or exponential term appears.
- **Engine contrast (§7.6):** on the archetypal evil pattern `^(a+)+$` against `"a"×N + "!"`, the two engines TruffleHog uses stay in the **microsecond** range independent of `N`, while `dlclark/regexp2` (backtracking) explodes from 6 ms (N=16) to a 10 s timeout (N≥28). The vulnerability is real — but only for an engine TruffleHog does not use.

---

## 5. Q3 — Which detector patterns, if any, can be exploited?

**Direct answer: None can be exploited for catastrophic (super‑linear) blow‑up.** A small set of patterns *contain* the nested‑quantifier *shape* an attacker would target, and we benchmarked the highest‑risk ones directly; every one runs in linear time and completes in sub‑second (or low‑second) time on 8 MiB of purpose‑built adversarial input.

### 5.1 Semantic candidate inventory (not a lexical grep)

A naïve `grep` for the tokens `)*` or `)+` across the Go source is **misleading**: it matches ordinary Go slice/arithmetic expressions and character‑class text, not regex group‑repetition. To enumerate *real* candidates we searched **only inside pure compiled regex literals** — `regexp.MustCompile(\`…\`)` patterns — for a *genuine* group‑repetition `)*`/`)+`, after discarding matches that are merely literal `)`, `*`, or `+` characters *inside a character‑class* (e.g. `[…()*+…]`). Across all **845** detector directories, exactly **6 production detectors** contain a genuine group‑repetition `)*`/`)+` (rows 1, 3, 4, 6, 7, 8 below). To those we add the **2** highest‑risk *bounded*‑quantifier detectors (`uri` and `azure_entra` v1, rows 2 and 5 — large overlapping character classes governed by `{0,50}`/`{3,50}`/`.{0,80}` quantifiers, the next‑most‑plausible ReDoS shape), for a total of **8 candidate patterns**. Two further detectors — `jiratoken` ([jiratoken.go:L33], v1 and v2: `(?:[a-zA-Z0-9-]{1,24}\.)+`) and `generic` ([generic.go:L25]: `([\w]+[/])+`) — also contain a group‑repetition, but are **excluded by the strict method** because each builds its pattern by string concatenation (`detectors.PrefixRegex(...)` prepended to a raw literal) or from a `[]string` slice rather than a single pure `MustCompile` literal; counting them under a broader reading would raise the genuine‑group‑repetition tally to **8** but changes no conclusion:

| # | Detector (file:line) | Risky quantifier sub‑expression (shape class) | Benchmarked? |
|---|----------|------------------------------------------------------|--------------|
| 1 | `mongodb` ([mongodb.go:L32]) | group‑rep `(?:,[-.%\w]+(?::\d{1,5})?)*` and `(?:&(?:amp;)?\w+=[\w@/.$-]+)*` | **Yes** — canonical scan |
| 2 | `uri` ([uri.go:L33]) | **bounded** `{0,50}`/`{3,50}` classes + trailing group; required `@` (no `)*`/`)+`) | **Yes** — canonical scan |
| 3 | `azuresastoken` ([azuresastoken.go:L32]) | group‑rep `(?:/[a-zA-Z0-9._-]+)*` | **Yes** — canonical scan |
| 4 | `databrickstoken` ([databrickstoken.go:L27]) | group‑rep `(?:\.[a-z0-9-]+)*` | **Yes** — canonical scan |
| 5 | `azure_entra` v1 ([spv1.go:L35]) | **bounded** `.{0,80}` around a bounded class (go‑re2; no `)*`/`)+`) | **Yes** — canonical scan |
| 6 | `coinbase_waas` ([coinbase_waas.go:L35]) | group‑rep `(?:[a-zA-Z0-9+/]+={0,2}(?:\r|\n|\\+r|\\+n))+` (`privKeyPat` base64 body) | Source‑reviewed only |
| 7 | `docker` auth config ([docker_auth_config.go:L51]) | group‑rep `(?:\s|\\+[nrt])*` whitespace repetition and lazy `(?:…)+?` auth‑block repetition | Source‑reviewed only |
| 8 | `robinhoodcrypto` ([robinhoodcrypto.go:L36]) | group‑rep `(?:[A-Za-z0-9+\/]{4})*` (`privKeyBase64Pat` base64 body) | Source‑reviewed only |

**Timed vs. source‑reviewed‑only — an honest distinction.** We drove candidates 1–5 through the **canonical** `trufflehog filesystem` scan on maximally‑adversarial 8 MiB inputs (§7.2, §7.5), plus the two stdlib‑engine detectors `jdbc` and `azure_cosmosdb` (§7.2). Candidates 6–8 were **reviewed in source but not individually benchmarked**; we do not claim measured times for them. This is acceptable because the ReDoS verdict is an **engine‑level** property, not a per‑pattern one: all eight compile on RE2‑lineage engines (§4), whose linear‑time guarantee holds for *every* pattern regardless of shape. Benchmarking the highest‑risk five is corroboration, not the basis of the conclusion.

### 5.2 Measured results for the timed candidates (8 MiB, medians)

| Detector | Adversarial construct | Matches? | scan_duration (median) | Findings |
|----------|-----------------------|----------|------------------------|----------|
| `mongodb` `connStrPat` | nested‑star host `,a`×480 (fits ±512 span) | **Yes** | **1103.53 ms** | 1,623 |
| `uri` `keyPat` | 50‑char class + `:` + 900 chars, **no** `@` | No (near‑miss) | **109.70 ms** | 0 |
| `azuresastoken` `urlPat` | `.blob.core.windows.net/` + `/a`×980 (fits ±1024) | Yes | **367.97 ms** | 0 |
| `databrickstoken` `domain` | `dapi ` + `.a`×980 + bad TLD (fits ±1024) | No (near‑miss) | **128.32 ms** | 0 |
| `azure_entra` (7 Azure dets) | `.{0,80}` bait | No | **1232.3 ms** (n=7) | 0 |
| `jdbc` (**stdlib** engine) | `jdbc:…` `{0,512}` maxed | Yes | **605.62 ms** | 20,796 |
| `azure_cosmosdb` (**stdlib** engine) | account‑URL bait (7 dets) | No | **3099.24 ms** | 0 |

Every timed candidate completes in **≤ ~3.1 s** on 8 MiB, and the size sweep (§7.4) shows each grows **linearly**. The `mongodb` host construct **matches** (1,623 findings) — so it is a *successful‑match stress test*, not a "late‑failure catastrophic‑backtracking" case; the guaranteed **non‑matching** near‑misses (`uri` no‑`@`, `mongodb` no‑`@`) are the cheapest of all (~110 ms, ~1.2× baseline), which is the exact opposite of a backtracking signature (a backtracker is *slowest* on non‑matching input).

---

## 6. Q4 — How much slower can a scan be made vs. normal files of equivalent size?

**Direct answer:** Controlling for input length, a ReDoS‑*structured* (non‑matching) file is only **~1.2×** slower than an equivalent‑size prefilter‑miss baseline — essentially free. The **maximum** amplification we could manufacture is **~62×**, produced not by any regex blow‑up but by a file of **unique synthetic (unverified) matches** that forces linear match‑extraction and finding‑emission work. All amplification is **linear and bounded**.

### 6.1 Ratios at 8 MiB (vs. the proven‑keyword‑free baseline, 89.34 ms)

| Input (8 MiB each) | What it exercises | scan_duration (median) | **× baseline** |
|--------------------|-------------------|------------------------|----------------|
| `baseline_miss` (proven prefilter MISS, §7.1) | regex **never runs** | **89.34 ms** | **1.00×** (control) |
| `patho_uri_noat` (evil nested‑quantifier, **non‑match**) | RE2 scans + fails | 109.70 ms | **1.23×** |
| `kw_nomatch` (keyword present, 0 matches) | RE2 scans every chunk, 0 extract | 139.81 ms | **1.56×** |
| `patho_mongodb_host` (nested‑star, **successful match**) | RE2 scans + extracts + `FromData` | 1103.53 ms | **12.35×** |
| `dense_uri` (valid `https://` URIs, **match‑dense**) | RE2 scans + extracts + `url.Parse` per match | 1962.13 ms | **21.96×** |
| `match_unique` (unique synthetic matches, **finding‑flood**) | max extraction + result build + output | 5558.10 ms (n=7) | **62.2×** ← max |

> **Arithmetic & aggregation (Finding #10 corrected).** Every figure above is a **median** (n = 3, or **n = 7** for the noisy `match_unique` series), with the full raw run series shown in §7.2 and dispersion reported there. The **maximum median amplification is 62.2×** (the earlier draft's "≈28×/≈34.7×" understated it and mixed aggregation methods). We adopt the **n = 7** value (62.2×) as the headline for `match_unique` because that series exceeded the 25 % dispersion threshold and was re‑run at higher n; the complete seven‑run series that yields it is printed verbatim in §7.2 — `raw(s): 5.180, 6.267, 5.542, 5.788, 4.943, 5.558, 5.717` → median **5558.1 ms** ÷ **89.34 ms** baseline = **62.2×** *(derived)*. A noisier three‑run aggregation of the same condition lands lower (≈55–56× — e.g. an independent n = 3 recapture gave `7.530 / 4.550 / 5.008 s` → median 5.008 s ÷ 90.04 ms = 55.6×), which is exactly why the higher‑n value is used as the headline. We do **not** subtract `kw_nomatch` from `match` and call the remainder "post‑processing time" — the pipeline does not permit that clean isolation (see §6.3).

### 6.2 Why the "match‑dense" attack is the real Q4 story, and its limits

- **Identical matches still amplify — the per‑chunk map limits *findings*, not *parse cost*.** A file repeating one connection string produces only **~820** *emitted* findings — the detector's **local, per‑`FromData`‑call** `uniqueMatches` map ([mongodb.go:L48], [mongodb.go:L81]) collapses identical strings *within* each chunk, and the ~820 chunks each emit one — but it still scans in **~3.0 s** at 8 MiB (n = 7 median; §7.2) — **~34× the `baseline_miss` control**. The reason: `mongodb.FromData` runs `connStrPat.FindAllStringSubmatch` and then a `url.Parse` (+ query re‑encode + `String()`) on **every raw match** ([mongodb.go:L49], [mongodb.go:L58], [mongodb.go:L79]) — on the order of the file's ~131,072 repeated lines — *before* that map de‑duplicates the emitted results. So naïve identical repetition is **not** cheap.
- **Unique matches amplify *further* — also linearly.** Making each match unique means the per‑chunk `uniqueMatches` map cannot merge any of them, so every line becomes a distinct emitted finding: **201,431 findings / 5.56 s at 8 MiB**, **402,901 / 10.27 s at 16 MiB** — a clean doubling (~0.66 s/MiB). That is only **~2×** the identical‑repetition case (~0.375 s/MiB) at the same size — the *same order of magnitude* — because both are dominated by the per‑raw‑match `url.Parse` post‑processing that de‑duplication does **not** save; unique matches merely add distinct‑finding emission on top. This is the residual CI‑availability concern of Q1, and it needs **no real secret** (verification is off, so every credential‑*shaped* line is reported as `unverified_secrets`).
- **The engine's cross‑result cache does not change this, and chunk overlap can *add* findings.** Separately from the detector‑local map, the engine keeps a cross‑result `dedupeCache` — an LRU (`cacheSize = 512`, [engine.go:L491]–[engine.go:L493], `hashicorp/golang-lru/v2` [engine.go:L18]). It is **not** a de‑duplicator an attacker "defeats": its key includes per‑line source metadata ([engine.go:L1216]) and it **deliberately preserves same‑decoder duplicates** (it skips a result only when the cached entry's decoder differs, or the source is Postman — [engine.go:L1217]–[engine.go:L1218]), so distinct‑line findings are never merged by it. Moreover, the chunker's **3 KiB peek overlap** ([chunker.go:L14]–[chunker.go:L18]) means a secret straddling a chunk boundary is scanned by *two* chunks and can be emitted **twice** — empirically confirmed: a single secret placed at the `ChunkSize` boundary (byte offset 10,240) yields **2** findings, one at offset 10,239 yields **1**, and one at 20,480 yields **2**. This is a small *additive* effect, not a super‑linear one.
- **It is bounded, not a hang.** Time is strictly proportional to file size; there is no point at which a fixed input causes unbounded work.

### 6.3 Cost attribution — end‑to‑end pipeline deltas, reconciled with pprof (Finding #8)

The comparison of conditions is best read as **end‑to‑end incremental deltas of the whole pipeline**, not as an experiment that isolates "regex vs. post‑processing" (changing the input also changes Aho matches, span processing, submatch extraction, map/dedup, result construction, line‑number computation, and output volume simultaneously). Reconciled with the CPU profile (§7.5), the dominant costs on a match‑dense scan are:

1. **RE2 matching *and submatch extraction*, executed in the WASM sandbox** — `runtime._ExternalCode` at **54.15 % flat** (reached through `go-re2/internal.(*lazyFunction).callWithStack` → `wazero … callWithStack`, the Go→WASM boundary for `go-re2`; see the embedded `-peek` in §7.5). This is the single largest cost and it is **linear** in input/match volume. (Note: this *includes* extraction, so it is inaccurate to say "regex execution is not the cost" — it is the largest cost.)
2. **Output / finding‑flood** — `notifierWorker` **21.72 % cum** → `PlainPrinter.Print` **16.26 % cum** → `os.File.Write` **5.15 % cum**. Formatting and writing hundreds of thousands of findings is a first‑class cost, directly corroborating the Q1 finding‑flood concern.
3. **Per‑match detector post‑processing** — `mongodb.Scanner.FromData` **8.65 % cum**, dominated by `url.Parse` (640 ms), `connUrl.String()` (420 ms), and query re‑encoding — all **linear per match**.

### 6.4 A note on `--print-avg-detector-time` (metric semantics, Finding #9)

TruffleHog's `--print-avg-detector-time` reports, per detector, the **arithmetic mean of `time.Since(start)`** over invocations that *returned at least one result* — the elapsed time is appended only on result‑returning calls at [pkg/engine/engine.go:L1093] (`elapsed := time.Since(start)`), [pkg/engine/engine.go:L1103] (`append`), [pkg/engine/engine.go:L1104] (`Store`), and displayed by `printAverageDetectorTime` ([main.go:L1021]–[main.go:L1029]). The tool's **own** output line states this explicitly: *"Average detector time is the measurement of average time spent on each detector when results are returned."* ([main.go:L1024]). These are therefore **per‑result‑returning averages**, **not** additive shares of the total scan. It is therefore incorrect to add or subtract them (e.g. "MongoDB 571 ms + URI 130 ms") to account for a multi‑second scan; we report them only as per‑call averages and rely on the CPU profile (§7.5) for actual whole‑scan CPU attribution.

The verbatim aggregate footer that `--print-avg-detector-time` prints (one line per detector), captured on four keyword‑bearing 8 MiB inputs, is:

```
# match_unique (unique valid MongoDB URIs; 201,431 results):
Average detector time is the measurement of average time spent on each detector when results are returned.
MongoDB: 794.816358ms          (scan_duration 5.246079931s)

# match_dense (one identical valid MongoDB URI x131,072; 820 emitted):
MongoDB: 163.475369ms          (scan_duration 2.329004039s)

# patho_mongodb_host (nested-STAR "evil" MongoDB pattern; 1,623 results):
MongoDB: 9.013853ms            (scan_duration 1.123193968s)

# dense_uri (valid https:// URIs; 820 emitted):
URI: 146.513857ms              (scan_duration 1.795834695s)
```

The ordering is itself a Q3 result: the **nested‑star "evil" pattern** (`patho_mongodb_host`, **9.01 ms** average) is the **cheapest** of the four — roughly two orders of magnitude below the finding‑flood case — because RE2 matches it in linear time. The expensive averages belong to the *valid‑match‑dense* inputs, whose cost is per‑match `url.Parse` / result‑building (§7.5 `-list`), **not** regex backtracking. (Per the semantics above, these are per‑result‑returning wall‑clock means inflated by 128‑worker contention on 4 cores, and are **not** additive into the scan total — e.g. `MongoDB: 794.8 ms` × 820 calls ≠ the 5.25 s scan.)


---

## 7. Q5 — Evidence (timing measurements + CPU profiling)

**Yes — both required evidence types are provided:** timing measurements (§7.1–§7.4, with per‑detector `--print-avg-detector-time` output in §6.4) **and** CPU‑profiling data (§7.5, a `go tool pprof` capture of the canonical `--profile` server), with an out‑of‑tree engine‑contrast benchmark as labeled corroboration (§7.6).

**How to read the blocks below (raw vs. derived).** Blocks introduced as *"verbatim"* are the unmodified bytes of a captured log or `pprof` view (any `<-` annotation is called out explicitly and lives *outside* the verbatim fence). The per‑condition timing blocks report the **`scan_duration` summary line** that TruffleHog itself emits at the end of each run — extracted from each run's complete log with `grep 'finished scanning'`. That is the tool's own reported metric; it is **not** the multi‑megabyte finding stdout, which for a finding‑flood run is far too large to embed (e.g. `match_unique` at 8 MiB prints all 201,431 findings, tens of MiB of text) and is instead summarized by its `unverified` count. All medians, ratios, and per‑MiB slopes are **derived** from those raw `scan_duration` values and are labeled *(derived)*. Environment: `go1.24.3`, host `nproc = 4` / `runtime.NumCPU() = 128`, canonical binary built `CGO_ENABLED=0`. Each condition ran `--no-verification --no-update`. Every input file is exactly its stated power‑of‑two size in bytes (8 MiB = 8,388,608 bytes → 820 chunks at `TotalChunkSize = 13 KiB`).

### 7.1 Prefilter verification — proving the baseline (Finding #5)

Output of the out‑of‑tree helper (source in §9.2) that imports TruffleHog's own `DefaultDetectors()` + Aho‑Corasick core and reports how many detectors each input would trigger:

```
=== prefilter verification of every input (TruffleHog's own Aho-Corasick core) ===

--- inputs/baseline_miss.txt ---
file=inputs/baseline_miss.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=0
RESULT: PREFILTER MISS - zero detectors triggered; no detector regex would run on this file.

--- inputs/kw_nomatch.txt ---
file=inputs/kw_nomatch.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=2
RESULT: PREFILTER HIT - the following detectors would run:
  HIT MongoDB
  HIT URI

--- inputs/match_dense.txt ---
file=inputs/match_dense.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT MongoDB

--- inputs/patho_mongodb_host.txt ---
file=inputs/patho_mongodb_host.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT MongoDB

--- inputs/patho_mongodb_userpass.txt ---
file=inputs/patho_mongodb_userpass.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT MongoDB

--- inputs/patho_uri_noat.txt ---
file=inputs/patho_uri_noat.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT URI

--- inputs/patho_uri_atspam.txt ---
file=inputs/patho_uri_atspam.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT URI

--- inputs/patho_databricks.txt ---
file=inputs/patho_databricks.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=1
RESULT: PREFILTER HIT - the following detectors would run:
  HIT DatabricksToken

--- inputs/patho_azuresas.txt ---
file=inputs/patho_azuresas.txt bytes=8388608 total_detectors=831 total_keywords=914 prefilter_detector_hits=3
RESULT: PREFILTER HIT - the following detectors would run:
  HIT AzureSasToken
  HIT AzureStorage
  HIT URI
```

`baseline_miss` is a **verified** prefilter MISS (0 detectors) — so its scan time is the true "regex never runs" control. Every adversarial input verifiably HITS its target detector.

### 7.2 Crafted vs. equivalent‑size, at 8 MiB (3 runs each, complete output)

```
CONDITION: baseline_miss   (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=89.336339ms    chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=88.857889ms    chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=91.629337ms    chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: kw_nomatch   (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=137.045059ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=141.94542ms    chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=139.806683ms   chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: match_dense (identical strings; noisy — n=7 median below)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=2.770462061s   chunks=820    bytes=10903552  verified=0    unverified=820
  run2: scan_duration=3.615154747s   chunks=820    bytes=10903552  verified=0    unverified=820
  run3: scan_duration=2.853991632s   chunks=820    bytes=10903552  verified=0    unverified=820

CONDITION: dense_uri (valid https:// URIs, one per line — Q4 dense-VALID-URI control, URI detector)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=1.962133403s   chunks=820    bytes=10903552  verified=0    unverified=820
  run2: scan_duration=1.523652521s   chunks=820    bytes=10903552  verified=0    unverified=820
  run3: scan_duration=1.999527011s   chunks=820    bytes=10903552  verified=0    unverified=820

CONDITION: patho_mongodb_host  (nested-star host, MATCHES)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=1.099791037s   chunks=820    bytes=10903552  verified=0    unverified=1623
  run2: scan_duration=1.111743563s   chunks=820    bytes=10903552  verified=0    unverified=1623
  run3: scan_duration=1.103531172s   chunks=820    bytes=10903552  verified=0    unverified=1623

CONDITION: patho_mongodb_userpass  (no '@', NON-match)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=117.516915ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=111.80568ms    chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=116.35372ms    chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: patho_uri_noat  (no '@', NON-match)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=108.226808ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=111.024869ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=109.69828ms    chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: patho_uri_atspam  ('a:@' spam)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=109.138012ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=112.517687ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=110.44925ms    chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: patho_databricks  (nested-star domain, NON-match)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=127.630783ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=128.319998ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=136.381997ms   chunks=820    bytes=10903552  verified=0    unverified=0

CONDITION: patho_azuresas  (3 detectors hit, MATCHES)  (flags: --no-verification --no-update )  tag=default
  run1: scan_duration=369.693927ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run2: scan_duration=367.968105ms   chunks=820    bytes=10903552  verified=0    unverified=0
  run3: scan_duration=362.710436ms   chunks=820    bytes=10903552  verified=0    unverified=0
```

**Stdlib‑engine detectors and the 7‑detector Azure bundle (3 runs @ 8 MiB):**

```
--- patho_jdbc (STDLIB regexp engine, jdbc:… {0,512} maxed, MATCHES) ---
  run1: scan_duration=605.616497ms   unverified=20796
  run2: scan_duration=602.111729ms   unverified=20796
  run3: scan_duration=609.529109ms   unverified=20796

--- patho_azentra (go-re2 spv1 + Azure detectors) ---
  run1: scan_duration=1.165946911s   unverified=0
  run2: scan_duration=1.590042539s   unverified=0
  run3: scan_duration=1.335493938s   unverified=0

--- patho_cosmos (STDLIB regexp azure_cosmosdb + detectors) ---
  run1: scan_duration=3.094741982s   unverified=0
  run2: scan_duration=3.161710545s   unverified=0
  run3: scan_duration=3.099237136s   unverified=0
```

**`match_unique` (unique synthetic matches — the finding‑flood worst case), n = 7 stable series:**

```
 1MiB match_unique: n=7 median=663.4ms  min=549.5  max=715.4  dispersion=25.0% unverified=25159
     raw(s): 0.591, 0.715, 0.663, 0.714, 0.665, 0.549, 0.650
 2MiB match_unique: n=7 median=1401.0ms min=1302.0 max=1446.0 dispersion=10.3% unverified=50320
     raw(s): 1.367, 1.401, 1.371, 1.403, 1.446, 1.302, 1.417
 4MiB match_unique: n=7 median=2792.6ms min=2657.2 max=3861.1 dispersion=43.1% unverified=100697
     raw(s): 2.657, 2.947, 3.861, 2.769, 2.735, 3.035, 2.793
 8MiB match_unique: n=7 median=5558.1ms min=4942.5 max=6267.5 dispersion=23.8% unverified=201431
     raw(s): 5.180, 6.267, 5.542, 5.788, 4.943, 5.558, 5.717
16MiB match_unique: n=7 median=10267.9ms min=9716.5 max=12316.0 dispersion=25.3% unverified=402901
     raw(s): 10.268, 12.316, 10.078, 11.246, 9.716, 10.167, 10.725
```

`patho_azentra` also exceeded the 25 % dispersion threshold and was re‑run at n = 7 (multi‑detector + GC noise on 4 cores): `median=1232.3ms min=689.9 max=1754.0 dispersion=86.4%; raw(ms): 689.9, 1232.3, 1178.5, 1754.0, 1160.5, 1424.9, 1238.1`. It remains bounded and shows no blow‑up.

`match_dense` (one 64‑byte valid connection string repeated ×131,072) likewise exceeded the 25 % dispersion threshold and was re‑run at n = 7: `median=3001.4ms min=2126.2 max=3822.0 dispersion=56.5%; raw(s): 2.126, 2.769, 2.803, 3.001, 3.183, 3.497, 3.822`. Its 820 *emitted* findings (≈ one per chunk, collapsed by the detector's **local per‑`FromData`** `uniqueMatches` map — [mongodb.go:L48], [mongodb.go:L81], not the engine LRU) hide **~131,072 raw matches** — one per repeated line — and `mongodb.FromData` runs a `url.Parse` on **every** raw match *before* that map ([mongodb.go:L49], [mongodb.go:L58]). At **~0.375 s/MiB** (≈ 3001 ms ÷ 8 MiB) it is the **same order of magnitude** as `match_unique` (~0.66 s/MiB), grows linearly, and is **~34× the `baseline_miss` control (89.34 ms) and ~22× `kw_nomatch` (139.81 ms)** — i.e. far above baseline, *not* "barely above" it. (The earlier draft's 135.84 ms was non‑reproducible: it wrongly showed `match_dense` as *faster* than `kw_nomatch`, which is impossible since `match_dense` performs a strict *superset* of `kw_nomatch`'s work — the identical RE2 scan of every chunk **plus** ~131,072 `url.Parse` calls.)

### 7.3 Worst‑case single regex call — `--scan-entire-chunk` (Finding #4)

By default the prefilter hands each detector only a **±512** (or **±1024** for MultiPart) byte span, not the whole ~13 KiB chunk. Re‑running the adversarial inputs with the hidden `--scan-entire-chunk` flag feeds the **entire chunk** to each regex — the absolute worst case for a single call. The result is **statistically identical** to the default, proving RE2's linear guarantee (not the span limit) is the real protection:

```
--- patho_uri_noat (--scan-entire-chunk) ---        default was 109.70 ms
  run1: 107.131245ms   run2: 108.721507ms   run3: 109.294364ms   unverified=0
--- patho_uri_atspam (--scan-entire-chunk) ---       default was 110.45 ms
  run1: 111.844353ms   run2: 112.238738ms   run3: 109.174245ms   unverified=0
--- patho_mongodb_userpass (--scan-entire-chunk) --- default was 116.35 ms
  run1: 114.567362ms   run2: 126.70675ms    run3: 120.260416ms   unverified=0
--- patho_mongodb_host (--scan-entire-chunk) ---     default was 1103.53 ms
  run1: 1.111543278s   run2: 1.132660035s   run3: 1.108265677s   unverified=1622
--- patho_databricks (--scan-entire-chunk) ---       default was 128.32 ms
  run1: 127.896715ms   run2: 128.917857ms   run3: 127.380749ms   unverified=0
--- patho_azuresas (--scan-entire-chunk) ---         default was 367.97 ms
  run1: 377.407668ms   run2: 379.378149ms   run3: 375.912174ms   unverified=0
```

### 7.4 Linearity size sweeps (1 / 2 / 4 / 8 / 16 MiB, medians + doubling ratios)

Each doubling of input size roughly **doubles** the time — the signature of **linear** complexity and the definitive absence of ReDoS. (Findings shown for matching series; they double too.)

```
-- baseline_miss (prefilter MISS) --            -- patho_uri_noat (evil nested-q, NON-match) --
   1MiB   14.71ms                                  1MiB   17.33ms
   2MiB   24.41ms  (x1.66)                          2MiB   29.69ms  (x1.71)
   4MiB   45.10ms  (x1.85)                          4MiB   54.98ms  (x1.85)
   8MiB   89.22ms  (x1.98)                          8MiB  107.78ms  (x1.96)
  16MiB  178.95ms  (x2.01)                         16MiB  205.45ms  (x1.91)
   => ~11.2 ms/MiB                                  => ~12.8 ms/MiB  (only ~1.15x baseline)

-- patho_mongodb_host (successful match) --     -- match_unique (finding-flood, n=7) --
   1MiB  144.30ms  (findings=206)                   1MiB   663.4ms  (findings=25159)
   2MiB  279.96ms  (x1.94, 410)                     2MiB  1401.0ms  (x2.11, 50320)
   4MiB  557.92ms  (x1.99, 820)                     4MiB  2792.6ms  (x1.99, 100697)
   8MiB 1107.46ms  (x1.98, 1623)                    8MiB  5558.1ms  (x1.99, 201431)
  16MiB 2220.32ms  (x2.00, 3260)                   16MiB 10267.9ms  (x1.85, 402901)
   => ~138 ms/MiB                                    => ~640-660 ms/MiB
```

All four series are cleanly linear (doubling ratios cluster at ~2.0). There is **no** super‑linear term at any size.

> The sweep is an **independent measurement batch** from the 8 MiB conditions table in §7.2, so its 8 MiB rows differ by sub‑percent run‑to‑run noise: e.g. `baseline_miss` 89.22 ms here vs. 89.34 ms in §7.2; `patho_mongodb_host` 1107.46 ms here vs. 1103.53 ms in §7.2. The Q4 ratios in §6.1 are computed **within** the §7.2 conditions batch (so numerator and denominator share the same batch); the sweep exists only to establish the *scaling law*, not to re‑derive those ratios.

**Complete per‑run sweep series (n = 3 at every size; medians and `log2` slope over 1→16 MiB are *derived*).** A `log2` slope of `1.0` is perfectly linear; a super‑linear (ReDoS) blow‑up would drive it well above 1.0 and grow with size. Every series stays at ~0.9–1.0:

```
baseline_miss (prefilter MISS):
   1 MiB:  14.480, 14.305, 15.317 ms   median  14.480
   2 MiB:  24.266, 23.998, 24.268 ms   median  24.266   (x1.68)
   4 MiB:  44.616, 45.434, 43.593 ms   median  44.616   (x1.84)
   8 MiB:  89.012, 88.389, 88.485 ms   median  88.485   (x1.98)
  16 MiB: 168.798,169.270,167.900 ms   median 168.798   (x1.91)     => log2-slope 0.8858

patho_uri_noat (evil nested-quantifier, NON-match):
   1 MiB:  16.366, 17.447, 16.445 ms   median  16.445
   2 MiB:  30.890, 30.153, 29.778 ms   median  30.153   (x1.83)
   4 MiB:  53.118, 55.744, 55.550 ms   median  55.550   (x1.84)
   8 MiB: 104.699,118.852,106.418 ms   median 106.418   (x1.92)
  16 MiB: 212.632,214.361,214.370 ms   median 214.361   (x2.01)     => log2-slope 0.9261

patho_mongodb_host (nested-STAR, successful match; findings double too):
   1 MiB: 158.771,144.899,145.882 ms   median 145.882   (findings=206)
   2 MiB: 281.775,287.275,283.785 ms   median 283.785   (x1.95, findings=410)
   4 MiB: 571.199,566.630,554.044 ms   median 566.630   (x2.00, findings=820)
   8 MiB:1107.291,1102.166,1110.440 ms  median1107.291   (x1.95, findings=1623)
  16 MiB:2274.158,2274.112,2416.033 ms  median2274.158   (x2.05, findings=3260)   => log2-slope 0.9906

match_unique (finding-flood; findings double too):
   1 MiB: 628.662,679.693,640.804 ms   median 640.804   (findings=25159)
   2 MiB: 910.792,1519.423,1264.052 ms  median1264.052   (x1.97, findings=50320)
   4 MiB:2284.748,2021.437,2516.126 ms  median2284.748   (x1.81, findings=100697)
   8 MiB:5712.214,5010.978,4623.697 ms  median5010.978   (x2.19, findings=201431)
  16 MiB:9078.248,10786.810,9120.337 ms median9120.337   (x1.82, findings=402901)  => log2-slope 0.9578
```

### 7.5 CPU profile (canonical `--profile` server)

Captured with the safe lifecycle in §9.5 while scanning a **56 MiB** (58,720,256‑byte) unique‑match file — deliberately sized so the scan runs **> 25 s**, keeping the entire bounded 20 s profiling window inside the active scan. Scan metadata (verbatim `finished scanning` line):

```
finished scanning  {"chunks": 5735, "bytes": 76335104, "verified_secrets": 0,
 "unverified_secrets": 1410214, "scan_duration": "34.228778881s",
 "trufflehog_version": "dev", "verification_caching":
 {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

`go tool pprof -top` over a bounded 20 s window (**Duration = 20.13 s, Total samples = 73.45 s = 364.93 % CPU ≈ 3.6 cores**, consistent with `nproc = 4`). Complete top‑25 by **flat**, **verbatim** (no annotations added inside the fence):

```
Duration: 20.13s, Total samples = 73.45s (364.93%)
Showing nodes accounting for 53.97s, 73.48% of 73.45s total
Dropped 710 nodes (cum <= 0.37s)
Showing top 25 nodes out of 154
      flat  flat%   sum%        cum   cum%
    39.77s 54.15% 54.15%     39.77s 54.15%  runtime._ExternalCode
        3s  4.08% 58.23%         3s  4.08%  internal/runtime/syscall.Syscall6
     1.54s  2.10% 60.33%      1.54s  2.10%  indexbytebody
     1.35s  1.84% 62.16%      1.35s  1.84%  runtime.memmove
     0.84s  1.14% 63.31%      3.03s  4.13%  bytes.Index
     0.77s  1.05% 64.36%      1.68s  2.29%  runtime.scanobject
     0.56s  0.76% 65.12%      0.56s  0.76%  runtime.memclrNoHeapPointers
     0.54s  0.74% 65.85%      1.06s  1.44%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.53s  0.72% 66.58%      0.53s  0.72%  runtime.nextFreeFast (inline)
     0.51s  0.69% 67.27%      0.58s  0.79%  runtime.casgstatus
     0.41s  0.56% 67.83%      0.41s  0.56%  runtime.(*mspan).base (inline)
     0.40s  0.54% 68.37%      1.54s  2.10%  internal/sync.(*Mutex).Lock (inline)
     0.39s  0.53% 68.90%     11.94s 16.26%  github.com/trufflesecurity/trufflehog/v3/pkg/output.(*PlainPrinter).Print
     0.38s  0.52% 69.42%      1.06s  1.44%  internal/sync.(*Mutex).Unlock (inline)
     0.38s  0.52% 69.94%      0.43s  0.59%  runtime.findObject
     0.37s   0.5% 70.44%      0.90s  1.23%  regexp.(*Regexp).tryBacktrack
     0.37s   0.5% 70.95%      0.53s  0.72%  runtime.fpTracebackPartialExpand
     0.36s  0.49% 71.44%      2.12s  2.89%  runtime.mallocgcSmallScanNoHeader
     0.26s  0.35% 71.79%      1.92s  2.61%  bytes.IndexByte (inline)
     0.24s  0.33% 72.12%      1.30s  1.77%  regexp.(*Regexp).backtrack
     0.24s  0.33% 72.44%      3.75s  5.11%  runtime.mallocgc
     0.21s  0.29% 72.73%      2.73s  3.72%  fmt.(*pp).doPrintf
     0.19s  0.26% 72.99%     15.95s 21.72%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).notifierWorker
     0.18s  0.25% 73.23%      0.41s  0.56%  encoding/json.checkValid
     0.18s  0.25% 73.48%      1.14s  1.55%  internal/sync.(*Mutex).lockSlow
```

Complete top by **cumulative** (the call‑tree view), **verbatim**:

```
      flat  flat%   sum%        cum   cum%
    39.77s 54.15% 54.15%     39.77s 54.15%  runtime._ExternalCode
         0     0% 54.15%     39.77s 54.15%  runtime._System
     0.19s  0.26% 54.40%     15.95s 21.72%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).notifierWorker
         0     0% 54.40%     15.95s 21.72%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startNotifierWorkers.func1
     0.03s 0.041% 54.45%     12.05s 16.41%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*PrinterDispatcher).Dispatch
     0.39s  0.53% 54.98%     11.94s 16.26%  github.com/trufflesecurity/trufflehog/v3/pkg/output.(*PlainPrinter).Print
     0.09s  0.12% 55.10%     11.64s 15.85%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectChunk
         0     0% 55.10%     11.64s 15.85%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectorWorker
         0     0% 55.10%     11.64s 15.85%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startDetectorWorkers.func1
     0.13s  0.18% 55.28%      6.35s  8.65%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mongodb.Scanner.FromData
         0     0% 55.28%      6.24s  8.50%  github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache.(*VerificationCache).FromData
     0.06s 0.082% 55.36%      5.11s  6.96%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).processResult
     0.02s 0.027% 55.38%      3.78s  5.15%  os.(*File).Write
```

**Annotation key (derived — my labels for the verbatim frames above, *not* part of `pprof` output):**

| Frame | flat / cum | What it is |
|---|---|---|
| `runtime._ExternalCode` | 54.15 % flat | RE2 executing inside the `wazero` WASM sandbox — **inferred**, see the `-peek` below |
| `engine.(*Engine).notifierWorker` | 21.72 % cum | Output pipeline dispatching 1.41 M findings |
| `output.(*PlainPrinter).Print` | 16.26 % cum | Formatting the finding‑flood |
| `detectChunk` / detector workers | 15.85 % cum | The detection path (Aho prefilter + go‑re2 calls) |
| `mongodb.Scanner.FromData` | 8.65 % cum | Per‑match `url.Parse` / result‑building |
| `os.(*File).Write` | 5.15 % cum | Writing findings to stdout |
| `bytes.Index` / `bytes.IndexByte` | 4.13 % / 2.61 % cum | Aho‑Corasick prefilter substring scans |
| `regexp.(*Regexp).backtrack` | 1.77 % cum | Go stdlib **bounded** bit‑state executor (the 3 stdlib detectors) |
| `wazevo.(*callEngine).callWithStack` | 1.44 % cum | Go→WASM boundary into RE2 |

**Interpretation (reconciled with Finding #8):** CPU is dominated by **linear RE2 matching + submatch extraction running in WASM** (`runtime._ExternalCode`, 54.15 % flat). Output/finding‑flood is the second cost (`notifierWorker` ~21.7 % cum). Per‑match `FromData` post‑processing is third (~8.65 % cum). **There is no catastrophic‑backtracking frame.**

**Why the RE2 attribution of `_ExternalCode` is an *inference*, and what grounds it (Finding #1).** `pprof` cannot see *inside* the WebAssembly sandbox: WASM execution surfaces as the opaque runtime leaf `runtime._ExternalCode`. The `-peek` below shows it is a **detached leaf** — its only caller is `runtime._System` and it has **zero callees** — so the profiler itself does **not** prove "this 54 % is RE2." That attribution is a **source/build‑backed inference**: the `CGO_ENABLED=0` build compiles `go-re2` to a WASM RE2 module run by `wazero` (§2, [go.mod:L100], [go.mod:L285]), and the *Go‑side* boundary is directly visible in the profile — `go-re2/internal.(*lazyFunction).callWithStack` (3.23 s cum) crosses into `wazero … callWithStack` immediately before control disappears into the sandbox. Raw `-peek` of the leaf and of that boundary, **verbatim**:

```
# go tool pprof -peek='runtime\._ExternalCode$'  (the WASM leaf — no callees)
                                            39.77s   100% |   runtime._System
    39.77s 54.15% 54.15%     39.77s 54.15%                | runtime._ExternalCode
```

```
# go tool pprof -peek='callWithStack'  (Go-side boundary: go-re2 -> wazero -> [WASM])
     0.04s 0.054%  0.79%      3.23s  4.40%                | github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
                                             1.15s 35.60% |   github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
                                             0.96s 29.72% |   github.com/wasilibs/go-re2/internal.getChildModule
                                             0.95s 29.41% |   github.com/wasilibs/go-re2/internal.putChildModule
```

Two profiler facts then settle the engine question directly. First, the backtracking engine `dlclark/regexp2` is **absent** from the entire node list (confirmed by grepping all 154 nodes) — it never executes on the canonical scan path. Second, the *only* `backtrack` frames are Go stdlib's **bounded bit‑state** executor (from the 3 stdlib‑`regexp` detectors), at **1.77 % cumulative**. Raw `-peek`, **verbatim**:

```
# go tool pprof -peek='regexp\.\(\*Regexp\)\.(backtrack|tryBacktrack)'
                                             0.90s   100% |   regexp.(*Regexp).backtrack
     0.37s   0.5%   0.5%      0.90s  1.23%                | regexp.(*Regexp).tryBacktrack
                                             0.27s 30.00% |   regexp.(*bitState).push (inline)
                                             0.10s 11.11% |   regexp.lazyFlag.match
                                             0.08s  8.89% |   regexp.(*inputBytes).context
                                             0.05s  5.56% |   regexp.(*bitState).shouldVisit (inline)
                                             0.03s  3.33% |   regexp.(*inputBytes).step
----------------------------------------------------------+-------------
                                             1.30s   100% |   regexp.(*Regexp).doExecute
     0.24s  0.33%  0.83%      1.30s  1.77%                | regexp.(*Regexp).backtrack
                                             0.90s 69.23% |   regexp.(*Regexp).tryBacktrack
                                             0.16s 12.31% |   regexp.(*inputBytes).step
```

That `backtrack` is reached via `doExecute → backtrack → tryBacktrack → bitState.push/shouldVisit` — the standard library's **`bitState`** one‑pass executor, whose memory (and therefore work) is **capped by construction** (it falls back to the linear NFA when the bound is exceeded). It is **not** PCRE‑style catastrophic backtracking (§4.2).

**Per‑match cost inside `mongodb.Scanner.FromData` (`go tool pprof -list`, verbatim line attributions from this same profile):**

```
     130ms      6.35s (flat, cum)  8.65% of Total
      10ms       10ms     44:func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
         .          .     48:	uniqueMatches := make(map[string]string)
      10ms      2.54s     49:	for _, match := range connStrPat.FindAllStringSubmatch(dataStr, -1) {
      60ms       60ms     51:		password := match[3]
         .      1.69s     52:		if password == "" || placeholderPasswordPat.MatchString(password) {
      30ms      100ms     57:		connStr := strings.Replace(strings.TrimSpace(match[1]), "&amp;", "&", -1)
         .      640ms     58:		connUrl, err := url.Parse(connStr)
      10ms      100ms     65:		for k, v := range connUrl.Query() {
         .      420ms     79:		connStr = connUrl.String()
         .      270ms     81:		uniqueMatches[connStr] = password
      10ms       10ms     84:	for connStr, password := range uniqueMatches {
```

Every one of these is **linear per match** — regex submatch extraction (L49, 2.54 s), a placeholder check (L52, 1.69 s), URL parse/re‑encode (L58 640 ms / L79 420 ms) — confirming the amplification is match‑count‑proportional, never super‑linear. Note the two‑stage structure that grounds §6.2's de‑duplication mechanics: `url.Parse` (L58) runs on **every raw match**, and only *afterward* is the result written into the **local, per‑`FromData`‑call** `uniqueMatches` map (L48/L81) that the emit loop (L84) drains — so the map bounds *emitted findings per chunk*, never the parse cost.

### 7.6 Engine‑contrast benchmark — CORROBORATION (NON‑CANONICAL)

This out‑of‑tree harness (source in §9.4) is **not** the canonical scan path; it demonstrates what a genuine ReDoS *looks like* by running the archetypal evil pattern `^(a+)+$` on the worst‑case non‑matching input `"a"×N + "!"` using the **two engines TruffleHog actually uses** (Go stdlib `regexp`, `go-re2`) and the **backtracking** `dlclark/regexp2` (which TruffleHog does **not** use for detection). Three independent binary runs:

```
################## ENGINE-CONTRAST BINARY RUN 1 ##################
N    | stdlib regexp (RE2)    | go-re2 (WASM RE2)      | dlclark/regexp2 (backtracking)
16   | 933ns                  | 1.48µs                 | 6.031144ms
20   | 766ns                  | 1.142µs                | 96.663509ms
24   | 1.002µs                | 3.351µs                | 1.557268499s
28   | 1.146µs                | 1.844µs                | 10.000039418s (TIMEOUT@10s)
30   | 1.272µs                | 2.74µs                 | 10.000025719s (TIMEOUT@10s)
32   | 1.325µs                | 1.184µs                | 10.000018263s (TIMEOUT@10s)
34   | 1.247µs                | 1.41µs                 | 10.000017326s (TIMEOUT@10s)

################## ENGINE-CONTRAST BINARY RUN 2 ##################
16   | 1.231µs                | 2.373µs                | 6.008274ms
20   | 938ns                  | 1.262µs                | 95.617441ms
24   | 917ns                  | 1.048µs                | 1.547234739s
28   | 1.058µs                | 1.059µs                | 10.000018021s (TIMEOUT@10s)
30   | 1.197µs                | 5.001µs                | 10.000044564s (TIMEOUT@10s)
32   | 1.392µs                | 1.298µs                | 10.000025191s (TIMEOUT@10s)
34   | 1.522µs                | 1.162µs                | 10.000020243s (TIMEOUT@10s)

################## ENGINE-CONTRAST BINARY RUN 3 ##################
16   | 956ns                  | 1.549µs                | 6.044448ms
20   | 830ns                  | 954ns                  | 96.272694ms
24   | 1.082µs                | 1.227µs                | 1.548197264s
28   | 1.14µs                 | 1.213µs                | 10.00002152s (TIMEOUT@10s)
30   | 1.16µs                 | 1.463µs                | 10.000026602s (TIMEOUT@10s)
32   | 1.245µs                | 1.571µs                | 10.00001901s (TIMEOUT@10s)
34   | 1.288µs                | 1.329µs                | 10.000016763s (TIMEOUT@10s)
```

The two engines TruffleHog uses stay in the **microsecond** range independent of `N`; `dlclark/regexp2` explodes **~2× per added character** (6 ms → 96 ms → 1.55 s), saturating the 10 s `MatchTimeout` guard by `N = 28` — and without that guard it would run effectively forever. This is exactly the hang the user fears, and it lives only in an engine TruffleHog does not use for detection.


---

## 8. Root‑Cause Analysis & Defense‑in‑Depth

**Cause → effect chain (why the observed behaviour occurs):**

1. Detector patterns are compiled by **RE2‑lineage engines** (`go-re2` [go.mod:L100] for 865 production detectors; Go stdlib `regexp` for 3). These simulate a finite automaton and perform **no unbounded backtracking** → match time is **linear** in input length → catastrophic‑backtracking ReDoS is *structurally impossible* regardless of pattern shape.
2. The **Aho‑Corasick prefilter** ([go.mod:L17]) means a chunk lacking a detector's keyword never reaches that detector's regex → benign, keyword‑free repository files are effectively free (~11 ms/MiB).
3. Even when a keyword *is* present, the regex only sees a **±512/±1024‑byte span** by default ([ahocorasickcore.go:L155]) → a single regex call operates on a small, bounded window; removing that limit (`--scan-entire-chunk`) changes nothing measurable (§7.3).
4. On keyword‑bearing, match‑dense files, RE2 must **extract** many submatches per chunk (crossing the WASM boundary), each match then incurs `url.Parse` + query re‑encode + result construction in `FromData` ([mongodb.go:L44]), and finally each finding is **formatted and written** → total cost grows **linearly** with match count (~0.66 s/MiB), never super‑linearly.

**Defense‑in‑depth (relevant to Q1's "hang or time out"):** TruffleHog wraps detector execution in cooperative deadlines — `context.WithTimeout(ctx, detectionTimeout)` (default 10 s) on the normal `detectChunk` path ([engine.go:L1066]) with a log‑only watchdog ([engine.go:L1067]–[engine.go:L1068]), and a shorter 2 s context in `verificationOverlapWorker` ([engine.go:L939]). These are **cooperative** and primarily bound slow **network verification**; because the regex call `FindAllStringSubmatch` takes no context ([mongodb.go:L49], [uri.go:L61]), a single match cannot be interrupted mid‑call. That is acceptable **precisely because** RE2's linear‑time guarantee — not the timeout — is the true protection against runaway matching. The timeouts and the span limit are secondary layers; the engine choice is primary.

**Residual risk restated (Q1):** The one realistic availability concern is a **linear** finding‑flood from a large file of unique synthetic (unverified) matches — bounded, proportional to size (~0.66 s/MiB), and mitigable operationally (input‑size caps, per‑file limits, or a CI step timeout sized with headroom). It is a resource‑consumption/log‑volume issue, not a catastrophic hang.

```mermaid
flowchart TD
    A[Crafted / benign file committed to repo] --> B[trufflehog filesystem: chunker 10 KiB + 3 KiB peek]
    B --> C{Aho-Corasick keyword prefilter}
    C -- No detector keyword --> Z[Chunk skipped: ~free, ~11 ms/MiB]
    C -- Keyword present --> D{Which engine compiled this detector's pattern?}
    D -- "865 production detectors" --> D1[go-re2: RE2 in wazero WASM, on a ±512/±1024 span]
    D -- "3 detectors: jdbc, azure_cosmosdb, azure_entra/spv2" --> D2[Go stdlib regexp: RE2-lineage, bounded bit-state]
    D1 --> E{Matches found?}
    D2 --> E
    E -- No matches --> F[Linear scan only: ~13 ms/MiB]
    E -- Many matches identical or unique --> G[Per-match url.Parse + result build; +format/write scales with EMITTED findings]
    G --> H[Linear in match count: ~0.375 s/MiB identical to ~0.66 s/MiB unique, bounded]
    D1 -. RE2 is non-backtracking .-> I[No exponential blow-up: ReDoS impossible]
    D2 -. bounded bit-state, also linear .-> I
    D1 --> J[context.WithTimeout 10s / 2s: cooperative defense-in-depth]
    D2 --> J
```

---

## 9. Reproduction

Everything below runs outside the repository. No source file is modified.

### 9.1 Build (canonical) & environment

```
$ go version
go version go1.24.3 linux/amd64

$ CGO_ENABLED=0 go build -o /tmp/trufflehog .          # matches the project Dockerfile
build exit=0
$ ls -l /tmp/trufflehog
-rwxr-xr-x 1 root root 194319670 /tmp/trufflehog
$ /tmp/trufflehog --version
trufflehog dev
```

### 9.2 Prove the keyword‑free baseline (out‑of‑tree helper via `go.work`)

The helper imports TruffleHog's own detector set + Aho‑Corasick core through a `go.work` workspace (no repo edit). Full source:

```go
// /tmp/redos_lab/kwcheck/main.go
// Out-of-tree helper: uses TruffleHog's OWN default detector set and its OWN
// Aho-Corasick prefilter core to (a) enumerate keywords and (b) PROVE whether a
// candidate file would trigger ANY detector's prefilter (i.e. whether any
// detector regex would ever run on it). This does NOT modify the repository;
// it imports it via a go.work workspace.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

func main() {
	dets := defaults.DefaultDetectors()
	core := ahocorasick.NewAhoCorasickCore(dets)
	kwmap := core.KeywordsToDetectors()

	if len(os.Args) >= 2 && os.Args[1] == "--list-keywords" {
		type kw struct {
			s string
			n int
		}
		var kws []kw
		for k := range kwmap {
			kws = append(kws, kw{k, len(k)})
		}
		sort.Slice(kws, func(i, j int) bool {
			if kws[i].n != kws[j].n {
				return kws[i].n < kws[j].n
			}
			return kws[i].s < kws[j].s
		})
		fmt.Printf("total_detectors=%d total_unique_keywords=%d\n", len(dets), len(kwmap))
		fmt.Println("=== shortest 40 keywords (length, keyword) ===")
		for i := 0; i < len(kws) && i < 40; i++ {
			fmt.Printf("%2d  %q\n", kws[i].n, kws[i].s)
		}
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("usage: kwcheck <file>|--list-keywords")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("read error:", err)
		os.Exit(1)
	}
	matches := core.FindDetectorMatches(data)
	fmt.Printf("file=%s bytes=%d total_detectors=%d total_keywords=%d prefilter_detector_hits=%d\n",
		os.Args[1], len(data), len(dets), len(kwmap), len(matches))
	if len(matches) == 0 {
		fmt.Println("RESULT: PREFILTER MISS - zero detectors triggered; no detector regex would run on this file.")
	} else {
		fmt.Println("RESULT: PREFILTER HIT - the following detectors would run:")
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Key.Type().String())
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("  HIT %s\n", n)
		}
	}
}
```

```
# Workspace so BOTH out-of-tree helpers compile against the local checkout without
# editing it. IMPORTANT: go.work `use`s ./enginetest (its main.go is added in §9.4),
# so its go.mod must exist *now* — otherwise `go build` fails with
# "directory ./enginetest ... does not contain a module".
$ mkdir -p /tmp/redos_lab/kwcheck /tmp/redos_lab/enginetest
$ printf 'go 1.24.2\n\nuse (\n\t%s\n\t./kwcheck\n\t./enginetest\n)\n' \
    /tmp/blitzy/trufflehog/blitzy-5f362aa7-e21b-49ac-9b19-ada176a8c834_04c077 > /tmp/redos_lab/go.work
# kwcheck module (the workspace resolves the trufflehog import to the local checkout):
$ printf 'module redoslab/kwcheck\n\ngo 1.24.2\n\nrequire github.com/trufflesecurity/trufflehog/v3 v3.90.0\n' \
    > /tmp/redos_lab/kwcheck/go.mod
# enginetest module (REQUIRED so `use ./enginetest` resolves; main.go added in §9.4):
$ printf 'module redoslab/enginetest\n\ngo 1.24.2\n\nrequire (\n\tgithub.com/dlclark/regexp2 v1.4.0\n\tgithub.com/wasilibs/go-re2 v1.9.0\n)\n' \
    > /tmp/redos_lab/enginetest/go.mod
# Build kwcheck. GOPROXY=off => offline, cache-only (deps are already in the module
# cache); do NOT pass -mod=mod, which is rejected in workspace mode.
$ cd /tmp/redos_lab/kwcheck && GOWORK=/tmp/redos_lab/go.work GOPROXY=off CGO_ENABLED=0 \
    go build -o /tmp/redos_lab/kwcheck_bin .
build exit=0
$ /tmp/redos_lab/kwcheck_bin --list-keywords | head -1
total_detectors=831 total_unique_keywords=914
# (after §9.3 has generated inputs) prove the keyword-free control is a prefilter MISS:
$ /tmp/redos_lab/kwcheck_bin /tmp/redos_lab/inputs/baseline_miss.txt
RESULT: PREFILTER MISS - zero detectors triggered; no detector regex would run on this file.
```

### 9.3 Generate inputs & run the canonical scans

The single generator (`/tmp/redos_lab/gen_inputs.py`) writes all 11 inputs at an **exact** byte size: it tiles each per-detector "evil unit" (sized to the **real** default span window) and pads the remainder with benign keyword-free `z` filler, then writes the unique-match finding-flood file via `write_unique()`. Complete, runnable source (no undefined names — the earlier draft's stray `line = … % (i, i, i)` is shown below inside its proper loop):

```python
#!/usr/bin/env python3
"""Generate exact-byte-size adversarial/benign inputs for the TruffleHog ReDoS lab.

Usage: python3 gen_inputs.py <size_bytes> <out_dir>
Every file is written to EXACTLY <size_bytes> bytes (tile the unit line, then pad
the remainder with benign keyword-free 'z' filler). All content is synthetic.
"""
import os
import sys

def write_exact(path, unit, size):
    """Tile `unit`, then pad with benign 'z' to hit EXACTLY `size` bytes."""
    body = unit * (size // len(unit))
    body += b"z" * (size - len(body))
    assert len(body) == size, (len(body), size)
    with open(path, "wb") as f:
        f.write(body)

def write_unique(path, size):
    """Unique valid MongoDB URIs (distinct user/host counter) -> finding flood."""
    buf = bytearray()
    i = 0
    while len(buf) < size:
        line = ("mongodb://u%08d:p%08dpw@host%08d.example/\n" % (i, i, i)).encode()
        buf += line
        i += 1
    del buf[size:]              # exact truncate (last line partial -> no match)
    with open(path, "wb") as f:
        f.write(buf)

def main():
    size = int(sys.argv[1]); out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    baseline_unit       = b"z" * 63 + b"\n"                                              # keyword-free control
    kw_nomatch_unit     = b"mongodb https:// " + b"z" * 47 + b"\n"                        # keyword hit, no full match
    match_dense_unit    = b"mongodb://user0000:pass0000pw@host0000000000.example.net/dddddd\n"  # 1 valid URI, repeated
    dense_uri_unit      = b"https://u:pw3456@h.example.com/" + b"a" * 32 + b"\n"          # valid https URIs (dense)
    mongo_host_unit     = b"mongodb://usr:abcdefabc@h" + b",a" * 480 + b"/\n"             # nested-star host (fits +/-512)
    uri_noat_unit       = b"https://" + b"a" * 50 + b":" + b"b" * 900 + b"\n"             # no trailing '@' (near-miss)
    mongo_userpass_unit = b"mongodb://" + b"a:" * 500 + b"\n"                             # user:pass spam (no '@')
    uri_atspam_unit     = b"https://" + b"a:@" * 900 + b"\n"                              # '@' spam
    databricks_unit     = b"dapi " + b"a" + b".a" * 980 + b".invalidtld\n"               # domain nested-star, bad TLD
    azuresas_unit       = b"https://abcstorage.blob.core.windows.net/c" + b"/a" * 980 + b"\n"  # path nested-star
    files = {
        "baseline_miss": baseline_unit,          "kw_nomatch": kw_nomatch_unit,
        "match_dense": match_dense_unit,          "dense_uri": dense_uri_unit,
        "patho_mongodb_host": mongo_host_unit,    "patho_uri_noat": uri_noat_unit,
        "patho_mongodb_userpass": mongo_userpass_unit, "patho_uri_atspam": uri_atspam_unit,
        "patho_databricks": databricks_unit,      "patho_azuresas": azuresas_unit,
    }
    for name, unit in files.items():
        write_exact(os.path.join(out, name + ".txt"), unit, size)
    write_unique(os.path.join(out, "match_unique.txt"), size)
    print("wrote %d inputs of exactly %d bytes to %s" % (len(files) + 1, size, out))

if __name__ == "__main__":
    main()
```

```
# 8 MiB inputs, then scan each (3 runs) through the canonical entry point:
$ python3 /tmp/redos_lab/gen_inputs.py $((8*1024*1024)) /tmp/redos_lab/inputs
wrote 11 inputs of exactly 8388608 bytes to /tmp/redos_lab/inputs
# exact-byte validation (all inputs identical in size => valid same-size controls):
$ for f in /tmp/redos_lab/inputs/*.txt; do wc -c "$f"; done | awk '{print $1}' | sort -u
8388608
$ for f in baseline_miss kw_nomatch match_dense dense_uri match_unique \
           patho_mongodb_host patho_mongodb_userpass patho_uri_noat \
           patho_uri_atspam patho_databricks patho_azuresas; do
    mkdir -p /tmp/redos_lab/scandirs/$f && cp /tmp/redos_lab/inputs/$f.txt /tmp/redos_lab/scandirs/$f/
    for r in 1 2 3; do
      /tmp/trufflehog filesystem /tmp/redos_lab/scandirs/$f --no-verification --no-update 2>&1 \
        | grep "finished scanning"
    done
  done
# worst-case single call:  add  --scan-entire-chunk
# per-detector averages:   add  --print-avg-detector-time
```

### 9.4 Engine‑contrast harness (corroboration)

Full source at `/tmp/redos_lab/enginetest/main.go` (save the block below to that path; its `go.mod` was already created in §9.2, and it is built via the same `go.work`):

```go
package main
import (
	"fmt"; "regexp"; "strings"; "time"
	"github.com/dlclark/regexp2"
	re2 "github.com/wasilibs/go-re2"
)
const pattern = `^(a+)+$`
func main() {
	reStd := regexp.MustCompile(pattern)          // RE2 (linear)
	reGo  := re2.MustCompile(pattern)              // go-re2 WASM RE2 (linear)
	reBt  := regexp2.MustCompile(pattern, 0)       // backtracking
	reBt.MatchTimeout = 10 * time.Second           // guard, else it runs ~forever
	for _, n := range []int{16,20,24,28,30,32,34} {
		s := strings.Repeat("a", n) + "!"          // guaranteed NON-match (worst case)
		t0 := time.Now(); reStd.MatchString(s); dStd := time.Since(t0)
		t1 := time.Now(); reGo.MatchString(s);  dGo  := time.Since(t1)
		t2 := time.Now(); _, err := reBt.MatchString(s); dBt := time.Since(t2)
		fmt.Printf("%d | %v | %v | %v timeout=%v\n", n, dStd, dGo, dBt, err != nil)
	}
}
```

```
$ cd /tmp/redos_lab/enginetest && GOWORK=/tmp/redos_lab/go.work GOPROXY=off CGO_ENABLED=0 \
    go build -o /tmp/redos_lab/enginetest_bin .
build exit=0
$ /tmp/redos_lab/enginetest_bin        # (run 3x; output in §7.6)
```

### 9.5 Safe CPU‑profiling lifecycle (Finding #15)

`--profile` starts an **unauthenticated** pprof/fgprof server on `:18066` ([main.go:L53]; server bound at [main.go:L433]–[main.go:L434]) — it should only be used on an **isolated host/loopback**, never exposed. The capture script polls readiness, captures only the spawned PID, bounds the profile window, waits for natural exit, and targets only that PID (never `pkill`/`killall`):

```bash
# $DIR must point at an input large enough that the scan outlives the 20 s profile
# window. A ~56 MiB unique-match file scans in ~32 s on this host:
$ python3 /tmp/redos_lab/gen_inputs.py $((56*1024*1024)) /tmp/redos_lab/inputs56
$ mkdir -p /tmp/redos_lab/scandirs/prof56
$ cp /tmp/redos_lab/inputs56/match_unique.txt /tmp/redos_lab/scandirs/prof56/
$ DIR=/tmp/redos_lab/scandirs/prof56                   # <-- define $DIR (was undefined)
$ /tmp/trufflehog filesystem "$DIR" --no-verification --no-update --profile > scan.log 2>&1 &
$ THPID=$!                                             # capture ONLY our PID
$ for n in $(seq 1 50); do                             # readiness poll on loopback (max ~10s)
    curl -s --max-time 1 http://localhost:18066/debug/pprof/ >/dev/null 2>&1 && break
    kill -0 "$THPID" 2>/dev/null || break; sleep 0.2; done
$ go tool pprof -seconds=20 -proto -output profile.pprof \
    http://localhost:18066/debug/pprof/profile          # bounded 20s window via loopback
$ while kill -0 "$THPID" 2>/dev/null; do sleep 1; done  # wait for natural exit
$ kill "$THPID" 2>/dev/null                             # targeted kill of ONLY our PID, if still alive
$ go tool pprof -top -nodecount=25 profile.pprof
```

### 9.6 Cleanup & read‑only proof

```
# remove every ephemeral artifact (all outside the repository tree)
$ rm -rf /tmp/redos_lab /tmp/trufflehog

# the repository is byte-for-byte unchanged except the answer document:
$ git status --porcelain
 M blitzy/documentation/trufflehog_e42153d44a5e.md

$ git status --porcelain | grep -v 'blitzy/documentation/' | wc -l
0
```

The ` M` line above is the *mid‑investigation* working‑tree snapshot — the answer document has been written but not yet committed — and it is the **only** entry; the `grep -v … | wc -l` guard proves **zero** other paths differ. After this document is committed (the final step of the deliverable), `git status --porcelain` is empty and the tree is clean. Either way, no `.go`, `go.mod`, `go.sum`, `Dockerfile`, CI, or any other source file is created, modified, or deleted — the sole change is this Markdown document.


---

## 10. Appendix — Consolidated `file:line` Citations

**Repository observations (what this checkout does):**

| Fact | Citation |
|------|----------|
| Go module path | `go.mod:L1` |
| `go 1.23.1`, `toolchain go1.24.2` | `go.mod:L3`, `go.mod:L5` |
| Aho‑Corasick prefilter dependency `v1.0.3` | `go.mod:L17` |
| `fgprof v0.9.5` (behind `--profile`) | `go.mod:L46` |
| **`go-re2 v1.9.0`** (primary regex engine, 865 production detectors) | `go.mod:L100` |
| `dlclark/regexp2 v1.4.0 // indirect` (unused for detection; 0 imports under `pkg/`) | `go.mod:L187` |
| `tetratelabs/wazero v1.9.0 // indirect` (pure‑Go WASM host for RE2) | `go.mod:L285` |
| 3 production stdlib‑`regexp` detectors | `azure_entra/serviceprincipal/v2/spv2.go:L7`, `azure_cosmosdb/azure_cosmosdb.go:L13`, `jdbc/jdbc.go:L8` |
| MongoDB `connStrPat` nested‑star pattern | `pkg/detectors/mongodb/mongodb.go:L32` |
| MongoDB `go-re2` import / keyword `"mongodb"` / per‑match `FromData` / `FindAllStringSubmatch` | `mongodb.go:L14`, `:L40`, `:L44`, `:L49` |
| URI `keyPat` (bounded quantifiers, required `@`) / keywords / `FindAllStringSubmatch` | `pkg/detectors/uri/uri.go:L33`, `:L44`, `:L61` |
| `databrickstoken` domain nested‑star `(?:\.[a-z0-9-]+)*` / `MultiPart` / keywords | `databrickstoken.go:L27`, `:L17`, `:L34` |
| `azuresastoken` `urlPat` nested‑star `(?:/[a-zA-Z0-9._-]+)*` / `MultiPart` / keywords | `azuresastoken.go:L32`, `:L22`, `:L45`–`:L46` |
| `azure_entra` v1 `secretPat` `.{0,80}` (go‑re2) / keywords (incl. `"az"`) | `serviceprincipal/v1/spv1.go:L35`, `:L45` |
| Detection loop: `detectorWorker` → `detectChunk` | `pkg/engine/engine.go:L1036`, `:L1044` |
| Normal‑path timeout `WithTimeout(detectionTimeout)` + log‑only watchdog + `verificationCache.FromData` | `engine.go:L1066`, `:L1067`, `:L1068`, `:L1070` |
| `detectionTimeout` variable (= `DefaultResponseTimeout`) | `engine.go:L37`; `pkg/detectors/http.go:L18` |
| Verification‑overlap 2 s timeout + `FromData` | `engine.go:L924`, `:L939`, `:L940` |
| `--print-avg-detector-time` per‑result‑returning average (self‑doc string; displayed by `printAverageDetectorTime`) | `engine.go:L1093`–`:L1104` (capture/append/store); `main.go:L1021`–`:L1029`, self‑doc `:L1024` |
| Chunker `ChunkSize`/`PeekSize`/`TotalChunkSize` (10 KiB + 3 KiB) | `pkg/sources/chunker.go:L14`, `:L16`, `:L18` |
| Default keyword span radius `defaultOffsetRadius = 512` | `pkg/engine/ahocorasick/ahocorasickcore.go:L155` |
| `DefaultDetectors()` | `pkg/engine/defaults/defaults.go:L1704` |
| `--profile` flag / pprof server `:18066` / `--scan-entire-chunk` / concurrency default / `finished scanning` / `scan_duration` | `main.go:L53`, `:L433`–`:L434`, `:L68`, `:L58`, `:L566`, `:L571` |
| Canonical build `CGO_ENABLED=0 go build` | `Dockerfile` |

**External engine safety contracts (independent of this repo):**

| Contract | Source |
|----------|--------|
| RE2 forbids backtracking; guarantees match time linear in input length; safe for untrusted patterns | Google RE2 — <https://github.com/google/re2/wiki/WhyRE2> |
| `go-re2` packages RE2 as a WebAssembly module run by `wazero` **by default** (usable without cgo); slower than stdlib for *small* inputs (constant factor, not complexity) | <https://github.com/wasilibs/go-re2>, <https://pkg.go.dev/github.com/wasilibs/go-re2> |
| Go stdlib `regexp` is RE2‑derived, runs in time linear in input size, and does not implement (unbounded) backtracking; uses a **bounded** bit‑state backtracker for small programs | <https://pkg.go.dev/regexp>; `src/regexp/backtrack.go`; background <https://swtch.com/~rsc/regexp/> |
| `wazero` is a pure‑Go, zero‑dependency, sandboxed WebAssembly runtime | <https://pkg.go.dev/github.com/tetratelabs/wazero> |

---

*End of assessment. This document is the sole change to the repository; TruffleHog source is unmodified, and all ephemeral lab artifacts were removed (§9.6).*

