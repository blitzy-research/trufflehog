# TruffleHog Resource‑Exhaustion / Denial‑of‑Service Investigation

**A security analysis of whether TruffleHog's detector pattern matching can be weaponized to hang, time out, or disproportionately slow a CI security scan.**

This report is written **from empirically‑observed runtime output** captured on this exact checkout using the canonical build. Every behavioral claim is paired with the specific observed line that demonstrates it, and every source fact carries a `file:line` citation that was re‑verified against the live tree. Values that depend on how the tool is built are labeled **build‑dependent**; the Python contrast is labeled **non‑canonical** (Python is not TruffleHog's engine); anything not directly observed is labeled **inferred**.

---

## The question under investigation (verbatim)

> We're evaluating TruffleHog for our CI pipeline, but I'm concerned about resource exhaustion attacks. If a malicious actor commits a specially crafted file to a repository we're scanning, could they cause TruffleHog to hang or time out, effectively blocking our security scans? I need you to determine if TruffleHog's pattern matching is vulnerable to computational complexity attacks. Find out which detector patterns, if any, can be exploited to cause disproportionate processing time. Measure the actual impact, how much slower can you make a scan compared to normal files of equivalent size? Provide timing measurements and CPU profiling data showing the vulnerability in action. Don't modify the TruffleHog source - just demonstrate the attack.

The question decomposes into five deliverables, answered explicitly and by name below:

- **A1** — Can a committed crafted file hang or time out the scan and block CI?
- **A2** — Is detector pattern matching vulnerable to computational‑complexity (ReDoS) attacks?
- **A3** — Which detector patterns, if any, can be exploited for disproportionate time?
- **A4** — How much slower than a normal file of equivalent size?
- **A5** — Timing measurements and CPU‑profiling evidence.

---

## Executive summary — verdict at a glance

| # | Question | Verdict | One‑line basis (evidence below) |
|---|----------|---------|----------------------------------|
| **A1** | Hang / time out & block CI? | **NO — bounded; cannot indefinitely hang** | Nested‑gzip bomb terminated in `scan_duration: "5.559156ms"` at `max archive depth reached`; multiple hard limits (per‑detector 10 s + watchdog, archive depth/size/timeout, 10 KiB chunk) guarantee termination. |
| **A2** | ReDoS / computational‑complexity? | **NO — RE2 engine, linear‑time, no backtracking** | Textbook `(a+)+$` against 9000 `a`s ran in `6.457806ms` (flat/linear). Detectors compile with `github.com/wasilibs/go-re2` (RE2). Same pattern in Python (backtracking) is KILLED at N≥28. |
| **A3** | Which detector patterns? | **No single catastrophic regex; the exploitable "pattern" is keyword‑density‑driven detector FAN‑OUT** | On a 1 MiB keyword‑dense file the whole scan took `3.501589448s`, yet the slowest single detector was `Parsehub: 2.089053ms` and all printed detectors summed to 9.531 ms (0.27 %). Cost is spread across hundreds of detectors, not one regex. |
| **A4** | How much slower vs equal‑size? | **~62× sustained, up to ~104× worst case (keyword‑dense) — bounded & linear, NOT exponential** | 8 MiB keyword `13.168888124s` vs equal‑size baseline `224.766665ms` ≈ 61.68×; doubling data (4→8 MiB) only ~1.72× time. Base64‑dense ~17×. |
| **A5** | Timing + CPU profiling | **CPU concentrates in linear RE2 matching fanned across detectors; no backtracking signature** | pprof: `runtime._ExternalCode` 55.05 % (RE2 in WASM/wazero), `go-re2 … FindAllStringSubmatch` dominant. fgprof: `Engine.detectorWorker` 71.65 %. |

**Bottom line for the CI decision:** A malicious contributor **cannot** make a single committed file hang TruffleHog indefinitely. The pattern‑matching layer is **not** vulnerable to catastrophic‑backtracking ReDoS because it uses the RE2 engine, which is guaranteed linear‑time. The realistic worst case is a **bounded, linear** slowdown (tens of × for a maximally keyword‑dense file versus a normal file of the same size), backstopped by hard per‑detector and per‑archive timeouts. This is a throughput/cost consideration (mitigable with scan timeouts and resource limits), not an availability vulnerability.

---

## Build & invocation provenance

All evidence in this report was produced by the canonical build and the tool's own instrumentation, on this checkout.

- **Runtime (observed):** `go version go1.24.3 linux/amd64`. The module declares `go 1.23.1` [go.mod:L3] with `toolchain go1.24.2` [go.mod:L5]; module path `github.com/trufflesecurity/trufflehog/v3` [go.mod:L1]. Local Go 1.24.3 ≥ the declared toolchain, so no toolchain download occurs. *(The provenance target of Go 1.24.2 and the actual installed 1.24.3 both satisfy the module; I report the version I actually ran.)*
- **Host (observed):** 4 logical CPUs (`nproc` = 4). This matters for A5: absolute timings and profile percentages are machine‑dependent and reflect a 4‑core box.
- **Canonical build:**

  ```bash
  CGO_ENABLED=0 go build -o /tmp/trufflehog .   # from repo root
  ```

  Because `CGO_ENABLED=0`, `go-re2` runs in its **default WebAssembly/wazero mode** (pure Go, no cgo) — confirmed by the absence of any `re2_cgo` reference under `pkg/` and by the `wazero` frames in the CPU profile (A5). Observed binary size:

  ```
  194322006   # bytes, stat -c '%s' /tmp/trufflehog
  ```

- **Version string — LABEL: BUILD‑DEPENDENT.** A plain `go build` (no release ldflags) yields the placeholder version:

  ```
  $ /tmp/trufflehog --version
  trufflehog dev
  ```

  This is sourced from `var BuildVersion = "dev"` [pkg/version/version.go:L3]; the scan log emits `"trufflehog_version", version.BuildVersion` [main.go:L572] and the `if version.BuildVersion == "dev"` branch is at [main.go:L360]. The `dev` string is a property of *how it was built*, not a runtime measurement.
- **Canonical scan invocation:** the real filesystem entry point [main.go:L143-L144]:

  ```bash
  /tmp/trufflehog filesystem <path> --no-verification
  ```

  `--no-verification` isolates **detection / pattern‑matching cost** from network verification latency, so every timing reflects the pattern‑matching path only. Concurrency is left at the CLI default `--concurrency=128`; when unset the engine defaults to `runtime.NumCPU()` [pkg/engine/engine.go:L337-L340].
- **Timing field:** the `finished scanning` log line [main.go:L566] emits `"scan_duration", metrics.ScanDuration.String()` [main.go:L571].
- **Per‑detector timing:** `--print-avg-detector-time` [main.go:L72] prints to STDERR via `printAverageDetectorTime` [main.go:L1021]. **Only detectors that RETURN results are printed**, gated by `if e.printAvgDetectorTime && len(results) > 0` [pkg/engine/engine.go:L1092] — a fact that is itself key evidence for A3.
- **CPU profiling:** `--profile` [main.go:L53] starts a pprof + fgprof HTTP server on `:18066` [main.go:L426-L434] — `router.Handle("/debug/pprof/", …)` [main.go:L431] and `router.Handle("/debug/fgprof", fgprof.Handler())` [main.go:L432], served by `http.ListenAndServe(":18066", router)` [main.go:L434], using imports `_ "net/http/pprof"` [main.go:L8] and `"github.com/felixge/fgprof"` [main.go:L20].
- **Benchmark convention aligned with:** `.github/workflows/performance.yml` pins `go-version: "1.24"` [.github/workflows/performance.yml:L16] and runs `… filesystem "$repo_tmp" --no-verification --no-update …` [.github/workflows/performance.yml:L37,L75]; the `Makefile` installs with `CGO_ENABLED=0 go install .` [Makefile:L17-L18] and defines `test:` [Makefile:L30] and `bench:` [Makefile:L45].

**Sanity scan — the canonical path works end‑to‑end.** A 46‑byte plain‑text file with no secrets:

```
finished scanning	{"chunks": 1, "bytes": 46, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.339906ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

---

## A1 — Can a crafted committed file hang or time out the scan and block CI? → **NO (bounded; cannot indefinitely hang)**

**Verdict:** A committed file cannot make TruffleHog hang indefinitely. The worst an attacker achieves is a *bounded* slowdown (quantified in A4), because every expensive code path is backstopped by a hard limit that guarantees termination. Each limit is a concrete literal in the source:

- **Per‑detector detection timeout = 10 s, plus a watchdog.** The engine wraps each detector call in a context timeout and arms a watchdog one second later:
  - `var detectionTimeout = detectors.DefaultResponseTimeout` [pkg/engine/engine.go:L37]
  - `const DefaultResponseTimeout = 10 * time.Second` [pkg/detectors/http.go:L18]
  - applied as `ctx, cancel := context.WithTimeout(ctx, detectionTimeout)` [pkg/engine/engine.go:L1066]
  - watchdog `t := time.AfterFunc(detectionTimeout+1*time.Second, func() {` [pkg/engine/engine.go:L1067] whose body logs `ctx.Logger().Error(nil, "a detector ignored the context timeout")` [pkg/engine/engine.go:L1068]
  - a tighter 2‑second bound also guards the verification‑overlap path: `ctx, cancel := context.WithTimeout(ctx, time.Second*2)` [pkg/engine/engine.go:L939]

  *Cause → effect:* any single detector that spun for more than 10 s would be cancelled; if it *ignored* cancellation, the watchdog would fire the diagnostic log at 11 s. Neither happened in any experiment (see the inferred note below).

- **Archive limits (decompression‑bomb defense).** `maxDepth = 5 * 2` (=10) [pkg/handlers/archive.go:L26], `maxSize = 2 << 30` (2 GB) [pkg/handlers/archive.go:L27], `maxTimeout = time.Duration(60) * time.Second` [pkg/handlers/archive.go:L28]. Enforced by `if depth >= maxDepth {` [pkg/handlers/archive.go:L124] returning `return ErrMaxDepthReached` [pkg/handlers/archive.go:L126] (defined `var ErrMaxDepthReached = errors.New("max archive depth reached")` [pkg/handlers/archive.go:L105]), by the file‑size skip `if int(fileSize) > maxSize {` [pkg/handlers/archive.go:L198], and by a per‑archive processing timeout `processingCtx, cancel := logContext.WithTimeout(ctx, maxTimeout)` [pkg/handlers/handlers.go:L384].

- **Chunk bound.** Any single regex pass sees at most one chunk: `ChunkSize = 10 * 1024` [pkg/sources/chunker.go:L14] plus `PeekSize = 3 * 1024` [pkg/sources/chunker.go:L16] overlap, i.e. `TotalChunkSize = ChunkSize + PeekSize` [pkg/sources/chunker.go:L18]. *Cause → effect:* an attacker cannot force a single regex to run over a multi‑megabyte string; input is capped at ~13 KiB per pass.

### Verbatim evidence — nested‑gzip archive bomb

I built a **15‑level nested gzip** (exceeding `maxDepth`=10) whose innermost payload contains the **AWS‑published documentation example access key ID** — a non‑functional placeholder AWS itself publishes that literally ends in "EXAMPLE" (redacted here as `AKIA…EXAMPLE` so this document does not embed an AWS‑key‑shaped literal, per secret‑hygiene practice; the actual payload used AWS's published example verbatim). The bomb file is 414 bytes on disk. Command:

```bash
/tmp/trufflehog filesystem /tmp/th_scratch/arcbomb/nested --no-verification --log-level=5
```

The handler recursed one level per gzip layer, each carrying the 60‑second archive timeout, from depth 0 up to depth 10 (11 distinct `"depth"` values 0–10 observed):

```
archive processing	{… "mime": "application/gzip", "timeout": 60, "depth": 0 …}
archive processing	{… "mime": "application/gzip", "timeout": 60, "depth": 1 …}
…
archive processing	{… "mime": "application/gzip", "timeout": 60, "depth": 10 …}
```

At depth 10 (`= maxDepth`) it stopped with the exact `ErrMaxDepthReached` message:

```
error	trufflehog	non-critical error processing chunk	{… "mime": "application/gzip", "timeout": 60, "error": "max archive depth reached"}
```

and the scan **terminated cleanly, without hanging**:

```
finished scanning	{"chunks": 0, "bytes": 0, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.559156ms", "trufflehog_version": "dev", …}
```

**Key facts (each tied to the line above):**
- **It did not hang** — the whole scan took `"scan_duration": "5.559156ms"`.
- **The innermost payload was never reached** — `"chunks": 0, "bytes": 0`, i.e. the depth limit stopped descent before the `AKIA…EXAMPLE` payload was ever chunked or scanned. A decompression bomb therefore cannot be used to force unbounded work.

### The per‑detector 10 s cap was never triggered — **LABEL: inferred (corroborated)**

I did **not** observe the watchdog line `a detector ignored the context timeout` [pkg/engine/engine.go:L1068] in any run, and I did not observe any detector approach the 10‑second cap. This is an **inferred** negative: the cap exists and would fire, but no experiment pushed a single detector near it, because RE2 keeps every per‑chunk regex in the low‑millisecond range. It is corroborated by (a) the per‑detector times in A3 (slowest single detector `Parsehub: 2.089053ms`) and (b) the flat ReDoS curve in A2 (`(a+)+$` on 9000 `a`s = `6.457806ms`). Both are three‑to‑four orders of magnitude below 10 s.

---

## A2 — Is detector pattern matching vulnerable to computational‑complexity / ReDoS attacks? → **NO**

**Verdict:** TruffleHog's pattern matching is **not** vulnerable to catastrophic‑backtracking ReDoS, because its regexes are compiled and executed by the **RE2 engine**, which is guaranteed to run in time linear in the input and structurally **excludes the backtracking constructs** (backreferences, generalized/lookaround assertions) that cause exponential blow‑up.

### Engine identity (source evidence)

- **Built‑in detectors use RE2.** A representative detector imports the RE2 engine under the local alias `regexp`:
  - `regexp "github.com/wasilibs/go-re2"` [pkg/detectors/aws/access_keys/accesskey.go:L17]
  - dependency pinned at `github.com/wasilibs/go-re2 v1.9.0` [go.mod:L100]
- **Custom (user‑supplied) detectors use Go's standard‑library `regexp`** — which also implements RE2 syntax/semantics and the same linear‑time guarantee: `regex, err := regexp.Compile(exclude)` [pkg/custom_detectors/custom_detectors.go:L71], again at [pkg/custom_detectors/custom_detectors.go:L82], and `regex, err := regexp.Compile(regex)` [pkg/custom_detectors/custom_detectors.go:L92].
- **Repo‑wide (observed via grep):** **867** `.go` files import `github.com/wasilibs/go-re2`; **29** import the standard‑library `"regexp"`; **865** non‑test detector implementations expose `FromData` under `pkg/detectors`. **No** backtracking‑capable engine (PCRE / `regexp2`) is used anywhere on the detection path — a grep for `regexp2` across `pkg/detectors`, `pkg/engine`, and `pkg/custom_detectors` returns **0** matches.
- **Caveat to pre‑empt a false positive:** `github.com/dlclark/regexp2 v1.4.0 // indirect` [go.mod:L187] *is* present in the module graph, pulled in transitively (via chroma → glamour, for TUI markdown highlighting). It is **never imported by first‑party detection code** (the 0‑match grep above). An investigator running `go list -m all` should not misread regexp2's presence in `go.sum` as ReDoS exposure of the scanner.

### Runtime confirmation (canonical path) — the textbook ReDoS pattern stays flat

Source evidence alone is not enough; the rule requires a runtime demonstration on the real path. I registered the classic catastrophic‑backtracking pattern `(a+)+$` as a **custom detector** and fed it through the canonical `filesystem` entry point. Config `/tmp/th_scratch/redos_config.yaml`:

```yaml
detectors:
  - name: redos-canonical
    keywords:
      - aaa
    regex:
      redos: (a+)+$
```

Input = `N` copies of `a` followed by `!` (the trailing `!` forces `$` to fail, which maximizes backtracking in a naive engine). Command:

```bash
/tmp/trufflehog filesystem /tmp/th_scratch/redos/r_<N>.txt --no-verification --config /tmp/th_scratch/redos_config.yaml
```

The detector is **live** — an all‑`a` input (so `$` matches) fires it and reports `"unverified_secrets": 1` in `"scan_duration": "3.872161ms"`, proving `(a+)+$` is genuinely executed by the engine. The observed `scan_duration` as the adversarial input grows:

| N (`a` count + `!`) | scan_duration |
|--------------------:|---------------|
| 20   | `3.837429ms` |
| 24   | `3.297999ms` |
| 28   | `3.938516ms` |
| 32   | `4.036374ms` |
| 36   | `4.352297ms` |
| 40   | `4.198208ms` |
| 44   | `4.061649ms` |
| 48   | `4.320399ms` |
| 100  | `4.136483ms` |
| 1000 | `4.331669ms` |
| 5000 | `6.037681ms` |
| 9000 | `6.457806ms` |

**→ FLAT / LINEAR.** Even at 9000 `a`s the whole scan is `6.457806ms`. RE2 does not backtrack, so the input that annihilates a backtracking engine costs essentially nothing here.

### Contrast: the identical pattern in a backtracking engine — **LABEL: NON‑CANONICAL**

To show what catastrophic backtracking *looks like* on the identical pattern, I ran `(a+)+$` in **Python's `re`** — a backtracking engine that is **NOT** TruffleHog's engine (shown only for contrast; each N in its own 8‑second‑timeout subprocess):

| N | Python `re` time |
|--:|------------------|
| 20 | `81.496ms` |
| 24 | `1308.853ms` |
| 26 | `5546.270ms` |
| 28 | `>8000ms` — KILLED (timeout) |
| 30 | `>8000ms` — KILLED |
| 32 | `>8000ms` — KILLED |
| 34 | `>8000ms` — KILLED |
| 40 | `>8000ms` — KILLED |

**→ EXPONENTIAL** (~4× per +2 to N); the process hangs by N=28. This is the behavior TruffleHog would exhibit **if** it used a backtracking engine — and precisely the behavior the RE2 curve above proves it does **not** exhibit. **This Python row is non‑canonical and is presented only as a reference for the shape of catastrophic backtracking.**

---

## A3 — Which detector patterns, if any, can be exploited for disproportionate time? → **No single catastrophic regex; the exploitable "pattern" is keyword‑density‑driven detector FAN‑OUT**

**Verdict:** No individual detector regex can be pushed to disproportionate (super‑linear) time — they all compile under RE2 and stay linear. The only lever an attacker has is **fan‑out**: a maximally keyword‑dense file makes the Aho‑Corasick keyword prefilter route every chunk to *hundreds* of detectors, so the cost is the **sum of many linear passes**, not one exponential pass.

### Mechanism (source evidence)

The keyword prefilter routes a chunk to a detector when a detector keyword appears within a ±512‑byte window: `const defaultOffsetRadius int64 = 512` [pkg/engine/ahocorasick/ahocorasickcore.go:L155], via `func (ac *Core) FindDetectorMatches(chunkData []byte) []*DetectorMatch {` [pkg/engine/ahocorasick/ahocorasickcore.go:L241]. Pack a chunk with many distinct real keywords and it fans out to many detectors, each running its (linear) RE2 regex once.

### High‑constant‑factor patterns (all bounded / linear under RE2)

These are the detectors whose regexes carry the largest constant factors (long bounded/open‑ended repetition). Under a backtracking engine some of these shapes could be dangerous; under RE2 they merely raise the **constant factor**, never the asymptotic class:

- `reallysimplesystems`: `keyPat = regexp.MustCompile(`\b(ey[a-zA-Z0-9-._]{153}.ey[a-zA-Z0-9-._]{916,1000})\b`)` — bounded repetition `{916,1000}` [pkg/detectors/reallysimplesystems/reallysimplesystems.go:L27]
- `graphcms`: `keyPat = regexp.MustCompile(`\b(ey[a-zA-Z0-9]{73}.ey[a-zA-Z0-9]{365}.[a-zA-Z0-9_-]{683})\b`)` — `{683}` [pkg/detectors/graphcms/graphcms.go:L27]
- `azure_entra/refreshtoken`: `refreshTokenPat = regexp.MustCompile(`\b[01]\.A[\w-]{50,}(?:\.\d)?\.Ag[\w-]{250,}(?:\.A[\w-]{200,})?`)` — open‑ended `[\w-]{250,}` [pkg/detectors/azure_entra/refreshtoken/refreshtoken.go:L39]
- `aws/session_keys`: `sessionPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([a-zA-Z0-9+/]{100,}={0,3})(?:[^A-Za-z0-9+/=]|\z)`)` — `{100,}` [pkg/detectors/aws/session_keys/sessionkey.go:L62]
- Bounded baseline for comparison: `idPat = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`)` [pkg/detectors/aws/access_keys/accesskey.go:L65]

The detector corpus contains **865** `FromData` implementations (observed grep count of non‑test `func … FromData(` under `pkg/detectors`); because all compile under RE2, even the high‑constant‑factor patterns above remain linear.

### Runtime evidence — the slowdown is fan‑out, not any single detector

On a 1 MiB keyword‑dense file (built from 914 real detector keywords — see A4), with per‑detector timing enabled:

```bash
/tmp/trufflehog filesystem /tmp/th_scratch/keyword_1m.txt --no-verification --print-avg-detector-time
```

The whole scan took **`"scan_duration": "3.501589448s"`**, yet only **21** detectors were printed (the gate `if e.printAvgDetectorTime && len(results) > 0` [pkg/engine/engine.go:L1092] prints only detectors that *returned* results). Every printed per‑detector average is tiny; the largest is:

```
Parsehub: 2.089053ms
```

with the rest smaller, e.g. `Mockaroo: 943.714µs`, `Uclassify: 930.452µs`, `FormBucket: 741.192µs`, `Host: 1.278276ms`, `Codacy: 1.169684ms`, down to `Eraser: 48.899µs`. **The 21 printed per‑detector averages sum to just 9.531 ms — only 0.27 % of the 3501.589 ms scan.**

*Cause → effect:* if a single detector's regex were the bottleneck, its per‑detector time would be seconds; instead the slowest is ~2 ms and the printed total is <10 ms, while the wall‑clock is 3.5 s. The remaining ~99.7 % is spent running the **hundreds of detectors that matched keywords but returned no result** (and are therefore hidden by the `len(results) > 0` gate). This is dispositive that the cost is **broad fan‑out across many linear detectors**, not one expensive pattern — and it confirms no single detector approaches the 10 s cap from A1.

---

## A4 — How much slower than a normal file of equivalent size? → **~62× sustained, up to ~104× worst case (keyword‑dense) — bounded & linear, NOT exponential**

**Method.** Each adversarial file is compared against a **random‑word baseline of identical byte length** (a "normal file of equivalent size"); the metric is the whole‑scan `scan_duration`; each measurement is repeated **twice** at each scale; all scans use `--no-verification`. Three input families, all generated ephemerally under `/tmp/th_scratch`:

- **baseline** — random lowercase words (a normal file).
- **keyword‑dense** — the **914 distinct real detector keywords** (dumped canonically from `defaults.DefaultDetectors()`), shuffled and repeated to fill the target size (maximizes Aho‑Corasick fan‑out per A3).
- **base64‑dense** — Base64 of the keyword text, which additionally exercises the Base64 decoder's **re‑expansion + re‑scan**. The default decoder chain is `DefaultDecoders()` = UTF8, Base64, UTF16, EscapedUnicode [pkg/decoders/decoders.go:L8-L14] with UTF8 first [pkg/decoders/decoders.go:L11] and Base64 second [pkg/decoders/decoders.go:L12].

Command per file: `/tmp/trufflehog filesystem /tmp/th_scratch/<file> --no-verification`.

### Verbatim `scan_duration` (two runs each) and ratios

| Scale | chunks | baseline (run1, run2) | keyword‑dense (run1, run2) | base64‑dense (run1, run2) | keyword ÷ baseline | base64 ÷ baseline |
|------:|-------:|------------------------|-----------------------------|----------------------------|-------------------:|------------------:|
| **1 MiB** | 103 | `37.651008ms`, `31.418078ms` | `3.538650593s`, `3.665156682s` | `662.787228ms`, `560.820661ms` | **104.30×** | **17.72×** |
| **4 MiB** | 410 | `120.040812ms`, `124.831177ms` | `7.494852569s`, `7.952342504s` | `2.408692055s`, `1.847809206s` | **63.08×** | **17.38×** |
| **8 MiB** | 820 | `224.766665ms`, `207.332444ms` | `13.168888124s`, `13.482203325s` | `3.491769292s`, `3.84540191s` | **61.68×** | **16.98×** |

Ratios are computed from the two‑run averages at each scale (e.g. 8 MiB keyword avg `13.325545725s` ÷ baseline avg `216.049555ms` = 61.68×).

### Interpretation

- **Magnitude.** A maximally keyword‑dense file is **~62× slower sustained** (4–8 MiB) than a normal file of the same size, rising to **~104×** at 1 MiB (where the baseline's ~34 ms is dominated by fixed startup, inflating the ratio). A base64‑dense file is a flatter **~17×**. Keyword fan‑out is the strongest lever — consistent with A3.
- **Stability (≥2 runs).** Every cell is stable across its two runs: e.g. keyword 8 MiB `13.168888124s` vs `13.482203325s` (within 2.4 %); keyword 1 MiB `3.538650593s` vs `3.665156682s` (within 3.6 %).
- **Bounded & LINEAR, not exponential — the crux.** In the parallelism‑saturated regime, doubling the input from 4 → 8 MiB multiplies time by only ~1.72–1.77× for **all three** families (baseline 1.765×, keyword 1.725×, base64 1.724×). If any regex were super‑linear, doubling the data would multiply time by far more than 2×; instead it is *sub*‑2×. This is exactly the RE2 caveat — asymptotically linear, with a larger *constant factor* for the adversarial file — **not** exponential blow‑up. A single‑chunk (9 KB) keyword file scans in `119.140386ms` / `119.095545ms`; the per‑chunk cost actually *drops* at larger scales (4‑core parallelism), which is the opposite of a complexity attack.
- **Pure detection cost.** `unverified_secrets` from the fake keywords is a byproduct (e.g. 141 at keyword‑1 MiB, 980 at keyword‑8 MiB) and never becomes a *verified* secret; with `--no-verification` these numbers reflect detection/matching work only.
- **Byte‑count note (so the log isn't misread).** The `"bytes"` field exceeds the file size — e.g. the 1 MiB baseline file is 1 048 576 bytes but the log reports `"bytes": 1361920` — because the chunker counts `TotalChunkSize` including the 3 KiB peek overlap per chunk [pkg/sources/chunker.go:L13-L18]. This applies to every family (base64 differs slightly at `1160482` due to newline‑driven chunk boundaries) and is expected, not a measurement error.

---

## A5 — Timing measurements + CPU‑profiling evidence → **CPU concentrates in linear RE2 matching fanned across detectors; no backtracking signature**

**Worst‑case input:** 32 MiB keyword‑dense (the strongest vector from A4). Whole‑scan timing, two runs:

- **run1 (no profiler):**
  ```
  finished scanning	{"chunks": 3277, "bytes": 43618304, "unverified_secrets": 4260, "scan_duration": "42.267363873s", …}
  ```
  Shell `time` for the same run: `real 0m44.053s`, `user 2m46.954s`, `sys 0m2.531s` — ~166.95 s of CPU over ~44 s wall ≈ **3.8 of 4 cores busy**, i.e. the scan is CPU‑bound and fully parallelized.
- **run2 (with `--profile`):** `"scan_duration": "45.41423137s"` (same `"chunks": 3277`). The ~3 s increase over run1 is profiler overhead. The two runs are **stable**.

Profiles were captured **from TruffleHog's own `--profile` server** on `:18066` (index returned `HTTP 200`) while run2 was matching:

```bash
curl -s "http://localhost:18066/debug/pprof/profile?seconds=15" -o cpu.pprof
curl -s "http://localhost:18066/debug/fgprof?seconds=15&format=pprof" -o fg.pprof
go tool pprof -top   <profile>
```

### pprof CPU profile (`go tool pprof -top`)

Header (verbatim): `Duration: 15.17s, Total samples = 59.33s (391.04%)` — i.e. ~3.9 cores busy during sampling. Top frames:

```
      flat  flat%   sum%        cum   cum%
    32.66s 55.05% 55.05%     32.66s 55.05%  runtime._ExternalCode
         0     0% 55.05%     14.90s 25.11%  …engine.(*Engine).verificationOverlapWorker (func1)
     0.42s  0.71% 55.76%     14.90s 25.11%  …engine.(*Engine).verificationOverlapWorker
     0.16s  0.27% 56.03%      7.58s 12.78%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.06s   0.1% 56.13%      6.99s 11.78%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
         0     0% 56.14%      4.67s  7.87%  …engine.(*Engine).scannerWorker
     0.09s  0.15% 56.30%      3.65s  6.15%  …engine/ahocorasick.(*Core).FindDetectorMatches
     0.05s 0.084% 58.71%      3.24s  5.46%  github.com/wasilibs/go-re2/internal.matchFrom
     0.05s 0.084% 59.09%      2.59s  4.37%  github.com/wasilibs/go-re2/internal.getChildModule
```

And, sorted by flat, alongside the WASM runtime and the keyword prefilter and named detectors:

```
    32.66s 55.05%  runtime._ExternalCode
     0.89s  1.50%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.82s  1.38%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
       …            …
      0.59s  0.99%  …pkg/detectors/couchbase.Scanner.FromData     (cum)
      0.57s  0.96%  …pkg/detectors/mapbox.Scanner.FromData        (cum)
      0.34s  0.57%  …pkg/detectors/snowflake.Scanner.FromData     (cum)
```

**Reading the CPU profile (each line = one piece of evidence):**
- `runtime._ExternalCode` flat **55.05 %** is the RE2 C++ automaton executing **inside the WebAssembly/wazero sandbox** — this is exactly what `go-re2` in its default `CGO_ENABLED=0` mode looks like (corroborated by the `wazero/internal/engine/wazevo` frame and the `_ "net/http/pprof"` [main.go:L8] / `"github.com/felixge/fgprof"` [main.go:L20] wiring).
- `github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch` cum **12.78 %** is the dominant *Go‑side* matching entry — RE2 matching, driven by the go‑re2 WASM plumbing (`callWithStack` 11.78 %, `matchFrom` 5.46 %, `getChildModule` 4.37 %).
- `…ahocorasick.(*Core).FindDetectorMatches` cum **6.15 %** plus `aho-corasick.(*Trie).Walk` flat **1.38 %** are the keyword prefilter — the routing layer that produces the fan‑out.
- Named detectors on the hot path — `couchbase`, `mapbox`, `snowflake` `Scanner.FromData` — each account for well under 1 %, confirming the A3 finding that **no single detector dominates**; cost is spread across many.

### fgprof full‑goroutine profile (`go tool pprof -top`)

Header (verbatim): `Duration: 15.01s, Total samples = 21556.30s (143625.34%)` — fgprof counts *all* goroutines including the 128 parked workers, so raw percentages are dominated by parked time. Top frames:

```
      flat  flat%   sum%        cum   cum%
         0     0%     0%  21556.19s   100%  runtime.goexit
 21314.76s 98.88% 98.88%  21314.76s 98.88%  runtime.gopark
         0     0% 98.88%  17799.46s 82.57%  runtime.chanrecv2
         0     0% 98.88%  15444.33s 71.65%  …engine.(*Engine).detectorWorker
         0     0% 98.88%   1930.54s  8.96%  …engine.(*Engine).scannerWorker
     0.22s 0.001% 98.88%   1930.42s  8.96%  …engine.(*Engine).verificationOverlapWorker
     0.86s 0.004% 98.89%   1764.74s  8.19%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
```

**Reading fgprof:** `runtime.gopark` at 98.88 % is the 128‑worker pool mostly parked on channels — expected and not a hotspot. The meaningful signal is `Engine.detectorWorker` cum **71.65 %**: active wall‑clock concentrates in the **detector worker pool** (the fan‑out engine), which in turn spends its time in `go-re2 … FindAllStringSubmatch` (8.19 %). This is the same story as the CPU profile and A3 — many detectors, each doing a linear RE2 pass.

### The one "backtrack" frame is Go's **bounded, linear** backtracker — not catastrophic

The CPU profile does contain standard‑library `regexp` frames whose names include "backtrack":

```
      cum   cum%
    1.77s  2.98%  regexp.(*Regexp).doExecute
    1.19s  2.01%  regexp.(*Regexp).backtrack
    1.01s  1.70%  regexp.(*Regexp).tryBacktrack
```

This is **not** evidence of a ReDoS vulnerability. Go's standard‑library `regexp` selects an internal "backtrack" execution strategy for small programs/inputs that is **provably linear** — it keeps a visited‑state bitmap so it can never do exponential work. Go's own source comment (`$GOROOT/src/regexp/backtrack.go`) states the technique `"limits the search to run in time linear in"` the input. These frames come from the ~29 first‑party files that use the standard library (including detectors such as `azure_entra/serviceprincipal/v2`, `azure_cosmosdb`, and `jdbc`). So even the frame literally named `backtrack` is a linear‑time engine: **there is no exponential/catastrophic backtracking signature anywhere in the profile.**

### A5 conclusion

CPU is spent in **linear RE2 matching** (55 % external WASM/RE2 code plus the go‑re2 Go‑side entry points) **fanned across many detectors** via the Aho‑Corasick prefilter and the detector worker pool. There is no single pathological hotspot and no exponential/backtracking signature. This corroborates A2 (RE2 is linear) and A4 (fan‑out, not complexity, is the amplifier).

---

## Sibling resource‑exhaustion vectors — exhaustive coverage

The question asks broadly about "hang or time out," so beyond the regex layer every plausible resource‑exhaustion vector was enumerated and probed. Each is bounded:

| Vector | Mechanism exercised | Observed outcome | Bound (file:line) |
|--------|---------------------|------------------|-------------------|
| **Regex ReDoS** | `(a+)+$` via the custom‑detector path (RE2) | Linear — `6.457806ms` at 9000 `a`s (A2) | RE2 linear‑time [go.mod:L100] |
| **Keyword fan‑out** | 914‑keyword dense file → hundreds of detectors per chunk | Bounded, linear ~62× (A3, A4); slowest single detector `Parsehub: 2.089053ms` | per‑detector 10 s + watchdog [pkg/engine/engine.go:L1066-L1067] |
| **Base64 decoder re‑expansion** | Base64 of keyword text → decode + re‑scan | Constant‑factor amplification ~17× (A4) | decoder chain [pkg/decoders/decoders.go:L8-L14] |
| **Archive / decompression bomb** | 15‑level nested gzip | Stopped at depth 10, `max archive depth reached`, `5.559156ms`, payload never reached (A1) | maxDepth/maxSize/maxTimeout [pkg/handlers/archive.go:L26-L28] |
| **Per‑archive processing** | archive timeout | each archive carried `"timeout": 60` | `WithTimeout(ctx, maxTimeout)` [pkg/handlers/handlers.go:L384] |
| **Chunk size** | large single input | any regex pass ≤ ~13 KiB | ChunkSize+PeekSize [pkg/sources/chunker.go:L14,L16,L18] |

---

## External authoritative sources (support the RE2 linear‑time premise)

These corroborate the engine‑identity reasoning in A2. Quotes are kept short (<20 words) and paraphrased otherwise.

- **wasilibs/go‑re2** (README / pkg.go.dev, the exact engine TruffleHog uses [go.mod:L100]) — the docs state: `"By default, re2 is packaged as a WebAssembly module and accessed with the pure Go runtime, wazero."` This matches the `CGO_ENABLED=0` build and the `wazero`/`runtime._ExternalCode` frames observed in A5; an optional cgo path exists behind the `re2_cgo` build tag (not used here). <https://github.com/wasilibs/go-re2>
- **Google RE2** (project docs / re2‑wasm) — RE2 deliberately omits the constructs that cause exponential runtime; per the docs its `"most noteworthy missing features are backreferences and lookahead assertions,"` and such features are described as `"fundamentally vulnerable to ReDoS."` Because RE2 excludes them, catastrophic backtracking is structurally impossible. <https://github.com/google/re2> · <https://github.com/google/re2-wasm>
- **Go `regexp` package** — the standard library uses RE2 syntax/semantics and runs in time linear in the length of the input (the same guarantee that makes the custom‑detector path in A2 safe). <https://pkg.go.dev/regexp>
- **Checkmarx, "ReDoS in Go"** — independent analysis that Go's RE2‑based engine has no backreferences and guarantees linear‑time execution, staying linear on inputs where Python/JavaScript backtracking engines go exponential — mirroring the A2 canonical‑vs‑Python contrast. <https://checkmarx.com/blog/redos-go/>

---

## Final coverage pass

Every deliverable and sibling variant is addressed with its literal, `file:line`, observed evidence, and rationale:

- [x] **A1 — hang/timeout → NO.** Per‑detector 10 s + watchdog [pkg/engine/engine.go:L1066-L1067], archive depth/size/timeout [pkg/handlers/archive.go:L26-L28], chunk bound [pkg/sources/chunker.go:L14,L16,L18]. Evidence: archive bomb `max archive depth reached` → `scan_duration: "5.559156ms"`, `chunks:0 bytes:0`.
- [x] **A2 — ReDoS → NO.** RE2 engine `go-re2` [pkg/detectors/aws/access_keys/accesskey.go:L17; go.mod:L100]; custom detectors via stdlib `regexp.Compile` [pkg/custom_detectors/custom_detectors.go:L71,L82,L92]; counts 867/29/865/0; regexp2 indirect‑only [go.mod:L187]. Evidence: flat `(a+)+$` curve (9000 → `6.457806ms`) + non‑canonical Python contrast (KILLED at N≥28).
- [x] **A3 — which patterns → fan‑out.** Aho‑Corasick ±512 B window [pkg/engine/ahocorasick/ahocorasickcore.go:L155,L241]; named high‑constant‑factor detectors `reallysimplesystems` {916,1000} [L27], `graphcms` {683} [L27], `refreshtoken` [\w-]{250,} [L39], `aws/session_keys` {100,} [L62]. Evidence: whole scan `3.501589448s` vs printed detectors summing 9.531 ms (0.27 %), slowest `Parsehub: 2.089053ms`.
- [x] **A4 — magnitude → ~62× sustained (up to ~104×), bounded/linear.** Scales 1/4/8/32 MiB, ≥2 runs each; ratios computed from verbatim `scan_duration`; linearity 8/4 MiB ≈ 1.72–1.77×.
- [x] **A5 — timing + CPU profiling.** pprof `runtime._ExternalCode` 55.05 %, `go-re2 FindAllStringSubmatch`, `ahocorasick FindDetectorMatches`; fgprof `detectorWorker` 71.65 %; stdlib `backtrack` frames shown to be the bounded/linear variant.
- [x] **Sibling vectors:** regex ReDoS, keyword fan‑out, base64 re‑expansion, archive bomb, per‑detector & per‑archive timeouts, chunk bound — all covered above.
- [x] **Labels:** `trufflehog dev` = **build‑dependent**; Python `re` contrast = **non‑canonical**; "10 s cap never triggered" = **inferred**.

---

## Reproduction commands (canonical)

```bash
# Build (default WASM/wazero mode)
CGO_ENABLED=0 go build -o /tmp/trufflehog .

# A2 — canonical ReDoS pattern via custom detector
/tmp/trufflehog filesystem <N_a_then_bang_file> --no-verification --config redos_config.yaml

# A1 — nested-gzip archive bomb
/tmp/trufflehog filesystem <15-level-nested-gzip> --no-verification --log-level=5

# A3 — fan-out (per-detector timing to STDERR)
/tmp/trufflehog filesystem <keyword-dense-1MiB> --no-verification --print-avg-detector-time

# A4 — magnitude vs equal-size baseline
/tmp/trufflehog filesystem <baseline|keyword|base64 @ 1/4/8 MiB> --no-verification

# A5 — worst-case CPU profiling (tool's own pprof + fgprof on :18066)
/tmp/trufflehog filesystem <keyword-dense-32MiB> --no-verification --profile &
curl -s "http://localhost:18066/debug/pprof/profile?seconds=15" -o cpu.pprof
curl -s "http://localhost:18066/debug/fgprof?seconds=15&format=pprof" -o fg.pprof
go tool pprof -top cpu.pprof ; go tool pprof -top fg.pprof
```

---

## Cleanup & integrity

- This investigation is **read‑only** with respect to the TruffleHog source tree. The **only** persisted change in the repository is this document, `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- All temporary artifacts live **outside** the repository and were removed after the investigation: the built binary `/tmp/trufflehog`, all adversarial and baseline inputs, generator/harness scripts, the keyword‑dump helper module, and the captured pprof/fgprof profiles — everything under `/tmp` and `/tmp/th_scratch`.
- No existing repository file — source, tests, configuration, `go.mod`, or `go.sum` — was modified. After cleanup, `git status --porcelain` shows only the added `blitzy/` path.

---

### Notes on provenance and reproducibility

Wall‑clock timings vary run‑to‑run and across hardware; the absolute values above were observed on a 4‑core Linux host with Go 1.24.3 and are reported verbatim, with each magnitude confirmed stable across ≥2 runs and ratios recomputed from those verbatim values. The verdicts (A1 NO/bounded; A2 NO/RE2‑linear; A3 fan‑out; A4 bounded‑linear; A5 linear‑RE2 CPU signature) are structural and do not depend on the specific hardware. The `trufflehog dev` version is a build‑dependent placeholder from a plain `go build`; the Python `re` figures are a non‑canonical contrast, not TruffleHog's engine.
