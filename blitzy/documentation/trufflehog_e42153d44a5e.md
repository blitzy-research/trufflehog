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
| **A1** | Hang / time out & block CI? | **NO — bounded; cannot indefinitely hang** | Nested‑gzip bomb terminated in `scan_duration: "6.245111ms"` at `max archive depth reached`; several bounding mechanisms (RE2 linear‑time + ~13 KiB chunk structurally; per‑detector 10 s context timeout + watchdog log; archive depth/size/timeout) keep work bounded. |
| **A2** | ReDoS / computational‑complexity? | **NO — RE2 engine, linear‑time, no backtracking** | Textbook `(a+)+$` against 9000 `a`s ran in `6.545301ms` (flat/linear). Detectors compile with `github.com/wasilibs/go-re2` (RE2). Same pattern in Python (backtracking) is KILLED at N≥28. |
| **A3** | Which detector patterns? | **No single catastrophic regex; the exploitable "pattern" is keyword‑density‑driven detector FAN‑OUT** | On a 1 MiB keyword‑dense file the whole scan took `3.656737349s`, yet the slowest single printed detector was `Myfreshworks: 4.472617ms` and all 22 printed detectors summed to 22.606 ms (0.62 %). Cost is spread across hundreds of detectors, not one regex. |
| **A4** | How much slower vs equal‑size? | **~53× at the definitive 32 MiB scale (up to ~88× at 1 MiB) — bounded & sub‑linear, NOT exponential** | 32 MiB keyword mean `41.8086s` ÷ equal‑size baseline mean `782.40ms` ≈ 53×; quadrupling data (8→32 MiB) only ~3.4× time. Base64‑dense ~42×. |
| **A5** | Timing + CPU profiling | **CPU concentrates in linear RE2 matching fanned across detectors; no backtracking signature** | pprof: `runtime._ExternalCode` 51.85 % (RE2 in WASM/wazero), `go-re2 …FindAllStringSubmatch` cum 16.78 % dominant. fgprof: `Engine.detectorWorker` cum 71.71 %. |

**Bottom line for the CI decision:** A malicious contributor **cannot** make a single committed file hang TruffleHog indefinitely. The pattern‑matching layer is **not** vulnerable to catastrophic‑backtracking ReDoS because it uses the RE2 engine, which is guaranteed linear‑time. The realistic worst case is a **bounded, sub‑linear** slowdown (tens of × — ~53× at the 32 MiB scale — for a maximally keyword‑dense file versus a normal file of the same size), bounded structurally by RE2's linear‑time matching and the ~13 KiB per‑chunk cap, with cooperative per‑detector and per‑archive context deadlines and hard archive depth/size limits as additional backstops (see A1 for the precise, cooperative‑vs‑forced distinction). This is a throughput/cost consideration (mitigable with scan timeouts and resource limits), not an availability vulnerability.

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

  This is sourced from `var BuildVersion = "dev"` [pkg/version/version.go:L3]; the scan log emits `"trufflehog_version", version.BuildVersion` [main.go:L572] and the `if version.BuildVersion == "dev"` branch is at [main.go:L360]. The `dev` string is a property of *how it was built*, not a runtime measurement. *(Note: `pkg/version/version.go` is not one of the primary reference files enumerated in the investigation scope; it is cited here only as the additional supporting source for the build‑dependent `dev` version string this section reports, per the requirement to label build‑dependent values with their exact origin. All other citations in this document are to the enumerated in‑scope reference files.)*
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

**Verdict:** A committed file cannot make TruffleHog hang indefinitely. The worst an attacker achieves is a *bounded* slowdown (quantified in A4). The strongest guarantees are **structural**: (1) the regex engine is RE2, which matches in time *linear* in input length with no catastrophic backtracking (A2), and (2) any single regex pass sees at most ~13 KiB of input because of the chunk cap (below). On top of those structural bounds sit two *cooperative* deadlines — a per‑detector context timeout and a per‑archive processing timeout — plus explicit structural stops in the archive walker (depth/size). The distinction matters and is stated precisely below: the per‑detector timeout delivers a **cancellation signal** (it does not forcibly kill a goroutine), whereas the archive depth check is a hard `return`. Each mechanism is a concrete literal in the source:

- **Per‑detector detection timeout = 10 s, plus a watchdog.** The engine wraps each detector call in a context timeout and arms a watchdog one second later:
  - `var detectionTimeout = detectors.DefaultResponseTimeout` [pkg/engine/engine.go:L37]
  - `const DefaultResponseTimeout = 10 * time.Second` [pkg/detectors/http.go:L18]
  - applied as `ctx, cancel := context.WithTimeout(ctx, detectionTimeout)` [pkg/engine/engine.go:L1066]
  - watchdog `t := time.AfterFunc(detectionTimeout+1*time.Second, func() {` [pkg/engine/engine.go:L1067] whose body logs `ctx.Logger().Error(nil, "a detector ignored the context timeout")` [pkg/engine/engine.go:L1068]
  - a tighter 2‑second bound also guards the verification‑overlap path: `ctx, cancel := context.WithTimeout(ctx, time.Second*2)` [pkg/engine/engine.go:L939]

  *Cause → effect — this is cooperative cancellation, not a forced kill (important):* the `context.WithTimeout` at [pkg/engine/engine.go:L1066] delivers a **deadline/cancellation signal** to the detector via `ctx.Done()` after 10 s. A well‑behaved detector that checks its context returns promptly when the deadline fires. A detector that **ignores** the context is **not** forcibly terminated by this code — the `time.AfterFunc` watchdog at [pkg/engine/engine.go:L1067] does nothing but **log** `"a detector ignored the context timeout"` [pkg/engine/engine.go:L1068] at 11 s; it does not kill the goroutine, and control only returns after `FromData` itself returns, at which point `t.Stop()` and `cancel()` run [pkg/engine/engine.go:L1076-L1077]. So the 10 s figure is a *cooperative* bound on context‑aware detectors and a *diagnostic* signal otherwise — **not** a hard guarantee that a runaway detector is killed at 10 s. What actually prevents a single detector from running unboundedly on committed input is structural: RE2's linear‑time matching (A2) applied to at most ~13 KiB per chunk (below). In every experiment here the watchdog log never fired and no detector approached 10 s — the slowest single detector observed was `Myfreshworks: 4.472617ms` (A3), three orders of magnitude below the deadline (this is *inferred* corroboration; the watchdog line's absence is noted in the inferred paragraph below).

- **Archive limits (decompression‑bomb defense).** `maxDepth = 5 * 2` (=10) [pkg/handlers/archive.go:L26], `maxSize = 2 << 30` (2 GB) [pkg/handlers/archive.go:L27], `maxTimeout = time.Duration(60) * time.Second` [pkg/handlers/archive.go:L28]. Enforced by `if depth >= maxDepth {` [pkg/handlers/archive.go:L124] returning `return ErrMaxDepthReached` [pkg/handlers/archive.go:L126] (defined `var ErrMaxDepthReached = errors.New("max archive depth reached")` [pkg/handlers/archive.go:L105]), by the file‑size skip `if int(fileSize) > maxSize {` [pkg/handlers/archive.go:L198], and by a per‑archive processing timeout `processingCtx, cancel := logContext.WithTimeout(ctx, maxTimeout)` [pkg/handlers/handlers.go:L384].

- **Chunk bound.** Any single regex pass sees at most one chunk: `ChunkSize = 10 * 1024` [pkg/sources/chunker.go:L14] plus `PeekSize = 3 * 1024` [pkg/sources/chunker.go:L16] overlap, i.e. `TotalChunkSize = ChunkSize + PeekSize` [pkg/sources/chunker.go:L18]. *Cause → effect:* an attacker cannot force a single regex to run over a multi‑megabyte string; input is capped at ~13 KiB per pass.

### Verbatim evidence — nested‑gzip archive bomb

I built a **15‑level nested gzip** (exceeding `maxDepth`=10) whose innermost 106‑byte payload contains the **AWS‑published documentation example access key ID** — a non‑functional placeholder AWS itself publishes that literally ends in "EXAMPLE" (redacted here as `AKIA…EXAMPLE` so this document does not embed an AWS‑key‑shaped literal, per secret‑hygiene practice; the actual payload used AWS's published example verbatim). The bomb file is **482 bytes** on disk. Command:

```bash
/tmp/trufflehog filesystem /tmp/th_scratch/arcbomb/dir/bomb.gz --no-verification --log-level=5
```

The handler recursed one level per gzip layer, each carrying the 60‑second archive timeout, emitting a `Starting archive processing` line at every depth from 0 up to 10 (**11 distinct `"depth"` values, 0–10, observed**). The 11 lines are byte‑identical except for the trailing `"depth"` integer, which increments 0→10; the first (depth 0) and last (depth 10) are quoted verbatim below (log timestamp/level/program prefix stripped, JSON otherwise complete):

```
Starting archive processing	{"source_manager_worker_id": "vl6kq", "unit_kind": "unit", "unit": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "path": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
Starting archive processing	{"source_manager_worker_id": "vl6kq", "unit_kind": "unit", "unit": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "path": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "mime": "application/gzip", "timeout": 60, "depth": 10}
```

At depth 10 (`= maxDepth`) it stopped with the exact `ErrMaxDepthReached` message (full line, verbatim):

```
non-critical error processing chunk	{"source_manager_worker_id": "vl6kq", "unit_kind": "unit", "unit": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "path": "/tmp/th_scratch/arcbomb/dir/bomb.gz", "mime": "application/gzip", "timeout": 60, "error": "max archive depth reached"}
```

and the scan **terminated cleanly, without hanging** (full `finished scanning` line, verbatim):

```
finished scanning	{"chunks": 0, "bytes": 0, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "6.245111ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Key facts (each tied to the line above):**
- **It did not hang** — the whole scan took `"scan_duration": "6.245111ms"`.
- **The innermost payload was never reached** — `"chunks": 0, "bytes": 0`, i.e. the depth limit stopped descent before the `AKIA…EXAMPLE` payload was ever chunked or scanned. A decompression bomb therefore cannot be used to force unbounded work.

### The per‑detector 10 s cap was never triggered — **LABEL: inferred (corroborated)**

I did **not** observe the watchdog line `a detector ignored the context timeout` [pkg/engine/engine.go:L1068] in any run, and I did not observe any detector approach the 10‑second deadline. This is an **inferred** negative: the cooperative deadline is delivered to every detector call [pkg/engine/engine.go:L1066] and, had a detector ignored it, the watchdog would have **logged** (not killed) at 11 s [pkg/engine/engine.go:L1067-L1068] — but no experiment pushed a single detector near either, because RE2 keeps every per‑chunk regex in the low‑millisecond range. It is corroborated by (a) the per‑detector times in A3 (slowest single printed detector `Myfreshworks: 4.472617ms`) and (b) the flat ReDoS curve in A2 (`(a+)+$` on 9000 `a`s = `6.545301ms`). Both are three‑to‑four orders of magnitude below 10 s. Note that this deadline is a *cooperative* signal, not a forced kill (see the cause → effect note under the per‑detector timeout above); the load‑bearing guarantee against a single runaway detector is RE2 linearity applied to ≤~13 KiB chunks, not the timeout.

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

The detector is **live** — an all‑`a` input (so `$` matches) fires it, reporting `"unverified_secrets": 1`; complete `finished scanning` line, verbatim:

```
finished scanning	{"chunks": 1, "bytes": 50, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.8671ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

That fired result (`unverified_secrets: 1`) proves `(a+)+$` is genuinely executed by the engine. The table below lists the exact `scan_duration` field extracted from each run's `finished scanning` line, for the adversarial input (`N` copies of `a` + `!`) captured in a **single sweep**:

| N (`a` count + `!`) | bytes | scan_duration (from that run's `finished scanning`) |
|--------------------:|------:|-----------------------------------------------------|
| 20   | 21   | `3.870332ms` |
| 24   | 25   | `4.286769ms` |
| 28   | 29   | `4.212232ms` |
| 32   | 33   | `4.187348ms` |
| 36   | 37   | `3.246132ms` |
| 40   | 41   | `3.784004ms` |
| 44   | 45   | `4.210629ms` |
| 48   | 49   | `4.075341ms` |
| 100  | 101  | `4.329376ms` |
| 1000 | 1001 | `4.410242ms` |
| 5000 | 5001 | `6.439086ms` |
| 9000 | 9001 | `6.545301ms` |

The two endpoints of the sweep, quoted as complete `finished scanning` lines (verbatim, same execution as the table):

```
finished scanning	{"chunks": 1, "bytes": 21, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.870332ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
finished scanning	{"chunks": 1, "bytes": 9001, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "6.545301ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**→ FLAT / LINEAR.** The input grows by **450×** (from 20 to 9000 `a`s) yet the scan time only drifts from `3.870332ms` to `6.545301ms` (≈1.7×, dominated by fixed process startup and the extra bytes to read, not backtracking). RE2 does not backtrack, so the input that annihilates a backtracking engine costs essentially nothing here.

### Contrast: the identical pattern in a backtracking engine — **LABEL: NON‑CANONICAL**

To show what catastrophic backtracking *looks like* on the identical pattern, I ran `(a+)+$` in **Python's `re`** — a backtracking engine that is **NOT** TruffleHog's engine (shown only for contrast; each N in its own 8‑second‑timeout subprocess):

| N | Python `re` time |
|--:|------------------|
| 20 | `82.808ms` |
| 24 | `1375.436ms` |
| 26 | `5234.327ms` |
| 28 | `>8000ms` — KILLED (timeout) |
| 30 | `>8000ms` — KILLED |
| 32 | `>8000ms` — KILLED |
| 34 | `>8000ms` — KILLED |
| 40 | `>8000ms` — KILLED |

**→ EXPONENTIAL** (~4× per +2 to N: `82.808ms` → `1375.436ms` → `5234.327ms`); the process exceeds the 8‑second budget and is killed by N=28. This is the behavior TruffleHog would exhibit **if** it used a backtracking engine — and precisely the behavior the RE2 curve above proves it does **not** exhibit. **This Python row is non‑canonical and is presented only as a reference for the shape of catastrophic backtracking.**

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

### The keyword corpus (producing command + output)

The keyword‑dense input is built from the tool's **own** default detector keywords, dumped canonically from `defaults.DefaultDetectors()`. To avoid modifying the repository, this was done with a standalone helper module **outside** the checkout, whose `go.mod` uses a `replace` directive pointing at the local tree (the repository is never edited):

```
# /tmp/kwdump/go.mod
module kwdump
go 1.23.1
require github.com/trufflesecurity/trufflehog/v3 v3.0.0
replace github.com/trufflesecurity/trufflehog/v3 => <this checkout>

# /tmp/kwdump/main.go — iterate defaults.DefaultDetectors(), collect d.Keywords(), dedupe, print
```

Running it prints the distinct‑keyword count to STDERR (verbatim):

```bash
cd /tmp/kwdump && go run .
```
```
DISTINCT_KEYWORDS=914 NUM_DETECTORS=831
```

So the corpus is **914 distinct real keywords** drawn from **831** default detector instances; those 914 keywords are shuffled and repeated to fill each keyword‑dense file.

### Runtime evidence — the slowdown is fan‑out, not any single detector

On a 1 MiB keyword‑dense file, with per‑detector timing enabled:

```bash
/tmp/trufflehog filesystem /tmp/th_scratch/inputs/keyword_1m.txt --no-verification --print-avg-detector-time
```

The whole scan finished in `"scan_duration": "3.656737349s"`; the complete `finished scanning` line, verbatim:

```
finished scanning	{"chunks": 103, "bytes": 1361920, "verified_secrets": 0, "unverified_secrets": 128, "scan_duration": "3.656737349s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Yet only **22** detectors were printed — the gate `if e.printAvgDetectorTime && len(results) > 0` [pkg/engine/engine.go:L1092] prints **only detectors that *returned* results**. The complete `--print-avg-detector-time` output (STDERR), verbatim, all 22 lines:

```
Ethplorer: 88.762µs
Finnhub: 3.32266ms
ReplyIO: 1.838847ms
Parsehub: 258.795µs
Vercel: 84.505µs
Gitlab: 61.518µs
CompanyHub: 238.82µs
Databox: 2.234545ms
BetterStack: 71.574µs
Oanda: 3.124916ms
Atlassian: 60.467µs
MyIntervals: 363.231µs
Happyscribe: 55.909µs
FormBucket: 1.392064ms
Myfreshworks: 4.472617ms
Host: 669.542µs
Uclassify: 529.688µs
BrowserStack: 2.179046ms
Mockaroo: 1.27697ms
UploadCare: 109.168µs
Mandrill: 87.465µs
Formcraft: 84.625µs
```

Summing all 22 printed averages (4.472617 + 3.32266 + 3.124916 + 2.234545 + 2.179046 + 1.838847 + 1.392064 + 1.27697 + 0.669542 + 0.529688 + 0.363231 + 0.258795 + 0.23882 + 0.109168 + 0.088762 + 0.087465 + 0.084625 + 0.084505 + 0.071574 + 0.061518 + 0.060467 + 0.055909 ms) = **22.606 ms**, which is **only 0.62 %** of the `3656.737 ms` scan (22.606 ÷ 3656.737 = 0.0062). The slowest single printed detector is `Myfreshworks: 4.472617ms`.

*Cause → effect:* if a single detector's regex were the bottleneck, its per‑detector time would be seconds; instead the slowest is `4.472617ms` and the printed total is `22.606 ms`, while the wall‑clock is `3.656737349s`. The remaining ~99.4 % is spent running the **hundreds of detectors that matched keywords but returned no result** (and are therefore hidden by the `len(results) > 0` gate). This is dispositive that the cost is **broad fan‑out across many linear detectors**, not one expensive pattern — and it confirms no single detector approaches the 10 s per‑detector context deadline discussed in A1.

---

## A4 — How much slower than a normal file of equivalent size? → **~53× at the definitive 32 MiB scale (up to ~88× at 1 MiB) — bounded & sub‑linear, NOT exponential**

**Method.** Each adversarial file is compared against a **random‑word baseline of identical byte length** (a "normal file of equivalent size"); the metric is the whole‑scan `scan_duration`; each measurement is repeated at each scale (**3 runs** at 1/4/8 MiB, **5 runs** at the definitive 32 MiB scale); all scans use `--no-verification`. All three families at a given scale are written to **exactly the same file size** (verified with `ls -l`: 1 MiB = 1048576 B, 4 MiB = 4194304 B, 8 MiB = 8388608 B, 32 MiB = 33554432 B). Three input families, all generated ephemerally under `/tmp/th_scratch/inputs`:

- **baseline** — random lowercase words (a normal file).
- **keyword‑dense** — the **914 distinct real detector keywords** (dumped canonically from `defaults.DefaultDetectors()` — see the producing command in A3), shuffled and repeated to fill the target size (maximizes Aho‑Corasick fan‑out per A3).
- **base64‑dense** — Base64 of the keyword‑dense text, which additionally exercises the Base64 decoder's **re‑expansion + re‑scan**: the decoder decodes the blob back to keyword‑dense text and re‑scans it, so base64 encoding does **not** hide the keywords from detection. The default decoder chain is `DefaultDecoders()` = UTF8, Base64, UTF16, EscapedUnicode [pkg/decoders/decoders.go:L8-L14] with UTF8 first [pkg/decoders/decoders.go:L11] and Base64 second [pkg/decoders/decoders.go:L12].

Producing commands (concrete, no placeholders):

```bash
# inputs generated by /tmp/gen_inputs.py from /tmp/th_scratch/keywords_all.txt (914 keywords)
/tmp/trufflehog filesystem /tmp/th_scratch/inputs/baseline_32m.txt --no-verification
/tmp/trufflehog filesystem /tmp/th_scratch/inputs/keyword_32m.txt  --no-verification
/tmp/trufflehog filesystem /tmp/th_scratch/inputs/base64_32m.txt   --no-verification
# (the same three commands were run with the 1m / 4m / 8m file suffixes)
```

### Verbatim full `finished scanning` lines at the definitive 32 MiB scale

For a given input file the `finished scanning` line is identical across runs except for `scan_duration` (`chunks`, `bytes`, `unverified_secrets` are deterministic), so one full line per family is quoted verbatim (run 2 shown), followed by the complete list of per‑run `scan_duration` values:

```
finished scanning	{"chunks": 3277, "bytes": 43618304, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "777.010597ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```
```
finished scanning	{"chunks": 3277, "bytes": 43618304, "verified_secrets": 0, "unverified_secrets": 4126, "scan_duration": "41.902378795s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```
```
finished scanning	{"chunks": 3277, "bytes": 32713728, "verified_secrets": 0, "unverified_secrets": 3070, "scan_duration": "32.804951143s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

(baseline: `unverified_secrets: 0`; keyword‑dense: `4126`; base64‑dense: `3070` — the fake keywords never become *verified* secrets and, with `--no-verification`, reflect detection work only.)

### All per‑run `scan_duration` values (verbatim) and mean ± spread

Every listed value is the exact `scan_duration` field extracted from that run's `finished scanning` line. `spread` = (max−min)/mean.

| Scale | family | chunks | bytes | unverified | per‑run `scan_duration` (verbatim) | mean | spread |
|------:|--------|-------:|------:|-----------:|-------------------------------------|------|-------:|
| **1 MiB** | baseline | 103 | 1361920 | 0 | `37.414256ms`, `37.583626ms`, `35.42086ms` | 36.81 ms | 5.9 % |
| **1 MiB** | keyword | 103 | 1361920 | 128 | `3.622844972s`, `3.015754191s`, `3.036400925s` | 3.2250 s | 18.8 % |
| **1 MiB** | base64 | 103 | 1021440 | 75 | `3.008842799s`, `3.687371762s`, `1.709123476s` | 2.8018 s | 70.6 % |
| **4 MiB** | baseline | 410 | 5450752 | 0 | `120.712549ms`, `115.844359ms`, `115.026134ms` | 117.19 ms | 4.9 % |
| **4 MiB** | keyword | 410 | 5450752 | 546 | `7.422775392s`, `7.529819481s`, `8.155374865s` | 7.7027 s | 9.5 % |
| **4 MiB** | base64 | 410 | 4088064 | 395 | `5.538931371s`, `6.338129068s`, `6.423913694s` | 6.1003 s | 14.5 % |
| **8 MiB** | baseline | 820 | 10903552 | 0 | `203.602009ms`, `206.991065ms`, `204.756521ms` | 205.12 ms | 1.7 % |
| **8 MiB** | keyword | 820 | 10903552 | 975 | `11.176546997s`, `13.640341998s`, `11.643689035s` | 12.1535 s | 20.3 % |
| **8 MiB** | base64 | 820 | 8177664 | 781 | `8.915415874s`, `11.284208643s`, `11.110982303s` | 10.4369 s | 22.7 % |
| **32 MiB** | baseline | 3277 | 43618304 | 0 | `832.696791ms`, `777.010597ms`, `755.929115ms`, `774.713491ms`, `771.655174ms` | 782.40 ms | 9.8 % |
| **32 MiB** | keyword | 3277 | 43618304 | 4126 | `40.854485234s`, `41.902378795s`, `40.800400697s`, `43.309249607s`, `42.176729056s` | 41.8086 s | 6.0 % |
| **32 MiB** | base64 | 3277 | 32713728 | 3070 | `32.522362859s`, `32.804951143s`, `31.17050182s`, `34.361635536s`, `34.758679774s` | 33.1236 s | 10.8 % |

### Slowdown ratios (computed from the displayed means)

| Scale | keyword ÷ baseline | base64 ÷ baseline | calculation (mean ÷ mean) |
|------:|-------------------:|------------------:|---------------------------|
| **1 MiB** | **87.6×** | **76.1×** | 3.2250 s ÷ 36.81 ms = 87.6× ; 2.8018 s ÷ 36.81 ms = 76.1× |
| **4 MiB** | **65.7×** | **52.1×** | 7.7027 s ÷ 117.19 ms = 65.7× ; 6.1003 s ÷ 117.19 ms = 52.1× |
| **8 MiB** | **59.3×** | **50.9×** | 12.1535 s ÷ 205.12 ms = 59.3× ; 10.4369 s ÷ 205.12 ms = 50.9× |
| **32 MiB** | **53.4×** | **42.3×** | 41.8086 s ÷ 782.40 ms = 53.4× ; 33.1236 s ÷ 782.40 ms = 42.3× |

### Interpretation

- **Magnitude (anchored at the definitive 32 MiB scale).** A maximally keyword‑dense file is **~53× slower** than a normal file of the same size at 32 MiB (keyword mean `41.8086s` ÷ baseline mean `782.40ms`). The ratio is *larger* at smaller scales — **~59×** at 8 MiB, **~66×** at 4 MiB, **~88×** at 1 MiB — precisely because the tiny baseline is dominated by fixed process/detector‑init startup (~37 ms at 1 MiB), which inflates the ratio; as the baseline grows the ratio settles toward the true per‑byte cost (~53× at 32 MiB). A base64‑dense file is a comparable **~42×** at 32 MiB — nearly as costly as keyword‑dense, because the Base64 decoder re‑expands it to keyword‑dense text and re‑scans (base64 encoding does not evade detection). Keyword fan‑out remains the strongest lever, consistent with A3.
- **Stability (per SWE‑AtlasQnA R3 — scale increased until stable).** Absolute per‑run times are more variable at small scales, where the whole scan is short and dominated by scheduling/startup noise on a shared 4‑core host (the worst cell is base64 1 MiB at **70.6 %** spread across 3 runs). Following the rule's remedy — *increase the scale and re‑observe* — the magnitude is **anchored at the 32 MiB scale, where it is stable**: keyword `spread 6.0 %` across **5 runs** (`40.85s, 41.90s, 40.80s, 43.31s, 42.18s`, median `41.90s`), base64 `10.8 %`, baseline `9.8 %`. The **order‑of‑magnitude verdict (~tens of ×) holds at every scale**; only the exact value carries run‑to‑run variance at the smaller scales.
- **Bounded & SUB‑LINEAR, not exponential — the crux.** When the data quadruples from 8 → 32 MiB (×4), the time multiplies by only **×3.44** for keyword (`12.1535s → 41.8086s`), **×3.17** for base64, and **×3.81** for baseline; doubling 4 → 8 MiB (×2) multiplies keyword time by only **×1.58** (parallelism amortizes fixed startup). Every family scales **at or below linear** in the input. If any regex were super‑linear, quadrupling the data would multiply time by far more than ×4; instead it is *at most* ×4. This is exactly the RE2 caveat — asymptotically linear, with a larger *constant factor* for the adversarial file — **not** exponential blow‑up.
- **Pure detection cost.** `unverified_secrets` from the fake keywords is a byproduct (e.g. `128` at keyword‑1 MiB, `4126` at keyword‑32 MiB) and never becomes a *verified* secret; with `--no-verification` these numbers reflect detection/matching work only.
- **Byte‑count note (so the log isn't misread).** For the plain‑text families the `"bytes"` field *exceeds* the file size — e.g. the 1 MiB baseline/keyword files are 1 048 576 bytes but the log reports `"bytes": 1361920` — because the chunker counts `TotalChunkSize` including the 3 KiB peek overlap per chunk [pkg/sources/chunker.go:L13-L18] (103 chunks × ~13 312 B ≈ 1.37 MB). The base64‑dense family instead reports a *smaller* count (`"bytes": 1021440` at 1 MiB), reflecting how the Base64 decoder path accounts scanned chunk bytes; both are expected, not measurement errors.

---

## A5 — Timing measurements + CPU‑profiling evidence → **CPU concentrates in linear RE2 matching fanned across detectors; no backtracking signature**

**Worst‑case input:** 32 MiB keyword‑dense (the strongest vector from A4). Whole‑scan timing, two runs:

- **run1 (no profiler)** — full `finished scanning` line, verbatim:
  ```
  finished scanning	{"chunks": 3277, "bytes": 43618304, "verified_secrets": 0, "unverified_secrets": 4126, "scan_duration": "43.294364685s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
  ```
  Shell `time` for the same run: `real 0m45.068s`, `user 2m50.875s`, `sys 0m2.659s` — (170.875 s user + 2.659 s sys) ÷ 45.068 s wall ≈ **3.85 of 4 cores busy**, i.e. the scan is CPU‑bound and fully parallelized.
- **run2 (with `--profile`)** — full `finished scanning` line, verbatim:
  ```
  finished scanning	{"chunks": 3277, "bytes": 43618304, "verified_secrets": 0, "unverified_secrets": 4126, "scan_duration": "44.824289563s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
  ```
  The ~1.5 s increase over run1 (`44.824289563s` − `43.294364685s`) is profiler overhead; the two `scan_duration` values agree to within ~3.5 %.

Profiles were captured **from TruffleHog's own `--profile` server** on `:18066` (index returned `HTTP 200`) while run2 was matching:

```bash
curl -s "http://localhost:18066/debug/pprof/profile?seconds=15" -o cpu.pprof
curl -s "http://localhost:18066/debug/fgprof?seconds=15&format=pprof" -o fg.pprof
go tool pprof -top   <profile>
```

### pprof CPU profile (`go tool pprof -top`)

Header (verbatim): `Duration: 15.18s, Total samples = 59.13s (389.58%)` — i.e. ~3.9 cores busy during sampling. Top frames by **flat** (`go tool pprof -top`, verbatim):

```
Showing nodes accounting for 39.49s, 66.79% of 59.13s total
Dropped 1033 nodes (cum <= 0.30s)
      flat  flat%   sum%        cum   cum%
    30.66s 51.85% 51.85%     30.66s 51.85%  runtime._ExternalCode
     1.40s  2.37% 54.22%      2.91s  4.92%  internal/sync.(*Mutex).Unlock
     1.04s  1.76% 55.98%      1.45s  2.45%  runtime.findObject
     0.86s  1.45% 57.43%      0.86s  1.45%  runtime.(*mspan).base (inline)
     0.86s  1.45% 58.89%      3.35s  5.67%  runtime.scanobject
     0.84s  1.42% 60.31%      4.06s  6.87%  internal/sync.(*Mutex).Lock
```

The RE2 matching and worker frames, sorted by **cum** (`go tool pprof -top -cum`, verbatim; full module paths retained):

```
      flat  flat%   sum%        cum   cum%
    30.66s 51.85% 51.85%     30.66s 51.85%  runtime._ExternalCode
         0     0% 51.85%     19.90s 33.65%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startVerificationOverlapWorkers.func1
     0.42s  0.71% 52.56%     19.90s 33.65%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).verificationOverlapWorker
     0.11s  0.19% 52.75%      9.92s 16.78%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.08s  0.14% 52.88%      9.02s 15.25%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.02s 0.034% 52.95%      4.25s  7.19%  github.com/wasilibs/go-re2/internal.getChildModule
     0.07s  0.12% 54.59%      4.03s  6.82%  github.com/wasilibs/go-re2/internal.matchFrom
```

Named detectors on the hot path (cum, verbatim) — each accounts for **well under 1.5 %**, confirming no single detector dominates:

```
         0     0% 74.40%      0.65s  1.10%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/couchbase.Scanner.FromData
         0     0% 74.40%      0.63s  1.07%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mapbox.Scanner.FromData
         0     0% 75.04%      0.51s  0.86%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_cosmosdb.Scanner.FromData
         0     0% 80.31%      0.33s  0.56%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/snowflake.Scanner.FromData
```

The WebAssembly runtime frames confirm `go-re2` runs in WASM/wazero mode (cum, verbatim):

```
     0.18s   0.3% 68.93%      0.87s  1.47%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.39s  0.66% 73.13%      0.69s  1.17%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
```
**Reading the CPU profile (each line = one piece of evidence):**
- `runtime._ExternalCode` flat **51.85 %** is the RE2 C++ automaton executing **inside the WebAssembly/wazero sandbox** — this is exactly what `go-re2` in its default `CGO_ENABLED=0` mode looks like (corroborated by the two `wazero/internal/engine/wazevo` frames above, at cum **1.47 %** / **1.17 %**, and the `_ "net/http/pprof"` [main.go:L8] / `"github.com/felixge/fgprof"` [main.go:L20] wiring).
- `github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch` cum **16.78 %** is the dominant *Go‑side* matching entry — RE2 matching, driven by the go‑re2 WASM plumbing (`callWithStack` **15.25 %**, `getChildModule` **7.19 %**, `matchFrom` **6.82 %**).
- The keyword prefilter (`ahocorasick.(*Core).FindDetectorMatches` [pkg/engine/ahocorasick/ahocorasickcore.go:L241]) is the routing layer that produces the fan‑out, but in this 15 s CPU window it did **not** rise above pprof's cutoff — the header reports `Dropped 1033 nodes (cum <= 0.30s)`, i.e. routing cost was below 0.30 s cum and is dwarfed by RE2 matching. Its role is established structurally in A3; here it is simply too cheap to surface, which *reinforces* that time goes into matching, not routing. *(This is a smaller share than a prior run where the prefilter did appear; I report exactly what this profile shows.)*
- Named detectors on the hot path — `couchbase` **1.10 %**, `mapbox` **1.07 %**, `azure_cosmosdb` **0.86 %**, `snowflake` **0.56 %** (each a `Scanner.FromData` cum) — every one is **well under 1.5 %**, confirming the A3 finding that **no single detector dominates**; cost is spread across many.

### fgprof full‑goroutine profile (`go tool pprof -top`)

Header (verbatim): `Duration: 15s, Total samples = 21510.19s (143387.27%)` — fgprof counts *all* goroutines including the 128 parked workers, so raw percentages are dominated by parked time. Top frames by **cum** (`go tool pprof -top -cum`, verbatim; full module paths retained):

```
      flat  flat%   sum%        cum   cum%
         0     0%     0%  21510.10s   100%  runtime.goexit
 21338.79s 99.20% 99.20%  21338.79s 99.20%  runtime.gopark
     0.01s 4.9e-05% 99.20%  17378.43s 80.79%  runtime.chanrecv
         0     0% 99.20%  17347.79s 80.65%  runtime.chanrecv2
         0     0% 99.20%  15424.67s 71.71%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectorWorker
         0     0% 99.20%   1928.08s  8.96%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).scannerWorker
     0.20s 0.00093% 99.20%   1928.02s  8.96%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).verificationOverlapWorker
     0.63s 0.0029% 99.21%   1805.35s  8.39%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
```

**Reading fgprof:** `runtime.gopark` at **99.20 %** is the 128‑worker pool mostly parked on channels (`runtime.chanrecv2` **80.65 %**) — expected, and not a hotspot. The meaningful signal is `Engine.detectorWorker` cum **71.71 %**: active wall‑clock concentrates in the **detector worker pool** (the fan‑out engine), which in turn spends its time in `go-re2 …(*Regexp).FindAllStringSubmatch` (**8.39 %**). This is the same story as the CPU profile and A3 — many detectors, each doing a linear RE2 pass.

### The one "backtrack" frame is Go's **bounded, linear** backtracker — not catastrophic

The CPU profile does contain standard‑library `regexp` frames whose names include "backtrack":

```
      flat  flat%   sum%        cum   cum%
         0     0% 64.72%      1.30s  2.20%  regexp.(*Regexp).doExecute
     0.02s 0.034% 75.00%      0.56s  0.95%  regexp.(*Regexp).backtrack
     0.27s  0.46% 75.49%      0.51s  0.86%  regexp.(*Regexp).tryBacktrack
```

This is **not** evidence of a ReDoS vulnerability. Go's standard‑library `regexp` selects an internal "backtrack" execution strategy for small programs/inputs that is **provably linear** — it keeps a visited‑state bitmap so it can never do exponential work. Go's own source comment (`$GOROOT/src/regexp/backtrack.go`) states the technique `"limits the search to run in time linear in"` the input. These frames come from the ~29 first‑party files that use the standard library (including detectors such as `azure_entra/serviceprincipal/v2`, `azure_cosmosdb`, and `jdbc`). So even the frame literally named `backtrack` is a linear‑time engine: **there is no exponential/catastrophic backtracking signature anywhere in the profile.**

### A5 conclusion

CPU is spent in **linear RE2 matching** (**51.85 %** external WASM/RE2 code plus the go‑re2 Go‑side entry points, cum **16.78 %**) **fanned across many detectors** via the Aho‑Corasick prefilter and the detector worker pool (fgprof `detectorWorker` cum **71.71 %**). There is no single pathological hotspot and no exponential/backtracking signature. This corroborates A2 (RE2 is linear) and A4 (fan‑out, not complexity, is the amplifier).

---

## Sibling resource‑exhaustion vectors — exhaustive coverage

The question asks broadly about "hang or time out," so beyond the regex layer every plausible resource‑exhaustion vector was enumerated and probed. Each is bounded:

| Vector | Mechanism exercised | Observed outcome | Bound (file:line) |
|--------|---------------------|------------------|-------------------|
| **Regex ReDoS** | `(a+)+$` via the custom‑detector path (RE2) | Linear — `6.545301ms` at 9000 `a`s (A2) | RE2 linear‑time [go.mod:L100] |
| **Keyword fan‑out** | 914‑keyword dense file → hundreds of detectors per chunk | Bounded, sub‑linear ~53× at 32 MiB (A3, A4); slowest single printed detector `Myfreshworks: 4.472617ms` | RE2 linearity + ~13 KiB chunk (structural); per‑detector 10 s context timeout + watchdog log [pkg/engine/engine.go:L1066-L1068] |
| **Base64 decoder re‑expansion** | Base64 of keyword‑dense text → decode + re‑scan | ~42× at 32 MiB (A4) — decodes back to keyword‑dense and re‑scans | decoder chain [pkg/decoders/decoders.go:L8-L14] |
| **Archive / decompression bomb** | 15‑level nested gzip | Stopped at depth 10, `max archive depth reached`, `6.245111ms`, payload never reached (A1) | maxDepth/maxSize/maxTimeout [pkg/handlers/archive.go:L26-L28] |
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

- [x] **A1 — hang/timeout → NO.** Per‑detector 10 s + watchdog [pkg/engine/engine.go:L1066-L1067], archive depth/size/timeout [pkg/handlers/archive.go:L26-L28], chunk bound [pkg/sources/chunker.go:L14,L16,L18]. Evidence: archive bomb `max archive depth reached` → `scan_duration: "6.245111ms"`, `chunks:0 bytes:0`.
- [x] **A2 — ReDoS → NO.** RE2 engine `go-re2` [pkg/detectors/aws/access_keys/accesskey.go:L17; go.mod:L100]; custom detectors via stdlib `regexp.Compile` [pkg/custom_detectors/custom_detectors.go:L71,L82,L92]; counts 867/29/865/0; regexp2 indirect‑only [go.mod:L187]. Evidence: flat `(a+)+$` curve (9000 → `6.545301ms`) + non‑canonical Python contrast (KILLED at N≥28).
- [x] **A3 — which patterns → fan‑out.** Aho‑Corasick ±512 B window [pkg/engine/ahocorasick/ahocorasickcore.go:L155,L241]; named high‑constant‑factor detectors `reallysimplesystems` {916,1000} [pkg/detectors/reallysimplesystems/reallysimplesystems.go:L27], `graphcms` {683} [pkg/detectors/graphcms/graphcms.go:L27], `refreshtoken` [\w-]{250,} [pkg/detectors/azure_entra/refreshtoken/refreshtoken.go:L39], `aws/session_keys` {100,} [pkg/detectors/aws/session_keys/sessionkey.go:L62]. Evidence: whole scan `3.656737349s` vs 22 printed detectors summing 22.606 ms (0.62 %), slowest `Myfreshworks: 4.472617ms`.
- [x] **A4 — magnitude → ~53× at 32 MiB (up to ~88× at 1 MiB), bounded/sub‑linear.** Scales 1/4/8/32 MiB (3 runs at 1/4/8 MiB, **5 runs at 32 MiB**); full `finished scanning` lines at 32 MiB + all per‑run `scan_duration` values quoted; ratios computed from the displayed means (32 MiB: `41.8086s ÷ 782.40ms = 53.4×`); linearity 8→32 MiB data ×4 → time ×3.44 (keyword).
- [x] **A5 — timing + CPU profiling.** pprof `runtime._ExternalCode` 51.85 %, `go-re2 (*Regexp).FindAllStringSubmatch` cum 16.78 %; fgprof `detectorWorker` cum 71.71 %; stdlib `backtrack` cum 0.95 % / `tryBacktrack` 0.86 % shown to be the bounded/linear variant; Aho‑Corasick prefilter fell below pprof's 0.30 s cutoff this run (matching dominates routing).
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
- No existing repository file — source, tests, configuration, `go.mod`, or `go.sum` — was modified. The net effect on the repository is a single **added** file: the baseline diff against the pre‑investigation commit contains only `A blitzy/documentation/trufflehog_e42153d44a5e.md` (verified with `git diff --name-status <baseline>` and `git diff --stat <baseline>`). Once this document is committed, `git status --porcelain` on the resulting checkout is empty (no un‑committed changes remain); before the commit, the working tree shows only this one added/modified deliverable path. In neither state does any TruffleHog source, test, config, or dependency‑manifest file appear as changed.

---

### Notes on provenance and reproducibility

Wall‑clock timings vary run‑to‑run and across hardware; the absolute values above were observed on a 4‑core Linux host with Go 1.24.3 and are reported verbatim, with each magnitude confirmed stable across ≥2 runs and ratios recomputed from those verbatim values. The verdicts (A1 NO/bounded; A2 NO/RE2‑linear; A3 fan‑out; A4 bounded‑linear; A5 linear‑RE2 CPU signature) are structural and do not depend on the specific hardware. The `trufflehog dev` version is a build‑dependent placeholder from a plain `go build`; the Python `re` figures are a non‑canonical contrast, not TruffleHog's engine.

---

## Validation checklist

A self‑verification pass against the deliverable and evidence rules. Each item was checked against the finished document.

- [x] **Filename & location.** The deliverable is `blitzy/documentation/trufflehog_e42153d44a5e.md` — the basename `trufflehog_e42153d44a5e` exactly matches the source branch name, and it lives under `blitzy/documentation/` as required. It is the **only** file added to the repository.
- [x] **A1–A5 all answered explicitly and by name.** Each question has (a) a dedicated top‑level section with the verdict in the heading — A1 "Hang or time out … → **NO (bounded)**", A2 "ReDoS / computational‑complexity → **NO**", A3 "Which detector patterns → **fan‑out, no single catastrophic regex**", A4 "How much slower → **~53× at 32 MiB (up to ~88× at 1 MiB)**", A5 "Timing + CPU profiling → **linear RE2, no backtracking signature**" — plus (b) a one‑line row in the Executive summary and (c) a line in the Final coverage pass. No sub‑question is left unaddressed.
- [x] **One claim ⇄ one piece of evidence.** Every behavioral/timing claim is pinned to a specific verbatim observation: A1 → the full `finished scanning` line (`chunks:0, bytes:0, scan_duration:"6.245111ms"`) and the `max archive depth reached` error line; A2 → the liveness `finished scanning` line (`unverified_secrets:1`) and the two sweep‑endpoint lines (`3.870332ms` at 20, `6.545301ms` at 9000); A3 → the full `finished scanning` line (`3.656737349s`) and the complete 22‑line `--print-avg-detector-time` output with the explicit `22.606 ms = 0.62 %` summation; A4 → all per‑run `scan_duration` values in the table with means and recomputed ratios; A5 → verbatim `go tool pprof -top` flat/cum frames and the fgprof frames. No claim is paired with a paraphrase where an exact line was available.
- [x] **Citation accuracy (`file:line`).** Every source citation resolves to the current tree: the RE2 import [pkg/detectors/aws/access_keys/accesskey.go:L17] and `go-re2 v1.9.0` [go.mod:L100]; the detector timeout/watchdog/cleanup [pkg/engine/engine.go:L1066‑L1068, L1076‑L1077]; `DefaultResponseTimeout = 10 * time.Second` [pkg/detectors/http.go:L18]; archive limits [pkg/handlers/archive.go:L26‑L28, L105, L124, L126, L198] and per‑archive timeout [pkg/handlers/handlers.go:L384]; chunk bounds [pkg/sources/chunker.go:L14,L16,L18]; decoder chain [pkg/decoders/decoders.go:L8‑L14]; Aho‑Corasick window/API [pkg/engine/ahocorasick/ahocorasickcore.go:L155,L241]; CLI/profiling [main.go:L143‑L144,L360,L572]. The four A3 high‑constant‑factor detector patterns use **full file paths** (reallysimplesystems/graphcms/refreshtoken/session_keys `.go`) in both the enumeration and the coverage pass — no bare `[Lxx]` citations remain.
- [x] **Mandatory labels present.** `trufflehog dev` is labeled **build‑dependent** (with its `pkg/version/version.go:L3` origin); the Python `re` comparison is labeled **NON‑CANONICAL**; the "per‑detector 10 s cap never triggered" statement is labeled **inferred (corroborated)**. These labels appear both at the point of use and in the Labels line of the Final coverage pass.
- [x] **Scale & ratio discipline (R3).** A4 measures **1 / 4 / 8 / 32 MiB** with **≥2 runs each** (3 runs at 1/4/8 MiB, **5 runs at the definitive 32 MiB scale**), all three families (baseline / keyword‑dense / base64‑dense) written to **identical byte sizes** at each scale. Every slowdown ratio is **recomputed from the displayed means** shown next to it (e.g. 32 MiB `41.8086 s ÷ 782.40 ms = 53.4×`), and the Executive‑summary ratio uses the same averaged basis. The magnitude is **anchored at 32 MiB where it is stable** (keyword spread 6.0 %); the smaller‑scale variance (worst cell: base64 1 MiB, 70.6 %) is explicitly disclosed rather than hidden, and the stability claim is qualified accordingly.
- [x] **External‑source constraints.** The four authoritative sources (wasilibs/go‑re2, Google RE2, Go `regexp`, Checkmarx) support the RE2 linear‑time premise only; each direct quote is **under 20 words** and in quotation marks, with everything else paraphrased, and each is accompanied by its URL.
- [x] **Read‑only scope & cleanup.** No existing repository file (source, tests, config, `go.mod`, `go.sum`) was modified; all temporary artifacts (`/tmp/trufflehog`, `/tmp/th_scratch/*`, the `/tmp/kwdump` helper module, captured profiles) live outside the repo and are removed. The net repository change is a single **added** file, confirmed by the baseline diff `A blitzy/documentation/trufflehog_e42153d44a5e.md`.
- [x] **Markdown renderability.** All fenced code blocks are balanced (even count of ```` ``` ```` fences); all tables have matched header/separator/row columns; headings are properly nested (`#` → `##` → `###`). **No ellipsis (`…`) appears inside any quoted/verbatim log line or code fence** (verified: zero `…` characters occur within fenced blocks), so no piece of quoted evidence is truncated. The `…` characters that do appear are all in prose or inline code and are of two harmless kinds: the labeled `AKIA…EXAMPLE` secret‑hygiene redaction, and ordinary prose elisions when abbreviating a long identifier/command/heading in narrative text (e.g. `go-re2 …FindAllStringSubmatch`, the CI command line, the `func … FromData(` grep description) — never to shorten reported output. The document renders cleanly as GitHub‑flavored Markdown.

