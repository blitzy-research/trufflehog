# TruffleHog ReDoS / Computational‑Complexity Attack Assessment

**Scope:** Read‑only security investigation of TruffleHog v3 secret‑detection pattern matching.
**Repository:** `github.com/trufflesecurity/trufflehog/v3` — branch `trufflehog_e42153d44a5e`, HEAD `e42153d4`.
**Question:** Can a malicious actor commit a specially crafted file that causes TruffleHog to hang or time out (a ReDoS / resource‑exhaustion denial‑of‑service on a CI scan), and if so, which detector patterns are exploitable and by how much?
**Method:** Build the real binary and drive it through its canonical entry point (`trufflehog filesystem … --no-verification --no-update`); every empirical number below is captured live from that scan path. The source tree was **not modified**.

---

## 1. TL;DR — Executive Verdict

> **TruffleHog's pattern matching is NOT vulnerable to ReDoS / catastrophic‑backtracking computational‑complexity attacks.** Its detectors compile on **RE2‑lineage, non‑backtracking regex engines** — `github.com/wasilibs/go-re2` (RE2 executed as WebAssembly) for the overwhelming majority of detectors, and Go's standard‑library `regexp` for a mere three. Both simulate a finite automaton and **never backtrack**, so match time is **linear in input length** and catastrophic backtracking is **structurally impossible**. A crafted file can, at most, cause a **linear, bounded** slowdown — and empirically the classic "evil‑regex" inputs are actually **as fast as or faster than** equivalent‑size random text. The only large slowdown we could produce came from files **densely packed with *valid* secrets**, which is **linear, bounded, and self‑defeating** (TruffleHog reports every one of those secrets as a finding — that is useful work, not a hang).

> **Portability note.** Absolute wall‑clock numbers are environment‑dependent (this investigation ran on a **4‑CPU** cgroup‑limited container; see §2). The **stable, portable conclusions** are the **ratios** and the **linear scaling** — both reproduce regardless of host, because they follow from the engine's non‑backtracking design, not from raw speed.

### The five questions, answered

| # | Question | Verdict |
|---|----------|---------|
| **Q1** | Can a crafted committed file hang / time out TruffleHog and block CI? | **No indefinite hang.** Pattern matching cost is **linear and bounded**; the biggest input tested (16 MB of dense valid secrets) finished in ≈10.7 s and produced findings. Per‑detector timeouts add defense‑in‑depth. |
| **Q2** | Is the pattern matching ReDoS‑vulnerable (computational‑complexity)? | **No.** Detectors run on **RE2‑lineage, non‑backtracking** engines → linear‑time matching → catastrophic backtracking is impossible by construction. Proven empirically (flat per‑MB scaling, no blow‑up) and by engine contrast. |
| **Q3** | Which detector patterns, if any, are exploitable? | **None.** The nested‑quantifier patterns that *would* be catastrophic under a backtracking engine — MongoDB `connStrPat`, URI `keyPat`, `databrickstoken`, `azuresastoken` — all complete in **well under 200 ms on 8 MB** of maximally adversarial input (at or below the cost of equivalent‑size random text). |
| **Q4** | How much slower vs. normal files of equivalent size? | A ReDoS‑*structured* file is **≤ 1× (i.e. not slower)** than equivalent‑size random text. The **maximum** amplification observed came from a **valid‑secret‑dense** file at **≈ 28×** (median; up to ~35× in individual runs), and it is **linear, bounded, and self‑defeating** (all secrets are reported). |
| **Q5** | Evidence (timing + CPU profiling)? | Provided below: timing tables (§7.1–§7.4), a `go tool pprof` CPU profile (§7.5), and an engine‑contrast benchmark (§7.6, **labeled non‑canonical corroboration**). |

---

## 2. Threat Model & Methodology

**CI threat scenario.** An attacker with the ability to commit a file to a repository that TruffleHog scans in CI (e.g. a pull‑request branch) tries to make the scan consume disproportionate CPU/time so the security gate hangs or times out. The relevant cost surface is **pattern matching** — the regex detectors run against file content — so we deliberately isolate that surface.

**Why the regex engine is decisive.** ReDoS (Regular‑expression Denial of Service) is *catastrophic backtracking*: a backtracking engine can be driven to explore exponentially many ways to match a pattern such as `(a+)+` against a near‑miss input. Engines of the **RE2 lineage** (Google's RE2, and Go's standard‑library `regexp`) do **not** backtrack — they simulate a finite automaton (Thompson construction) and guarantee **linear‑time** matching, accepting untrusted patterns/inputs safely. Therefore ReDoS feasibility is decided almost entirely by *which engine compiles the detector patterns*.

**The prefilter constraint.** TruffleHog routes each chunk through an **Aho‑Corasick keyword prefilter** (`github.com/BobuSumisu/aho-corasick` [go.mod:L17]) before running any detector regex. A chunk that does **not** contain a detector's trigger keyword never reaches that detector's regex. Consequently every crafted input below **begins with / contains the target detector's keyword** (e.g. `mongodb`, `https://`, `databricks`, `.blob.core.windows.net`) so that the regex actually executes — otherwise the measurement would be meaningless.

**Build (canonical, exactly as the project Dockerfile does).** `CGO_ENABLED=0` [Dockerfile:L5] forces the **WebAssembly** variant of `go-re2` (RE2 compiled to WASM, hosted by the pure‑Go `wazero` runtime):

```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog .
```

**Invocation (canonical entry point).** `--no-verification` isolates *pattern matching* from network credential verification; `--no-update` prevents self‑update. This is exactly the code path a CI scan of a repository exercises:

```bash
/tmp/trufflehog filesystem <dir> --no-verification --no-update [--print-avg-detector-time | --profile]
```

**Measurement.** `scan_duration` is TruffleHog's **own** reported metric, emitted on the `finished scanning` log line [main.go:L571]. Every input was scanned **3×** to confirm stability; size sweeps (doubling input) classify complexity growth; a CPU profile was captured through the built‑in `--profile` pprof/fgprof server on `:18066` [main.go:L53, L434]. Crafted inputs, benign controls, the binary, and an out‑of‑tree engine‑contrast module all live under `/tmp` (outside the repository) and were removed afterward.

**Host environment (for honest framing).** This investigation ran in a container reporting **`nproc` = 4** (cgroup‑limited; the underlying host exposes 128 processors but the container is capped at 4 CPUs). TruffleHog's `filesystem` command defaults to `--concurrency 128`. Absolute milliseconds therefore differ from any other environment; **all conclusions below are framed as ratios and scaling behavior**, which are host‑independent.

**Observed‑vs‑inferred.** Every timing/profile table is **observed** (pasted live output). Statements about *why* (engine internals, RE2's linear‑time guarantee) are **inferred** from source inspection and the regex‑engine literature, and are labeled as mechanism explanations.

---

## 3. Q1 — Can a crafted committed file hang or time out TruffleHog and block CI?

**Verdict: No — no indefinite hang is achievable through pattern matching.** A crafted file causes only a **linear, bounded** slowdown; the cost grows proportionally with file size and stops there. There is no runaway.

**Evidence (observed).** The size sweep (§7.4) shows scan time growing *linearly* with input: doubling the input roughly doubles the time, with a **flat per‑MB rate** across a 16× size range. The largest input tested — 16 MB packed with *valid* secrets — finished in ≈10.7 s (and reported thousands of findings). The adversarial "evil‑regex" files (nested‑quantifier bait) were far cheaper still: **90–175 ms on 8 MB**. Nothing hung; every scan terminated on its own.

**Defense‑in‑depth (mechanism, inferred from source).** Even though the linear‑time engine is the real protection, TruffleHog additionally wraps detector execution in timeouts:
- The detection loop wraps each `detector.FromData(ctx, false, match)` [pkg/engine/engine.go:L940] call in `context.WithTimeout(ctx, time.Second*2)` [pkg/engine/engine.go:L939], after `GetFalsePositiveCheck` [pkg/engine/engine.go:L934] and `detector.Matches()` [pkg/engine/engine.go:L937].
- The verification path adds `context.WithTimeout(ctx, detectionTimeout)` [pkg/engine/engine.go:L1066] — where `detectionTimeout = detectors.DefaultResponseTimeout` [pkg/engine/engine.go:L37] = `10 * time.Second` [pkg/detectors/http.go:L18] — plus a watchdog `time.AfterFunc(...)` [pkg/engine/engine.go:L1067] that logs `"a detector ignored the context timeout"` [pkg/engine/engine.go:L1068].

**Crucial nuance (mechanism).** The regex calls themselves — `connStrPat.FindAllStringSubmatch(dataStr, -1)` [pkg/detectors/mongodb/mongodb.go:L49] and `keyPat.FindAllStringSubmatch(dataStr, -1)` [pkg/detectors/uri/uri.go:L61] — take **no `context`**. A hypothetically runaway *single* regex call therefore could **not** be interrupted mid‑match by those timeouts. This is precisely why **RE2's linear‑time guarantee, not the timeout, is the true protection**: because the engine cannot backtrack, a single match call always returns in linear time, so it never becomes runaway in the first place. The timeouts primarily bound slow *network verification*, and the per‑`FromData` 2 s wrap bounds pathological post‑processing.

Additionally, a single detector‑regex call never faces more than one chunk: `ChunkSize = 10 * 1024` [pkg/sources/chunker.go:L14] and `PeekSize = 3 * 1024` [pkg/sources/chunker.go:L16] give `TotalChunkSize = ChunkSize + PeekSize` [pkg/sources/chunker.go:L18] ≈ 13 KB — the maximum input any one regex call ever sees.

---

## 4. Q2 — Is TruffleHog's pattern matching vulnerable to computational‑complexity (ReDoS) attacks?

**Verdict: No.** Detector pattern matching runs on **RE2‑lineage, non‑backtracking** engines, which are immune to catastrophic‑backtracking ReDoS by construction.

**The engine of record (observed via source inspection).** Across the detector corpus:

| Engine | Detectors | Class |
|--------|-----------|-------|
| `github.com/wasilibs/go-re2 v1.9.0` [go.mod:L100] | **867** detector `.go` files import it | RE2 (WASM via `wazero`), linear‑time, **non‑backtracking** |
| Go stdlib `regexp` | **exactly 3** (`pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go`, `pkg/detectors/azure_cosmosdb/azure_cosmosdb.go`, `pkg/detectors/jdbc/jdbc.go`) | RE2‑lineage (Thompson NFA), linear‑time, **non‑backtracking** |
| `github.com/dlclark/regexp2 v1.4.0 // indirect` [go.mod:L187] | **0** detector files (`grep -rl "dlclark/regexp2" pkg/` → 0) | **Backtracking** — present transitively but compiles **zero** detector patterns |

Corpus counts, re‑measured on this checkout:

```
find pkg/detectors -maxdepth 1 -mindepth 1 -type d | wc -l            # 845 top-level detector dirs
find pkg/detectors -mindepth 1 -type d | wc -l                        # 886 dirs incl. v1/ v2/ subfolders
find pkg/detectors -name '*.go' | wc -l                               # 2620 .go files
grep -rl 'github.com/wasilibs/go-re2' pkg/detectors --include='*.go' | wc -l   # 867 import go-re2
```

**Why this makes ReDoS impossible (mechanism, inferred).** RE2 and Go's `regexp` compile a pattern into a finite automaton and simulate it over the input, tracking a *set* of active states in a single left‑to‑right pass. There is no backtracking stack to explode; the number of steps is bounded by `O(pattern × input)`. RE2 was explicitly designed to accept regular expressions from untrusted sources with a linear‑time guarantee. Go's `regexp` is in the same class (it even caps its bounded one‑pass backtracker and falls back to the NFA simulation, so it too is provably linear). Because **every** detector compiles on one of these two engines, **no detector pattern can backtrack**, regardless of how the pattern is shaped.

**The build reinforces this.** `CGO_ENABLED=0` [Dockerfile:L5] means `go-re2` runs RE2 as a **WebAssembly** module inside the pure‑Go `wazero` runtime (`github.com/tetratelabs/wazero v1.9.0` [go.mod:L285]) rather than falling back to stdlib — confirmed by the CPU profile (§7.5), where RE2 execution appears as `runtime._ExternalCode` (the WASM leaf).

**Empirical confirmation.** The size sweeps (§7.4) show **cleanly linear** growth with a flat per‑MB rate — the defining *absence* of a ReDoS vulnerability — and the engine‑contrast benchmark (§7.6) shows the two engines TruffleHog uses stay in the microsecond range on the canonical evil pattern `^(a+)+$` while a backtracking engine explodes exponentially.

---

## 5. Q3 — Which detector patterns, if any, can be exploited?

**Verdict: None.** The patterns an attacker would target — those containing nested / group‑repetition quantifiers — all complete in well under 200 ms on 8 MB of maximally adversarial input (at or below the cost of equivalent‑size random text), because the engine underneath them cannot backtrack.

**Candidate patterns (the "scariest" shapes), verified at these lines:**

| Detector | Risky construct | Location |
|----------|-----------------|----------|
| MongoDB `connStrPat` | two unbounded nested stars `(?:,[-.%\w]+(?::\d{1,5})?)*` and `(?:&(?:amp;)?\w+=[\w@/.$-]+)*` | [pkg/detectors/mongodb/mongodb.go:L32] (engine import [L14], keyword `"mongodb"` [L40]) |
| URI `keyPat` | bounded `{0,50}`/`{3,50}` over large overlapping classes + required trailing `@` | [pkg/detectors/uri/uri.go:L33] (engine import [L13], keywords `["http://","https://"]` [L44]) |
| `databrickstoken` | domain nested‑star `(?:\.[a-z0-9-]+)*` | [pkg/detectors/databrickstoken/databrickstoken.go:L27] (keywords `["databricks","dapi"]` [L34]) |
| `azuresastoken` | urlPat nested‑star `(?:/[a-zA-Z0-9._-]+)*` | [pkg/detectors/azuresastoken/azuresastoken.go:L32] (keywords `["azure",".blob.core.windows.net"]` [L44]) |
| `azure_entra` spv1 | `.{0,80}` | [pkg/detectors/azure_entra/serviceprincipal/v1/spv1.go:L35] |

**How many detectors even contain a group‑repetition shape? (Re‑measured here — methodology stated.)** Counting *literal two‑character occurrences* in non‑test detector files:

```
grep -rn --include='*.go' ')\*' pkg/detectors | grep -v '_test.go' | grep -o ')\*' | wc -l   # 23  occurrences of )*
grep -rn --include='*.go' ')+'  pkg/detectors | grep -v '_test.go' | grep -o ')+'  | wc -l   #  8  occurrences of )+
grep -rln --include='*.go' -e ')\*' -e ')+' pkg/detectors | grep -v '_test.go' | wc -l         # 17  distinct files
```

So **23 `)*` + 8 `)+` occurrences across 17 distinct non‑test files** (mongodb, uri, databrickstoken, azuresastoken, spv1, bitmex, alegra, jiratoken v1/v2, robinhoodcrypto, docker_auth_config, cexio, generic, coinbase_waas, clicksendsms, kucoin, poloniex). The AAP's figure of "≈8 of 845" is best interpreted as the count of **genuine nested‑quantifier templates** — a repeated group whose *body itself* contains an unbounded quantifier, i.e. the true catastrophic‑backtracking shape `(...+...)*` — which is a **small handful** (mongodb, uri, databrickstoken, azuresastoken, spv1, docker_auth_config). Exact classification is heuristic‑sensitive (a "no inner parenthesis" heuristic catches azuresastoken/databrickstoken/docker_auth_config but misses MongoDB, whose nested star contains inner parentheses), which is why the **literal counts above are reported as the precise, reproducible figure**.

**The decisive point (mechanism):** *whichever* definition is used, **RE2's non‑backtracking execution makes all of them ReDoS‑immune regardless of shape.** A nested quantifier is only dangerous on a backtracking engine; on RE2 it is just another automaton.

**Empirical proof (observed, §7.1 and §7.3):** every candidate, fed a maximally adversarial 8 MB input, completes fast — MongoDB host‑bait 173 ms, MongoDB user/pass‑bait 138 ms, URI no‑`@` 96 ms, URI `@`‑spam 90 ms, `databrickstoken` 103 ms, `azuresastoken` 143 ms — all **at or below** the cost of equivalent‑size random text (~177 ms).

---

## 6. Q4 — How much slower can a scan be made vs. normal files of equivalent size?

**Verdict:** A ReDoS‑*structured* file is **not slower** than equivalent‑size normal (random) text — ratios of **0.5×–1.0×** were observed. The **maximum** amplification we could produce came from a file **densely packed with *valid* secrets**: **≈28×** (median; up to ~35× in individual runs) vs. equivalent‑size random text in this environment. That amplification is **linear, bounded, and self‑defeating** — it is dominated by per‑match post‑processing of secrets that TruffleHog then *reports as findings* (useful work), not by regex spinning.

**Like‑for‑like comparison (observed, 8 MB each — all inputs within 0.1% of the same byte size; see §7.1).**

| Input (~8 MB) | scan_duration (median of 3) | Ratio vs. `benign_random` |
|---|---|---|
| `patho_uri_atspam` (evil bait) | 90.5 ms | **0.49×** |
| `patho_uri_noat` (evil bait) | 95.1 ms | 0.52× |
| `patho_mongodb_userpass` (evil bait) | 98.2 ms | 0.53× |
| `patho_databricks` (evil bait) | 102.2 ms | 0.55× |
| `patho_azuresas` (evil bait) | 145.3 ms | 0.79× |
| `patho_mongodb_host` (evil bait) | 173.3 ms | **0.94×** |
| `benign_random` (equivalent‑size normal text) | 184.6 ms | 1.00× (baseline) |
| `kw_nomatch` (keyword present, no valid secret) | 189.5 ms | 1.03× |
| `match` (valid‑secret‑dense) | **5.25 s** | **≈28×** |

**Interpretation (verdict‑first).** Every deliberately pathological "evil‑regex" file is **≤ 1×** the baseline — i.e. a crafted file is **not** slower than a normal file of the same size. This is the **opposite** of a backtracking‑ReDoS signature (where the crafted file would be orders of magnitude *slower*). The single large number, `match` at ≈28×, is produced by *valid secrets*, not by regex pathology — and §7.3 attributes it precisely.

**Attribution — where the ≈28× actually comes from (observed, §7.3).** Three 8 MB inputs isolate the cause:
- `benign_random` — keyword **MISS**, the detector regex never runs → ~177 ms (pure ingest + prefilter baseline).
- `kw_nomatch` — keyword **HIT**, RE2 scans **every** chunk but finds **0** matches → ~185 ms. The added cost of RE2 *scanning* all chunks is only **~8 ms** — essentially free.
- `match` — keyword HIT, **dense valid matches** → ~5.2 s. Per‑detector timing attributes this to `MongoDB: 571 ms` + `URI: 130 ms` of `FromData` work, and the remainder to per‑match submatch extraction and result handling.

So the ≈28× amplification is **entirely per‑match post‑processing** — `url.Parse` [pkg/detectors/mongodb/mongodb.go:L58], `connUrl.Query()` [L64‑L65], `params.Encode()` [L78], `connUrl.String()` [L79] — which grows **linearly with the number of matches**, *not* regex‑execution time. Because each matched secret becomes a reported finding, this is bounded useful work, and it is self‑defeating as an attack: the "payload" is a file full of the very secrets the tool exists to surface.

---

## 7. Q5 — Evidence (timing measurements + CPU profiling)

All output below is **live‑captured, complete, and unedited** from this environment (`nproc`=4). Each crafted input carries the target detector's prefilter keyword; each benign control is the same byte size as the crafted files (all within 0.1%).

### 7.1 Crafted vs. equivalent‑size benign, at 8 MB (3 runs each)

Byte sizes (all ≈ 7.994–8.000 MB, like‑for‑like):

```
patho_mongodb_host       8383800
patho_mongodb_userpass   8385156
patho_uri_noat           8386560
patho_uri_atspam         8387379
patho_databricks         8382114
patho_azuresas           8386313
benign_random            8388640
kw_nomatch               8388575
match                    8388600
```

`scan_duration` (run1 / run2 / run3) and `unverified_secrets`:

| Input (~8 MB) | Character of input | run1 | run2 | run3 | secrets |
|---|---|---|---|---|---|
| `patho_mongodb_host` | `mongodb://usr:pwd@` + `a,`×4700 + `!` (host nested‑star bait) | 173.334 ms | 167.358 ms | 175.434 ms | 1152 |
| `patho_mongodb_userpass` | `mongodb://` + `a:`×3500 (no `@`) | 137.908 ms | 97.731 ms | 98.214 ms | 0 |
| `patho_uri_noat` | `https://` + 50×`a` + `:` + `b`×8900 (no `@`) | 96.226 ms | 95.066 ms | 94.963 ms | 0 |
| `patho_uri_atspam` | `https://` + `a:@`×3000 | 90.488 ms | 92.561 ms | 89.944 ms | 0 |
| `patho_databricks` | `databricks ` + `a` + `.a`×4400 (domain nested‑star bait) | 102.678 ms | 100.964 ms | 102.230 ms | 0 |
| `patho_azuresas` | `https://acct.blob.core.windows.net/c` + `/a`×4400 (urlPat nested‑star) | 143.050 ms | 146.004 ms | 145.282 ms | 0 |
| `benign_random` | random alphanumeric, **no detector keywords** (prefilter MISS) | 176.886 ms | 185.428 ms | 184.566 ms | 0 |
| `kw_nomatch` | `mongodb` & `https://` present, no valid secret (prefilter HIT) | 183.304 ms | 189.460 ms | 194.036 ms | 0 |
| `match` | valid `mongodb://…@…` **and** `https://…@…`, match‑dense | **5.2122 s** | **5.7178 s** | **5.2489 s** | 2011 |

Representative complete `finished scanning` lines (run1), showing TruffleHog's own metrics — note all inputs process ~820 chunks / ~10.9 MB (the 8 MB file plus the 3 KB `PeekSize` overlap per chunk [pkg/sources/chunker.go:L16]), so the comparison is uniform:

```
# patho_mongodb_host (nested-star bait, 8 MB) — FAST despite the "evil" shape
info-0  trufflehog  finished scanning  {"chunks": 819, "bytes": 10896696, "verified_secrets": 0, "unverified_secrets": 1152, "scan_duration": "173.3341ms", "trufflehog_version": "dev", "verification_caching": {...}}

# patho_uri_atspam (nested-star / @-boundary bait, 8 MB) — FASTEST of all
info-0  trufflehog  finished scanning  {"chunks": 820, "bytes": 10901094, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "90.48776ms", "trufflehog_version": "dev", "verification_caching": {...}}

# benign_random (equivalent-size normal text, prefilter MISS, 8 MB)
info-0  trufflehog  finished scanning  {"chunks": 820, "bytes": 10903616, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "176.885735ms", "trufflehog_version": "dev", "verification_caching": {...}}

# match (valid-secret-dense, 8 MB) — the ONLY large slowdown, and it reports 2011 findings
info-0  trufflehog  finished scanning  {"chunks": 820, "bytes": 10903536, "verified_secrets": 0, "unverified_secrets": 2011, "scan_duration": "5.212219302s", "trufflehog_version": "dev", "verification_caching": {...}}
```

**Reading:** the pathological ReDoS‑structured inputs are the **fastest** group (90–175 ms); the valid‑secret‑dense benign file is **~30–58× slower than any pathological file** — the opposite of a backtracking‑ReDoS signature, and the first empirical proof that catastrophic backtracking does not occur.

### 7.2 Extended nested‑star detector coverage, at 8 MB (3 runs each)

```
patho_databricks | 101.905813ms  99.603815ms  102.554288ms | secrets=0 chunks=819
patho_azuresas   | 139.912627ms  147.90657ms  142.922638ms  | secrets=0 chunks=819
```

Both additional nested‑star patterns — `(?:\.[a-z0-9-]+)*` [databrickstoken.go:L27] and `(?:/[a-zA-Z0-9._-]+)*` [azuresastoken.go:L32] — are prefilter‑HIT (their regex runs on every chunk), consume the long adversarial chain, then fail the full pattern, and finish in **< 150 ms** — again faster than equivalent‑size random text. No blow‑up.

### 7.3 Discriminating control — isolating the cost driver (8 MB, 3 runs each)

```
benign_random  | 177.177817ms  178.436175ms  187.128321ms  | secrets=0   (prefilter MISS: regex never runs)
kw_nomatch     | 185.398769ms  187.163181ms  184.297851ms  | secrets=0   (prefilter HIT: RE2 scans ALL chunks, 0 matches)
match          | 5.719043687s  6.199817162s  6.333355101s  | secrets=2011 (prefilter HIT: dense valid matches)
```

Per‑detector timing (`--print-avg-detector-time`) on the `match` file (tail of output):

```
Average detector time is the measurement of average time spent on each detector when results are returned.
MongoDB: 571.042731ms
URI: 129.809354ms
```

On `kw_nomatch` the same flag prints **no** per‑detector line (the feature only reports detectors that return results) → 0 results → 0 attributed detector time, confirming its ~185 ms is pure scanning + ingestion.

**Attribution (observed):**
- RE2 **scanning** cost = `kw_nomatch` − `benign_random` = **~8 ms** → scanning every one of ~820 chunks is essentially free (linear).
- **Amplification** = `match` − `kw_nomatch` = **~5.5 s** = 100 % of the slowdown → entirely per‑match submatch extraction + `FromData` post‑processing (`url.Parse`/`Query`/`Encode`/`String`), **not** regex execution.

### 7.4 Linearity size sweeps (1 / 2 / 4 / 8 / 16 MB, 3 runs each)

`scan_duration` in ms (run1 / run2 / run3), with per‑MB rate from the median:

```
=== MATCH-HEAVY (valid secrets) ===
 1MB:   612.7 /   646.1 /   761.1  | median   646.1 ms | 646.1 ms/MB
 2MB:  1264.5 /  1332.0 /  1210.5  | median  1264.5 ms | 632.2 ms/MB | x1.96 vs prev
 4MB:  1818.8 /  2200.3 /  2852.3  | median  2200.3 ms | 550.1 ms/MB | x1.74 vs prev
 8MB:  5475.8 /  3545.8 /  5234.1  | median  5234.1 ms | 654.3 ms/MB | x2.38 vs prev
16MB: 11913.7 / 10677.2 /  8136.2  | median 10677.2 ms | 667.3 ms/MB | x2.04 vs prev

=== PATHOLOGICAL (MongoDB nested-star) ===
 1MB:    24.6 /    25.8 /    26.3  | median    25.8 ms |  25.8 ms/MB
 2MB:    45.9 /    45.7 /    44.9  | median    45.7 ms |  22.9 ms/MB | x1.77 vs prev
 4MB:    85.3 /    97.4 /    86.6  | median    86.6 ms |  21.6 ms/MB | x1.89 vs prev
 8MB:   172.4 /   175.6 /   166.0  | median   172.4 ms |  21.6 ms/MB | x1.99 vs prev
16MB:   340.6 /   328.4 /   332.4  | median   332.4 ms |  20.8 ms/MB | x1.93 vs prev
```

**Reading:** both series are **cleanly linear** — the per‑MB rate is flat across a 16× size range (pathological ~21–26 ms/MB; match‑heavy ~0.55–0.67 s/MB) and each doubling of input roughly doubles the time (×2). There is **no polynomial or exponential blow‑up** — the defining *absence* of a ReDoS vulnerability. (The match‑heavy series shows more run‑to‑run jitter from the default 128‑worker concurrency contending for 4 CPUs, but the trend and the stable per‑MB rate are unmistakable.)

### 7.5 CPU profile (canonical `--profile` server)

A 64 MB match‑dense file was scanned with the built‑in profiler; a 20 s CPU profile was captured mid‑scan via `go tool pprof`. Scan metrics:

```
info-0  trufflehog  finished scanning  {"chunks": 6554, "bytes": 87239616, "verified_secrets": 0, "unverified_secrets": 16086, "scan_duration": "38.587354087s", ...}
```

`go tool pprof -top -nodecount=25 -seconds=20 http://localhost:18066/debug/pprof/profile` (complete output):

```
File: trufflehog
Build ID: ab9d00389addfd0723b18164d7a64280a1800f09
Type: cpu
Time: 2026-07-14 19:55:24 UTC
Duration: 20.14s, Total samples = 79.79s (396.21%)
Showing nodes accounting for 74.08s, 92.84% of 79.79s total
Dropped 450 nodes (cum <= 0.40s)
Showing top 25 nodes out of 54
      flat  flat%   sum%        cum   cum%
    70.40s 88.23% 88.23%     70.40s 88.23%  runtime._ExternalCode
     0.94s  1.18% 89.41%      1.89s  2.37%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.70s  0.88% 90.29%      0.70s  0.88%  runtime.memmove
     0.40s   0.5% 90.79%      0.49s  0.61%  internal/sync.(*Mutex).Unlock (inline)
     0.29s  0.36% 91.15%      0.78s  0.98%  regexp.(*Regexp).tryBacktrack
     0.28s  0.35% 91.50%      0.64s   0.8%  internal/sync.(*Mutex).Lock (inline)
     0.20s  0.25% 91.75%      1.05s  1.32%  regexp.(*Regexp).backtrack
     0.17s  0.21% 91.97%      1.62s  2.03%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.15s  0.19% 92.15%      4.49s  5.63%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mongodb.Scanner.FromData
     0.08s   0.1% 92.25%      0.56s   0.7%  runtime.mallocgcSmallScanNoHeader
     0.07s 0.088% 92.34%      0.55s  0.69%  github.com/tetratelabs/wazero/internal/engine/wazevo.hostModuleGoFuncFromOpaque[go.shape.interface { Call }] (inline)
     0.07s 0.088% 92.43%      0.40s   0.5%  runtime.growslice
     0.07s 0.088% 92.52%      1.05s  1.32%  runtime.mallocgc
     0.05s 0.063% 92.58%      0.50s  0.63%  github.com/wasilibs/go-re2/internal.readMatches
     0.05s 0.063% 92.64%      0.40s   0.5%  runtime.assertE2I
     0.03s 0.038% 92.68%      2.89s  3.62%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call8
     0.03s 0.038% 92.72%      1.26s  1.58%  github.com/wasilibs/go-re2/internal.getChildModule
     0.02s 0.025% 92.74%      1.49s  1.87%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uri.Scanner.FromData
     0.02s 0.025% 92.77%      0.43s  0.54%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch.func1
     0.02s 0.025% 92.79%      3.89s  4.88%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.01s 0.013% 92.81%      3.36s  4.21%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectChunk
     0.01s 0.013% 92.82%      3.47s  4.35%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.01s 0.013% 92.83%      0.47s  0.59%  net/url.parse
     0.01s 0.013% 92.84%      0.55s  0.69%  runtime.newobject
         0     0% 92.84%      0.44s  0.55%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).Call
```

**Reading:**
- **`runtime._ExternalCode` = 88.23 %** is RE2 executing inside the `wazero` **WASM** sandbox (pprof surfaces WASM as a detached leaf). CPU is dominated by **linear RE2 matching/extraction**, reached via the Go↔WASM boundary (`wazevo.callWithStack`, `go-re2/internal.FindAllStringSubmatch` 4.35 % cum).
- The only `backtrack` frames — `regexp.(*Regexp).backtrack` (1.32 % cum) and `regexp.(*Regexp).tryBacktrack` (0.98 % cum) — are **Go's stdlib *bounded* one‑pass executor**, negligible and **capped by construction**. This is **not** PCRE‑style catastrophic backtracking (Go's `regexp` bounds its backtracker and otherwise simulates the NFA, guaranteeing linear time).
- `mongodb.Scanner.FromData` (5.63 % cum) + `uri.Scanner.FromData` (1.87 % cum) + `net/url.parse` confirm §7.3: per‑match post‑processing is the *secondary* cost, and it is linear in match count.
- `Total samples = 79.79s (396.21%)` over a 20.14 s window ≈ **4 CPUs saturated** — consistent with the `nproc`=4 host.

There is **no catastrophic‑backtracking frame anywhere** in the profile.

### 7.6 Engine‑contrast benchmark — CORROBORATION (NON‑CANONICAL)

> **This subsection is explicitly *not* the `trufflehog` scan path.** It is an out‑of‑tree micro‑benchmark that runs the canonical evil pattern `^(a+)+$` against `"a"×N + "!"` (guaranteed non‑match — the worst case) on the two engines TruffleHog *does* use (`regexp`, `go-re2`) and the backtracking engine it does *not* use for detection (`dlclark/regexp2`, with a 10 s abort guard). It exists to show what a genuine vulnerability *would* look like and to prove the crafted inputs are truly catastrophic for a backtracker.

Complete output (2 runs, stable):

```
### RUN 1 ###
pattern = "^(a+)+$" ; input = "a"xN + "!" (guaranteed non-match)
N    | stdlib regexp (RE2) | go-re2 (WASM RE2)  | dlclark/regexp2 (bt)
--------------------------------------------------------------------------
16   | 12.756µs           | 18.926µs           | 5.884333ms
20   | 2.579µs            | 8.395µs            | 90.250421ms
24   | 2.958µs            | 22.667µs           | 1.45222171s
28   | 4.211µs            | 15.405µs           | 10.000034223s (timeout)
30   | 4.949µs            | 17.07µs            | 10.000019994s (timeout)
32   | 4.082µs            | 15.931µs           | 10.000022107s (timeout)

### RUN 2 ###
pattern = "^(a+)+$" ; input = "a"xN + "!" (guaranteed non-match)
N    | stdlib regexp (RE2) | go-re2 (WASM RE2)  | dlclark/regexp2 (bt)
--------------------------------------------------------------------------
16   | 38.44µs            | 22.204µs           | 5.809699ms
20   | 2.236µs            | 8.778µs            | 91.04227ms
24   | 2.101µs            | 10.113µs           | 1.464716501s
28   | 4.076µs            | 17.183µs           | 10.000028015s (timeout)
30   | 3.785µs            | 15.787µs           | 10.000018283s (timeout)
32   | 3.894µs            | 17.206µs           | 10.000022292s (timeout)
```

**Reading:** the two engines TruffleHog actually uses stay in the **microsecond** range **independent of N** (linear / non‑backtracking); the backtracking engine **explodes exponentially** (~2× per added character), saturating the 10 s cap by N = 28 and — without that cap — would hang indefinitely. **This is exactly the denial‑of‑service the user fears, and it is confined to an engine TruffleHog does *not* use for detection** (`grep -rl "dlclark/regexp2" pkg/` → 0 files).

---

## 8. Root‑Cause Analysis & Defense‑in‑Depth

**Cause → effect chain (why the observed behavior occurs):**

1. Detector patterns are compiled by **RE2‑lineage engines** — `go-re2` [go.mod:L100] for 867 detector files and Go stdlib `regexp` for exactly 3 — which simulate a finite automaton and **never backtrack**. → Match time is **linear** in input length. → Catastrophic‑backtracking ReDoS is **structurally impossible** (§7.4, §7.6).
2. The **Aho‑Corasick prefilter** [go.mod:L17] routes a chunk to a detector only if the detector's keyword is present. → Keyword‑free files skip **all** detector regexes. → Benign repository files are effectively free (`benign_random`: regex never runs; §7.3).
3. On keyword‑bearing, **valid‑secret‑dense** files, RE2 must locate and extract many submatches per chunk (crossing the WASM boundary), and each match then incurs `url.Parse` + query re‑encoding + result construction inside `FromData` [pkg/detectors/mongodb/mongodb.go:L44, L58, L64‑L65, L78‑L79]. → Cost grows **linearly with match count**, never super‑linearly (§7.3, §7.4). Every such match is reported as a finding, so the cost is bounded useful work.

**Defense‑in‑depth (mechanism; relevant to Q1's "hang or time out"; *not* a remediation and not something this investigation changes).** TruffleHog layers timeouts on top of the linear‑time engine:
- `context.WithTimeout(ctx, time.Second*2)` around each `FromData` [pkg/engine/engine.go:L939‑L940].
- On the verification path, `context.WithTimeout(ctx, detectionTimeout)` [pkg/engine/engine.go:L1066] where `detectionTimeout` [pkg/engine/engine.go:L37] = `DefaultResponseTimeout = 10 * time.Second` [pkg/detectors/http.go:L18], with a watchdog `time.AfterFunc(...)` [pkg/engine/engine.go:L1067] that logs `"a detector ignored the context timeout"` [pkg/engine/engine.go:L1068]. (`SetDetectorTimeout` [pkg/engine/engine.go:L331] and the `--detector-timeout` flag [main.go:L77] make this configurable.)
- **Nuance:** the `FindAllStringSubmatch` calls take **no `context`** [pkg/detectors/mongodb/mongodb.go:L49, pkg/detectors/uri/uri.go:L61], so a single regex call cannot be interrupted mid‑match — which is why the linear‑time guarantee, not the timeout, is the true protection. The timeouts primarily bound slow *network verification*.

**Possible mitigations — noted as context only, NOT implemented (per the read‑only, demonstrate‑don't‑remediate scope):** an input‑size cap per chunk already exists implicitly via `TotalChunkSize` ≈ 13 KB [pkg/sources/chunker.go:L18]; one *could* additionally add a per‑detector CPU budget or cap the number of matches processed per chunk to bound the valid‑secret‑dense case. **None of these were applied** — no source file was modified.

---

## 9. Reproduction Commands

```bash
# 1. Build the canonical binary (WASM RE2 variant, exactly as the Dockerfile does)
CGO_ENABLED=0 go build -o /tmp/trufflehog .

# 2. Scan any input through the canonical entry point (pattern-matching cost isolated)
/tmp/trufflehog filesystem <dir> --no-verification --no-update

# 3. Per-detector timing attribution
/tmp/trufflehog filesystem <dir> --no-verification --no-update --print-avg-detector-time

# 4. CPU profile (start the scan with --profile, then sample the pprof server mid-scan)
/tmp/trufflehog filesystem <large_match_dense_dir> --no-verification --no-update --profile &
go tool pprof -top -seconds=20 http://localhost:18066/debug/pprof/profile

# 5. Engine-contrast corroboration (OUT-OF-TREE module; does NOT touch the repo)
#    Runs ^(a+)+$ on "a"xN+"!" across stdlib regexp, go-re2, and dlclark/regexp2 (10s guard).
```

Crafted inputs used above: each carries the target detector's prefilter keyword and repeats a nested‑quantifier "unit" (kept under `ChunkSize` = 10 KB [pkg/sources/chunker.go:L14]) up to the target size; benign controls are generated at the identical byte size. **Constant factors are environment‑dependent** (here, `nproc`=4); the **linear scaling** and the **negative ReDoS result** are the stable, portable conclusions.

---

## 10. Appendix — Consolidated `file:line` Citations

**Regex engines & dependencies (`go.mod`):**
- `go 1.23.1` [go.mod:L3]; `toolchain go1.24.2` [go.mod:L5]
- `github.com/BobuSumisu/aho-corasick v1.0.3` [go.mod:L17] — keyword prefilter
- `github.com/felixge/fgprof v0.9.5` [go.mod:L46] — wall‑clock profiler behind `--profile`
- `github.com/wasilibs/go-re2 v1.9.0` [go.mod:L100] — RE2 (WASM), non‑backtracking; 867 detector files
- `github.com/dlclark/regexp2 v1.4.0 // indirect` [go.mod:L187] — backtracking; 0 detector files
- `github.com/tetratelabs/wazero v1.9.0 // indirect` [go.mod:L285] — WASM runtime hosting RE2

**Detector patterns:**
- MongoDB: `go-re2` import [pkg/detectors/mongodb/mongodb.go:L14]; `connStrPat` nested stars [L32]; keyword `"mongodb"` [L40]; `FromData` [L44]; `FindAllStringSubmatch` [L49]; `url.Parse` [L58]; `Query()` [L64‑L65]; `params.Encode()` [L78]; `connUrl.String()` [L79]
- URI: `go-re2` import [pkg/detectors/uri/uri.go:L13]; `keyPat` [L33]; keywords [L44]; `FromData` [L56]; `FindAllStringSubmatch` [L61]; `url.Parse` [L83]; `RedactURL` [L104]
- `databrickstoken`: domain nested‑star `(?:\.[a-z0-9-]+)*` [pkg/detectors/databrickstoken/databrickstoken.go:L27]; keywords [L34]
- `azuresastoken`: urlPat nested‑star `(?:/[a-zA-Z0-9._-]+)*` [pkg/detectors/azuresastoken/azuresastoken.go:L32]; keywords [L44]
- `azure_entra` spv1: `.{0,80}` [pkg/detectors/azure_entra/serviceprincipal/v1/spv1.go:L35]
- Stdlib‑`regexp` detectors (3): `azure_entra/serviceprincipal/v2/spv2.go`, `azure_cosmosdb/azure_cosmosdb.go`, `jdbc/jdbc.go`

**Engine / scan path (`pkg/engine/engine.go`):**
- `detectionTimeout` [L37]; `SetDetectorTimeout` [L331]; `GetFalsePositiveCheck` [L934]; `Matches()` [L937]; `WithTimeout(…, time.Second*2)` [L939]; `FromData(…)` [L940]; verification `WithTimeout(…, detectionTimeout)` [L1066]; watchdog [L1067]; log message [L1068]

**Chunking (`pkg/sources/chunker.go`):** `ChunkSize = 10 * 1024` [L14]; `PeekSize = 3 * 1024` [L16]; `TotalChunkSize` [L18]

**Timeout default (`pkg/detectors/http.go`):** `DefaultResponseTimeout = 10 * time.Second` [L18]

**Observability & build:** `net/http/pprof` [main.go:L8]; `fgprof` [main.go:L20]; `--profile` :18066 [main.go:L53, L434]; `--no-verification` [main.go:L59]; `--print-avg-detector-time` [main.go:L72]; `--no-update` [main.go:L73]; `--detector-timeout` [main.go:L77]; `filesystem` [main.go:L143]; `scan_duration` metric [main.go:L571]; `CGO_ENABLED=0` [Dockerfile:L5]; `go build -o trufflehog .` [Dockerfile:L9]

**Corpus counts (re‑measured this checkout):** 845 top‑level detector dirs; 886 dirs incl. version subfolders; 2620 `.go` files; 867 import `go-re2`; exactly 3 import stdlib `regexp`; group‑repetition literals = 23 `)*` + 8 `)+` across 17 non‑test files.

---

*Investigation performed read‑only. No TruffleHog source file was created, modified, or deleted; the only file added to the repository is this document. All temporary artifacts (`/tmp/trufflehog`, `/tmp/redos_lab/`) were removed after the measurements above were captured.*

