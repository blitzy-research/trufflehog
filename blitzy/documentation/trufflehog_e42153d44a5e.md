# TruffleHog Pattern‑Matching ReDoS / Resource‑Exhaustion Assessment

**Question addressed:** Can an attacker who commits a specially crafted file to a repository that TruffleHog scans in a CI pipeline weaponize that content to trigger a Regular‑Expression Denial‑of‑Service (ReDoS) / computational‑complexity condition — hanging the scan, exhausting CPU/memory, or exceeding timeouts — and thereby block security scanning?

**Method:** Empirical, run‑first. Every behavioral claim below is placed next to the verbatim output line that produced it, and every mechanism claim carries a `file:line` citation verified against the source tree on this branch. Timings and profiles are **my own measured values** on this host; the TruffleHog source was treated as strictly read‑only (no file under `pkg/**`, `main.go`, `go.mod`, `go.sum`, `Makefile`, `Dockerfile*`, or CI was modified), and all scratch artifacts (crafted inputs, the microbenchmark, the compiled binary, captured profiles) lived under `/tmp/redos_work` outside the repository and were deleted afterward.

**Build/version fidelity (production configuration):**

- Go toolchain `go1.24.2` (`go.mod:5`; `go 1.23.1` floor at `go.mod:3`).
- Regex engine `github.com/wasilibs/go-re2 v1.9.0` (`go.mod:100`) running on the WebAssembly runtime `github.com/tetratelabs/wazero v1.9.0 // indirect` (`go.mod:285`). No `re2_cgo` build tag exists anywhere (`grep -rn re2_cgo Makefile Dockerfile* .goreleaser.yml` → none) and the `Makefile` builds with `CGO_ENABLED=0` (e.g. `Makefile:18` `CGO_ENABLED=0 go install .`), so `go-re2` runs its default **WASM** engine — the exact production configuration.
- Binary built for this assessment: `CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -o /tmp/redos_work/bin/trufflehog .` → reports `trufflehog dev`.
- Host: 4 CPUs (`nproc` = 4), so `--concurrency` defaults to `runtime.NumCPU()` = 4 here (`main.go:58`). All scans used `--no-verification --no-update`.

---

## 1. Executive summary & verdict

**Verdict: TruffleHog's pattern matching is NOT vulnerable to catastrophic‑backtracking ReDoS.** A subject‑only attacker (one who controls scanned file content but not the detector regexes) **cannot** induce super‑linear matching, cannot hang the scanner, and cannot exhaust memory through pattern matching. The realistic worst case is a **bounded, completing slowdown**: a maximally keyword‑dense file is slower to scan than an equal‑size benign file by a large but finite factor, and the scan still finishes in seconds with bounded memory.

This conclusion is reported as the **true, measured result even though it contradicts the "vulnerability" premise** of the question. The evidence is unambiguous and is presented in full below.

| Requirement | Answer | Headline evidence (my measured values) |
|---|---|---|
| **R1** — Can a crafted file hang / time out and block scans? | **No.** Nothing hangs; the scan completes. | A 26 MiB maximally‑pathological file finished: `"scan_duration": "27.994055339s"` (wall 29.750 s); a 52 MiB one finished: `"scan_duration": "56.828875429s"`. Peak memory `VmHWM = 175060 kB` (~171 MB). |
| **R2** — Is pattern matching vulnerable to computational‑complexity ReDoS? | **No.** The detection engine is RE2 (`go-re2`), a non‑backtracking automaton with a linear‑time bound. | On `^(a+)+$`: `go-re2` matched **10,000,000** chars in `elapsed=53.71359ms` (linear); a backtracking engine (`regexp2`) `TIMEOUT after 5s` at **26** chars. |
| **R3** — Which detector patterns, *if any*, are exploitable? | **None.** Two independent reasons (engine‑level + pattern audit). | All 867 `go-re2` importers + 29 stdlib‑`regexp` importers under `pkg/` are RE2‑based. Catastrophic pattern shapes in `pkg/detectors/**`: **0**. |
| **R4** — How much slower vs. a normal file of equivalent size? | **Bounded**, ~**108.9× internal / ~14.8× wall**, and it completes. | Two byte‑for‑byte equal 27,262,976‑byte files: benign `"scan_duration": "257.141053ms"` vs. pathological `"scan_duration": "27.994055339s"`. |
| **R5** — Timing + CPU‑profiling data. | Provided. CPU is dominated by **bounded linear RE2** matching; no exponential hotspot. | 30 s CPU profile: `41.77s 35.43% runtime._ExternalCode` (go‑re2 as WASM). The only `backtrack` frame is Go's *bounded* stdlib one‑pass backtracker at ~1.80 % cum. |

**Why the premise fails (one sentence):** ReDoS requires attacker influence over **both** a vulnerable (backtracking‑prone) pattern **and** its subject; in TruffleHog the patterns are fixed in the binary and compiled by a **non‑backtracking** RE2 engine, so a subject‑only attacker has no lever to pull.

**Bounded residual risk (honest caveat):** keyword‑dense content does cause a real, roughly **linear** slowdown by maximizing detector fan‑out. It is a throughput/cost concern, not a denial‑of‑service, and it is mitigable operationally (`--detector-timeout`, `--concurrency`; and, for the separate archive vector, `--archive-timeout` / `--archive-max-size` / `--archive-max-depth`).

---

## 2. Mechanism — why the observed behavior occurs

TruffleHog's scan is a bounded pipeline: `chunk → decode → Aho‑Corasick keyword pre‑filter → per‑detector extraction window → detector regex → dedup/verify`. Each stage caps the work an attacker can induce. The stages, by name, with citations:

### 2.1 Regex‑engine binding — RE2 via `go-re2` (the decisive fact)

Detectors compile their patterns with `github.com/wasilibs/go-re2`, imported under the alias `regexp` so it is a drop‑in replacement for the standard library:

- `pkg/detectors/aws/access_keys/accesskey.go:17` → `regexp "github.com/wasilibs/go-re2"` (a hot‑path detector).
- `pkg/detectors/aha/aha.go:9` → `regexp "github.com/wasilibs/go-re2"`.

RE2 is Google's automaton‑based engine; its defining property is that match time is linear in the length of the input and it does **not** backtrack, which is exactly why it is the recommended engine when subjects or patterns are attacker‑influenced. The Go standard‑library `regexp` follows the same RE2 principles and the same linear‑time guarantee. Consequently, **classic exponential catastrophic backtracking is architecturally impossible on the detection path**, regardless of how any individual detector pattern is written.

Importer counts on this branch (reproduced here):

```
$ grep -rlE 'regexp[[:space:]]+"github.com/wasilibs/go-re2"' pkg/ --include='*.go' | wc -l
867
$ grep -rlE '^[[:space:]]*"regexp"$' pkg/ --include='*.go' | wc -l
29
```

So **867** source files under `pkg/` use the `go-re2` RE2 engine and **29** use Go's standard‑library `regexp` — and both are RE2‑semantics, linear‑time engines. There is no third, backtracking engine on the scan path (see §5 for the `regexp2` module, which is TUI‑only).

### 2.2 WASM execution via `wazero` (no cgo) — the one caveat

`go-re2 v1.9.0` (`go.mod:100`) can wrap native RE2 through cgo **only** when built with the `re2_cgo` tag; otherwise it runs RE2 compiled to WebAssembly on `tetratelabs/wazero v1.9.0` (`go.mod:285`). This project sets no such tag (`grep -rn re2_cgo Makefile Dockerfile* .goreleaser.yml` → none) and builds with `CGO_ENABLED=0`, so the **WebAssembly** engine is what ships and what I measured. WASM adds a constant‑factor overhead versus native cgo but **preserves the linear‑time guarantee** — the complexity class is unchanged. All numbers in this report are therefore stated for the WASM configuration TruffleHog actually uses.

### 2.3 Keyword pre‑filter (Aho‑Corasick) — routes chunks only to detectors whose keywords appear

A chunk is only handed to a detector if one of that detector's keywords is present in the chunk:

- `pkg/engine/engine.go:795` → `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)`.
- The trie is built case‑insensitively — `pkg/engine/ahocorasick/ahocorasickcore.go:149` → `kwLower := strings.ToLower(kw)` — and matched case‑insensitively — `pkg/engine/ahocorasick/ahocorasickcore.go:242` → `matches := ac.prefilter.Match(bytes.ToLower(chunkData))`.

This pre‑filter is precisely **why keyword density drives detector fan‑out**: a benign chunk with no keyword matches runs *zero* detector regexes, whereas a chunk packed with many distinct keywords fans out to many detectors. This is the entire basis of the "pathological" file in §6 — and it is a **linear** multiplier, not an exponential one.

### 2.4 Bounded extraction window (±512 bytes) per keyword hit

For each keyword hit the engine extracts a bounded window around it rather than handing the detector the whole chunk:

- `pkg/engine/ahocorasick/ahocorasickcore.go:155` → `const defaultOffsetRadius int64 = 512`.
- `pkg/engine/ahocorasick/ahocorasickcore.go:160` → `spanCalculator: newAdjustableSpanCalculator(defaultOffsetRadius)` (the default), whose `calculateSpan` is at `ahocorasickcore.go:80`.
- The whole‑chunk alternative `EntireChunkSpanCalculator` (`ahocorasickcore.go:57`; its `calculateSpan` at `ahocorasickcore.go:61`) is used **only** when `scanEntireChunk` is set, wired at `pkg/engine/engine.go:525-526` (`if e.scanEntireChunk { ahoCOptions = append(ahoCOptions, ahocorasick.WithSpanCalculator(new(ahocorasick.EntireChunkSpanCalculator))) }`) — and it defaults to **false**.
- Overlapping windows are merged: `pkg/engine/ahocorasick/ahocorasickcore.go:196` → `func (d *DetectorMatch) mergeMatches()`.

So each detector regex typically runs against ~1 KB of text (±512 B), not the full chunk.

### 2.5 Chunking bound (~13 KB max per regex)

Source data is split into fixed chunks, so no single regex ever sees more than ~13 KB regardless of file size:

- `pkg/sources/chunker.go:14` → `ChunkSize = 10 * 1024`.
- `pkg/sources/chunker.go:16` → `PeekSize = 3 * 1024`.
- `pkg/sources/chunker.go:18` → `TotalChunkSize = ChunkSize + PeekSize` (= 13312 bytes).

Even the whole‑chunk mode (§2.4) caps a single regex at ~13 KB. Combined with RE2's linear time, per‑regex cost is bounded by a small constant.

### 2.6 Per‑detector data limiting (explicit in‑code optimization)

The engine deliberately limits how much data each detector regex processes — `pkg/engine/engine.go:1056-1060`:

```
// To reduce the overhead of regex calls in the detector,
// we limit the amount of data passed to each detector.
// The matches field of the DetectorMatch struct contains the
// relevant portions of the chunk data that were matched.
// This avoids the need for additional regex processing on the entire chunk data.
```

`pkg/engine/engine.go:1061` → `matches := data.detector.Matches()` — only the extracted windows are looped over and passed to the detector.

### 2.7 Per‑detector timeout (10 s) and the timeout nuance

- `pkg/engine/engine.go:37` → `var detectionTimeout = detectors.DefaultResponseTimeout`.
- `pkg/detectors/http.go:18` → `const DefaultResponseTimeout = 10 * time.Second`.
- Overridable at `pkg/engine/engine.go:331` → `func SetDetectorTimeout(timeout time.Duration) { detectionTimeout = timeout }` (exposed as `--detector-timeout`, `main.go:77`).
- Each detector call is wrapped at `pkg/engine/engine.go:1066` → `ctx, cancel := context.WithTimeout(ctx, detectionTimeout)`, plus a safety‑log timer at `pkg/engine/engine.go:1067-1069`:

```
t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
    ctx.Logger().Error(nil, "a detector ignored the context timeout")
})
```

**Nuance (stated precisely):** the wrapped call `e.verificationCache.FromData(ctx, …)` (`pkg/engine/engine.go:1070-1075`) ultimately runs the detector's `FromData`, which calls `FindAllStringSubmatch` **synchronously without polling the context**. A long‑running match is therefore **not preempted mid‑flight**; the `AfterFunc` only *logs* "a detector ignored the context timeout". The `context.WithTimeout` deadline is a budget for verification/network I/O, **not** a preemption of regex CPU. This design is safe **only because** RE2 guarantees the match itself completes in linear time — which is exactly what the measurements in §3–§7 confirm. (If a backtracking engine were on this path, this non‑preemptive design would be dangerous; it is not.)

### 2.8 Sample detectors (named)

- **`pkg/detectors/aha/aha.go`** — `keyPat` at `aha.go:27` = `regexp.MustCompile(detectors.PrefixRegex([]string{"aha"}) + `\b([0-9a-f]{64})\b`)`; `URLPat` at `aha.go:28`; `Keywords()` returns `[]string{"aha.io"}` at `aha.go:33-34`; applied via `keyPat.FindAllStringSubmatch(dataStr, -1)` at `aha.go:47`. This is the `go-re2` engine.
- **`pkg/detectors/aws/access_keys/accesskey.go`** — the AWS access‑key detector, a hot‑path detector, imports `go-re2` at `accesskey.go:17`.
- **`pkg/detectors/jdbc/jdbc.go`** — imports Go's **standard‑library** `"regexp"` at `jdbc.go:8`; its key pattern at `jdbc.go:53` is exactly:

```
keyPat = regexp.MustCompile(`(?i)jdbc:[\w]{3,10}:[^\s"']{0,512}`)
```

Note the leading `(?i)` and the bounded quantifiers `{3,10}` and `{0,512}`. This detector is one of the 29 stdlib‑`regexp` importers — still RE2‑based, still linear‑time.

### 2.9 Shared prefix helper is bounded — `PrefixRegex`

Most detectors prepend a keyword‑proximity prefix built by `PrefixRegex` (`pkg/detectors/detectors.go:230-234`):

```
func PrefixRegex(keywords []string) string {
    pre := `(?i:`
    middle := strings.Join(keywords, "|")
    post := `)(?:.|[\n\r]){0,40}?`
    return pre + middle + post
}
```

The prefix is a **lazy, capped `{0,40}?`** quantifier (documented at `pkg/detectors/detectors.go:227-228` as "within 40 characters"). It is bounded to 40 characters and cannot cause runaway matching — and, on RE2, could not backtrack even if it were unbounded.

---


## 3. R1 — Feasibility of a scan‑blocking hang / timeout

**Answer: No. A crafted committed file cannot hang TruffleHog or make it time out; the scan completes.**

The strongest test is the *maximally* pathological file: 26 MiB packed with all 914 distinct default‑detector keywords (see §6 for construction), which maximizes detector fan‑out. Scanned through the `filesystem` subcommand (`main.go:143-144`), it completed.

> **Reading the evidence blocks.** In every `finished scanning` line quoted in this document the leading structured‑log columns — `<RFC3339 timestamp>	info-0	trufflehog	` — are trimmed for width; the JSON metrics payload that follows is reproduced **complete and verbatim** (no fields elided). All magnitude scans add `--results=verified`, which suppresses per‑result *printing* so the engine‑reported `scan_duration` reflects detection CPU rather than output I/O; a control run in §6 confirms this flag does not change `scan_duration`, and every keyword‑triggered detector still runs.

```
$ /tmp/redos_work/bin/trufflehog filesystem pathological.txt --no-verification --no-update --results=verified
finished scanning	{"chunks": 2663, "bytes": 35440640, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "27.994055339s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# wall-clock 29.750s
```

A larger 52 MiB version also completed cleanly:

```
finished scanning	{"chunks": 5325, "bytes": 70881280, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "56.828875429s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Memory stayed bounded throughout the 26 MiB scan — peak resident high‑water mark polled from `/proc/<pid>/status`:

```
$ awk '/VmHWM/{print $2}' /proc/<pid>/status   # sampled during the pathological scan
peak VmHWM = 175060 kB  (~171.0 MB)
```

**Why it finishes (the finish reason).** Total work is a **bounded sum**:

```
work ≈ (chunks) × (detectors triggered per chunk) × (linear-RE2 cost on a ±512 B window)
     ≈ 2663 chunks × up to ~831 detectors × sub-millisecond each
```

Every factor is bounded: the chunk count is linear in file size (§2.5), the detector count is capped at the 831 enabled detectors (§2.3, §5), and each regex call is linear‑time RE2 on ~1 KB (§2.1, §2.4). There is no exponential term anywhere, so the product grows **linearly**, not explosively — which is exactly the ~28 s (26 MiB) → ~57 s (52 MiB) near‑doubling observed (27.994 s → 56.829 s = **2.03× time for a 2× size increase**).

**Reconciliation with the 10 s per‑detector timeout (§2.7).** The timeout is *never the thing that saves you*. No single detector call on a ~1 KB window comes anywhere near 10 s — each is a tiny, bounded linear‑time RE2 match (the profile in §7 shows that RE2 matching dominates aggregate CPU while being spread across the millions of per‑window detector invocations, with no single frame indicating a long‑running match). It is **linear‑time matching**, not the deadline, that guarantees completion. This matters because the deadline is non‑preemptive for regex CPU (§2.7): if the engine *could* run away, the timeout would only log, not stop it — but on RE2 it never runs away.

**Conclusion for CI adoption:** a malicious committed file cannot "block security scans" via pattern‑matching complexity. The worst it can do is make a scan take longer (quantified in §6), which is a cost/throughput consideration addressed by the operational mitigations in §8.

---

## 4. R2 — Complexity‑class proof (engine microbenchmark)

**Answer: No, TruffleHog's pattern matching is not vulnerable to computational‑complexity ReDoS**, because the detection engine belongs to the linear‑time (non‑backtracking) complexity class. I proved this by benchmarking the **exact shipped engine versions** against the canonical ReDoS pattern `^(a+)+$` with input `n×'a' + '!'` (the trailing `!` forces a full scan that never matches — the worst case for a backtracker).

```
$ go run .   # module pins go-re2 v1.9.0 and regexp2 v1.4.0
pattern="^(a+)+$"
go-re2   n=1000      input_bytes=1001      match=false elapsed=25.32µs
go-re2   n=10000     input_bytes=10001     match=false elapsed=52.229µs
go-re2   n=100000    input_bytes=100001    match=false elapsed=544.754µs
go-re2   n=1000000   input_bytes=1000001   match=false elapsed=5.735773ms
go-re2   n=10000000  input_bytes=10000001  match=false elapsed=53.71359ms
regexp2  n=20        input_bytes=21        match=false elapsed=96.013774ms
regexp2  n=22        input_bytes=23        match=false elapsed=385.565518ms
regexp2  n=24        input_bytes=25        match=false elapsed=1.530281092s
regexp2  n=26        input_bytes=27        TIMEOUT/err=match timeout after 5s on input `aaaaaaaaaaaaaaaaaaaaaaaaaa!` elapsed=5.000018891s
regexp2  n=28        input_bytes=29        TIMEOUT/err=match timeout after 5s on input `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!` elapsed=5.000021084s
regexp2  n=30        input_bytes=31        TIMEOUT/err=match timeout after 5s on input `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` elapsed=5.000058941s
```

**Interpretation — the crux of the whole assessment:**

- **`go-re2 v1.9.0` (the engine TruffleHog's detectors actually use) scales linearly.** Increasing the input 10× (1,000,000 → 10,000,000 chars) increased the time ~9.4× (5.74 ms → 53.7 ms). It processed **ten million** pathological characters in **~53.7 ms**. This is the textbook signature of an O(n) automaton.
- **`regexp2 v1.4.0` (a backtracking engine) explodes exponentially.** Each `+2` characters multiplied the time roughly 4× (96 ms → 386 ms → 1.53 s), and at **26 characters** it could not finish within a **5 s** timeout. This is textbook catastrophic backtracking.

Identical pattern, identical inputs: one engine dispatches 10,000,000 characters in 53.7 ms while the other cannot finish 26. Catastrophic backtracking is **real for backtracking engines but architecturally impossible for the RE2 engine on TruffleHog's detection path.** This matches the well‑established external consensus that Google's RE2 is a non‑backtracking, automaton‑based engine that guarantees linear‑time matching and is therefore immune to catastrophic backtracking — the reason it is the recommended defense when inputs are attacker‑influenced.

**End‑to‑end confirmation through the real binary.** Feeding classic `(a+)+`‑style bait (a 50 KB file of `<keyword> + 900×'a' + '!'` blocks) through the *entire* TruffleHog pipeline is trivial:

```
$ /tmp/redos_work/bin/trufflehog filesystem bait.txt --no-verification --no-update --results=verified
finished scanning	{"chunks": 6, "bytes": 64490, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "14.94823ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

`"scan_duration": "14.94823ms"` across 6 chunks — the payload that would hang a backtracking engine is dispatched in low double‑digit milliseconds by RE2.

---


## 5. R3 — Which detector patterns, *if any*, are exploitable?

**Answer: None.** No detector pattern can be driven into super‑linear (disproportionate) processing time. This rests on **two independent layers**, either of which is sufficient.

### 5.1 Layer 1 — PRIMARY, engine‑level (decisive)

Every detector regex is compiled by a **non‑backtracking, linear‑time** engine, so **no pattern shape — however it is written — can be driven into catastrophic backtracking on the detection path.** As shown in §2.1:

- **867** files under `pkg/` use `go-re2` (RE2 as WASM).
- **29** files use Go's standard‑library `regexp` (e.g. `jdbc`, `pkg/detectors/jdbc/jdbc.go:8`) — which is *also* RE2‑semantics and linear‑time.

This layer holds **regardless** of the pattern audit below. Even a deliberately "evil" pattern like `^(a+)+$` is linear on this engine (proven in §4). Therefore the honest answer to "which patterns are exploitable" is *none, by construction of the engine*.

### 5.2 Layer 2 — SECONDARY, pattern audit of `pkg/detectors/**` (defense‑in‑depth)

Even setting the engine aside, the detector corpus contains no dangerous pattern shapes. Audited with correct grep flags (see the pitfall in §5.3):

```
# canonical catastrophic shapes  (.*)* / (.*)+ / (.+)+ / (.+)*
$ grep -rnoE '\(\??:?\.[*+]\)[+*]' pkg/detectors --include='*.go' | wc -l
0
# char-class nested with no delimiter (shape e.g. ([a-z]+)+)
$ grep -rnoE '\(\??:?\[[^]]*\][+*]\)[+*]' pkg/detectors --include='*.go' | wc -l
0
# double-greedy adjacency (fixed-string search)
$ grep -rF '.*.*' pkg/detectors --include='*.go' | wc -l   # -> 0
$ grep -rF '.+.+' pkg/detectors --include='*.go' | wc -l   # -> 0
$ grep -rF '.*.+' pkg/detectors --include='*.go' | wc -l   # -> 0
$ grep -rF '.+.*' pkg/detectors --include='*.go' | wc -l   # -> 0
```

Every count is **0**. A broader heuristic for any `(X+)+` / `(X*)*` shape returns exactly **two** hits — and **both are delimiter‑anchored**, which makes them non‑catastrophic *even on a backtracking engine*:

```
$ grep -rnoE '\([^()]*[+*]\)[+*]' pkg/detectors --include='*.go'
pkg/detectors/azuresastoken/azuresastoken.go:32:(?:/[a-zA-Z0-9._-]+)*
pkg/detectors/databrickstoken/databrickstoken.go:27:(?:\.[a-z0-9-]+)*
```

- `pkg/detectors/azuresastoken/azuresastoken.go:32` — the `(?:/[a-zA-Z0-9._-]+)*` group sits inside `urlPat` (`https://…(?:/[a-zA-Z0-9._-]+)*`). Each outer iteration **must begin with a literal `/`**, so there is no ambiguity for a matcher to explode on.
- `pkg/detectors/databrickstoken/databrickstoken.go:27` — `domain = \b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(cloud\.databricks\.com|gcp\.databricks\.com|azuredatabricks\.net))\b`. The `(?:\.[a-z0-9-]+)*` group requires each iteration **to begin with a literal `.`** — the classic *safe* domain‑label pattern.

Neither is the dangerous "`(<chars>+)+` with overlapping alternatives" shape; both are the safe "`(?:<delimiter><chars>)*`" shape.

Two more corpus facts:

- The shared prefix `PrefixRegex` is bounded to 40 characters via a lazy `{0,40}?` quantifier (`pkg/detectors/detectors.go:230-234`, §2.9).
- Detector inventory size: `find pkg/detectors -maxdepth 1 -type d | wc -l` → **846** family directories; the enumerated default set via `defaults.DefaultDetectors()` (`pkg/engine/defaults/defaults.go:1704`) is **831 detectors / 914 distinct keywords** (reproduction in §8).

### 5.3 The only backtracking engine in the graph is TUI‑only

`github.com/dlclark/regexp2 v1.4.0` (`go.mod:187`, **// indirect**) *is* a backtracking engine, but it never touches scanned content. It is pulled in **only transitively** through the terminal UI:

```
$ go mod graph | grep dlclark/regexp2
github.com/trufflesecurity/trufflehog/v3 github.com/dlclark/regexp2@v1.4.0
github.com/alecthomas/chroma/v2@v2.8.0 github.com/dlclark/regexp2@v1.4.0
github.com/charmbracelet/glamour@v0.7.0 github.com/dlclark/regexp2@v1.4.0
$ grep -rl 'dlclark/regexp2' pkg/ --include='*.go'
# (no output — no scan-path source imports it)
```

The first line — `github.com/trufflesecurity/trufflehog/v3 github.com/dlclark/regexp2@v1.4.0` — is the main module's own graph edge: `go mod graph` prints **every** requirement of the root module (including *indirect* ones) as a direct `github.com/trufflesecurity/trufflehog/v3 → …` edge, so this line is exactly the `// indirect` requirement recorded at `go.mod:187`; it reflects a module‑graph *requirement*, not a source‑level import. That no scan‑path source actually imports the package is confirmed directly by the empty `grep -rl 'dlclark/regexp2' pkg/ --include='*.go'` result above. The real (source‑level) chain is `pkg/tui/common → charmbracelet/glamour → alecthomas/chroma/v2 → dlclark/regexp2`; `glamour` is imported only by `pkg/tui/common/style.go`. The backtracking engine is used for Markdown syntax highlighting in the TUI and is **never** applied to repository content.

### 5.4 Grep pitfall disclosure (so the "zero" counts can be trusted)

The "zero" counts above are only trustworthy with the right grep dialect. GNU `grep`'s **default is Basic Regular Expressions (BRE)**, in which `\+` is the *one‑or‑more operator*, not a literal `+`. A naïve search for the shape `.+.+` therefore silently mis‑fires:

```
# WRONG (BRE): \+ is an operator, so this matches runs of dots like Go's variadic '...'
$ grep -r '\.\+\.\+' pkg/detectors --include='*.go' | wc -l
44
# examples of the false positives it returns:
pkg/detectors/aws/access_keys/accesskey.go:32:func New(opts ...func(*scanner)) *scanner {

# CORRECT (fixed-string): matches the literal five-character shape ".+.+"
$ grep -rF '.+.+' pkg/detectors --include='*.go' | wc -l
0
```

The BRE search reports **44** phantom "hits" (Go variadic `...`, slice ranges, etc.); the fixed‑string search reports the true **0**. All shape audits in §5.2 use `-F` (fixed string) or `-E` (ERE), so their zero counts are correct.

---


## 6. R4 — Magnitude vs. a normal file of equivalent size

**Answer: bounded — ~108.9× the engine's internal `scan_duration` and ~14.8× wall‑clock — and the scan still completes.**

I compared two **byte‑for‑byte equal‑size** files (both exactly **27,262,976 bytes** = 26 MiB), differing only in keyword density:

- **Pathological** — the 914 distinct default‑detector keywords space‑joined into an 8,475‑byte "soup" block, repeated to fill exactly 27,262,976 bytes (maximal detector fan‑out).
- **Benign** — keyword‑free lorem‑ipsum filler truncated to the same 27,262,976 bytes. Verified to contain **0** of the 914 keywords as case‑insensitive substrings before scanning.

```
$ /tmp/redos_work/bin/trufflehog filesystem benign.txt --no-verification --no-update --results=verified
finished scanning	{"chunks": 2663, "bytes": 35440640, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "257.141053ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# wall-clock 2.007s

$ /tmp/redos_work/bin/trufflehog filesystem pathological.txt --no-verification --no-update --results=verified
finished scanning	{"chunks": 2663, "bytes": 35440640, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "27.994055339s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
# wall-clock 29.750s
```

Both files decode to **identical** `"chunks": 2663` and `"bytes": 35440640`, so file size and chunking are held constant — **keyword density is the only variable**. The measured slowdown:

| Metric | Benign | Pathological | Slowdown |
|---|---|---|---|
| Engine `scan_duration` | `257.141053ms` | `27.994055339s` | **≈ 108.9×** |
| Wall‑clock | `2.007s` | `29.750s` | **≈ 14.8×** |

(The wall‑clock ratio is smaller than the internal ratio because wall‑clock includes ~1.75 s of fixed binary/detector startup that is identical for both files: benign `2.007 s − 257.141053 ms ≈ 1.75 s`, pathological `29.750 s − 27.994055339 s ≈ 1.76 s`.)

**Control — result printing does not inflate the timing.** To confirm the slowdown is genuine *detection* CPU and not result‑output I/O, I re‑ran the pathological scan three ways: with `--results=verified` (unverified results suppressed) `scan_duration` was `28.23181507s`; with the default filter printing all **4,167** unverified matches to `/dev/null` it was `28.354478205s`; writing those 4,167 matches to a real file it was `27.54004066s`. All three are within run‑to‑run noise (and bracket the headline `27.994055339s` above), so printing the results does **not** materially change `scan_duration` — the reported time is detection work, and every keyword‑triggered detector runs identically regardless of the output filter.

**Why the ratio is this large — and why it is still bounded.** This is deliberately the *worst realistic* case: the pathological file packs **all 914** distinct keywords, so nearly every one of the **831** detectors is routed work on essentially every 13 KB chunk (maximal fan‑out, §2.3), whereas the benign file triggers almost no detectors. The slowdown is a roughly **linear** function of (keyword density × file size), i.e. of total detector‑invocation count — **not** an exponential blow‑up. A less contrived pathological file (fewer distinct keywords) produces a proportionally smaller ratio.

**`"bytes": 35440640` accounting.** The engine's reported decoded‑byte count exceeds the 27,262,976 file bytes by the chunk peek‑overlap factor:

```
35440640 / 27262976 = 1.3000  ==  TotalChunkSize / ChunkSize = 13312 / 10240
35440640 / 2663 chunks = 13308.5 B/chunk  ≈  TotalChunkSize (13312)
```

i.e. each 10 KB `ChunkSize` chunk re‑emits a 3 KB `PeekSize` overlap (§2.5), so decoded bytes ≈ chunks × `TotalChunkSize`. This is bookkeeping, not attacker leverage.

**Bottom line:** an attacker can make a scan meaningfully slower (here ~109× internally) but **cannot** make it fail to complete. It is a throughput/cost impact, not a denial of service.

---

## 7. R5 — Timing and CPU‑profiling evidence

TruffleHog ships a built‑in profiler: the `--profile` flag (`main.go:53`, "Enables profiling and sets a pprof and fgprof server on :18066.") starts an HTTP profiling server, backed by `_ "net/http/pprof"` (`main.go:8`), `runtime.SetBlockProfileRate(1)` (`main.go:427`), and `http.ListenAndServe(":18066", router)` (`main.go:434`). Startup log, captured verbatim:

```
starting pprof and fgprof server on :18066 /debug/pprof and /debug/fgprof
```

I scanned the 52 MiB pathological file with `--profile` and sampled a 30 s CPU profile with `go tool pprof`.

### 7.1 Timing (engine‑reported)

```
$ /tmp/redos_work/bin/trufflehog filesystem pathological_big.txt --no-verification --no-update --results=verified --profile
finished scanning	{"chunks": 5325, "bytes": 70881280, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "56.828875429s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### 7.2 CPU profile — default concurrency (= `runtime.NumCPU()` = 4)

```
$ curl -s "http://localhost:18066/debug/pprof/profile?seconds=30" -o cpu.pprof
$ go tool pprof -top /tmp/redos_work/bin/trufflehog cpu.pprof
File: trufflehog
Build ID: 0702f216b67cdebdf0eb8919fb59a29c34f2fd57
Type: cpu
Time: 2026-07-01 23:18:57 UTC
Duration: 30.31s, Total samples = 117.91s (389.06%)
Showing nodes accounting for 71.49s, 60.63% of 117.91s total
Dropped 1379 nodes (cum <= 0.59s)
Showing top 15 nodes out of 170
      flat  flat%   sum%        cum   cum%
    41.77s 35.43% 35.43%     41.77s 35.43%  runtime._ExternalCode
     4.67s  3.96% 39.39%     11.32s  9.60%  internal/sync.(*Mutex).Unlock
     2.74s  2.32% 41.71%      2.74s  2.32%  runtime.(*mspan).base (inline)
     2.72s  2.31% 44.02%      3.69s  3.13%  runtime.findObject
     2.57s  2.18% 46.20%      4.61s  3.91%  runtime.lock2
     2.40s  2.04% 48.23%     14.21s 12.05%  internal/sync.(*Mutex).Lock
     2.33s  1.98% 50.21%      8.27s  7.01%  runtime.scanobject
     2.06s  1.75% 51.95%     11.81s 10.02%  internal/sync.(*Mutex).lockSlow
     1.73s  1.47% 53.42%      1.73s  1.47%  runtime.futex
     1.67s  1.42% 54.84%      1.67s  1.42%  runtime.memmove
     1.60s  1.36% 56.20%      1.60s  1.36%  runtime.cansemacquire (inline)
     1.52s  1.29% 57.48%      2.07s  1.76%  runtime.fpTracebackPartialExpand
     1.33s  1.13% 58.61%      1.45s  1.23%  container/list.(*List).remove
     1.19s  1.01% 59.62%      1.66s  1.41%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
     1.19s  1.01% 60.63%      1.19s  1.01%  runtime.procyield
```

Ordered by cumulative time (same profile), which surfaces the RE2/WASM call chain:

```
$ go tool pprof -top -cum /tmp/redos_work/bin/trufflehog cpu.pprof
Duration: 30.31s, Total samples = 117.91s (389.06%)
Showing nodes accounting for 53.88s, 45.70% of 117.91s total
Dropped 1379 nodes (cum <= 0.59s)
Showing top 25 nodes out of 170
      flat  flat%   sum%        cum   cum%
     1.08s  0.92%  0.92%     55.44s 47.02%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).verificationOverlapWorker
         0     0%  0.92%     55.42s 47.00%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startVerificationOverlapWorkers.func1
    41.77s 35.43% 36.34%     41.77s 35.43%  runtime._ExternalCode
         0     0% 36.34%     41.77s 35.43%  runtime._System
     0.24s   0.2% 36.54%     32.43s 27.50%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.20s  0.17% 36.71%     30.55s 25.91%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.04s 0.034% 36.75%     18.14s 15.38%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call1
     0.13s  0.11% 36.86%     15.36s 13.03%  github.com/wasilibs/go-re2/internal.getChildModule
     0.01s 0.0085% 36.87%     14.22s 12.06%  sync.(*Mutex).Lock (inline)
     2.40s  2.04% 38.90%     14.21s 12.05%  internal/sync.(*Mutex).Lock (inline)
     0.09s 0.076% 38.98%     14.11s 11.97%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
     0.21s  0.18% 39.16%     14.01s 11.88%  github.com/wasilibs/go-re2/internal.matchFrom
     0.20s  0.17% 39.33%     13.80s 11.70%  github.com/wasilibs/go-re2/internal.(*lazyFunction).Call8
     0.03s 0.025% 39.35%     13.48s 11.43%  runtime.systemstack
     0.19s  0.16% 39.51%     13.30s 11.28%  github.com/wasilibs/go-re2/internal.putChildModule
     0.02s 0.017% 39.53%     12.25s 10.39%  github.com/trufflesecurity/trufflehog/v3/pkg/context.WithTimeout
     2.06s  1.75% 41.28%     11.81s 10.02%  internal/sync.(*Mutex).lockSlow
     4.67s  3.96% 45.24%     11.32s  9.60%  internal/sync.(*Mutex).Unlock (inline)
         0     0% 45.24%     11.32s  9.60%  sync.(*Mutex).Unlock (partial-inline)
         0     0% 45.24%     10.09s  8.56%  github.com/wasilibs/go-re2/internal.(*libre2ABI).reserve (inline)
         0     0% 45.24%     10.09s  8.56%  github.com/wasilibs/go-re2/internal.(*libre2ABI).startOperation (inline)
     0.20s  0.17% 45.41%     10.09s  8.56%  github.com/wasilibs/go-re2/internal.malloc
     0.34s  0.29% 45.70%      8.82s  7.48%  runtime.mallocgc
         0     0% 45.70%      8.77s  7.44%  runtime.gcBgMarkWorker
         0     0% 45.70%      8.77s  7.44%  runtime.gcBgMarkWorker.func2
```

The stdlib‑`regexp` `backtrack`/`doExecute` frames, the `go-re2` allocator `free`, the span‑calculator, and the Aho‑Corasick core sit deeper than the top‑25 cumulative nodes; isolated from the **same** profile with `grep` (complete rows, no elision):

```
$ go tool pprof -top -cum /tmp/redos_work/bin/trufflehog cpu.pprof | grep -E 'FindDetectorMatches|doExecute|\.backtrack|tryBacktrack|internal\.malloc|internal\.free|calculateSpan'
     0.20s  0.17% 45.41%     10.09s  8.56%  github.com/wasilibs/go-re2/internal.malloc
         0     0% 48.55%      8.25s  7.00%  github.com/wasilibs/go-re2/internal.free (inline)
     0.15s  0.13% 49.35%      5.36s  4.55%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*Core).FindDetectorMatches
         0     0% 52.64%      3.71s  3.15%  regexp.(*Regexp).doExecute
     0.22s  0.19% 59.05%      2.12s  1.80%  regexp.(*Regexp).backtrack
     0.82s   0.7% 61.76%      1.85s  1.57%  regexp.(*Regexp).tryBacktrack
     0.24s   0.2% 78.14%      0.83s   0.7%  github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick.(*adjustableSpanCalculator).calculateSpan
```

### 7.3 CPU profile — `--concurrency=1` (cleaner, less pool contention)

```
$ go tool pprof -top /tmp/redos_work/bin/trufflehog cpu.pprof   # 26 MiB pathological scan run with --concurrency=1
File: trufflehog
Build ID: 0702f216b67cdebdf0eb8919fb59a29c34f2fd57
Type: cpu
Time: 2026-07-01 23:20:38 UTC
Duration: 30.15s, Total samples = 43.71s (144.95%)
Showing nodes accounting for 30.59s, 69.98% of 43.71s total
Dropped 678 nodes (cum <= 0.22s)
Showing top 15 nodes out of 144
      flat  flat%   sum%        cum   cum%
    18.44s 42.19% 42.19%     18.44s 42.19%  runtime._ExternalCode
     2.78s  6.36% 48.55%      9.08s 20.77%  runtime.scanobject
     1.93s  4.42% 52.96%      1.93s  4.42%  runtime.(*mspan).base (inline)
     1.42s  3.25% 56.21%      1.44s  3.29%  runtime.(*gcBits).bitp (inline)
     0.97s  2.22% 58.43%      1.54s  3.52%  runtime.findObject
     0.80s  1.83% 60.26%      0.80s  1.83%  runtime.memmove
     0.64s  1.46% 61.73%      9.88s 22.60%  runtime.gcDrain
     0.60s  1.37% 63.10%      0.75s  1.72%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
     0.49s  1.12% 64.22%      0.49s  1.12%  runtime.nextFreeFast (inline)
     0.47s  1.08% 65.29%      0.47s  1.08%  internal/sync.(*Mutex).Unlock (inline)
     0.46s  1.05% 66.35%      0.48s  1.10%  internal/sync.(*Mutex).Lock (inline)
     0.44s  1.01% 67.35%      0.44s  1.01%  runtime.memclrNoHeapPointers
     0.40s  0.92% 68.27%     11.30s 25.85%  github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).verificationOverlapWorker
     0.38s  0.87% 69.14%      0.38s  0.87%  aeshashbody
     0.37s  0.85% 69.98%      0.37s  0.85%  runtime.spanOf (inline)
```

### 7.4 Interpretation

- **The dominant CPU consumer is bounded linear RE2 matching executing as WebAssembly.** `runtime._ExternalCode` — the `go-re2` RE2 automaton running inside `wazero` — is **35.43 %** flat at the default concurrency (4) and **42.19 %** flat at `--concurrency=1`. Its call chain is visible in the cumulative view: `FindAllStringSubmatch` (27.50 %) → `callWithStack` (the WASM bridge, 25.91 %) → `malloc`/`free` and the `getChildModule`/`putChildModule` wazero **module‑instance pool** (13.03 % / 11.28 %). I report my **own** percentages here; they are not a fixed "90 %". The difference between concurrency levels is honest and expected: with more workers, the wazero module‑instance pool becomes mutex‑contended (the `internal/sync.(*Mutex).Lock`/`lockSlow` frames, ~12 % cum at concurrency 4) and GC surfaces as separate frames, so the engine's *flat* share is lower at concurrency 4 (35.43 %) and rises at concurrency 1 (42.19 %) as contention drops. On this 4‑CPU host the gap is modest; it would widen on a many‑core host.
- **The Aho‑Corasick pre‑filter and decoders are minor contributors** — `ahocorasick.(*Core).FindDetectorMatches` is 4.55 % cum (concurrency 4) / 5.01 % cum (concurrency 1), and the `(*adjustableSpanCalculator).calculateSpan` window logic is ~0.7 %.
- **There is no exponential hotspot.** The single `backtrack` frame — `regexp.(*Regexp).backtrack` at ~**1.80 %** cum (with `tryBacktrack` ~1.57 % and `doExecute` ~3.15 % at concurrency 4) — is **Go's standard‑library one‑pass *bounded* backtracker**, used by the 29 stdlib‑`regexp` detectors (e.g. `jdbc`). It maintains a **fixed visited‑state budget** and falls back to the NFA when that budget would be exceeded, so it remains linear‑time. Its small, stable cumulative share — under 2 % — reflects many tiny bounded calls spread across the scan, **not** catastrophic backtracking. The frame name is easy to misread; it is explicitly *not* a ReDoS signal.
- **Memory is bounded** — peak `VmHWM = 175060 kB` (~171 MB) during the 26 MiB scan (§3), constrained by 10 KB chunking (§2.5) and fixed worker pools (the equal‑size *benign* scan peaked at essentially the same `173984 kB`, confirming peak memory is engine/pool‑bound, not driven by keyword density). There is no memory‑exhaustion vector from pattern matching.

**Net:** the overwhelming majority of scan CPU is *bounded, linear* RE2 matching plus its allocator / GC / module‑pool overhead; the Aho‑Corasick pre‑filter is minor and the profile contains **no** super‑linear frame.

---


## 8. Reproduction, threat‑model boundary, and operational mitigations

### 8.1 Reproduction steps (condensed)

All work was done outside the repository, under `/tmp/redos_work`; the source tree was never modified. Build uses the production `CGO_ENABLED=0` (WASM) configuration; scans use `--no-verification` (isolate pattern‑matching CPU from network) and `--no-update`.

```
# 0. Toolchain: go1.24.2 (matches go.mod:5).
# 1. Build the real binary (readonly so go.mod/go.sum are never rewritten):
CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -o /tmp/redos_work/bin/trufflehog .

# 2. R2 engine microbench (ephemeral /tmp module pinning the shipped versions):
#    go get github.com/wasilibs/go-re2@v1.9.0 github.com/dlclark/regexp2@v1.4.0
#    compile ^(a+)+$ with each engine; time MatchString(strings.Repeat("a",n)+"!");
#    go-re2 up to n=10,000,000; regexp2 n=10..30 with re.MatchTimeout=5*time.Second.

# 3. Enumerate the default detector keywords (ephemeral module with
#    replace github.com/trufflesecurity/trufflehog/v3 => <repo>, importing
#    pkg/engine/defaults): defaults.DefaultDetectors() -> 831 detectors / 914 keywords.

# 4. Craft equal-size inputs (Python): pathological.txt = 914-keyword soup repeated to
#    27,262,976 bytes; benign.txt = keyword-free lorem truncated to the SAME size
#    (verify 0 keyword substrings); bait.txt = 50 KB of <kw>+900*'a'+'!'; and a 52 MiB
#    pathological_big.txt for the profile window.

# 5. R1/R4 magnitude: time-wrap trufflehog filesystem <file> --no-verification --no-update;
#    grep the "finished scanning" line and read its "scan_duration" field; ratio via python3.

# 6. R5 profile: run the binary on pathological_big.txt --no-verification --no-update --profile & ;
#    sleep 3 ; curl -s "http://localhost:18066/debug/pprof/profile?seconds=30" -o cpu.pprof ;
#    go tool pprof -top [-cum] /tmp/redos_work/bin/trufflehog cpu.pprof
#    (repeat with --concurrency=1 for a cleaner engine-dominated view).

# 7. Memory: poll `awk '/VmHWM/{print $2}' /proc/<pid>/status` during the 26 MiB scan.

# 8. Cleanup + integrity: rm -rf /tmp/redos_work ; git status --porcelain must be EMPTY.
```

### 8.2 Threat‑model boundary — why a subject‑only attacker cannot induce ReDoS

ReDoS requires the attacker to influence **both**:

1. a **vulnerable pattern** (one whose structure a backtracking engine can be driven to explore super‑linearly), **and**
2. the **subject** (the text the pattern is matched against).

In this threat model the attacker controls only the **subject** — the content of a committed file. The **patterns** are the detector regexes, which are **fixed in the compiled binary** and compiled by a **non‑backtracking RE2 engine** (§2.1, §4). Missing lever (1), and with an engine whose worst‑case is linear regardless of pattern shape, the subject‑only attacker cannot induce super‑linear matching. This is the structural reason the vulnerability premise does not hold.

### 8.3 Operational mitigations (each with `file:line`)

Although there is no ReDoS vulnerability, the bounded keyword‑density slowdown of §6 is a real cost factor. It is contained operationally:

- **`--detector-timeout`** (`main.go:77`; wired via `SetDetectorTimeout`, `pkg/engine/engine.go:331`) — caps per‑detector time (default 10 s, `pkg/detectors/http.go:18`). Note the §2.7 nuance: this bounds verification/I/O and the *budget* per call, not regex CPU preemption — but on RE2 no single call is long anyway.
- **`--concurrency`** (`main.go:58`, default `runtime.NumCPU()`) — bounds parallel CPU consumption on the CI host.
- For the **separate** archive vector: **`--archive-timeout`** (`main.go:80`), plus `--archive-max-size` (`main.go:78`) and `--archive-max-depth` (`main.go:79`).

Practical CI guidance: run scans with a CPU/wall budget (e.g. a job timeout) and a sensible `--concurrency` for the runner; the pattern‑matching path will always complete within a linear multiple of file size × keyword density.

### 8.4 Adjacent, separately‑bounded vectors (noted, not the focus)

The question is specifically about **pattern‑matching** complexity. Two other resource‑exhaustion classes exist but are out of scope and are bounded by different controls:

- **Archive / decompression bombs** — handled by the archive handler's depth/size/timeout limits (`--archive-timeout` `main.go:80`, `--archive-max-size` `main.go:78`, `--archive-max-depth` `main.go:79`), not by the regex engine.
- **Pathological git‑history traversal** — a source‑enumeration cost, unrelated to regex complexity.

Neither is a pattern‑matching ReDoS, and neither changes the verdict for the question asked.

---

## 9. Coverage check (every requirement and named item addressed)

- **R1** (hang/timeout): §3 — completes; 27.99 s (26 MiB) / 56.83 s (52 MiB); peak ~171 MB.
- **R2** (complexity class): §4 — `go-re2` linear (10M chars/53.7 ms) vs. `regexp2` exponential (timeout at 26 chars); 50 KB bait 14.94823 ms.
- **R3** (exploitable patterns): §5 — none; engine‑level + audit (0 catastrophic shapes; 2 safe delimiter‑anchored patterns named; BRE/ERE pitfall disclosed; `regexp2` TUI‑only).
- **R4** (magnitude vs. equal size): §6 — ~108.9× internal / ~14.8× wall, bounded, completes.
- **R5** (timing + CPU profile): §7 — `runtime._ExternalCode` 35.43 %/42.19 %; `backtrack` = Go bounded one‑pass backtracker; memory bounded.
- **Named mechanisms/items:** `go-re2` (§2.1), `wazero` (§2.2), `regexp2` (§5.3), RE2 (§2.1/§4), Aho‑Corasick pre‑filter (§2.3), `defaultOffsetRadius=512` (§2.4), `EntireChunkSpanCalculator` (§2.4), `mergeMatches` (§2.4), `ChunkSize`/`PeekSize`/`TotalChunkSize` (§2.5), `PrefixRegex` `{0,40}?` (§2.9), `DefaultResponseTimeout=10s` (§2.7), `detectionTimeout` (§2.7), `FindDetectorMatches` (§2.3), `context.WithTimeout`+`AfterFunc` (§2.7), `--profile`/`:18066` (§7), `net/http/pprof` (§7), `SetBlockProfileRate` (§7), `--detector-timeout` (§8.3), `--concurrency` (§8.3), `--archive-timeout` (§8.3/§8.4), `--archive-max-size`/`--archive-max-depth` (§8.3/§8.4), `filesystem` subcommand (`main.go:143-144`, §3/§8.1), sample detectors `aha` / `aws access_keys` / `jdbc` (§2.8), `runtime._ExternalCode` (§7), `regexp.(*Regexp).backtrack` (§7), `FindAllStringSubmatch` (§2.8/§7), `VmHWM` (§3/§7).

**Final verdict:** TruffleHog's regex‑based pattern matching is **not** vulnerable to computational‑complexity / catastrophic‑backtracking ReDoS. A committed file cannot hang or time out the scanner via pattern matching; the realistic worst case is a **bounded, completing** slowdown driven linearly by keyword density, mitigable with standard operational controls.

