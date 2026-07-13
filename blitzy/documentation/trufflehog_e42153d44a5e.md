# TruffleHog Secret-Detection Pipeline — Runtime-Observed Q&A

This document answers six questions about TruffleHog's secret-detection pipeline. Every
answer is derived from **directly observed runtime behavior** of a canonical build of the CLI
(exercised through its real entry point), cross-checked against the source at branch
`trufflehog_e42153d44a5e` (HEAD commit `e42153d4`). The investigation created no product code
and modified **no** existing repository file; the only artifact added to the repository is this
Markdown document. All temporary artifacts used during the investigation (the compiled binary,
scan fixtures, and one external observation module) were removed afterward — see the closing
section for the clean `git status` proof.

---

## Methodology

**Canonical build.** The CLI was built from the module root with the repository's declared Go
toolchain (`go 1.23.1` / `toolchain go1.24.2` in `go.mod`, lines 3 and 5) using Go **1.24.2**:

```bash
GOFLAGS=-mod=mod go build -o /tmp/thog .
```

**Version banner (canonical, non-release).** A default build stamps no release version, so the
banner reports `dev`. This is the canonical value reported throughout; no `ldflags` were used to
inject a release string:

```bash
$ /tmp/thog --version
trufflehog dev
```

**Streams.** TruffleHog writes **detection results to `stdout`** (via the printer/dispatcher) and
**structured logs to `stderr`** (zap + logr, tab-delimited
`TIMESTAMP<TAB>level<TAB>trufflehog<TAB>msg<TAB>{fields}`). Each question captures the correct
stream, redirecting with `1>stdout.log 2>stderr.log` where both are needed.

**Verbosity mapping** (`main.go`): `--trace` → `log.SetLevel(5)` (`main.go:L305-306`); `--debug`
→ `log.SetLevel(2)` (`main.go:L307-308`); otherwise `--log-level N`. The worker-count lines
(Q4) and the pipeline sequence (Q2) are emitted at `ctx.Logger().V(2)`, so they require `--debug`
or `--log-level 2`+. The short `-v/-vv/-vvv` flags do **not** map to these V-levels.

**Fixtures.** All scan fixtures were created in temporary directories **outside** the repository
tree (`/tmp/thog_obs*`); the in-repo `pkg/engine/testdata` was never touched.

**Labeling convention.** Every non-trivial claim is labeled:
- **(observed)** — established from captured runtime output.
- **(inferred / code-derived)** — established by reading source; used only where a runtime signal
  is not directly emitted (and the reason is stated).

**Authoritative in-repo design docs** (terminology mirrored below):
- `docs/process_flow.md` — Data Flow: **Source Decomposition → Chunk-to-Detector Matching
  (Aho-Corasick keyword matching) → Secret Detection (de-dupe, collect matches, verify) →
  Result Notification (Dispatcher)**.
- `docs/concurrency.md` — worker-pool sequence: **ScannerWorkers → VerificationOverlapWorkers →
  DetectorWorkers → NotifierWorkers**, with channel fan-out/fan-in via `e.ChunksChan()`,
  `e.detectableChunksChan`, `e.verificationOverlapChunksChan`, and `e.ResultsChan()` / `e.results`.

**Relevant dependency versions** (from `go.mod`): `github.com/BobuSumisu/aho-corasick v1.0.3`
(L17), `github.com/alecthomas/kingpin/v2 v2.4.0` (L20), `github.com/hashicorp/golang-lru/v2
v2.0.7` (L64), `go.uber.org/zap v1.27.0` (L106), `golang.org/x/crypto v0.37.0` (L107).

**Pipeline overview** (the flow these six answers dissect):

```mermaid
graph LR
    A[Source Chunk] --> B[Decoder Chain<br/>UTF8, Base64, UTF16, EscapedUnicode]
    B --> C[Aho-Corasick<br/>keyword match on DECODED data]
    C --> D{More than one<br/>matching detector?}
    D -->|Yes| E[verificationOverlapChunksChan]
    D -->|No| F[detectableChunksChan]
    E --> G[Detector Workers<br/>regex + verification cache]
    F --> G
    G --> H[Notifier Workers<br/>LRU dedupe + dispatch]
    H --> I[Results to stdout]
```

---

## Q1 — Keyword loading into the Aho-Corasick trie

> **Verbatim question:** "When the engine initializes with the default detector set, how many
> unique keywords get loaded into the Aho Corasick trie and do multiple detectors end up sharing
> the same keywords or are they distinct per detector."

**Direct answer (observed, stable across 3 runs):** The canonical default set of **831 detectors**
loads **914 unique keywords** into the trie (out of **955** total `(keyword, detector)` pairs fed
to the trie builder). Keywords are **shared** across detectors — **32** keywords map to more than
one detector, and `"azure"` is shared by **6** detectors (with `airtable`, `cloudflare`, `github`,
`teamwork`, and `twitter` each shared by 3).

**How this was observed (canonical constructors, no source edits).** A throwaway Go module was
created **outside** the repository, using a `go.work` workspace that references the repository as a
workspace module (so it links against the exact source tree without modifying it). The program
calls the canonical `defaults.DefaultDetectors()` and passes the result to the canonical
`ahocorasick.NewAhoCorasickCore(...)`, then measures `len(core.KeywordsToDetectors())` and counts
the map values whose slice length exceeds 1. These are the same constructors `main.go` uses — not
a debug hook. The module was deleted afterward.

The observation program (`/tmp/thog_obs_q1/main.go`):

```go
package main

import (
	"fmt"
	"sort"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

func main() {
	// Canonical default detector set feeding the canonical Aho-Corasick core constructor.
	dets := defaults.DefaultDetectors()
	core := ahocorasick.NewAhoCorasickCore(dets)
	k2d := core.KeywordsToDetectors()

	unique := len(k2d)
	totalPairs := 0
	shared := 0
	type kv struct {
		kw string
		n  int
	}
	var sharedList []kv
	for kw, ds := range k2d {
		totalPairs += len(ds)
		if len(ds) > 1 {
			shared++
			sharedList = append(sharedList, kv{kw, len(ds)})
		}
	}
	sort.Slice(sharedList, func(i, j int) bool {
		if sharedList[i].n != sharedList[j].n {
			return sharedList[i].n > sharedList[j].n
		}
		return sharedList[i].kw < sharedList[j].kw
	})

	fmt.Printf("default_detectors=%d\n", len(dets))
	fmt.Printf("unique_keywords(len keywordsToDetectors)=%d\n", unique)
	fmt.Printf("total_keyword_detector_pairs=%d\n", totalPairs)
	fmt.Printf("keywords_shared_by_multiple_detectors=%d\n", shared)
	fmt.Printf("top_shared_keywords (keyword -> #detectors):\n")
	limit := 12
	for i, e := range sharedList {
		if i >= limit {
			break
		}
		fmt.Printf("  %q -> %d\n", e.kw, e.n)
	}
}
```

**Exact command** (run inside the external module; `-mod=mod` is incompatible with workspace
mode, so plain `go run .` is used — it resolves against the repository's own `go.sum` via the
workspace):

```bash
cd /tmp/thog_obs_q1 && go run .
```

**Complete, unedited output** (run 2; run 1, run 2, and run 3 were byte-for-byte identical —
`diff` reported no differences):

```
default_detectors=831
unique_keywords(len keywordsToDetectors)=914
total_keyword_detector_pairs=955
keywords_shared_by_multiple_detectors=32
top_shared_keywords (keyword -> #detectors):
  "azure" -> 6
  "airtable" -> 3
  "cloudflare" -> 3
  "github" -> 3
  "teamwork" -> 3
  "twitter" -> 3
  "airbrake" -> 2
  "asana" -> 2
  "auth0" -> 2
  "box" -> 2
  "captaindata" -> 2
  "docker" -> 2
```

**`file:line` grounding (verified at HEAD `e42153d4`).** In
`pkg/engine/ahocorasick/ahocorasickcore.go`, the keyword store is
`keywordsToDetectors map[string][]DetectorKey` (**L133**). The constructor
`func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core` (**L141**)
allocates the map (**L142**) and, for each detector and each `kw` in `d.Keywords()`, lowercases the
keyword via `kwLower := strings.ToLower(kw)` (**L149**) and appends the detector key with
`keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)` (**L151**). It also
appends `kwLower` to a parallel `keywords []string` slice, which is handed to the trie builder:
`prefilter: *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()` (**L159**). The accessor is
`func (ac *Core) KeywordsToDetectors() map[string][]DetectorKey` (**L302**). The default set comes
from `func DefaultDetectors() []detectors.Detector` in `pkg/engine/defaults/defaults.go` (**L1704**).
Matching is case-insensitive: `ac.prefilter.Match(bytes.ToLower(chunkData))` inside
`func (ac *Core) FindDetectorMatches(chunkData []byte) []*DetectorMatch` (**L241-242**).

**Cause → effect.** The **unique-keyword count equals `len(keywordsToDetectors)`** because the map
is keyed by the (lowercased) keyword — 914 distinct keys. The **`[]DetectorKey` slice value** is the
direct proof that a single keyword can map to multiple detectors: summing the slice lengths over the
whole map gives **955** (the number of `append` operations, i.e., the total `(keyword, detector)`
pairs, which is also the length of the `keywords` slice fed to `AddStrings`), and **32** of those
keys carry a slice longer than one — so keywords are **shared, not distinct per detector**. Because
keywords are lowercased at build time (`strings.ToLower`, L149) and the chunk is lowercased at match
time (`bytes.ToLower`, L242), keyword matching is **case-insensitive**. The default detector list is
static, so the magnitude is **deterministic** — confirmed identical across three runs.

**Reconciliation note (observed).** The Technical Specification §1.2 cites "845+" as a
*detector-directory* approximation; the observed canonical `DefaultDetectors()` count is **831**, which
is the authoritative number for the actual default set loaded at runtime.

---

## Q2 — Decoder sequencing: decode before, or after, keyword matching?

> **Verbatim question:** "whether the decoder pipeline processes encoded content like base64 before
> or after keyword matching happens, and what that sequence looks like in verbose output for a chunk
> that contains both plain and encoded secrets."

**Direct answer (observed + code-derived):** Decoding happens **before** keyword matching, and
matching runs on the **decoded** bytes. The decoder chain runs in a fixed order
`[UTF8, Base64, UTF16, EscapedUnicode]`, and for each decoded view the Aho-Corasick keyword match is
applied to the decoded data.

**Fixture.** A directory with the same URI credential in two forms — plaintext in `plain.txt` and
base64-encoded in `encoded.txt` — so a single scan shows both a `PLAIN` and a `BASE64` result:

```
plain.txt
  1  app config
  2  url = https://myuser:mypassword123@api.example.com
  3  end

encoded.txt   (line 2 is base64 of "https://myuser:mypassword123@api.example.com")
  1  token blob below
  2  aHR0cHM6Ly9teXVzZXI6bXlwYXNzd29yZDEyM0BhcGkuZXhhbXBsZS5jb20=
  3  trailer
```

**Exact command** (results → `stdout`, logs → `stderr`):

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q2 --trace --no-verification \
  --results=verified,unverified,unknown --no-update  1>stdout.log 2>stderr.log
```

**Complete, unedited `stdout` (results):**

```
Found unverified result 🐷🔑❓
Detector Type: URI
Decoder Type: BASE64
Raw result: https://myuser:mypassword123@api.example.com
File: /tmp/thog_obs_q2/encoded.txt
Line: 2

Found unverified result 🐷🔑❓
Detector Type: URI
Decoder Type: PLAIN
Raw result: https://myuser:mypassword123@api.example.com
File: /tmp/thog_obs_q2/plain.txt
Line: 2
```

The `BASE64` result's `Raw result` is the **decoded plaintext URI** — the base64 payload was decoded
first, and the URI keyword then matched on the decoded bytes.

**Complete, unedited `stderr` (trace pipeline).** Lines 1–21 are shown verbatim; they contain every
distinct pipeline event. After them the log emits 128 identical `finished scanning chunks` lines (one
per scanner worker) plus two `link is empty, skipping update` lines from the `--no-verification` path;
the final `finished scanning` summary (line 151) is shown verbatim after the elision marker:

```
2026-07-13T17:23:24Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T17:23:24Z	info-4	trufflehog	default engine options set
2026-07-13T17:23:24Z	info-4	trufflehog	engine initialized
2026-07-13T17:23:24Z	info-4	trufflehog	setting up aho-corasick core
2026-07-13T17:23:24Z	info-4	trufflehog	set up aho-corasick core
2026-07-13T17:23:24Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T17:23:24Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T17:23:24Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T17:23:24Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T17:23:24Z	info-0	trufflehog	--directory flag is deprecated, please pass directories as arguments
2026-07-13T17:23:24Z	info-0	trufflehog	running source	{"source_manager_worker_id": "rvmzV", "with_units": true}
2026-07-13T17:23:24Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "rvmzV"}
2026-07-13T17:23:24Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/encoded.txt"}
2026-07-13T17:23:24Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/encoded.txt", "path": "/tmp/thog_obs_q2/encoded.txt"}
2026-07-13T17:23:24Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/encoded.txt", "path": "/tmp/thog_obs_q2/encoded.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:23:24Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/plain.txt"}
2026-07-13T17:23:24Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/plain.txt", "path": "/tmp/thog_obs_q2/plain.txt"}
2026-07-13T17:23:24Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "rvmzV", "unit_kind": "unit", "unit": "/tmp/thog_obs_q2/plain.txt", "path": "/tmp/thog_obs_q2/plain.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T17:23:24Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "C8WZg"}
[... 127 additional "finished scanning chunks" lines follow — one per scanner worker (128 total) —
 plus two "link is empty, skipping update" lines from the --no-verification path ...]
2026-07-13T17:23:24Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 136, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.595265ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**`file:line` grounding (verified).** In `func (e *Engine) scannerWorker(ctx context.Context)`
(`pkg/engine/engine.go:L777`), for each chunk and each decoder in order, the decode runs first:
`decoded := decoder.FromChunk(chunk)` (**L786**), and only then the keyword match:
`matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` (**L795**) — note the
match consumes `decoded.Chunk.Data`. The decoder order is fixed by `func DefaultDecoders() []Decoder`
(`pkg/decoders/decoders.go:L8`): the comment `// UTF8 must be first for duplicate detection` is at
**L10**, then `&UTF8{}` (L11), `&Base64{}` (L12), `&UTF16{}` (L13), `&EscapedUnicode{}` (L14).

**Important framing (inferred / code-derived — labeled).** Per-decoder latency is **not** a log line;
it is a Prometheus histogram `decodeLatency = promauto.NewHistogramVec(...)`
(`pkg/engine/metrics.go:L11`). Therefore even at `--trace` there is no per-decode log message. What
verbose output *does* show is the worker/pipeline sequence (above); the per-result `Decoder Type` label
(`PLAIN` vs `BASE64`) is the runtime proof that matching occurred on decoded data.

**Cause → effect.** Because `FromChunk` (L786) precedes `FindDetectorMatches` (L795) inside the
per-decoder loop, keyword matching necessarily runs on decoded bytes. The `BASE64`-labeled result,
whose `Raw result` equals the decoded plaintext URI, is the observed confirmation that the base64
payload was decoded before the URI keyword matched.

---

## Q3 — Verification-cache metrics and cross-invocation persistence

> **Verbatim question:** "what metrics does the verification cache report at the end of a scan and do
> those hit and miss numbers change if you run the exact same scan twice consecutively, or does the
> cache not persist across invocations."

**Direct answer (observed):** The end-of-scan `finished scanning` log reports a `verification_caching`
object with **five** values — **`Hits`, `Misses`, `HitsWasted`, `AttemptsSaved`,
`VerificationTimeSpentMS`**. Running the exact same scan **twice consecutively** yields **identical
count metrics** (`Hits:0, Misses:3, HitsWasted:0, AttemptsSaved:0` both times); only
`VerificationTimeSpentMS` (wall-clock) differs. The cache therefore does **not** persist across
invocations — it is in-memory / in-process, constructed fresh each run.

**Fixture.** Three distinct URI credentials (`a.txt`, `b.txt`, `c.txt`) → three distinct
verification-cache misses, with no intra-run duplicates (so `Hits` stays 0).

**Exact command** (verification is ON by default — no `--no-verification`), run twice back-to-back:

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q3 --results=verified,unverified,unknown --no-update
```

**Complete, unedited `finished scanning` lines (stderr):**

```
RUN 1:
2026-07-13T17:25:50Z	info-0	trufflehog	finished scanning	{"chunks": 3, "bytes": 178, "verified_secrets": 0, "unverified_secrets": 3, "scan_duration": "62.531115ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":122}}

RUN 2 (identical input, immediately after):
2026-07-13T17:25:52Z	info-0	trufflehog	finished scanning	{"chunks": 3, "bytes": 178, "verified_secrets": 0, "unverified_secrets": 3, "scan_duration": "43.283676ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":75}}
```

The **count** fields are identical across the two runs (`Hits:0, Misses:3, HitsWasted:0,
AttemptsSaved:0`); only `VerificationTimeSpentMS` changed (122 → 75). If the cache persisted across
invocations, RUN 2 would show `Hits:3` instead of `Misses:3`. It does not → **no cross-invocation
persistence**.

**Edge case — cache disabled** (`--no-verification-cache`, `main.go:L85`):

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q3 --no-verification-cache --results=verified,unverified,unknown --no-update
```

```
2026-07-13T17:26:05Z	info-0	trufflehog	finished scanning	{"chunks": 3, "bytes": 178, "verified_secrets": 0, "unverified_secrets": 3, "scan_duration": "35.621528ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":69}}
```

With the result cache disabled the counts are all **0** (the cache lookup path is never exercised),
yet verification still runs, so `VerificationTimeSpentMS` is non-zero (69).

**Edge case — verification disabled** (`--no-verification`, for contrast):

```
2026-07-13T17:26:07Z	info-0	trufflehog	finished scanning	{"chunks": 3, "bytes": 178, "verified_secrets": 0, "unverified_secrets": 3, "scan_duration": "5.179031ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

With verification off, everything is **0**, including `VerificationTimeSpentMS` — verification never
runs, so nothing is timed and no cache lookups occur.

**`file:line` grounding (verified).** In `main.go`, the metrics accumulator is constructed fresh each
run: `verificationCacheMetrics := verificationcache.InMemoryMetrics{}` (**L511**); the result cache is
wired only when not disabled: `if !*noVerificationCache { engConf.VerificationResultCache =
simple.NewCache[detectors.Result]() }` (**L534-536**). The reported snapshot is an anonymous struct
with fields `Hits` (**L552**), `Misses` (**L553**), `HitsWasted` (**L554**), `AttemptsSaved` (**L555**),
`VerificationTimeSpentMS` (**L556**), populated from the atomics `ResultCacheHits`,
`ResultCacheMisses`, `ResultCacheHitsWasted`, `CredentialVerificationsSaved`,
`FromDataVerifyTimeSpentMS` (**L558-562**), and emitted by `logger.Info("finished scanning", ...)`
(**L566**) under the key `"verification_caching"` (**L573**). The five source atomics live in
`type InMemoryMetrics struct` (`pkg/verificationcache/in_memory_metrics.go:L9`, fields **L11-15**:
`CredentialVerificationsSaved`, `FromDataVerifyTimeSpentMS`, `ResultCacheHits`,
`ResultCacheHitsWasted`, `ResultCacheMisses`). The result-cache key (distinct from Q5's LRU dedupe
key) is blake2b-based: `func (v *VerificationCache) getResultCacheKey(...)`
(`pkg/verificationcache/verification_cache.go:L136`) returns `v.hasher.Hash(keyBytes)` (**L146**),
where `hasher: hasher.NewBlake2B()` (L35; `pkg/hasher/blake2b.go:L9`).

**Cause → effect.** (observed) the count fields are identical across two consecutive runs and `Hits`
stays 0. (inferred / code-derived) the reason: the five counters are in-process atomics re-initialized
on every `main()` invocation (`InMemoryMetrics{}` at L511) and the result cache is a fresh
`simple.NewCache[...]` per run (L535-536); nothing is written to disk or shared memory, so a second
process starts with zeroed counters — which is exactly what "the cache does not persist across
invocations" means.


---

## Q4 — Worker concurrency multipliers and backpressure

> **Verbatim question:** "If concurrency is set to a specific value like 4, what multipliers get
> applied to determine the actual goroutine counts for scanner workers versus detector workers versus
> notifier workers, and is there any observable queuing or backpressure when chunks pile up faster
> than detectors can process them."

**Direct answer (observed at `--concurrency=4`):** scanner **×1 = 4**, detector **×8 = 32**,
verificationOverlap **×1 = 4**, notifier **×1 = 4**. Backpressure is **structural, not instrumented**:
the pipeline uses plain bounded buffered channels, and when a buffer fills the sending worker blocks
on the channel send. There is no channel-depth metric to observe (the `pkg/channelmetrics` wrapper is
present in the tree but is **not** wired into these pipeline channels).

**Exact command** (worker-count lines are emitted at `V(2)`, so `--debug` is required):

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q3 --concurrency=4 --debug --no-verification --no-update
```

**Complete, unedited `stderr` (worker-count lines):**

```
2026-07-13T17:26:50Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-13T17:26:50Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-13T17:26:50Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-13T17:26:50Z	info-2	trufflehog	starting notifier workers	{"count": 4}
```

**Stability cross-check at a second concurrency value** (`--concurrency=128`) — same ×1/×8/×1/×1
ratios, confirming the multipliers hold across two concurrency values:

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q3 --concurrency=128 --debug --no-verification --no-update
```

```
2026-07-13T17:26:52Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T17:26:52Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T17:26:52Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T17:26:52Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

**`file:line` grounding (verified).** The multiplier defaults are set in `pkg/engine/engine.go`:
the detector multiplier defaults to 8 — `if e.detectorWorkerMultiplier < 1` (**L343**) →
`e.detectorWorkerMultiplier = 8` (**L345**); the notifier multiplier defaults to 1 (**L348-349**);
the verificationOverlap multiplier defaults to 1 (**L352-353**). The spawn sites read:
`func (e *Engine) startScannerWorkers` uses `count = e.concurrency`
(log line **L663**); `startDetectorWorkers` uses `numWorkers := e.concurrency *
e.detectorWorkerMultiplier` (**L676**, log **L678**); `startVerificationOverlapWorkers` uses
`e.concurrency * e.verificationOverlapWorkerMultiplier` (**L691**, log **L693**); `startNotifierWorkers`
uses `numWorkers := e.notificationWorkerMultiplier * e.concurrency` (**L706**, log **L708**). All four
"starting … workers" lines are emitted at `ctx.Logger().V(2)`. The `--concurrency` flag is defined at
`main.go:L58` (default `runtime.NumCPU()`), which is why the un-set default resolved to 128 on this
host.

**Backpressure — channel wiring (observed structure) + behavior (inferred).** The pipeline channels
are plain bounded buffered channels sized `defaultChannelBuffer` × a per-channel multiplier, all in
`pkg/engine/engine.go`:

- `detectableChunksChanMultiplier = 50` (**L503**);
- `verificationOverlapChunksChanMultiplier = 25` (**L507**);
- `resultsChanMultiplier = detectableChunksChanMultiplier` (=50) (**L508**);
- `e.detectableChunksChan = make(chan detectableChunk, defaultChannelBuffer*detectableChunksChanMultiplier)`
  (**L515**);
- `e.verificationOverlapChunksChan = make(chan verificationOverlapChunk,
  defaultChannelBuffer*verificationOverlapChunksChanMultiplier)` (**L516-518**);
- `e.results = make(chan detectors.ResultWithMetadata, defaultChannelBuffer*resultsChanMultiplier)`
  (**L519**);
- `var defaultChannelBuffer = runtime.NumCPU()` (**L627**).

On this host `runtime.NumCPU()` = 128 (observed: the un-set default produced 128 scanner workers), so
the buffers are `128×50 = 6400` (detectable), `128×25 = 3200` (verificationOverlap), and `128×50 =
6400` (results) — these sizes are **(inferred / code-derived)**, computed from the constants above.
**(inferred)** When a buffer fills, the sending worker **blocks** on the channel send; that blocking
send *is* the backpressure mechanism. There is no observable channel-depth counter: `grep` confirms
`channelmetrics` is not referenced in `engine.go`, so the pipeline channels are unwrapped, and
backpressure is not surfaced as a metric.

**Discrepancy to call out (observed comment/code mismatch).** The comment at
`pkg/engine/engine.go:L658` reads `// We want 1/4th of the notifier workers as the number of scanner
workers.`, but the code uses a default notifier multiplier of **1**, so the notifier count *equals* the
scanner count (both 4 at `--concurrency=4`, both 128 at `--concurrency=128`). The comment does not
match the implemented behavior.

**Cause → effect.** The observed counts are exactly `concurrency × {1, 8, 1, 1}` for
scanner/detector/verificationOverlap/notifier, matching the multiplier defaults and spawn expressions.
Because the channels are bounded and unwrapped, backpressure manifests only as blocked sends (no
metric), and the "1/4th" comment is stale relative to the multiplier-of-1 code.

---

## Q5 — Deduplication key and cross-decoder behavior

> **Verbatim question:** "what the LRU cache key looks like and whether it prevents duplicates across
> decoder types, meaning if the same credential shows up both plaintext and base64 encoded does it get
> reported once or twice."

**Direct answer (observed + code-derived):** The dedupe key is
`fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2,
result.SourceMetadata)` — built in the notifier worker at **`pkg/engine/engine.go:L1216`**. The
**decoder type is not part of the key**; it is the stored *value*. Because `SourceMetadata` (file/line)
is part of the key, the **same credential appearing plaintext and base64-encoded at different
file/line locations has different keys and is reported twice** (observed).

**Fixture.** The same URI credential, plaintext in `plain.txt` (line 2) and base64-encoded in
`encoded.txt` (line 2) — different files/lines, hence different `SourceMetadata`.

**Exact command:**

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q5 --no-verification --results=verified,unverified,unknown --no-update
```

**Complete, unedited `stdout` — reported twice:**

```
Found unverified result 🐷🔑❓
Detector Type: URI
Decoder Type: BASE64
Raw result: https://myuser:mypassword123@api.example.com
File: /tmp/thog_obs_q5/encoded.txt
Line: 2

Found unverified result 🐷🔑❓
Detector Type: URI
Decoder Type: PLAIN
Raw result: https://myuser:mypassword123@api.example.com
File: /tmp/thog_obs_q5/plain.txt
Line: 2
```

Two results: identical `Detector Type`, `Raw result`, `RawV2` — but different `File`/`Line`
(`SourceMetadata`), so the two dedupe keys differ and neither is skipped.

**`file:line` grounding (verified).** The cache is declared as
`dedupeCache *lru.Cache[string, detectorspb.DecoderType]` (`pkg/engine/engine.go:L209`, with the
explanatory comment at L207-208), constructed with `const cacheSize = 512` (**L491**) via
`lru.New[string, detectorspb.DecoderType](cacheSize)` (**L493**) and assigned `e.dedupeCache = cache`
(**L520**). Inside `func (e *Engine) notifierWorker(ctx context.Context)` (**L1189**), a comment block
(**L1210-1215**, including the Postman note at L1215) precedes the key construction:

```go
// L1216
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
// L1217-1219
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
// L1221
e.dedupeCache.Add(key, result.DecoderType)
```

The key is `DetectorType + Raw + RawV2 + SourceMetadata`; the stored value is `result.DecoderType`.

**Cause → effect.** Because `SourceMetadata` (which encodes the file and line) is part of the key and
differs between the two locations, the two keys differ → the second result is not skipped → the
credential is reported twice.

**Edge cases (inferred / code-derived — not reproducible with filesystem fixtures at different
locations).**
- **Report once (cross-decoder dedupe):** the skip fires only when `DetectorType + Raw + RawV2 +
  SourceMetadata` are *identical* **and** the stored decoder differs from the current one
  (`val != result.DecoderType`, L1217). The `// UTF8 must be first for duplicate detection` ordering
  (`pkg/decoders/decoders.go:L10`) guarantees the plaintext/UTF8 hit is stored first, so a later
  duplicate at the **same** metadata but a **different** decoder is dropped — reported once.
- **Postman sources:** when `result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN` (L1218),
  results are deduped regardless of decoder type (the `||` short-circuits the skip condition).


---

## Q6 — `--print-avg-detector-time`: coverage and verification-time inclusion

> **Verbatim question:** "when using the flag that prints average detector timing, does that output
> include all detectors or only ones that matched something, and does verification time factor into
> those numbers or get tracked separately."

**Direct answer (observed + code-derived):** `--print-avg-detector-time` prints **only the detectors
that returned results** (not all 831) — recording is gated on `len(results) > 0`. The measured
interval **includes verification time**: it wraps the `verificationCache.FromData(...)` call, so with
verification on the times are milliseconds and with `--no-verification` they collapse to microseconds.

**Fixture.** A directory matching a small number of detectors: a URI credential (`uri.txt`) and a
Slack-style bot token (`slack.txt`).

**Exact command — verification ON (default):**

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q6 --print-avg-detector-time --results=verified,unverified,unknown --no-update
```

**Complete, unedited `stderr` (banner + timing lines + final summary):**

```
Average detector time is the measurement of average time spent on each detector when results are returned.
URI: 32.684847ms
Slack: 160.096694ms
2026-07-13T17:29:15Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 138, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "164.754486ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":191}}
```

Only two detectors appear (`URI`, `Slack`) — no line for the other ~829 detectors. (Note: in the
verification-ON run the URI result reported `Verification issue: lookup api.example.com … no such
host` on stdout — verification was genuinely attempted over the network, which is why the timings are
in the millisecond range.)

**Exact command — verification OFF (`--no-verification`):**

```bash
/tmp/thog filesystem --directory=/tmp/thog_obs_q6 --print-avg-detector-time --no-verification --results=verified,unverified,unknown --no-update
```

**Complete, unedited `stderr`:**

```
Average detector time is the measurement of average time spent on each detector when results are returned.
Slack: 167.188µs
URI: 1.003999ms
2026-07-13T17:30:04Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 138, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.193523ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Side-by-side (the same two detectors, verify on vs off):**

| Detector | verification ON | verification OFF |
|----------|-----------------|------------------|
| URI      | 32.684847ms     | 1.003999ms       |
| Slack    | 160.096694ms    | 167.188µs        |

Slack drops from ~160 ms to ~167 µs — roughly a 1000× reduction — when verification is disabled. That
collapse is the empirical proof that the network verification call is **inside** the measured window.
(The set is the same two matched detectors in both runs; their print order differs because
`GetDetectorsMetrics()` iterates a `sync.Map`, whose iteration order is not fixed.)

**`file:line` grounding (verified).** The flag `--print-avg-detector-time` is defined at `main.go:L72`
and wired via `PrintAvgDetectorTime: *printAvgDetectorTime` (`main.go:L530`). In
`func (e *Engine) detectChunk(ctx context.Context, data detectableChunk)` (`pkg/engine/engine.go:L1044`):
`var start time.Time` (L1045) and `if e.printAvgDetectorTime { start = time.Now() }` (start captured at
**L1047**). Verification runs *inside* the window at `results, err := e.verificationCache.FromData(...)`
(**L1070**). Recording is gated by `if e.printAvgDetectorTime && len(results) > 0` (**L1092**), with
`elapsed := time.Since(start)` (**L1093**) and the value stored via
`e.metrics.detectorAvgTime.Store(detectorName, avgTime)` (**L1104**) into `detectorAvgTime sync.Map`
(**L60**). The values are surfaced by `GetDetectorsMetrics()` (**L578**) / `DetectorAvgTime()`
(**L596**). They are printed by `func printAverageDetectorTime(e *engine.Engine)` (`main.go:L1021`) —
called at **`main.go:L964`** — which writes to `os.Stderr` (L1023) under the banner
`"Average detector time is the measurement of average time spent on each detector when results are
returned."` (**L1024**), then loops `for detectorName, duration := range e.GetDetectorsMetrics()`
(**L1026**).

**Cause → effect.** Recording is gated on `len(results) > 0` (L1092), so detectors that returned
nothing are never stored in `detectorAvgTime` → the printed set covers **only matched detectors**.
Because `start` is captured before the match loop (L1047) and `elapsed` is computed after `FromData`
returns (L1093, with L1070 inside the `[L1047 … L1093]` window), the interval **includes verification**;
disabling verification collapses the timing to microseconds, confirming inclusion empirically. This
per-detector metric is **distinct** from the verification-cache block's `VerificationTimeSpentMS` (Q3),
which tracks verification wall-time separately.

---

## Coverage summary

| # | Question | Direct answer |
|---|----------|---------------|
| Q1 | Unique keywords in the trie; are keywords shared? | 831 detectors → **914 unique keywords** (955 pairs); **shared** — 32 keywords map to >1 detector, `"azure"` → 6 |
| Q2 | Decode before or after keyword matching? | **Decode first**; matching runs on decoded bytes; order `[UTF8, Base64, UTF16, EscapedUnicode]` |
| Q3 | Verification-cache metrics; persist across runs? | Five metrics (`Hits, Misses, HitsWasted, AttemptsSaved, VerificationTimeSpentMS`); counts **identical** across two runs → **no cross-invocation persistence** |
| Q4 | Concurrency multipliers; backpressure? | ×1/×8/×1/×1 (scanner/detector/verificationOverlap/notifier); backpressure = **blocking sends** on bounded buffered channels (not instrumented) |
| Q5 | LRU dedupe key; cross-decoder duplicates? | Key = `DetectorType + Raw + RawV2 + SourceMetadata` (decoder type is the *value*); same secret at **different** locations → reported **twice** |
| Q6 | `--print-avg-detector-time` coverage; verification time? | **Only matched detectors**; verification time **is included** (ms → µs when disabled) |

---

## Repository left unmodified

The baseline was verified clean at the start of the investigation, and the repository remains clean at
the end — the only addition is this deliverable. No tracked/source file was modified: `git diff` against
HEAD reports zero changed tracked files.

```bash
$ git diff --name-status HEAD | wc -l
0

$ git status --porcelain --untracked-files=all
?? blitzy/documentation/trufflehog_e42153d44a5e.md
```

The single untracked entry is this document itself. Every temporary artifact used during the
investigation lived **outside** the repository tree and was removed on completion:

- the compiled binary `/tmp/thog`;
- all scan fixtures (`/tmp/thog_obs_smoke`, `/tmp/thog_obs_q2`, `/tmp/thog_obs_q3`, `/tmp/thog_obs_q5`,
  `/tmp/thog_obs_q6`);
- the external observation module used for Q1 (`/tmp/thog_obs_q1`, including its `go.work` /
  `go.mod` / `main.go`);
- the capture directory (`/tmp/blitzy_captures`).

No source, configuration, test, or in-tree documentation file was created, edited, or deleted, and
`go.mod` / `go.sum` were untouched.

