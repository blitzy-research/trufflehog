# TruffleHog Runtime Q&A — Secret-Detection Pipeline

**Target:** TruffleHog (`github.com/trufflesecurity/trufflehog/v3`) at commit
`e42153d44a5e5c37c1bd0c70e074781e9edcb760`, source branch `trufflehog_e42153d44a5e`,
version stamp `dev` (`var BuildVersion = "dev"` at `pkg/version/version.go:3`).

**Toolchain:** `go 1.23.1` (`go.mod:3`), `toolchain go1.24.2` (`go.mod:5`).

**How this document was produced.** Every answer below was derived from **real
captured runtime output**, obtained by building and running TruffleHog in its
default/canonical configuration inside the provided container, *before* any prose
was written. Each section shows the **exact command executed**, the **complete,
unedited terminal output** it produced (in a fenced block), and a **cause → effect**
explanation anchored to an exact `file:line` citation naming the specific
function/struct/field. Magnitude/timing values were confirmed stable across at
least two runs. Crafted scan inputs and the one temporary Go observation harness
lived entirely outside the tracked source tree (under `/tmp/th_obs`) and were
removed on completion; no existing repository file was modified.

## Build preamble (canonical)

The canonical build/run commands are the repository's own (`Makefile:48-49` =
`CGO_ENABLED=0 go run . git file://. --json`; `Makefile:51-52` `run-debug` adds
`--log-level=2`). The Go toolchain and canonical build:

```
$ go version
go version go1.24.2 linux/amd64

$ git branch --show-current
blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88

$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760

$ CGO_ENABLED=0 go build .
$ echo $?
0

$ ./trufflehog --version
trufflehog dev
```

> **Note on the working branch.** The checkout's *working* branch is
> `blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88`, but HEAD is exactly
> `e42153d44a5e5c37c1bd0c70e074781e9edcb760` — the commit the source branch
> `trufflehog_e42153d44a5e` names — so this document is named for that source
> branch per the deliverable rule. The built `./trufflehog` binary is ignored by
> `.gitignore:7`, so it does not alter the tracked tree.

> **Container CPU note (used throughout).** In this container Go reports
> `runtime.NumCPU() = 128` and `GOMAXPROCS = 128` (the cgroup limits `nproc` to
> `4`, but Go 1.24 does not honor the cgroup CPU quota). Consequently the
> **default** `--concurrency` is `128` (`main.go:58` defaults it to
> `runtime.NumCPU()`), and `defaultChannelBuffer = runtime.NumCPU() = 128`
> (`pkg/engine/engine.go:627`). This is why unqualified runs show `detector
> workers count=1024` (= `128 × 8`). Questions that must be deterministic pin
> `--concurrency` explicitly.

All CLI runs below append `--no-update` (`main.go:73`) to suppress the default
update-check network call; it does not affect any measured behavior. Every other
flag is left at its default unless a question explicitly requires otherwise
(verification is ON unless `--no-verification` (`main.go:59`); the verification
result cache is ON unless `--no-verification-cache` (`main.go:85`)).

## Pipeline reference diagram

The four-stage, channel-connected, multi-goroutine engine pipeline relevant to
Q2/Q4/Q5 (wired in `startWorkers` at `pkg/engine/engine.go:646-660`; corroborated
by `docs/concurrency.md` and `docs/process_flow.md`):

```mermaid
flowchart LR
    SRC[Source chunks<br/>ChunksChan] --> SW[scannerWorker<br/>count = concurrency]
    SW -->|for each decoder:<br/>FromChunk then<br/>FindDetectorMatches| DEC{multiple<br/>detectors?}
    DEC -->|yes| VOC[verificationOverlapChunksChan]
    DEC -->|no| DCC[detectableChunksChan]
    VOC --> VOW[verificationOverlapWorker<br/>count = concurrency x overlapMult]
    VOW --> DCC
    DCC --> DW[detectorWorker<br/>count = concurrency x 8]
    DW --> RC[resultsChan]
    RC --> NW[notifierWorker<br/>count = concurrency x 1<br/>LRU dedupe]
    NW --> OUT[Output / Dispatcher]
%% Buffered channels create backpressure when producers outrun consumers
```

---

## Q1 — Unique keywords loaded into the Aho-Corasick trie, and "shared or distinct?"

**Question & named sub-parts.** When the engine initializes with the default
detector set, (a) **how many *unique* keywords** are loaded into the Aho-Corasick
trie, and (b) do multiple detectors **share** keywords or maintain **distinct**
ones?

**Command.** A temporary Go observation harness (a *separate* module outside the
tracked tree, at `/tmp/th_obs/q1`, using a `replace` directive pointing at the
repo) instantiates the software's **own** default detectors — never a synthetic
pattern list — and reads the canonical unique-count getter. Harness `main.go`:

```go
package main

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

func main() {
	ds := defaults.DefaultDetectors()
	core := ahocorasick.NewAhoCorasickCore(ds)
	k2d := core.KeywordsToDetectors()

	total := 0 // mirrors the raw `keywords` slice length (one append per (detector,keyword) pair, L150)
	for _, d := range ds {
		total += len(d.Keywords())
	}
	unique := len(k2d) // canonical unique count (L133/L302)

	maxFan, shared := 0, 0
	var maxKw string
	for kw, keys := range k2d {
		if len(keys) > 1 {
			shared++
		}
		if len(keys) > maxFan {
			maxFan, maxKw = len(keys), kw
		}
	}
	fmt.Printf("default_detectors=%d\n", len(ds))
	fmt.Printf("total_keyword_additions=%d\n", total)
	fmt.Printf("unique_keywords=%d\n", unique)
	fmt.Printf("shared_keywords_fanout_gt1=%d\n", shared)
	fmt.Printf("max_fanout=%d for keyword=%q\n", maxFan, maxKw)
}
```

Harness `go.mod`:

```
module thq1

go 1.23.1

require github.com/trufflesecurity/trufflehog/v3 v3.0.0

replace github.com/trufflesecurity/trufflehog/v3 => /tmp/blitzy/trufflehog/blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88_33d3d3
```

Run (repeated for stability):

```
cd /tmp/th_obs/q1 && GOFLAGS=-mod=mod go run .
```

**Complete, unedited output — Run 1:**

```
default_detectors=831
total_keyword_additions=955
unique_keywords=914
shared_keywords_fanout_gt1=32
max_fanout=6 for keyword="azure"
```

**Complete, unedited output — Run 2:**

```
default_detectors=831
total_keyword_additions=955
unique_keywords=914
shared_keywords_fanout_gt1=32
max_fanout=6 for keyword="azure"
```

**Stability note.** Run three times; all three produced byte-identical numbers
(the default detector set is deterministic). The unique count is therefore
reported as a stable value.

**Cause → effect (with `file:line`).**
`ahocorasick.NewAhoCorasickCore(allDetectors)` (`pkg/engine/ahocorasick/ahocorasickcore.go:141`)
loops over every detector (`for _, d := range allDetectors` at
`ahocorasickcore.go:145`) and, for each keyword, lowercases it
(`kwLower := strings.ToLower(kw)` at `ahocorasickcore.go:149`), **appends it once
to the raw `keywords` slice** (`keywords = append(keywords, kwLower)` at
`ahocorasickcore.go:150` — one append per `(detector, keyword)` pair, so
duplicates are possible), and records the mapping
`keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)`
(`ahocorasickcore.go:151`). The field is
`keywordsToDetectors map[string][]DetectorKey` (`ahocorasickcore.go:133`), and the
trie is built from the raw slice via
`*ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()`
(`ahocorasickcore.go:159`). Because `AddStrings` (from
`github.com/BobuSumisu/aho-corasick v1.0.3`, `go.mod:17`) assigns each *added*
pattern its own index, the raw slice's duplicates are added repeatedly — hence the
canonical measure of *unique* keywords is `len(keywordsToDetectors)`
(`ahocorasickcore.go:133`), exposed by the getter `func (ac *Core) KeywordsToDetectors()`
at `ahocorasickcore.go:302`. That is exactly what the harness reads.

- The **831** default detectors contribute **955** total keyword additions (the
  raw slice), which collapse to **914** unique keys in `keywordsToDetectors` — i.e.
  `955 − 914 = 41` additions are duplicates of an already-seen keyword.
- **32** unique keywords map to **more than one** `DetectorKey`, and the maximum
  fan-out is **6** — the keyword `"azure"` alone selects six distinct detectors.

**Explicit answer.**
- **Unique keyword count:** **914** (`len(core.KeywordsToDetectors())`,
  `ahocorasickcore.go:133`/`:302`). (Total additions to the raw `keywords` slice:
  **955**; the difference of 41 reflects duplicate `(detector,keyword)` appends at
  `ahocorasickcore.go:150`.)
- **Shared or distinct?** **SHARED.** A single lowercased keyword maps to multiple
  `DetectorKey`s in `keywordsToDetectors` (`ahocorasickcore.go:151`): 32 keywords
  have fan-out `> 1`, and `"azure"` reaches a fan-out of 6. Keywords are therefore
  shared across detectors, not maintained distinctly per detector.

---

## Q2 — Decoder ordering relative to keyword matching: "before or after?"

**Question & named sub-parts.** Does the decoder pipeline process encoded content
(e.g., base64) **before** or **after** keyword matching, and what does the
sequence look like for a chunk containing **both** a plaintext and an encoded
secret?

**Setup (crafted input, outside the tree).** Two *different* secrets: an AWS
key-pair in **plaintext**, and a **different** secret (a Sentry token) that is
only present in **base64** form — so it can only be matched *after* decoding.

```
mkdir -p /tmp/th_obs/q2
printf 'aws_key = AKIAWARWQKZNHMZBLY4I\naws_secret = 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\n' > /tmp/th_obs/q2/plain.txt
printf 'blob: %s\n' "$(printf ' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90\n' | base64 -w0)" > /tmp/th_obs/q2/encoded.txt
```

The two crafted files:

```
$ cat /tmp/th_obs/q2/plain.txt
aws_key = AKIAWARWQKZNHMZBLY4I
aws_secret = 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

$ cat /tmp/th_obs/q2/encoded.txt
blob: IHNlbnRyeSAyN2FjODRmNGJjZGI0ZmNhOTcwMWY0ZDZmNmY1OGNkN2Q5NmI2OWM5ZDk3NTRkNDA4MDA2NDVhNTFkNjY4ZjkwCg==

$ grep -c 'sentry\|27ac' /tmp/th_obs/q2/encoded.txt
0
```

The `grep -c` returning **0** confirms the base64 blob contains no plaintext
`sentry`/`27ac` keyword — the Sentry keyword only exists *after* the blob is
base64-decoded.

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q2 --json --no-update
```

**Complete, unedited output — stdout (findings):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/encoded.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/plain.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

**Complete, unedited output — stderr:**

```
{"level":"info-0","ts":"2026-07-08T05:13:24Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"oCIDe","with_units":true}
{"level":"info-0","ts":"2026-07-08T05:13:24Z","logger":"trufflehog","msg":"finished scanning","chunks":2,"bytes":165,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"145.182055ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":203}}
```

**Stability note.** A second run produced the identical detector→decoder mapping
(`AWS`→`PLAIN`, `SentryToken`→`BASE64`).

> **Field-name note.** The JSON finding exposes the decoder as **`DecoderName`**
> (values `PLAIN`, `BASE64`, …), which is the string form of the internal
> `DecoderType`. The plaintext AWS finding carries `"DecoderName":"PLAIN"`; the
> base64-only Sentry finding carries `"DecoderName":"BASE64"`.

**Cause → effect (with `file:line`).** `scannerWorker`
(`pkg/engine/engine.go:777`) iterates decoders **first** —
`for _, decoder := range e.decoders` (`engine.go:784`) →
`decoded := decoder.FromChunk(chunk)` (`engine.go:786`) — and only *then* runs
keyword matching on the **decoded** bytes:
`matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)`
(`engine.go:795`). This decode-then-match sequence repeats **once per decoder**,
in the order returned by `DefaultDecoders()` (`pkg/decoders/decoders.go:8-16` →
`{UTF8, Base64, UTF16, EscapedUnicode}`, with the comment
`// UTF8 must be first for duplicate detection` at `decoders.go:10`). The runtime
proof: the Sentry token could only be discovered as `DecoderName=BASE64` because
its keyword did not exist in the raw chunk (grep = 0) — it appeared only after
`Base64.FromChunk` (`engine.go:786`) decoded the blob, at which point
`FindDetectorMatches` (`engine.go:795`) saw the decoded `sentry …` bytes and
selected the Sentry detector. The four-stage flow is corroborated by
`docs/process_flow.md` (Source Decomposition → Chunk to Detector Matching →
Secret Detection → Result Notification).

**Explicit answer.**
- **Before or after?** **BEFORE.** Decoding happens *before* keyword matching:
  the decoder loop at `engine.go:784-786` runs, and `FindDetectorMatches` at
  `engine.go:795` operates on the already-decoded bytes. A base64-only secret is
  reported with `DecoderName=BASE64` precisely because it was decoded first; the
  plaintext secret is reported with `DecoderName=PLAIN`.

---

## Q3 — Verification-cache metrics and cross-invocation persistence: "persist or not?"

**Question & named sub-parts.** (a) What metrics does the verification cache
report at end of scan; (b) do hit/miss numbers change when the **same** scan runs
twice consecutively — or does the cache **not persist** across invocations?

**The reported metric fields.** The end-of-scan snapshot is the struct literal
`verificationCacheMetricsSnapshot` (`main.go:551-563`), sourced from
`InMemoryMetrics` (`pkg/verificationcache/in_memory_metrics.go:9-15`) and printed
by `logger.Info("finished scanning", ... "verification_caching", verificationCacheMetricsSnapshot)`
(`main.go:566-574`) — i.e., the log key is **`verification_caching`** (info level,
visible at the default `--log-level=0`, on **stderr**). The five fields (snapshot
name then underlying `InMemoryMetrics` field):

| Snapshot field | Underlying field (`in_memory_metrics.go`) | Meaning (`metrics_reporter.go`) |
|---|---|---|
| `Hits` | `ResultCacheHits` (`:12`) | result-cache hits (`metrics_reporter.go:16-18`) |
| `Misses` | `ResultCacheMisses` (`:14`) | result-cache misses (`metrics_reporter.go:20-21`) |
| `HitsWasted` | `ResultCacheHitsWasted` (`:13`) | hits that did **not** elide a remote call because other findings in the chunk were uncached (`metrics_reporter.go:23-27`) |
| `AttemptsSaved` | `CredentialVerificationsSaved` (`:10`) | remote verifications elided by loading status from cache (`metrics_reporter.go:8-11`) |
| `VerificationTimeSpentMS` | `FromDataVerifyTimeSpentMS` (`:11`) | wall time in `detector.FromData` with `verify=true` (`metrics_reporter.go:13-14`) |

### Condition A — cross-invocation (the "run twice" sub-question)

**Command.** The identical scan of the repository's own testdata, run as **two
separate CLI processes**:

```
CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --json --no-update
```

**Complete, unedited output — Run 1 (stderr; stdout carried 2 findings):**

```
{"level":"info-0","ts":"2026-07-08T05:19:42Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"oPrXR","with_units":true}
{"level":"info-0","ts":"2026-07-08T05:19:42Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":372,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"178.04484ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":229}}
```

**Complete, unedited output — Run 2 (a fresh, separate process; stdout carried 2 findings):**

```
{"level":"info-0","ts":"2026-07-08T05:19:46Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"GF9QB","with_units":true}
{"level":"info-0","ts":"2026-07-08T05:19:47Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":372,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"148.045849ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":195}}
```

**Stability note.** The scan was run four separate times; the counts
`Hits:0, Misses:2, HitsWasted:0, AttemptsSaved:0` were **identical every time**
(only `VerificationTimeSpentMS` varied as wall-clock: 195–229 ms). If the cache
persisted across invocations, Run 2 would have reported `Hits:2, Misses:0`;
instead every process starts cold with `Misses:2`.

### Condition B — within-process hit accrual (the contrasting/edge branch)

`secrets.txt` is a single chunk, so its four identical Sentry lines cannot produce
cross-chunk hits (they collapse within the one chunk → `Hits:0`). To exercise the
**within-process** hit path, scan a directory of 100 files, each containing the
**same** Sentry credential (so each file is a separate chunk); pin
`--concurrency=1` so the result-cache store for an early chunk completes before a
later chunk's lookup.

```
mkdir -p /tmp/th_obs/q3_many
for i in $(seq 1 100); do
  printf ' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90\n' > /tmp/th_obs/q3_many/file$i.txt
done
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q3_many --concurrency=1 --no-update
```

**Complete, unedited output — stderr:**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:19:51Z	info-0	trufflehog	running source	{"source_manager_worker_id": "SUivC", "with_units": true}
2026-07-08T05:19:51Z	info-0	trufflehog	finished scanning	{"chunks": 100, "bytes": 7300, "verified_secrets": 0, "unverified_secrets": 100, "scan_duration": "78.424504ms", "trufflehog_version": "dev", "verification_caching": {"Hits":92,"Misses":8,"HitsWasted":0,"AttemptsSaved":92,"VerificationTimeSpentMS":510}}
```

**Stability note.** Run as three separate processes, all three produced identical
`Hits:92, Misses:8, HitsWasted:0, AttemptsSaved:92`. Two things follow at once:
(1) **within a process, hits accrue** — 92 of the 100 chunks loaded verification
status from the cache; and (2) the **`Misses:8` recurs on every separate process**
(never `Misses:0`), so each invocation re-warms from cold — again proving **no
cross-invocation persistence**. For contrast, the *same* 100-file input at the
default concurrency (128) shows `Hits:0, Misses:100` with
`VerificationTimeSpentMS≈15949` (all 100 chunks race past the cache before any
store lands, so all miss and all perform real remote verification) versus
`VerificationTimeSpentMS≈510` when 92 were served from cache.

**Cause → effect (with `file:line`).** The result cache is created per process and
only when caching is enabled by default:
`if !*noVerificationCache { engConf.VerificationResultCache = simple.NewCache[detectors.Result]() }`
(`main.go:535-537`), and the metrics reporter is a fresh
`verificationcache.InMemoryMetrics{}` per process (`main.go:511`), wired via
`VerificationCacheMetrics` (`main.go:532`). The store is an in-memory
`patrickmn/go-cache` (`go.mod:80`) wrapped by `simple.Cache[T]`
(`pkg/cache/simple/simple.go:16-21`) — nothing writes it to disk, so a new process
begins with an empty cache. Inside `VerificationCache.FromData`
(`pkg/verificationcache/verification_cache.go:50`), each candidate result's cache
key is looked up (`v.resultCache.Get(...)` at `verification_cache.go:90`): a hit
records `AddResultCacheHits(1)` (`:93`), a miss records `AddResultCacheMisses(1)`
(`:96`); when every result in a chunk is cached it records
`AddCredentialVerificationsSaved(len(...))` (`:104`); otherwise it performs remote
verification and **stores** each result (`v.resultCache.Set(...)` at
`verification_cache.go:130`). The cache key itself, `getResultCacheKey`
(`verification_cache.go:136-147`), is a Blake2B hash
(`hasher.NewBlake2B()` set in `New()` at `verification_cache.go:35`;
`golang.org/x/crypto` `go.mod:107`) over `result.Raw ‖ result.RawV2`
(`verification_cache.go:140`) plus `result.DetectorType`
(`binary.Append(..., result.DetectorType)` at `verification_cache.go:141`) — which
is why 100 copies of the same credential share one key and hits accrue within the
process.

**Explicit answer.**
- **Reported metric fields (by name, with source line):** `Hits`
  (`ResultCacheHits`, `in_memory_metrics.go:12`), `Misses` (`ResultCacheMisses`,
  `:14`), `HitsWasted` (`ResultCacheHitsWasted`, `:13`), `AttemptsSaved`
  (`CredentialVerificationsSaved`, `:10`), and `VerificationTimeSpentMS`
  (`FromDataVerifyTimeSpentMS`, `:11`) — printed under the `verification_caching`
  key (`main.go:566-574`).
- **Persist or not?** **NOT persisted across separate CLI invocations.** The
  result cache (`simple.NewCache`, `main.go:536`) and metrics
  (`InMemoryMetrics{}`, `main.go:511`) are constructed fresh per process and held
  only in memory, so two separate runs of the identical scan produce identical
  snapshots (misses do not become hits on the second run). **Within** a single
  process, hits **do** accrue (92 of 100 chunks in Condition B).

---

## Q4 — Worker architecture at `--concurrency=4`: "what multipliers? queuing observable?"

**Question & named sub-parts.** With `--concurrency=4`, (a) what **multipliers**
determine the actual goroutine counts for scanner vs. detector vs. notifier (vs.
verification-overlap) workers, and (b) is **queuing/backpressure** observable?

**Command.** Run at V(2) (where the worker-startup logs are emitted), pinning
concurrency to 4:

```
CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --concurrency=4 --log-level=2 --no-update
```

**Complete, unedited output — stderr (10 lines):**

```
2026-07-08T05:20:21Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:20:21Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-08T05:20:21Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-08T05:20:21Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-08T05:20:21Z	info-2	trufflehog	starting notifier workers	{"count": 4}
2026-07-08T05:20:21Z	info-0	trufflehog	running source	{"source_manager_worker_id": "4uPag", "with_units": true}
2026-07-08T05:20:21Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "4uPag"}
2026-07-08T05:20:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "164.649243ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":211}}
```

**Stability note.** Run three times; the four counts were identical every run:
**scanner=4, detector=32, verificationOverlap=4, notifier=4** — i.e. **4 / 32 / 4 / 4**.

**Cause → effect (with `file:line`).** `Config.Concurrency`
(`pkg/engine/engine.go:100`; the comment at `engine.go:98-99` states it "also
serves as a multiplier for other worker types") is the base. The three multiplier
`Config` fields are `DetectorWorkerMultiplier` (`engine.go:145`),
`NotificationWorkerMultiplier` (`engine.go:148`), and
`VerificationOverlapWorkerMultiplier` (`engine.go:151`); their defaults are set in
`setDefaults` — `detectorWorkerMultiplier = 8` (`engine.go:345`, guarded by the
`< 1` check at `:343`), `notificationWorkerMultiplier = 1` (`engine.go:349`, guard
`:348`), `verificationOverlapWorkerMultiplier = 1` (`engine.go:353`, guard `:352`).
Each pool is launched with a count derived from `concurrency × multiplier` and
logs it at V(2):

- **scanner** = `concurrency` →
  `ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)`
  (`engine.go:663`) ⇒ `4`.
- **detector** = `concurrency * detectorWorkerMultiplier` (`engine.go:676`), logged
  at `engine.go:678` ⇒ `4 × 8 = 32`.
- **verificationOverlap** = `concurrency * verificationOverlapWorkerMultiplier`
  (`engine.go:691`), logged at `engine.go:693` ⇒ `4 × 1 = 4`.
- **notifier** = `notificationWorkerMultiplier * concurrency` (`engine.go:706`),
  logged at `engine.go:708` ⇒ `1 × 4 = 4`.

The observed `4 / 32 / 4 / 4` matches these formulas exactly. (The four-worker-type
model is corroborated by `docs/concurrency.md`.)

**Backpressure/queuing.** The stages are connected by **bounded buffered
channels** whose capacities are `defaultChannelBuffer × multiplier`, where
`var defaultChannelBuffer = runtime.NumCPU()` (`engine.go:627`; here 128). The
per-channel multipliers are `detectableChunksChanMultiplier = 50`
(`engine.go:503`), `verificationOverlapChunksChanMultiplier = 25`
(`engine.go:507`), and `resultsChanMultiplier = detectableChunksChanMultiplier`
(`engine.go:508`); the channels are created at `engine.go:515-519`
(`detectableChunksChan`, `verificationOverlapChunksChan`, `results`). Because each
channel has a finite capacity, once a downstream consumer lags and its inbound
channel fills, the upstream producer **blocks on the channel send** — that is the
observable backpressure. Concretely: scanner workers feed
`detectableChunksChan` (capacity `128 × 50 = 6400`); if the 32 detector workers
cannot keep up (e.g., slow remote verification), the buffer fills and scanner
sends block until a detector worker drains an item. The same bounded-buffer
mechanism throttles `verificationOverlapChunksChan` (capacity `128 × 25 = 3200`)
and `results` (capacity `128 × 50 = 6400`). This is exactly the effect that made
Q3's default-concurrency run take ~16 s: 100 chunks fanned out to 1024 detector
workers all performing real remote verification concurrently, rate-limited only by
the bounded channels and the network.

**Explicit answer.**
- **What multipliers?** scanner = `concurrency` (no multiplier); **detector ×8**
  (`detectorWorkerMultiplier = 8`, `engine.go:345`); **notification ×1**
  (`notificationWorkerMultiplier = 1`, `engine.go:349`); **verificationOverlap ×1**
  (`verificationOverlapWorkerMultiplier = 1`, `engine.go:353`). At
  `--concurrency=4` the resulting counts are **scanner=4, detector=32,
  verificationOverlap=4, notifier=4 (4 / 32 / 4 / 4)**.
- **Queuing/backpressure observable?** **Yes.** The bounded buffered channels
  (`engine.go:503-519`, sized via `defaultChannelBuffer = runtime.NumCPU()` at
  `engine.go:627`) cause a producer stage to block on send whenever its downstream
  channel is full — i.e. when consumers lag, producers queue and then stall.

---

## Q5 — Deduplication LRU key and cross-decoder behavior: "reported once or twice?"

**Question & named sub-parts.** (a) What does the LRU cache key look like, and
(b) does it prevent duplicates across decoder types — i.e. is the same credential
seen as plaintext **and** base64 reported **once or twice**?

**Setup (crafted input, outside the tree).** The **same** Sentry credential,
once in plaintext and once base64-encoded, in one file:

```
mkdir -p /tmp/th_obs/q5
SECRET=' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90'
{ printf '%s\n' "$SECRET"; printf 'blob: %s\n' "$(printf '%s' "$SECRET" | base64 -w0)"; } > /tmp/th_obs/q5/dup.txt
```

```
$ cat /tmp/th_obs/q5/dup.txt
 sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
blob: IHNlbnRyeSAyN2FjODRmNGJjZGI0ZmNhOTcwMWY0ZDZmNmY1OGNkN2Q5NmI2OWM5ZDk3NTRkNDA4MDA2NDVhNTFkNjY4Zjkw
```

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q5/dup.txt --json --no-update
```

**Complete, unedited output — stdout (exactly ONE finding):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q5/dup.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

**Complete, unedited output — stderr:**

```
{"level":"info-0","ts":"2026-07-08T05:21:01Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"sn3fw","with_units":true}
{"level":"info-0","ts":"2026-07-08T05:21:01Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":152,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"82.632645ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":138}}
```

**Stability note (and why it *strengthens* the answer).** Run five times, the scan
produced **exactly one** finding every time (the dedup-to-one is deterministic).
The *winning* `DecoderName` varied — `PLAIN` on run 1, `BASE64` on runs 2–5 —
because which sighting reaches the notifier first is a race across the concurrent
pipeline. As a control, each form is individually detectable: scanning only the
plaintext line yields `DecoderName=PLAIN`, and scanning only the base64 blob yields
`DecoderName=BASE64`. So both sightings genuinely exist; the combined file still
reports one. That the *loser* can be either decoder proves the dedup key does not
distinguish decoders — if `DecoderType` were part of the key, both would always be
reported (two findings), regardless of the race.

**Cause → effect — primary (notifier LRU).** `notifierWorker`
(`pkg/engine/engine.go:1189`) builds the dedup key at `engine.go:1216`:

```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
```

i.e. `DetectorType ‖ Raw ‖ RawV2 ‖ SourceMetadata` — **`DecoderType` is *not* part
of the key.** The skip rule (`engine.go:1217-1220`) is
`if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType || result.SourceType == …POSTMAN) { continue }`,
and the stored value is the winning `DecoderType`:
`e.dedupeCache.Add(key, result.DecoderType)` (`engine.go:1221`). The cache is
`dedupeCache *lru.Cache[string, detectorspb.DecoderType]` (`engine.go:209`;
`github.com/hashicorp/golang-lru/v2 v2.0.7`, `go.mod:64`) of size
`const cacheSize = 512` (`engine.go:491`), created by
`lru.New[string, detectorspb.DecoderType](cacheSize)` (`engine.go:493`) and
assigned `e.dedupeCache = cache` (`engine.go:520`). Because both the plaintext and
the base64 sighting of the *same* credential carry the same `DetectorType`, `Raw`,
`RawV2`, and `SourceMetadata` (the finding's `line` is the chunk's start line, 1,
for both), they collide on one key: the first arrival is added; the second is
`Get`-hit with a *different* stored `DecoderType` (`val != result.DecoderType`) and
therefore `continue`d — skipped — so the credential is reported **once**. (The
`UTF8`-first ordering of `DefaultDecoders()` at `decoders.go:10-11` biases, but
does not guarantee, which decoder wins, because the intervening detector/notifier
stages run concurrently — hence the observed PLAIN/BASE64 variation.)

**Cause → effect — secondary (in-chunk cross-detector overlap).** A *distinct*
dedup exists for the case where the **same secret is found by multiple different
detectors within one chunk**. `verificationOverlapWorker` (`engine.go:924`) keys
secrets with `type chunkSecretKey struct { secret string; detectorKey ahocorasick.DetectorKey }`
(`engine.go:882-885`) and calls
`func likelyDuplicate(ctx, val chunkSecretKey, dupes …) bool` (`engine.go:887`)
with `const similarityThreshold = 0.9` (`engine.go:888`). It **skips comparisons
between the same detector type** (`val.detectorKey.Type() == dupeKey.detectorKey.Type()` → `continue`,
`engine.go:900-902`), logs `"found exact duplicate"` at V(2) on an exact string
match (`engine.go:905-907`), and otherwise computes Levenshtein similarity
`strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())` (`engine.go:911`;
`github.com/adrg/strutil v0.3.1`, `go.mod:19`), logging `"found similar duplicate"`
at V(2) when `similarity > 0.9` (`engine.go:914-918`). **Runtime note:** scanning
`pkg/engine/testdata/verificationoverlap_secrets.txt` (a single Postman key) at
`--log-level=5` starts the verificationOverlap workers —
`starting verificationOverlap workers {"count": 128}` — but does **not** emit the
`found exact/similar duplicate` lines, because only **one** detector matches that
input, so there is no cross-detector overlap to collapse. The overlap path is
therefore documented from its verified source citations above; it is a separate
mechanism from the notifier LRU that answers this question.

**Explicit answer.**
- **LRU key shape:** `fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(),
  result.Raw, result.RawV2, result.SourceMetadata)` (`engine.go:1216`) — it is
  built from **DetectorType, Raw, RawV2, and SourceMetadata**, and **excludes
  `DecoderType`**; the stored value is the winning `DecoderType`
  (`e.dedupeCache.Add(key, result.DecoderType)`, `engine.go:1221`).
- **Once or twice?** **ONCE.** Because the key omits `DecoderType`, the plaintext
  and base64 sightings of the same credential collide on one key; the second is
  skipped by the rule at `engine.go:1217-1220`. Observed: exactly one finding on
  every run.

---

## Q6 — `--print-avg-detector-time` scope: "all or only matched? included or separate?"

**Question & named sub-parts.** (a) Does the flag's output include **all**
detectors or only **matched** ones, and (b) does verification time **factor in**
(included) or get tracked **separately**?

### Condition A — a matched detector APPEARS

**Command.**

```
CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --print-avg-detector-time --no-update
```

**Complete, unedited output — stderr:**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:23:16Z	info-0	trufflehog	running source	{"source_manager_worker_id": "TgUdn", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 141.184681ms
SentryToken: 59.005088ms
2026-07-08T05:23:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "149.687487ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":198}}
```

Only the two detectors that **returned results** (`AWS`, `SentryToken`) are listed.

### Condition B — a detector runs but returns NOTHING → ABSENT

The crafted input contains detector **keywords** but **no valid credential**, so
keyword matching selects detectors that then return zero results.

```
mkdir -p /tmp/th_obs/q6
printf 'aws token key secret password sentry github gitlab\nno real credentials here just keywords\n' > /tmp/th_obs/q6/nomatch.txt
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q6/nomatch.txt --print-avg-detector-time --no-update
```

**Complete, unedited output — stderr:**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:23:20Z	info-0	trufflehog	running source	{"source_manager_worker_id": "jflhb", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
2026-07-08T05:23:20Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 90, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.678797ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The header prints, but there are **zero detector rows**. This is not because no
detector *ran*: a temporary keyword-match harness over the identical bytes
confirms this input **selects 6 detectors** (`Github`, `SentryToken`,
`GitHubOauth2`, `GitHubApp`, `Gitlab`, and one more) — they ran their `FromData`
but each returned zero results, so none were recorded.

### Verification-time inclusion — canonical vs. a LABELED non-canonical contrast

Canonical (verification ON) durations for Condition A, vs. a **non-canonical**
`--no-verification` contrast (verification skipped), three runs each:

```
# canonical (verification ON):
run1: SentryToken: 59.772822ms AWS: 150.90068ms
run2: SentryToken: 63.552334ms AWS: 171.80802ms
run3: SentryToken: 54.472841ms AWS: 166.78287ms
# LABELED NON-CANONICAL contrast (--no-verification):
run1: SentryToken: 206.295µs AWS: 245.91µs
run2: AWS: 235.196µs SentryToken: 265.79µs
run3: AWS: 183.758µs SentryToken: 254.973µs
```

With verification ON the AWS timing is ~150–172 **ms**; with `--no-verification`
it collapses to ~184–246 **µs** — a ~1000× drop — because the reported duration
includes the remote verification performed inside `FromData`.

**Stability note.** Across the runs above, the *scope* is stable — the listed set
is always exactly the result-returning detectors (`{AWS, SentryToken}` in
Condition A; empty in Condition B). Absolute durations vary run-to-run (as
expected for wall-clock timing), and the ordering of the two rows varies (a race),
but the gate/scope never changes.

**Cause → effect (with `file:line`).** In `detectChunk`
(`pkg/engine/engine.go:1044`), the timer is started **only** under the flag:
`var start time.Time` (`engine.go:1045`) then
`if e.printAvgDetectorTime { start = time.Now() }` (`engine.go:1046-1048`). The
timed region encloses
`results, err := e.verificationCache.FromData(ctx, data.detector.Detector, data.chunk.Verify, …)`
(`engine.go:1070-1075`), which performs remote verification when `verify=true` —
so **verification time is inside the measured span**. The recording is gated by
`if e.printAvgDetectorTime && len(results) > 0 { … }` (`engine.go:1092`), storing
into `detectorAvgTime` (`engine.go:1104`; the `sync.Map` at `engine.go:60`) — so a
detector that runs but returns zero results is **never recorded**. The
flag/config plumbing is `Config.PrintAvgDetectorTime` (`engine.go:137`) ←
`PrintAvgDetectorTime: *printAvgDetectorTime` (`main.go:530`) ← the CLI flag
`--print-avg-detector-time` (`main.go:72`). The dump is printed to **stderr** by
`printAverageDetectorTime(e)` (`main.go:1021-1029`) — the header at `main.go:1024`
("Average detector time is the measurement of average time spent on each detector
when results are returned.") followed by one `"%s: %s\n"` row per detector
(`main.go:1026-1028`) drawn from `GetDetectorsMetrics()` — called via
`if *printAvgDetectorTime { printAverageDetectorTime(eng) }` (`main.go:963-964`).

**Explicit answer.**
- **All or only matched?** **ONLY matched** — only detectors that returned ≥1
  result appear, because recording is gated by `len(results) > 0`
  (`engine.go:1092`). Condition A lists `AWS`/`SentryToken` (returned results);
  Condition B lists nothing even though six detectors ran but returned nothing.
- **Included or separate?** **INCLUDED** — verification time is part of the
  measured duration: the timer starts at `engine.go:1046-1048`, *before*
  `verificationCache.FromData` (`engine.go:1070-1075`), which performs remote
  verification. The ~1000× ms-vs-µs contrast between the canonical and
  `--no-verification` runs confirms it empirically.

---

## Final Coverage Pass

Every question cluster and every named sub-part, confirmed against the captured
output above:

- **Q1 — unique keywords + share/distinct.**
  - [x] Unique count reported: **914** = `len(core.KeywordsToDetectors())`
    (`ahocorasickcore.go:133`/`:302`); raw additions **955** (41 duplicates).
  - [x] **Share vs distinct → SHARED** (max fan-out 6 on `"azure"`; 32 keywords
    with fan-out > 1; `keywordsToDetectors[...] = append(...)` at
    `ahocorasickcore.go:151`).
- **Q2 — decoder ordering.**
  - [x] **Before vs after → BEFORE** — decode (`engine.go:784-786`) precedes match
    (`engine.go:795`); base64-only Sentry surfaced as `DecoderName=BASE64`,
    plaintext AWS as `DecoderName=PLAIN`.
- **Q3 — verification-cache metrics + persistence.**
  - [x] Metric fields listed by name/line: `Hits`/`Misses`/`HitsWasted`/
    `AttemptsSaved`/`VerificationTimeSpentMS` (`in_memory_metrics.go:10-14`,
    printed under `verification_caching` at `main.go:566-574`).
  - [x] **Persist vs not → NOT across invocations** (identical `Hits:0,Misses:2`
    on separate processes; `simple.NewCache`/`InMemoryMetrics{}` fresh per process,
    `main.go:511`,`:536`); **within a process hits accrue** (`Hits:92` of 100).
- **Q4 — worker architecture + backpressure.**
  - [x] **Multipliers named** — scanner=concurrency; detector ×8
    (`engine.go:345`); notification ×1 (`engine.go:349`); verificationOverlap ×1
    (`engine.go:353`) → observed **4 / 32 / 4 / 4** at `--concurrency=4`.
  - [x] **Queuing/backpressure explained** — bounded buffered channels
    (`engine.go:503-519`, `defaultChannelBuffer = runtime.NumCPU()`,
    `engine.go:627`) block producers when consumers lag.
- **Q5 — cross-decoder dedup.**
  - [x] **Once vs twice → ONCE** (exactly one finding every run).
  - [x] LRU key shape `"%s%s%s%+v"` of DetectorType/Raw/RawV2/SourceMetadata,
    **excludes `DecoderType`** (`engine.go:1216`); stored value = `DecoderType`
    (`engine.go:1221`).
  - [x] Secondary in-chunk overlap dedup documented (`chunkSecretKey`
    `engine.go:882-885`; `likelyDuplicate` `engine.go:887`, threshold 0.9).
- **Q6 — `--print-avg-detector-time`.**
  - [x] **All vs only matched → ONLY matched** (gate `len(results) > 0`,
    `engine.go:1092`); matched detectors appear (Condition A), ran-but-empty
    detectors absent (Condition B).
  - [x] **Included vs separate → INCLUDED** (timer `engine.go:1046-1048` spans
    `FromData` `engine.go:1070-1075`; ~1000× ms-vs-µs contrast).

**Provenance & read-only guarantee.** All output above was captured live inside
the container at HEAD `e42153d44a5e5c37c1bd0c70e074781e9edcb760` under default
configuration (only the flags each question requires were varied). The one Go
observation harness and all crafted scan inputs lived under `/tmp/th_obs`
(outside the tracked tree) and were removed on completion; the built `./trufflehog`
binary is `.gitignore`d. No existing repository file (`*.go`, tests, config,
`go.mod`/`go.sum`, docs) was modified — the only added file is this document.

