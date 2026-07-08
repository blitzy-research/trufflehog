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

**Complete, unedited output — Run 3:**

```
default_detectors=831
total_keyword_additions=955
unique_keywords=914
shared_keywords_fanout_gt1=32
max_fanout=6 for keyword="azure"
```

**Stability note.** The harness was run three times (all three complete outputs are
shown above); every run produced byte-identical numbers (the default detector set is
deterministic), so the unique count is reported as a stable value.

**Cause → effect (with `file:line`).** The default detector set the harness feeds
in is the software's own: `defaults.DefaultDetectors()`
(`pkg/engine/defaults/defaults.go:1704`), which returns the list assembled by
`buildDetectorList()` (`pkg/engine/defaults/defaults.go:839-1702`) — the canonical
enumeration of every default detector (the 831 counted above). That slice is passed
to `ahocorasick.NewAhoCorasickCore(allDetectors)`
(`pkg/engine/ahocorasick/ahocorasickcore.go:141`), which
loops over every detector (`for _, d := range allDetectors` at
`pkg/engine/ahocorasick/ahocorasickcore.go:145`) and, for each keyword, lowercases it
(`kwLower := strings.ToLower(kw)` at `pkg/engine/ahocorasick/ahocorasickcore.go:149`),
**appends it once to the raw `keywords` slice**
(`keywords = append(keywords, kwLower)` at
`pkg/engine/ahocorasick/ahocorasickcore.go:150` — one append per
`(detector, keyword)` pair, so duplicates are possible), and records the mapping
`keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)`
(`pkg/engine/ahocorasick/ahocorasickcore.go:151`). The field is
`keywordsToDetectors map[string][]DetectorKey`
(`pkg/engine/ahocorasick/ahocorasickcore.go:133`), and the
trie is built from the raw slice via
`*ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()`
(`pkg/engine/ahocorasick/ahocorasickcore.go:159`). Because `AddStrings` (from
`github.com/BobuSumisu/aho-corasick v1.0.3`, `go.mod:17`) assigns each *added*
pattern its own index, the raw slice's duplicates are added repeatedly — hence the
canonical measure of *unique* keywords is `len(keywordsToDetectors)`
(`pkg/engine/ahocorasick/ahocorasickcore.go:133`), exposed by the getter
`func (ac *Core) KeywordsToDetectors()`
at `pkg/engine/ahocorasick/ahocorasickcore.go:302`. That is exactly what the harness
reads.

- The **831** default detectors contribute **955** total keyword additions (the
  raw slice), which collapse to **914** unique keys in `keywordsToDetectors` — i.e.
  `955 − 914 = 41` additions are duplicates of an already-seen keyword.
- **32** unique keywords map to **more than one** `DetectorKey`, and the maximum
  fan-out is **6** — the keyword `"azure"` alone selects six distinct detectors.

**Explicit answer.**
- **Unique keyword count:** **914** (`len(core.KeywordsToDetectors())` — the
  `keywordsToDetectors` field at `pkg/engine/ahocorasick/ahocorasickcore.go:133`,
  read through the getter at `pkg/engine/ahocorasick/ahocorasickcore.go:302`). (Total
  additions to the raw `keywords` slice: **955**; the difference of 41 reflects
  duplicate `(detector,keyword)` appends at
  `pkg/engine/ahocorasick/ahocorasickcore.go:150`.)
- **Shared or distinct?** **SHARED.** A single lowercased keyword maps to multiple
  `DetectorKey`s in `keywordsToDetectors`
  (`pkg/engine/ahocorasick/ahocorasickcore.go:151`): 32 keywords
  have fan-out `> 1`, and `"azure"` reaches a fan-out of 6. Keywords are therefore
  shared across detectors, not maintained distinctly per detector.

---

## Q2 — Decoder ordering relative to keyword matching: "before or after?"

**Question & named sub-parts.** Does the decoder pipeline process encoded content
(e.g., base64) **before** or **after** keyword matching, and what does the
sequence look like for a chunk containing **both** a plaintext and an encoded
secret?

**Setup (one crafted file -> one chunk, outside the tree).** Per the question's exact
condition, a **single** file holds **both** secrets so they land in **one chunk**: an
AWS key-pair in **plaintext** (lines 1-2) and a *different* secret (a Sentry token)
present **only in base64** form (line 3), so the Sentry keyword can only be matched
*after* decoding.

```
mkdir -p /tmp/th_obs/q2
B64=$(printf ' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90\n' | base64 -w0)
{ printf 'aws_key = AKIAWARWQKZNHMZBLY4I\n'; \
  printf 'aws_secret = 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\n'; \
  printf 'blob: %s\n' "$B64"; } > /tmp/th_obs/q2/both.txt
```

The one crafted file (all three lines in a single file => a single chunk):

```
$ cat -n /tmp/th_obs/q2/both.txt
     1	aws_key = AKIAWARWQKZNHMZBLY4I
     2	aws_secret = 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
     3	blob: IHNlbnRyeSAyN2FjODRmNGJjZGI0ZmNhOTcwMWY0ZDZmNmY1OGNkN2Q5NmI2OWM5ZDk3NTRkNDA4MDA2NDVhNTFkNjY4ZjkwCg==

$ grep -c 'sentry\|27ac' /tmp/th_obs/q2/both.txt
0
```

The `grep -c` returning **0** confirms the base64 blob contains no plaintext
`sentry`/`27ac` keyword — the Sentry keyword only exists *after* the blob is
base64-decoded.

> **Note — no per-decoder log lines exist (at any verbosity).** TruffleHog does
> **not** log the per-decoder step. In `scannerWorker` the decode loop records only a
> Prometheus metric —
> `decodeLatency.WithLabelValues(decoder.Type().String(), ...).Observe(...)`
> (`pkg/engine/engine.go:788`) — and the *only* logger call in the whole worker is
> `ctx.Logger().V(4).Info("finished scanning chunks")` (`pkg/engine/engine.go:840`).
> Decode-before-match is therefore proven from (a) the source ordering (below) and
> (b) the runtime `DecoderName` field on each finding from the single chunk.

### Run A — the single-chunk scan (primary evidence)

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q2/both.txt --json --no-update
```

**Complete, unedited output — stdout (findings):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

**Complete, unedited output — stderr:**

```
{"level":"info-0","ts":"2026-07-08T06:13:55Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"wgE9s","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:13:55Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":165,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"157.630549ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":356}}
```

`chunks:1` confirms the single file was scanned as **one chunk** containing both
secrets. The **SentryToken** finding carries `"DecoderName":"BASE64"` — decisive,
because its keyword is absent from the raw bytes (`grep = 0`): it could only be
matched **after** the Base64 decoder ran. (`Misses:3` is explained under Run C.)

### Run B — same command again (stability + the PLAIN decoder value)

Re-running the identical command shows **SentryToken is always `BASE64`** while the
plaintext **AWS** secret surfaces here with `"DecoderName":"PLAIN"` (it races between
`PLAIN` and `BASE64`; see the cause->effect below).

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q2/both.txt --json --no-update
```

**Complete, unedited output — stdout (findings):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

**Complete, unedited output — stderr:**

```
{"level":"info-0","ts":"2026-07-08T06:14:53Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"bzy8o","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:14:53Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":165,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"148.234034ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":353}}
```

### Run C — requested verbosity (`--log-level=5`), concurrency pinned to 1

The same single-chunk scan at `--log-level=5` (trace) with `--concurrency=1` (one
scanner worker -> minimal noise), to show the requested verbose sequence:

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q2/both.txt --json --log-level=5 --concurrency=1 --no-update
```

**Complete, unedited output — stdout (findings):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q2/both.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

**Complete, unedited output — stderr (19 lines):**

```
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"default engine options set"}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"engine initialized"}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"setting up aho-corasick core"}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"set up aho-corasick core"}
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"starting scanner workers","count":1}
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"starting detector workers","count":8}
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":1}
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"starting notifier workers","count":1}
{"level":"info-0","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"SalHE","with_units":true}
{"level":"info-2","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"enumerating source","source_manager_worker_id":"SalHE"}
{"level":"info-3","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"chunking unit","source_manager_worker_id":"SalHE","unit_kind":"unit","unit":"/tmp/th_obs/q2/both.txt"}
{"level":"info-3","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"scanning file","source_manager_worker_id":"SalHE","unit_kind":"unit","unit":"/tmp/th_obs/q2/both.txt","path":"/tmp/th_obs/q2/both.txt"}
{"level":"info-5","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"dataErrChan closed, all chunks processed","source_manager_worker_id":"SalHE","unit_kind":"unit","unit":"/tmp/th_obs/q2/both.txt","path":"/tmp/th_obs/q2/both.txt","mime":"text/plain; charset=utf-8","timeout":60}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"finished scanning chunks","scanner_worker_id":"fXI3F"}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"link is empty, skipping update","detector_worker_id":"3egxn","detector":{"type":"SentryToken","version":1},"timeout":10}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"link is empty, skipping update","detector_worker_id":"121im","detector":{"type":"AWS"},"timeout":10}
{"level":"info-4","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"link is empty, skipping update","detector_worker_id":"ZK2Vj","detector":{"type":"AWS"},"timeout":10}
{"level":"info-0","ts":"2026-07-08T06:14:10Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":165,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"160.116485ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":418}}
```

There is **no** per-decoder/decode/match log line anywhere in the trace (consistent
with the note above). What the trace *does* reveal is the worker pipeline and —
crucially — **three** `"link is empty, skipping update"` lines: one for `SentryToken`
and **two** for `AWS`. Those are the three post-decode verification attempts (matching
`Misses:3`): the AWS key was keyword-matched under **both** the PLAIN pass *and* the
BASE64 pass, because the Base64 decoder leaves the intact plaintext AWS key in its
output (see cause->effect). The notifier LRU then collapses the two AWS sightings into
one finding (forward reference: Q5), whose `DecoderName` is whichever sighting won the
race.

**Cause -> effect (with `file:line`).** `scannerWorker`
(`pkg/engine/engine.go:777`) iterates decoders **first** —
`for _, decoder := range e.decoders` (`pkg/engine/engine.go:784`) ->
`decoded := decoder.FromChunk(chunk)` (`pkg/engine/engine.go:786`) — and only *then*
runs keyword matching on the **decoded** bytes:
`matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)`
(`pkg/engine/engine.go:795`). This decode-then-match sequence repeats **once per
decoder**, in the order returned by `DefaultDecoders()`
(`pkg/decoders/decoders.go:8-16` -> `{UTF8, Base64, UTF16, EscapedUnicode}`, with the
comment `// UTF8 must be first for duplicate detection` at
`pkg/decoders/decoders.go:10`). The decisive runtime proof: the Sentry token was
discovered as `DecoderName=BASE64` even though its keyword did not exist in the raw
chunk (`grep = 0`) — it appeared only after `(*Base64).FromChunk`
(`pkg/decoders/base64.go:34`) decoded the blob, at which point `FindDetectorMatches`
(`pkg/engine/engine.go:795`) saw the decoded `sentry ...` bytes and selected the
Sentry detector.

Why AWS appears under **both** decoders (so its `DecoderName` races): the Base64
decoder only *extracts* substrings of **more than 20** (i.e. >=21) consecutive base64
characters — the extraction gate is `count > threshold` with `threshold = 20`
(`pkg/decoders/base64.go:97`, `:103`, `:118`, `:125`), applied to the run counted from
the `getSubstringsOfCharacterSet(chunk.Data, 20, ...)` call at `pkg/decoders/base64.go:36`
— and, among the extracted substrings, *substitutes* only those whose decoded bytes are
ASCII (`isASCII(dec)` gate at `pkg/decoders/base64.go:41`). The long Sentry blob is
extracted and decodes to ASCII (`sentry ...`), so it is substituted in; the 40-char AWS
secret `s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0` is extracted (40 > 20) but decodes to
non-ASCII, so the `isASCII` gate rejects it and it is left intact. The 20-char AWS key
`AKIAWARWQKZNHMZBLY4I` is a run of exactly 20 base64 characters, which does **not**
exceed the `>20` threshold, so it is never extracted and passes through the Base64
decoder unchanged (the operative gate for the key is the length threshold, not
`isASCII`).
Consequently the AWS key is keyword-matched under **both** the PLAIN pass and the
BASE64 pass — hence the two `"link is empty"` AWS lines and `Misses:3` in Run C — and
the notifier LRU dedupe (`pkg/engine/engine.go:1216`, key excludes `DecoderType`)
reports it once, the winning decoder decided by the concurrent race (`PLAIN` in Run B,
`BASE64` in Runs A/C). The four-stage flow is corroborated by `docs/process_flow.md`
(Source Decomposition -> Chunk to Detector Matching -> Secret Detection -> Result
Notification).

**Explicit answer.**
- **Before or after?** **BEFORE.** Decoding happens *before* keyword matching: the
  decoder loop at `pkg/engine/engine.go:784-786` runs, and `FindDetectorMatches` at
  `pkg/engine/engine.go:795` operates on the already-decoded bytes. In the single
  chunk containing both secrets, the base64-only Sentry token is reported with
  `DecoderName=BASE64` (its keyword absent from the raw bytes), and the plaintext AWS
  key is reported with `DecoderName=PLAIN` (Run B).
- **What does the verbose sequence look like?** There are **no** per-decoder log
  lines (decode timing is a Prometheus metric, `pkg/engine/engine.go:788`, not a log);
  the `--log-level=5` trace (Run C) shows the worker pipeline plus the three
  post-decode verification attempts, and the `DecoderName` field on each finding is
  the authoritative runtime record of which decoder produced it.

---

## Q3 — Verification-cache metrics and cross-invocation persistence: "persist or not?"

**Question & named sub-parts.** (a) What metrics does the verification cache
report at end of scan; (b) do hit/miss numbers change when the **same** scan runs
twice consecutively — or does the cache **not persist** across invocations?

**The reported metric fields.** The end-of-scan snapshot is the anonymous struct
literal `verificationCacheMetricsSnapshot` (`main.go:551-563`), whose five fields
are loaded from the `verificationcache.InMemoryMetrics` value constructed at
`main.go:511` (fields at `pkg/verificationcache/in_memory_metrics.go:9-14`), and it
is printed by `logger.Info("finished scanning", … "verification_caching", verificationCacheMetricsSnapshot)`
(`main.go:566-574`) — i.e., the log key is **`verification_caching`**
(`main.go:573`), emitted at info level (visible at the default `--log-level=0`) on
**stderr**. The five fields (snapshot name → underlying `InMemoryMetrics` field →
meaning per `pkg/verificationcache/metrics_reporter.go`):

| Snapshot field | Underlying field | Meaning |
|---|---|---|
| `Hits` | `ResultCacheHits` (`pkg/verificationcache/in_memory_metrics.go:12`) | result-cache hits (`pkg/verificationcache/metrics_reporter.go:18`) |
| `Misses` | `ResultCacheMisses` (`pkg/verificationcache/in_memory_metrics.go:14`) | result-cache misses (`pkg/verificationcache/metrics_reporter.go:21`) |
| `HitsWasted` | `ResultCacheHitsWasted` (`pkg/verificationcache/in_memory_metrics.go:13`) | hits that did **not** elide a remote call because other findings in the chunk were uncached (`pkg/verificationcache/metrics_reporter.go:23-27`) |
| `AttemptsSaved` | `CredentialVerificationsSaved` (`pkg/verificationcache/in_memory_metrics.go:10`) | remote verifications elided by loading status from cache (`pkg/verificationcache/metrics_reporter.go:8-11`) |
| `VerificationTimeSpentMS` | `FromDataVerifyTimeSpentMS` (`pkg/verificationcache/in_memory_metrics.go:11`) | wall time in `detector.FromData` with `verify=true` (`pkg/verificationcache/metrics_reporter.go:13-14`) |

### Condition A — cross-invocation (the "run twice" sub-question)

**Command.** The identical scan of the repository's own testdata, run as **three
separate CLI processes** (stdout and stderr captured separately for each run):

```
CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --json --no-update
```

**Complete, unedited output — Run 1.** stdout (the two findings):

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

stderr (the two `info-0` log lines):

```
{"level":"info-0","ts":"2026-07-08T06:22:39Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"yfT43","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:22:39Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":372,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"154.703374ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":211}}
```

**Complete, unedited output — Run 2** (a fresh, separate process). stdout:

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:22:44Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"EWSwt","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:22:44Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":372,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"154.909504ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":209}}
```

**Complete, unedited output — Run 3** (a third separate process). stdout:

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":3}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"pkg/engine/testdata/secrets.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAWARWQKZNHMZBLY4I","RawV2":"AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0","Redacted":"AKIAWARWQKZNHMZBLY4I","ExtraData":{"account":"413504919130","resource_type":"Access key"},"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:22:48Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"CbnFc","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:22:48Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":372,"verified_secrets":0,"unverified_secrets":2,"scan_duration":"157.431623ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":236}}
```

**Stability & interpretation.** Across all **three** separate processes the cache
counts were **identical** — `Hits:0, Misses:2, HitsWasted:0, AttemptsSaved:0` — and
only `VerificationTimeSpentMS` varied as wall-clock (211 / 209 / 236 ms). If the
cache persisted across invocations, Run 2 and Run 3 would have reported `Hits:2,
Misses:0` (the two credentials cached by Run 1); instead **every process starts
cold with `Misses:2`**, so there is **no cross-invocation persistence**.

### Condition B — within-process hit accrual (the contrasting/edge branch)

`secrets.txt` is a single chunk, so its four identical Sentry lines cannot produce
cross-chunk hits (they collapse within the one chunk → `Hits:0`, as Condition A
shows). To exercise the **within-process** hit path, scan a directory of **20
files**, each containing the **same** Sentry credential (so each file is a separate
chunk), and pin `--concurrency=1`:

```
mkdir -p /tmp/th_obs/q3/many20
for i in $(seq 1 20); do
  printf ' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90\n' > /tmp/th_obs/q3/many20/file$i.txt
done
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q3/many20 --concurrency=1 --json --no-update
```

**Complete, unedited output — Run 1.** stdout (20 findings, one per file):

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file15.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file17.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file18.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file19.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file2.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file20.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file3.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file4.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file5.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file6.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file7.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file8.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file9.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file14.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file16.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file13.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file12.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file11.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file10.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:27:14Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"V7tKP","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:27:14Z","logger":"trufflehog","msg":"finished scanning","chunks":20,"bytes":1460,"verified_secrets":0,"unverified_secrets":20,"scan_duration":"75.939188ms","trufflehog_version":"dev","verification_caching":{"Hits":12,"Misses":8,"HitsWasted":0,"AttemptsSaved":12,"VerificationTimeSpentMS":488}}
```

**Complete, unedited output — Run 2** (a fresh, separate process). stdout:

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file13.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file17.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file18.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file19.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file2.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file20.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file3.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file4.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file5.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file6.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file7.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file8.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file9.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":true,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file16.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file12.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file14.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file11.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file15.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q3/many20/file10.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:27:19Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"zq34k","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:27:19Z","logger":"trufflehog","msg":"finished scanning","chunks":20,"bytes":1460,"verified_secrets":0,"unverified_secrets":20,"scan_duration":"76.777955ms","trufflehog_version":"dev","verification_caching":{"Hits":12,"Misses":8,"HitsWasted":0,"AttemptsSaved":12,"VerificationTimeSpentMS":486}}
```

**Stability & cross-check.** Both processes reported **identical** cache counts —
`Hits:12, Misses:8, HitsWasted:0, AttemptsSaved:12` (only `VerificationTimeSpentMS`
varied: 488 / 486 ms). Two independent facts inside the same output corroborate one
another: (1) the **aggregate** stderr snapshot says 12 hits / 8 misses; and (2) the
**per-finding** `VerificationFromCache` field on stdout is `true` for exactly
**12** findings and `false` for exactly **8** in each run (the field is set on a hit
at `pkg/verificationcache/verification_cache.go:92`). The two runs emit the **same
20 findings**, proven identical modulo concurrent emission order:

```
$ diff <(sort wp1.out) <(sort wp2.out) && echo "IDENTICAL (same 20 findings, modulo emission order)"
IDENTICAL (same 20 findings, modulo emission order)
```

**Why `Misses:8` (not 1) even at `--concurrency=1`.** `--concurrency` sizes the
scanner pool, but detector workers are `concurrency × detectorWorkerMultiplier`
with `detectorWorkerMultiplier = 8` (`pkg/engine/engine.go:345`) and **no CLI flag
overrides it**, so at `--concurrency=1` there are still **8 detector workers**
(exactly the count Q4 observes). All 8 pull a chunk and reach the cache lookup
before the first remote verification completes and writes its key, so the first 8
chunks **miss**; the remaining 12 arrive after the key is stored and **hit**. The
miss count therefore tracks the detector-worker pool size (8) rather than the file
count — exactly what the 20-file run above shows (`Misses:8`, `Hits:12`).

**Cause → effect (with `file:line`).** The result cache is created **per process**
and only when caching is enabled (the default):
`if !*noVerificationCache { engConf.VerificationResultCache = simple.NewCache[detectors.Result]() }`
(`main.go:535-536`), and the metrics reporter is a fresh
`verificationcache.InMemoryMetrics{}` per process (`main.go:511`), wired via
`VerificationCacheMetrics` (`main.go:532`). The store is an in-memory
`patrickmn/go-cache` (`go.mod:80`) wrapped by `simple.Cache[T]`
(`pkg/cache/simple/simple.go:16-21`) — nothing writes it to disk, so a new process
begins with an empty cache. Inside `VerificationCache.FromData`
(`pkg/verificationcache/verification_cache.go:50`), each candidate result's cache
key is looked up (`v.resultCache.Get(...)` at
`pkg/verificationcache/verification_cache.go:90`): a hit records
`AddResultCacheHits(1)` (`pkg/verificationcache/verification_cache.go:93`) and sets
`VerificationFromCache = true` (`pkg/verificationcache/verification_cache.go:92`); a
miss records `AddResultCacheMisses(1)`
(`pkg/verificationcache/verification_cache.go:96`); when every result in a chunk is
cached it records `AddCredentialVerificationsSaved(len(...))`
(`pkg/verificationcache/verification_cache.go:104`); otherwise it performs remote
verification and **stores** each result (`v.resultCache.Set(...)` at
`pkg/verificationcache/verification_cache.go:130`). The cache key itself,
`getResultCacheKey` (`pkg/verificationcache/verification_cache.go:136-147`), is a
Blake2B hash (`hasher.NewBlake2B()` set in `New()` at
`pkg/verificationcache/verification_cache.go:35`; `golang.org/x/crypto`
`go.mod:107`) over `result.Raw ‖ result.RawV2`
(`pkg/verificationcache/verification_cache.go:140`) plus `result.DetectorType`
(`binary.Append(..., result.DetectorType)` at
`pkg/verificationcache/verification_cache.go:141`) — which is why 20 copies of the
same credential share one key and hits accrue within the process.

**Explicit answer.**
- **Reported metric fields (by name, with source line):** `Hits`
  (`ResultCacheHits`, `pkg/verificationcache/in_memory_metrics.go:12`), `Misses`
  (`ResultCacheMisses`, `pkg/verificationcache/in_memory_metrics.go:14`),
  `HitsWasted` (`ResultCacheHitsWasted`,
  `pkg/verificationcache/in_memory_metrics.go:13`), `AttemptsSaved`
  (`CredentialVerificationsSaved`, `pkg/verificationcache/in_memory_metrics.go:10`),
  and `VerificationTimeSpentMS` (`FromDataVerifyTimeSpentMS`,
  `pkg/verificationcache/in_memory_metrics.go:11`) — printed under the
  `verification_caching` key (`main.go:573`).
- **Persist or not?** **NOT persisted across separate CLI invocations.** The result
  cache (`simple.NewCache`, `main.go:536`) and metrics (`InMemoryMetrics{}`,
  `main.go:511`) are constructed fresh per process and held only in memory, so the
  three separate runs of the identical scan produced identical snapshots (`Misses:2`
  never became `Hits:2`). **Within** a single process, hits **do** accrue (12 of the
  20 chunks in Condition B).

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

**Output format & method.** Run **without** `--json`, so findings print (console
format) to **stdout** while the worker-startup logs print to **stderr**; the scan is
repeated as **three separate processes** to show the counts are stable.

**Run 1 — stdout (the two findings):**

```
Found unverified result 🐷🔑❓
Detector Type: SentryToken
Decoder Type: PLAIN
Raw result: 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
File: pkg/engine/testdata/secrets.txt
Line: 3

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWARWQKZNHMZBLY4I
Resource_type: Access key
Account: 413504919130
File: pkg/engine/testdata/secrets.txt
Line: 1
```

**Run 1 — stderr (banner, the four `info-2` worker-startup lines, and the
end-of-scan snapshot):**

```
2026-07-08T06:40:06Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:40:06Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-08T06:40:06Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-08T06:40:06Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-08T06:40:06Z	info-2	trufflehog	starting notifier workers	{"count": 4}
2026-07-08T06:40:06Z	info-0	trufflehog	running source	{"source_manager_worker_id": "6Cswo", "with_units": true}
2026-07-08T06:40:06Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "6Cswo"}
2026-07-08T06:40:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "159.845726ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":249}}
```

**Run 2 — stdout:**

```
Found unverified result 🐷🔑❓
Detector Type: SentryToken
Decoder Type: PLAIN
Raw result: 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
File: pkg/engine/testdata/secrets.txt
Line: 3

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWARWQKZNHMZBLY4I
Resource_type: Access key
Account: 413504919130
File: pkg/engine/testdata/secrets.txt
Line: 1
```

**Run 2 — stderr:**

```
2026-07-08T06:40:10Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:40:10Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-08T06:40:10Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-08T06:40:10Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-08T06:40:10Z	info-2	trufflehog	starting notifier workers	{"count": 4}
2026-07-08T06:40:10Z	info-0	trufflehog	running source	{"source_manager_worker_id": "s58Xg", "with_units": true}
2026-07-08T06:40:10Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "s58Xg"}
2026-07-08T06:40:10Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "158.114691ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":226}}
```

**Run 3 — stdout:**

```
Found unverified result 🐷🔑❓
Detector Type: SentryToken
Decoder Type: PLAIN
Raw result: 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
File: pkg/engine/testdata/secrets.txt
Line: 3

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWARWQKZNHMZBLY4I
Resource_type: Access key
Account: 413504919130
File: pkg/engine/testdata/secrets.txt
Line: 1
```

**Run 3 — stderr:**

```
2026-07-08T06:40:14Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:40:14Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-08T06:40:14Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-08T06:40:14Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-08T06:40:14Z	info-2	trufflehog	starting notifier workers	{"count": 4}
2026-07-08T06:40:14Z	info-0	trufflehog	running source	{"source_manager_worker_id": "34xCZ", "with_units": true}
2026-07-08T06:40:14Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "34xCZ"}
2026-07-08T06:40:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "138.916497ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":205}}
```

**Stability.** Across all three separate processes the four worker counts were
**identical** — **scanner=4, detector=32, verificationOverlap=4, notifier=4**
(i.e. **4 / 32 / 4 / 4**); only the timestamps, `source_manager_worker_id`,
`scan_duration`, and `VerificationTimeSpentMS` (249 / 226 / 205 ms) varied. The two
findings on stdout were byte-identical across the runs (modulo concurrent emission
order). Extracting just the counts from each run's stderr:

```
$ for r in 1 2 3; do echo "run $r:"; grep -oE "starting (scanner|detector|verificationOverlap|notifier) workers.*count.: [0-9]+" q4/run$r.err \
    | sed -E "s/.*starting (\w+) workers.*: ([0-9]+)/  \1=\2/"; done
run 1:
  scanner=4
  detector=32
  verificationOverlap=4
  notifier=4
run 2:
  scanner=4
  detector=32
  verificationOverlap=4
  notifier=4
run 3:
  scanner=4
  detector=32
  verificationOverlap=4
  notifier=4
```

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
and `results` (capacity `128 × 50 = 6400`). Because a send on a full Go channel
blocks until a receiver drains an item, the pipeline's throughput is gated by its
slowest stage: when the detector workers are all busy with real remote
verification, the scanner's sends into `detectableChunksChan` stall until a
detector frees a slot. (Backpressure here is reasoned from the channel sizing in
source, `engine.go:503-519`/`engine.go:627`, together with Go's blocking-send
semantics; it is not a numeric value printed by the CLI.)

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

**Setup (crafted inputs, outside the tree).** The **same** Sentry credential in
three files — combined (plaintext + base64 in one file), plaintext-only, and
base64-only:

```
mkdir -p /tmp/th_obs/q5
SECRET=' sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90'
# combined: plaintext line + base64-blob line (one file)
{ printf '%s\n' "$SECRET"; printf 'blob: %s\n' "$(printf '%s' "$SECRET" | base64 -w0)"; } > /tmp/th_obs/q5/dup.txt
# controls
printf '%s\n' "$SECRET" > /tmp/th_obs/q5/plain.txt
printf 'blob: %s\n' "$(printf '%s' "$SECRET" | base64 -w0)" > /tmp/th_obs/q5/b64.txt
```

```
$ cat -n /tmp/th_obs/q5/dup.txt
     1	 sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
     2	blob: IHNlbnRyeSAyN2FjODRmNGJjZGI0ZmNhOTcwMWY0ZDZmNmY1OGNkN2Q5NmI2OWM5ZDk3NTRkNDA4MDA2NDVhNTFkNjY4Zjkw
```

### Combined file — reported ONCE (the primary question)

**Command.**

```
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q5/dup.txt --json --no-update
```

Which decoder's sighting reaches the notifier first is a race, so the *winning*
`DecoderName` varies run to run; both outcomes are shown below, and **each is
exactly one finding**.

**Representative run — PLAIN wins. Complete stdout (one finding):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q5/dup.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:48:21Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"rCPkB","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:48:21Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":152,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"75.100122ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":123}}
```

**Representative run — BASE64 wins. Complete stdout (one finding):**

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q5/dup.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

stderr:

```
{"level":"info-0","ts":"2026-07-08T06:48:26Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"m3UFc","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:48:26Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":152,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"70.16019ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":117}}
```

Both stderr snapshots show `unverified_secrets:1` (one credential **reported**)
while `verification_caching` shows `Misses:2` — i.e. **both** the plaintext and the
base64 sighting traversed the pipeline (two verification-cache lookups), yet the
notifier collapsed them to a single report.

**Distribution across 25 separate runs (magnitude/stability).** The finding count is
invariant (always `1`) while the winning decoder splits between the two — which is
only possible if the dedup key does **not** distinguish decoders:

```
$ findings=(); plain=0; base64=0; for r in $(seq 1 25); do
    out=$(CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q5/dup.txt --json --no-update 2>/dev/null)
    n=$(printf "%s\n" "$out" | grep -c "\"DetectorName\"")
    dec=$(printf "%s\n" "$out" | grep -o "\"DecoderName\":\"[A-Z0-9]*\"")
    findings+=("$n"); case "$dec" in *PLAIN*) plain=$((plain+1));; *BASE64*) base64=$((base64+1));; esac
  done
  echo "distinct finding-counts: $(printf "%s\n" "${findings[@]}" | sort -u | tr "\n" " ")"
  echo "winner tally over 25 runs: PLAIN=$plain BASE64=$base64"
distinct finding-counts: 1 
winner tally over 25 runs: PLAIN=11 BASE64=14
```

### Controls — each form is individually detectable

To show both sightings genuinely exist (so the combined "once" is real
deduplication, not a missed detection), scan each form alone.

**Plaintext-only** — `CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q5/plain.txt --json --no-update`

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q5/plain.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

```
{"level":"info-0","ts":"2026-07-08T06:48:31Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"LMGjU","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:48:31Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":73,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"64.945227ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":59}}
```

**Base64-only** — `CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q5/b64.txt --json --no-update`

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/th_obs/q5/b64.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":87,"DetectorName":"SentryToken","DetectorDescription":"Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry tokens can be used to access and manage projects and organizations within Sentry.","DecoderName":"BASE64","Verified":false,"VerificationFromCache":false,"Raw":"27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}
```

```
{"level":"info-0","ts":"2026-07-08T06:48:35Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"1e5Ij","with_units":true}
{"level":"info-0","ts":"2026-07-08T06:48:35Z","logger":"trufflehog","msg":"finished scanning","chunks":1,"bytes":79,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"82.293898ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":59}}
```

Plaintext-only reports `DecoderName:"PLAIN"` and base64-only reports
`DecoderName:"BASE64"` — one finding each — so the combined file's single report is
genuine cross-decoder deduplication, not a missed sighting.

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
dedup exists for when the **same secret is found by multiple different detectors
within one chunk**. `verificationOverlapWorker` (`pkg/engine/engine.go:924`) keys
secrets with `type chunkSecretKey struct { secret string; detectorKey ahocorasick.DetectorKey }`
(`pkg/engine/engine.go:882-885`) and calls
`func likelyDuplicate(ctx, val chunkSecretKey, dupes ...) bool`
(`pkg/engine/engine.go:887`) with `const similarityThreshold = 0.9`
(`pkg/engine/engine.go:888`). It **skips comparisons between the same detector
type** (`val.detectorKey.Type() == dupeKey.detectorKey.Type()` → `continue`,
`pkg/engine/engine.go:900-902`), logs `"found exact duplicate"` at V(2) on an exact
string match (`pkg/engine/engine.go:905-907`), and otherwise computes Levenshtein
similarity `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())`
(`pkg/engine/engine.go:911`; `github.com/adrg/strutil v0.3.1`, `go.mod:19`), logging
`"found similar duplicate"` at V(2) when `similarity > 0.9`
(`pkg/engine/engine.go:914-918`).

**Runtime evidence (workers start; collapse branch not reached with one detector).**
The repo's `pkg/engine/testdata/verificationoverlap_secrets.txt` holds a single
Postman key, so only **one** detector matches it — there is no cross-detector
overlap to collapse. Run at V(2), the level where both the worker-startup lines and
the `found exact/similar duplicate` lines are emitted:

```
CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/verificationoverlap_secrets.txt --concurrency=4 --log-level=2 --no-update
```

Complete stdout (the single Postman finding):

```
Found unverified result 🐷🔑❓
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: pkg/engine/testdata/verificationoverlap_secrets.txt
Line: 2
```

Complete stderr — the verificationOverlap workers **do** start (`count: 4`) but
**no** `found exact/similar duplicate` line appears, because a lone detector cannot
overlap with itself (the same-type comparison is skipped at
`pkg/engine/engine.go:900-902`):

```
2026-07-08T06:51:41Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:51:41Z	info-2	trufflehog	starting scanner workers	{"count": 4}
2026-07-08T06:51:41Z	info-2	trufflehog	starting detector workers	{"count": 32}
2026-07-08T06:51:41Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 4}
2026-07-08T06:51:41Z	info-2	trufflehog	starting notifier workers	{"count": 4}
2026-07-08T06:51:41Z	info-0	trufflehog	running source	{"source_manager_worker_id": "PRlQx", "with_units": true}
2026-07-08T06:51:41Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "PRlQx"}
2026-07-08T06:51:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 84, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "178.398072ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":176}}
```

Confirming the absence programmatically:

```
$ grep -c "found exact duplicate\|found similar duplicate" overlap2.err
0
```

So the overlap-collapse branch is verified from source (above) and its worker pool
is observed starting at runtime; *triggering the collapse itself* requires an input
where two **different** detectors extract the same/similar secret from one chunk
(the source's own example: a Postman key `PMAK-…` and a generic "api key" detector
over the identical inner value), which the default detector set does not produce for
this test input. This secondary mechanism is separate from the notifier LRU that
answers the headline question.

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

**Complete, unedited output — stdout (the two findings):**

```
Found unverified result 🐷🔑❓
Detector Type: SentryToken
Decoder Type: PLAIN
Raw result: 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
File: pkg/engine/testdata/secrets.txt
Line: 3

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWARWQKZNHMZBLY4I
Resource_type: Access key
Account: 413504919130
File: pkg/engine/testdata/secrets.txt
Line: 1
```

**Complete, unedited output — stderr (banner, `running source`, the
`--print-avg-detector-time` dump, then the end-of-scan snapshot):**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:58:14Z	info-0	trufflehog	running source	{"source_manager_worker_id": "eKwGw", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 131.657724ms
SentryToken: 68.146928ms
2026-07-08T06:58:14Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "137.091936ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":198}}
```

Only the two detectors that **returned results** — `AWS` and `SentryToken` —
appear in the dump.

### Condition B — a detector runs but returns NOTHING → ABSENT

The crafted input holds detector **keywords** but **no valid credential**, so
keyword matching *selects* detectors that then return zero results:

```
mkdir -p /tmp/th_obs/q6
printf 'aws token key secret password sentry github gitlab\nno real credentials here just keywords\n' > /tmp/th_obs/q6/nomatch.txt
CGO_ENABLED=0 go run . filesystem /tmp/th_obs/q6/nomatch.txt --print-avg-detector-time --no-update
```

**Complete, unedited output — stdout:** the captured stdout is **empty — zero
findings** were printed (`wc -c` on the redirected stdout returns `0`).

**Complete, unedited output — stderr (the dump header prints, but there are ZERO
detector rows):**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:58:31Z	info-0	trufflehog	running source	{"source_manager_worker_id": "hpbAL", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
2026-07-08T06:58:31Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 90, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.282458ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Proof the detectors DID run — naming every selected detector.** The missing rows
are *not* because no detector executed. A temporary harness runs the real keyword
matcher — `ahocorasick.NewAhoCorasickCore(defaults.DefaultDetectors())` then
`core.FindDetectorMatches(...)` — over the **identical** bytes and prints the
complete selected set. Harness source (`/tmp/th_obs/q6harness/main.go`; module
`thq6`, whose `go.mod` carries
`replace github.com/trufflesecurity/trufflehog/v3 => <repo root>` so it links the
real detector registry):

```go
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	core := ahocorasick.NewAhoCorasickCore(defaults.DefaultDetectors())
	matches := core.FindDetectorMatches(data)
	lines := make([]string, 0, len(matches))
	for _, m := range matches {
		lines = append(lines, fmt.Sprintf("%s\t(%T)", m.Detector.Type().String(), m.Detector))
	}
	sort.Strings(lines)
	fmt.Printf("selected_detectors=%d\n", len(matches))
	for _, l := range lines {
		fmt.Println(l)
	}
}
```

Command and **complete, unedited** output:

```
$ cd /tmp/th_obs/q6harness && GOFLAGS=-mod=mod go run . /tmp/th_obs/q6/nomatch.txt
selected_detectors=6
GitHubApp	(*githubapp.Scanner)
GitHubOauth2	(*github_oauth2.Scanner)
Github	(*github.Scanner)
Gitlab	(*gitlab.Scanner)
SentryToken	(*sentrytoken.Scanner)
SentryToken	(*sentrytoken.Scanner)
```

So **exactly six** detectors are selected: `GitHubApp`, `GitHubOauth2`, `Github`,
`Gitlab`, and `SentryToken` **twice** (two registered `*sentrytoken.Scanner`
versions share the `sentry` keyword — that pair is the "sixth"). All six ran
`FromData` over the keyword-only text, all returned zero results, and therefore
**none** was recorded by the `len(results) > 0` gate (`pkg/engine/engine.go:1092`)
— which is exactly why the Condition B dump has no rows.

### Verification-time inclusion — canonical vs. a LABELED non-canonical contrast

To prove verification time is *inside* the measured per-detector duration, compare
the canonical run (verification ON) against a **LABELED non-canonical**
`--no-verification` run — two runs each. Only stderr is shown per run (the dump
lives there); the stdout findings are identical to Condition A and, as the final
block proves, still print under `--no-verification`.

**Canonical (verification ON) — run 1.**

```
$ CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --print-avg-detector-time --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:58:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "XFONq", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 171.273541ms
SentryToken: 66.352508ms
2026-07-08T06:58:55Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "176.515922ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":236}}
```

**Canonical (verification ON) — run 2** (identical command):

```
$ CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --print-avg-detector-time --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:59:00Z	info-0	trufflehog	running source	{"source_manager_worker_id": "nodk7", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
SentryToken: 73.938748ms
AWS: 153.588931ms
2026-07-08T06:59:00Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "158.59796ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":226}}
```

**LABELED NON-CANONICAL (`--no-verification`) — run 1.**

```
$ CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --print-avg-detector-time --no-verification --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:59:04Z	info-0	trufflehog	running source	{"source_manager_worker_id": "PsVaH", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 244.4µs
SentryToken: 316.509µs
2026-07-08T06:59:04Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "7.804152ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**LABELED NON-CANONICAL (`--no-verification`) — run 2** (identical command):

```
$ CGO_ENABLED=0 go run . filesystem pkg/engine/testdata/secrets.txt --print-avg-detector-time --no-verification --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:59:09Z	info-0	trufflehog	running source	{"source_manager_worker_id": "CyZOI", "with_units": true}
Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 225.993µs
SentryToken: 327.116µs
2026-07-08T06:59:09Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 372, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "6.133697ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Findings still print under `--no-verification` (the stdout of the first
non-canonical run), confirming the detectors still executed — only the remote
verification step was skipped:

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWARWQKZNHMZBLY4I
Account: 413504919130
Resource_type: Access key
File: pkg/engine/testdata/secrets.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: SentryToken
Decoder Type: PLAIN
Raw result: 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90
File: pkg/engine/testdata/secrets.txt
Line: 3
```

**Interpretation.** With verification ON, the `AWS` duration is **131–171 ms** and
the end-of-scan snapshot reports `VerificationTimeSpentMS` of **198–236**; with
`--no-verification` the same detector collapses to **~226–244 µs** with
`VerificationTimeSpentMS:0` — roughly a **700×** drop. The per-detector time
therefore **includes** the remote verification performed inside `FromData`.

**Stability note.** Across every run above the *scope* is invariant: the listed set
is always exactly the result-returning detectors (`{AWS, SentryToken}` in Condition
A; empty in Condition B). Absolute durations vary run-to-run (wall-clock) and the
order of the two rows varies (a race), but the gate/scope never changes.

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
  verification. The ~700× ms-vs-µs contrast between the canonical and
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
    `main.go:511`,`:536`); **within a process hits accrue** (`Hits:12` of 20).
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
    `FromData` `engine.go:1070-1075`; ~700× ms-vs-µs contrast).

**Provenance & read-only guarantee.** All output above was captured live inside
the container at HEAD `e42153d44a5e5c37c1bd0c70e074781e9edcb760` under default
configuration (only the flags each question requires were varied). The one Go
observation harness and all crafted scan inputs lived under `/tmp/th_obs`
(outside the tracked tree) and were removed on completion; the built `./trufflehog`
binary is `.gitignore`d. No existing repository file (`*.go`, tests, config,
`go.mod`/`go.sum`, docs) was modified — the only added file is this document.

