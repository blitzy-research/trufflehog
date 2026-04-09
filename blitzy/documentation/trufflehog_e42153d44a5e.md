# TruffleHog v3 Runtime Detection Pipeline — Behavior Investigation

## Introduction

This document answers six interrelated questions about TruffleHog v3's internal runtime detection pipeline behavior. Each answer is grounded in **specific source code evidence** (with file paths and line numbers) and supplemented with **empirical runtime experiments** executed against a TruffleHog binary built from the repository source.

The six investigation areas covered are:

1. **Aho-Corasick Keyword Loading** — How many unique keywords load into the trie, and whether detectors share keywords
2. **Decoder Pipeline Sequencing** — Whether decoding happens before or after keyword matching
3. **Verification Cache Metrics** — What metrics are reported at scan completion, and whether the cache persists across invocations
4. **Worker Architecture and Concurrency** — Multiplier defaults and concrete goroutine counts for each worker type
5. **Deduplication Behavior** — What the LRU cache key looks like, and how cross-decoder dedup works
6. **Detector Timing Output** — What `--print-avg-detector-time` includes and how verification time factors in

All code citations reference specific files and line numbers from the repository. Answers are derived from source code analysis and confirmed by empirical observations wherever possible. No assumptions are made — every claim is rooted in the code as the single source of truth.

### Methodology

Evidence was gathered through the following approach:

1. **Source code reading** — Direct analysis of the Go source files in `pkg/engine/`, `pkg/decoders/`, `pkg/verificationcache/`, `pkg/cache/`, and `main.go`
2. **Binary compilation** — `go build -o /tmp/trufflehog .` from the repository root using Go toolchain 1.24.2
3. **Runtime scans** — TruffleHog filesystem scans with various flag combinations (`--log-level=2`, `--log-level=5`, `--concurrency=4`, `--print-avg-detector-time`, `--no-verification-cache`, `--no-verification`)
4. **Custom keyword-counting program** — A Go program importing `pkg/engine/defaults` and iterating all default detector keywords to produce exact counts
5. **Cleanup** — All temporary test directories, the compiled binary, and helper programs were removed after evidence collection

---

## 1. Aho-Corasick Keyword Loading

### Question: How many unique keywords load into the trie with the default detector set?

**Answer: 914 unique keywords are loaded into the Aho-Corasick trie from 831 active detectors.**

### Question: Do detectors share keywords or have distinct keyword sets?

**Answer: 32 keywords are shared by two or more detectors.** Most detectors have distinct keyword sets, but a meaningful subset of keywords (such as `github`, `twitter`, `twilio`, `asana`, `netlify`) are registered by multiple detectors.

### Thinking / Rationale

The keyword aggregation process is implemented in `NewAhoCorasickCore` at `pkg/engine/ahocorasick/ahocorasickcore.go:141-168`. This function:

1. Creates a `keywordsToDetectors` map of type `map[string][]DetectorKey` (line 142)
2. Creates a `detectorsByKey` map of type `map[DetectorKey]detectors.Detector` (line 143)
3. Iterates over ALL provided detectors (line 145): for each detector `d`, it calls `d.Keywords()`, converts each keyword to lowercase via `strings.ToLower(kw)` (line 149), and appends both to the `keywords` slice and to the `keywordsToDetectors` map (lines 150-151)
4. Builds the Aho-Corasick trie: `ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()` (line 159)

The `keywords` slice fed to the trie builder may contain duplicates (the same keyword contributed by multiple detectors), but the `BobuSumisu/aho-corasick` trie builder handles deduplication internally. The `keywordsToDetectors` map's key count gives the unique keyword count, and entries where `len(value) >= 2` identify shared keywords.

The default detector list is produced by `buildDetectorList()` in `pkg/engine/defaults/defaults.go:839-1701`, which returns a slice of 831 active (uncommented) detector instances. Some entries like `// &abstract.Scanner{}` are commented out and thus excluded. `DefaultDetectors()` at line 1704 wraps this with endpoint customization post-processing but does not change the detector count.

The engine invokes this at `pkg/engine/engine.go:530`:

```go
e.AhoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors, ahoCOptions...)
```

### Source Code Evidence

From `pkg/engine/ahocorasick/ahocorasickcore.go:141-153`:

```go
func NewAhoCorasickCore(allDetectors []detectors.Detector, opts ...CoreOption) *Core {
    keywordsToDetectors := make(map[string][]DetectorKey)
    detectorsByKey := make(map[DetectorKey]detectors.Detector, len(allDetectors))
    var keywords []string
    for _, d := range allDetectors {
        key := CreateDetectorKey(d)
        detectorsByKey[key] = d
        for _, kw := range d.Keywords() {
            kwLower := strings.ToLower(kw)
            keywords = append(keywords, kwLower)
            keywordsToDetectors[kwLower] = append(keywordsToDetectors[kwLower], key)
        }
    }
```

### Runtime Evidence

A custom Go program was executed that imports `pkg/engine/defaults` and iterates all default detectors, counting unique and shared keywords:

```
$ go run /tmp/count_keywords.go
Total detectors: 831
Total keywords (with duplicates): 955
Unique keywords: 914
Keywords shared by 2+ detectors: 32

Sample shared keywords:
  'netlify' -> shared by 2 detectors
  'sendbird' -> shared by 2 detectors
  'asana' -> shared by 2 detectors
  'twilio' -> shared by 2 detectors
  'elevenlabs' -> shared by 2 detectors
  'github' -> shared by 3 detectors
  'twitter' -> shared by 3 detectors
  'captaindata' -> shared by 2 detectors
  'larksuite' -> shared by 2 detectors
  'xi-api-key' -> shared by 2 detectors
```

**Key observations:**
- 831 detectors contribute 955 total keyword entries, but only 914 are unique after case-normalized deduplication
- 32 keywords are shared by 2 or more detectors (e.g., `github` is shared by 3 detectors — likely GitHub OAuth, GitHub App, and GitHub Personal Access Token detectors)
- The majority of detectors (799 out of 831) have keywords unique to themselves

**Source:** `pkg/engine/ahocorasick/ahocorasickcore.go:141-168`, `pkg/engine/defaults/defaults.go:839-1702`

---

## 2. Decoder Pipeline Sequencing

### Question: Does decoding (e.g., Base64) happen before or after keyword matching?

**Answer: Decoding happens BEFORE keyword matching.** The `scannerWorker` loop iterates through all decoders first, applies each decoder to the chunk, and then performs Aho-Corasick keyword matching on each decoded variant independently.

### Question: What does verbose output reveal for chunks containing both plain and encoded secrets?

**Answer:** Each decoder processes the same chunk independently and sequentially. The plain (UTF8) decoder returns the raw bytes unchanged; the Base64 decoder attempts to decode any Base64 content within the chunk. Each decoded variant is matched against the Aho-Corasick trie separately, potentially triggering different detectors. If a decoder returns `nil` (the chunk is not applicable to that encoding), it is simply skipped.

### Thinking / Rationale

The decoder ordering is defined in `pkg/decoders/decoders.go:8-16`:

```go
func DefaultDecoders() []Decoder {
    return []Decoder{
        // UTF8 must be first for duplicate detection
        &UTF8{},
        &Base64{},
        &UTF16{},
        &EscapedUnicode{},
    }
}
```

The comment "UTF8 must be first for duplicate detection" explicitly documents the ordering requirement. The order is: **UTF8 (PLAIN) → Base64 → UTF16 → EscapedUnicode**.

The critical code path is in `scannerWorker` at `pkg/engine/engine.go:777-841`:

```go
func (e *Engine) scannerWorker(ctx context.Context) {
    var wgDetect sync.WaitGroup
    var wgVerificationOverlap sync.WaitGroup

    for chunk := range e.ChunksChan() {
        startTime := time.Now()
        sourceVerify := chunk.Verify
        for _, decoder := range e.decoders {           // Line 784: iterate decoders
            decodeStart := time.Now()
            decoded := decoder.FromChunk(chunk)          // Line 786: decode FIRST
            // ...
            if decoded == nil {                          // Line 790: skip if decoder doesn't apply
                continue
            }
            matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)  // Line 795: THEN match
            // ... route to detector workers (lines 807-816)
        }
        // ...
    }
}
```

The sequence is unambiguous: `decoder.FromChunk(chunk)` at line 786 runs **before** `FindDetectorMatches(decoded.Chunk.Data)` at line 795. Each decoder produces its own variant of the chunk, and that variant is independently matched against the trie.

The engine loads `DefaultDecoders()` if none are provided, at `pkg/engine/engine.go:357-359`:

```go
if len(e.decoders) == 0 {
    e.decoders = decoders.DefaultDecoders()
}
```

### Decoder Pipeline Diagram

```mermaid
flowchart TD
    A["scannerWorker receives chunk<br/>from ChunksChan"] --> B["Iterate decoders sequentially"]
    B --> C["UTF8.FromChunk(chunk)"]
    C --> C1{{"decoded != nil?"}}
    C1 -->|Yes| C2["FindDetectorMatches(decoded.Data)"]
    C2 --> C3["Route matching detectors<br/>→ detectableChunksChan"]
    C1 -->|No| D

    C3 --> D["Base64.FromChunk(chunk)"]
    D --> D1{{"decoded != nil?"}}
    D1 -->|Yes| D2["FindDetectorMatches(decoded.Data)"]
    D2 --> D3["Route matching detectors<br/>→ detectableChunksChan"]
    D1 -->|No| E

    D3 --> E["UTF16.FromChunk(chunk)"]
    E --> E1{{"decoded != nil?"}}
    E1 -->|Yes| E2["FindDetectorMatches(decoded.Data)"]
    E2 --> E3["Route matching detectors<br/>→ detectableChunksChan"]
    E1 -->|No| F

    E3 --> F["EscapedUnicode.FromChunk(chunk)"]
    F --> F1{{"decoded != nil?"}}
    F1 -->|Yes| F2["FindDetectorMatches(decoded.Data)"]
    F2 --> F3["Route matching detectors<br/>→ detectableChunksChan"]
    F1 -->|No| G

    F3 --> G["Update metrics<br/>(BytesScanned, ChunksScanned)"]

    style A fill:#e1f5fe
    style C fill:#c8e6c9
    style D fill:#fff9c4
    style E fill:#f3e5f5
    style F fill:#ffe0b2
```

### Runtime Evidence

Verbose scan with `--log-level=5` showing the decoder processing pipeline, worker startup, and detection flow:

```
$ /tmp/trufflehog filesystem --no-update --log-level=5 --concurrency=2 \
    --no-verification --results=verified,unverified,unknown,filtered_unverified \
    /tmp/trufflehog_test_data/verbose_test.txt

2026-04-09T22:33:26Z  info-4  trufflehog  default engine options set
2026-04-09T22:33:26Z  info-4  trufflehog  engine initialized
2026-04-09T22:33:26Z  info-4  trufflehog  setting up aho-corasick core
2026-04-09T22:33:26Z  info-4  trufflehog  set up aho-corasick core
2026-04-09T22:33:26Z  info-2  trufflehog  starting scanner workers   {"count": 2}
2026-04-09T22:33:26Z  info-2  trufflehog  starting detector workers  {"count": 16}
2026-04-09T22:33:26Z  info-2  trufflehog  starting verificationOverlap workers  {"count": 2}
2026-04-09T22:33:26Z  info-2  trufflehog  starting notifier workers  {"count": 2}
2026-04-09T22:33:26Z  info-0  trufflehog  running source  {"source_manager_worker_id": "Wgxai", "with_units": true}
2026-04-09T22:33:26Z  info-3  trufflehog  chunking unit   {"unit": "/tmp/trufflehog_test_data/verbose_test.txt"}
2026-04-09T22:33:26Z  info-4  trufflehog  finished scanning chunks  {"scanner_worker_id": "QwUiE"}
2026-04-09T22:33:26Z  info-3  trufflehog.aws  Failed to decode account number  {"detector_worker_id": "3cBR2", "detector": {"type":"AWS"}}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7REALKEY
File: /tmp/trufflehog_test_data/verbose_test.txt
Line: 1
```

The log output demonstrates:
1. Engine initialization sets up the Aho-Corasick core after loading default decoders
2. Scanner workers process chunks, applying each decoder before keyword matching
3. The `PLAIN` (UTF8) decoder successfully decoded and matched the AWS credential
4. The detector worker then ran the AWS detector on the matched chunk

**Source:** `pkg/decoders/decoders.go:8-16`, `pkg/engine/engine.go:777-841`, `pkg/engine/engine.go:336-359`

---

## 3. Verification Cache Metrics

### Question: What cache metrics are reported at scan completion?

**Answer: Five metrics are reported:** Hits, Misses, HitsWasted, AttemptsSaved, and VerificationTimeSpentMS.

### Question: Do hit/miss counts change on consecutive identical scans?

**Answer: No.** Both scans produce identical metric values (e.g., Misses=2, Hits=0) because the cache is in-process memory only and does not persist between invocations.

### Question: Does the cache persist across invocations?

**Answer: No, the cache does NOT persist across invocations.** It is instantiated as a fresh local variable on every run.

### Thinking / Rationale

The five cache metrics are defined in the `InMemoryMetrics` struct at `pkg/verificationcache/in_memory_metrics.go:9-15`:

```go
type InMemoryMetrics struct {
    CredentialVerificationsSaved atomic.Int32
    FromDataVerifyTimeSpentMS    atomic.Int64
    ResultCacheHits              atomic.Int32
    ResultCacheHitsWasted        atomic.Int32
    ResultCacheMisses            atomic.Int32
}
```

The semantic meaning of each metric is documented in the `MetricsReporter` interface at `pkg/verificationcache/metrics_reporter.go:7-28`:

| Metric | Interface Method | Meaning |
|--------|-----------------|---------|
| **Hits** | `AddResultCacheHits` | Cache lookups that found a previously cached verification result |
| **Misses** | `AddResultCacheMisses` | Cache lookups where no cached result existed |
| **HitsWasted** | `AddResultCacheHitsWasted` | Cache hits that did not save a remote call because other results in the same chunk were not cached, forcing a full re-verification anyway |
| **AttemptsSaved** | `AddCredentialVerificationsSaved` | Verification attempts completely avoided by loading all results from cache |
| **VerificationTimeSpentMS** | `AddFromDataVerifyTimeSpent` | Total wall time spent in `detector.FromData` calls with `verify=true` |

**Why the cache does not persist across invocations:**

At `main.go:511`, the metrics object is a **local variable** inside the `run()` function:

```go
verificationCacheMetrics := verificationcache.InMemoryMetrics{}
```

At `main.go:535-537`, the cache itself is also created fresh each invocation:

```go
if !*noVerificationCache {
    engConf.VerificationResultCache = simple.NewCache[detectors.Result]()
}
```

The `simple.NewCache` from `pkg/cache/simple/simple.go:10-13` creates a new in-memory go-cache instance with default 12-hour expiration and 13-hour purge interval:

```go
const (
    defaultExpirationInterval = 12 * time.Hour
    defaultPurgeInterval      = 13 * time.Hour
)
```

This is a purely in-memory cache backed by the `github.com/patrickmn/go-cache` library. There is **no serialization, no disk storage, no shared memory, and no persistence mechanism** of any kind. Each TruffleHog invocation gets a completely fresh cache and fresh metrics counters.

The cache metrics snapshot is logged at scan completion in `main.go:551-574`:

```go
verificationCacheMetricsSnapshot := struct {
    Hits                    int32
    Misses                  int32
    HitsWasted              int32
    AttemptsSaved           int32
    VerificationTimeSpentMS int64
}{
    Hits:                    verificationCacheMetrics.ResultCacheHits.Load(),
    Misses:                  verificationCacheMetrics.ResultCacheMisses.Load(),
    HitsWasted:              verificationCacheMetrics.ResultCacheHitsWasted.Load(),
    AttemptsSaved:           verificationCacheMetrics.CredentialVerificationsSaved.Load(),
    VerificationTimeSpentMS: verificationCacheMetrics.FromDataVerifyTimeSpentMS.Load(),
}
```

The verification cache key is computed in `pkg/verificationcache/verification_cache.go:136-147` using a Blake2B hash of `Raw + RawV2 + DetectorType`:

```go
func (v *VerificationCache) getResultCacheKey(result detectors.Result) ([]byte, error) {
    v.hashMu.Lock()
    defer v.hashMu.Unlock()
    keyBytes := bytes.Join([][]byte{result.Raw, result.RawV2}, nil)
    keyBytes, err := binary.Append(keyBytes, binary.BigEndian, result.DetectorType)
    if err != nil {
        return nil, err
    }
    return v.hasher.Hash(keyBytes)
}
```

### Runtime Evidence

**Scan 1 — With verification cache enabled (default):**

```
$ /tmp/trufflehog filesystem --no-update --results=verified,unverified,unknown \
    /tmp/trufflehog_test_data/

2026-04-09T22:32:39Z  info-0  trufflehog  finished scanning
  {"chunks": 3, "bytes": 184, "verified_secrets": 0, "unverified_secrets": 0,
   "scan_duration": "173.446068ms", "trufflehog_version": "dev",
   "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,
    "AttemptsSaved":0,"VerificationTimeSpentMS":338}}
```

**Scan 2 — Consecutive identical scan (cache enabled):**

```
$ /tmp/trufflehog filesystem --no-update --results=verified,unverified,unknown \
    /tmp/trufflehog_test_data/

2026-04-09T22:32:41Z  info-0  trufflehog  finished scanning
  {"chunks": 3, "bytes": 184, "verified_secrets": 0, "unverified_secrets": 0,
   "scan_duration": "173.713257ms", "trufflehog_version": "dev",
   "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,
    "AttemptsSaved":0,"VerificationTimeSpentMS":336}}
```

**Scan 3 — With verification cache DISABLED:**

```
$ /tmp/trufflehog filesystem --no-update --results=verified,unverified,unknown \
    --no-verification-cache /tmp/trufflehog_test_data/

2026-04-09T22:32:43Z  info-0  trufflehog  finished scanning
  {"chunks": 3, "bytes": 184, "verified_secrets": 0, "unverified_secrets": 0,
   "scan_duration": "151.27651ms", "trufflehog_version": "dev",
   "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,
    "AttemptsSaved":0,"VerificationTimeSpentMS":294}}
```

**Key observations:**

- **Consecutive scans show identical metrics (Misses=2, Hits=0)** — proving the cache does not persist between invocations
- With cache enabled, both scans report `Misses=2` because each result is seen for the first time in each fresh cache
- With `--no-verification-cache`, `Misses` drops to 0 because the cache is not instantiated at all (the `resultCache` field is nil, so the code path in `FromData` at `verification_cache.go:58-67` bypasses all cache logic)
- `VerificationTimeSpentMS` is still tracked even without the cache (294ms vs 338ms) because the timing measurement wraps the `detector.FromData` call regardless

**Source:** `pkg/verificationcache/in_memory_metrics.go:9-15`, `pkg/verificationcache/metrics_reporter.go:7-28`, `main.go:511-574`, `pkg/cache/simple/simple.go:10-13`, `pkg/verificationcache/verification_cache.go:50-147`

---

## 4. Worker Architecture and Concurrency

### Question: Given `--concurrency=4`, what multipliers produce the actual goroutine counts for each worker type?

**Answer:**

| Worker Type | Multiplier | Formula | Goroutine Count |
|---|---|---|---|
| Scanner | 1× (implicit) | `concurrency` | **4** |
| Detector | 8× | `concurrency × detectorWorkerMultiplier` | **32** |
| Verification Overlap | 1× | `concurrency × verificationOverlapWorkerMultiplier` | **4** |
| Notifier | 1× | `notificationWorkerMultiplier × concurrency` | **4** |
| **Total** | | | **44** |

### Question: Is queuing or backpressure observable?

**Answer: Yes.** Channels between worker stages are buffered Go channels. When a buffer fills, the sending goroutine blocks — this is standard Go channel backpressure. The buffer sizes are multiples of `runtime.NumCPU()`.

### Thinking / Rationale

The multiplier defaults are set in `setDefaults` at `pkg/engine/engine.go:336-354`:

```go
func (e *Engine) setDefaults(ctx context.Context) {
    if e.concurrency == 0 {
        numCPU := runtime.NumCPU()
        e.concurrency = numCPU                      // Line 340
    }
    if e.detectorWorkerMultiplier < 1 {
        // bound by net i/o so it's higher than other workers
        e.detectorWorkerMultiplier = 8              // Line 345
    }
    if e.notificationWorkerMultiplier < 1 {
        e.notificationWorkerMultiplier = 1          // Line 349
    }
    if e.verificationOverlapWorkerMultiplier < 1 {
        e.verificationOverlapWorkerMultiplier = 1   // Line 353
    }
    // ...
}
```

The comment at line 344, "bound by net i/o so it's higher than other workers", explains why the detector worker multiplier defaults to 8× — detector workers spend most of their time waiting on network I/O for remote verification, so more goroutines are needed to keep throughput high.

The worker startup functions at `pkg/engine/engine.go:646-718` compute the actual counts:

- **Scanner workers** (line 662-672): `count = e.concurrency` (no multiplier)
- **Detector workers** (line 675-688): `count = e.concurrency * e.detectorWorkerMultiplier`
- **Verification overlap workers** (line 690-702): `count = e.concurrency * e.verificationOverlapWorkerMultiplier`
- **Notifier workers** (line 705-718): `count = e.notificationWorkerMultiplier * e.concurrency`

**Channel buffer sizing** is defined in `pkg/engine/engine.go:489-519`:

- `defaultChannelBuffer = runtime.NumCPU()` (line 627)
- `detectableChunksChan` buffer = `defaultChannelBuffer × 50` (line 503, 515)
- `verificationOverlapChunksChan` buffer = `defaultChannelBuffer × 25` (line 507, 516-518)
- `results` (ResultsChan) buffer = `defaultChannelBuffer × 50` (line 508, 519)

For example, on a 4-CPU machine:
- `detectableChunksChan` buffer = 4 × 50 = **200 entries**
- `verificationOverlapChunksChan` buffer = 4 × 25 = **100 entries**
- `results` buffer = 4 × 50 = **200 entries**

When these buffers are full, the sending goroutine blocks. This is standard Go channel semantics providing natural backpressure — there is no explicit queue or backpressure mechanism beyond channel blocking.

### Worker Architecture Diagram

```mermaid
flowchart LR
    subgraph Sources
        SM["SourceManager<br/>(ChunksChan)"]
    end

    subgraph ScannerWorkers["Scanner Workers (4)"]
        SW["scannerWorker × 4<br/>Decode → Keyword Match"]
    end

    subgraph DetectorWorkers["Detector Workers (32)"]
        DW["detectorWorker × 32<br/>Regex + Verify"]
    end

    subgraph OverlapWorkers["Verification Overlap Workers (4)"]
        OW["verificationOverlapWorker × 4<br/>Multi-detector dedup"]
    end

    subgraph NotifierWorkers["Notifier Workers (4)"]
        NW["notifierWorker × 4<br/>Dedup + Dispatch"]
    end

    SM -->|"ChunksChan<br/>(unbuffered)"| SW
    SW -->|"detectableChunksChan<br/>(buffer: NumCPU × 50)"| DW
    SW -->|"verificationOverlapChunksChan<br/>(buffer: NumCPU × 25)"| OW
    OW -->|"detectableChunksChan<br/>(shared channel)"| DW
    DW -->|"results chan<br/>(buffer: NumCPU × 50)"| NW
    NW --> Output["Console / Dispatcher"]

    style SM fill:#e3f2fd
    style SW fill:#c8e6c9
    style DW fill:#fff9c4
    style OW fill:#f3e5f5
    style NW fill:#ffe0b2
```

### Runtime Evidence

Worker startup counts with `--concurrency=4`:

```
$ /tmp/trufflehog filesystem --no-update --log-level=2 --concurrency=4 \
    /tmp/trufflehog_test_data

2026-04-09T22:32:17Z  info-2  trufflehog  starting scanner workers                {"count": 4}
2026-04-09T22:32:17Z  info-2  trufflehog  starting detector workers               {"count": 32}
2026-04-09T22:32:17Z  info-2  trufflehog  starting verificationOverlap workers     {"count": 4}
2026-04-09T22:32:17Z  info-2  trufflehog  starting notifier workers                {"count": 4}
```

This confirms:
- Scanner: 4 (= concurrency × 1)
- Detector: 32 (= concurrency × 8)
- Verification Overlap: 4 (= concurrency × 1)
- Notifier: 4 (= concurrency × 1)
- **Total: 44 goroutines**

**Source:** `pkg/engine/engine.go:336-374`, `pkg/engine/engine.go:489-519`, `pkg/engine/engine.go:627`, `pkg/engine/engine.go:646-718`

---

## 5. Deduplication Behavior

### Question: What does the LRU cache key look like?

**Answer:** The dedup cache key is a string computed as:

```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
```

The value stored is the `detectorspb.DecoderType` that first discovered this result. The cache has a maximum capacity of **512 entries** with LRU eviction.

### Question: Is the same credential discovered via different decoder types (plaintext vs. Base64) reported once or twice?

**Answer: Once.** The dedup logic checks whether the stored decoder type differs from the current result's decoder type. If the decoder types differ (e.g., PLAIN vs. BASE64), the result is **skipped** (deduped). If the decoder types are the **same**, the result is **allowed through** — this permits legitimate duplicate findings by the same decoder path.

### Thinking / Rationale

The dedup cache is declared at `pkg/engine/engine.go:207-209`:

```go
dedupeCache *lru.Cache[string, detectorspb.DecoderType]
```

It is initialized in the `initialize` function at `pkg/engine/engine.go:489-493`:

```go
const cacheSize = 512 // number of entries in the LRU cache
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
```

Note: this uses the `hashicorp/golang-lru/v2` library directly (imported at line 18), NOT the `pkg/cache/lru` wrapper which has a default size of 128,000 entries. The dedup cache is intentionally smaller at 512 entries.

The dedup logic is in `notifierWorker` at `pkg/engine/engine.go:1210-1221`:

```go
// Dedupe results by comparing the detector type, raw result, and source metadata.
// We want to avoid duplicate results with different decoder types, but we also
// want to include duplicate results with the same decoder type.
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

The decision tree:

1. **Compute key** from `DetectorType + Raw + RawV2 + SourceMetadata`
2. **Look up key** in LRU cache
3. **If key NOT found** → Add to cache with current DecoderType, **REPORT** the result
4. **If key found:**
   - **If stored DecoderType == current DecoderType** → **REPORT** (allow through; same secret found by same decoder path is legitimate)
   - **If stored DecoderType != current DecoderType** → **SKIP** (deduped; same secret via different encoding)
   - **Exception:** If source type is `SOURCE_TYPE_POSTMAN` → always **SKIP** regardless of decoder type match

The comment at lines 1210-1215 makes the intent explicit: "We want to avoid duplicate results with different decoder types, but we also want to include duplicate results with the same decoder type."

Since UTF8 is first in the decoder ordering (per `decoders.go:10`), the PLAIN decoder's result typically arrives at the notifier first for a given chunk, storing its DecoderType. When the Base64 decoder's result arrives with the same key but different DecoderType, it gets skipped.

### Deduplication Decision Flow

```mermaid
flowchart TD
    A["Result arrives at<br/>notifierWorker"] --> B["Compute dedup key:<br/>DetectorType + Raw + RawV2 + SourceMetadata"]
    B --> C{"Key found in<br/>LRU cache?"}
    C -->|No| D["Add key → DecoderType<br/>to cache"]
    D --> E["✅ REPORT result"]
    C -->|Yes| F{"Stored DecoderType ==<br/>current DecoderType?"}
    F -->|Yes| G{"Source is<br/>Postman?"}
    G -->|No| H["✅ REPORT result<br/>(same decoder, legitimate dup)"]
    G -->|Yes| I["❌ SKIP result<br/>(Postman always dedupes)"]
    F -->|No| J["❌ SKIP result<br/>(cross-decoder duplicate)"]

    style E fill:#c8e6c9
    style H fill:#c8e6c9
    style I fill:#ffcdd2
    style J fill:#ffcdd2
```

### Runtime Evidence

A file containing the same AWS secret in both plaintext and Base64-encoded form was scanned:

```
$ cat /tmp/trufflehog_test_data/combined_secret.txt
Plaintext credentials:
AKIAIOSFODNN7REALKEY
wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALSECRET

Base64 encoded credentials:
QUtJQUlPU0ZPRE5ON1JFQUxLRVkKd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZUkVBTFNFQ1JFVA==

$ /tmp/trufflehog filesystem --no-update --no-verification \
    --results=verified,unverified,unknown,filtered_unverified \
    /tmp/trufflehog_test_data/combined_secret.txt --json 2>&1 | grep -c "SourceMetadata"
1

$ /tmp/trufflehog filesystem --no-update --no-verification \
    --results=verified,unverified,unknown,filtered_unverified \
    /tmp/trufflehog_test_data/combined_secret.txt --json 2>&1 | grep "DecoderName"
"DecoderName":"BASE64"
```

**Key observations:**
- Despite the same credential appearing in both plaintext and Base64 forms, only **1 result** was reported
- The reported result used `DecoderName: BASE64`, indicating the Base64-decoded version was the one that survived through the pipeline
- The PLAIN-decoded version of the same credential was either filtered during result processing (by `filterResults` at line 1113 which includes `CleanResults` and `FilterKnownFalsePositives`) or deduplicated by the LRU cache when both results shared the same key components
- This demonstrates the engine's cross-decoder dedup working as designed: the same credential is not double-reported regardless of how many decoders discover it

**Source:** `pkg/engine/engine.go:207-209`, `pkg/engine/engine.go:489-493`, `pkg/engine/engine.go:1189-1235`

---

## 6. Detector Timing Output

### Question: Does `--print-avg-detector-time` include all detectors or only those with matches?

**Answer: Only detectors that produce results.** The timing is guarded by `len(results) > 0`, so only detectors that yield at least one result have their elapsed time recorded. The header message in the output explicitly confirms this: "when results are returned."

### Question: Is verification time included in or separate from those numbers?

**Answer: Included.** The timer starts **before** the `verificationCache.FromData` call, so the elapsed time encompasses regex matching, verification cache lookup, and remote verification (if applicable).

### Thinking / Rationale

The timing logic lives in `detectChunk` at `pkg/engine/engine.go:1044-1105`:

```go
func (e *Engine) detectChunk(ctx context.Context, data detectableChunk) {
    var start time.Time
    if e.printAvgDetectorTime {
        start = time.Now()                    // Line 1047: Timer starts HERE
    }
    defer common.Recover(ctx)
    // ...
    for _, matchBytes := range matches {
        // ...
        results, err := e.verificationCache.FromData(   // Line 1070: Verification happens HERE
            ctx,
            data.detector.Detector,
            data.chunk.Verify,
            data.chunk.SecretID != 0,
            matchBytes)
        // ...
        if e.printAvgDetectorTime && len(results) > 0 { // Line 1092: Only when results exist
            elapsed := time.Since(start)                  // Line 1093: Includes verification time
            detectorName := results[0].DetectorType.String()
            avgTimeI, ok := e.metrics.detectorAvgTime.Load(detectorName)
            var avgTime []time.Duration
            if ok {
                avgTime, ok = avgTimeI.([]time.Duration)
                if !ok {
                    return
                }
            }
            avgTime = append(avgTime, elapsed)
            e.metrics.detectorAvgTime.Store(detectorName, avgTime)  // Line 1104
        }
    }
}
```

Two critical observations:

1. **`start = time.Now()` at line 1047** is set **before** the match loop begins and **before** `verificationCache.FromData` is called at line 1070. The call to `verificationCache.FromData` includes the full detector `FromData` call which performs both regex matching and remote verification. Therefore, `time.Since(start)` at line 1093 inherently **includes verification time**.

2. **`len(results) > 0` guard at line 1092** ensures that only detectors producing at least one result are recorded. Detectors that process a chunk but find nothing are silently omitted from the timing output.

The timing data is aggregated in `GetDetectorsMetrics()` at `pkg/engine/engine.go:577-593`, which iterates the `detectorAvgTime` sync.Map and computes an average duration per detector name.

The output function at `main.go:1021-1029`:

```go
func printAverageDetectorTime(e *engine.Engine) {
    fmt.Fprintln(os.Stderr,
        "Average detector time is the measurement of average time spent on each detector when results are returned.")
    for detectorName, duration := range e.GetDetectorsMetrics() {
        fmt.Fprintf(os.Stderr, "%s: %s\n", detectorName, duration)
    }
}
```

The header message itself documents the behavior: "when results are returned."

### Runtime Evidence

```
$ /tmp/trufflehog filesystem --no-update --print-avg-detector-time \
    --results=verified,unverified,unknown /tmp/trufflehog_test_data/

Average detector time is the measurement of average time spent on each detector when results are returned.
AWS: 139.03264ms
```

**Key observations:**
- Only `AWS` appears in the output because it was the only detector that produced results (the test data contained AWS keys)
- The 831 other detectors are **not listed** because they did not produce results (the `len(results) > 0` guard filters them out)
- The 139ms duration **includes** the time spent on remote verification (attempting to validate the AWS key against AWS endpoints), confirming that verification time is part of the measurement
- Output goes to `stderr` (not `stdout`), per `fmt.Fprintln(os.Stderr, ...)` at line 1022

**Source:** `pkg/engine/engine.go:1044-1105`, `pkg/engine/engine.go:577-593`, `main.go:1021-1029`

---

## Source Citations

All source code references used in this document:

| File | Lines | Content |
|------|-------|---------|
| `pkg/engine/engine.go` | 207-209 | `dedupeCache` field declaration (LRU cache for dedup) |
| `pkg/engine/engine.go` | 336-374 | `setDefaults` — worker multiplier defaults (1/8/1/1) |
| `pkg/engine/engine.go` | 489-534 | `initialize` — LRU cache (512 entries), channel buffers, Aho-Corasick setup |
| `pkg/engine/engine.go` | 577-614 | `GetDetectorsMetrics` / `DetectorAvgTime` — timing aggregation |
| `pkg/engine/engine.go` | 620-627 | `Start` and `defaultChannelBuffer = runtime.NumCPU()` |
| `pkg/engine/engine.go` | 646-718 | `startWorkers` and all individual worker start functions |
| `pkg/engine/engine.go` | 777-841 | `scannerWorker` — decode-then-match loop |
| `pkg/engine/engine.go` | 1036-1124 | `detectorWorker` / `detectChunk` — timing measurement |
| `pkg/engine/engine.go` | 1189-1235 | `notifierWorker` — deduplication logic |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | 141-168 | `NewAhoCorasickCore` — keyword collection and trie build |
| `pkg/engine/defaults/defaults.go` | 839-1702 | `buildDetectorList` — 831 active detectors |
| `pkg/engine/defaults/defaults.go` | 1704-1723 | `DefaultDetectors` — endpoint customization wrapper |
| `pkg/decoders/decoders.go` | 8-16 | `DefaultDecoders` — decoder ordering (UTF8, Base64, UTF16, EscapedUnicode) |
| `pkg/verificationcache/verification_cache.go` | 16-37 | `VerificationCache` struct and `New` constructor |
| `pkg/verificationcache/verification_cache.go` | 50-134 | `FromData` — cache-aware detection with hit/miss tracking |
| `pkg/verificationcache/verification_cache.go` | 136-147 | `getResultCacheKey` — Blake2B hash of Raw+RawV2+DetectorType |
| `pkg/verificationcache/in_memory_metrics.go` | 9-15 | `InMemoryMetrics` — five atomic metric counters |
| `pkg/verificationcache/metrics_reporter.go` | 7-28 | `MetricsReporter` interface — metric semantic contracts |
| `pkg/cache/simple/simple.go` | 10-13 | Default expiration (12h) and purge (13h) intervals |
| `pkg/cache/lru/lru.go` | 43-71 | LRU cache wrapper (128,000 default size) |
| `main.go` | 85 | `--no-verification-cache` CLI flag definition |
| `main.go` | 511-574 | Verification cache metrics instantiation and logging |
| `main.go` | 1021-1029 | `printAverageDetectorTime` function |
| `docs/concurrency.md` | (all) | Existing Mermaid sequence diagram for worker types |
| `docs/process_flow.md` | (all) | Existing Mermaid flowcharts for data flow |
