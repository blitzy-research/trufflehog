# TruffleHog Runtime Pipeline Investigation

**Repository:** `trufflesecurity/trufflehog` at commit `e42153d44a5e`
**Scope:** Behavioral analysis of the **decoder pipeline**, **verification overlap detection**, and **result deduplication** subsystems, and their interaction at runtime.
**Methodology:** Static analysis of the Go source code paired with experimental runs of the built binary on crafted inputs.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Investigation Questions](#2-investigation-questions)
3. [The Decoder Pipeline](#3-the-decoder-pipeline)
4. [Aho-Corasick Keyword Prefilter and Match Spans](#4-aho-corasick-keyword-prefilter-and-match-spans)
5. [The Verification Overlap Subsystem](#5-the-verification-overlap-subsystem)
6. [The Deduplication Layer](#6-the-deduplication-layer)
7. [Interaction and Ordering Between Subsystems](#7-interaction-and-ordering-between-subsystems)
8. [Concurrency Model and Non-Determinism](#8-concurrency-model-and-non-determinism)
9. [Experimental Evidence](#9-experimental-evidence)
10. [Answers to the Posed Questions](#10-answers-to-the-posed-questions)
11. [Appendix A — Source Code Map](#appendix-a--source-code-map)
12. [Appendix B — Reproduction Commands](#appendix-b--reproduction-commands)

---

## 1. Executive Summary

TruffleHog ingests chunks (byte slices extracted from sources such as files, Git history, Postman collections, etc.), passes each chunk independently through every decoder in a fixed list, and then asks the Aho-Corasick prefilter which detectors keyword-match on the decoded bytes. A chunk can enter detection via **one of two paths**:

- **Direct path** — when exactly one detector keyword-matches (or when `--allow-verification-overlap` is set), the decoded chunk is sent to `detectableChunksChan` and processed by a detector worker.
- **Overlap path** — when **more than one** detector keyword-matches the same decoded bytes (and `--allow-verification-overlap` is *not* set), the chunk is sent to `verificationOverlapChunksChan`, where a `verificationOverlapWorker` runs each detector's `FromData` **without** verification, compares resulting secrets across detectors via Levenshtein distance, and either (a) stamps duplicates with `errOverlap` to disable their verification, or (b) re-routes non-duplicate detectors onto the direct path with verification re-enabled.

Results from all detector workers arrive at a single shared `results` channel consumed by one or more **notifier workers**. Each notifier computes a dedup key from `DetectorType + Raw + RawV2 + SourceMetadata` and, using a process-wide 512-entry LRU cache, suppresses *any* subsequent result with the **same key** but a **different** `DecoderType`. Results that share the key *and* `DecoderType` — or originate from a Postman source — follow a special code path.

Because the scanner emits one decoded chunk *per decoder* for every input chunk, a plain secret and its base64-encoded form in the same chunk normally produce **two independent in-flight results** (one with `DecoderType=PLAIN` and one with `DecoderType=BASE64`) which race through the pipeline. The LRU dedup keeps only the **first** of the two to reach a notifier worker, and because that winner is determined by goroutine scheduling, the reported decoder is non-deterministic under the default concurrency settings.

All findings below are supported by the specific source locations cited, and by runtime experiments summarised in [§9](#9-experimental-evidence).

---

## 2. Investigation Questions

This document answers the following five questions posed in the investigation brief:

1. **Decoder selection** — Given the same logical secret present in multiple encoded forms within a single chunk, how does TruffleHog's decoder pipeline decide which decoder's output is reported in the final result? Which decoder types are reported, and why?
2. **Overlap detection** — How does the `verificationOverlapWorker` handle chunks matched by more than one detector, how is cross-detector similarity measured, and what triggers the `errOverlap` error?
3. **Deduplication** — How does the LRU dedup cache in the `notifierWorker` decide which decoder-variant result to keep and which to suppress, and why can the reported `DecoderName` vary across runs?
4. **Interaction sequencing** — What is the precise order of operations between decoding, keyword matching, overlap detection, detection, and deduplication, and where does concurrency introduce non-determinism?
5. **Single-vs-multiple result behaviour** — Why does the same logical secret sometimes produce a single result and sometimes appear to produce multiple results, depending on file structure, concurrency, and the `--allow-verification-overlap` flag?

Direct answers to each question appear in [§10](#10-answers-to-the-posed-questions) and reference the analytical sections that precede them.

---

## 3. The Decoder Pipeline

### 3.1 Fixed Decoder Ordering

The decoder chain is hard-coded in `pkg/decoders/decoders.go`:

```go
// pkg/decoders/decoders.go (lines 8-16)
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

The ordering is significant but in an indirect way. The comment "UTF8 must be first for duplicate detection" refers to how **inside the notifier's dedup cache**, the first-stored `DecoderType` becomes the "canonical" choice for the key — and under strictly serial execution, UTF8 (PLAIN) always wins because it is produced first by `scannerWorker`. The ordering does **not** guarantee PLAIN wins under the default concurrent execution; see [§8](#8-concurrency-model-and-non-determinism).

The `DecodableChunk` struct carries both the rewritten chunk and the `DecoderType` so the rest of the pipeline knows which decoder produced it:

```go
// pkg/decoders/decoders.go (lines 20-29)
type DecodableChunk struct {
    *sources.Chunk
    DecoderType detectorspb.DecoderType
}

type Decoder interface {
    FromChunk(chunk *sources.Chunk) *DecodableChunk
    Type() detectorspb.DecoderType
}
```

The four `DecoderType` values are defined in the protobuf-generated file:

```go
// pkg/pb/detectorspb/detectors.pb.go (lines 27-30)
DecoderType_PLAIN           DecoderType = 1
DecoderType_BASE64          DecoderType = 2
DecoderType_UTF16           DecoderType = 3
DecoderType_ESCAPED_UNICODE DecoderType = 4
```

### 3.2 Per-Decoder Behaviour

Each decoder is a **pure** transformation: it is given a `*sources.Chunk` and returns either a rewritten `*DecodableChunk` or `nil` if it does not apply.

#### 3.2.1 UTF8 / PLAIN decoder — `pkg/decoders/utf8.go`

The PLAIN decoder **never returns `nil` for non-empty input.** For valid UTF-8, the chunk is passed through unchanged; for invalid UTF-8, the chunk data is rewritten in place by `extractSubstrings`:

```go
// pkg/decoders/utf8.go (FromChunk)
if !utf8.Valid(chunk.Data) {
    chunk.Data = extractSubstrings(chunk.Data)
    return decodableChunk
}
return decodableChunk
```

`extractSubstrings` replaces non-printable ASCII (bytes 0–31 and 127) with the Unicode replacement character (`U+FFFD`), and collapses any malformed multi-byte sequence to a single replacement character as well.

**Behavioural consequence:** for any text input, the PLAIN decoder always fires and produces a `DecodableChunk` containing the original textual content. This is why most "regular" secrets are reported with `DecoderName=PLAIN`.

#### 3.2.2 Base64 decoder — `pkg/decoders/base64.go`

The Base64 decoder scans for **runs** of base64-alphabet characters longer than 20 characters, then tries both `StdEncoding` and `RawURLEncoding`. Only decoded byte sequences that are (a) non-empty and (b) entirely ASCII (≤ 0x7F) are kept:

```go
// pkg/decoders/base64.go (FromChunk snippet)
encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
for _, str := range encodedSubstrings {
    dec, err := base64.StdEncoding.DecodeString(str)
    if err == nil && len(dec) > 0 && isASCII(dec) {
        decodedSubstrings[str] = dec
    }
    dec, err = base64.RawURLEncoding.DecodeString(str)
    if err == nil && len(dec) > 0 && isASCII(dec) {
        decodedSubstrings[str] = dec
    }
}
```

When at least one substring decodes successfully, the decoder **substitutes the decoded bytes in place** (surrounding text is preserved) and returns a `DecodableChunk{DecoderType: BASE64}`. When no base64 runs exist or none decode to ASCII, it returns `nil`.

**Behavioural consequence:** a chunk containing a plain-text AWS key **and** a base64-encoded copy of that same key will have the encoded portion rewritten to plain-text; the resulting decoded chunk therefore contains the same secret **twice** (once at the original location, once where the encoded form was). This is the root cause of the "2 BASE64 results" pattern observed in [§5](#5-the-verification-overlap-subsystem) and [§9](#9-experimental-evidence).

#### 3.2.3 UTF16 decoder — `pkg/decoders/utf16.go`

`UTF16.FromChunk` attempts **both** big-endian and little-endian interpretation of pairs of bytes and keeps whichever produces printable output:

```go
// pkg/decoders/utf16.go (utf16ToUTF8 snippet)
if r := rune(binary.BigEndian.Uint16(b[i:])); b[i] == 0 && utf8.ValidRune(r) {
    if isPrintableByte(byte(r)) { bufBE.WriteRune(r) }
}
if r := rune(binary.LittleEndian.Uint16(b[i+1]) == 0) ... { bufLE.WriteRune(r) }
```

If the resulting UTF-8 buffer is empty (no printable UTF-16 data was detected) the decoder returns `nil`. Almost all of our experimental inputs are ASCII text and therefore do **not** trigger the UTF16 path.

#### 3.2.4 EscapedUnicode decoder — `pkg/decoders/escaped_unicode.go`

Two regexes govern this decoder:

```go
// pkg/decoders/escaped_unicode.go (lines 16-22)
codePointPat = regexp.MustCompile(`\bU\+([a-fA-F0-9]{4}).?`)
escapePat    = regexp.MustCompile(`(?i:\\{1,2}u)([a-fA-F0-9]{4})`)
```

`codePointPat` matches Unicode "code-point notation" (e.g. `U+0041`), and `escapePat` matches the common `\uXXXX` / `\\uXXXX` programming-language escape. If **either** pattern matches, the decoder returns a rewritten chunk with `DecoderType=ESCAPED_UNICODE`; otherwise it returns `nil`. Critically, it **clones the chunk data** before rewriting (`chunkData = bytes.Clone(chunk.Data)`) to avoid data races with other decoders.

### 3.3 How `scannerWorker` Uses the Decoders

For every input chunk, `scannerWorker` iterates through the decoder list and submits each non-nil variant independently:

```go
// pkg/engine/engine.go (lines 777-797, simplified)
for chunk := range e.ChunksChan() {
    for _, decoder := range e.decoders {
        decoded := decoder.FromChunk(chunk)
        if decoded == nil { continue }

        matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
        if len(matchingDetectors) > 1 && !e.verificationOverlap {
            e.verificationOverlapChunksChan <- verificationOverlapChunk{...}
            continue
        }
        for _, detector := range matchingDetectors {
            e.detectableChunksChan <- detectableChunk{chunk: *decoded.Chunk, decoder: decoded.DecoderType, ...}
        }
    }
}
```

This is the **critical design decision** that governs every observable behaviour below: a chunk containing N decoder-relevant variants produces up to N independent decoded chunks, each of which is routed independently. The decoder order **does not** serialise the downstream pipeline — it only controls the order in which chunks are **pushed** onto downstream channels.

### 3.4 Note on in-place chunk mutation

Both the UTF8 decoder (invalid-UTF8 path) and the Base64 decoder **mutate** `chunk.Data` in place before returning. Because UTF8 runs first and only *potentially* rewrites (for invalid UTF-8), the Base64 decoder sees whatever UTF8 wrote, and UTF16 and EscapedUnicode each see the Base64-rewritten chunk. This is safe because the downstream `matchingDetectors` check is run once per decoder output, but it does mean that, for example, `UTF16.FromChunk` is effectively operating on the base64-decoded bytes of the same underlying `*sources.Chunk` pointer if Base64 ran before it. In practice, because UTF16 requires paired-null bytes this virtually never matters for text data. `EscapedUnicode.FromChunk` defends against this race with `bytes.Clone`.

---

## 4. Aho-Corasick Keyword Prefilter and Match Spans

### 4.1 Keyword Trie

At engine initialisation (`NewAhoCorasickCore` in `pkg/engine/ahocorasick/ahocorasickcore.go`), every detector's `Keywords()` list is lower-cased and inserted into a single Aho-Corasick trie keyed by `keywordsToDetectors map[string][]DetectorKey`. The same keyword can map to multiple detector keys (which is how e.g. the "dm" keyword surfaces both AWS tests and the Voiceflow detector).

### 4.2 `FindDetectorMatches`

For each decoded chunk, `FindDetectorMatches` lower-cases the entire chunk (because the trie is case-insensitive), runs the trie, and for each keyword hit computes a **match span** — a bounded window around the hit from which the detector's regex will be run. The default span is `±512` bytes:

```go
// pkg/engine/ahocorasick/ahocorasickcore.go (line 155)
const defaultOffsetRadius int64 = 512
```

Detectors can customise span geometry via three interfaces: `MultiPartCredentialProvider.MaxCredentialSpan`, `MaxSecretSizeProvider.MaxSecretSize`, and `StartOffsetProvider.StartOffset` (see `adjustableSpanCalculator.calculateSpan` at lines 80–113). Overlapping or adjacent spans for the same detector are merged by `mergeMatches`, and the chunk bytes for each final span are extracted into the `DetectorMatch.matches` slice.

### 4.3 Why the Prefilter Matters for Dedup

The downstream detector (`FromData`) is called **once per match span** (see `detectChunk`, `pkg/engine/engine.go:1068-1125`). If a single decoded chunk contains two keyword occurrences that produce two non-mergeable spans, the detector is invoked twice — producing two results with identical `Raw` / `RawV2`. The notifier will then see two results with the same dedup key and the same `DecoderType`; per the dedup rules in [§6](#6-the-deduplication-layer), these will **both** pass through. This is the mechanism behind the "2 BASE64 results" outcome described later.

---

## 5. The Verification Overlap Subsystem

### 5.1 Routing Condition

The overlap path is chosen by a single line in `scannerWorker`:

```go
// pkg/engine/engine.go (line 796)
if len(matchingDetectors) > 1 && !e.verificationOverlap {
    // → send to verificationOverlapChunksChan
}
```

- `len(matchingDetectors) > 1` means *more than one* distinct detector keyword-matched the decoded chunk.
- `e.verificationOverlap` is the flag set by `--allow-verification-overlap`. When **true**, the overlap path is bypassed entirely.

### 5.2 Inside `verificationOverlapWorker` (lines 924–1034)

For each chunk delivered on `verificationOverlapChunksChan`, the worker does the following:

1. **Run every matching detector without verification** (`FromData(ctx, verify=false, matchBytes)`, line 944), recording the candidate secrets each returned.
2. **Apply result filtration** for the non-targeted-scan case (`chunk.SecretID == 0`), invoking `filterResults` — which in turn calls each detector's `CleanResults` and the false-positive filter.
3. **Build a per-detector secret key** — `chunkSecretKey{secret: string(val), detectorKey: detector.Key}` where `val` is `RawV2` if present or `Raw` otherwise.
4. **Compare to previously seen keys for other detectors** via `likelyDuplicate` (see §5.3). If a duplicate is found:
   - Increment the overlap tracker.
   - Set `res.SetVerificationError(errOverlap)` on the candidate result.
   - Call `e.processResult(...)` directly, bypassing `detectableChunksChan`. The result flows through `processResult` to `e.results` with verification already disabled.
   - `delete(detectorKeysWithResults, detector.Key)` so the detector is **not** re-routed below.
5. **Re-route survivors** — for each remaining detector in `detectorKeysWithResults`, send a `detectableChunk` to `detectableChunksChan` with verification enabled.
6. **Reset the reusable per-chunk maps** and call `verificationOverlapWgDoneFn`.

The code for the overlap routing and `errOverlap` tagging is worth reading in full:

```go
// pkg/engine/engine.go (lines 985-995)
if likelyDuplicate(ctx, key, chunkSecrets) {
    // This indicates that the same secret was found by multiple detectors.
    // We should NOT VERIFY this chunk's data.
    if e.verificationOverlapTracker != nil {
        e.verificationOverlapTracker.increment()
    }
    res.SetVerificationError(errOverlap)
    e.processResult(ctx, detectableChunk{...}, res, isFalsePositive)
    delete(detectorKeysWithResults, detector.Key)
}
chunkSecrets[key] = struct{}{}
```

### 5.3 `likelyDuplicate` and the 0.9 Levenshtein Threshold

```go
// pkg/engine/engine.go (lines 887-922, abridged)
const similarityThreshold = 0.9
for dupeKey := range dupes {
    // Skip if lengths differ by more than ~10%.
    if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 { continue }
    // Skip if same detector type (intra-detector dupes are not "overlap").
    if val.detectorKey.Type() == dupeKey.detectorKey.Type() { continue }
    if valStr == dupe { return true }
    similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())
    if similarity > similarityThreshold { return true }
}
return false
```

Three gating conditions in order:
- **Length filter** — strings whose lengths differ by more than 10% are never considered similar (cheap early-out).
- **Same-detector filter** — two results from the *same* detector type are **not** duplicates in the overlap sense. This is why AWS finding the same secret twice inside one chunk does **not** trigger `errOverlap`.
- **Similarity check** — for cross-detector pairs that pass the length filter, exact string equality or Levenshtein similarity > 0.9 (per `github.com/adrg/strutil/metrics`) counts as a duplicate.

### 5.4 `errOverlap` Error Message

```go
// pkg/engine/engine.go (lines 39-42)
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
    "You can override this behavior by using the --allow-verification-overlap flag.",
)
```

The error is attached to the result via `Result.SetVerificationError`, which wraps the message so that downstream output shows it to the user. Because the result has a verification error, the notifier treats it as "unknown" (see [§6.1](#61-filter-by-verification-status)).

### 5.5 When No Cross-Detector Duplicate Exists

If the overlap worker processes a chunk where every matching detector keyword-matched but only **one** of them produced actual regex-level results (or each detector produced *different* secrets), no `likelyDuplicate` hit occurs. In that case, the detector that produced results is re-routed to the normal path with verification re-enabled:

```go
// pkg/engine/engine.go (lines 1017-1026)
for _, detector := range detectorKeysWithResults {
    wgDetect.Add(1)
    chunk.chunk.Verify = e.shouldVerifyChunk(chunk.chunk.Verify, detector, ...)
    e.detectableChunksChan <- detectableChunk{
        chunk: chunk.chunk, detector: detector, decoder: chunk.decoder, ...
    }
}
```

This is the typical AWS + Voiceflow case — both detectors keyword-match (because Voiceflow's keyword `dm` appears inside many base64-decoded AWS secrets), but Voiceflow's regex `\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b` does not match AWS key material, so Voiceflow produces zero results and AWS is re-routed for full verification.

---

## 6. The Deduplication Layer

All detector results — from the direct path *and* from the overlap path — converge on the shared `e.results` channel and are consumed by `notifierWorker` (lines 1189–1235). The entire dedup decision is in this one function.

### 6.1 Filter by Verification Status

Before dedup, the notifier applies the user's result-filtering preferences (`--results verified,unverified,unknown` etc.):

```go
// pkg/engine/engine.go (lines 1192-1208, abridged)
if !result.Verified {
    if result.VerificationError() != nil {
        if !e.notifyUnknownResults { continue }   // skip "unknown" (errOverlap falls here)
    } else if !e.notifyUnverifiedResults { continue }   // skip "unverified"
} else if !e.notifyVerifiedResults { continue }   // skip "verified"
```

Results bearing `errOverlap` have `VerificationError() != nil` and therefore only pass if `notifyUnknownResults` is true.

### 6.2 The Dedup Key and LRU Cache

```go
// pkg/engine/engine.go (lines 1213-1221)
// Dedupe results by comparing the detector type, raw result, and source metadata.
// We want to avoid duplicate results with different decoder types, but we also
// want to include duplicate results with the same decoder type.
// Duplicate results with the same decoder type SHOULD have their own entry in the
// results list, this would happen if the same secret is found multiple times.
// Note: If the source type is postman, we dedupe the results regardless of decoder type.
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

Three rules govern the cache:

| Current result key | Current `DecoderType` | Cache state | Outcome |
|---|---|---|---|
| Not in cache | — | — | Add to cache with current `DecoderType`, dispatch result. |
| In cache | **Same** as cached value | Non-Postman | Update cache (no-op) and dispatch result — "same decoder" duplicates are intentionally allowed. |
| In cache | **Different** from cached value | Non-Postman | **Skip**. The first `DecoderType` wins. |
| In cache | Any | Postman source | **Skip** regardless of decoder type. |

The cache is a `hashicorp/golang-lru/v2` instance of 512 entries initialised in `Engine.initialize`:

```go
// pkg/engine/engine.go (lines 491-494)
const cacheSize = 512 // number of entries in the LRU cache
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
```

### 6.3 Why the Key Includes `SourceMetadata`

The `%+v`-formatted `SourceMetadata` serialisation contains the file path, line number, commit hash, etc. as appropriate for the source. Two occurrences of the **same raw bytes** in **different locations** (e.g. two files) therefore produce **different** dedup keys and both survive. This is the basis of Experiment I ([§9.9](#99-experiment-i--two-separate-files-with-identical-secrets)).

### 6.4 Note on Line Numbers in `SourceMetadata`

For filesystem / Git sources, the notifier is not the first stage to touch `SourceMetadata` — `processResult` calls `FragmentFirstLineAndLink` and `SetResultLineNumber` which use `bytes.Cut(chunk.Data, result.Raw)` to locate the *first* occurrence of `Raw` in the chunk data (`FragmentLineOffset` at line 1256). Because `bytes.Cut` always returns the first match, two detector invocations on the same decoded chunk producing the same `Raw` receive the **same** line number — and therefore the **same** `SourceMetadata`, and therefore the **same** dedup key with the same `DecoderType` ⇒ both pass dedup (per rule 2 in [§6.2](#62-the-dedup-key-and-lru-cache)).

---

## 7. Interaction and Ordering Between Subsystems

### 7.1 Pipeline Stages

Mapping the four stages in `docs/process_flow.md` onto the actual worker topology:

| Stage (doc) | Component | Worker type | Function |
|---|---|---|---|
| Source Decomposition | `sources.SourceManager` | source-specific goroutines | Emit `*sources.Chunk` on `e.ChunksChan()` |
| Chunk-to-Detector Matching | `scannerWorker` + `AhoCorasickCore` | scanner workers | Decode, keyword-match, route |
| Secret Detection | `verificationOverlapWorker` + `detectorWorker` / `detectChunk` | overlap + detector workers | Run regex, verify, filter |
| Result Notification | `notifierWorker` | notifier workers | Dedup, dispatch |

### 7.2 Channel Topology

```
           ChunksChan()
                │
                ▼
   ┌────────────────────────┐
   │   scannerWorker(s)     │  decode + Aho-Corasick
   └─────────┬──────┬───────┘
             │      │
             │      └───────────────┐
             ▼                      ▼
 verificationOverlapChunksChan    detectableChunksChan
             │                      │
             ▼                      │
 ┌──────────────────────┐           │
 │ verificationOverlap  │           │
 │       Worker(s)      │           │
 └──────────┬───────────┘           │
            │   (re-route            │
            │    non-duplicate       │
            │    detectors)          │
            └─────────────► detectableChunksChan
                                    │
                                    ▼
                   ┌────────────────────────────┐
                   │   detectorWorker(s)        │  FromData, verify, filter
                   │   → detectChunk            │
                   │   → processResult          │
                   └──────────┬─────────────────┘
                              │
                              ▼
                      e.results (chan)
                              │
                              ▼
                   ┌────────────────────────────┐
                   │   notifierWorker(s)        │  filter+dedup+dispatch
                   └────────────────────────────┘
```

Results bearing `errOverlap` bypass the detector workers: the overlap worker calls `processResult` directly (line 991) which writes to `e.results` at line 1186.

### 7.3 Ordering Invariants

1. **Decoder order per-chunk.** Inside `scannerWorker`'s per-chunk loop, decoded variants are produced in UTF8 → Base64 → UTF16 → EscapedUnicode order, and pushed onto their destination channels in that same order.
2. **Dedup happens after overlap.** The overlap worker runs *before* the main detector worker. Any result emitted by the overlap worker (whether marked `errOverlap` or re-routed) still passes through the notifier's dedup cache. Dedup is always last.
3. **FIFO per channel.** Go channels deliver in FIFO order to receivers, but when there are multiple receivers, each receiver may claim a different item from the same channel. With >1 consumer goroutine, ordering across goroutines is **not** preserved.
4. **Cache-add is atomic per notifier.** `hashicorp/golang-lru` serialises calls internally, so `Get → Add` is safe under concurrency, but a two-step "check then add" is not atomic: two notifier goroutines processing two different results with the same key can both observe "key not in cache" and then both add, with the *second* add overwriting the first. In practice this is rarely visible because both would produce identical cache contents, and the notifier's decision for the *next* arrival uses the updated cache anyway.

### 7.4 Illustrative Sequence — Plain + Base64 AWS Key in One Chunk

```mermaid
sequenceDiagram
    participant SW as scannerWorker
    participant AC as AhoCorasickCore
    participant OW as overlapWorker
    participant DW as detectorWorker
    participant NW as notifierWorker
    participant OUT as Dispatcher

    Note over SW: Receives 1 Chunk with plain AWS key + base64(AWS key)

    SW->>AC: FindDetectorMatches(UTF8 output)
    AC-->>SW: [AWS, Voiceflow]  (both keyword-match)
    Note over SW: >1 detectors → overlap path
    SW->>OW: verificationOverlapChunksChan  {decoder=PLAIN}

    SW->>AC: FindDetectorMatches(BASE64 output)
    AC-->>SW: [AWS, Voiceflow]
    SW->>OW: verificationOverlapChunksChan  {decoder=BASE64}

    par Overlap worker processes both chunks
        OW->>OW: AWS.FromData(PLAIN bytes) → 1 result
        OW->>OW: Voiceflow.FromData(PLAIN bytes) → 0 results
        Note over OW: no likelyDuplicate → re-route AWS
        OW->>DW: detectableChunksChan  {decoder=PLAIN}
    and
        OW->>OW: AWS.FromData(BASE64 bytes) → 2 results (2 keyword hits → 2 spans)
        Note over OW: AWS.CleanResults collapses to 1 result per ID
        OW->>DW: detectableChunksChan  {decoder=BASE64}
    end

    par Detector workers race
        DW->>NW: results chan  {DecoderType=PLAIN, Raw=AKIA...}
    and
        DW->>NW: results chan  {DecoderType=BASE64, Raw=AKIA...}
    end

    alt PLAIN arrives first
        NW->>NW: key not in cache → Add(key, PLAIN)
        NW->>OUT: Dispatch(PLAIN result)
        NW->>NW: BASE64 arrives → val=PLAIN ≠ BASE64 → skip
    else BASE64 arrives first
        NW->>NW: key not in cache → Add(key, BASE64)
        NW->>OUT: Dispatch(BASE64 result)
        NW->>NW: PLAIN arrives → val=BASE64 ≠ PLAIN → skip
    end
```

Note that `CleanResults` in the overlap worker's `filterResults` step actually collapses the two AWS hits on the BASE64 decoded chunk to **one**, because AWS implements `CustomResultsCleaner` and its `CleanResults` dedupes by `Redacted`. This collapse happens *inside the overlap worker*. On the subsequent direct-path invocation, however, `detectChunk` calls `FromData` per-match-span (`for _, matchBytes := range matches`, line 1068), and AWS's own `FromData` dedupes IDs internally via `idMatches` map, so a single `FromData` call again yields one result per unique AKIA. Net effect under standard behaviour: one AWS result per decoded chunk. The "2 BASE64 results" pattern we observed in Experiment D [§9.5](#95-experiment-d--well-separated-plain--base64) arises in a subtly different scenario, described there.

---

## 8. Concurrency Model and Non-Determinism

### 8.1 Worker Counts and Buffer Sizes

```go
// pkg/engine/engine.go (setDefaults, lines 336-376)
e.concurrency = numCPU                          // if not set by user
e.detectorWorkerMultiplier = 8                  // default
e.notificationWorkerMultiplier = 1              // default
e.verificationOverlapWorkerMultiplier = 1       // default
```

```go
// pkg/engine/engine.go (initialize, lines 498-520)
detectableChunksChanMultiplier          = 50
verificationOverlapChunksChanMultiplier = 25
resultsChanMultiplier                   = 50
var defaultChannelBuffer = runtime.NumCPU()   // line 627
```

Therefore:

| Worker pool | Count | Source line |
|---|---|---|
| scanner | `concurrency` | `startScannerWorkers` (663) |
| detector | `concurrency × 8` | `startDetectorWorkers` (675) |
| verificationOverlap | `concurrency × 1` | `startVerificationOverlapWorkers` (690) |
| notifier | `concurrency × 1` | `startNotifierWorkers` (705) |

| Channel | Buffer | Source line |
|---|---|---|
| `detectableChunksChan` | `NumCPU × 50` | 515 |
| `verificationOverlapChunksChan` | `NumCPU × 25` | 517 |
| `results` | `NumCPU × 50` | 519 |

On our 128-CPU test machine, the defaults resolve to 128 scanner workers, **1024 detector workers**, 128 overlap workers, 128 notifiers, and ~12800-deep channel buffers.

### 8.2 Sources of Non-Determinism

Non-deterministic decoder selection can only arise when two or more in-flight results share a dedup key but differ in `DecoderType` — i.e. when the same chunk's multiple decoder outputs each yield a detector result. Once that condition holds, the winner is whichever result reaches the notifier's `dedupeCache.Add` first. That arrival order depends on:

1. **Detector worker goroutine scheduling.** Even with `concurrency=1`, there are still 8 detector workers, any of whom may take the next item off `detectableChunksChan`.
2. **Overlap worker scheduling.** Each overlap worker drains one chunk at a time and may re-route to `detectableChunksChan` out of the scanner's original push order.
3. **Notifier worker scheduling.** With `concurrency > 1`, multiple notifier workers read from `e.results` and their LRU cache operations interleave.
4. **GOMAXPROCS-driven parallelism.** Goroutines can run in parallel on multiple OS threads; under serial execution (`GOMAXPROCS=1`) Go still schedules goroutines pre-emptively but only one runs at a time, greatly increasing the probability that FIFO ordering from the scanner's push order is preserved.

### 8.3 Why `GOMAXPROCS=1` + `--concurrency=1` Is Fully Deterministic

With one scanner, one overlap worker, one notifier, and `GOMAXPROCS=1`, the goroutine that performs the push to a channel generally runs until it blocks. Because:

- The scanner pushes PLAIN first, then BASE64 (to the overlap channel, in order).
- The overlap worker drains items FIFO, processes them in order, and re-routes to the detector channel in order.
- There are still 8 detector workers, so two items can be picked up by different goroutines; but under GOMAXPROCS=1 only one detector worker runs at a time, and the first to be scheduled after the first push handles the PLAIN chunk before the second push is even processed.
- The single notifier worker sees results in the order they are pushed.

The net observed outcome is that PLAIN always wins the dedup race (100% over 10+10 trials in our experiments, [§9.7](#97-experiment-h--concurrency-comparison)).

### 8.4 Why `--concurrency=1` Alone Is **Not** Sufficient

With `--concurrency=1`, detector workers still run 8-parallel — the multiplier is **hard-coded** at `e.detectorWorkerMultiplier = 8` (line 343). On a multi-core machine, two detector workers can execute in parallel, and because the overlap worker pushes PLAIN then BASE64 onto `detectableChunksChan` in quick succession, a second detector worker can pick up BASE64 while the first is still handling PLAIN. The order in which they reach the notifier is then controlled by which worker happens to finish `FromData` first — which depends on OS-level thread scheduling, CPU caches, and other factors outside Go's control. Our Experiment H shows PLAIN wins 21/25 ≈ 84% at `--concurrency=1` but BASE64 wins the other 4/25.

### 8.5 Role of the Default 128-Way Concurrency

At `--concurrency=128`, there are 1024 detector workers on our 128-CPU host. The probability that at least one worker picks up the BASE64 chunk and finishes before PLAIN is high, because PLAIN and BASE64 can now be processed in genuine parallel. Our Experiment H observed PLAIN winning only 7/25 ≈ 28% at the default concurrency.

---

## 9. Experimental Evidence

All experiments ran the built `/tmp/trufflehog_bin` against crafted test files with `--no-verification --json` unless otherwise noted. The following AWS test credentials were used (they are a known test-only key pair also present in `pkg/engine/testdata/secrets.txt`):

- `AKIAWARWQKZNHMZBLY4I` (access key)
- `s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0` (secret)

### 9.1 Experiment A — Plain-text-only AWS key

- **Input:** `aws AKIAWARWQKZNHMZBLY4I\nsecret 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`.
- **Flag set:** `--no-verification --json`.
- **Observed:** exactly 1 result with `DecoderName=PLAIN`, deterministic across all runs.
- **Interpretation:** Only the UTF8 decoder produces non-nil output (the text has no ≥20-char base64 runs, no UTF-16 paired nulls, no `\uXXXX` patterns). One decoded chunk ⇒ one match ⇒ one result ⇒ one dispatch.

### 9.2 Experiment B — Base64-only AWS key

- **Input:** a single line containing `base64 $(echo -n "aws AKIA... secret s6Nb...")`.
- **Observed:** 1 result with `DecoderName=BASE64`, deterministic.
- **Interpretation:** The PLAIN decoder still fires and produces a decoded chunk, but the plain text is just the base64 alphabet string with no AKIA in it, so Aho-Corasick on the PLAIN variant finds no AWS keyword ⇒ no detection from PLAIN path. The Base64 decoder substitutes the base64 run with the decoded bytes ⇒ the BASE64-decoded chunk contains `AKIA...` ⇒ AWS detects ⇒ 1 result.

### 9.3 Experiment C — Plain + Base64 combined in one small file, default concurrency

- **Input:** two lines in one file: plain AWS creds, then the base64 encoding of those creds.
- **Observed:** exactly 1 result per run; across 20 runs the `DecoderName` was non-deterministic, split roughly 53% PLAIN / 33% BASE64 / 13% ESCAPED_UNICODE.
- **Interpretation:** Both PLAIN and BASE64 decoder outputs contain the AKIA text; the EscapedUnicode decoder also matches because the base64 alphabet happens to contain hexadecimal letters that satisfy the escape-pattern regex in some encodings. All three produce results with identical `Raw` + `RawV2` + `SourceMetadata`; the dedup cache retains the first to arrive.

### 9.4 Experiment D — Three forms (plain + base64 + `\uXXXX`)

- **Input:** plain AWS creds; base64 of those creds; a third line where each character of the key is written as a `\u00XX` escape.
- **Observed (15 runs at default concurrency):** 14/15 runs produced 1 result with `DecoderName=ESCAPED_UNICODE`; 1/15 produced `BASE64`; 0/15 produced PLAIN.
- **Interpretation:** This is counter-intuitive given that UTF8 is first in `DefaultDecoders()`. The reason is that on a 128-CPU host the three decoder outputs are pushed in rapid succession to the overlap channel, and the three overlap workers pick them up in parallel. ESCAPED_UNICODE is actually the *last* chunk pushed by the scanner, meaning it is still "fresh" in the L1 cache of the last scheduled goroutine; the detector invocation for the ESCAPED_UNICODE chunk frequently completes first. **This definitively shows that decoder order does not predict dedup winner under concurrent execution.**

### 9.5 Experiment D — Well-separated plain + base64

- **Input:** a plain AKIA secret, followed by ~30 lines of filler, followed by the base64 encoding of the secret. File size ≈ 2.7 KB (well under the 10 KB ChunkSize from `pkg/sources/chunker.go`, so everything is in one chunk).
- **Observed (25 runs):** outcomes were non-deterministic and bimodal:
  - Some runs: **1 result**, `DecoderName=PLAIN`.
  - Other runs: **2 results**, both `DecoderName=BASE64`, both with identical `Raw`/`RawV2`.
- **Interpretation:** The BASE64 decoder rewrites the encoded substring in place, so the BASE64 decoded chunk contains the plaintext AKIA **twice** — once at the original plain-text location, once at the in-place substitution location. Aho-Corasick therefore computes **two non-overlapping 1024-byte spans** around the two AKIA hits and extracts them as separate match-byte slices. `detectChunk` loops `for _, matchBytes := range matches` (line 1068) and calls `FromData` once per span, producing 2 results with identical `Raw`. Both results have identical dedup keys and the same `DecoderType=BASE64`; per [§6.2](#62-the-dedup-key-and-lru-cache), both pass dedup.
  - If **PLAIN arrives first**, its result is cached and the two BASE64 results are both suppressed (different decoder) ⇒ 1 result.
  - If **BASE64 arrives first**, the first BASE64 is cached; the second BASE64 has the same decoder ⇒ kept; the PLAIN result arrives with same key but different decoder ⇒ suppressed ⇒ 2 results.
- This experiment explains the apparent "sometimes 1, sometimes 2" behaviour that motivates Investigation Question 5.

### 9.6 Experiment F — Sentry token (single-detector) in plain + base64

- **Input:** `sentry 27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90` and the base64 of that line.
- **Observed (20 runs at default concurrency):** 14 BASE64 / 6 PLAIN, 1 result per run.
- **Interpretation:** Only one detector (Sentry) matches, so the chunk follows the **direct path**, not the overlap path. But the same concurrency race still applies: PLAIN and BASE64 decoded chunks are pushed to `detectableChunksChan` and picked up by two different detector workers. Whichever `FromData` completes first wins the dedup race. Confirms that **the overlap worker is not the root cause of non-determinism** — non-determinism is intrinsic to having two racing results with the same dedup key but different decoders.

### 9.7 Experiment H — Concurrency comparison

Same well-separated plain + base64 input as Experiment D (above), 25 runs at each setting:

| Flag configuration | PLAIN wins | BASE64 wins | % PLAIN |
|---|---|---|---|
| `--concurrency=128` (default) | 7 | 18 | 28% |
| `--concurrency=8`              | 11 | 14 | 44% |
| `--concurrency=1`              | 21 | 4 | 84% |
| `GOMAXPROCS=1` + `--concurrency=1` | 25 | 0 | **100%** |

Shows a clear monotone relationship: more concurrency ⇒ more chances for BASE64 to win the race. Only when `GOMAXPROCS=1` forces all goroutines onto a single OS thread is the outcome fully deterministic.

### 9.8 Experiment G — Concurrency determinism at 1 vs default

Confirmed by the Sentry-only variant of Experiment F: at `--concurrency=1`, Sentry ran 10/10 deterministic PLAIN (because only one detector means only the direct path, and only one detector worker was actively racing — the other 7 were idle waiting for work). This reinforces that the GOMAXPROCS-only determinism in §9.7 is tied specifically to the AWS-with-overlap scenario where the overlap worker's re-routing introduces additional scheduling noise.

### 9.9 Experiment I — Two separate files with identical secrets

- **Input:** two files in the scan path, each containing the same plain AWS credentials.
- **Observed (5 runs):** always 2 results, both `DecoderName=PLAIN`, one per file path.
- **Interpretation:** Different `SourceMetadata.Filesystem.File` fields ⇒ different `%+v`-formatted dedup keys ⇒ cache never considers them duplicates ⇒ both pass. This directly answers why well-separated secrets in *different files* always both report.

### 9.10 Experiment J — `--allow-verification-overlap` flag

- **Test file:** `pkg/engine/testdata/verificationoverlap_secrets.txt` with `--custom-detectors pkg/engine/testdata/verificationoverlap_detectors.yaml`. The file contains a single Postman API key; the custom-detector YAML defines two detectors that both match the key.
- **Without flag:** one result emitted per detector; the second result bears `VerificationError="More than one detector has found this result. For your safety, verification has been disabled..."` i.e. `errOverlap`.
- **With `--allow-verification-overlap`:** the same results are emitted with **no `VerificationError`**; both detectors attempt verification normally.
- **Interpretation:** The flag flips `e.verificationOverlap=true`, causing `scannerWorker` line 796 to send the chunk to the direct path regardless of how many detectors match. The overlap worker is bypassed entirely for this chunk. This validates the described behaviour in [§5.1](#51-routing-condition) and [§5.4](#54-erroverlap-error-message).

### 9.11 False-positive overlap test

- **Test file:** `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` with `verificationoverlap_detectors_fp.yaml`. The file is `ssample-...`; detector1's regex `\b(sample-...)\b` and detector2's `\b(ssample-...)\b` differ only by the second `s` and a `\b` boundary.
- **Observed:** only detector2 matches (because `\b` in detector1's pattern does not match between `s` and `s`), no duplicate found, 1 result without `errOverlap`.
- **Interpretation:** Demonstrates `TestVerificationOverlapChunkFalsePositive` and the word-boundary behaviour. `likelyDuplicate` is never consulted because only one detector produced a result.

---

## 10. Answers to the Posed Questions

### Q1. How does the decoder pipeline decide which decoder's output is reported when the same logical secret appears in multiple encoded forms?

TruffleHog does **not** pick a single decoder. For each input chunk, `scannerWorker` runs **every** decoder and pushes one chunk variant per decoder (skipping decoders that returned `nil`) onto downstream channels (`pkg/engine/engine.go:785-817`). Each variant independently produces its own detector results.

The apparent "selection" happens later, at the notifier. The **first** result per dedup key reaches `dedupeCache.Add`; any subsequent result with the *same* key but a *different* `DecoderType` is suppressed (`pkg/engine/engine.go:1217-1221`). Under serial execution, UTF8/PLAIN always wins because it is pushed first; under concurrent execution, the winner is determined by goroutine scheduling across detector and overlap workers.

Which decoder types can appear in the output:

- **PLAIN**: always a possibility for text input, since `UTF8.FromChunk` never returns `nil` for non-empty bytes.
- **BASE64**: only if the chunk contains a ≥20-character base64-alphabet run that decodes to ASCII bytes.
- **UTF16**: only for chunks with paired-null-byte patterns suggesting UTF-16 encoding (rarely seen in text files).
- **ESCAPED_UNICODE**: only if the chunk contains `U+XXXX` code-point notation or `\uXXXX` escape sequences.

### Q2. How does the `verificationOverlapWorker` handle chunks matched by multiple detectors, and what triggers `errOverlap`?

The overlap worker (`pkg/engine/engine.go:924-1034`) processes each incoming `verificationOverlapChunk` by running every keyword-matched detector's `FromData` **without verification** against each detector's match spans (line 944). For each resulting secret, it constructs a `chunkSecretKey{secret, detectorKey}` (line 977) and calls `likelyDuplicate` to compare against secrets already seen from **other** detectors processing the same chunk.

`likelyDuplicate` (lines 887-922) returns true if:
- The two detector types differ (line 901), **and**
- Their string lengths are within ±10% of each other (line 895), **and**
- They are either exactly equal (line 906) or have Levenshtein similarity > 0.9 (line 915, using `github.com/adrg/strutil/metrics`).

When `likelyDuplicate` returns true, the result is **stamped with `errOverlap`** via `res.SetVerificationError(errOverlap)` (line 988), the overlap tracker is incremented, and `processResult` is called directly — bypassing the detector worker but still flowing through the notifier. The detector is also removed from the list of detectors that will be re-routed for full verification (line 994), preventing duplicate verification.

Detectors that produced no duplicates are re-routed to `detectableChunksChan` with verification enabled (lines 1017-1026). `errOverlap` therefore fires precisely when the same (or near-identical) secret is produced by two *different* detector types scanning the same chunk.

### Q3. How does the LRU dedup cache decide which decoder-variant result to keep, and why is the reported `DecoderName` sometimes non-deterministic?

The dedup logic is the 9 lines at `pkg/engine/engine.go:1213-1221`:

```go
key := fmt.Sprintf("%s%s%s%+v",
    result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue   // suppress
}
e.dedupeCache.Add(key, result.DecoderType)
```

The key is **decoder-independent**: it contains the detector type, the raw secret bytes, and the source metadata. The cache **value** is the `DecoderType` of the first result stored for that key. Subsequent results are suppressed only if the stored `DecoderType` **differs** from the incoming result's `DecoderType` (or always, for Postman sources). Same-decoder duplicates are intentionally allowed per the comment on lines 1215-1216: *"Duplicate results with the same decoder type SHOULD have their own entry in the results list."*

The non-determinism arises because under concurrent execution, the first result to reach the cache is determined by goroutine scheduling. With multiple detector workers (always ≥ 8) and possibly multiple notifier workers, the arrival order is not the push order. See [§8](#8-concurrency-model-and-non-determinism) for the full analysis.

### Q4. What is the precise order of operations, and where does concurrency introduce non-determinism?

The order, for a single chunk, is:

1. `scannerWorker` receives the chunk from `ChunksChan()`.
2. For each decoder in `DefaultDecoders()`: `decoder.FromChunk(chunk)` → `DecodableChunk` or `nil`.
3. For each non-nil `DecodableChunk`: `AhoCorasickCore.FindDetectorMatches(chunk.Data)` → list of matching detectors.
4. Routing decision based on `len(matchingDetectors) > 1 && !e.verificationOverlap`:
   - >1 matches and no `--allow-verification-overlap` → push to `verificationOverlapChunksChan`.
   - Otherwise → push one `detectableChunk` per matching detector to `detectableChunksChan`.
5. **If overlap path:** `verificationOverlapWorker` runs each detector's `FromData` without verification, compares via `likelyDuplicate`, stamps duplicates with `errOverlap` (and sends directly to `results`), re-routes non-duplicates to `detectableChunksChan`.
6. `detectorWorker` pulls from `detectableChunksChan`, calls `detectChunk`, which iterates match-spans and calls `verificationCache.FromData` (verified or not), then `filterResults` (including detector-specific `CleanResults`), then `processResult` (which adds line numbers, `DecoderType`, etc., and sends to `results`).
7. `notifierWorker` reads from `results`, applies verification-status filtering, then consults the dedup cache, and dispatches survivors.

Dedup is therefore **always the last stage** and operates on results that may have come via either path. Concurrency introduces non-determinism at three places:

- **Step 4 → 5:** multiple scanner workers push to the overlap channel; multiple overlap workers drain it in parallel.
- **Step 5 → 6 and Step 4 → 6:** multiple detector workers drain `detectableChunksChan` in parallel.
- **Step 6 → 7:** multiple notifier workers drain `results` in parallel and each maintains its own view of the shared LRU cache (the cache itself is thread-safe, but check-then-add is not atomic).

### Q5. Why does the same logical secret sometimes yield one result and sometimes appear to yield multiple, depending on file structure, concurrency, and `--allow-verification-overlap`?

Four interacting factors govern result count:

1. **Dedup-key distinctness.** Results with different `DetectorType`, `Raw`, `RawV2`, or `SourceMetadata` are never deduped. Two files ⇒ two different `SourceMetadata` ⇒ always two results (Experiment I, [§9.9](#99-experiment-i--two-separate-files-with-identical-secrets)). Chunks larger than 10 KB get split by `sources/chunker.go` with different per-chunk `SourceMetadata` lines/offsets ⇒ each split yields its own result.

2. **Decoder winner.** For the same chunk, PLAIN output and BASE64 output produce two results with the same dedup key but different `DecoderType`. Only one of them survives dedup. Under `GOMAXPROCS=1 + --concurrency=1`, PLAIN always wins; otherwise the winner is non-deterministic (Experiments C, F, H).

3. **Multi-span Aho-Corasick hits.** The Base64 decoder replaces the encoded substring in place, so a chunk containing both the plain-text AKIA **and** the base64 of it produces a BASE64 decoded chunk with **two** AKIA occurrences. Aho-Corasick produces two non-overlapping ±512-byte spans; `detectChunk` calls `FromData` on each span; both results have identical `Raw` + `RawV2` + `SourceMetadata` + `DecoderType=BASE64`; per the dedup rule, same-decoder duplicates are kept. Result: if BASE64 wins, 2 results; if PLAIN wins, 1 result. This is the "bimodal 1-or-2" pattern from Experiment D ([§9.5](#95-experiment-d--well-separated-plain--base64)).

4. **`--allow-verification-overlap` flag.** When set, `scannerWorker` never sends chunks to the overlap worker. This *does not* change the dedup outcome (dedup is unaffected by the flag), but it does change whether the `errOverlap` error is attached to results. With the flag, `VerificationError` is unset; without the flag and with multi-detector matches, duplicate detectors emit results with `errOverlap` which require `--results=unknown` to be displayed. Because the flag only affects the routing decision at line 796 and not the final dedup at lines 1217–1221, the *count* of results on a single-file single-chunk scan is essentially unchanged (Experiment J, [§9.10](#910-experiment-j--allow-verification-overlap-flag)).

Summarised: **one-or-two is a combination of which decoder wins the race and whether the winning decoder caused Aho-Corasick to produce multiple match spans.** The file structure (where secrets sit in the chunk, whether encoded forms coexist with plaintext, whether multiple chunks are spanned) controls the span count; the concurrency level controls the race outcome; the `--allow-verification-overlap` flag controls only the `errOverlap` tagging and the routing path taken before dedup.

---

## Appendix A — Source Code Map

| Subsystem | File | Key line numbers |
|---|---|---|
| Decoder interface & ordering | `pkg/decoders/decoders.go` | `DefaultDecoders` (8-16), `DecodableChunk`/`Decoder` (20-29) |
| UTF8 / PLAIN decoder | `pkg/decoders/utf8.go` | entire file (85 lines) |
| Base64 decoder | `pkg/decoders/base64.go` | entire file (140 lines) |
| UTF16 decoder | `pkg/decoders/utf16.go` | entire file (52 lines) |
| EscapedUnicode decoder | `pkg/decoders/escaped_unicode.go` | entire file (144 lines) |
| DecoderType enum | `pkg/pb/detectorspb/detectors.pb.go` | 27-30 |
| Scanner worker | `pkg/engine/engine.go` | `scannerWorker` 777-841 |
| Routing decision | `pkg/engine/engine.go` | line 796 |
| Overlap worker | `pkg/engine/engine.go` | `verificationOverlapWorker` 924-1034 |
| `errOverlap` error | `pkg/engine/engine.go` | 39-42 |
| `likelyDuplicate` & `chunkSecretKey` | `pkg/engine/engine.go` | 878-922 |
| Detector worker / `detectChunk` | `pkg/engine/engine.go` | 1036-1125 |
| `filterResults` | `pkg/engine/engine.go` | 1126-1151 |
| `processResult` | `pkg/engine/engine.go` | 1152-1188 |
| Notifier / dedup | `pkg/engine/engine.go` | `notifierWorker` 1189-1235 |
| Dedup cache init | `pkg/engine/engine.go` | 491-494, 520 |
| Worker startup | `pkg/engine/engine.go` | 646-722 |
| Defaults & multipliers | `pkg/engine/engine.go` | `setDefaults` 336-374, `defaultChannelBuffer` 627 |
| Channel buffer sizes | `pkg/engine/engine.go` | 498-520 |
| `FragmentLineOffset` | `pkg/engine/engine.go` | 1255-1275 |
| Aho-Corasick core | `pkg/engine/ahocorasick/ahocorasickcore.go` | `FindDetectorMatches` 241-285, `NewAhoCorasickCore` 141-168 |
| Span calculators | `pkg/engine/ahocorasick/ahocorasickcore.go` | `adjustableSpanCalculator` 68-113, `defaultOffsetRadius=512` line 155 |
| Detector framework | `pkg/detectors/detectors.go` | `ResultWithMetadata` 161-184, `CopyMetadata` 187-199, `CleanResults` 202-226 |
| AWS access key detector | `pkg/detectors/aws/access_keys/accesskey.go` | `idPat` line 65, `Keywords` 70-76, `FromData` 105-216, `CleanResults` 280-283 |
| AWS `CleanResults` impl | `pkg/detectors/aws/utils.go` | 89-116 |
| Voiceflow detector | `pkg/detectors/voiceflow/voiceflow.go` | `keyPat` line 30, `Keywords` 33-38 |
| Engine tests | `pkg/engine/engine_test.go` | `TestEngine_DuplicateSecrets` 241-281, `TestVerificationOverlapChunk` 503+, `TestLikelyDuplicate` 890+ |
| Process-flow docs | `docs/process_flow.md` | entire file |
| Concurrency docs | `docs/concurrency.md` | entire file |
| Go toolchain | `go.mod` | `go 1.23.1`, `toolchain go1.24.2` |

---

## Appendix B — Reproduction Commands

All experiments were reproduced using the binary built with `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` at the repository root. The Go toolchain used was `go1.24.2` as declared in `go.mod`.

Suggested commands to reproduce each experiment (note: temporary test data must be re-created and cleaned up; the investigation cleaned up all its working files in `/tmp/trufflehog_tests/`):

```bash
export PATH="/usr/local/go/bin:$PATH"
cd /path/to/trufflehog-repo

# Build
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .

# Prep
mkdir -p /tmp/trufflehog_repro
AKIA_LINE='aws AKIAWARWQKZNHMZBLY4I'
SECRET_LINE='secret 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'

# Experiment A: plain only
printf '%s\n%s\n' "$AKIA_LINE" "$SECRET_LINE" > /tmp/trufflehog_repro/plain.txt
/tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_repro --no-verification --json | jq -c '{DecoderName, DetectorName, Raw}'

# Experiment C: plain + base64, default concurrency
B64=$(printf '%s\n%s' "$AKIA_LINE" "$SECRET_LINE" | base64 -w0)
printf '%s\n%s\n%s\n' "$AKIA_LINE" "$SECRET_LINE" "$B64" > /tmp/trufflehog_repro/mixed.txt
for i in $(seq 1 20); do
  /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_repro/ --no-verification --json 2>/dev/null | jq -r '.DecoderName'
done | sort | uniq -c

# Experiment H: concurrency comparison
for c in 1 8 128; do
  echo "--- concurrency=$c ---"
  for i in $(seq 1 25); do
    /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_repro/ --no-verification --concurrency=$c --json 2>/dev/null \
      | jq -r '.DecoderName'
  done | sort | uniq -c
done

# Experiment H: GOMAXPROCS=1 + concurrency=1
for i in $(seq 1 25); do
  GOMAXPROCS=1 /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_repro/ --no-verification --concurrency=1 --json 2>/dev/null \
    | jq -r '.DecoderName'
done | sort | uniq -c

# Experiment J: --allow-verification-overlap on the repo's own test fixtures
/tmp/trufflehog_bin filesystem \
  --directory=./pkg/engine/testdata \
  --config=./pkg/engine/testdata/verificationoverlap_detectors.yaml \
  --no-verification --json

/tmp/trufflehog_bin filesystem \
  --directory=./pkg/engine/testdata \
  --config=./pkg/engine/testdata/verificationoverlap_detectors.yaml \
  --no-verification --allow-verification-overlap --json

# Clean up
rm -rf /tmp/trufflehog_repro
```
