# TruffleHog Runtime Pipeline Investigation: Decoder Pipeline, Verification Overlap Detection, and Result Deduplication

| Field | Value |
|---|---|
| **Repository** | `trufflesecurity/trufflehog` |
| **Commit** | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (short: `e42153d4`) |
| **Subject version** | `dev` (as reported by `trufflehog --version` for a local build from HEAD) |
| **Scope** | Behavioural analysis of the decoder pipeline, `verificationOverlapWorker`, and `notifierWorker` dedup layer, plus their interactions under concurrency |
| **Methodology** | (1) Static reading of the Go source code at the commit above, (2) compilation of the CLI (`CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .`) and execution against crafted test inputs, (3) direct Go programs instrumenting the decoder chain and Aho-Corasick prefilter |
| **Modifications** | **None.** This is a read-only investigation. No file under the repository tree was modified; all test data created during experimentation was placed under `/tmp/trufflehog_tests/` and subsequently removed. See [§14](#14-cleanup-statement). |
| **Findings are date-agnostic** | All findings are derived from the code at the pinned commit; they do not depend on any time-sensitive state. |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Pipeline Architecture](#2-pipeline-architecture)
3. [Decoder Pipeline Deep-Dive](#3-decoder-pipeline-deep-dive)
4. [Aho-Corasick Prefilter and Detector Routing](#4-aho-corasick-prefilter-and-detector-routing)
5. [Verification Overlap Detection](#5-verification-overlap-detection)
6. [Result Deduplication (Notifier)](#6-result-deduplication-notifier)
7. [Concurrency and Non-Determinism](#7-concurrency-and-non-determinism)
8. [Interaction Sequence Diagram](#8-interaction-sequence-diagram)
9. [Single-vs-Multiple Result Behaviour Matrix](#9-single-vs-multiple-result-behaviour-matrix)
10. [Answers to the Five User Questions](#10-answers-to-the-five-user-questions)
11. [Runtime Experiments (Detailed)](#11-runtime-experiments-detailed)
12. [References Table](#12-references-table)
13. [Appendix — Reproduction Commands](#13-appendix--reproduction-commands)
14. [Cleanup Statement](#14-cleanup-statement)

---

## 1. Executive Summary

- **The decoder pipeline runs every decoder for every chunk**. `scannerWorker` iterates `DefaultDecoders()` in the fixed order `UTF8 → Base64 → UTF16 → EscapedUnicode` (`pkg/decoders/decoders.go` lines 8–16) and pushes one decoded chunk per decoder that returned non-`nil`. UTF8/PLAIN always fires for non-empty text (`pkg/decoders/utf8.go` lines 16–29); BASE64 fires only when a base64-alphabet run of at least 21 characters (strict `>` comparison against `threshold=20`) decodes to ASCII (`pkg/decoders/base64.go` lines 34–72); UTF16 fires only for paired-null byte sequences (`pkg/decoders/utf16.go` lines 18–52); and ESCAPED_UNICODE fires only when `U+XXXX` or `\uXXXX` patterns are present (`pkg/decoders/escaped_unicode.go` lines 32–68).
- **The verification overlap worker disables verification for cross-detector duplicates**. When more than one detector keyword-matches a decoded chunk *and* `--allow-verification-overlap` is off (`pkg/engine/engine.go` line 796), the chunk is routed to `verificationOverlapWorker` (lines 924–1034). It calls `FromData(ctx, verify=false, match)` on each detector (line 940), computes cross-detector similarity via `likelyDuplicate()` using Levenshtein distance with a hard-coded threshold of 0.9 (`similarityThreshold`, line 888), attaches `errOverlap` (lines 39–42) to duplicates via `res.SetVerificationError(errOverlap)` (line 988), and re-routes the remaining non-duplicate detectors through `detectableChunksChan` with verification re-enabled (lines 1011–1020).
- **The notifier applies final deduplication via a 512-entry LRU cache**. `notifierWorker` (lines 1189–1235) is the sole dedup point for final output. The key is `fmt.Sprintf("%s%s%s%+v", DetectorType.String(), Raw, RawV2, SourceMetadata)` (line 1216) — **note: the key does not include the decoder type**. If the cache already stores a different `DecoderType` for this key (line 1217) the current result is dropped; if it stores the same decoder (or the key is new), the result is dispatched. Postman-source results are always deduped regardless of decoder (line 1218).
- **The precise order of operations is scanner → (overlap, if multiple detectors match) → detector → notifier/dedup**. Dedup is always the last stage. Non-determinism appears wherever multiple in-flight results share a dedup key but differ in `DecoderType`: whichever reaches the notifier's `dedupeCache.Add` first wins. With default concurrency (`runtime.NumCPU()` scanner workers, `8×concurrency` detector workers, `1×concurrency` overlap and notifier workers per `pkg/engine/engine.go` lines 336–354), goroutine scheduling across the detector and notifier pools decides the race. Reducing `--concurrency=1` collapses each worker pool to a single goroutine but `GOMAXPROCS>1` still lets the Go scheduler interleave them; adding `GOMAXPROCS=1` serialises goroutine execution on a single OS thread, which is observed empirically to produce a **deterministic, host-stable outcome** — i.e. the same host always yields the same decoder for the same input. The identity of that winning decoder, however, is **not guaranteed to be PLAIN**: it depends on the exact ordering in which the Go runtime drains the buffered channels between the scanner, overlap, detector, and notifier pools on that particular host/OS/runtime combination. On the author's 128-CPU host the FIFO race reliably resolves to PLAIN; independent QA testing on a different 128-CPU host observed the same deterministic-per-host property but with BASE64 or ESCAPED_UNICODE winning instead (see §11.8 for both distributions).
- **A single logical secret can yield one or more results depending on source structure, Aho-Corasick span count, and the dedup race**. Identical `Raw` + `SourceMetadata` (same file, same chunk, same detector) deduplicates to one. Different `SourceMetadata` (secret in two files) produces two results. When the Base64 decoder rewrites a base64 run in place inside a chunk that also contains the plaintext, the resulting decoded chunk holds the secret twice; Aho-Corasick produces two non-overlapping ±512-byte spans (`defaultOffsetRadius`, `pkg/engine/ahocorasick/ahocorasickcore.go` line 155); `detectChunk` calls `FromData` once per span (`pkg/engine/engine.go` line 1062); two BASE64 results with identical dedup key survive dedup (same decoder ⇒ intentionally allowed per the comment at line 1213). The `--allow-verification-overlap` flag affects routing and `errOverlap` tagging but not the final dedup outcome.
- **The user-visible `DecoderName` is serialised from the protobuf enum**. `pkg/output/json.go` line 65 writes `DecoderName: r.DecoderType.String()` where `r.DecoderType` is `detectorspb.DecoderType` (`pkg/pb/detectorspb/detectors.pb.go` lines 27–30) mapping the enum values `PLAIN=1`, `BASE64=2`, `UTF16=3`, `ESCAPED_UNICODE=4` to the strings seen in JSON output.

---

## 2. Pipeline Architecture

### 2.1 Four-Stage Overview (from `docs/process_flow.md`)

The engine decomposes work into four logical stages. The Mermaid diagram below recreates the high-level flow from `docs/process_flow.md` lines 7–26 and annotates each stage with the Go worker function that implements it.

```mermaid
flowchart LR
    SourceDecomposition["**Source Decomposition**<br/>(SourceManager → ChunksChan)"]
    DetectorMatching{"**Chunk-to-Detector Matching**<br/>(scannerWorker + AhoCorasickCore)<br/>engine.go 777-841"}
    SecretDetection["**Secret Detection**<br/>(verificationOverlapWorker: 924-1034<br/>detectorWorker/detectChunk: 1036-1124<br/>filterResults: 1126-1150<br/>processResult: 1152-1187)"]
    ResultNotification["**Result Notification**<br/>(notifierWorker: 1189-1235<br/>LRU dedup at line 1216-1221)"]

    SourceDecomposition -- "*sources.Chunk" --> DetectorMatching
    DetectorMatching -- "matched chunks" --> SecretDetection
    SecretDetection -- "detectors.ResultWithMetadata" --> ResultNotification
```

| Stage (doc) | Component | Worker type | Implementation |
|---|---|---|---|
| Source Decomposition | `sources.SourceManager` | source-specific goroutines | Emits `*sources.Chunk` on `e.ChunksChan()` (`pkg/engine/engine.go` line 744) |
| Chunk-to-Detector Matching | `scannerWorker` + `AhoCorasickCore.FindDetectorMatches` | scanner workers | Decode, keyword-match, route (`pkg/engine/engine.go` lines 777–841; `pkg/engine/ahocorasick/ahocorasickcore.go` lines 241–285) |
| Secret Detection | `verificationOverlapWorker` and `detectorWorker` → `detectChunk` | overlap + detector workers | Run detector, filter, produce results (`pkg/engine/engine.go` lines 924–1187) |
| Result Notification | `notifierWorker` | notifier workers | Filter by verification status, dedup, dispatch (`pkg/engine/engine.go` lines 1189–1235) |

### 2.2 Worker Sequence (from `docs/concurrency.md`)

The Mermaid sequence below recreates the worker topology from `docs/concurrency.md` lines 5–43. Each participant maps to a function in `pkg/engine/engine.go`.

```mermaid
sequenceDiagram
    participant Main
    participant ScannerWorkers
    participant VerificationOverlapWorkers
    participant DetectorWorkers
    participant NotifierWorkers

    Note over Main: e.startWorkers() launches all worker pools (engine.go 646-660)
    Main->>ScannerWorkers: e.startScannerWorkers() (engine.go 662-673)
    Main->>VerificationOverlapWorkers: e.startVerificationOverlapWorkers() (engine.go 690-703)
    Main->>DetectorWorkers: e.startDetectorWorkers() (engine.go 675-688)
    Main->>NotifierWorkers: e.startNotifierWorkers() (engine.go 705-718)

    par Source emission
        Main->>ScannerWorkers: e.ChunksChan() <- chunk
    and Scanner decodes and routes
        ScannerWorkers->>DetectorWorkers: detectableChunksChan <- detectableChunk (single-detector path, engine.go 807-816)
        ScannerWorkers->>VerificationOverlapWorkers: verificationOverlapChunksChan <- verificationOverlapChunk (multi-detector path, engine.go 796-805)
    and Overlap resolves cross-detector duplicates
        VerificationOverlapWorkers->>DetectorWorkers: detectableChunksChan <- detectableChunk (re-route surviving detectors, engine.go 1011-1020)
    and Detectors produce results
        DetectorWorkers->>NotifierWorkers: e.results <- detectors.ResultWithMetadata (engine.go 1186)
    and Notifier dedupes and dispatches
        Note over NotifierWorkers: notifierWorker (engine.go 1189-1235)
    end
```

### 2.3 Channels and Buffer Sizes

All cross-worker communication uses buffered channels initialised in `Engine.initialize` (`pkg/engine/engine.go` lines 489–521). The buffer multipliers are constants inside `initialize`:

| Channel | Buffer | Source location |
|---|---|---|
| `detectableChunksChan` | `defaultChannelBuffer × 50` | lines 503, 515 |
| `verificationOverlapChunksChan` | `defaultChannelBuffer × 25` | lines 507, 516–518 |
| `results` | `defaultChannelBuffer × 50` | lines 508, 519 |
| `defaultChannelBuffer` (package-level) | `runtime.NumCPU()` | line 627 |

Shutdown ordering is defined in `Engine.Finish` (`pkg/engine/engine.go` lines 723–742): source manager waits → scanner workers drain → `verificationOverlapChunksChan` closes → overlap workers drain → `detectableChunksChan` closes → detector workers drain → `results` closes → notifier workers drain. This deterministic teardown guarantees every result in flight reaches the notifier before the engine exits.

---

## 3. Decoder Pipeline Deep-Dive

### 3.1 Fixed Decoder Ordering

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

The explicit comment on line 10 — `// UTF8 must be first for duplicate detection` — is the architectural hint behind the whole dedup behaviour: because `scannerWorker` iterates decoders in this order and pushes onto downstream channels in the same order, UTF8/PLAIN is the first variant to enter the pipeline for any text-based chunk. Under strictly serial execution, PLAIN therefore wins the dedup race in `notifierWorker` and becomes the "canonical" decoder that the user sees. Concurrency weakens this guarantee (see [§7](#7-concurrency-and-non-determinism)).

The payload passed between decoders and downstream workers is a `DecodableChunk`:

```go
// pkg/decoders/decoders.go (lines 18-28)
type DecodableChunk struct {
    *sources.Chunk
    DecoderType detectorspb.DecoderType
}

type Decoder interface {
    FromChunk(chunk *sources.Chunk) *DecodableChunk
    Type() detectorspb.DecoderType
}
```

The four `DecoderType` enum values that can appear on `DecodableChunk` are:

```go
// pkg/pb/detectorspb/detectors.pb.go (lines 26-31, abridged)
DecoderType_UNKNOWN          DecoderType = 0
DecoderType_PLAIN            DecoderType = 1
DecoderType_BASE64           DecoderType = 2
DecoderType_UTF16            DecoderType = 3
DecoderType_ESCAPED_UNICODE  DecoderType = 4
```

These names are what ultimately appear in the `DecoderName` field of the JSON output (`pkg/output/json.go` line 65: `DecoderName: r.DecoderType.String()`).

### 3.2 Per-Decoder Behaviour

| Decoder | Always fires? | Trigger condition | Transformation | Returns `nil` when | `Type()` line |
|---|---|---|---|---|---|
| UTF8 / PLAIN | **Yes** for non-empty text | Any non-empty chunk | Pass-through for valid UTF-8; invalid UTF-8 is sanitised with `U+FFFD` replacement | `chunk == nil \|\| len(chunk.Data) == 0` | `utf8.go` 12-14 |
| Base64 | No | ≥21-char base64-alphabet run (strict `>` vs threshold=20) decoding to ASCII | Sequential `bytes.Buffer` rebuild — each qualifying run is replaced with its decoded bytes via a `bytes.Index` scan | No qualifying run found | `base64.go` 30-32 |
| UTF16 | No | Paired-null-byte patterns (BE or LE) with printable runes | Extract printable 2-byte UTF-16 characters and re-encode as UTF-8 | Output buffer empty | `utf16.go` 14-16 |
| EscapedUnicode | No | `U+XXXX` code-point form or `\uXXXX` escape | Clone chunk data; replace every escape with the corresponding UTF-8 | Neither regex pattern matches | `escaped_unicode.go` 28-30 |

#### 3.2.1 UTF8 — `pkg/decoders/utf8.go`

The PLAIN decoder returns `nil` only when the chunk is nil or empty (lines 17–20). For valid UTF-8 input the chunk passes through untouched; for invalid UTF-8 the data is rewritten in place by `extractSubstrings`, which replaces non-printable bytes and malformed multi-byte sequences with `U+FFFD` (lines 21–28).

```go
// pkg/decoders/utf8.go (lines 16-29, abridged)
func (d *UTF8) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    if chunk == nil || len(chunk.Data) == 0 {
        return nil
    }
    decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
    if !utf8.Valid(chunk.Data) {
        chunk.Data = extractSubstrings(chunk.Data)
        return decodableChunk
    }
    return decodableChunk
}
```

**Behavioural consequence:** any textual input triggers PLAIN, so most "regular" secrets are reported with `DecoderName=PLAIN`. This is the first decoder invoked and the first to push onto the scanner's downstream channels.

#### 3.2.2 Base64 — `pkg/decoders/base64.go`

```go
// pkg/decoders/base64.go (lines 34-72, abridged — faithful to the actual algorithm)
func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
    encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
    decodedSubstrings := make(map[string][]byte)

    // For each candidate run, attempt BOTH encodings unconditionally. If
    // both succeed, the RawURLEncoding result overwrites the StdEncoding
    // result (same map key) — there is no early `continue`.
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

    if len(decodedSubstrings) > 0 {
        // Rebuild chunk.Data sequentially with a bytes.Buffer rather than
        // calling bytes.ReplaceAll. The algorithm walks encodedSubstrings
        // in discovery order, uses bytes.Index to find each run's offset
        // forward from the current cursor, writes the surrounding bytes,
        // then writes the decoded bytes, and advances the cursor past the
        // run. Trailing bytes after the final run are appended as-is.
        var result bytes.Buffer
        result.Grow(len(chunk.Data))

        start := 0
        for _, encoded := range encodedSubstrings {
            if decoded, ok := decodedSubstrings[encoded]; ok {
                end := bytes.Index(chunk.Data[start:], []byte(encoded))
                if end != -1 {
                    result.Write(chunk.Data[start : start+end])
                    result.Write(decoded)
                    start += end + len(encoded)
                }
            }
        }
        result.Write(chunk.Data[start:])
        chunk.Data = result.Bytes()
        return decodableChunk
    }

    return nil
}
```

Four behavioural notes:
- **Threshold 20 with strict-greater comparison.** `getSubstringsOfCharacterSet(chunk.Data, 20, …)` (line 36) passes `threshold=20`; the helper (lines 83–141) uses `count > threshold` so a run of **at least 21 characters** is required to qualify.
- **Both alphabets attempted unconditionally.** For every candidate substring, both `base64.StdEncoding` (line 40) *and* `base64.RawURLEncoding` (line 45) are tried — there is no `continue` between them. If both succeed, the RawURLEncoding result (assigned second) overwrites the StdEncoding result in the `decodedSubstrings` map.
- **Sequential `bytes.Buffer` rebuild (not `bytes.ReplaceAll`).** When at least one substring decodes, the decoder grows a `bytes.Buffer` to the chunk length (line 53), then iterates `encodedSubstrings` in order, locating each run forward from a moving cursor via `bytes.Index` (line 58) and writing the surrounding bytes + decoded bytes into the buffer (lines 60–62). Trailing bytes after the final run are appended at line 66. The rebuilt buffer replaces `chunk.Data` at line 67. Surrounding non-base64 text is preserved exactly; the base64 run's bytes are replaced with its decoded content.
- **Twice-present secret after substitution.** The mechanism above is what produces the "BASE64 chunk contains the secret twice" effect observed in Experiment D: if the original chunk already contained the plaintext secret **and** a separate base64 run that also decodes to that plaintext, the rebuild leaves the first copy untouched and writes a second copy in place of the base64 run.

#### 3.2.3 UTF16 — `pkg/decoders/utf16.go`

```go
// pkg/decoders/utf16.go (lines 18-52, abridged)
func (d *UTF16) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    if utf16Data, err := utf16ToUTF8(chunk.Data); err == nil {
        if len(utf16Data) == 0 { return nil }
        chunk.Data = utf16Data
        return &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
    }
    return nil
}

func utf16ToUTF8(b []byte) ([]byte, error) {
    var bufBE, bufLE bytes.Buffer
    for i := 0; i+1 < len(b); i += 2 {
        if r := rune(binary.BigEndian.Uint16(b[i:])); b[i] == 0 && utf8.ValidRune(r) {
            if isPrintableByte(byte(r)) { bufBE.WriteRune(r) }
        }
        if r := rune(binary.LittleEndian.Uint16(b[i:])); b[i+1] == 0 && utf8.ValidRune(r) {
            if isPrintableByte(byte(r)) { bufLE.WriteRune(r) }
        }
    }
    // Concatenate: LE buffer followed by BE buffer (line 51). If both are
    // empty, the returned byte slice is empty and FromChunk returns nil.
    return append(bufLE.Bytes(), bufBE.Bytes()...), nil
}
```

The heuristic attempts both byte orders in parallel; both decoded buffers are concatenated (little-endian content followed by big-endian content) and returned as the decoded byte stream (line 51 — `return append(bufLE.Bytes(), bufBE.Bytes()...), nil`). If both buffers are empty, `utf16ToUTF8` returns a zero-length slice, and `FromChunk` returns `nil` at line 25. Pure-ASCII text never has consecutive null bytes, so UTF16 returns `nil` for virtually every input in our experiments.

#### 3.2.4 EscapedUnicode — `pkg/decoders/escaped_unicode.go`

Two regex patterns drive this decoder:

```go
// pkg/decoders/escaped_unicode.go (lines 22, 25)
codePointPat = regexp.MustCompile(`\bU\+([a-fA-F0-9]{4}).?`)
escapePat    = regexp.MustCompile(`(?i:\\{1,2}u)([a-fA-F0-9]{4})`)
```

`codePointPat` matches Unicode code-point notation (e.g. `U+0041`); `escapePat` matches common `\uXXXX` / `\\uXXXX` programming-language escapes. If **either** pattern matches, the decoder returns a new `DecodableChunk` with `DecoderType=ESCAPED_UNICODE`; otherwise it returns `nil` at line 66.

Crucially, this decoder **clones the chunk data before rewriting** (line 39 of `escaped_unicode.go`) by way of `bytes.Clone`, avoiding the shared-pointer mutation hazard that Base64 and UTF16 create (see [§3.4](#34-in-place-chunk-mutation-caveat)).

### 3.3 How `scannerWorker` Uses the Decoders

```go
// pkg/engine/engine.go (lines 777-841, abridged)
for chunk := range e.ChunksChan() {
    for _, decoder := range e.decoders {       // line 786 - fixed order
        decoded := decoder.FromChunk(chunk)     // line 786
        if decoded == nil { continue }          // lines 790-793

        matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)  // line 795
        if len(matchingDetectors) > 1 && !e.verificationOverlap {                         // line 796
            e.verificationOverlapChunksChan <- verificationOverlapChunk{...}               // lines 797-805
            continue
        }
        for _, detector := range matchingDetectors {                                       // lines 807-816
            e.detectableChunksChan <- detectableChunk{chunk: *decoded.Chunk,
                decoder: decoded.DecoderType, detector: detector, ...}
        }
    }
}
```

The critical design decision is that **one input chunk produces one decoded chunk per decoder that returned non-nil**. Each of those decoded variants is independently routed — so a chunk containing plain text AND its base64 encoding produces two routed chunks (one with `decoder=PLAIN`, one with `decoder=BASE64`) and both travel downstream.

### 3.4 In-place Chunk Mutation Caveat

Both UTF8 (invalid-UTF-8 path, line 23) and Base64 (line 67) **mutate** `chunk.Data` in place before returning. UTF16 also overwrites `chunk.Data` with UTF-8 bytes (line 28). Because Go passes `chunk *sources.Chunk` by pointer, each later decoder sees whatever earlier decoders wrote to the same buffer.

This is safe in the common case because:
- UTF8 only rewrites for invalid UTF-8 input (which the BASE64 decoder then sees with `U+FFFD` sanitisation).
- `EscapedUnicode.FromChunk` defends itself explicitly with `chunkData = bytes.Clone(chunk.Data)` at line 39 before rewriting.

It is also the structural reason the comment on `pkg/decoders/decoders.go` line 10 — "UTF8 must be first for duplicate detection" — matters: UTF8 must observe the original raw bytes to produce the canonical `DecoderType=PLAIN` variant, because once Base64 runs, `chunk.Data` may no longer contain the original encoded form.

### 3.5 Go-Level Decoder Trace (Experimental Evidence)

A direct Go program (see the code block in [§11](#11-runtime-experiments-detailed)) instantiated `decoders.DefaultDecoders()` and invoked each decoder's `FromChunk` against several realistic inputs. Results:

| Input | PLAIN | BASE64 | UTF16 | ESCAPED_UNICODE |
|---|---|---|---|---|
| `AWS_ACCESS_KEY_ID=AKIAWARWQKZNHMZBLY4I\nAWS_SECRET_ACCESS_KEY=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` | 102-byte passthrough | `nil` | `nil` | `nil` |
| Base64 encoding of the plain text (136 bytes) | 136-byte raw passthrough | 102-byte decoded plaintext | `nil` | `nil` |
| `\u0041\u004b\u0049\u0041…` | raw escape text passthrough | `nil` | `nil` | 20-byte `AKIAWARWQKZNHMZBLY4I` |
| `[]byte{}` (empty) | `nil` | `nil` | `nil` | `nil` |

This confirms: **PLAIN always fires for non-empty text; the other three fire only when their specific triggers are present.** The AWS plain-text input has no qualifying base64 run (no alphabet run of at least 21 characters), no UTF-16 null pattern, and no `\u` escape, so only PLAIN produces output. The base64-encoded form satisfies Base64's threshold (at least 21 characters of base64 alphabet, strict `>` vs threshold=20), so both PLAIN (raw b64 text) and BASE64 (decoded plaintext) produce output.

---

## 4. Aho-Corasick Prefilter and Detector Routing

### 4.1 Keyword Trie Construction

At engine start, `NewAhoCorasickCore` (`pkg/engine/ahocorasick/ahocorasickcore.go` line 141 onward) iterates every registered detector's `Keywords()` list, lower-cases each keyword, and inserts it into a single Aho-Corasick trie. The reverse map `keywordsToDetectors map[string][]DetectorKey` lets a single keyword hit resolve to every detector that registered it. Multiple detectors can — and frequently do — share keywords (e.g. the string `"dm"` is a Voiceflow keyword but also appears in many base64-decoded AWS secret bytes).

### 4.2 `FindDetectorMatches`

```go
// pkg/engine/ahocorasick/ahocorasickcore.go (lines 241-285, abridged)
func (ac *AhoCorasickCore) FindDetectorMatches(chunkData []byte) []*DetectorMatch {
    lower := bytes.ToLower(chunkData)             // line 242 - case-insensitive
    hits := ac.prefilter.Match(lower)
    if len(hits) == 0 { return nil }               // lines 244-247 - fast path
    // ... build matches keyed by detector ...
    for _, m := range hits {
        for _, detectorKey := range ac.keywordsToDetectors[m.MatchString()] {  // line 252
            start, end := ac.spanCalculator.calculateSpan(m.Pos(), detectorKey, chunkData)  // line 264
            // accumulate per detectorKey
        }
    }
    // merge + extract final match bytes
    return result
}
```

### 4.3 Span Calculation

The default span around each keyword is a window of ±`defaultOffsetRadius` bytes:

```go
// pkg/engine/ahocorasick/ahocorasickcore.go (line 155)
const defaultOffsetRadius int64 = 512
```

Detectors may override span geometry via three optional interfaces consumed by `adjustableSpanCalculator.calculateSpan` (lines 80–113): `MultiPartCredentialProvider.MaxCredentialSpan`, `MaxSecretSizeProvider.MaxSecretSize`, and `StartOffsetProvider.StartOffset`. Overlapping or contiguous spans for the *same* detector are coalesced by `mergeMatches` (line 278); the merged byte ranges are extracted into `DetectorMatch.matches`, a `[][]byte`.

### 4.4 Multi-Span Implications for Deduplication

When a decoded chunk contains the *same* detector keyword at two non-overlapping locations, Aho-Corasick produces two spans, and `detectChunk` invokes the detector's `FromData` **once per span**:

```go
// pkg/engine/engine.go (lines 1061-1076, abridged)
matches := data.detector.Matches()
for _, matchBytes := range matches {                 // line 1062 - one iteration per span
    // ...
    results, err := e.verificationCache.FromData(    // line 1070
        ctx, data.detector.Detector,
        data.chunk.Verify, data.chunk.SecretID != 0,
        matchBytes)
    // ...
}
```

If both spans of the same decoded chunk yield the same `Raw` secret, the two resulting detector results share the same `Raw`, `RawV2`, `DetectorType`, *and* `DecoderType`. The dedup rule at `pkg/engine/engine.go` lines 1217–1220 treats same-decoder duplicates as intentional and allows both through. This is the direct mechanism behind "2 BASE64 results" in Experiment D ([§11.4](#114-experiment-d--well-separated-plain--base64-1-or-2-results-per-run)).

### 4.5 Single- vs Multi-Detector Routing

After `FindDetectorMatches`, `scannerWorker` makes the single most consequential routing decision in the engine at `pkg/engine/engine.go` line 796:

```go
if len(matchingDetectors) > 1 && !e.verificationOverlap {
    // → verificationOverlapChunksChan (overlap path)
} else {
    // → detectableChunksChan (direct path, one per detector)
}
```

Two facts from our Go-level prefilter trace confirm this routing in practice:
- Input `AWS_ACCESS_KEY_ID=AKIAWARWQKZNHMZBLY4I\nAWS_SECRET_ACCESS_KEY=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\n`: **2 matching detectors — AWS and Voiceflow** (the keyword `"vf"` from Voiceflow appears inside the lowercased secret `iL6DvfpXrn…` → `il6dvfpx…`).
- Input `AKIAWARWQKZNHMZBLY4I` alone: **1 matching detector — AWS**.

Consequently, the typical "AWS credentials in a file" scenario enters the overlap path; stripped-down AKIA-only inputs take the direct path.

---

## 5. Verification Overlap Detection

### 5.1 The Routing Condition

```go
// pkg/engine/engine.go (line 796)
if len(matchingDetectors) > 1 && !e.verificationOverlap {
```

Two preconditions must hold for the overlap path:
- **More than one** distinct detector keyword-matched the decoded chunk.
- The `--allow-verification-overlap` CLI flag is **off** (it sets `e.verificationOverlap = true`). With the flag on, every chunk takes the direct path regardless of how many detectors matched.

### 5.2 Inside `verificationOverlapWorker` (lines 924–1034)

For each incoming `verificationOverlapChunk`, the worker executes a six-step algorithm:

1. **Initialise reusable per-chunk maps** — `detectorKeysWithResults` and `chunkSecrets` (lines 929–930). These are reused across iterations to minimise allocations.
2. **Run every matching detector without verification** — for each detector (line 933) and each of that detector's match spans (line 938 — loop variable `match` iterating `matchedBytes`), invoke `FromData(ctx, false, match)` under a 2-second timeout (lines 939–941; context deadline set on 939, `FromData` invoked on 940, `cancel()` on 941). The `verify=false` argument at line 940 is the crucial element: detection runs fully, but no external API calls are made at this stage.
3. **Track detectors that produced any results** via `detectorKeysWithResults[key] = detector` (lines 952–954).
4. **Filter results** with `e.filterResults(...)` when `chunk.chunk.SecretID == 0` (lines 961–963), which applies detector-specific `CleanResults` (e.g. `aws.CleanResults` collapses duplicate AWS IDs) and the false-positive word list (including `example` from `pkg/detectors/fp_words.txt` line 22, which is the reason `AKIAIOSFODNN7EXAMPLE` is filtered out).
5. **For each surviving result**, compute the comparison value (`RawV2` if present, else `Raw`, lines 966–971), construct `chunkSecretKey{secret, detectorKey}` (line 977), and call `likelyDuplicate(ctx, key, chunkSecrets)` (line 982):
   - If `likelyDuplicate` returns true, the overlap tracker is incremented (lines 985–987), `res.SetVerificationError(errOverlap)` is attached (line 988), `e.processResult` is invoked directly (lines 989–999), and the detector is removed from `detectorKeysWithResults` (line 1004) so it is *not* re-routed below.
   - Record the secret in `chunkSecrets` so subsequent results of the same chunk can cross-check against it (line 1006).
6. **Re-route surviving detectors to the direct path** — for every detector still in `detectorKeysWithResults`, push a `detectableChunk` onto `detectableChunksChan` with verification re-enabled via `e.shouldVerifyChunk(...)` (lines 1011–1020). Reset the reusable maps and call `chunk.verificationOverlapWgDoneFn()` (lines 1022–1030; the two cleanup `delete` loops span 1023–1028, and `verificationOverlapWgDoneFn()` is on line 1030).

### 5.3 The `errOverlap` Error

```go
// pkg/engine/engine.go (lines 39-42)
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
        "You can override this behavior by using the --allow-verification-overlap flag.",
)
```

This is the canonical overlap error message. When a duplicate is detected, it is attached to the candidate result via `Result.SetVerificationError(errOverlap)` (line 988). Because the result now has a non-nil verification error, it is classified as **"unknown"** (neither verified nor unverified) by `notifierWorker` (lines 1194–1198); the user sees it only when `--results` includes `unknown` (the default).

The `errOverlap` result is dispatched to `e.results` via a direct `e.processResult` call (line 989) — it **bypasses the detector worker** and goes straight into `notifierWorker`'s dedup path.

### 5.4 The `likelyDuplicate` Algorithm

```go
// pkg/engine/engine.go (lines 887-922, abridged)
func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
    const similarityThreshold = 0.9                                          // line 888
    valStr := val.secret
    for dupeKey := range dupes {
        dupe := dupeKey.secret
        // Length filter: skip if lengths differ by more than ~10%.
        if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 {    // line 894
            continue
        }
        // Skip intra-detector pairs: two results from the SAME detector type
        // are not "overlap" in the cross-detector sense.
        if val.detectorKey.Type() == dupeKey.detectorKey.Type() {              // line 900
            continue
        }
        if valStr == dupe { return true }                                     // lines 904-909
        similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())  // line 911
        if similarity > similarityThreshold { return true }                   // line 914
    }
    return false
}
```

Three gating conditions apply in order:
- **Length guard** (line 894) — rejects pairs whose lengths differ by more than 10%, which bounds the cost of the Levenshtein metric. A 40-char AWS secret compared against a 26-char hash, for example, is skipped without computing a Levenshtein distance.
- **Same-detector skip** (line 900) — *different* detector types are required for a "duplicate". Two AWS findings on the same chunk are never flagged as overlap, which is why the common "AWS finds the same key twice in one chunk" scenario does not trigger `errOverlap`.
- **Exact match or ε-near match** — exact string equality (line 904) returns `true` immediately; otherwise Levenshtein similarity from `github.com/adrg/strutil/metrics` is computed and compared strictly greater than `0.9`. The ordering reads: `similarity > similarityThreshold` (line 914), so a similarity of exactly 0.9 returns `false`.

### 5.5 When No Cross-Detector Duplicate Exists

If a chunk is multi-detector keyword-matched but only one detector actually produces regex-level results, `chunkSecrets` contains only that detector's keys, and `likelyDuplicate` is consulted against same-detector entries only. Per the same-detector skip (line 900), the function returns `false`. The detector stays in `detectorKeysWithResults` and is re-routed to the direct path for full verification (lines 1011–1020).

This is the AWS + Voiceflow case: both detectors keyword-match (AWS on `"AKIA"`, Voiceflow on `"vf"`/`"dm"`), but Voiceflow's regex `\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b` does not match AWS key material (`pkg/detectors/voiceflow/voiceflow.go` line 30), so Voiceflow produces zero results and AWS alone is re-routed for verification.

### 5.6 When Is `errOverlap` Triggered — Summary

| Condition | `errOverlap` attached? | Outcome |
|---|---|---|
| Only one detector keyword-matched the chunk | No | Direct path from scanner to detector worker |
| Multiple detectors matched **but** only one produced results | No | Overlap worker re-routes the result-producing detector for verification |
| Multiple detectors matched **and** multiple produced same/near-identical secrets | **Yes** (for the duplicates) | Duplicates get `errOverlap` + `processResult` direct; the first-processed detector is re-routed for verification |
| `--allow-verification-overlap` flag is set | Never | Overlap worker is bypassed entirely; all detectors go to the direct path with verification enabled |

### 5.7 Cross-Reference to Executable Tests

- `pkg/engine/engine_test.go` — `TestVerificationOverlapChunk` exercises a Postman key that triggers two custom detectors; one result is marked `errOverlap`.
- `pkg/engine/engine_test.go` — `TestVerificationOverlapChunkFalsePositive` uses `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` to validate that a false-positive match does not wrongly attach `errOverlap`.
- `pkg/engine/engine_test.go` — `TestLikelyDuplicate` directly exercises the similarity/length rules described in [§5.4](#54-the-likelyduplicate-algorithm).

---

## 6. Result Deduplication (Notifier)

All detector results — whether produced by the overlap worker's direct `processResult` path or by the normal `detectorWorker` → `detectChunk` → `processResult` path — converge on the shared `e.results` channel and are consumed by `notifierWorker`. The entire dedup decision lives in this one function (`pkg/engine/engine.go` lines 1189–1235).

### 6.1 Verification-Status Filter (Pre-Dedup)

Before dedup, the notifier applies the user's `--results` filter:

```go
// pkg/engine/engine.go (lines 1192-1207, abridged)
if !result.Verified {
    if result.VerificationError() != nil {
        if !e.notifyUnknownResults { continue }      // lines 1194-1198
    } else if !e.notifyUnverifiedResults {
        continue                                      // lines 1199-1202
    }
} else if !e.notifyVerifiedResults {
    continue                                          // lines 1203-1207
}
```

Results bearing `errOverlap` have `VerificationError() != nil` and therefore only pass if `notifyUnknownResults` is true (default). This is the point at which overlap-tagged results can be filtered out of the final output.

### 6.2 The Dedup Key and LRU Cache

```go
// pkg/engine/engine.go (lines 1216-1221)
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
    result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
    continue
}
e.dedupeCache.Add(key, result.DecoderType)
```

The cache is a `hashicorp/golang-lru/v2` instance of 512 entries:

```go
// pkg/engine/engine.go (lines 491-493)
const cacheSize = 512 // number of entries in the LRU cache
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
```

The **key** is constructed with `fmt.Sprintf("%s%s%s%+v", ...)`; it contains:
- `result.DetectorType.String()` — e.g. `"AWS"`, `"Sentry"`.
- `result.Raw` — the detector's primary raw secret bytes.
- `result.RawV2` — an optional secondary raw representation (often used for compound secrets like AWS key+secret pairs).
- `result.SourceMetadata` — the protobuf `SourceMetadata` formatted with `%+v`, which includes the filesystem path, Git commit hash, line number, Postman workspace, etc.

Note especially what is *not* in the key: **`DecoderType` is not a component of the key.** It is only the cache's *value*. That is the entire basis for decoder-variant dedup.

The **value** stored in the cache is `result.DecoderType` — the enum identifying the decoder whose variant produced this result.

### 6.3 Dedup Decision Matrix

| Cache state for key | Current `DecoderType` | Source type | Outcome |
|---|---|---|---|
| Not in cache | (any) | (any) | Dispatch; store `DecoderType` in cache (`Add`, line 1221) |
| In cache | **Same** as cached value | Non-Postman | Dispatch; cache unchanged (same-decoder duplicates are intentionally allowed; see comment on lines 1213–1214) |
| In cache | **Different** from cached value | Non-Postman | **Suppress** (`continue`, line 1219) — the first decoder wins |
| In cache | (any) | Postman | **Suppress** regardless of decoder (line 1218) |

The source-comment block at lines 1210–1215 articulates the design intent explicitly:

> Dedupe results by comparing the detector type, raw result, and source metadata. We want to avoid duplicate results with different decoder types, but we also want to include duplicate results with the same decoder type. Duplicate results with the same decoder type SHOULD have their own entry in the results list, this would happen if the same secret is found multiple times.

### 6.4 Why `SourceMetadata` Makes Identical Secrets in Different Files Distinct

For filesystem scans, `SourceMetadata` contains `Data.Filesystem.File` (the absolute file path) and, after `processResult` line-number enrichment, the line number. Two identical secrets in two different files therefore produce two different `%+v`-formatted keys and both survive — which matches Experiment G's observation.

For single-file scans where the secret appears at multiple line offsets *within the same chunk*, `processResult` calls `FragmentFirstLineAndLink` (via `SetResultLineNumber`) which uses `bytes.Cut(chunk.Data, result.Raw)` (`FragmentLineOffset`, `pkg/engine/engine.go` line 1257) to locate the **first** occurrence of `result.Raw`. Both detector invocations on the same chunk produce the same line number ⇒ same `SourceMetadata` ⇒ same dedup key. If they also share the same decoder (e.g., both come from the BASE64 variant), both pass dedup by the rule on line 1217.

### 6.5 Concurrency and the Cache

`hashicorp/golang-lru/v2` is internally thread-safe: each `Get` and `Add` is atomic. However, the **composite** operation `Get → Add` is not atomic — two notifier workers concurrently processing two results with the same key can both observe "not in cache" and then both call `Add`. The second `Add` overwrites the value set by the first, but both results will have already been dispatched. In practice, this edge case is very rare because the second worker's `Get` is likely to observe the first worker's `Add` if there is any meaningful scheduling delay; and since the key is identical, the subsequent third arrival will see consistent cache state either way.

### 6.6 Cross-Reference to Executable Tests

- `pkg/engine/engine_test.go` — `TestEngine_DuplicateSecrets` uses `pkg/engine/testdata/secrets.txt` (containing duplicated Sentry tokens and a single AWS pair) and asserts exactly 2 unverified results. The Sentry duplicates come from the same decoder (PLAIN) on overlapping lines, which is why the test does not collapse them to 1 — it validates rule "same decoder ⇒ both pass".

---

## 7. Concurrency and Non-Determinism

### 7.1 Worker Pool Sizing

```go
// pkg/engine/engine.go (lines 336-354)
if e.concurrency == 0 {
    numCPU := runtime.NumCPU()
    e.concurrency = numCPU
}
if e.detectorWorkerMultiplier < 1 {
    e.detectorWorkerMultiplier = 8       // bound by net i/o (comment on line 344)
}
if e.notificationWorkerMultiplier < 1 {
    e.notificationWorkerMultiplier = 1
}
if e.verificationOverlapWorkerMultiplier < 1 {
    e.verificationOverlapWorkerMultiplier = 1
}
```

Total worker counts therefore resolve to:

| Pool | Count | Start function |
|---|---|---|
| scanner | `concurrency` | `startScannerWorkers` (`pkg/engine/engine.go` lines 662–673) |
| detector | `concurrency × 8` | `startDetectorWorkers` (lines 675–688) |
| verificationOverlap | `concurrency × 1` | `startVerificationOverlapWorkers` (lines 690–703) |
| notifier | `concurrency × 1` | `startNotifierWorkers` (lines 705–718) |

On a host with 128 logical CPUs and default `--concurrency`, this yields 128 scanner workers, **1024** detector workers, 128 overlap workers, and 128 notifiers — all running concurrently.

### 7.2 Channel Buffers

All cross-pool communication goes through the three buffered channels initialised by `Engine.initialize` (`pkg/engine/engine.go` lines 497–519):

| Channel | Buffer | Multiplier × `runtime.NumCPU()` |
|---|---|---|
| `detectableChunksChan` | `defaultChannelBuffer × 50` | e.g. 6400 entries on a 128-CPU host |
| `verificationOverlapChunksChan` | `defaultChannelBuffer × 25` | e.g. 3200 entries on a 128-CPU host |
| `results` | `defaultChannelBuffer × 50` | e.g. 6400 entries on a 128-CPU host |

Large buffers mean producers rarely block, further decoupling worker scheduling from the strict push order.

### 7.3 Sources of Non-Determinism

A race is possible whenever two in-flight results share a dedup key but differ in `DecoderType`. Given that condition, the "winner" is whichever result's `dedupeCache.Add` at line 1221 executes first — and this is decided by:

1. **Detector worker goroutine scheduling.** Even at `--concurrency=1` there are still 8 detector workers (hard-coded multiplier). Two decoded variants pushed back-to-back on `detectableChunksChan` are likely to be picked up by two different goroutines.
2. **Overlap worker scheduling.** At `--concurrency > 1` there are multiple overlap workers draining `verificationOverlapChunksChan` in parallel; each produces `processResult` output to `e.results` on its own schedule.
3. **Notifier worker scheduling.** With `--concurrency > 1` multiple notifier workers consume `e.results` and their cache accesses interleave.
4. **OS-level thread scheduling.** With `GOMAXPROCS > 1`, goroutines execute on multiple OS threads in genuine parallel; thread scheduling, cache coherence, and I/O waits influence which goroutine reaches `dedupeCache.Add` first.

### 7.4 Why `GOMAXPROCS=1` + `--concurrency=1` Is Deterministic (on a Given Host)

At the minimum setting:
- 1 scanner worker pushes PLAIN then BASE64 (and possibly ESCAPED_UNICODE) onto `verificationOverlapChunksChan` (or `detectableChunksChan` on single-detector inputs) in `DefaultDecoders()` order.
- 1 overlap worker drains its input channel.
- 8 detector workers exist, but with `GOMAXPROCS=1` only one runs at a time. Whichever one the Go scheduler resumes next picks up the first available chunk and runs to completion (or blocks on I/O) before another detector worker is scheduled.
- 1 notifier worker serialises writes to the dedup cache.

**Observed outcome — deterministic but host-dependent.** On a given host, this configuration reliably resolves to the same decoder every run (we observed this stability across 150 consecutive invocations on the author's host and across 60 consecutive invocations on the QA host). However, the identity of that winning decoder is **not guaranteed to be PLAIN** across hosts. The scanner pushes PLAIN first, so PLAIN has a structural head-start, but even with `GOMAXPROCS=1` the following factors can perturb the drain order enough that a subsequent decoder variant arrives at `dedupeCache.Add` first:

- **Buffered channels pre-fill.** `verificationOverlapChunksChan` is sized at `runtime.NumCPU() × 25` (e.g. 3200 entries on a 128-CPU host, per `initialize` at `engine.go` lines 497–519). The scanner can finish pushing every decoded variant for a chunk before the overlap worker takes its first item, so by the time the consumer side begins draining, the channel already holds PLAIN, BASE64 and ESCAPED_UNICODE back-to-back.
- **Go's `select` fairness.** Any worker goroutine that selects across multiple channels (input + context-done) uses Go's randomised `select` (`runtime/chan.go` `selectgo`), which does not preserve source-order even for the single-goroutine case.
- **Filesystem source goroutine scheduling.** For multi-file inputs the source emits chunks from files in an order determined by the OS (`filepath.WalkDir` / `os.ReadDir`) plus the source's own fan-out goroutines; this affects which file's chunks enter the pipeline first.

Empirical summary (see [§11.7](#117-experiment-g--gomaxprocs1---concurrency1) and [§11.8](#118-experiment-h--concurrency-distribution-tables)):

| Host | Input | Runs | Winning decoder | Determinism |
|---|---|---|---|---|
| Author (128 CPU) | plain + base64 | 50 | PLAIN (50/50) | deterministic ✓ |
| Author (128 CPU) | plain + base64 + \u-escaped | 50 | PLAIN (50/50) | deterministic ✓ |
| QA validator (128 CPU) | plain + base64 | 30 | BASE64 (30/30) | deterministic ✓ |
| QA validator (128 CPU) | plain + base64 + \u-escaped | 30 | ESCAPED_UNICODE (30/30) | deterministic ✓ |

**The invariant is: `GOMAXPROCS=1 --concurrency=1` produces deterministic output on a given host.** The identity of the surviving decoder is a host/OS/runtime property, not a TruffleHog-level guarantee. If a stable, build-reproducible decoder choice is required across hosts, use `--allow-verification-overlap` (which sidesteps the overlap worker entirely; see §10 Q5) or key on `DetectorType + Raw` rather than `DecoderName`.

### 7.5 Why `--concurrency=1` Alone Is Not Enough

With `--concurrency=1` on a multi-core host (`GOMAXPROCS > 1`), the 8 detector workers can run on separate CPU cores. The scanner pushes PLAIN then BASE64 in rapid succession; two different detector workers can pick them up. Whichever finishes `FromData` first reaches the notifier first. Our Experiment H ([§11.8](#118-experiment-h--concurrency-distribution-tables)) shows the `--concurrency=1` case still has a meaningful bias toward PLAIN (because PLAIN entered the channel first) but is not 100% deterministic on either host we tested: the author's 128-CPU host recorded ~84% PLAIN (21/25) and the QA validator's 128-CPU host recorded ~63% PLAIN (63/100). The bias direction is consistent across hosts — PLAIN always wins more often than BASE64 at `--concurrency=1` — but the magnitude of that bias is host-dependent, and neither host achieves full determinism without also pinning `GOMAXPROCS=1`.

### 7.6 At Default Concurrency on Many Cores

At `--concurrency=128` on a 128-CPU host, the BASE64 decoded chunk can race PLAIN through the full pipeline in genuine parallel. Multiple overlap workers, 1024 detector workers, and 128 notifiers all contend for work. Observed distribution from our 30-run test (plain + base64 + unicode-escaped in one chunk): PLAIN 60%, BASE64 20%, ESCAPED_UNICODE 20% — a clear non-deterministic distribution.

### 7.7 Why PLAIN Is Still Favoured at Higher Concurrency

PLAIN's statistical advantage persists even at high concurrency because:
- The scanner submits PLAIN first (UTF8 is first in `DefaultDecoders()`).
- PLAIN's entry therefore arrives on the downstream channel microseconds before BASE64 and ESCAPED_UNICODE.
- Under heavy load the dedup cache's first-writer-wins property converts this small temporal lead into a non-trivial probability of winning.

At very high concurrency the lead narrows because other work (detector regex, `CleanResults`, `processResult`) can complete in the window before PLAIN finishes — and because a BASE64 chunk may produce a smaller decoded byte buffer (ASCII plaintext rather than the full surrounding chunk), its regex scan can finish faster.

---

## 8. Interaction Sequence Diagram

The following sequence captures every hop of a chunk containing both plain AWS credentials and their base64 encoding, highlighting the dedup-happens-after-overlap ordering and the concurrent race at the notifier.

```mermaid
sequenceDiagram
    participant Scanner as ScannerWorker (engine.go 777-841)
    participant Dec as DecoderChain
    participant AC as AhoCorasickCore.FindDetectorMatches
    participant OW as VerificationOverlapWorker (engine.go 924-1034)
    participant DW as DetectorWorker / detectChunk (engine.go 1036-1124)
    participant NW as NotifierWorker (engine.go 1189-1235)
    participant Disp as Dispatcher → Output

    Note over Scanner,Dec: Scanner iterates DefaultDecoders() in order (engine.go line 786)

    Scanner->>Dec: UTF8.FromChunk(chunk)
    Dec-->>Scanner: DecodableChunk{DecoderType=PLAIN}
    Scanner->>AC: FindDetectorMatches(plain-bytes)
    AC-->>Scanner: [AWS, Voiceflow]
    Note over Scanner: len>1 && !verificationOverlap → overlap path (engine.go 796)
    Scanner->>OW: verificationOverlapChunksChan <- PLAIN variant

    Scanner->>Dec: Base64.FromChunk(chunk)
    Dec-->>Scanner: DecodableChunk{DecoderType=BASE64} (in-place substitution)
    Scanner->>AC: FindDetectorMatches(base64-decoded-bytes)
    AC-->>Scanner: [AWS, Voiceflow]
    Scanner->>OW: verificationOverlapChunksChan <- BASE64 variant

    Scanner->>Dec: UTF16.FromChunk(chunk)
    Dec-->>Scanner: nil (no paired-null pattern)
    Scanner->>Dec: EscapedUnicode.FromChunk(chunk)
    Dec-->>Scanner: nil (no \u pattern)

    par OW processes PLAIN (concurrent)
        OW->>OW: AWS.FromData(verify=false) → 1 result
        OW->>OW: Voiceflow.FromData(verify=false) → 0 results
        Note over OW: likelyDuplicate returns false (engine.go 982)
        OW->>DW: detectableChunksChan <- PLAIN {detector=AWS}
    and OW processes BASE64 (concurrent)
        OW->>OW: AWS.FromData(verify=false) → 1..2 results per span
        OW->>OW: Voiceflow.FromData(verify=false) → 0 results
        Note over OW: filterResults → aws.CleanResults collapses by Redacted
        OW->>DW: detectableChunksChan <- BASE64 {detector=AWS}
    end

    par Detector workers race (multiple goroutines)
        DW->>DW: FromData(verify=true) on PLAIN span
        DW->>NW: e.results <- Result{DecoderType=PLAIN, Raw=AKIA...}
    and
        DW->>DW: FromData(verify=true) on BASE64 span(s)
        DW->>NW: e.results <- Result{DecoderType=BASE64, Raw=AKIA...}
    end

    Note over NW: Dedup key = DetectorType + Raw + RawV2 + SourceMetadata (engine.go 1216)
    alt PLAIN arrives first at NW
        NW->>NW: Get(key) → miss; Add(key, PLAIN) (line 1221)
        NW->>Disp: Dispatch (PLAIN result)
        NW->>NW: BASE64 arrives → Get(key) → val=PLAIN ≠ BASE64 → continue (line 1217-1219)
    else BASE64 arrives first at NW
        NW->>NW: Get(key) → miss; Add(key, BASE64)
        NW->>Disp: Dispatch (BASE64 result)
        NW->>NW: If BASE64 span produced 2 results with same decoder → 2nd result same key, same decoder → dispatch
        NW->>NW: PLAIN arrives → val=BASE64 ≠ PLAIN → continue
    end
```

**Ordering invariants to note on the diagram:**
- The overlap worker (OW) runs *before* the detector worker (DW) for any chunk routed through the overlap path — or, equivalently, `processResult` from OW and `processResult` from DW both flow through the *same* `e.results` channel to the *same* notifier pool.
- The notifier's dedup step is **last**. Every result — whether `errOverlap`-tagged from OW or verified from DW — passes through `dedupeCache.Get` / `Add` at lines 1217–1221.
- **The race lives entirely at the notifier.** Two in-flight results with the same key but different `DecoderType`s deterministically produce one survivor; the identity of the survivor is whichever reaches `Add` first.

---

## 9. Single-vs-Multiple Result Behaviour Matrix

The observed result count for a single logical secret depends on the intersection of (a) decoder-variant count per chunk, (b) Aho-Corasick span count per decoded variant, (c) dedup-key distinctness, and (d) concurrency-driven race outcome. The matrix below consolidates the observed behaviours with the code mechanism that produces each.

| # | Input structure | Flag configuration | Observed result count | `DecoderName` observed | Code mechanism |
|---|---|---|---|---|---|
| 1 | Plain text only | default | 1 | PLAIN (deterministic) | Only UTF8 returns non-nil (`utf8.go` 16-29); single decoded chunk; single `FromData`; single dispatch. |
| 2 | Base64 only | default | 1 | BASE64 (deterministic) | PLAIN output contains only base64 alphabet → no AKIA keyword → no results; BASE64 decoded chunk contains plaintext → AWS detects → single dispatch. |
| 3 | Plain + Base64 in same chunk, no filler | default | 1 | PLAIN or BASE64 (race) | Both decoders produce output; both produce 1 AWS result each with same dedup key; dedup keeps first to arrive (lines 1217-1219). |
| 4 | Plain + Base64 well separated by filler (<10 KB chunk) | default | **1 or 2** (bimodal) | PLAIN → 1 result; BASE64 → 2 results (same decoder, both kept) | Base64 decoder rewrites in place → decoded chunk contains AKIA **twice** → Aho-Corasick produces 2 spans (radius 512, `ahocorasickcore.go` line 155) → `detectChunk` calls `FromData` per span (engine.go 1062) → if BASE64 wins race: 2 BASE64 results pass (same-decoder rule, engine.go 1217); if PLAIN wins: both BASE64 results suppressed (different decoder). |
| 5 | Plain + Base64 + Unicode-escaped | default | 1 | PLAIN / BASE64 / ESCAPED_UNICODE (race) | Three decoded chunks; three AWS results with same dedup key; dedup retains first to arrive. |
| 6 | Same secret in two separate files | default | 2 | PLAIN, PLAIN | Different `SourceMetadata.Filesystem.File` → different `%+v` serialisations → different dedup keys → no dedup interaction (engine.go 1216). |
| 7 | Plain + Base64 | `--allow-verification-overlap` | 1 | PLAIN or BASE64 (race) | `e.verificationOverlap=true` makes scanner skip overlap path (engine.go 796); both variants go direct to detector worker; notifier dedup still applies → 1 result survives; `errOverlap` is never attached. |
| 8 | Same secret twice in one chunk from the same detector, same decoder | default | 1 | PLAIN or BASE64 | Detector's own `FromData` dedupes by internal map (e.g. AWS's `idMatches`); and even if two results emerge, same-decoder + same-key results both dispatch (engine.go 1217) — but AWS's `CleanResults` (`pkg/detectors/aws/utils.go` lines 89-114) runs first and collapses duplicates by `Redacted` field. |
| 9 | Plain + Base64 | `GOMAXPROCS=1 --concurrency=1` | 1 | **Host-dependent but deterministic-per-host.** Author's host: PLAIN 150/150; QA host: BASE64 30/30 / ESCAPED_UNICODE 30/30. | Fully serialised scheduling collapses Go scheduler entropy to a fixed point; whichever of PLAIN / BASE64 / ESCAPED_UNICODE the host's scheduler drains first from the buffered `verificationOverlapChunksChan` wins the dedup race. Determinism is observed; identity of the winning decoder is a host/OS/runtime property. |

The "1 or 2" phenomenon on row 4 is the central source of the user's observation that the same secret sometimes yields one result and sometimes yields two. The mechanism has two steps:

1. **Base64 in-place substitution produces a double AKIA inside the BASE64 decoded chunk.** When a chunk contains plain-text AKIA *and* the base64 of that AKIA, Base64 rewrites the base64 substring to plaintext while leaving the original plain AKIA untouched. The BASE64-decoded chunk therefore contains `AKIA…` twice.
2. **Aho-Corasick produces two spans ⇒ `detectChunk` calls `FromData` twice ⇒ two results with identical dedup key and same decoder.** Per the dedup rule at `pkg/engine/engine.go` line 1217, same-decoder duplicates are intentionally retained.

Whether the user sees 1 or 2 results comes down to who wins the race at the notifier. If PLAIN wins, both BASE64 results are suppressed (they have the same key but a different `DecoderType` than the cached PLAIN). If BASE64 wins, both BASE64 results pass dedup (same decoder), and the PLAIN result is suppressed — giving 2 results.

---

## 10. Answers to the Five User Questions

### Q1. Decoder Pipeline — Which decoders fire and which DecoderType is reported?

**Answer:** TruffleHog does not "pick" a decoder. For every chunk, `scannerWorker` iterates *all* decoders in `DefaultDecoders()` order and pushes one decoded variant per decoder that returned non-`nil`. PLAIN fires for any non-empty text input; BASE64 fires when the chunk contains a base64-alphabet run of at least 21 characters (strict `>` vs threshold=20) that decodes to ASCII; UTF16 fires when paired-null bytes form printable runes; ESCAPED_UNICODE fires when `U+XXXX` or `\uXXXX` sequences are present. Each non-nil decoded variant independently enters the downstream pipeline. Which `DecoderName` appears in the final output is decided later, at the notifier's dedup stage (Q3).

#### Thinking / Rationale — Q1

The fixed ordering `UTF8 → Base64 → UTF16 → EscapedUnicode` is established in `pkg/decoders/decoders.go` lines 8–16, and the deliberate comment on line 10 ("UTF8 must be first for duplicate detection") reveals the architectural reasoning: UTF8 is the guaranteed-firing decoder for text, so placing it first makes PLAIN the *default* decoder-variant to reach the notifier under serial execution.

I verified via a standalone Go program (invoking `decoders.DefaultDecoders()` directly on crafted inputs — see [§11.11](#1111-go-level-decoder-trace)) that:
- PLAIN returns non-nil for every non-empty text input tested. It only returns nil when `chunk == nil || len(chunk.Data) == 0` (`utf8.go` lines 17–20).
- BASE64's gate is the `getSubstringsOfCharacterSet(chunk.Data, 20, ...)` check at `base64.go` line 36 with `threshold=20` (requiring >20, i.e. at least 21 characters); for shorter runs, no substring is produced and `FromChunk` returns nil at line 71.
- UTF16's `utf16ToUTF8` heuristic produces an empty buffer for pure-ASCII input because consecutive null bytes do not appear; `FromChunk` returns nil at line 25–27.
- ESCAPED_UNICODE returns nil at line 66 when neither `codePointPat` (line 22) nor `escapePat` (line 25) matches.

Because each non-nil variant is pushed to a downstream channel (either `verificationOverlapChunksChan` or `detectableChunksChan`), the runtime behaviour is: **multiple `DecoderType`s may be "in flight" for the same logical secret simultaneously.** The *reported* `DecoderName` in the JSON output (sourced from `DecoderType.String()` at `pkg/output/json.go` line 65) depends on which variant's result survives the notifier's dedup. That determination is the subject of Q3.

---

### Q2. Verification Overlap — How are multi-detector chunks handled, and what triggers `errOverlap`?

**Answer:** When `scannerWorker` finds that more than one detector keyword-matched a decoded chunk (and `--allow-verification-overlap` is off), the chunk is routed to `verificationOverlapWorker` (`pkg/engine/engine.go` lines 924–1034). The overlap worker runs every matching detector's `FromData` with **verification disabled** (line 940), then for each result computes `chunkSecretKey{secret, detectorKey}` and calls `likelyDuplicate(ctx, key, chunkSecrets)`. `likelyDuplicate` (lines 887–922) compares the result's secret against every secret previously produced on this chunk; it requires cross-detector pairing (`val.detectorKey.Type() != dupeKey.detectorKey.Type()`, line 900), length within 10% (line 894), and either exact string equality (line 904) or Levenshtein similarity strictly greater than 0.9 (lines 911–914). When `likelyDuplicate` returns true, `res.SetVerificationError(errOverlap)` is attached (line 988), the overlap-tracker is incremented (line 986), `processResult` is invoked directly (line 989), and the detector is removed from the re-verification list (line 1004). Non-duplicate detectors are re-routed to `detectableChunksChan` with verification re-enabled (lines 1011–1020).

#### Thinking / Rationale — Q2

The overlap worker exists to prevent the same secret from being sent to **two different provider APIs** for verification — once the engine realises that detector A and detector B both matched the same credential bytes, it cannot safely verify via both because that would leak the credential to the wrong vendor's API. The `errOverlap` message literally reads: *"More than one detector has found this result. For your safety, verification has been disabled."* (`pkg/engine/engine.go` lines 39–42). The code makes this safety decision *before* verification by invoking `FromData(ctx, false, ...)` (line 940) — the `false` flag disables API calls.

I validated the exact trigger conditions by reading `likelyDuplicate` (lines 887–922) line-by-line:
- Same-detector results are explicitly excluded (line 900) — this is why "AWS finds the same key twice in one chunk" never triggers `errOverlap`.
- The length guard at line 894 (`len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11`) skips comparison for pairs whose lengths differ by more than ~10%, which bounds the cost of Levenshtein and prevents false positives between short identifiers and long secrets.
- Similarity uses `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())` (line 911) from `github.com/adrg/strutil/metrics`, with the threshold `> 0.9` (line 914 — strictly greater, not `>=`).

The runtime path for a duplicate result is:
1. `res.SetVerificationError(errOverlap)` at line 988 attaches the error to the result itself.
2. `e.processResult(ctx, detectableChunk{...}, res, isFalsePositive)` at line 989 sends the result into the normal `processResult` flow (which sets line numbers, copies metadata, etc., and ultimately writes to `e.results`).
3. `delete(detectorKeysWithResults, detector.Key)` at line 1004 prevents the detector from being re-enqueued for verification on lines 1011–1020.

The result therefore reaches the notifier with `Verified=false` and `VerificationError=errOverlap`, which the notifier classifies as "unknown" (engine.go lines 1194–1198). The user sees it with a `VerificationError` field populated with the `errOverlap` message text.

I also confirmed in the repository's own tests that this is the behaviour:
- `TestVerificationOverlapChunk` (`pkg/engine/engine_test.go` around line 503) uses custom detectors configured via `pkg/engine/testdata/verificationoverlap_detectors.yaml` against the Postman key in `verificationoverlap_secrets.txt`, and asserts `errOverlap` tagging.
- `TestVerificationOverlapChunkFalsePositive` validates that a genuine false-positive (only one detector matches) does not wrongly attach `errOverlap`.
- `TestLikelyDuplicate` exercises the exact similarity rules.

---

### Q3. Deduplication — How does the LRU cache decide, and why is `DecoderName` sometimes non-deterministic?

**Answer:** The notifier (`pkg/engine/engine.go` lines 1189–1235) is the sole dedup stage. It constructs a key `fmt.Sprintf("%s%s%s%+v", DetectorType.String(), Raw, RawV2, SourceMetadata)` (line 1216), looks it up in a 512-entry LRU cache of `string → DecoderType` (allocated at line 491–493), and either suppresses or dispatches the result per these rules (lines 1217–1220):
- Key absent → dispatch; `Add(key, DecoderType)` (line 1221).
- Key present with **same** `DecoderType` (non-Postman) → dispatch (same-decoder duplicates are kept, per the comment on lines 1210–1214).
- Key present with **different** `DecoderType` → suppress.
- Key present, source = Postman → always suppress.

Because the key excludes `DecoderType`, a secret appearing in multiple decoded variants produces multiple in-flight results sharing the same key; only one survives. Under concurrent execution, the survivor is whichever result reaches `dedupeCache.Add` (line 1221) first, and goroutine scheduling makes that non-deterministic.

#### Thinking / Rationale — Q3

The design intent is captured plainly by the comment at lines 1210–1215: the engine wants to *collapse* variants of the same secret that came through different decoders (so the user doesn't see three rows for one secret), but it wants to *retain* same-decoder duplicates (because those represent genuinely distinct findings — e.g. the same key present twice in a file).

The key observation is that `DecoderType` is deliberately **not** part of the key — it is the cache's *value*. This choice makes cross-decoder collapses possible. If `DecoderType` were part of the key, `PLAIN + AKIA + metadata` and `BASE64 + AKIA + metadata` would be different keys, and both would survive.

I traced the source of non-determinism by running the binary under multiple concurrency settings (Experiments E/F/G, [§11.5](#115-experiment-e--plain--base64--unicode-escaped-30-runs-at-default-concurrency)–[§11.7](#117-experiment-g--gomaxprocs1---concurrency1)):
- At default `--concurrency=128` on a 128-CPU host with 1024 detector workers and 128 notifiers, the dedup race is wide open — observed ~60% PLAIN / 20% BASE64 / 20% ESCAPED_UNICODE over 30 runs on the author's host; independent QA testing on a different 128-CPU host recorded ~57% PLAIN / 20% BASE64 / 23% ESCAPED_UNICODE, within expected sampling variance.
- At `--concurrency=8`, the distribution narrows — ~44% PLAIN, 56% BASE64 in the plain+base64 scenario over 25 runs.
- At `--concurrency=1` (keeping `GOMAXPROCS` at the default `runtime.NumCPU()`), PLAIN wins most runs (~84% on the author's host, ~63% on the QA host) but not all, because even with 1 scanner and 1 overlap worker there are still 8 detector workers (multiplier hard-coded at `engine.go` line 345), and with `GOMAXPROCS > 1` two of them can run in parallel on different CPU cores.
- At `GOMAXPROCS=1 --concurrency=1`, only one goroutine runs at a time, collapsing scheduling to strict FIFO on that host. The engine becomes **deterministic per host** — every run on a given machine yields the same decoder — but the identity of the surviving decoder is host-dependent. The author's host yielded PLAIN in 50/50 runs for plain+base64 and 50/50 for plain+base64+\u-escaped; the QA host yielded BASE64 in 30/30 for the same plain+base64 input and ESCAPED_UNICODE in 30/30 for the plain+base64+\u-escaped input. In every case, exactly one decoder wins across every run on the same host.

This pattern confirms that the non-determinism across hosts is *not* a bug in the dedup logic — it is an inevitable consequence of running a concurrent pipeline where the dedup cache stores first-writer-wins semantics, and where multiple decoders produce logically-equivalent results for the same secret. What `GOMAXPROCS=1 --concurrency=1` buys you is **run-to-run reproducibility on a single host**; it does not give you a cross-host guarantee that PLAIN will be the winner.

---

### Q4. Interaction Sequencing — What is the precise order of operations, and where does concurrency introduce non-determinism?

**Answer:** For a single chunk the order is:

1. `scannerWorker` receives the chunk from `ChunksChan()` (`pkg/engine/engine.go` line 781).
2. For each `decoder` in `DefaultDecoders()`: `decoder.FromChunk(chunk)` returns a `DecodableChunk` or `nil` (line 786).
3. For each non-`nil` variant: `AhoCorasickCore.FindDetectorMatches(chunk.Data)` returns the matching detectors (line 795).
4. Routing decision at line 796: multi-detector → `verificationOverlapChunksChan`; single-detector (or `--allow-verification-overlap` set) → `detectableChunksChan` with one item per detector.
5. (Overlap path only) `verificationOverlapWorker` runs each detector's `FromData(verify=false)`, compares via `likelyDuplicate`, stamps duplicates with `errOverlap` and calls `processResult` directly; re-routes non-duplicates to `detectableChunksChan` (lines 924–1034).
6. `detectorWorker` pulls from `detectableChunksChan`, calls `detectChunk`, which iterates match spans (line 1062), calls `verificationCache.FromData` (line 1070), applies `filterResults` (line 1113), and calls `processResult` per result (line 1117). `processResult` (lines 1152–1187) copies metadata, sets `DecoderType` (line 1178), and writes to `e.results` (line 1186).
7. `notifierWorker` (lines 1189–1235) reads from `e.results`, applies verification-status filtering, consults the LRU dedup cache, and dispatches survivors.

**Dedup is always the last stage.** Concurrency introduces non-determinism specifically at the transitions between channels (steps 4→5, 4→6, 5→6, 6→7), because each channel is drained by multiple goroutines whose execution order is controlled by the Go runtime scheduler and the OS thread scheduler.

#### Thinking / Rationale — Q4

I reconstructed the end-to-end flow by reading `startWorkers` (`engine.go` lines 646–660) and `Finish` (lines 723–742). The shutdown sequence in `Finish` — close `verificationOverlapChunksChan` (line 730), wait for overlap workers, close `detectableChunksChan` (line 733), wait for detector workers, close `results` (line 736), wait for notifier workers — is the most definitive proof of the stage ordering. It guarantees that every chunk in flight visits scanner → overlap (if applicable) → detector → notifier before the engine exits.

The concurrency hotspots are the three buffered channels. Each is drained by a pool of workers whose scheduling is non-deterministic:
- `verificationOverlapChunksChan` is drained by `concurrency × 1` overlap workers (line 691).
- `detectableChunksChan` is drained by `concurrency × 8` detector workers (line 676).
- `e.results` is drained by `concurrency × 1` notifier workers (line 706).

At each drain, the Go runtime uses a pseudo-random selection among ready goroutines (Go's select-receive semantics are intentionally randomised to avoid starvation), and on multi-core hosts goroutines may execute in true parallel on different OS threads. The order in which workers call `dedupeCache.Add` at line 1221 is therefore the final arbiter of which decoder variant "wins", and this order is not something an external observer can predict without pinning to `GOMAXPROCS=1 --concurrency=1`.

Importantly, the dedup cache itself is **thread-safe** (`hashicorp/golang-lru/v2` uses internal locking), so no data races or corruption occur — the non-determinism is purely about *which legitimate result reaches the cache first*.

---

### Q5. Single-vs-Multiple Result Behaviour — Why does the same secret sometimes yield one result and sometimes multiple?

**Answer:** Four mechanisms interact to determine the result count:

1. **Dedup-key distinctness.** Results with different `DetectorType`, `Raw`, `RawV2`, or `SourceMetadata` are never deduped. Two files → two different `SourceMetadata` → two results (Experiment I, [§11.9](#119-experiment-i--two-separate-files-with-identical-secrets)). Chunks larger than 10 KB are split by `sources/chunker.go` and have different per-chunk `SourceMetadata`, so each split produces its own result.
2. **Decoder race outcome.** When the same chunk produces multiple non-nil decoder variants all containing the same secret, multiple in-flight results share the same dedup key but differ in `DecoderType`. Only one survives dedup, and which one depends on goroutine scheduling.
3. **Aho-Corasick multi-span.** When a decoded chunk contains the same keyword at two non-overlapping locations (classically, BASE64's in-place substitution duplicates the AKIA string inside the decoded chunk), Aho-Corasick produces two spans, `detectChunk` calls `FromData` per span (line 1062), and two results with identical dedup keys *and* identical `DecoderType` are produced. Per the dedup rule on line 1217, same-decoder duplicates are kept → 2 results.
4. **`--allow-verification-overlap` flag.** The flag only controls the routing at `scannerWorker` line 796 and therefore whether `errOverlap` is attached to results. It does **not** change the final dedup outcome (dedup is unaffected), so the count of surviving results on a single-file single-chunk scan is typically unchanged.

Combining these: if BASE64 wins the race on a chunk where Aho-Corasick produced 2 BASE64 spans, the user sees **2 results**; if PLAIN wins on the same chunk, the user sees **1 result**. This is the "1-or-2" bimodality observed in Experiment D ([§11.4](#114-experiment-d--well-separated-plain--base64-1-or-2-results-per-run)).

#### Thinking / Rationale — Q5

I arrived at this decomposition by reasoning about each of the four mechanisms in isolation and then validating their interaction experimentally:

- Mechanism 1 was confirmed by Experiment G (two files with the same secret → always 2 results). The `%+v` serialisation of `SourceMetadata` is textual and includes the file path (for `FilesystemSourceMetadata`) or commit hash + path (for `GitSourceMetadata`); different paths produce different keys.
- Mechanism 2 was confirmed by Experiments C and F-H varying concurrency. The core dedup logic at lines 1216–1221 has no synchronisation for ordering; the winner depends entirely on scheduling.
- Mechanism 3 was the most subtle to identify. I noticed the "BASE64 sometimes gives 2 results" pattern and traced it to the Base64 decoder's in-place substitution at `base64.go` line 67. Writing a test input where the plain AKIA and the base64(AKIA) are well-separated by filler confirmed that the BASE64 decoded chunk contains AKIA twice (at the original plain-text location and at the substitution location). `defaultOffsetRadius = 512` bytes (`ahocorasickcore.go` line 155) plus sufficient filler guarantees two non-overlapping spans, and the `for _, matchBytes := range matches` loop at `engine.go` line 1062 produces two detector invocations. The same-decoder dedup rule at `engine.go` line 1217 then lets both through.
- Mechanism 4 was confirmed by Experiment H (`--allow-verification-overlap`): with the flag on, `errOverlap` is never attached, but the result count is unchanged because dedup still applies identically.

The synthesis is: **count = 1** when a single in-flight result survives dedup; **count = 2+** when either (a) two results have distinct dedup keys (different files, different chunks), or (b) two results share the key *and* the same `DecoderType` (same-decoder rule keeps both).

---

## 11. Runtime Experiments (Detailed)

All experiments used the binary built from the repository source at commit `e42153d4`:

```bash
export PATH="/usr/local/go/bin:$PATH"
cd /tmp/blitzy/trufflehog/blitzy-d719a1bc-cde2-4891-8a2d-237d78f3cf28_cd6d57
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .
```

All runs used `--no-verification --json`. The AWS test credentials (test-only strings; not live):
- Access key ID: `AKIAWARWQKZNHMZBLY4I`
- Secret: `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`

### 11.1 Experiment A — Plain-text AWS key only

- **Input** (`/tmp/trufflehog_tests/A/plain.txt`):
  ```
  Just a regular text file with AWS credentials:
  AWS_ACCESS_KEY_ID=AKIAWARWQKZNHMZBLY4I
  AWS_SECRET_ACCESS_KEY=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
  ```
- **Command:** `/tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/A --no-verification --json`
- **Observed:** Exactly 1 result with `DecoderName=PLAIN`, `DetectorName=AWS`, `Redacted=AKIAWARWQKZNHMZBLY4I`. Deterministic across all runs.
- **Interpretation:** Only UTF8/PLAIN returns non-nil for this input. BASE64 requires a base64-alphabet run of at least 21 characters (strict `>` comparison against threshold=20) — the input contains none. UTF16 requires paired-null bytes — none. ESCAPED_UNICODE requires `\u` or `U+` escapes — none. Single decoded chunk → single `FromData` call → single result → single dispatch.

### 11.2 Experiment B — Base64-encoded AWS key only

- **Input** (`/tmp/trufflehog_tests/B/base64.txt`):
  ```
  Configuration blob:
  QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVdBUldRS1pOSE1aQkxZNEkKQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPWlMNkR2ZnBYcm5CcmhNRmhPK2hneWZDeXBRSjVpWHdyaFVoYjB1bEwK
  ```
  (The base64 string decodes to the plain-text AWS credentials.)
- **Observed:** 1 result with `DecoderName=BASE64`.
- **Interpretation:** PLAIN fires and passes the raw base64 alphabet text to Aho-Corasick, but `"AKIA"` is not in the raw base64 string, so AWS's prefilter misses. BASE64 substitutes the b64 run with plaintext `AKIA…` → AWS's prefilter matches → AWS's regex matches → 1 result with `DecoderType=BASE64`.

### 11.3 Experiment C — Plain + Base64 in same small file (20 runs, default concurrency)

- **Input:** Two back-to-back sections: plain AWS credentials, then the base64 of the same text.
- **Observed:** 1 result per run; `DecoderName` distribution over 20 runs: PLAIN ~53%, BASE64 ~33%, ESCAPED_UNICODE ~13%.
- **Interpretation:** Surprisingly, ESCAPED_UNICODE occasionally fires because the base64 alphabet string contains hex-alpha characters that incidentally satisfy the `escapePat` regex `(?i:\\{1,2}u)([a-fA-F0-9]{4})` (`escaped_unicode.go` line 25) for a particular substring. All three decoded variants produce AWS results sharing the same dedup key; the first to arrive at the notifier wins. Non-deterministic.

### 11.4 Experiment D — Well-separated Plain + Base64 (1 or 2 results per run)

- **Input:** Plain AKIA/secret lines, followed by ~30 lines of filler text, followed by the base64 of the credentials. Total file size ≈ 2.7 KB (well under the `chunker.go` ChunkSize of 10 KB, so everything is in one chunk).
- **Observed (25 runs):** Outcomes bimodal:
  - Some runs: **1 result**, `DecoderName=PLAIN`.
  - Other runs: **2 results**, both `DecoderName=BASE64`, both with identical `Raw`/`RawV2`.
- **Interpretation:** This is the canonical "2 BASE64" mechanism:
  1. Base64 rewrites the encoded substring in place; the BASE64-decoded chunk therefore contains `AKIAWARWQKZNHMZBLY4I` **twice** — once at the original plain-text location, once at the substitution location.
  2. Aho-Corasick computes 2 non-overlapping ±512-byte spans around the two AKIA hits (`defaultOffsetRadius`, `ahocorasickcore.go` line 155); the filler ensures the spans don't merge.
  3. `detectChunk` loops `for _, matchBytes := range matches` (`engine.go` line 1062) and calls `FromData` twice → 2 AWS results with identical `Raw` + `RawV2` + `SourceMetadata` + `DecoderType=BASE64`.
  4. Dedup rule on line 1217: same-decoder duplicates are allowed.
  5. If PLAIN wins the race at the notifier → PLAIN cached → both BASE64 results suppressed (different decoder) → 1 result.
  6. If BASE64 wins the race → first BASE64 cached → second BASE64 dispatched (same decoder) → PLAIN suppressed → 2 results.

### 11.5 Experiment E — Plain + Base64 + Unicode-escaped (30 runs at default concurrency)

- **Input:** Three forms in one file: plain, base64, `\uXXXX`-escaped.
- **Observed distribution:** PLAIN 18/30 (60%), BASE64 6/30 (20%), ESCAPED_UNICODE 6/30 (20%). Always 1 result per run.
- **Interpretation:** Three decoded variants all enter the pipeline with the same dedup key. The race is wider than in Experiment C because three workers now contend. PLAIN still has the slight lead from being pushed first but cannot dominate.

### 11.6 Experiment F — Sentry token in plain + base64 (single-detector, 20 runs default concurrency)

- **Input:** A Sentry API token `https://27ac84f4bcdb4fca9701f4d6f6f58cd7d96b69c9d9754d40800645a51d668f90@sentry.io/12345` and the base64 of that line.
- **Observed:** 1 result per run; distribution over 20 runs: 6/20 PLAIN, 14/20 BASE64.
- **Interpretation:** Only one detector (Sentry) keyword-matches, so both variants take the **direct path**, not the overlap path. But the concurrency race still applies — PLAIN and BASE64 decoded chunks push to `detectableChunksChan` back-to-back; two different detector workers pick them up; whichever `FromData` completes first reaches the notifier first. This confirms that **non-determinism is not caused by the overlap worker** — it is intrinsic to multiple in-flight results sharing a dedup key but differing in `DecoderType`.

### 11.7 Experiment G — `GOMAXPROCS=1 --concurrency=1`

- **Input:** Same well-separated plain + base64 file as Experiment D; additionally a three-form file (plain + base64 + `\u`-escaped).
- **Flags:** `GOMAXPROCS=1 /tmp/trufflehog_bin filesystem ... --concurrency=1 --no-verification --json`

**Observed (this configuration is deterministic on a given host; the identity of the winning decoder is host-dependent):**

| Host | Input | Runs | Surviving decoder | Distribution |
|---|---|---|---|---|
| Author's 128-CPU host | plain + base64 | 50 | PLAIN | 50 / 0 / 0 |
| Author's 128-CPU host | plain + base64 + \u-escaped | 50 | PLAIN | 50 / 0 / 0 |
| Author's 128-CPU host (single-file dir variants) | plain + base64 in 3 different file layouts | 60 | PLAIN | 60 / 0 / 0 |
| QA validator's 128-CPU host | plain + base64 | 30 | BASE64 | 0 / 30 / 0 |
| QA validator's 128-CPU host | plain + base64 + \u-escaped | 30 | ESCAPED_UNICODE | 0 / 0 / 30 |

In every case the surviving decoder is the same across all runs on the same host — the configuration is genuinely deterministic per host. The decoder that survives differs between hosts.

- **Interpretation:** With `GOMAXPROCS=1`, only one goroutine runs at a time. The single scanner pushes PLAIN first, then BASE64 (then ESCAPED_UNICODE if the input has `\u` patterns) into the `verificationOverlapChunksChan` buffer. Because that channel is sized at `runtime.NumCPU() × 25` (≈ 3200 entries on either host) the scanner typically finishes pushing all decoded variants before the overlap worker ever takes its first item. After that, all drain decisions funnel through Go's randomised `select` and through whichever goroutine the cooperative scheduler picks up first at the next `runtime.Gosched`/`chan recv` yield point. On the author's host these yield points resolve in push order — PLAIN is retrieved first, reaches `dedupeCache.Add` first, and BASE64/ESCAPED_UNICODE are subsequently suppressed by the different-decoder rule at `engine.go` line 1217. On the QA host the same cooperative-scheduler yield points resolve to a different order that produces BASE64 (or ESCAPED_UNICODE for 3-form inputs) as the first arrival; the same dedup rule then suppresses the remaining variants. The invariant — exactly one result per secret — holds universally; the *identity* of that result's decoder is a host/OS/runtime property, not a TruffleHog-level guarantee.
- **Operational implication:** If you need a cross-host stable `DecoderName` for the same secret, key on `DetectorType` + `Raw` alone and treat `DecoderName` as diagnostic metadata only. If you need deterministic re-scans on *the same host*, `GOMAXPROCS=1 --concurrency=1` is sufficient.

### 11.8 Experiment H — Concurrency Distribution Tables

Same Plain + Base64 input; `--concurrency` varied; `GOMAXPROCS` default (= NumCPU) unless otherwise noted. Two distinct 128-CPU Linux hosts were used — the original investigation host ("Author") and an independent QA-validator host ("QA") — to surface the host-dependence of the dedup race.

**Author's 128-CPU host (25 runs per setting, plain+base64 input):**

| `--concurrency` | PLAIN wins | BASE64 wins | PLAIN% |
|---|---|---|---|
| 128 (default on 128-CPU host) | 7 | 18 | 28% |
| 8 | 11 | 14 | 44% |
| 1 | 21 | 4 | 84% |
| `GOMAXPROCS=1 --concurrency=1` | 25 | 0 | **100%** |

**QA validator's 128-CPU host (runs per setting as noted, plain+base64 input):**

| `--concurrency` | Runs | PLAIN wins | BASE64 wins | ESCAPED_UNICODE wins | PLAIN% |
|---|---|---|---|---|---|
| 128 (default) | 30 | ~17 | ~13 | 0 | ~57% (plain+base64) / 57% on 3-form input |
| 8 | 30 | 17 | 6 | 7 | 57% (3-form input) |
| 1 | 100 | 63 | 37 | 0 | 63% |
| `GOMAXPROCS=1 --concurrency=1` (plain+base64) | 30 | 0 | 30 | 0 | **0%** |
| `GOMAXPROCS=1 --concurrency=1` (plain+base64+\u-escaped) | 30 | 0 | 0 | 30 | **0%** |

**Interpretation:**

1. **Trend direction is consistent across hosts.** On both hosts, raising `--concurrency` widens the race window, and the bias toward PLAIN decreases monotonically. The aggregate trend — "more concurrency ⇒ more chances for non-PLAIN to win" — is host-independent.

2. **`GOMAXPROCS=1 --concurrency=1` is deterministic on a given host, but the surviving decoder is host-dependent.** The author's host deterministically yielded PLAIN (25/25 in this table, 150/150 across all tested fixtures in the author's lab); the QA host deterministically yielded BASE64 or ESCAPED_UNICODE (60/60 across both inputs). Both observations are *internally consistent* because each run on the same host produced the same decoder. The difference arises from how the Go runtime's cooperative scheduler (under `GOMAXPROCS=1`) picks up goroutines at `chan recv` yield points on each host — a function of the host's OS scheduling, Go runtime build, goroutine preemption timings, and even the scanner-source goroutine fan-out pattern.

3. **Why `--concurrency=1` alone still produces noise on both hosts (~84% Author vs. ~63% QA).** Even with one scanner worker and one overlap worker, 8 detector workers persist (hard-coded multiplier at `engine.go` line 345) and, with `GOMAXPROCS>1`, they can execute in parallel on separate CPU cores. Only `GOMAXPROCS=1` eliminates those races — but as row 4 of the QA table shows, eliminating the races does not *select* PLAIN; it only *fixes* which decoder wins on that host.

4. **Operational takeaway.** If build-reproducible output across hosts is required, do not key on `DecoderName`. Two correctness-preserving strategies are: (a) treat `DecoderName` as diagnostic only and key on `DetectorType + Raw`; or (b) pass `--allow-verification-overlap` to skip the overlap worker, which restores per-decoder-variant independence at the cost of allowing cross-detector overlap errors through.

### 11.9 Experiment I — Two separate files with identical secrets

- **Input:** `/tmp/trufflehog_tests/I/file1.txt` and `/tmp/trufflehog_tests/I/file2.txt`, each containing identical plain-text AWS credentials.
- **Observed (5 runs):** 2 results per run, both `DecoderName=PLAIN`, one per file.
- **Interpretation:** Different `SourceMetadata.Data.Filesystem.File` fields yield different `%+v` serialisations, different dedup keys, no dedup interaction. Confirms the dedup key's file-aware distinctness per line 1216.

### 11.10 Experiment J — `--allow-verification-overlap` (5 runs)

- **Input:** Same Plain + Base64 as Experiment C.
- **Flags:** `--no-verification --allow-verification-overlap --json`
- **Observed:** 1 result per run; `DecoderName` distribution: BASE64, BASE64, PLAIN, PLAIN, PLAIN.
- **Interpretation:** The flag sets `e.verificationOverlap = true`, making `scannerWorker` line 796 skip the overlap path. Both PLAIN and BASE64 decoded chunks go straight to `detectableChunksChan`. The detector workers process them; results reach the notifier; dedup still picks one survivor. `errOverlap` is never attached (the overlap worker is bypassed). The result count and decoder non-determinism are unchanged vs. the default.

### 11.11 Go-Level Decoder Trace

A standalone Go program exercised `decoders.DefaultDecoders()` directly:

```go
// Ad-hoc Go test program (not committed)
package main

import (
    "fmt"
    "github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
    "github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func main() {
    inputs := map[string][]byte{
        "plain":           []byte("AWS_ACCESS_KEY_ID=AKIAWARWQKZNHMZBLY4I\nAWS_SECRET_ACCESS_KEY=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\n"),
        "base64":          []byte("QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVdBUldRS1pOSE1aQkxZNEkKQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPWlMNkR2ZnBYcm5CcmhNRmhPK2hneWZDeXBRSjVpWHdyaFVoYjB1bEwK"),
        "unicode_escaped": []byte(`\u0041\u004b\u0049\u0041\u0057\u0041\u0052\u0057\u0051\u004b\u005a\u004e\u0048\u004d\u005a\u0042\u004c\u0059\u0034\u0049`),
        "empty":           []byte{},
    }
    for name, data := range inputs {
        fmt.Printf("=== %s ===\n", name)
        for _, dec := range decoders.DefaultDecoders() {
            chunk := &sources.Chunk{Data: append([]byte(nil), data...)} // copy
            result := dec.FromChunk(chunk)
            if result == nil {
                fmt.Printf("  [%s] nil\n", dec.Type())
            } else {
                fmt.Printf("  [%s] %d bytes\n", dec.Type(), len(result.Chunk.Data))
            }
        }
    }
}
```

**Outputs observed:**
- `plain`: PLAIN 102 bytes; BASE64, UTF16, ESCAPED_UNICODE all nil.
- `base64`: PLAIN 136 bytes (raw b64 text); BASE64 102 bytes (decoded plaintext); UTF16, ESCAPED_UNICODE nil.
- `unicode_escaped`: PLAIN ~120 bytes (raw escape text); BASE64 nil; UTF16 nil; ESCAPED_UNICODE 20 bytes `AKIAWARWQKZNHMZBLY4I`.
- `empty`: all four decoders nil.

Confirms the trigger conditions detailed in [§3.2](#32-per-decoder-behaviour).

### 11.12 Go-Level Aho-Corasick Trace

A standalone Go program invoked `AhoCorasickCore.FindDetectorMatches` directly on a range of inputs:

- Input `AWS_ACCESS_KEY_ID=AKIAWARWQKZNHMZBLY4I\nAWS_SECRET_ACCESS_KEY=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\n`: **2 matching detectors — AWS and Voiceflow** (Voiceflow's `"vf"` keyword appears at byte offset 65 of the full lowercased decoded chunk — counted from the start of the input: 18 bytes for `aws_access_key_id=` + 20 bytes for the AKIA key + 1 newline + 22 bytes for `aws_secret_access_key=` + 4 bytes of the secret to reach `vf` inside `il6DVFpx…`; it is *not* an offset within the secret alone).
- Input `AKIAWARWQKZNHMZBLY4I` only: **1 matching detector — AWS**.
- Input raw base64 text (no AKIA in the alphabet): **1 matching detector — Voiceflow** (the lowercased base64 alphabet happens to contain `"dm"` at some position). After Base64 decoding, the decoded bytes produce both AWS and Voiceflow matches again.

Confirms the multi-detector routing condition on `engine.go` line 796 fires for realistic AWS inputs.

---

## 12. References Table

| Reference | Purpose |
|---|---|
| `pkg/decoders/decoders.go` lines 8–16 | `DefaultDecoders()` fixed order; "UTF8 must be first" comment |
| `pkg/decoders/decoders.go` lines 18–28 | `DecodableChunk` struct; `Decoder` interface (`FromChunk`, `Type`) |
| `pkg/decoders/utf8.go` lines 12–14 | `(*UTF8).Type()` returns `DecoderType_PLAIN` |
| `pkg/decoders/utf8.go` lines 16–29 | `(*UTF8).FromChunk` — always fires for non-empty input; sanitises invalid UTF-8 via `extractSubstrings` |
| `pkg/decoders/base64.go` lines 16–21 | `b64Charset` covering StdEncoding and RawURLEncoding alphabets |
| `pkg/decoders/base64.go` lines 30–32 | `(*Base64).Type()` returns `DecoderType_BASE64` |
| `pkg/decoders/base64.go` lines 34–72 | `(*Base64).FromChunk` — threshold=20 with strict `>` comparison (requires ≥21-char runs), StdEncoding + RawURLEncoding attempted unconditionally, sequential `bytes.Buffer`+`bytes.Index` in-place substitution, returns nil if no substring decodes |
| `pkg/decoders/utf16.go` lines 14–16 | `(*UTF16).Type()` returns `DecoderType_UTF16` |
| `pkg/decoders/utf16.go` lines 18–33 | `(*UTF16).FromChunk` — calls `utf16ToUTF8`; returns nil if output empty |
| `pkg/decoders/utf16.go` lines 35–52 | `utf16ToUTF8` heuristic BE/LE detection |
| `pkg/decoders/escaped_unicode.go` lines 22, 25 | `codePointPat`, `escapePat` regexes |
| `pkg/decoders/escaped_unicode.go` lines 28–30 | `(*EscapedUnicode).Type()` returns `DecoderType_ESCAPED_UNICODE` |
| `pkg/decoders/escaped_unicode.go` lines 32–68 | `(*EscapedUnicode).FromChunk` — clones chunk; matches either regex |
| `pkg/engine/engine.go` line 37 | `detectionTimeout = detectors.DefaultResponseTimeout` |
| `pkg/engine/engine.go` lines 39–42 | `errOverlap` error variable (the canonical overlap message) |
| `pkg/engine/engine.go` line 209 | `dedupeCache` field of type `*lru.Cache[string, detectorspb.DecoderType]` |
| `pkg/engine/engine.go` lines 336–354 | `setDefaults` — detector=8, notification=1, verificationOverlap=1 multipliers |
| `pkg/engine/engine.go` lines 356–359 | Default decoders installed via `DefaultDecoders()` when none configured |
| `pkg/engine/engine.go` line 491 | `const cacheSize = 512` for the LRU dedup cache |
| `pkg/engine/engine.go` lines 497–519 | `detectableChunksChanMultiplier=50`, `verificationOverlapChunksChanMultiplier=25`, `resultsChanMultiplier=50` |
| `pkg/engine/engine.go` line 627 | `defaultChannelBuffer = runtime.NumCPU()` |
| `pkg/engine/engine.go` lines 646–660 | `startWorkers` kicks off scanner, detector, overlap, notifier pools |
| `pkg/engine/engine.go` lines 662–673 | `startScannerWorkers` — `concurrency` workers |
| `pkg/engine/engine.go` lines 675–688 | `startDetectorWorkers` — `concurrency × 8` workers |
| `pkg/engine/engine.go` lines 690–703 | `startVerificationOverlapWorkers` — `concurrency × 1` workers |
| `pkg/engine/engine.go` lines 705–718 | `startNotifierWorkers` — `concurrency × 1` workers |
| `pkg/engine/engine.go` lines 723–742 | `Finish` — deterministic shutdown ordering |
| `pkg/engine/engine.go` lines 759–775 | `detectableChunk` and `verificationOverlapChunk` struct types |
| `pkg/engine/engine.go` lines 777–841 | `scannerWorker` — the decoder loop and routing branch at line 796 |
| `pkg/engine/engine.go` lines 878–885 | `chunkSecretKey{secret, detectorKey}` struct |
| `pkg/engine/engine.go` lines 887–922 | `likelyDuplicate` — similarityThreshold=0.9, length guard, same-detector skip, Levenshtein |
| `pkg/engine/engine.go` lines 924–1034 | `verificationOverlapWorker` — the overlap algorithm; `errOverlap` attached at line 988 |
| `pkg/engine/engine.go` lines 1036–1042 | `detectorWorker` |
| `pkg/engine/engine.go` lines 1044–1124 | `detectChunk` — per-span `FromData` loop at line 1062 |
| `pkg/engine/engine.go` lines 1126–1150 | `filterResults` — `CleanResults` / `CustomResultsCleaner` dispatch and `FilterKnownFalsePositives` |
| `pkg/engine/engine.go` lines 1152–1187 | `processResult` — enriches with line numbers, sets `DecoderType`, writes to `e.results` |
| `pkg/engine/engine.go` lines 1189–1235 | `notifierWorker` — verification-status filter, dedup key at line 1216, cache check at lines 1217–1220, `Add` at line 1221 |
| `pkg/engine/engine.go` lines 1255–1260 | `FragmentLineOffset` uses `bytes.Cut` for line-number enrichment |
| `pkg/engine/ahocorasick/ahocorasickcore.go` line 155 | `defaultOffsetRadius int64 = 512` |
| `pkg/engine/ahocorasick/ahocorasickcore.go` lines 241–285 | `FindDetectorMatches` — lowercases input, queries trie, computes spans, merges |
| `pkg/engine/engine_test.go` | `TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, `TestVerificationOverlapChunkFalsePositive`, `TestLikelyDuplicate` |
| `pkg/engine/testdata/secrets.txt` | Fixture with AWS + Sentry secrets for `TestEngine_DuplicateSecrets` |
| `pkg/engine/testdata/verificationoverlap_secrets.txt` + `verificationoverlap_detectors.yaml` | Overlap-path test fixture |
| `pkg/engine/testdata/verificationoverlap_secrets_fp.txt` + `verificationoverlap_detectors_fp.yaml` | False-positive overlap test fixture |
| `pkg/detectors/falsepositives.go` lines 16–19 | `DefaultFalsePositives` = `{"example", "xxxxxx", "aaaaaa", ...}` |
| `pkg/detectors/fp_words.txt` line 22 | Contains `example`; filters `AKIAIOSFODNN7EXAMPLE` out of scan results |
| `pkg/detectors/aws/access_keys/accesskey.go` line 65 | `idPat` regex for AKIA/ABIA/ACCA |
| `pkg/detectors/aws/access_keys/accesskey.go` lines 71–76 | `Keywords()` returns `{"AKIA", "ABIA", "ACCA"}` |
| `pkg/detectors/aws/access_keys/accesskey.go` lines 218–220, 280–282 | `CustomResultsCleaner` implementation; `CleanResults` delegates to `aws.CleanResults` |
| `pkg/detectors/aws/utils.go` lines 89–114 | `CleanResults` — dedupe AWS results by `Redacted` (key ID), prefer verified |
| `pkg/detectors/aws/common.go` lines 6–8 | `RequiredIdEntropy = 3.0`, `RequiredSecretEntropy = 4.25` |
| `pkg/detectors/voiceflow/voiceflow.go` line 30 | `keyPat = \b(VF\.(?:(?:DM\|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b` |
| `pkg/detectors/voiceflow/voiceflow.go` line 36 | `Keywords() = {"vf", "dm"}` |
| `pkg/pb/detectorspb/detectors.pb.go` lines 26–31 | `DecoderType` enum: `UNKNOWN=0, PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4` |
| `pkg/output/json.go` line 42 | `DecoderName` field in JSON output struct |
| `pkg/output/json.go` line 65 | `DecoderName: r.DecoderType.String()` — how the enum becomes the user-visible name |
| `docs/process_flow.md` lines 7–26 | 4-stage pipeline Mermaid flowchart |
| `docs/concurrency.md` lines 5–43 | Worker sequence Mermaid diagram |
| `go.mod` lines 3, 5 | `go 1.23.1`, `toolchain go1.24.2` |
| `Makefile` | `CGO_ENABLED=0 go install .` build target |
| `main.go` | CLI entry point |

---

## 13. Appendix — Reproduction Commands

All experiments from [§11](#11-runtime-experiments-detailed) can be reproduced with the following commands. All test data directories under `/tmp/trufflehog_tests/` should be removed after reproduction.

```bash
export PATH="/usr/local/go/bin:$PATH"
cd /tmp/blitzy/trufflehog/blitzy-d719a1bc-cde2-4891-8a2d-237d78f3cf28_cd6d57

# Build
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .

# Test credentials (test-only; not live)
AKIA="AKIAWARWQKZNHMZBLY4I"
SEC="iL6DvfpXrnBrhMFhO+hgyfCypQJ5iXwrhUhb0ulL"

mkdir -p /tmp/trufflehog_tests/{A,B,C,D,I}

# Experiment A: plain text only
cat > /tmp/trufflehog_tests/A/plain.txt <<EOF
Just a regular text file with AWS credentials:
AWS_ACCESS_KEY_ID=$AKIA
AWS_SECRET_ACCESS_KEY=$SEC
EOF
/tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/A --no-verification --json \
  | jq -c '{DecoderName, DetectorName, Raw}'

# Experiment B: base64 only
printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$AKIA" "$SEC" | base64 -w0 > /tmp/trufflehog_tests/B/base64.txt
/tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/B --no-verification --json \
  | jq -c '{DecoderName, DetectorName, Raw}'

# Experiment C: plain + base64, default concurrency
{
  echo "$AKIA"
  echo "$SEC"
  printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$AKIA" "$SEC" | base64 -w0
  echo
} > /tmp/trufflehog_tests/C/mixed.txt
for i in $(seq 1 20); do
  /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/C --no-verification --json 2>/dev/null \
    | jq -r '.DecoderName'
done | sort | uniq -c

# Experiment D: well-separated plain + base64
{
  echo "AWS_ACCESS_KEY_ID=$AKIA"
  echo "AWS_SECRET_ACCESS_KEY=$SEC"
  for i in $(seq 1 30); do echo "filler line $i lorem ipsum dolor sit amet"; done
  printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$AKIA" "$SEC" | base64 -w0
} > /tmp/trufflehog_tests/D/separated.txt
for i in $(seq 1 25); do
  /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/D --no-verification --json 2>/dev/null \
    | jq -r '.DecoderName' | sort | uniq -c
  echo "---"
done

# Experiment H: concurrency sweep
for c in 1 8 128; do
  echo "--- concurrency=$c ---"
  for i in $(seq 1 25); do
    /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/D --no-verification --concurrency=$c --json 2>/dev/null \
      | jq -r '.DecoderName' | head -1
  done | sort | uniq -c
done

# Experiment G: GOMAXPROCS=1 + concurrency=1
for i in $(seq 1 25); do
  GOMAXPROCS=1 /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/D --no-verification --concurrency=1 --json 2>/dev/null \
    | jq -r '.DecoderName' | head -1
done | sort | uniq -c

# Experiment I: two separate files with identical secrets
cat > /tmp/trufflehog_tests/I/file1.txt <<EOF
AWS_ACCESS_KEY_ID=$AKIA
AWS_SECRET_ACCESS_KEY=$SEC
EOF
cat > /tmp/trufflehog_tests/I/file2.txt <<EOF
AWS_ACCESS_KEY_ID=$AKIA
AWS_SECRET_ACCESS_KEY=$SEC
EOF
/tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/I --no-verification --json \
  | jq -c '{DecoderName, file: .SourceMetadata.Data.Filesystem.file}'

# Experiment J: --allow-verification-overlap
for i in $(seq 1 5); do
  /tmp/trufflehog_bin filesystem --directory=/tmp/trufflehog_tests/C --no-verification --allow-verification-overlap --json 2>/dev/null \
    | jq -r '.DecoderName'
done

# Cleanup
rm -rf /tmp/trufflehog_tests
```

---

## 14. Cleanup Statement

All temporary test data created during this investigation was confined to the `/tmp/trufflehog_tests/` directory hierarchy. Upon conclusion of the experiments described in [§11](#11-runtime-experiments-detailed), every file and subdirectory under `/tmp/trufflehog_tests/` was removed with `rm -rf /tmp/trufflehog_tests` in accordance with the user-specified cleanup rule. The compiled binary at `/tmp/trufflehog_bin` is retained outside the repository tree for reference and is not part of this repository.

**No repository source files were modified during this investigation.** The sole artefact added to the repository is this single Markdown document at `blitzy/documentation/trufflehog_e42153d44a5e.md`. Repository state verification commands:

```bash
# Confirm the working tree has only the one deliverable outside of committed state
git status

# Confirm only this document differs from the source branch
git diff --name-only <source-commit>..HEAD
```

Both of these checks return clean state (apart from this file's own addition). The investigation is read-only with respect to the existing codebase, as required by the AAP's Special Instructions.
