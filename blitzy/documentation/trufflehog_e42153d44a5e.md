# TruffleHog Decoder Pipeline, Overlap Detection, and Result Deduplication: A Code Investigation

## Introduction

When scanning a file containing the same logical secret in multiple encoded forms — plain text, Base64, escaped Unicode — TruffleHog can produce seemingly inconsistent output:

- Sometimes the same secret is reported **twice** with different `DecoderType` labels (e.g., `PLAIN` and `BASE64`).
- Sometimes TruffleHog reports a **verification overlap error** (`errOverlap`) instead of clean results.
- Sometimes the results are **deduplicated** down to a single finding.
- The behavior can **change** depending on how the test file is structured (same line vs. separate lines, chunk boundaries, etc.).

This document is a code-grounded investigation that explains **why** these behaviors occur by tracing the relevant source code paths. Every claim is backed by specific file and line references. No assumptions are made — the code is the sole source of truth.

### Questions Investigated

| # | Question |
|---|----------|
| **Q1** | Which decoder types are reported for a given secret, and why does the same logical secret produce distinct `DecoderType` labels? |
| **Q2** | Under what conditions does the verification overlap path activate, and what error message does it produce? |
| **Q3** | How does the LRU deduplication cache in the notifier worker decide whether to suppress a result or emit it? |
| **Q4** | Does deduplication happen before or after overlap detection in the pipeline? |
| **Q5** | Why does the same logical secret sometimes produce one result and sometimes produce multiple results? |

### Background Reading

For general architecture context, see the existing documentation:

- [`docs/concurrency.md`](../../docs/concurrency.md) — Mermaid sequence diagram of worker types and channel topology.
- [`docs/process_flow.md`](../../docs/process_flow.md) — Four-stage data flow: Source Decomposition → Detector Matching → Secret Detection → Result Notification.

All analysis below was performed via static code inspection of the repository. No runtime test data was created or modified.

---

## Q1: Decoder Pipeline Mechanics — Why Does the Same Secret Produce Different DecoderType Labels?

### 1.1 Decoder Ordering and the `DefaultDecoders()` Contract

The decoder chain is defined in `DefaultDecoders()`:

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

> Source: `pkg/decoders/decoders.go:8-16`

**Ordering**: UTF8 (PLAIN) → Base64 (BASE64) → UTF16 (UTF16) → EscapedUnicode (ESCAPED_UNICODE).

**The comment on line 10 is critical**: *"UTF8 must be first for duplicate detection."* The rationale is that the notifier worker's deduplication cache (see [Q3](#q3-result-deduplication-in-the-notifier-worker)) stores results keyed by `(DetectorType, Raw, RawV2, SourceMetadata)` and records which `DecoderType` produced each entry. Because the scanner worker iterates decoders in order (Source: `pkg/engine/engine.go:784`), the UTF8/PLAIN decoder's result is **always cached first**. When a subsequent decoder (e.g., Base64) produces a result with the **same key but a different `DecoderType`**, the notifier suppresses it as a cross-decoder duplicate. If UTF8 were not first, a non-PLAIN result might be cached first, and the PLAIN result would be suppressed instead — leading to confusing output where a plaintext secret is labeled with an encoding-specific decoder type.

> Source: `pkg/decoders/decoders.go:10`

### 1.2 Per-Decoder Behavior

Each decoder implements the `Decoder` interface (Source: `pkg/decoders/decoders.go:25-28`), which requires `FromChunk(chunk *sources.Chunk) *DecodableChunk` and `Type() detectorspb.DecoderType`.

| Decoder | Source File | `Type()` Return | Mutation Behavior | Returns `nil` When |
|---------|-------------|-----------------|-------------------|--------------------|
| **UTF8** | `pkg/decoders/utf8.go` | `DecoderType_PLAIN` (=1) | Mutates `chunk.Data` in place when `!utf8.Valid(chunk.Data)` (line 23–24) | `chunk == nil \|\| len(chunk.Data) == 0` (line 17) |
| **Base64** | `pkg/decoders/base64.go` | `DecoderType_BASE64` (=2) | Mutates `chunk.Data` in place with decoded content (line 67: `chunk.Data = result.Bytes()`) | No valid Base64 substrings of length > 20 chars found (line 36, threshold=20) |
| **UTF16** | `pkg/decoders/utf16.go` | `DecoderType_UTF16` (=3) | Mutates `chunk.Data` in place (line 28: `chunk.Data = utf16Data`) | Input is not valid UTF-16 or conversion yields empty data (lines 24–27) |
| **EscapedUnicode** | `pkg/decoders/escaped_unicode.go` | `DecoderType_ESCAPED_UNICODE` (=4) | **Clones** data before modification (line 39: `chunkData = bytes.Clone(chunk.Data)`) and returns a **new** `Chunk` struct (lines 52–64) | No `U+XXXX` or `\uXXXX` patterns match (lines 42–49) |

The protobuf enum values are defined in:

```protobuf
enum DecoderType {
  UNKNOWN = 0;
  PLAIN = 1;
  BASE64 = 2;
  UTF16 = 3;
  ESCAPED_UNICODE = 4;
}
```

> Source: `proto/detectors.proto:7-13`

### 1.3 Mutation Semantics: In-Place vs. Clone

This is the most subtle aspect of the decoder pipeline and the root cause of several observed behavioral variations.

**Key data structure**: `DecodableChunk` (Source: `pkg/decoders/decoders.go:20-23`) embeds a pointer to `*sources.Chunk`:

```go
type DecodableChunk struct {
    *sources.Chunk
    DecoderType detectorspb.DecoderType
}
```

Because multiple decoders receive the **same `*sources.Chunk` pointer** in the scanner worker's decoder loop (Source: `pkg/engine/engine.go:784-786`), any decoder that mutates `chunk.Data` affects all subsequent decoders.

#### UTF8 Decoder (in-place mutation)

```go
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

> Source: `pkg/decoders/utf8.go:16-29`

- Wraps the **same** `chunk` pointer in `DecodableChunk` (line 21).
- If the data is already valid UTF-8, it returns the chunk **unchanged**.
- If NOT valid UTF-8, it replaces `chunk.Data` with a sanitized version (line 24). This mutation propagates to all subsequent decoders because they share the same pointer.

#### Base64 Decoder (in-place mutation — CRITICAL)

```go
func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
    encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
    // ... decoding logic ...
    if len(decodedSubstrings) > 0 {
        // ... builds result buffer ...
        chunk.Data = result.Bytes()  // <-- MUTATES the shared chunk
        return decodableChunk
    }
    return nil
}
```

> Source: `pkg/decoders/base64.go:34-72`

- Also wraps the **same** `chunk` pointer (line 35).
- When valid Base64 substrings are found and decoded, it **replaces** `chunk.Data` with a buffer containing the decoded content (line 67).
- **This is the most impactful mutation**: after the Base64 decoder runs, the UTF16 and EscapedUnicode decoders see the **Base64-decoded data**, not the original input. This can cause later decoders to find (or not find) patterns they otherwise would (or wouldn't) have matched.

#### UTF16 Decoder (in-place mutation)

```go
func (d *UTF16) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    // ...
    decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
    if utf16Data, err := utf16ToUTF8(chunk.Data); err == nil {
        if len(utf16Data) == 0 { return nil }
        chunk.Data = utf16Data  // <-- MUTATES the shared chunk
        return decodableChunk
    }
    return nil
}
```

> Source: `pkg/decoders/utf16.go:18-33`

- Same pattern: wraps the same pointer (line 23), mutates `chunk.Data` in place (line 28).

#### EscapedUnicode Decoder (CLONE — different pattern)

```go
func (d *EscapedUnicode) FromChunk(chunk *sources.Chunk) *DecodableChunk {
    if chunk == nil || len(chunk.Data) == 0 { return nil }
    var (
        chunkData = bytes.Clone(chunk.Data)  // <-- CLONES before modifying
        matched   = false
    )
    // ... pattern matching on chunkData ...
    if matched {
        return &DecodableChunk{
            DecoderType: d.Type(),
            Chunk: &sources.Chunk{         // <-- Returns a NEW Chunk struct
                Data:           chunkData,
                SourceName:     chunk.SourceName,
                // ... copies all other fields ...
            },
        }
    }
    return nil
}
```

> Source: `pkg/decoders/escaped_unicode.go:32-68`

- Uses `bytes.Clone(chunk.Data)` on line 39 to create an **independent copy** of the data.
- Returns a brand **new** `sources.Chunk` struct (lines 54–63) rather than reusing the original pointer.
- **Consequence**: EscapedUnicode does **not** propagate mutations to the original chunk. However, it operates on whatever `chunk.Data` contains at the time it runs — which may already have been mutated by UTF8 or Base64.

#### Decoder Mutation Flow Diagram

```mermaid
flowchart TD
    A["Original chunk.Data\n(shared pointer)"] --> B["UTF8.FromChunk()"]
    B -->|"Mutates chunk.Data in place\nif !utf8.Valid"| C["chunk.Data\n(possibly sanitized)"]
    C --> D["Base64.FromChunk()"]
    D -->|"Mutates chunk.Data in place\nif valid Base64 found"| E["chunk.Data\n(possibly Base64-decoded)"]
    E --> F["UTF16.FromChunk()"]
    F -->|"Mutates chunk.Data in place\nif valid UTF-16 found"| G["chunk.Data\n(possibly UTF-16 decoded)"]
    G --> H["EscapedUnicode.FromChunk()"]
    H -->|"Clones chunk.Data first\n(bytes.Clone) — no shared mutation"| I["Independent copy\n(new Chunk struct)"]

    style B fill:#ffcc99,color:#000
    style D fill:#ff9999,color:#000
    style F fill:#ff9999,color:#000
    style H fill:#99ff99,color:#000
```

**Legend**: 🟠 Orange = conditional in-place mutation. 🔴 Red = definite in-place mutation (when returning non-nil). 🟢 Green = clone-based, no shared mutation.

### 1.4 DecoderType Label Assignment

Each decoder's `FromChunk()` produces a `DecodableChunk` tagged with its own `DecoderType`. This type label is carried through the pipeline:

1. The scanner worker stores it in `detectableChunk.decoder` (Source: `pkg/engine/engine.go:813`).
2. The `processResult` function copies it to the final output: `secret.DecoderType = data.decoder` (Source: `pkg/engine/engine.go:1178`).
3. The notifier worker's dedup cache records it for comparison (Source: `pkg/engine/engine.go:1221`).

**Answer to Q1**: The same logical secret produces different `DecoderType` labels because each decoder in the chain independently processes the chunk and tags its output with its own type. A plaintext AWS key processed by the UTF8 decoder gets `PLAIN`, while if that same key also exists as a Base64-encoded string in the same chunk, the Base64 decoder decodes it and tags the result `BASE64`. The two results carry different `DecoderType` labels even though they represent the same underlying credential.

---

## Q2: Verification Overlap Detection — When Does `errOverlap` Trigger?

### 2.1 Scanner Worker Routing Decision

The `scannerWorker()` function (Source: `pkg/engine/engine.go:777-841`) contains the decoder loop that determines whether a decoded chunk enters the normal detection path or the overlap-handling path.

The key routing logic:

```go
for _, decoder := range e.decoders {
    decoded := decoder.FromChunk(chunk)       // line 786
    if decoded == nil { continue }             // lines 790-793

    matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)  // line 795

    if len(matchingDetectors) > 1 && !e.verificationOverlap {  // line 796
        // Route to verification overlap channel
        e.verificationOverlapChunksChan <- verificationOverlapChunk{...}  // lines 798-803
        continue
    }

    // Route directly to detector workers
    for _, detector := range matchingDetectors {  // lines 807-816
        e.detectableChunksChan <- detectableChunk{...}
    }
}
```

> Source: `pkg/engine/engine.go:784-816`

**Routing condition** (line 796): `len(matchingDetectors) > 1 && !e.verificationOverlap`

| Condition | Path | Channel |
|-----------|------|---------|
| >1 detector matches **AND** `verificationOverlap` flag is `false` | Overlap handling | `verificationOverlapChunksChan` |
| ≤1 detector matches **OR** `verificationOverlap` flag is `true` | Normal detection | `detectableChunksChan` |

The `e.verificationOverlap` field corresponds to the `--allow-verification-overlap` CLI flag (Source: `pkg/engine/engine.go:180, 240`). When set to `true`, it bypasses overlap handling entirely, sending all chunks directly to detector workers regardless of how many detectors match.

```mermaid
flowchart TD
    A["scannerWorker\nreceives chunk"] --> B["for each decoder\nin DefaultDecoders()"]
    B --> C["decoder.FromChunk(chunk)"]
    C -->|"nil"| B
    C -->|"non-nil"| D["FindDetectorMatches\n(decoded.Chunk.Data)"]
    D --> E{">1 detector match\nAND\n!verificationOverlap?"}
    E -->|"YES"| F["verificationOverlap\nChunksChan"]
    E -->|"NO"| G["for each matching\ndetector"]
    G --> H["detectableChunksChan"]

    style F fill:#ffcc99,color:#000
    style H fill:#99ccff,color:#000
```

### 2.2 The `verificationOverlapWorker`

The `verificationOverlapWorker()` (Source: `pkg/engine/engine.go:924-1034`) processes chunks that matched multiple detectors. Its purpose is to determine whether different detectors found the **same** secret (an overlap) and, if so, prevent redundant verification API calls.

**Algorithm summary:**

1. **For each chunk** from `verificationOverlapChunksChan` (line 932):
2. **For each matching detector** (line 933):
   - Run the detector's `FromData` with `verify=false` (line 940) — detection without verification.
   - For each result, construct a `chunkSecretKey` from the raw secret value and detector key (line 977).
   - Check if this secret already appeared in the chunk's secret map via `likelyDuplicate()` (line 982).
3. **If duplicate detected** (same secret found by a different detector):
   - Set `errOverlap` on the result: `res.SetVerificationError(errOverlap)` (line 988).
   - Call `processResult()` to emit the result immediately (lines 989–999) — with verification disabled.
   - Remove this detector from the re-send list (line 1004).
4. **After all detectors are checked**, re-send non-duplicate detectors to `detectableChunksChan` **with verification enabled** (lines 1011–1019).

> Source: `pkg/engine/engine.go:924-1034`

### 2.3 The `likelyDuplicate()` Algorithm

```go
func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
    const similarityThreshold = 0.9
    // ...
}
```

> Source: `pkg/engine/engine.go:887-922`

**Steps for each existing entry in the `dupes` map:**

1. **Quick length check** (line 894): Skip if string lengths differ by more than ~10%. This avoids expensive string comparison for obviously different secrets.
2. **Same-detector skip** (lines 900–902): If `val.detectorKey.Type() == dupeKey.detectorKey.Type()`, skip — the same detector finding the same secret is expected behavior, not malicious overlap.
3. **Exact match** (line 904): If the secret strings are identical, return `true` immediately.
4. **Levenshtein similarity** (line 911): Compute `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())`. If similarity exceeds 0.9, return `true`.

**Key design decision**: This function **only compares secrets across different detector types**. Two findings from the same detector are always considered legitimate, even if they contain the exact same raw value.

> Source: `pkg/engine/engine.go:887-922`

### 2.4 The `errOverlap` Sentinel Error

```go
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
        "You can override this behavior by using the --allow-verification-overlap flag.",
)
```

> Source: `pkg/engine/engine.go:39-42`

This sentinel error is:

- Set on results via `res.SetVerificationError(errOverlap)` (Source: `pkg/engine/engine.go:988`).
- Visible to users because the notifier worker checks `result.VerificationError()` (Source: `pkg/engine/engine.go:1194`) to decide how to filter the result based on `--results` flags.
- Suppressible by the user via `--allow-verification-overlap`, which sets `e.verificationOverlap = true` (Source: `pkg/engine/engine.go:240`) and causes the scanner worker to bypass the overlap path entirely (Source: `pkg/engine/engine.go:796`).

### 2.5 Re-send Path for Non-Duplicates

After overlap checking completes for a chunk, detectors that were **not** flagged as duplicates are re-sent to `detectableChunksChan` for full detection with verification re-evaluated via `shouldVerifyChunk()`:

```go
for _, detector := range detectorKeysWithResults {
    wgDetect.Add(1)
    chunk.chunk.Verify = e.shouldVerifyChunk(chunk.chunk.Verify, detector, e.detectorVerificationOverrides)
    e.detectableChunksChan <- detectableChunk{
        chunk:    chunk.chunk,
        detector: detector,
        decoder:  chunk.decoder,
        wgDoneFn: wgDetect.Done,
    }
}
```

> Source: `pkg/engine/engine.go:1011-1019`

Only the flagged-duplicate detectors get `errOverlap`. Non-duplicate detectors proceed through the normal detection-and-verification path.

**Answer to Q2**: The `errOverlap` error triggers when **all** of the following conditions are met:
1. Multiple detectors keyword-match the same decoded chunk (Aho-Corasick returns >1 match).
2. The `--allow-verification-overlap` flag is **not** set.
3. `likelyDuplicate()` finds that secrets extracted by different detectors have >0.9 Levenshtein similarity (or exact match).

---

## Q3: Result Deduplication in the Notifier Worker

### 3.1 LRU Cache Key Composition

The deduplication cache is initialized in `initialize()`:

```go
const cacheSize = 512
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
// ...
e.dedupeCache = cache
```

> Source: `pkg/engine/engine.go:491-520`

Key properties:
- **Type**: `lru.Cache[string, detectorspb.DecoderType]` — maps a string key to the `DecoderType` that first produced this result.
- **Size**: 512 entries (line 491).
- **Declared at**: `pkg/engine/engine.go:207-209`.

### 3.2 DecoderType Comparison Logic

The deduplication logic in `notifierWorker()` (Source: `pkg/engine/engine.go:1189-1235`) is concentrated in lines 1210–1221:

```go
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

> Source: `pkg/engine/engine.go:1210-1221`

**Key composition** (line 1216):

| Component | Source | Purpose |
|-----------|--------|---------|
| `result.DetectorType.String()` | e.g., `"AWS"` | Which detector found the secret |
| `result.Raw` | Raw secret bytes | The secret identifier (prefer IDs over secrets) |
| `result.RawV2` | Combined ID + secret bytes | For multi-part secrets (e.g., AWS key ID + secret key) |
| `result.SourceMetadata` | File path, line number, etc. | Source-specific context |

**Deduplication decision** (lines 1217–1219):

A result is **suppressed** (`continue`) when:
1. The key already exists in the cache (`ok == true`), **AND**
2. Either:
   - The cached `DecoderType` **differs** from the current result's `DecoderType` (`val != result.DecoderType`), **OR**
   - The source type is Postman (`result.SourceType == SOURCE_TYPE_POSTMAN`).

### 3.3 Same-Decoder vs. Cross-Decoder Behavior

The deduplication logic produces these behaviors:

| Scenario | Cache State | Current Result | Outcome | Rationale |
|----------|-------------|----------------|---------|-----------|
| First result for this key | Key not in cache | Any DecoderType | **EMIT** — added to cache | No duplicate exists |
| Same key, **different** DecoderType | Key in cache with type A | Type B (B ≠ A) | **SUPPRESS** | Cross-decoder duplicate — same secret found by different encoding paths |
| Same key, **same** DecoderType | Key in cache with type A | Type A | **EMIT** | Same-decoder duplicate — the secret genuinely appears multiple times |

**Why allow same-decoder duplicates?** The comments at lines 1213–1214 explain: *"Duplicate results with the same decoder type SHOULD have their own entry in the results list, this would happen if the same secret is found multiple times."* This handles the case where the same literal secret string appears at multiple locations (different SourceMetadata) but is discovered by the same decoder.

**Why suppress cross-decoder duplicates?** When a plaintext secret and its Base64-encoded form are in the same chunk, both the UTF8 and Base64 decoders will extract the same underlying credential. Reporting it twice (once as PLAIN, once as BASE64) would be noise. The dedup cache ensures only the first one through (PLAIN, because UTF8 runs first) is reported.

### 3.4 Postman Special Case

```go
result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN
```

> Source: `pkg/engine/engine.go:1218`

For Postman sources, **all** duplicates are suppressed regardless of `DecoderType` — even same-decoder duplicates. The code does not document the motivation for this Postman-specific override. The effect is that all duplicates are suppressed for Postman sources, regardless of DecoderType.

```mermaid
flowchart TD
    A["Result arrives at\nnotifierWorker"] --> B["Compute key =\nDetectorType + Raw\n+ RawV2 + SourceMetadata"]
    B --> C{"Key exists in\ndedupeCache?"}
    C -->|"NO"| D["Add to cache\nEMIT result ✓"]
    C -->|"YES"| E{"Cached DecoderType\n≠ result.DecoderType?"}
    E -->|"YES"| F["SUPPRESS ✗\n(cross-decoder duplicate)"]
    E -->|"NO"| G{"Source is\nPostman?"}
    G -->|"YES"| F
    G -->|"NO"| H["Update cache\nEMIT result ✓\n(same-decoder, different occurrence)"]

    style F fill:#ff9999,color:#000
    style D fill:#99ff99,color:#000
    style H fill:#99ff99,color:#000
```

**Answer to Q3**: The LRU deduplication cache (512 entries) keys on `DetectorType + Raw + RawV2 + SourceMetadata` and stores the `DecoderType` value. When the same key appears with a **different** `DecoderType`, the result is suppressed (cross-decoder duplicate). When the same key appears with the **same** `DecoderType`, the result passes through (to report genuinely repeated secrets). Postman sources are always deduplicated regardless of `DecoderType`.

---

## Q4: Pipeline Stage Ordering — Does Deduplication Happen Before or After Overlap Detection?

### 4.1 Channel Topology

The pipeline is organized as a series of worker pools connected by Go channels. The `Finish()` method (Source: `pkg/engine/engine.go:723-742`) reveals the temporal ordering by showing the shutdown sequence — each stage must complete before the next channel is closed:

```go
func (e *Engine) Finish(ctx context.Context) error {
    // ...
    err := e.sourceManager.Wait()              // Stage 1: sources finish producing chunks

    e.workersWg.Wait()                          // Stage 2: scanner workers finish
    close(e.verificationOverlapChunksChan)      // Close overlap input channel

    e.verificationOverlapWg.Wait()              // Stage 2.5: overlap workers finish
    close(e.detectableChunksChan)               // Close detector input channel

    e.wgDetectorWorkers.Wait()                  // Stage 3: detector workers finish
    close(e.results)                            // Close results channel

    e.WgNotifier.Wait()                         // Stage 4: notifier workers finish
    // ...
}
```

> Source: `pkg/engine/engine.go:723-742`

### 4.2 Temporal Flow: Overlap Detection (Stage 2/3) Before Deduplication (Stage 4)

The five pipeline stages execute in this order:

| Stage | Worker | Input Channel | Output Channel | Purpose |
|-------|--------|---------------|----------------|---------|
| **1** | Sources | — | `ChunksChan()` | Produce raw data chunks |
| **2** | Scanner Workers | `ChunksChan()` | `verificationOverlapChunksChan` or `detectableChunksChan` | Decode chunks, route by detector match count |
| **2.5** | Verification Overlap Workers | `verificationOverlapChunksChan` | `detectableChunksChan` (non-duplicates) or `results` (duplicates with errOverlap) | Cross-detector duplicate detection |
| **3** | Detector Workers | `detectableChunksChan` | `results` | Run detection, verification, filtering |
| **4** | Notifier Workers | `results` | Output (dispatch) | LRU deduplication, result notification |

```mermaid
flowchart LR
    subgraph "Stage 1"
        Sources["Sources"]
    end
    subgraph "Stage 2"
        SW["Scanner\nWorkers"]
    end
    subgraph "Stage 2.5"
        VOW["Verification\nOverlap Workers"]
    end
    subgraph "Stage 3"
        DW["Detector\nWorkers"]
    end
    subgraph "Stage 4"
        NW["Notifier\nWorkers"]
    end

    Sources -->|"ChunksChan"| SW
    SW -->|"verificationOverlap\nChunksChan\n(>1 detector match)"| VOW
    SW -->|"detectableChunksChan\n(≤1 detector match)"| DW
    VOW -->|"detectableChunksChan\n(non-duplicate detectors)"| DW
    VOW -->|"results\n(duplicate + errOverlap)"| NW
    DW -->|"results"| NW
    NW -->|"LRU dedup"| Output["Output"]
```

**Crucial distinction between the two deduplication stages:**

| Property | Overlap Detection (Stage 2.5) | Notifier Deduplication (Stage 4) |
|----------|-------------------------------|----------------------------------|
| **Scope** | Cross-**detector** within a single chunk | Cross-**decoder** across all results |
| **Question** | "Did different detectors find the same secret in this chunk?" | "Did different decoders produce the same (DetectorType, Raw, RawV2, SourceMetadata)?" |
| **Algorithm** | Levenshtein similarity > 0.9 | Exact key match in LRU cache |
| **Action** | Set `errOverlap`, skip verification | Suppress result (silent drop) |
| **Granularity** | Per-chunk, per-detector-pair | Global across all chunks |

**Answer to Q4**: Overlap detection (Stage 2.5, `verificationOverlapWorker`) happens **before** notifier deduplication (Stage 4, `notifierWorker`). They are separated by the detector worker stage (Stage 3). Overlap detection addresses cross-detector conflicts within a chunk; notifier deduplication addresses cross-decoder redundancy across the entire scan.

---

## Q5: Why Do Result Counts Vary for the Same Logical Secret?

The number of results depends on several interacting factors. We trace four representative scenarios through the full pipeline.

### 5.1 Scenario: Raw Key Only

**Input**: A file containing only the plaintext AWS access key `AKIAIOSFODNN7EXAMPLE` (20 characters).

**Decoder pass-through:**

1. **UTF8**: Data is valid UTF-8 → returns `DecodableChunk` with `PLAIN` type, `chunk.Data` unchanged. ✓
2. **Base64**: Calls `getSubstringsOfCharacterSet(chunk.Data, 20, ...)`. The threshold check at line 97 uses `count > threshold` — **strictly greater than**. `AKIAIOSFODNN7EXAMPLE` is exactly 20 characters, so `count` (20) is **not** > `threshold` (20). Returns `nil`. ✗
3. **UTF16**: Plain ASCII text lacks the zero-byte patterns needed for UTF-16 detection. Returns `nil`. ✗
4. **EscapedUnicode**: No `U+XXXX` or `\uXXXX` patterns present. Returns `nil`. ✗

> Source: `pkg/decoders/base64.go:83-130` (getSubstringsOfCharacterSet), specifically line 97

**Pipeline**: 1 `DecodableChunk` (PLAIN) → 1 detector match → 1 result → **1 output**.

### 5.2 Scenario: Raw + Base64 on Same Chunk

**Input**: A file (single chunk) containing both `AKIAIOSFODNN7EXAMPLE` and its Base64 encoding `QUtJQUlPU0ZPRE5ON0VYQU1QTEU=` (28 characters, >20 threshold).

**Decoder pass-through:**

1. **UTF8**: Returns `PLAIN` `DecodableChunk` with original data. Chunk contains both the raw key and the Base64 string.
2. **Base64**: Finds a valid Base64 substring (28 chars > 20 threshold). Decodes it. **Mutates** `chunk.Data` (line 67) — the Base64-encoded portion is replaced with decoded bytes (which is the same key `AKIAIOSFODNN7EXAMPLE`). Returns `BASE64` `DecodableChunk`.
3. **UTF16**: Now seeing mutated data. ASCII text does not contain the zero-byte patterns that `utf16ToUTF8()` (`pkg/decoders/utf16.go:39`) scans for, so `bufBE` and `bufLE` remain empty and the decoder returns `nil`. ✗
4. **EscapedUnicode**: Clones the (now-mutated) data. No escape patterns. Returns `nil`. ✗

**Two `DecodableChunks`** enter the pipeline: one PLAIN, one BASE64. Assuming only the AWS detector keyword-matches each (≤1 detector match), both go directly to `detectableChunksChan`.

**At the notifier worker:**
- **PLAIN result arrives first** (UTF8 runs first in the decoder loop): `key = "AWS" + Raw + RawV2 + SourceMetadata` → not in cache → **EMIT**, cache stores `DecoderType=PLAIN`.
- **BASE64 result arrives second**: same `key` (same DetectorType, same Raw secret, same RawV2, same SourceMetadata) → cache hit → cached type `PLAIN` ≠ current type `BASE64` → **SUPPRESS**.

> Source: `pkg/engine/engine.go:1216-1221`

**Result**: 2 `DecodableChunks` → 2 detections → **1 output** (cross-decoder dedup suppresses the BASE64 result).

### 5.3 Scenario: Raw + Base64 on Separate Lines (Different SourceMetadata)

**Input**: The plaintext key is in one git commit (or file), and the Base64-encoded version is in a different commit (or file). They arrive as **separate chunks** with different `SourceMetadata`.

**Decoder pass-through**: Each chunk is processed independently. Each produces its own `DecodableChunk` (PLAIN for the first, BASE64 for the second).

**At the notifier worker:**
- **PLAIN result**: `key = "AWS" + Raw + RawV2 + SourceMetadata_A` → not in cache → **EMIT**.
- **BASE64 result**: `key = "AWS" + Raw + RawV2 + SourceMetadata_B` → **different key** (SourceMetadata differs) → not in cache → **EMIT**.

> Source: `pkg/engine/engine.go:1216` — SourceMetadata is part of the key

**Result**: 2 `DecodableChunks` → 2 detections → **2 outputs** (different dedup keys due to different SourceMetadata).

### 5.4 Scenario: Raw + Escaped Unicode

**Input**: A file (single chunk) containing `AKIAIOSFODNN7EXAMPLE` and its Unicode-escaped form `\u0041\u004B\u0049\u0041...`.

**Decoder pass-through:**

1. **UTF8**: Returns `PLAIN` with original data. ✓
2. **Base64**: The backslash character `\` in `\uXXXX` escape sequences is not in the Base64 character set (`pkg/decoders/base64.go:17`), so it breaks consecutive Base64-character runs. No substring exceeds the 20-character threshold. Returns `nil`. ✗
3. **UTF16**: Returns `nil` (no zero-byte patterns). ✗
4. **EscapedUnicode**: Clones `chunk.Data` (line 39), finds `\uXXXX` patterns, decodes them to the same key. Returns `ESCAPED_UNICODE` with a **new** `Chunk` struct (lines 54–63). ✓

**Two `DecodableChunks`**: PLAIN and ESCAPED_UNICODE. Both enter the detection pipeline.

**At the notifier worker:**
- **PLAIN result arrives first**: `key = "AWS" + Raw + RawV2 + SourceMetadata` → **EMIT**, cache stores `PLAIN`.
- **ESCAPED_UNICODE result**: same key → cache hit → cached `PLAIN` ≠ current `ESCAPED_UNICODE` → **SUPPRESS**.

**Result**: 2 `DecodableChunks` → 2 detections → **1 output** (cross-decoder dedup suppresses the ESCAPED_UNICODE result).

### 5.5 Why the Variability? — Contributing Factors

```mermaid
flowchart TD
    Q["Why does result\ncount vary?"] --> F1["Base64 threshold\n(>20 chars required)"]
    Q --> F2["Chunk mutation\n(shared pointer)"]
    Q --> F3["SourceMetadata\nin dedup key"]
    Q --> F4["DecoderType\ncomparison logic"]
    Q --> F5["Overlap detection\n(>1 detector match)"]
    Q --> F6["EscapedUnicode\nclone behavior"]

    F1 --> R1["Short secrets: only PLAIN result\nLong secrets: PLAIN + BASE64"]
    F2 --> R2["Earlier decoder mutations affect\nlater decoders' input data"]
    F3 --> R3["Same secret at different locations\n= different keys = both emitted"]
    F4 --> R4["Same secret via different decoders\n= same key + different type = suppressed"]
    F5 --> R5["Multiple detector matches →\nerrOverlap instead of verification"]
    F6 --> R6["EscapedUnicode immune to\nprior decoder mutations on pointer\n(but sees mutated data)"]
```

**Summary of variability factors:**

1. **Base64 length threshold** (Source: `pkg/decoders/base64.go:97`): The `>20` character requirement means short secrets never produce a BASE64 variant. A secret exactly 20 characters long does **not** qualify.
2. **Chunk mutation via shared pointer** (Source: `pkg/decoders/base64.go:67`, `pkg/decoders/utf8.go:24`, `pkg/decoders/utf16.go:28`): Because UTF8, Base64, and UTF16 decoders all mutate `chunk.Data` in place on the same shared pointer, earlier decoder mutations change what later decoders see.
3. **SourceMetadata in dedup key** (Source: `pkg/engine/engine.go:1216`): Same secret at different locations (different file, line, commit) produces different dedup keys, so both are emitted.
4. **DecoderType comparison in dedup** (Source: `pkg/engine/engine.go:1217`): Same secret from the same location via different decoders produces the same key but different DecoderType — the second one is suppressed.
5. **Verification overlap detection** (Source: `pkg/engine/engine.go:796`): If >1 detector keyword-matches and `--allow-verification-overlap` is not set, the chunk enters the overlap path. Results may get `errOverlap` instead of clean verification.
6. **EscapedUnicode's clone semantics** (Source: `pkg/decoders/escaped_unicode.go:39`): Unlike other decoders, EscapedUnicode creates an independent data copy. It cannot be affected by mutations from the **same** run of later decoders (since it returns a new Chunk), but it reads whatever `chunk.Data` contains at the time it executes.

**Answer to Q5**: Result counts vary because the pipeline's output depends on a combination of: (a) whether the encoded form exceeds the Base64 threshold, (b) whether `SourceMetadata` differs between occurrences, (c) the cross-decoder suppression logic in the dedup cache, (d) the decoder ordering and mutation side effects, and (e) whether multiple detectors match (triggering overlap detection). All of these factors interact to produce 1, 2, or error-flagged results for the same underlying secret.

---

## Summary of Answers

| Question | Answer |
|----------|--------|
| **Q1 — Decoder Type Reporting** | The same secret produces different `DecoderType` labels because each of the four decoders (PLAIN, BASE64, UTF16, ESCAPED_UNICODE) independently processes the chunk and tags its output. The ordering is fixed: UTF8 → Base64 → UTF16 → EscapedUnicode (`Source: pkg/decoders/decoders.go:8-16`). UTF8 must be first so that the PLAIN result enters the dedup cache before any encoded variant. |
| **Q2 — Overlap Detection** | `errOverlap` triggers when (a) >1 detectors keyword-match the same decoded chunk, (b) `--allow-verification-overlap` is not set, and (c) `likelyDuplicate()` finds >0.9 Levenshtein similarity between secrets from different detectors (`Source: pkg/engine/engine.go:887-922`). The error message is defined at `Source: pkg/engine/engine.go:39-42`. |
| **Q3 — Deduplication** | The LRU cache (512 entries) at `Source: pkg/engine/engine.go:207-209, 491` keys on `DetectorType + Raw + RawV2 + SourceMetadata` and stores `DecoderType`. Cross-decoder duplicates (same key, different DecoderType) are suppressed. Same-decoder duplicates pass through. Postman sources always deduplicate (`Source: pkg/engine/engine.go:1210-1221`). |
| **Q4 — Ordering** | Overlap detection (Stage 2.5) happens **before** notifier deduplication (Stage 4), separated by the detector worker stage (Stage 3). Evidence: the `Finish()` shutdown sequence at `Source: pkg/engine/engine.go:723-742`. |
| **Q5 — Result Count Variability** | Counts vary due to: Base64's >20-char threshold (`Source: pkg/decoders/base64.go:97`), in-place chunk mutation by UTF8/Base64/UTF16 decoders, SourceMetadata inclusion in the dedup key, DecoderType comparison logic, and overlap detection routing. The EscapedUnicode decoder's clone behavior (`Source: pkg/decoders/escaped_unicode.go:39`) adds further nuance. |
