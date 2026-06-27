# How TruffleHog Handles One Secret in Multiple Encoded Forms

### Decoder Pipeline, Verification-Overlap Detection, and Result Deduplication — A Source-Grounded, Runtime-Verified Investigation

> **Repository:** `github.com/trufflesecurity/trufflehog/v3`
> **Analyzed commit:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (pinned)
> **Method:** Static source analysis (code as the source of truth) corroborated by a fresh out-of-tree build (`go1.24.2`) and controlled `filesystem` scans.
> **Scope:** Read-only investigation. No source file was modified; all reproduction fixtures and the compiled binary lived outside the repository tree and were removed afterward.

---

## The question being answered

A user scanned a single file that contained both a **raw AWS access key** and the **same key re-encoded as Base64**, and observed seemingly inconsistent output:

1. Sometimes TruffleHog reported the secret **twice with different decoder types**.
2. Sometimes it reported an **overlap error**.
3. Sometimes it **deduplicated down to a single result**.

The behaviour "seemed inconsistent depending on how I structured the test file."

This document explains — grounded in the source and corroborated by reproduced runtime evidence — exactly **how the decoder pipeline, verification-overlap detection, and result deduplication interact** to produce these outputs, and shows that the outcomes are **deterministic consequences of file structure**, with a single well-defined source of run-to-run variation (which decoder type *survives* a collapse).

The investigation is organized around six concrete questions:

| Ref | Question |
|-----|----------|
| **R1** | How does the decoder pipeline handle the same secret in plain text, Base64, and escaped-unicode forms? |
| **R2** | Which `DecoderType` values are reported? |
| **R3** | When does verification-overlap detection occur? |
| **R4** | How does deduplication reduce the final result count? |
| **R5** | Does deduplication happen **before** or **after** overlap detection? |
| **R6** | Why does the same logical secret sometimes yield one result and sometimes multiple? |

---

## Table of contents

1. [Executive summary (TL;DR)](#1-executive-summary-tldr)
2. [The four-stage detection pipeline](#2-the-four-stage-detection-pipeline)
3. [The decoder chain and `DecoderType` enum (R1, R2)](#3-the-decoder-chain-and-decodertype-enum-r1-r2)
4. [Mechanism A — Verification *overlap* (cross-detector, Stage 3) (R3)](#4-mechanism-a--verification-overlap-cross-detector-stage-3-r3)
5. [Mechanism B — Result *deduplication* (cross-decoder, Stage 4) (R4)](#5-mechanism-b--result-deduplication-cross-decoder-stage-4-r4)
6. [Ordering: deduplication happens *after* overlap detection (R5)](#6-ordering-deduplication-happens-after-overlap-detection-r5)
7. [Why one result vs. many — and the concurrency nuance (R6)](#7-why-one-result-vs-many--and-the-concurrency-nuance-r6)
8. [Reproduction appendix (commands + observed evidence)](#8-reproduction-appendix-commands--observed-evidence)
9. ["Code as truth" rationale (per-question)](#9-code-as-truth-rationale-per-question)
10. [Relevant CLI flags](#10-relevant-cli-flags)
11. [Version caveat](#11-version-caveat)

---

## 1. Executive summary (TL;DR)

The user is observing the **combined effect of two completely separate mechanisms** that operate at different stages of the pipeline and answer different questions. Conflating them is the root of the "inconsistent" perception.

> [!IMPORTANT]
> **These are two distinct mechanisms. Keep them separate.**
>
> | | Verification **OVERLAP** | Result **DEDUPLICATION** |
> |---|---|---|
> | **Granularity** | cross-**detector** | cross-**decoder** |
> | **Question it answers** | "Did 2+ *different detectors* fire on the same decoded chunk? If so, don't trust automated verification." | "Is this the same secret already reported under a *different decoder type*?" |
> | **Pipeline stage** | **Stage 3** — `verificationOverlapWorker` | **Stage 4** — `notifierWorker` |
> | **Effect on output** | Attaches an `errOverlap` verification error; disables verification for the overlapping result | Drops a later result whose dedup key collides but whose decoder type differs |
> | **Key code** | `pkg/engine/engine.go:L796`, `L924-L1034` | `pkg/engine/engine.go:L1189-L1235` (key at `L1216`) |

With that separation in mind, the three observations resolve cleanly:

| User observed | Why it happens | Deterministic? |
|---------------|----------------|----------------|
| **"deduplicated to a single result"** | The plaintext and Base64 variants resolve to the **same source line**, so they produce an **identical dedup key**; the cross-decoder dedup in the notifier drops the colliding one. | The **dedup key is deterministic** (same line ⇒ identical key). The resulting count is **usually 1**, but under default multi-worker concurrency a *rare*, non-atomic notifier `Get`/`Add` race can let **both** survive (count = 2); `--concurrency=1` makes the collapse stable. *Which* decoder type survives a collapse is also non-deterministic (see R6). |
| **"reported twice with different decoder types"** | The variants resolve to **different source lines**, so the line number embedded in `SourceMetadata` makes their dedup keys **differ** → both are kept, one `PLAIN`, one `BASE64`. | Deterministic for a fixed file layout (different keys never collide, so concurrency is irrelevant here). |
| **"reported an overlap error"** | **Two or more distinct detectors** matched the **same decoded chunk**, triggering the Stage-3 overlap guard, which attaches `errOverlap` and disables verification. | Deterministic; suppressed by `--allow-verification-overlap`. |

**One-line answer:** the outcome is governed jointly by (a) *which detectors fire on a chunk* (overlap path) and (b) *the cross-decoder dedup key, whose `SourceMetadata` component carries the source line number* (dedup path). The **dedup key** is a deterministic function of file layout; what is *not* guaranteed is the **actual output count under concurrent notifier workers** — same-key / different-decoder results **usually** collapse to one, but because the notifier's dedup is a non-atomic `Get`-then-`Add` performed by `concurrency` parallel workers (`pkg/engine/engine.go:L1217-L1221`, `:L705-L706`), a rare race can let both through (count = 2). Separately, *which* decoder-type label survives a collapse is also non-deterministic. Running with `--concurrency=1` removes the **count** variation (it forces a single notifier worker; §5.6) — but **not** the **label** variation: the *detector* pool stays at `concurrency × 8` workers even at `--concurrency=1` (`pkg/engine/engine.go:L676`, multiplier default 8 at `:L343-L345`), so the surviving label can still rarely flip (§7.2).

---

## 2. The four-stage detection pipeline

TruffleHog's engine is a pipeline of worker pools connected by channels. The narrative `docs/process_flow.md` describes four conceptual stages, and the engine workers in `pkg/engine/engine.go` implement them:

| Stage | Conceptual name (`docs/process_flow.md`) | Engine worker (`pkg/engine/engine.go`) | Channel consumed → produced |
|-------|------------------------------------------|----------------------------------------|------------------------------|
| 1 | **Source Decomposition** (`docs/process_flow.md:L28`) | source chunking | source → `ChunksChan` |
| 2 | **Chunk to Detector Matching** (`docs/process_flow.md:L74`) | `scannerWorker` (`:L777-L841`) | `ChunksChan` → `verificationOverlapChunksChan` / `detectableChunksChan` |
| 3 | **Secret Detection** (`docs/process_flow.md:L88`), incl. the *De-Dupe-Detectors* box (`:L106-L108`) | `verificationOverlapWorker` (`:L924-L1034`) + `detectorWorker` (`:L1036`) | `verificationOverlapChunksChan` → `detectableChunksChan` → `ResultsChan` |
| 4 | **Result Notification** (`docs/process_flow.md:L126`) | `notifierWorker` (`:L1189-L1235`) | `ResultsChan` → dispatcher |

The two mechanisms in this investigation live in **different stages**: verification-overlap is a **Stage 3** concern (`verificationOverlapWorker`), and result deduplication is a **Stage 4** concern (`notifierWorker`). This is the structural reason dedup happens *after* overlap (R5).

The relationship the rest of this document explains:

```mermaid
flowchart TD
    A[Raw Chunk] --> B[Decoder Chain: UTF8 / Base64 / UTF16 / EscapedUnicode]
    B --> C[Each non-nil variant -> Aho-Corasick match]
    C --> D{More than one DISTINCT detector on this chunk AND overlap not allowed?}
    D -- Yes --> E[Stage 3: verificationOverlapWorker<br/>likelyDuplicate + errOverlap, verification disabled]
    D -- No --> F[detectableChunksChan -> detector verification]
    E --> F
    F --> G[Stage 4: notifierWorker LRU dedup<br/>key = DetectorType + Raw + RawV2 + SourceMetadata]
    G --> H{Key seen with a DIFFERENT decoder type?}
    H -- Yes --> I[Skip duplicate]
    H -- No --> J[Dispatch result]
```

**Worker concurrency** (relevant to R6's non-determinism): the detector pool is sized at `concurrency × 8` (`pkg/engine/engine.go:L343-L345`), the verification-overlap pool at `concurrency × 1` (`:L352-L353`), and the notifier at `concurrency × 1` (`:L705-L706`, with the notification multiplier defaulting to 1 at `:L348-L349`; `--concurrency` itself defaults to `runtime.NumCPU()`, `main.go:L58`). Two consequences follow. First, because many detector workers feed a single `ResultsChan`, the *order* in which two variants of the same secret reach the notifier is not guaranteed (this drives the label non-determinism of §7.2). Second, because the notifier runs as **multiple** workers and its dedup is a non-atomic `Get`-then-`Add`, the *emitted count* of a same-line collision is not strictly guaranteed either — a rare race can let both variants through (§5.6).

---

## 3. The decoder chain and `DecoderType` enum (R1, R2)

### 3.1 The fixed decoder chain (R1)

Every chunk is run through a **fixed, ordered chain of four decoders** returned by `DefaultDecoders()`:

```go
// pkg/decoders/decoders.go:L8-L16
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

The ordering is intentional: the comment **"UTF8 must be first for duplicate detection"** sits at `pkg/decoders/decoders.go:L10`. UTF-8 first guarantees a plaintext baseline variant exists before any re-encoding variant, which matters for the dedup behaviour in R6.

Each chunk is decoded in a **single linear pass** inside `scannerWorker`:

```go
// pkg/engine/engine.go:L784-L795 (excerpt)
for _, decoder := range e.decoders {            // L784  single linear pass over the 4 decoders
	...
	decoded := decoder.FromChunk(chunk)         // L786  produce a decoded variant (or nil)
	...
	if decoded == nil {                         // L790-L793  decoder not applicable -> skip
		continue
	}

	matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data) // L795
	...
}
```

Three facts establish how the same secret in multiple encodings is handled:

- **One pass, four decoders.** The loop at `pkg/engine/engine.go:L784` iterates the four decoders exactly once each. There is **no iterative re-decoding** at this commit (see the [version caveat](#11-version-caveat)).
- **Each non-nil variant is scanned independently.** A decoder that doesn't understand a chunk returns `nil` and is skipped (`:L790-L793`); every **non-nil** variant is independently routed into Aho-Corasick keyword matching at `:L795` via `FindDetectorMatches` (defined at `pkg/engine/ahocorasick/ahocorasickcore.go:L241`, doc comment at `:L230`). So **a single raw chunk can produce several decoded variants, each scanned separately** — this is how one logical secret can surface under more than one decoder type.
- **Independent variants, independent results.** Because each variant is matched and (potentially) verified on its own, the *same* secret value can enter the results stream multiple times tagged with different `DecoderType`s — which is exactly what the Stage-4 dedup (R4) later has to reconcile.

### 3.2 What each decoder emits

| Decoder | `Type()` returns | Emits a variant when… | Citation |
|---------|------------------|------------------------|----------|
| `UTF8` | `PLAIN` | always, for any non-empty chunk (returns `nil` only for nil/empty) | `pkg/decoders/utf8.go:L12-L14`; `FromChunk` `:L16-L29` |
| `Base64` | `BASE64` | a base64 run **longer than 20 chars** decodes to **valid ASCII**; otherwise returns `nil` | `pkg/decoders/base64.go:L30-L32`, `:L36`, `:L41-L48`, `:L71` |
| `UTF16` | `UTF16` | the chunk decodes as UTF-16 | `pkg/decoders/utf16.go:L14-L16` |
| `EscapedUnicode` | `ESCAPED_UNICODE` | escaped-unicode sequences are present | `pkg/decoders/escaped_unicode.go:L28-L30` |

**UTF-8 always yields a baseline `PLAIN` variant** for any non-empty chunk: `FromChunk` (`pkg/decoders/utf8.go:L16-L29`) returns `nil` only when the chunk is nil or empty, otherwise it returns a `DecodableChunk` tagged `PLAIN`. This is the plaintext occurrence that the user's raw AWS key is found in.

### 3.3 The Base64 nuance — gating and *in-place* replacement (the crux of R6)

The Base64 decoder is the most consequential for the user's scenario, for two reasons.

**(a) It is gated.** It only emits a `BASE64` variant when a base64 run is both long enough and decodes to printable ASCII:

```go
// pkg/decoders/base64.go:L34-L72 (excerpt)
func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
	encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars) // L36  threshold = 20
	decodedSubstrings := make(map[string][]byte)

	for _, str := range encodedSubstrings {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && isASCII(dec) {          // L41-L43  must be non-empty + ASCII
			decodedSubstrings[str] = dec
		}
		dec, err = base64.RawURLEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && isASCII(dec) {          // L45-L48
			decodedSubstrings[str] = dec
		}
	}

	if len(decodedSubstrings) > 0 {
		// ... in-place replacement (see below) ...               // L51-L67
		return decodableChunk
	}
	return nil                                                    // L71  nothing decoded -> no BASE64 variant
}
```

`getSubstringsOfCharacterSet(..., 20, ...)` requires a base64 run **strictly longer than the threshold of 20** (the internal condition is `count > threshold`, `pkg/decoders/base64.go:L97`/`:L103`/`:L118`/`:L125`). **Consequence:** a *trivially short* base64 encoding produces **no second variant at all**, so for short encodings the questions of overlap and dedup simply never arise.

**(b) It replaces decoded substrings *in place*.** When something does decode, the decoder rebuilds the chunk by substituting the decoded bytes back into their original position, preserving the surrounding plaintext:

```go
// pkg/decoders/base64.go:L51-L67 (excerpt)
var result bytes.Buffer
start := 0
for _, encoded := range encodedSubstrings {
	if decoded, ok := decodedSubstrings[encoded]; ok {
		end := bytes.Index(chunk.Data[start:], []byte(encoded))   // L58  locate the encoded run
		if end != -1 {
			result.Write(chunk.Data[start : start+end])           // keep preceding plaintext
			result.Write(decoded)                                 // L61  splice in decoded bytes
			start += end + len(encoded)
		}
	}
}
result.Write(chunk.Data[start:])
chunk.Data = result.Bytes()                                       // L67  the BASE64 variant chunk
```

**Why this matters for R6:** because replacement is *in place*, the `BASE64` variant chunk still contains **all of the surrounding plaintext**. If a plaintext key *and* a Base64 blob of the same key live in the **same chunk**, then **both** the `PLAIN` variant and the `BASE64` variant contain the key, and **both resolve to the plaintext's first-occurrence line**. Identical line ⇒ identical dedup key ⇒ they collapse to one result (Scenario A). When they land in **different chunks** (or the decoded content resolves to a different line), their line numbers differ ⇒ keys differ ⇒ both survive (Scenario B).

### 3.4 The `DecoderType` enum and how it appears in output (R2)

The four decoder labels come from a protobuf enum:

```go
// pkg/pb/detectorspb/detectors.pb.go:L23, L26-L30
type DecoderType int32

const (
	DecoderType_UNKNOWN         DecoderType = 0
	DecoderType_PLAIN           DecoderType = 1
	DecoderType_BASE64          DecoderType = 2
	DecoderType_UTF16           DecoderType = 3
	DecoderType_ESCAPED_UNICODE DecoderType = 4
)
```

The name map is at `:L35-L41` and the `String()` method at `:L57-L59`. For the user's scenario the relevant labels are **`PLAIN`** (the raw key) and **`BASE64`** (the encoded copy).

**In JSON output, the decoder is reported as the top-level string field `DecoderName`**, not `DecoderType`:

```go
// pkg/output/json.go:L42-L43 (field) and L65 (assignment)
// DecoderName is the string name of the DecoderType.
DecoderName           string
...
DecoderName:           r.DecoderType.String(),   // L65
```

So `-j/--json` output shows `"DecoderName": "PLAIN"` or `"DecoderName": "BASE64"`. (The JSON record *also* carries a numeric `DetectorType` and a string `DetectorName` for the *detector*; these are unrelated to the *decoder*. The plain-text and github-actions printers expose a field literally named `DecoderType` instead — but every JSON example in this document uses `DecoderName`, matching the JSON writer.)

---

## 4. Mechanism A — Verification *overlap* (cross-detector, Stage 3) (R3)

> **Scope of this mechanism:** *cross-**detector***. It asks: *"did two or more **different detectors** match the **same decoded chunk**?"* It is **not** about decoders, and it is a different code path from deduplication (Section 5).

### 4.1 The trigger

Back in `scannerWorker`, after a decoded variant is matched against all detectors, the overlap path is taken when **more than one distinct detector** matched **and** the override flag is off:

```go
// pkg/engine/engine.go:L795-L804 (excerpt)
matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)  // L795
if len(matchingDetectors) > 1 && !e.verificationOverlap {                        // L796  THE TRIGGER
	wgVerificationOverlap.Add(1)
	e.verificationOverlapChunksChan <- verificationOverlapChunk{                 // L797-L804  route to Stage 3
		chunk:                       *decoded.Chunk,
		detectors:                   matchingDetectors,
		decoder:                     decoded.DecoderType,
		verificationOverlapWgDoneFn: wgVerificationOverlap.Done,
	}
	continue
}
```

`matchingDetectors` is the set of detectors whose keywords matched, produced by `FindDetectorMatches` (`pkg/engine/ahocorasick/ahocorasickcore.go:L241`); it returns one `*DetectorMatch` per matching detector key, so `len(matchingDetectors) > 1` precisely means *"at least two distinct detectors keyword-matched this chunk."* The `e.verificationOverlap` field is set by the `--allow-verification-overlap` flag; when the flag is supplied, the guard is bypassed entirely and the chunk goes straight to normal verification.

### 4.2 The overlap worker disables verification and runs the duplicate gate

The routed chunk is handled by `verificationOverlapWorker` (`pkg/engine/engine.go:L924-L1034`). Crucially, it runs detectors **with verification disabled** at this stage:

```go
// pkg/engine/engine.go:L936-L940 (excerpt)
// DO NOT VERIFY at this stage of the pipeline.
matchedBytes := detector.Matches()
for _, match := range matchedBytes {
	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	results, err := detector.FromData(ctx, false, match)   // L940  verify = false
	...
}
```

The cross-detector duplicate decision is made by `likelyDuplicate` (`pkg/engine/engine.go:L887-L921`):

```go
// pkg/engine/engine.go:L887-L921 (structure)
func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
	const similarityThreshold = 0.9                                          // L888
	valStr := val.secret
	for dupeKey := range dupes {
		dupe := dupeKey.secret
		if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 {    // L894  skip length-mismatched
			continue
		}
		if val.detectorKey.Type() == dupeKey.detectorKey.Type() {            // L900-L902  SAME detector -> not a dupe
			continue
		}
		if valStr == dupe {                                                  // L904-L909  exact match -> duplicate
			return true
		}
		similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())
		if similarity > similarityThreshold {                                // L911-L919  Levenshtein > 0.9 -> duplicate
			return true
		}
	}
	return false
}
```

Three properties are worth highlighting (all confirmed by `TestLikelyDuplicate`, `pkg/engine/engine_test.go:L890-L966`):

- It **only compares across *different* detector types** — the same-type short-circuit at `:L900-L902` means two matches from the *same* detector are never treated as overlap duplicates (subtest *"similar within threshold same detector" → false*).
- It compares by **value similarity** (exact, or Levenshtein similarity `> 0.9`), with a length pre-filter (`:L894`) that rejects values of wildly different lengths (subtest *"non-duplicate length outside range" → false*).
- Exact matches and ≥ 0.9-similar matches across different detectors are duplicates (subtests *"exact duplicate different detector" → true*, *"similar within threshold" → true*).

### 4.3 The `errOverlap` outcome

When a cross-detector duplicate is flagged, the result is emitted **with a sentinel verification error and without verification**, and the duplicated detector key is removed so it is not re-verified downstream:

```go
// pkg/engine/engine.go:L988-L1004 (excerpt)
res.SetVerificationError(errOverlap)                  // L988
e.processResult(ctx, detectableChunk{                 // L989-L999  emit the result (unverified)
	chunk:    chunk.chunk,
	detector: detector,
	decoder:  chunk.decoder,
	wgDoneFn: wgDetect.Done,
}, res, isFalsePositive)
// Remove the detector key so the chunk is not reprocessed with verification enabled.
delete(detectorKeysWithResults, detector.Key)         // L1004
```

Detectors that are **not** flagged as duplicates are routed onward to the normal detectable channel and verify as usual (`pkg/engine/engine.go:L1011-L1020`).

The sentinel is defined at `pkg/engine/engine.go:L39-L42`. Its message is two string literals concatenated with **no space** after `disabled.` — reproduced verbatim from a live scan in Scenario C:

```
More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
```

### 4.4 Why this is *not* what usually happens with one Base64-encoded AWS key

The overlap guard fires on **multiple detectors**, not multiple **decoders**. A single AWS key (plaintext + Base64) is matched by **one** detector (AWS), so it does **not** by itself trigger overlap. To reproduce the user's "overlap error" you need **two or more distinct detectors** matching the same chunk — for example a built-in detector plus a custom regex detector keyed on the same token (Scenario C). This distinction is the single most common source of confusion, and it is why this document keeps overlap (cross-detector) and dedup (cross-decoder) in separate sections.

---

## 5. Mechanism B — Result *deduplication* (cross-decoder, Stage 4) (R4)

> **Scope of this mechanism:** *cross-**decoder***. It asks: *"is this the same secret already reported under a **different decoder type**?"* It is **not** about detectors, and it is a different code path from overlap (Section 4). **This** is the mechanism responsible for the user's "deduplicated to a single result" / "reported twice" observations.

### 5.1 The dedup cache

The notifier owns a small **LRU cache** keyed by string, valued by `DecoderType`:

```go
// pkg/engine/engine.go:L491, L493
const cacheSize = 512 // number of entries in the LRU cache
cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
```

The cache is backed by `github.com/hashicorp/golang-lru/v2` and holds up to **512** entries.

### 5.2 The notifier worker and the dedup key

Stage 4 is `notifierWorker` (`pkg/engine/engine.go:L1189-L1235`). After `--results` filtering (Section 5.4), it builds a dedup key and decides whether to drop the result:

```go
// pkg/engine/engine.go:L1210-L1221 (excerpt)
// Dedupe results by comparing the detector type, raw result, and source metadata.
// We want to avoid duplicate results with different decoder types, but we also
// want to include duplicate results with the same decoder type.
// Duplicate results with the same decoder type SHOULD have their own entry in the
// results list, this would happen if the same secret is found multiple times.
// Note: If the source type is postman, we dedupe the results regardless of decoder type.
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata) // L1216
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||                                       // L1217
	result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {                                            // L1218
	continue
}
e.dedupeCache.Add(key, result.DecoderType)                                                                      // L1221
```

The key (`pkg/engine/engine.go:L1216`) is composed of exactly four parts:

```
key = DetectorType.String()  +  Raw  +  RawV2  +  SourceMetadata
```

**The decoder type is *deliberately excluded* from the key.** Instead, the `DecoderType` is stored as the cache **value** (`e.dedupeCache.Add(key, result.DecoderType)`, `:L1221`). This is the entire design: the key identifies "the same secret in the same place," and the value records "which decoder produced the entry we already kept."

### 5.3 The skip condition (and the POSTMAN exception)

The drop decision is at `pkg/engine/engine.go:L1217-L1218`:

```go
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||
	result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
	continue   // drop this result
}
```

Reading the boolean precisely, a result is dropped when its key is already cached **and** either:

- **`val != result.DecoderType`** — the cached entry for this exact key was produced by a **different decoder type**. This is the core rule: *avoid reporting the same secret twice under different decoder types.* Conversely, a collision with the **same** decoder type is **kept** (the comment at `:L1211-L1214` explains that genuine repeats of the same secret under the same decoder should each get their own entry).
- **OR the source is Postman** (`result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN`) — Postman-sourced results are **force-deduplicated regardless of decoder type**. This is an explicit exception called out in the code comment at `:L1215` and must be stated for accuracy: outside Postman, same-decoder-type duplicates are kept; for Postman, any key collision is dropped.

### 5.4 `--results` classing happens *before* dedup

Immediately before the dedup block, the notifier filters by result class according to `--results` (`pkg/engine/engine.go:L1192-L1207`):

```go
// pkg/engine/engine.go:L1192-L1207 (structure)
if !result.Verified {
	if result.VerificationError() != nil {
		if !e.notifyUnknownResults { continue }   // results WITH a verification error are "unknown"
	} else if !e.notifyUnverifiedResults {
		continue                                  // unverified, no error
	}
} else if !e.notifyVerifiedResults {
	continue                                      // verified
}
```

The consequence relevant to Scenario C: a result carrying a verification error — **including `errOverlap`** — is classed **"unknown."** To see overlap-erroring results in the output you must include `unknown` in `--results` (the default is `verified,unverified,unknown`, so they show by default). This is why the reproduction commands use `--results=verified,unverified,unknown`.

### 5.5 The result-count metric is incremented *after* dedup

The unverified-secret metric (asserted by the tests) is incremented only after a result survives dedup:

```go
// pkg/engine/engine.go:L1223-L1226 (excerpt)
if result.Verified {
	atomic.AddUint64(&e.metrics.VerifiedSecretsFound, 1)
} else {
	atomic.AddUint64(&e.metrics.UnverifiedSecretsFound, 1)   // L1226  post-dedup count
}
```

So `UnverifiedSecretsFound` reflects the **post-dedup** count — which is why `TestEngine_DuplicateSecrets` (`pkg/engine/engine_test.go:L242-L282`) can assert a precise value of `2` for `testdata/secrets.txt`.

### 5.6 The dedup is **not atomic** — multiple notifier workers can race (the one-vs-two count nuance)

The dedup decision above is **deterministic at the level of the key**: two results that share a key collide, and (outside Postman) a collision with a *different* decoder type is dropped. But the *number of results that actually reach the output* is **not** guaranteed to be the deterministic post-dedup count, because the notifier runs as **multiple concurrent workers** and the dedup is a **non-atomic `Get`-then-`Add`**.

**There is more than one notifier worker by default.** The notifier pool is sized `notificationWorkerMultiplier × concurrency`:

```go
// pkg/engine/engine.go:L705-L706
func (e *Engine) startNotifierWorkers(ctx context.Context) {
	numWorkers := e.notificationWorkerMultiplier * e.concurrency
```

The multiplier defaults to **1** (`pkg/engine/engine.go:L348-L349`), and `--concurrency` defaults to **`runtime.NumCPU()`** (`main.go:L58`: `cli.Flag("concurrency", …).Default(strconv.Itoa(runtime.NumCPU()))`). So on a typical multi-core host there are **`NumCPU` notifier workers**, all consuming the same `ResultsChan` and all sharing the **same** `dedupeCache`.

**The dedup is a check-then-act with no lock spanning the two steps.** Re-reading the block (`pkg/engine/engine.go:L1216-L1221`):

```go
key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata) // L1216
if val, ok := e.dedupeCache.Get(key); ok && (val != result.DecoderType ||                                       // L1217  ← read
	result.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
	continue
}
e.dedupeCache.Add(key, result.DecoderType)                                                                      // L1221  ← write
```

The LRU cache (`hashicorp/golang-lru/v2`) makes each individual `Get` and `Add` internally thread-safe, but **the `Get`…`Add` pair is not atomic as a unit**. There is a small window between the `Get` at `:L1217` and the `Add` at `:L1221`. If the `PLAIN` variant and the `BASE64` variant of the same secret (same key, different decoder type) are handled by **two different notifier workers** that both execute their `Get` *before* either executes its `Add`, **both** see a cache miss, **both** pass the skip condition, and **both** are dispatched — yielding **two** results for a key that "should" have collapsed to one.

**Consequences for the user's question (R4/R6):**

- The **dedup key equality** is deterministic (a pure function of `DetectorType + Raw + RawV2 + SourceMetadata`).
- The **actual output count under concurrent notifier workers is *not* guaranteed**: same-line / different-decoder results **usually** collapse to one, but a **rare** `Get`/`Add` race can let both survive (count = 2). This is a code-grounded consequence of the non-atomic `Get`/`Add`; in practice it is sporadic and **not guaranteed to reproduce** — see the measurements in §8.3.
- Running with **`--concurrency=1`** forces a **single** notifier worker, eliminating the race; the collapse to one result becomes stable. This is the reliable way to get the deterministic **count** the dedup key implies. It does **not**, however, stabilize *which* decoder type survives the collapse: that is governed by the *detector* pool, which stays at `concurrency × 8` workers (still 8 at `--concurrency=1`: `pkg/engine/engine.go:L676`, `:L343-L345`), not the notifier pool — so the surviving label can still rarely flip (see §7.2).

> [!NOTE]
> This race is benign for TruffleHog's purpose (it can only ever *under*-deduplicate, i.e. emit a true secret twice; it never drops a distinct secret). It matters here only because it is the precise reason the user sometimes saw "two results with different decoder types" even from a same-line layout.

---

## 6. Ordering: deduplication happens *after* overlap detection (R5)

**Answer: deduplication happens *after* overlap detection.** This follows directly from the worker/channel wiring — overlap is a Stage-3 concern and dedup is a Stage-4 concern, so a result must pass through the overlap stage before it can ever reach the dedup stage.

Trace the path of a chunk through the channels:

```
scannerWorker (Stage 2, :L777)
   │  len(matchingDetectors) > 1 && !verificationOverlap  (:L796)
   ├─ yes ─►  verificationOverlapChunksChan
   │             └─►  verificationOverlapWorker (Stage 3, :L924-L1034)
   │                     • runs detectors with verify=false (:L940)
   │                     • likelyDuplicate -> errOverlap (:L988), OR
   │                     • routes non-duplicates onward (:L1011-L1020)
   │                         │
   └─ no ──────────────────► detectableChunksChan
                                 └─►  detectorWorker (:L1036, consumes :L1037)
                                         └─►  ResultsChan
                                                 └─►  notifierWorker (Stage 4, :L1189)
                                                         • consumes ResultsChan (:L1190)
                                                         • --results classing (:L1192-L1207)
                                                         • cross-decoder dedup (:L1216-L1221)
                                                         • dispatch
```

Key observations from the wiring:

- The overlap worker (`pkg/engine/engine.go:L924-L1034`) sits on `verificationOverlapChunksChan` and emits onto `detectableChunksChan` (`:L1011-L1020`) or directly produces results via `processResult` (`:L989`).
- The detector worker (`pkg/engine/engine.go:L1036`) consumes `detectableChunksChan` (`:L1037`) and produces onto `ResultsChan`.
- The notifier (`pkg/engine/engine.go:L1189`) consumes `ResultsChan` (`:L1190`) and only *then* runs dedup (`:L1216-L1221`).

Mapping onto the conceptual stages in `docs/process_flow.md`: the overlap logic is part of **Secret Detection** (`docs/process_flow.md:L88`, specifically the *De-Dupe-Detectors* box at `:L106-L108`, which decides *which detector* gets to verify), while result deduplication is part of **Result Notification** (`docs/process_flow.md:L126`). Secret Detection precedes Result Notification, so **overlap detection precedes deduplication**.

> [!NOTE]
> The *De-Dupe-Detectors* box in `docs/process_flow.md:L106-L108` is about **detectors** (the overlap mechanism), not the notifier's cross-**decoder** dedup. The naming is an easy trap; they remain two different mechanisms in two different stages.

---

## 7. Why one result vs. many — and the concurrency nuance (R6)

This is the heart of the user's confusion, and it is fully explained by the dedup key (`pkg/engine/engine.go:L1216`).

### 7.1 The line number is in the key

For filesystem sources, `SourceMetadata` carries the **file** and the **line number**. Observed JSON shape:

```json
"SourceMetadata": { "Data": { "Filesystem": { "file": "…", "line": N } } }
```

Because `SourceMetadata` is one of the four components of the dedup key (`:L1216`), **the line number is part of the key.** Therefore:

- **Same resolved line ⇒ identical key ⇒ collapse (usually) to ONE.** When the `PLAIN` and `BASE64` variants of the same key resolve to the *same* line (which happens when they share a chunk — recall the Base64 in-place replacement of §3.3), the two results share a dedup key. Whichever variant reaches the notifier first is cached; the other collides with a **different decoder type** (`val != result.DecoderType`, `:L1217`) and is dropped. **Net: one result — in the overwhelming majority of runs.** The one exception is the rare, non-atomic notifier `Get`/`Add` race of §5.6: if two notifier workers handle the two variants and both read the cache before either writes, both survive (**count = 2**).
- **Different resolved lines ⇒ different keys ⇒ keep BOTH.** When the variants resolve to *different* lines, their `SourceMetadata` differs, so their keys differ, so **neither collides** and both are kept — one `PLAIN`, one `BASE64`. **Net: multiple results with different decoder types.** (Concurrency is irrelevant here: distinct keys never collide, so there is nothing for the notifier race to affect.)

What is fully deterministic is the **dedup key**: whether the two encodings collide is entirely a function of **whether they resolve to the same source line**, which in turn is a function of **file structure** (do the plaintext and the blob share a chunk, and where does each decoded variant resolve to?). The *output count* then follows from key equality, with one caveat: **different lines reliably give two results**, and **the same line gives one result on essentially every run**, the **only** exception being the §5.6 notifier race that can occasionally bump a same-line collapse back up to two. So "sometimes one, sometimes two" is *primarily* the same-line-vs-different-line question, *plus* a rare concurrency race on the same-line side.

### 7.2 The non-deterministic parts: the label (always) and, rarely, the count

Two things vary run-to-run under default multi-worker concurrency, and it is important to keep them separate:

1. **Which decoder-type label survives a collapse — always non-deterministic.** When two variants collapse to one result, the surviving entry is simply *whichever variant reached the notifier first*, and ordering across the `concurrency × 8` detector workers (`pkg/engine/engine.go:L343-L345`) feeding a single `ResultsChan` is not guaranteed.
2. **Whether the collapse happens at all — rarely non-deterministic.** Because the notifier's dedup is a non-atomic `Get`-then-`Add` performed by `concurrency` parallel workers (§5.6, `pkg/engine/engine.go:L1217-L1221`, `:L705-L706`), a same-line collision can *occasionally* fail to dedupe, leaving **two** results instead of one.

This was directly observed (see Scenario A in the appendix): scanning the *same* single-chunk file produced a count of **1 on essentially every run** (e.g. 89 of 90 runs across two back-to-back samples), while the surviving `DecoderName` alternated between `BASE64` and `PLAIN` (e.g. a 40-run sample yielded roughly 31 `BASE64` to 8 `PLAIN`). Separately — and far more rarely — the §5.6 notifier race can let **both** labels survive, producing a count of **2** (`PLAIN@line1` + `BASE64@line1`) from that very same single-chunk layout. This is a code-grounded but **sporadic, non-deterministic** outcome: it surfaced just once in one 40-run sample and **not at all** in a separate 50-run sample nor across a 4 800-collision stress batch, so it is **not guaranteed to reproduce**. With **`--concurrency=1`** the **count** effect vanishes — a single notifier worker (§5.6) makes the count a stable **1** (observed 1 in all 120 runs of a `--concurrency=1` sample) — whereas the **label** effect does **not** fully vanish: the *detector* pool remains at `concurrency × 8` workers even at `--concurrency=1` (`pkg/engine/engine.go:L676`, `:L343-L345`), so the surviving label can still rarely flip (a low, sample-dependent rate; see Scenario A in the appendix).

> [!IMPORTANT]
> **Separate the *key* from the *count*.** The dedup *key* is deterministic (same line ⇒ identical key). What varies under default concurrency is (a) **which** decoder-type label survives a collapse — non-deterministic on every collapse — and (b) far more rarely, **whether** the collapse happens at all, because the notifier's `Get`/`Add` is not atomic across multiple workers (§5.6). Under `--concurrency=1` only variation (b) disappears — a single notifier worker removes the non-atomic `Get`/`Add` race — while variation (a) persists, because the *detector* pool that decides which variant arrives first stays at `concurrency × 8` workers regardless (`pkg/engine/engine.go:L676`, `:L343-L345`): that is **8 workers even at `--concurrency=1`**, so the order in which the two variants reach the notifier still races. The earlier intuition that "the count is deterministic" holds for the *dedup key*, **not** for the *actual emitted count* under the default concurrent pipeline.

### 7.3 Putting it together — the user's three observations

```mermaid
flowchart TD
    S[One AWS key: plaintext + Base64 in a file] --> Q1{Do the two variants<br/>resolve to the SAME line?}
    Q1 -- Yes same chunk --> ONE[Cross-decoder dedup USUALLY collapses to 1 result<br/>surviving DecoderName PLAIN or BASE64 is non-deterministic<br/>rare notifier Get/Add race can leave 2 — see section 5.6]
    Q1 -- No different lines --> TWO[Both kept: 1x PLAIN + 1x BASE64<br/>different SourceMetadata = different dedup keys]
    S --> Q2{Do 2+ DIFFERENT detectors<br/>match the same chunk?}
    Q2 -- Yes --> OV[errOverlap attached, verification disabled<br/>suppressed by --allow-verification-overlap]
    Q2 -- No --> NOOV[No overlap error]
```

| User observation | Governing mechanism | Deterministic part | Non-deterministic part |
|------------------|---------------------|--------------------|------------------------|
| "deduplicated to a single result" | cross-decoder dedup, same line (R4/R6) | the **dedup key** (same line ⇒ collision) | **count** (usually 1; rarely 2 via the §5.6 notifier race) **and** which `DecoderName` survives |
| "twice with different decoder types" | cross-decoder dedup, different lines (R4/R6) | both kept; **PLAIN + BASE64** (distinct keys, concurrency-independent) | — |
| "an overlap error" | cross-detector overlap (R3) | presence of `errOverlap`; suppressed by flag | which specific result carries it |

---

## 8. Reproduction appendix (commands + observed evidence)

All evidence below was reproduced against the pinned commit. **The binary and all scratch fixtures were created outside the repository tree** (`/tmp`) and removed afterward; the repository working tree was verified clean.

### 8.0 Build and fidelity checks

```bash
# Build out-of-tree (the ./trufflehog binary is .gitignore'd anyway). go1.24.2 matches go.mod's toolchain.
CGO_ENABLED=0 go build -o /tmp/th/bin/trufflehog .

# Fidelity: the relevant flags exist.
# NOTE 1: Kingpin prints --help to STDERR, so redirect 2>&1 before grep (otherwise the pipe
#         sees nothing and grep exits non-zero).
# NOTE 2: Kingpin renders boolean flags as "--[no-]<name>" and value flags as "--<name>=<VAL>",
#         so match the displayed substrings (e.g. `json`, `no-verification`, `--results`, `--config`)
#         rather than a literal `--json`.
/tmp/th/bin/trufflehog filesystem --help 2>&1 | grep -iE 'allow-verification-overlap|filter-unverified|no-verification|--results|--config|json'

# …and the newer iterative-decoding feature does NOT exist at this commit. A correct no-match makes
# `grep -c` print 0 but exit 1, so guard with `|| true` and assert the count is zero explicitly:
count=$(/tmp/th/bin/trufflehog --help 2>&1 | grep -ic max-decode-depth || true); test "$count" -eq 0 && echo "ok: max-decode-depth absent (count=$count)"
```

**Observed:** because Kingpin writes help to **stderr**, the `2>&1` redirect is required — without it the pipe to `grep` receives nothing and the command fails (exit 1). With the redirect, the `filesystem` sub-command's help lists the flags in Kingpin's rendered forms: `-j, --[no-]json`, `--[no-]no-verification`, `--results=RESULTS`, `--[no-]allow-verification-overlap`, `--[no-]filter-unverified`, and `--config=CONFIG` (which is exactly why the grep pattern matches the substrings `json` / `no-verification` / `--results` / `--config`, not a literal `--json`). The `max-decode-depth` count is **0** (the `|| true` prevents grep's no-match exit code from aborting the line, and the explicit `test "$count" -eq 0` asserts absence), and a repository-wide grep for `max-decode-depth|maxDecodeDepth|DecodeDepth` (excluding this `blitzy/` document itself) returns **0 matches** — confirming the **single linear decoder pass** of this commit.

The default chunking that drives Scenarios A vs. B is `ChunkSize = 10*1024` (10 KiB) with `PeekSize = 3*1024` (3 KiB overlap), `pkg/sources/chunker.go:L14`/`:L16`.

### 8.1 Cited tests (offline, no credentials)

```bash
go test ./pkg/engine -run 'TestDefaultDecoders|TestEngine_DuplicateSecrets|TestVerificationOverlapChunk|TestLikelyDuplicate' -v
```

**Observed — all PASS:**

```
--- PASS: TestDefaultDecoders (0.00s)
--- PASS: TestEngine_DuplicateSecrets (0.01s)
--- PASS: TestVerificationOverlapChunk (0.00s)
--- PASS: TestVerificationOverlapChunkFalsePositive (0.00s)
--- PASS: TestLikelyDuplicate (0.00s)
    --- PASS: TestLikelyDuplicate/exact_duplicate_different_detector
    --- PASS: TestLikelyDuplicate/non-duplicate_length_outside_range
    --- PASS: TestLikelyDuplicate/similar_within_threshold
    --- PASS: TestLikelyDuplicate/similar_outside_threshold
    --- PASS: TestLikelyDuplicate/empty_strings
    --- PASS: TestLikelyDuplicate/similar_within_threshold_same_detector
PASS
ok  	github.com/trufflesecurity/trufflehog/v3/pkg/engine	0.72s
```

These tests are authoritative behavioural evidence: `TestDefaultDecoders` (`pkg/engine/engine_test.go:L201-L206`) asserts UTF-8 is the first decoder; `TestEngine_DuplicateSecrets` (`pkg/engine/engine_test.go:L242-L282`) asserts a **post-dedup** `UnverifiedSecretsFound == 2` for `testdata/secrets.txt`; `TestVerificationOverlapChunk` (`pkg/engine/engine_test.go:L503-L556`) exercises the overlap path with custom detectors; `TestLikelyDuplicate` (`pkg/engine/engine_test.go:L890-L966`) pins the cross-detector duplicate rules.

### 8.2 The dedup-key fields (full JSON of one AWS result)

A single AWS result, showing every field that participates in the dedup key (`DetectorType` + `Raw` + `RawV2` + `SourceMetadata`) and the separate `DecoderName`:

```json
{
    "SourceMetadata": { "Data": { "Filesystem": { "file": "/tmp/scratch/A/creds.txt", "line": 1 } } },
    "SourceID": 1,
    "SourceType": 15,
    "SourceName": "trufflehog - filesystem",
    "DetectorType": 2,
    "DetectorName": "AWS",
    "DecoderName": "BASE64",
    "Verified": false,
    "VerificationFromCache": false,
    "Raw": "AKIAWARWQKZNHMZBLY4I",
    "RawV2": "AKIAWARWQKZNHMZBLY4I:s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0",
    "Redacted": "AKIAWARWQKZNHMZBLY4I",
    "ExtraData": { "account": "413504919130", "resource_type": "Access key" },
    "StructuredData": null
}
```

Note the `"line": 1` inside `SourceMetadata`: this is the lever from R6. (`SourceType: 15` is the filesystem source; `DetectorType: 2` is the AWS *detector*; `DecoderName` is the *decoder* — `"BASE64"` in this particular run.)

> The example AWS key `AKIAWARWQKZNHMZBLY4I` / secret `s6NbZeygUrUdM95K683Lb6IsILWXOJlJ8ZVd1Kw0` is the harmless test value already present in `pkg/engine/testdata/secrets.txt`. (The AWS-documentation key `AKIAIOSFODNN7EXAMPLE` is filtered out by the detector and yields no results, so it cannot be used for reproduction.)

### 8.3 Scenario A — same chunk ⇒ *usually* one result (user: *"deduplicated to a single result"*)

**Layout:** plaintext credentials and the Base64 blob of the *same* credentials placed close together so they share **one chunk**:

```
line 1:  aws_access_key_id=AKIAWARWQKZNHMZBLY4I
line 2:  aws_secret_access_key=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
line 3:  # encoded copy of the same credentials below
line 4:
line 5:  blob=YXdzX2FjY2Vzc19rZXlfaWQ9QUtJQVdBUldRS1pOSE1aQkxZNEkg…   (136-char base64, decodes to the same creds)
```

```bash
/tmp/th/bin/trufflehog filesystem /tmp/scratch/A --no-verification --results=verified,unverified,unknown -j
```

**Observed — default concurrency, 10 consecutive runs:**

```
run  1: count=1 decoders=['PLAIN']
run  2: count=1 decoders=['BASE64']
run  3: count=1 decoders=['BASE64']
run  4: count=1 decoders=['PLAIN']
run  5: count=1 decoders=['BASE64']
run  6: count=1 decoders=['BASE64']
run  7: count=1 decoders=['BASE64']
run  8: count=1 decoders=['BASE64']
run  9: count=1 decoders=['BASE64']
run 10: count=1 decoders=['PLAIN']
```

The count is **1 on every run in this sample**, but the **surviving `DecoderName` alternates** (`PLAIN` vs `BASE64`) — that is the §7.2 label non-determinism (whichever variant reached the notifier first wins). (Count = 1 is the practical norm; the lone, rare exception is the count = 2 race discussed just below.)

**Pinning to `--concurrency=1` stabilizes the *count* (a single notifier worker) — but *not* the surviving *label*:**

```bash
/tmp/th/bin/trufflehog filesystem /tmp/scratch/A --no-verification --results=verified,unverified,unknown -j --concurrency=1
```

```
# Repeated runs at --concurrency=1 (this investigation used a 120-run sample):
count : 1 on every run                        # STABLE — the §5.6 notifier Get/Add race is gone (1 notifier worker)
label : almost always identical; rare flips   # STILL flips occasionally — detector pool is 8 workers even at --concurrency=1
#   120-run sample here: count=1 on all 120, label PLAIN on all 120 (0 flips); other sampling has shown ~1 flip per 100 runs
```

`--concurrency=1` collapses only the **notifier** pool to a single worker (`notificationWorkerMultiplier × concurrency = 1 × 1`, `pkg/engine/engine.go:L705-L706`, `:L348-L349`), which removes the §5.6 `Get`/`Add` race and makes the **count** a stable **1**. It does **not** collapse the **detector** pool, which stays at `concurrency × 8 = 8` workers (`pkg/engine/engine.go:L676`, `:L343-L345`); those 8 workers still race to feed `ResultsChan`, so *which* variant reaches the single notifier first — and therefore the surviving `DecoderName` — can still flip, just far less often than under default concurrency. (The flip is rare and its rate is sample-dependent: a 120-run `--concurrency=1` sample here showed **no** flips, while other sampling has shown on the order of ~1 flip per 100 runs — a 10-run sample is far too small to surface it.) This matches §7.2 and the R6 summary (§9): the surviving label is **always** governed by the detector pool and is never stabilized by `--concurrency=1`.

**The count = 2 race — code-grounded, but rare and not guaranteed to reproduce.** The §5.6 notifier `Get`/`Add` is non-atomic across the `concurrency` parallel notifier workers, so two workers *can* both observe a cache miss for the same key and both dispatch, leaving **two** results where the dedup key implies one. This is a real, code-derived possibility — but it is **sporadic and non-deterministic**, and it may not appear at all in a given run or even in a large batch, so **no exact "extra-result" count should be relied upon**.

What is reliably observable is the opposite: the same-line collision **almost always collapses to one**. Measurements at this commit (default concurrency, single-file loop) put the count at **1 in the overwhelming majority of runs** — e.g. **89 of 90** runs across two back-to-back samples — with the surviving `DecoderName` alternating between `PLAIN` and `BASE64` (the §7.2 label non-determinism). The count = 2 race surfaced **only once**, in one 40-run sample, and **not at all** in a separate 50-run sample.

Exercising the collision **at scale** — a directory of **60 independent copies** of the single-chunk fixture (each collides `PLAIN`+`BASE64` at its *own* line 1) scanned across many parallel processes — is the natural way to *attempt* to provoke the race under scheduling pressure:

```bash
# 60 identical single-chunk fixtures; each is EXPECTED to collapse to exactly 1 result.
# Run many scans in parallel to oversubscribe CPUs and widen the notifier Get->Add window.
for r in $(seq 1 5); do
  for p in $(seq 1 16); do
    /tmp/th/bin/trufflehog filesystem /tmp/scratch/Amany --no-verification \
      --results=verified,unverified,unknown -j --no-update > /tmp/out_${r}_${p}.json 2>/dev/null &
  done; wait
done
# expected if every collision collapses = (number of scans) x 60 AWS results
```

In this investigation an **80-scan x 60-file** batch (**4 800** independent same-line collisions) returned **exactly 4 800** AWS results — **zero** files emitted a second result, i.e. the race did **not** surface even under heavy load. (A separate, larger stress run during QA — on the order of 8 640 collisions — likewise produced zero double-emits.) The takeaway: the race is real per the code, but a clean collapse to one is the practical expectation, and the rare count = 2 is **not guaranteed to reproduce**.

When the race *does* fire, the two surviving records share an identical dedup key (`DetectorType` + `Raw` + `RawV2` + `SourceMetadata`) and differ only in `DecoderName` — schematically:

```json
// illustrative shape of a (rare) double-emit — schematic, NOT a guaranteed or captured observation
{ "DetectorName":"AWS", "DecoderName":"PLAIN",  "SourceMetadata":{"Data":{"Filesystem":{"file":".../creds.txt","line":1}}}, "Raw":"AKIAWARWQKZNHMZBLY4I" }
{ "DetectorName":"AWS", "DecoderName":"BASE64", "SourceMetadata":{"Data":{"Filesystem":{"file":".../creds.txt","line":1}}}, "Raw":"AKIAWARWQKZNHMZBLY4I" }
```

Both records "should" have collapsed to one; two notifier workers raced the non-atomic `Get`/`Add` (§5.6) and both survived — which is exactly the "reported twice with different decoder types" outcome the user *occasionally* saw from a same-line layout.

**Interpretation:** both the `PLAIN` and `BASE64` variants resolve to line 1 (Base64 in-place replacement, §3.3), so they share a dedup key and the cross-decoder dedup (`:L1217`) drops the colliding one — hence count = 1 with an alternating surviving label in essentially every run. The lone exception is the rare, non-atomic notifier `Get`-then-`Add` (§5.6, `pkg/engine/engine.go:L1217-L1221`, `:L705-L706`, default `runtime.NumCPU()` via `main.go:L58`): it *can* let both variants survive (count = 2), but as the measurements above show this is sporadic and **not guaranteed to reproduce**. Running with **`--concurrency=1`** forces a single notifier worker and makes the count a stable **1** (observed 1 in all 120 runs of a `--concurrency=1` sample). It does **not** stabilize the surviving label: the detector pool stays at `concurrency × 8` = 8 workers even at `--concurrency=1` (`pkg/engine/engine.go:L676`, `:L343-L345`), so the label can still rarely flip (§7.2).

### 8.4 Scenario B — two results, different decoder types (user: *"reported twice with different decoder types"*)

**Layout:** the same plaintext on lines 1–2, then enough filler (> 13 KiB, i.e. past one full `ChunkSize + PeekSize` window) to push the Base64 blob into a **separate chunk**, so the decoded variant resolves to a **different line** than the plaintext:

```bash
/tmp/th/bin/trufflehog filesystem /tmp/scratch/B2 --no-verification --results=verified,unverified,unknown -j
```

**Observed — 6 consecutive runs (stable):**

```
run: count=2 ['BASE64@L107', 'PLAIN@L1']
run: count=2 ['BASE64@L107', 'PLAIN@L1']
…(identical for all 6 runs)…
```

**Interpretation:** `PLAIN` resolves to line 1, the Base64 blob (on file line 243) decodes to a variant that resolves to line 107. **Different lines ⇒ different `SourceMetadata` ⇒ different dedup keys ⇒ both kept**, one `PLAIN`, one `BASE64`. Stable across runs because the line numbers (hence keys) are fixed by the layout.

> **A more dramatic variant (honest reporting):** with ~400 filler lines (~32 KiB) and the blob at file line 403, the scan stably returns **three** results: `[PLAIN@L1, BASE64@L22, BASE64@L149]`. The two `BASE64` results arise because the blob falls in the **3 KiB peek/overlap** region shared by two adjacent chunks (`pkg/sources/chunker.go:L16`), so it is scanned twice and its decoded content resolves to two different lines. This is the same principle (different resolved line ⇒ different key ⇒ kept) and underlines that the *exact* count is a deterministic function of the **precise file layout and chunk boundaries** — which is exactly why the user perceived "inconsistency."

### 8.5 Scenario C — the overlap error (user: *"reported an overlap error"*)

**Layout:** a Postman API key plus a custom config that adds two regex detectors keyed on the same token, so that — together with the **built-in Postman detector** — **three distinct detectors** match the same chunk:

```yaml
# /tmp/scratch/C/overlap.yaml
detectors:
  - name: detector1
    keywords: [PMAK]
    regex: { api_key: '\b(PMAK-[a-zA-Z-0-9]{59})\b' }
  - name: detector2
    keywords: [POSTMAN]
    regex: { api_key: '\b(PMAK-[a-zA-Z-0-9]{59})\b' }
```

```bash
# data file contains: POSTMAN_API_KEY="PMAK-…59chars…"
# Default (overlap guard ON):
/tmp/th/bin/trufflehog filesystem /tmp/scratch/C --config /tmp/scratch/C/overlap.yaml \
    --no-verification --results=verified,unverified,unknown -j
# Guard OFF:
/tmp/th/bin/trufflehog filesystem /tmp/scratch/C --config /tmp/scratch/C/overlap.yaml \
    --allow-verification-overlap --no-verification --results=verified,unverified,unknown -j
```

**Observed:**

| Run | Results | With `errOverlap` |
|-----|---------|-------------------|
| **Default** (guard ON) | 3 (`Postman`, `CustomRegex`, `CustomRegex`) | **one or more** carry the overlap error — the *exact* number varies run to run (observed **1 or 2** across repeated runs; e.g. in one 30-run sample, 1 erroring result in 23 runs and 2 in 7). The robust invariant is that overlap errors are **present by default**. |
| **`--allow-verification-overlap`** | 3 (same) | **0** — overlap errors are fully suppressed by the flag (0 in every run). |

The verbatim verification error on the erroring result:

```
More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
```

**Interpretation:** more than one **distinct detector** matched the same chunk, so the Stage-3 overlap guard (`:L796`) routed it through `verificationOverlapWorker`, `likelyDuplicate` flagged the cross-detector duplicate, and the result was emitted with `errOverlap` and without verification (`:L988`). The flag `--allow-verification-overlap` bypasses the guard entirely (`:L796`), so the error disappears. **Both *how many* results carry the error and *which* ones do can vary run to run** — because the overlapping detectors run on concurrent workers, repeated default-guard runs here yielded **1 or 2** erroring results (never zero). The robust, reproducible invariants are therefore only that overlap errors are **present by default** and are **fully suppressed by `--allow-verification-overlap`** (zero in every run); the precise erroring-result count is not a stable quantity.

### 8.6 The in-repo `secrets.txt` fixture (read-only)

```bash
# read-only scan of the tracked fixture; the repo tree is NOT modified
/tmp/th/bin/trufflehog filesystem "$PWD/pkg/engine/testdata/secrets.txt" \
    --no-verification --results=verified,unverified,unknown -j
```

**Observed — 2 results:**

```
Detector=AWS         Decoder=PLAIN line=1  Raw=AKIAWARWQKZNHMZBLY4I
Detector=SentryToken Decoder=PLAIN line=3  Raw=27ac84f4bcdb4fca9701f4d6…
```

This matches the `TestEngine_DuplicateSecrets` assertion of `2`. Note that the **four identical Sentry tokens** on lines 3–6 collapse to a **single** `SentryToken@line3` result. That collapse is a **per-detector in-chunk** dedup of identical matches (first occurrence wins, line 3), which is a *different* thing from the notifier's cross-decoder dedup of §5 — included here only so the count of `2` is not misread as evidence of the cross-decoder rule.

### 8.7 Cleanup / cleanliness proof

```bash
rm -rf /tmp/scratch /tmp/th
git status --porcelain   # MUST be empty (no source modified, no stray fixtures)
```

---

## 9. "Code as truth" rationale (per-question)

A concise statement of *why* each answer is what it is, with the decisive citation(s).

- **R1 — How are multiple encodings handled?** A fixed four-decoder chain `[UTF8, Base64, UTF16, EscapedUnicode]` is applied in a **single linear pass**; every non-nil variant is independently keyword-matched. *Why we conclude this:* `DefaultDecoders()` (`pkg/decoders/decoders.go:L8-L16`) and the single `for _, decoder := range e.decoders` loop (`pkg/engine/engine.go:L784`) with per-variant matching at `:L795`. There is no feedback loop re-decoding outputs at this commit (§11).

- **R2 — Which `DecoderType` values appear?** `PLAIN`, `BASE64`, `UTF16`, `ESCAPED_UNICODE` (and `UNKNOWN=0`). *Why:* the enum at `pkg/pb/detectorspb/detectors.pb.go:L26-L30` plus each decoder's `Type()` (`pkg/decoders/utf8.go:L12-L14`, `pkg/decoders/base64.go:L30-L32`, `pkg/decoders/utf16.go:L14-L16`, `pkg/decoders/escaped_unicode.go:L28-L30`). In JSON the value surfaces as `DecoderName` (`pkg/output/json.go:L65`).

- **R3 — When does overlap detection occur?** Only when **`len(matchingDetectors) > 1`** for a chunk **and** `--allow-verification-overlap` is off. *Why:* the trigger at `pkg/engine/engine.go:L796`, the worker at `:L924-L1034`, the duplicate gate `likelyDuplicate` at `:L887-L921`, and the `errOverlap` sentinel at `:L39-L42`.

- **R4 — How does dedup reduce the count?** The notifier's LRU cache (size 512) keys on `DetectorType + Raw + RawV2 + SourceMetadata` — **excluding** `DecoderType` — and drops a later result whose key collides with a **different** cached decoder type. *Why:* the key at `pkg/engine/engine.go:L1216` and the skip condition at `:L1217-L1218`, with the Postman force-dedup exception in the same condition. **Concurrency caveat (feeds R6):** the dedup is a non-atomic `Get`-then-`Add` (`:L1217-L1221`) run by `concurrency` notifier workers (`:L705-L706`, default `runtime.NumCPU()` via `main.go:L58`, multiplier default 1 at `:L348-L349`). So *key equality* is deterministic, but the *emitted count* is not strictly guaranteed — a rare two-worker race can let a same-key collision survive twice (§5.6), a sporadic, non-deterministic outcome that is **not guaranteed to reproduce** (see §8.3); `--concurrency=1` removes it.

- **R5 — Dedup before or after overlap?** **After.** *Why:* overlap runs in the Stage-3 `verificationOverlapWorker` (`pkg/engine/engine.go:L924-L1034`) and dedup runs in the Stage-4 `notifierWorker` (`:L1189-L1235`); the channel wiring forces results through Stage 3 before Stage 4 (`:L1011-L1020` → `detectorWorker` `:L1036` → `ResultsChan` → notifier `:L1190`).

- **R6 — Why one vs. many (and why does the label flicker)?** The dedup key includes the **source line number** (inside `SourceMetadata`, `:L1216`). Same line ⇒ same key ⇒ collapse (usually) to one; different lines ⇒ different keys ⇒ keep both. Under the default concurrent pipeline two run-to-run variations remain: **(a)** when a collapse occurs, the surviving `DecoderName` is whichever variant reached the notifier first across the `concurrency × 8` detector workers (`:L343-L345`) — *always* non-deterministic; and **(b)** far more rarely, the same-line collapse can fail entirely because the notifier's dedup `Get`/`Add` is non-atomic across `concurrency` notifier workers (`:L1217-L1221`, `:L705-L706`, `main.go:L58`), leaving two results. So the **dedup key is deterministic, but the emitted count is only *usually* 1** (rarely 2) and the **surviving label is non-deterministic**: the label non-determinism is confirmed empirically (§8.3), while the rare count = 2 is a code-grounded outcome that surfaces only sporadically and is **not guaranteed to reproduce** (§8.3). `--concurrency=1` eliminates the *count* variation **(b)** (a single notifier worker), but **not** the *label* non-determinism **(a)**: the detector pool stays at `concurrency × 8` workers regardless (`:L676`, `:L343-L345`), so the surviving label can still rarely flip even at `--concurrency=1`.

---

## 10. Relevant CLI flags

All defined in `main.go`:

| Flag | Effect | Citation |
|------|--------|----------|
| `--concurrency` | Number of concurrent workers; **defaults to `runtime.NumCPU()`**. It sizes every worker pool, including the notifier pool (`notificationWorkerMultiplier × concurrency`). Setting **`--concurrency=1`** forces a single notifier worker, which removes the non-atomic dedup race of §5.6 (stable **count**). It does **not** remove the label non-determinism of §7.2: the *detector* pool stays at `concurrency × 8` = 8 workers (`pkg/engine/engine.go:L676`, `:L343-L345`), so the surviving label can still rarely flip. | `main.go:L58` |
| `--no-verification` | Don't verify results (used throughout this investigation so scans are side-effect-free). | `main.go:L59` |
| `--results` | Which result classes to output: `verified`, `unknown`, `unverified`, `filtered_unverified`. **Defaults to `verified,unverified,unknown`.** Results carrying a verification error (e.g. `errOverlap`) are classed **`unknown`** (§5.4). | `main.go:L61` |
| `--allow-verification-overlap` | **Disables the overlap guard** (`e.verificationOverlap`), so chunks matched by multiple detectors verify normally and carry no `errOverlap`. | `main.go:L65` |
| `--filter-unverified` | "Only output first unverified result per chunk per detector if there are more than one results." A *per-detector* in-chunk filter — again distinct from the cross-decoder notifier dedup. | `main.go:L66` |
| `--config` | Path to a configuration file (used to add the custom detectors in Scenario C). It is `--config`; there is **no `-c` short form**. | `main.go:L70` |

---

## 11. Version caveat

This document describes commit `e42153d44a5e` only, which performs a **single linear decoder pass** (§3.1, §8.0). Newer upstream TruffleHog adds an **iterative-decoding** feature (`--max-decode-depth`, where each decoder's output is fed back through all decoders); that feature is **not present** at this commit — a repository-wide grep for `max-decode-depth`/`maxDecodeDepth`/`DecodeDepth` returns zero matches and the built binary's help exposes no such flag. All conclusions here are scoped accordingly.

---

### Appendix: files consulted (reference only — never modified)

`pkg/decoders/decoders.go`, `pkg/decoders/utf8.go`, `pkg/decoders/base64.go`, `pkg/decoders/utf16.go`, `pkg/decoders/escaped_unicode.go`, `pkg/pb/detectorspb/detectors.pb.go`, `pkg/engine/engine.go`, `pkg/engine/ahocorasick/ahocorasickcore.go`, `pkg/engine/engine_test.go`, `pkg/engine/testdata/secrets.txt`, `pkg/engine/testdata/verificationoverlap_secrets.txt`, `pkg/engine/testdata/verificationoverlap_detectors.yaml`, `pkg/output/json.go`, `pkg/sources/chunker.go`, `main.go`, `docs/process_flow.md`.
