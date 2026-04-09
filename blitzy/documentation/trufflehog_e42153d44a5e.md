# TruffleHog v3 Secret Detection Behavior Investigation

This document investigates and explains TruffleHog v3's secret detection behavior — specifically why AWS credentials are detected inconsistently across different file contexts, how encoding (particularly Base64) affects scanner behavior, why test fixture credentials evade detection, what the "verification disabled for safety" CI log warnings mean, and what determines the exact boundary between detection and evasion.

Every technical claim in this document cites the specific source file path from the TruffleHog v3 codebase. All answers are based on code analysis as the source of truth — no assumptions are made.

---

## Table of Contents

- [TruffleHog Detection Pipeline Architecture](#trufflehog-detection-pipeline-architecture)
- [Q1: Why Are AWS Credentials Detected in Some Files but Missed in Others?](#q1-why-are-aws-credentials-detected-in-some-files-but-missed-in-others)
- [Q2: How Does Encoding Sensitive Data Affect Detection?](#q2-how-does-encoding-sensitive-data-affect-detection)
- [Q3: Why Don't Test Fixture Credentials Get Flagged?](#q3-why-dont-test-fixture-credentials-get-flagged)
- [Q4: What Does "Verification Disabled for Safety" Mean?](#q4-what-does-verification-disabled-for-safety-mean)
- [Q5: Detection Boundaries — What Gets Caught vs. What Slips Through?](#q5-detection-boundaries--what-gets-caught-vs-what-slips-through)
- [Summary: Key Takeaways](#summary-key-takeaways)

---

## TruffleHog Detection Pipeline Architecture

Before answering any specific question, it is essential to understand the complete pipeline that every chunk of data passes through. A credential must survive **every stage** of this pipeline to be reported as a finding. Failure at any single stage means the credential is silently dropped.

### Pipeline Flowchart

```mermaid
flowchart TD
    A["Source\n(Git, GitHub, Filesystem, S3, etc.)"] --> B["Source Decomposition\ninto Chunks"]
    B --> C{"Decoder Chain\n(4 decoders applied independently)"}
    
    C -->|"UTF8 (always succeeds)"| D["Decoded Chunk (plain text)"]
    C -->|"Base64 (if >20 char substrings)"| D
    C -->|"UTF16 (if UTF-16 BOM found)"| D
    C -->|"EscapedUnicode (if \\uXXXX found)"| D
    C -.->|"Decoder returns nil → chunk skipped\nfor that decoder pass"| DROP1["❌ Dropped:\nNo decodable content"]
    
    D --> E{"Aho-Corasick\nKeyword Prefilter"}
    E -->|"Keyword found\n(e.g., AKIA, ABIA, ACCA)"| F["512-byte Span\nExtracted Around Match"]
    E -.->|"No keyword match"| DROP2["❌ Dropped:\nDetector never invoked"]
    
    F --> G{"Verification Overlap Check\n(multiple detectors match?)"}
    G -->|"Single detector OR\n--allow-verification-overlap"| H["Normal Detection Path"]
    G -->|"Multiple detectors AND\noverlap not allowed"| VOW["Verification Overlap Worker\n(verify=false)"]
    
    H --> I{"Regex Extraction\n(detector-specific patterns)"}
    I -->|"ID and Secret\npatterns match"| J["Candidate Credentials"]
    I -.->|"No regex match"| DROP3["❌ Dropped:\nPattern mismatch"]
    
    J --> K{"Shannon Entropy\nFiltering"}
    K -->|"ID ≥ 3.0 AND\nSecret ≥ 4.25"| L["Entropy-Validated\nCredentials"]
    K -.->|"Below threshold"| DROP4["❌ Dropped:\nLow entropy"]
    
    L --> M{"Hex False Positive\nPattern Check"}
    M -->|"Secret is NOT pure\nlowercase hex"| N["Non-Hex Credentials"]
    M -.->|"Unverified AND matches\n[a-f0-9]{40}"| DROP5["❌ Dropped:\nLooks like git hash"]
    
    N --> O{"Verification\n(optional, calls AWS STS)"}
    O --> P{"Known False Positive\nFiltering (engine-level)"}
    P -->|"No FP word match"| Q["Result Cleaning\n& Deduplication"]
    P -.->|"Contains FP word\n(e.g., 'example', 'token')"| DROP6["❌ Dropped:\nKnown false positive"]
    
    Q --> R["✅ Reported Finding"]
    
    VOW --> |"Duplicate secret across\ndetectors → errOverlap"| S["Result with\nverification disabled"]
    VOW --> |"Unique to one detector\n→ normal path"| H
    S --> P

    style DROP1 fill:#ffcccc,stroke:#cc0000
    style DROP2 fill:#ffcccc,stroke:#cc0000
    style DROP3 fill:#ffcccc,stroke:#cc0000
    style DROP4 fill:#ffcccc,stroke:#cc0000
    style DROP5 fill:#ffcccc,stroke:#cc0000
    style DROP6 fill:#ffcccc,stroke:#cc0000
    style R fill:#ccffcc,stroke:#00cc00
```

### Pipeline Stage Sources

| Stage | Description | Source |
|-------|-------------|--------|
| Source Decomposition | Sources produce chunks of data | `docs/process_flow.md` |
| Decoder Chain | 4 decoders in order: UTF8 → Base64 → UTF16 → EscapedUnicode | `pkg/decoders/decoders.go`, lines 8–16 |
| Aho-Corasick Prefilter | Keyword matching on lowercased chunk data | `pkg/engine/ahocorasick/ahocorasickcore.go`, line 242 |
| Span Extraction | 512-byte radius around keyword match | `pkg/engine/ahocorasick/ahocorasickcore.go`, line 155 |
| Verification Overlap Check | Routes multi-detector chunks to safety worker | `pkg/engine/engine.go`, line 796 |
| Regex Extraction | Detector-specific ID and secret patterns | `pkg/detectors/aws/access_keys/accesskey.go`, line 65; `pkg/detectors/aws/common.go`, line 10 |
| Shannon Entropy Filtering | ID ≥ 3.0, Secret ≥ 4.25 | `pkg/detectors/aws/common.go`, lines 6–7 |
| Hex FP Pattern | Rejects unverified secrets matching `[a-f0-9]{40}` | `pkg/detectors/aws/utils.go`, line 47 |
| Known FP Filtering | Aho-Corasick trie from 4 word lists + DefaultFalsePositives map | `pkg/detectors/falsepositives.go`, lines 17–19, 32–67, 85–109 |
| Result Cleaning | Deduplication preferring verified results | `pkg/detectors/aws/utils.go`, lines 89–114 |

---

## Q1: Why Are AWS Credentials Detected in Some Files but Missed in Others?

### Thinking / Rationale

To understand why the same AWS credential pattern might be detected in one file but missed in another, the investigation traced the complete detection pipeline from chunk ingestion through every filtering stage. The key insight is that TruffleHog's pipeline has **six distinct filtering layers**, and a credential must survive ALL of them to produce a finding. Each layer is deterministic — the same input always produces the same output — so the "inconsistency" across files is actually consistent behavior: different file contexts cause credentials to fail at different pipeline stages.

### The Six-Layer Detection Gauntlet

TruffleHog's AWS access key detection pipeline applies six filtering stages sequentially. A credential must pass **every single layer** to be reported. Failure at any one layer means silent non-detection.

#### Layer 1: Aho-Corasick Keyword Prefiltering

The chunk must contain at least one keyword from the AWS access key detector. The keywords are:

```go
func (s scanner) Keywords() []string {
    return []string{
        "AKIA",
        "ABIA",
        "ACCA",
    }
}
```

*Source: `pkg/detectors/aws/access_keys/accesskey.go`, lines 70–76*

Keywords are lowercased before matching against lowercased chunk data:

```go
matches := ac.prefilter.Match(bytes.ToLower(chunkData))
```

*Source: `pkg/engine/ahocorasick/ahocorasickcore.go`, line 242*

**Key insight**: If none of these keywords appear anywhere in the chunk, the AWS detector is never even invoked. This is an optimization — TruffleHog has 800+ detectors, and the Aho-Corasick prefilter ensures only relevant detectors are run.

When a keyword is found, a **512-byte radius span** is extracted around the match position:

```go
const defaultOffsetRadius int64 = 512
```

*Source: `pkg/engine/ahocorasick/ahocorasickcore.go`, line 155*

#### Layer 2: Regex Pattern Matching

The detector applies two regex patterns to extract candidate credential components:

**Access Key ID Pattern:**
```
\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b
```
*Source: `pkg/detectors/aws/access_keys/accesskey.go`, line 65*

Requirements:
- Exactly 20 characters total: 4-character prefix (`AKIA`, `ABIA`, or `ACCA`) + 16 uppercase alphanumeric characters
- Word boundaries (`\b`) on both sides
- **Only uppercase letters and digits** are allowed after the prefix — mixed-case IDs like `AKIAs9L8MS5iPHTZPPUQ` will **not** match because lowercase letters fail the `[A-Z0-9]{16}` character class

**Secret Key Pattern:**
```
(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)
```
*Source: `pkg/detectors/aws/common.go`, line 10*

Requirements:
- Exactly 40 characters from the Base64 alphabet (`A-Za-z0-9+/`)
- A non-Base64 boundary character (or start/end of string) must exist on both sides
- Characters like `=`, spaces, or special symbols within the 40-character run invalidate the match

#### Layer 3: Shannon Entropy Filtering

Candidate strings must exceed minimum entropy thresholds to be considered real credentials rather than placeholder text:

```go
const (
    RequiredIdEntropy     = 3.0
    RequiredSecretEntropy = 4.25
)
```
*Source: `pkg/detectors/aws/common.go`, lines 6–7*

The entropy is calculated using the Shannon entropy formula implemented in `StringShannonEntropy`:

```go
func StringShannonEntropy(input string) float64 {
    chars := make(map[rune]float64)
    inverseTotal := 1 / float64(len(input))
    for _, char := range input {
        chars[char]++
    }
    entropy := 0.0
    for _, count := range chars {
        probability := count * inverseTotal
        entropy += probability * math.Log2(probability)
    }
    return -entropy
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 136–151*

The ID entropy check occurs at:
```go
if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy {
    continue
}
```
*Source: `pkg/detectors/aws/access_keys/accesskey.go`, lines 122–123*

The secret entropy check occurs at:
```go
if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
    continue
}
```
*Source: `pkg/detectors/aws/access_keys/accesskey.go`, lines 132–133*

#### Layer 4: Hex False Positive Pattern

If a result is **unverified** and its secret matches the pattern `[a-f0-9]{40}` (looks like a git SHA-1 hash), it is dropped:

```go
var FalsePositiveSecretPat = regexp.MustCompile(`[a-f0-9]{40}`)
```
*Source: `pkg/detectors/aws/utils.go`, line 47*

```go
if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) {
    // Unverified results that look like hashes are probably not secrets
    continue
}
```
*Source: `pkg/detectors/aws/access_keys/accesskey.go`, lines 202–205*

This specifically targets the 40-character overlap between the AWS secret key pattern and git commit hashes.

#### Layer 5: Known False Positive Filtering (Engine-Level)

After detection, the engine's `filterResults()` function applies additional false positive filtering:

```go
if !e.retainFalsePositives {
    results = detectors.FilterKnownFalsePositives(ctx, detector.Detector, results)
}
```
*Source: `pkg/engine/engine.go`, lines 1141–1143*

This checks against two data sources:

1. **`DefaultFalsePositives` map** — 7 common placeholder patterns:
   ```go
   DefaultFalsePositives = map[FalsePositive]struct{}{
       "example": {}, "xxxxxx": {}, "aaaaaa": {}, "abcde": {}, "00000": {}, "sample": {}, "*****": {},
   }
   ```
   *Source: `pkg/detectors/falsepositives.go`, lines 17–19*

2. **Aho-Corasick trie** — built from 4 embedded text files:
   - `fp_badlist.txt` — programming/crypto terms: "value", "token", "config", "export", "auth", "hash", "sha256", etc.
   - `fp_words.txt` — common English words: "number", "people", "through", "weather", etc.
   - `fp_programmingbooks.txt` — programming book title words
   - `fp_uuids.txt` — known false positive UUID strings
   
   *Source: `pkg/detectors/falsepositives.go`, lines 32–61*

The check is case-insensitive and uses **substring matching** — if the lowercased raw value contains any of these terms, it is flagged:

```go
for fp := range falsePositives {
    fps := string(fp)
    if strings.Contains(lower, fps) {
        return true, "contains term: " + fps
    }
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 95–99*

```go
if m := filter.MatchFirstString(lower); m != nil {
    return true, "matches wordlist: " + m.MatchString()
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 103–105*

Additionally, if the `--filter-entropy` CLI flag is set, a separate engine-level entropy filter is applied:

```go
if e.filterEntropy != 0 {
    results = detectors.FilterResultsWithEntropy(ctx, results, e.filterEntropy, e.retainFalsePositives)
}
```
*Source: `pkg/engine/engine.go`, lines 1145–1147*

#### Layer 6: Result Deduplication / Cleaning

`CleanResults()` keeps at most one result per redacted ID, preferring verified results:

```go
func CleanResults(results []detectors.Result) []detectors.Result {
    // ...
    idResults := map[string]detectors.Result{}
    for _, result := range results {
        if result.Verified {
            idResults[result.Redacted] = result
            continue
        }
        if _, exist := idResults[result.Redacted]; !exist {
            idResults[result.Redacted] = result
        }
    }
    // ...
}
```
*Source: `pkg/detectors/aws/utils.go`, lines 89–114*

### Why Results Are Deterministic

The detection pipeline is **entirely deterministic** — no randomness is involved anywhere:

- **Regex matching** is deterministic (same input → same match result)
- **Shannon entropy calculation** is a pure mathematical function of character frequencies
- **False positive word lists** are static, embedded at compile time via Go's `//go:embed` directive
- **Aho-Corasick keyword matching** is deterministic for the same input data

The same file content scanned under the same conditions will **always** produce the same detection result. When a user observes that "file A always triggers detection but file B never does," this is because the two files cause the credential to fail at different layers of the gauntlet — it is consistent, not random.

The only variable factor is chunk boundaries: how the source is decomposed into chunks can affect which data the detector sees. However, for `trufflehog filesystem` scans, each file is typically a single chunk, so results are fully reproducible.

### Concrete Examples

#### Example 1: Detected — Credential Passes All Layers

Consider a file `config.env` containing:
```
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Layer 1 — Keyword Prefilter:** The chunk contains `AKIA` → keyword match found ✓

**Layer 2 — Regex Matching:**
- ID: `AKIAIOSFODNN7EXAMPLE` → matches `\b(AKIA[A-Z0-9]{16})\b` (4 prefix + 16 uppercase alphanumeric = 20 chars) ✓
- Secret: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` → 40 characters from `[A-Za-z0-9+/]` with `=` boundary on left side ✓

**Layer 3 — Entropy Filtering:**

*ID entropy calculation for `AKIAIOSFODNN7EXAMPLE`:*

| Character | Count | Probability (p) | p × log₂(p) |
|-----------|-------|-----------------|--------------|
| 7 | 1 | 1/20 = 0.0500 | −0.216096 |
| A | 3 | 3/20 = 0.1500 | −0.410545 |
| D | 1 | 1/20 = 0.0500 | −0.216096 |
| E | 2 | 2/20 = 0.1000 | −0.332193 |
| F | 1 | 1/20 = 0.0500 | −0.216096 |
| I | 2 | 2/20 = 0.1000 | −0.332193 |
| K | 1 | 1/20 = 0.0500 | −0.216096 |
| L | 1 | 1/20 = 0.0500 | −0.216096 |
| M | 1 | 1/20 = 0.0500 | −0.216096 |
| N | 2 | 2/20 = 0.1000 | −0.332193 |
| O | 2 | 2/20 = 0.1000 | −0.332193 |
| P | 1 | 1/20 = 0.0500 | −0.216096 |
| S | 1 | 1/20 = 0.0500 | −0.216096 |
| X | 1 | 1/20 = 0.0500 | −0.216096 |

**H = −(sum) = 3.684 bits** → 3.684 ≥ 3.0 ✓

*Secret entropy for `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`:*
- 29 unique characters across 40 characters → **H = 4.663 bits** → 4.663 ≥ 4.25 ✓

**Layer 4 — Hex FP Check:**
The secret `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` contains uppercase letters and `/` — it does **not** match `[a-f0-9]{40}` ✓

**Layer 5 — Known FP Check:**
The ID `AKIAIOSFODNN7EXAMPLE` lowercased is `akiaiosfodnn7example`. This **contains the substring "example"**, which is in `DefaultFalsePositives`. **However**, the false positive check is applied to `result.Raw`, which is set to the ID bytes — `[]byte(idMatch)` (*Source: `pkg/detectors/aws/access_keys/accesskey.go`, line 138*). Since the ID contains "example", this result **would be filtered** by `FilterKnownFalsePositives`.

> **Important correction**: The well-known AWS example key `AKIAIOSFODNN7EXAMPLE` is actually **caught by the false positive filter** because it contains the word "example". This is intentional — it is a documented example key, not a real credential. A real AWS key with high-entropy random characters would pass this check.

#### Example 2: Missed — Credential Fails at Layer 2 (Regex)

Consider a file containing a mixed-case access key ID:
```
aws_access_key_id = AKIAs9L8MS5iPHTZPPUQ
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4W
```

**Layer 1 — Keyword Prefilter:** The chunk contains `AKIA` (case-insensitive match) → keyword match found ✓

**Layer 2 — Regex Matching:**
The ID `AKIAs9L8MS5iPHTZPPUQ` contains lowercase letters (`s`, `i`). The regex `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` requires all 16 characters after the prefix to be `[A-Z0-9]` (uppercase only).

**Result: ✗ FAIL** — the credential is silently dropped. The AWS detector was invoked (passed Layer 1) but found no valid ID matches, so no results are produced.

*Source: `pkg/detectors/aws/access_keys/accesskey.go`, line 65 — the regex `[A-Z0-9]{16}` strictly requires uppercase.*

#### Example 3: Missed — Credential Fails at Layer 4 (Hex FP)

Consider a file containing:
```
AKIA_KEY=AKIAZ3MRHLLKZZ4GZN5Q
SECRET=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
```

**Layers 1–3:** The ID passes keyword, regex, and entropy checks. The secret `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0` is 40 characters of `[A-Za-z0-9+/]` and has sufficient entropy ✓

**Layer 4 — Hex FP Check:**
The secret `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0` consists entirely of lowercase hex characters (`[a-f0-9]`). It matches `FalsePositiveSecretPat`:

```go
var FalsePositiveSecretPat = regexp.MustCompile(`[a-f0-9]{40}`)
```
*Source: `pkg/detectors/aws/utils.go`, line 47*

Since the result is unverified (verification would confirm it's not a real key, but verification hasn't happened yet in this pipeline stage), it is dropped:

**Result: ✗ FAIL** — the credential looks like a git commit hash and is silently dropped.

---

## Q2: How Does Encoding Sensitive Data Affect Detection?

### Thinking / Rationale

To understand how encoding affects detection, the investigation analyzed the decoder pipeline in `pkg/decoders/`. TruffleHog runs each chunk through a chain of 4 decoders **independently** — meaning each decoder gets the original chunk and produces a decoded version (or nil). The decoded versions are then each processed through the rest of the detection pipeline. This means Base64-encoded credentials can be detected, but only if the Base64 decoder successfully extracts and decodes them.

### Supported vs. Unsupported Encodings

TruffleHog's decoder chain is defined in `DefaultDecoders()`:

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
*Source: `pkg/decoders/decoders.go`, lines 8–16*

Each chunk is passed through **all 4 decoders independently**, producing up to 4 decoded versions of the chunk:

| Decoder | Purpose | Always Succeeds? | Source |
|---------|---------|-------------------|--------|
| UTF8 | Plain text passthrough (baseline) | **Yes** — always returns a DecodableChunk | `pkg/decoders/decoders.go`, line 10 |
| Base64 | Decodes Base64-encoded substrings | No — requires substrings > 20 chars that decode to valid ASCII | `pkg/decoders/base64.go` |
| UTF16 | Converts UTF-16 to UTF-8 | No — requires UTF-16 BOM or valid UTF-16 content | `pkg/decoders/utf16.go` |
| EscapedUnicode | Normalizes `\uXXXX` and `U+XXXX` sequences | No — requires escaped unicode sequences | `pkg/decoders/escaped_unicode.go` |

**Encodings NOT supported** (will evade detection entirely):
- Hex encoding (e.g., `0x414b4941...`)
- ROT13 or other Caesar cipher variants
- Custom obfuscation schemes
- XOR-based encoding
- Any encoding not in the 4-decoder chain

### Base64 Decoder Internals and Thresholds

The Base64 decoder has several constraints that determine whether encoded content is decoded:

#### 1. Minimum Length Threshold: > 20 Characters

Base64-encoded substrings must be **strictly longer than 20 characters** to be considered for decoding:

```go
encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
```
*Source: `pkg/decoders/base64.go`, line 36*

The `getSubstringsOfCharacterSet` function uses a **strictly greater than** comparison:

```go
if count > threshold {
    substringsCount++
}
```
*Source: `pkg/decoders/base64.go`, lines 97, 103, 118, 125*

This means exactly 20 characters does **not** qualify — the substring must be at least 21 characters.

#### 2. Valid Base64 Character Set

Only characters in the Base64 alphabet are considered part of encoded substrings:

```go
b64Charset = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
```
*Source: `pkg/decoders/base64.go`, line 17*

#### 3. Dual Decoding Attempts

Both standard and URL-safe Base64 encodings are tried:

```go
dec, err := base64.StdEncoding.DecodeString(str)
if err == nil && len(dec) > 0 && isASCII(dec) {
    decodedSubstrings[str] = dec
}

dec, err = base64.RawURLEncoding.DecodeString(str)
if err == nil && len(dec) > 0 && isASCII(dec) {
    decodedSubstrings[str] = dec
}
```
*Source: `pkg/decoders/base64.go`, lines 40–48*

#### 4. ASCII Validation

Decoded output must be valid ASCII (all bytes ≤ 127):

```go
func isASCII(b []byte) bool {
    for i := 0; i < len(b); i++ {
        if b[i] > unicode.MaxASCII {
            return false
        }
    }
    return true
}
```
*Source: `pkg/decoders/base64.go`, lines 74–81*

If the decoded bytes contain non-ASCII characters (e.g., binary data that happens to be valid Base64), the decoded output is rejected.

#### 5. Substitution Mechanism

Successfully decoded substrings **replace** the encoded substrings in the chunk data, producing a new chunk that is then processed by the normal detection pipeline.

*Source: `pkg/decoders/base64.go`, lines 51–68*

### Partial URL Encoding Support

A limited form of URL encoding is handled **within the AWS detector itself** (not as a general decoder):

```go
var UrlEncodedReplacer = strings.NewReplacer(
    "%2B", "+",
    "%2b", "+",
    "%2F", "/",
    "%2f", "/",
    "%3d", "=",
    "%3D", "=",
)
```
*Source: `pkg/detectors/aws/utils.go`, lines 35–42*

This only handles the 3 Base64 special characters (`+`, `/`, `=`) that are commonly URL-encoded. It does not handle general URL encoding of arbitrary characters.

### Iterative Decoding Depth

TruffleHog supports iterative decoding (e.g., double-Base64) via the `--max-decode-depth` CLI flag (default: 5). Each iteration requires the decoded result to still exceed the 20-character threshold and produce valid ASCII.

### Concrete Examples

#### Example 1: Base64-Encoded Credential — DETECTED

A config file contains the following Base64-encoded block:
```
credentials = QVDTX0FDQ0VTU19LRVlfSUQ9QUtJQVo3WDNNUkhMTDJHWk40TTgKQVdTX1NFQ1JFVF9BQ0NFU1NfS0VZPXdKYWxyWFV0bkZFTUkvSzdNREVORy9iUHhSZmlDWXpROWgyakw0VzU=
```

The Base64-encoded string is 100 characters long (> 20 threshold ✓). When decoded, it produces valid ASCII:
```
AWS_ACCESS_KEY_ID=AKIAZ7X3MRHLL2GZN4M8
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4W5
```

The Base64 decoder replaces the encoded string with the decoded content. The decoded chunk then passes through the normal detection pipeline:
- Layer 1: Contains "AKIA" → ✓
- Layer 2: ID and secret match regex patterns → ✓
- Layers 3–6: Standard filtering applies

**Result: DETECTED** — the Base64 decoder successfully reveals the embedded credential.

#### Example 2: Hex-Encoded Credential — EVADES Detection

The same credential hex-encoded:
```
credentials = 414b49415a375833-4d52484c4c32475a4e344d38
```

**Why it evades:**
1. Hex encoding is **not in the decoder chain** — there is no hex decoder in `DefaultDecoders()`
2. The hex string `414b49415a375833...` does not contain the keyword `AKIA` (it contains the hex representation `414b4941`, not the ASCII text)
3. The Aho-Corasick prefilter never finds a keyword match
4. The AWS detector is never invoked

**Result: NOT DETECTED** — the credential is invisible to TruffleHog.

#### Example 3: Short Base64 — EVADES Detection

A file contains a short Base64-encoded snippet:
```
key = QUtJQTEyMzQ1Njc4
```

The Base64 string `QUtJQTEyMzQ1Njc4` is only 16 characters long. The Base64 decoder's minimum threshold requires > 20 characters:

```go
encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
```
*Source: `pkg/decoders/base64.go`, line 36*

Since 16 ≤ 20, the substring is not even considered for decoding.

**Result: NOT DETECTED** — the Base64 decoder ignores short encoded strings.

---

## Q3: Why Don't Test Fixture Credentials Get Flagged?

### Thinking / Rationale

Test fixture credentials typically evade detection through a combination of three mechanisms: (1) false positive word lists that catch common placeholder terms, (2) low Shannon entropy from repetitive or simple patterns, and (3) the hex false positive pattern that catches git-hash-like strings. The investigation traced each mechanism through the codebase to document exactly how test fixtures are filtered.

### False Positive Filtering Deep Dive

TruffleHog uses a multi-layered false positive filtering system specifically designed to suppress test fixtures and placeholder credentials:

#### Mechanism 1: `DefaultFalsePositives` Map

Seven common placeholder patterns are hardcoded:

```go
DefaultFalsePositives = map[FalsePositive]struct{}{
    "example": {}, "xxxxxx": {}, "aaaaaa": {}, "abcde": {}, "00000": {}, "sample": {}, "*****": {},
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 17–19*

The check is **case-insensitive** and uses both **exact match** and **substring containment**:

```go
lower := strings.ToLower(match)

if _, exists := falsePositives[FalsePositive(lower)]; exists {
    return true, "matches term: " + lower
}

for fp := range falsePositives {
    fps := string(fp)
    if strings.Contains(lower, fps) {
        return true, "contains term: " + fps
    }
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 89–99*

This means any credential containing the **substring** "example", "sample", "xxxxxx", "aaaaaa", "abcde", "00000", or "*****" (case-insensitive) will be filtered.

#### Mechanism 2: Aho-Corasick Trie Word Lists

At initialization, TruffleHog builds an Aho-Corasick trie from 4 embedded text files:

```go
//go:embed "fp_badlist.txt"
badList []byte
//go:embed "fp_words.txt"
wordList []byte
//go:embed "fp_programmingbooks.txt"
programmingBookWords []byte
//go:embed "fp_uuids.txt"
uuidList []byte
```
*Source: `pkg/detectors/falsepositives.go`, lines 35–42*

The trie is built during `init()`:
```go
func init() {
    builder := ahocorasick.NewTrieBuilder()
    builder.AddStrings(bytesToCleanWordList(wordList))
    builder.AddStrings(bytesToCleanWordList(badList))
    builder.AddStrings(bytesToCleanWordList(programmingBookWords))
    builder.AddStrings(bytesToCleanWordList(uuidList))
    filter = builder.Build()
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 45–61*

The word lists contain:
- **`fp_badlist.txt`**: Programming and crypto terms — "value", "token", "config", "export", "auth", "hash", "sha256", "module", "import", "package", "crypto", "secret", "password", etc.
- **`fp_words.txt`**: Common English words — "number", "people", "through", "weather", "school", "between", etc.
- **`fp_programmingbooks.txt`**: Programming book title words
- **`fp_uuids.txt`**: Known false positive UUID strings

The check uses `MatchFirstString` which finds the first word from any list that appears as a **substring** in the lowercased credential:

```go
if m := filter.MatchFirstString(lower); m != nil {
    return true, "matches wordlist: " + m.MatchString()
}
```
*Source: `pkg/detectors/falsepositives.go`, lines 103–105*

#### Mechanism 3: `trufflehog:ignore` Inline Comments

Code files can include inline suppression comments to prevent specific lines from being flagged. This is a scanner-level feature that developers can use intentionally for test fixtures.

### Entropy Gating on Test Fixtures

Test fixture IDs and secrets often use simple, repetitive patterns that fail Shannon entropy checks.

The `StringShannonEntropy` function calculates entropy as:

**H = −Σ(pᵢ × log₂(pᵢ))** where pᵢ is the frequency of each character divided by total length.

*Source: `pkg/detectors/falsepositives.go`, lines 136–151*

**Example — test ID with low entropy:**

Consider the test ID `AKIAAAAABBBBCCCCDDDD` (a pattern test fixtures sometimes use):

| Character | Count | Probability | p × log₂(p) |
|-----------|-------|-------------|--------------|
| A | 6 | 6/20 = 0.300 | −0.521 |
| B | 4 | 4/20 = 0.200 | −0.464 |
| C | 4 | 4/20 = 0.200 | −0.464 |
| D | 4 | 4/20 = 0.200 | −0.464 |
| I | 1 | 1/20 = 0.050 | −0.216 |
| K | 1 | 1/20 = 0.050 | −0.216 |

**H = 2.346 bits** → 2.346 < 3.0 → **FAIL ✗** — dropped at Layer 3.

### Hex False Positive Pattern

The hex false positive pattern specifically targets the 40-character overlap between AWS secret keys and git commit hashes:

```go
var FalsePositiveSecretPat = regexp.MustCompile(`[a-f0-9]{40}`)
```
*Source: `pkg/detectors/aws/utils.go`, line 47*

If an unverified secret consists entirely of lowercase hex characters (`[a-f0-9]`), it matches the pattern for a git SHA-1 hash and is dropped. This is checked within the detector itself:

```go
if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) {
    continue
}
```
*Source: `pkg/detectors/aws/access_keys/accesskey.go`, lines 202–205*

### Concrete Examples

#### Example 1: Fixture with "example" in the Credential

The well-known AWS documentation example:
```go
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Why it's filtered:**

The ID `AKIAIOSFODNN7EXAMPLE` passes Layers 1–4 (keyword present, regex matches, entropy = 3.684 ≥ 3.0, not pure hex). However, at Layer 5:

1. The `Raw` field is set to `[]byte(idMatch)` = `AKIAIOSFODNN7EXAMPLE`
   
   *Source: `pkg/detectors/aws/access_keys/accesskey.go`, line 138*

2. `IsKnownFalsePositive` lowercases it to `akiaiosfodnn7example`

3. The substring check finds "example" in `DefaultFalsePositives`:
   ```go
   strings.Contains("akiaiosfodnn7example", "example") → true
   ```

**Result: FILTERED** — the credential is dropped because it contains the word "example".

*Source: `pkg/detectors/falsepositives.go`, lines 95–99*

#### Example 2: Fixture with Low-Entropy Secret

A test file contains:
```
TEST_AWS_KEY=AKIAZ3MRHLLKZZ4GZN5Q
TEST_AWS_SECRET=AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFFFFGG
```

The ID `AKIAZ3MRHLLKZZ4GZN5Q` passes all checks (entropy = 3.622, regex valid, no FP words). But the secret `AAAAAABBBBBBCCCCCCDDDDDDEEEEEEFFFFFFFFGG`:

| Character | Count | Probability | p × log₂(p) |
|-----------|-------|-------------|--------------|
| A | 6 | 6/40 = 0.150 | −0.411 |
| B | 6 | 6/40 = 0.150 | −0.411 |
| C | 6 | 6/40 = 0.150 | −0.411 |
| D | 6 | 6/40 = 0.150 | −0.411 |
| E | 6 | 6/40 = 0.150 | −0.411 |
| F | 8 | 8/40 = 0.200 | −0.464 |
| G | 2 | 2/40 = 0.050 | −0.216 |

**H = 2.733 bits** → 2.733 < 4.25 → **FAIL ✗** — the secret is dropped at Layer 3 (entropy filtering).

*Source: `pkg/detectors/aws/common.go`, line 7: `RequiredSecretEntropy = 4.25`*

---

## Q4: What Does "Verification Disabled for Safety" Mean?

### Thinking / Rationale

The "verification disabled for safety" warning appears when TruffleHog detects the same credential with multiple detectors simultaneously. To understand why, the investigation traced the `verificationOverlapWorker` in `pkg/engine/engine.go` and the security motivation behind it — a supply chain attack vector where malicious detectors could exfiltrate credentials found by legitimate detectors.

### The Verification Overlap Safety System

The exact error message is defined in the engine:

```go
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
        "You can override this behavior by using the --allow-verification-overlap flag.",
)
```
*Source: `pkg/engine/engine.go`, lines 39–42*

> **Note:** There is a missing space between the two sentences in the actual source code — the message reads `"...disabled.You can..."` (no space after the period). This is a minor formatting bug in the codebase.

### How the Overlap System Works

The verification overlap system is implemented as a routing decision in the scanner worker:

```mermaid
sequenceDiagram
    participant SW as scannerWorker
    participant AC as AhoCorasickCore
    participant VOC as verificationOverlapChunksChan
    participant VOW as verificationOverlapWorker
    participant DC as detectableChunksChan
    participant DW as detectorWorker

    SW->>AC: FindDetectorMatches(chunkData)
    AC-->>SW: matchingDetectors[]

    alt len(matchingDetectors) > 1 AND !verificationOverlap
        SW->>VOC: Route chunk to overlap channel
        VOC->>VOW: Process chunk
        
        loop For each detector
            VOW->>VOW: FromData(ctx, verify=false, match)
            VOW->>VOW: Check results for duplicates
        end
        
        alt Duplicate secret found across detectors
            VOW->>VOW: Set errOverlap as verification error
            VOW->>VOW: processResult (without verification)
        else Unique to one detector
            VOW->>DC: Route to normal detection
            DC->>DW: Process with verification enabled
        end
    else len(matchingDetectors) == 1 OR verificationOverlap
        SW->>DC: Route to normal detection
        DC->>DW: Process normally
    end
```

The key decision point is in `scannerWorker`:

```go
matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
if len(matchingDetectors) > 1 && !e.verificationOverlap {
    wgVerificationOverlap.Add(1)
    e.verificationOverlapChunksChan <- verificationOverlapChunk{
        chunk:     *decoded.Chunk,
        detectors: matchingDetectors,
        decoder:   decoded.DecoderType,
        verificationOverlapWgDoneFn: wgVerificationOverlap.Done,
    }
    continue
}
```
*Source: `pkg/engine/engine.go`, lines 795–804*

When **multiple detectors** match the same chunk **and** `--allow-verification-overlap` is **not** set, the chunk is routed to the `verificationOverlapWorker` instead of the normal detection path.

The `verificationOverlapWorker` then:

1. Calls each detector's `FromData()` with `verify=false` — **never sends credentials to external services**:
   ```go
   results, err := detector.FromData(ctx, false, match)
   ```
   *Source: `pkg/engine/engine.go`, line 940*

2. Uses `likelyDuplicate()` with Levenshtein distance to check if the same secret was found by multiple detectors:
   ```go
   if likelyDuplicate(ctx, key, chunkSecrets) {
   ```
   *Source: `pkg/engine/engine.go`, line 982*

3. If a duplicate is found, sets `errOverlap` as the verification error and processes the result **without verification**:
   ```go
   res.SetVerificationError(errOverlap)
   ```
   *Source: `pkg/engine/engine.go`, line 988*

4. If the secret is unique to one detector, that detector is sent to the normal detection path **with verification enabled**:
   ```go
   for _, detector := range detectorKeysWithResults {
       wgDetect.Add(1)
       chunk.chunk.Verify = e.shouldVerifyChunk(chunk.chunk.Verify, detector, e.detectorVerificationOverrides)
       e.detectableChunksChan <- detectableChunk{...}
   }
   ```
   *Source: `pkg/engine/engine.go`, lines 1011–1020*

### Security Motivation (Supply Chain Attack Vector)

This safety system exists to prevent a **supply chain attack** against TruffleHog:

1. **Attack scenario**: A malicious actor contributes a custom detector to TruffleHog (either via a pull request to the open-source project or through a custom detector configuration). The malicious detector has keywords that overlap with legitimate detectors (e.g., it also matches on `AKIA`).

2. **Exploitation**: When the malicious detector's `FromData()` method is called with `verify=true`, instead of (or in addition to) verifying the credential against a legitimate service, it **exfiltrates** the credential — sending it to an attacker-controlled server.

3. **Impact**: The malicious detector would receive credentials that were extracted by the **legitimate** AWS detector, because both detectors operate on the same chunk data.

4. **Mitigation**: By disabling verification when multiple detectors match the same chunk, TruffleHog ensures that no detector's `FromData()` is called with `verify=true` in the overlap scenario. Credentials are still reported (as unverified), but they are never sent to external services.

This was introduced as a security mitigation in TruffleHog v3.67.0.

### How to Override and When You Should

The `--allow-verification-overlap` CLI flag overrides the safety check:

When this flag is set, `e.verificationOverlap` is `true`, and the check at line 796 is bypassed — all matching detectors are sent to the normal detection path with verification enabled.

**When to use this flag:**
- Only when you **trust all detectors** in your configuration
- In environments with no custom or third-party detectors
- When you need verified results and accept the security trade-off

**When NOT to use this flag:**
- When running with custom detectors from untrusted sources
- In CI/CD pipelines that use community-contributed detector configurations
- When security is more important than verification completeness

*Source: `pkg/engine/engine.go`, line 796*

---

## Q5: Detection Boundaries — What Gets Caught vs. What Slips Through?

### Thinking / Rationale

To map the exact detection boundaries, the investigation catalogued every threshold, regex pattern, and filtering rule from the AWS detection pipeline. Each boundary is binary — a credential either passes or fails at each stage. This section provides the complete boundary map and demonstrates exact threshold behavior with computed entropy values.

### Boundary Map: Complete Detection Criteria

| # | Criterion | Threshold / Pattern | Pass (Detected) | Fail (Missed) | Source |
|---|-----------|-------------------|-----------------|---------------|--------|
| 1 | Keyword present | `AKIA`, `ABIA`, `ACCA` in chunk | Keyword found (case-insensitive) | Keyword absent | `pkg/detectors/aws/access_keys/accesskey.go`, lines 70–76 |
| 2 | ID regex | `\b((?:AKIA\|ABIA\|ACCA)[A-Z0-9]{16})\b` | All uppercase + digits, exactly 20 chars | Mixed case, wrong length, or missing boundaries | `pkg/detectors/aws/access_keys/accesskey.go`, line 65 |
| 3 | Secret regex | `(?:[^A-Za-z0-9+/]\|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]\|\z)` | Exactly 40 Base64 chars with boundary chars | Wrong length, invalid chars, or missing boundaries | `pkg/detectors/aws/common.go`, line 10 |
| 4 | ID entropy | ≥ 3.0 bits | High character variety (14 unique in 20 → 3.68) | Repetitive patterns (6 unique in 20 → 2.35) | `pkg/detectors/aws/common.go`, line 6 |
| 5 | Secret entropy | ≥ 4.25 bits | High character variety (20+ unique in 40) | Repetitive patterns (7 unique in 40 → 2.73) | `pkg/detectors/aws/common.go`, line 7 |
| 6 | Hex FP pattern | `[a-f0-9]{40}` (unverified only) | Contains uppercase, `+`, or `/` | Pure lowercase hex | `pkg/detectors/aws/utils.go`, line 47 |
| 7 | FP word list | Aho-Corasick trie from 4 lists | No substring match | Contains "value", "token", "auth", etc. | `pkg/detectors/falsepositives.go`, lines 102–106 |
| 8 | DefaultFP map | 7 placeholder terms | Not contained as substring | Contains "example", "sample", "xxxxxx", etc. | `pkg/detectors/falsepositives.go`, lines 17–19 |

### Entropy Threshold Boundary Examples

#### ID Entropy at the 3.0 Boundary

**PASSES (entropy = 3.03):** `AKIAABBBCCCDDDEEE112`

| Character | Count | Probability (p) | p × log₂(p) |
|-----------|-------|-----------------|--------------|
| 1 | 2 | 2/20 = 0.100 | −0.332 |
| 2 | 1 | 1/20 = 0.050 | −0.216 |
| A | 3 | 3/20 = 0.150 | −0.411 |
| B | 3 | 3/20 = 0.150 | −0.411 |
| C | 3 | 3/20 = 0.150 | −0.411 |
| D | 3 | 3/20 = 0.150 | −0.411 |
| E | 3 | 3/20 = 0.150 | −0.411 |
| I | 1 | 1/20 = 0.050 | −0.216 |
| K | 1 | 1/20 = 0.050 | −0.216 |

**H = 3.033 bits** → 3.033 ≥ 3.0 → **PASS ✓**

**FAILS (entropy = 2.88):** `AKIAABBBBCCCCDDDD123`

| Character | Count | Probability (p) | p × log₂(p) |
|-----------|-------|-----------------|--------------|
| 1 | 1 | 1/20 = 0.050 | −0.216 |
| 2 | 1 | 1/20 = 0.050 | −0.216 |
| 3 | 1 | 1/20 = 0.050 | −0.216 |
| A | 3 | 3/20 = 0.150 | −0.411 |
| B | 4 | 4/20 = 0.200 | −0.464 |
| C | 4 | 4/20 = 0.200 | −0.464 |
| D | 4 | 4/20 = 0.200 | −0.464 |
| I | 1 | 1/20 = 0.050 | −0.216 |
| K | 1 | 1/20 = 0.050 | −0.216 |

**H = 2.884 bits** → 2.884 < 3.0 → **FAIL ✗**

The difference: 9 unique characters with more uniform distribution (PASS) vs. 9 unique characters with skewed distribution (FAIL). More concentrated character frequencies reduce entropy below the threshold.

#### Secret Entropy at the 4.25 Boundary

**PASSES (entropy = 4.32):** A 40-character string with 20 unique characters, each appearing exactly twice.

Example: `AaBbCcDdEeFfGgHhIiJjAaBbCcDdEeFfGgHhIiJj`

Each of the 20 unique characters appears exactly 2 times:
- p = 2/40 = 0.05 for all characters
- Each contribution: 0.05 × log₂(0.05) = −0.216

**H = 20 × 0.216 = 4.322 bits** → 4.322 ≥ 4.25 → **PASS ✓**

**FAILS (entropy = 4.22):** A 40-character string with 19 unique characters — 18 appearing twice and 1 appearing four times.

Example: `AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRaaaa`

- 18 characters with count = 2: p = 2/40 = 0.05, contrib = −0.216 each
- 1 character (`a`) with count = 4: p = 4/40 = 0.10, contrib = −0.332

**H = (18 × 0.216) + 0.332 = 4.222 bits** → 4.222 < 4.25 → **FAIL ✗**

The margin is razor-thin: **4.322 vs. 4.222** — a difference of just 0.1 bits caused by one character appearing 4 times instead of 2. This demonstrates how a small reduction in character diversity pushes a credential below the detection threshold.

### Regex Boundary Examples

#### ID Pattern: `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`

| Input | Length | Chars After Prefix | Result | Reason |
|-------|--------|-------------------|--------|--------|
| `AKIAIOSFODNN7EXAMPLE` | 20 | 16 uppercase/digits | ✓ PASS | All requirements met |
| `AKIAiosfodnn7example` | 20 | 16 mixed-case | ✗ FAIL | Lowercase letters fail `[A-Z0-9]{16}` |
| `AKIAIOSFODNN7EXAMPL` | 19 | 15 chars | ✗ FAIL | Only 15 chars after prefix (needs 16) |
| `AKIAIOSFODNN7EXAMPLES` | 21 | 17 chars | ✗ FAIL | 17 chars after prefix — regex matches first 20, but `\b` may not be at position 20 |
| `AKIAIOSFODNN7EXAMP+E` | 20 | Includes `+` | ✗ FAIL | `+` is not in `[A-Z0-9]` |
| `xAKIAIOSFODNN7EXAMPLE` | — | — | ✓ PASS | `\b` matches at word boundary before `AKIA` |

*Source: `pkg/detectors/aws/access_keys/accesskey.go`, line 65*

#### Secret Pattern: `(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)`

| Input | Length | Result | Reason |
|-------|--------|--------|--------|
| `=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4W5=` | 40 inner chars | ✓ PASS | `=` is a non-Base64 boundary char; 40 valid inner chars |
| ` wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4W` | 40 inner chars | ✓ PASS | Space is a non-Base64 boundary char |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4` | 39 chars | ✗ FAIL | Only 39 characters (needs exactly 40) |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9h2jL4W5m` | 41 chars | ✗ FAIL | 41 characters — no exact 40-char match extracted |
| `wJalrXUtnFEMI/K7MDEN /bPxRfiCYzQ9h2jL4W5` | Space inside | ✗ FAIL | Space breaks the `[A-Za-z0-9+/]{40}` run |

*Source: `pkg/detectors/aws/common.go`, line 10*

#### Session Key Patterns (Bonus)

For AWS session keys (`ASIA` prefix), additional constraints apply:

- ID pattern: `\b((?:ASIA)[A-Z0-9]{16})\b` — same structure but `ASIA` prefix
- Session token pattern: requires 100+ Base64 characters: `(?:[^A-Za-z0-9+/]|\A)([a-zA-Z0-9+/]{100,}={0,3})(?:[^A-Za-z0-9+/=]|\z)`
- Session token entropy threshold: **4.5** (higher than the regular secret threshold of 4.25)

*Source: `pkg/detectors/aws/session_keys/sessionkey.go`, lines 61–62, 108*

---

## Summary: Key Takeaways

1. **Inconsistent detection is caused by the six-layer detection gauntlet** — a credential must survive keyword prefiltering, regex matching, entropy filtering, hex false positive checking, known false positive word list filtering, and result deduplication. Failure at **any single layer** means silent non-detection. The behavior is deterministic: the same file always produces the same result.

2. **Base64 encoding is handled by the decoder chain** but only for substrings strictly longer than 20 characters that produce valid ASCII when decoded. Other encodings (hex, ROT13, custom obfuscation) are **not** in the decoder chain and will evade detection entirely.
   *Source: `pkg/decoders/base64.go`, line 36*

3. **Test fixtures typically evade detection** through three mechanisms: the `DefaultFalsePositives` map (catches "example", "sample", etc.), the Aho-Corasick word list trie (catches programming terms like "token", "config", "auth"), and low Shannon entropy from repetitive patterns falling below the 3.0 (ID) or 4.25 (secret) thresholds.
   *Source: `pkg/detectors/falsepositives.go`, lines 17–19, 32–67, 136–151*

4. **"Verification disabled for safety"** is a security measure preventing credential exfiltration when multiple detectors match the same chunk. It mitigates a supply chain attack vector where a malicious detector could steal credentials found by legitimate detectors. The `--allow-verification-overlap` flag overrides this behavior but should only be used when all detectors are trusted.
   *Source: `pkg/engine/engine.go`, lines 39–42, 795–804*

5. **Detection boundaries are sharp and deterministic** — entropy thresholds (3.0 for ID, 4.25 for secret), regex patterns (exact character classes and lengths), and word lists create binary pass/fail outcomes. The margin between detection and evasion can be as small as 0.1 bits of entropy or a single lowercase character in an ID.
   *Source: `pkg/detectors/aws/common.go`, lines 6–7, 10; `pkg/detectors/aws/access_keys/accesskey.go`, line 65*
