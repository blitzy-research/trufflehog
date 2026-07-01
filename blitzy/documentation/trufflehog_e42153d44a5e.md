# Why TruffleHog's AWS credential detection looks "inconsistent" — a run-first investigation

> **Scope & method.** This document answers, with running evidence, why TruffleHog v3 detects a valid-looking AWS credential in some files but misses or reports it differently in others. Every mechanism is grounded in **both** an exact `file:line` citation from the codebase **and** verbatim output captured from a binary we built and ran. The repository was **not modified**: all fixtures live under `/tmp/th_fixtures` (outside the repo) and the binary is `/tmp/trufflehog`. `git status --porcelain` is empty aside from this document.
>
> **Module:** `github.com/trufflesecurity/trufflehog/v3` · **Binary:** built from this branch with `CGO_ENABLED=0 go build -o /tmp/trufflehog .` (reports `trufflehog dev`).

---

## TL;DR

Detection is **100% deterministic** — the code path is pure keyword / regex / Shannon-entropy logic with no randomness. A credential is reported **only if it clears every gate in order**:

1. A **keyword** (`AKIA`, `ABIA`, or `ACCA`) is present in the (possibly decoded) chunk.
2. The data window around that keyword contains **both** a matching **ID** and a matching **secret** (AWS uses a **±1024-byte** window, not the default ±512).
3. The ID's Shannon entropy is **≥ 3.0** *and* the secret's is **≥ 4.25**.
4. When unverified, the secret is **not** a hex string matching `[a-f0-9]{40}`.
5. The value is **not** a known false positive (e.g. it does not contain `"example"`).
6. The value is **not** flagged as a cross-detector overlap duplicate.

Two gates behave very differently and explain most of the confusion:

- The **entropy gates (step 3)** are **detector-internal**: sub-threshold candidates are dropped **before a result object exists**, so `--results=filtered_unverified` **cannot** bring them back.
- The **known-false-positive filter (step 5)** is **engine-level**: it runs **after** the result is produced, so `--results=filtered_unverified` **can** recover it.

---

## 1. The detection pipeline (frame for every answer)

Every file chunk flows through the same stages. Understanding the order is the key to every "inconsistency."

```mermaid
flowchart TD
    A["File chunk"] --> B["Decoders, in order:<br/>UTF8 · Base64 · UTF16 · EscapedUnicode<br/>decoders.go:11-14"]
    B --> C{"Aho-Corasick:<br/>keyword present?<br/>AKIA / ABIA / ACCA<br/>accesskey.go:70-76"}
    C -- no --> X["No AWS scan → no result"]
    C -- yes --> D["Extract span around keyword.<br/>AWS window = keywordIdx ± 1024 bytes<br/>multi_part_credential_provider.go:8<br/>ahocorasickcore.go:88 vs default 512 at :155"]
    D --> E["AWS FromData: idPat + SecretPat<br/>accesskey.go:65 · common.go:10"]
    E --> F{"ID entropy ≥ 3.0 AND<br/>secret entropy ≥ 4.25?<br/>accesskey.go:122,132 · common.go:6-7"}
    F -- no --> X2["Dropped PRE-RESULT<br/>not recoverable by --results"]
    F -- yes --> G{"Unverified secret matches<br/>hex [a-f0-9] 40 chars?<br/>accesskey.go:202 · utils.go:47"}
    G -- yes --> X3["Dropped as false positive"]
    G -- no --> H["Result object created"]
    H --> I{"More than one detector<br/>matched this chunk?<br/>engine.go:796"}
    I -- yes --> J["Overlap worker: if same value<br/>Levenshtein similarity over 0.9 → errOverlap<br/>engine.go:887-911, 988"]
    I -- no --> K["Verify via STS unless --no-verification"]
    J --> L["filterResults engine.go:1126"]
    K --> L
    L --> M{"retainFalsePositives?<br/>--results=filtered_unverified<br/>engine.go:317-318, 1141-1142"}
    M -- no --> N["FilterKnownFalsePositives<br/>drops 'example' etc."]
    M -- yes --> O["Keep filtered results"]
    N --> P["Output · plain.go:55-65"]
    O --> P
```

**Why it's deterministic:** none of these stages uses randomness. Regexes, the Shannon-entropy computation (`StringShannonEntropy`, `falsepositives.go:136`), the fixed wordlists, the fixed byte window, and Levenshtein similarity are all pure functions of the input bytes. The same file therefore always yields the same result.

---

## 2. Answers to each sub-question

### Q1 — Why is detection "inconsistent" across files (but deterministic)?

**Mechanism.** The AWS detector never sees the whole file. Two facts combine:

1. **Keyword pre-filter.** A chunk is routed to the AWS detector only if it contains one of the detector's keywords. `pkg/detectors/aws/access_keys/accesskey.go:70-76`:

   ```go
   func (s scanner) Keywords() []string {
       return []string{
           "AKIA",   // :72
           "ABIA",   // :73
           "ACCA",   // :74
       }
   }
   ```

2. **Bounded credential window.** The bytes handed to the detector are only a *span* around the matched keyword. The default half-width is 512 bytes — `pkg/engine/ahocorasick/ahocorasickcore.go:155`:

   ```go
   const defaultOffsetRadius int64 = 512
   ```

   But the AWS detector implements `MultiPartCredentialProvider`, so the span calculator overrides that width — `pkg/engine/ahocorasick/ahocorasickcore.go:88-90`:

   ```go
   if provider, ok := params.detector.(detectors.MultiPartCredentialProvider); ok {
       maxSize = provider.MaxCredentialSpan() + keywordIdx
       startOffset = keywordIdx - provider.MaxCredentialSpan()
   ```

   and the width is **1024** — `pkg/detectors/multi_part_credential_provider.go:8`:

   ```go
   const defaultMaxCredentialSpan = 1024
   ```

`FromData` (`accesskey.go:105`) only emits a result when it finds **both** an ID (`idPat`) and a secret (`SecretPat`) inside that one span; there is no ID-only result path. So if the secret sits farther than 1024 bytes from the `AKIA` keyword, the ID and secret are never in the same window, and **nothing is reported** — even though both strings are physically in the file.

**Observed — the same pair, close vs. far apart (both `--no-verification`).** Each block below is the verbatim `finished scanning` summary line that TruffleHog writes to **stderr**. The leading RFC3339 timestamp and the `scan_duration` field vary from run to run; every other field — notably `bytes` and the `verified_secrets`/`unverified_secrets` counts — is exact and reproducible.

`proximity_close.txt` (ID → secret gap ~24 bytes) — **one** finding:

```
2026-07-01T06:26:26Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.771814ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

`proximity_far.txt` (`AKIA` at byte 0, secret ~2825 B later; gap 2805 > 1024) — **no** finding:

```
2026-07-01T06:26:28Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2866, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.47386ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The far case stays empty **even with `--results=filtered_unverified`** — the ID and secret are never evaluated together, so no result is ever produced to recover:

```
2026-07-01T06:26:29Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2866, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.487287ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed — determinism (same file `entropy_above.txt`, three consecutive runs).** These are the three verbatim stderr summary lines; only the timestamp and `scan_duration` change — the count (`"unverified_secrets": 1`) is identical every time:

```
2026-07-01T06:35:03Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.267185ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
2026-07-01T06:35:05Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.487618ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
2026-07-01T06:35:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.61583ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Answer.** Detection is deterministic; the *apparent* inconsistency is layout-driven. If the credential ID and secret are within the ±1024-byte AWS window they are detected; if a file separates them by more than that, the pair is never evaluated together and produces no finding.

---

### Q2 — Does encoding (e.g. Base64) hide a credential?

**Mechanism.** Every chunk is run through an ordered decoder chain — `pkg/decoders/decoders.go:11-14`:

```go
&UTF8{},            // :11  ("UTF8 must be first for duplicate detection")
&Base64{},          // :12
&UTF16{},           // :13
&EscapedUnicode{},  // :14
```

The Base64 decoder (`pkg/decoders/base64.go:34`) scans for base64 runs of length **≥ 20** and tries two alphabets, keeping only results that decode to **ASCII**:

```go
encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)   // :36
...
dec, err := base64.StdEncoding.DecodeString(str)     // :40
if err == nil && len(dec) > 0 && isASCII(dec) { ... } // :41
dec, err = base64.RawURLEncoding.DecodeString(str)   // :45
if err == nil && len(dec) > 0 && isASCII(dec) { ... } // :46
```

The decoded text is then re-scanned by the whole detector pipeline. So Base64 does **not** hide a credential (as long as the decoded bytes are ASCII and still contain the keyword). It merely changes the reported **decoder type**.

**Observed — a file containing *only* Base64 (no plaintext `AKIA`), `--no-verification`:**

The fixture `encoded_b64.txt` is a single base64 line that decodes to `aws_access_key_id=AKIAZ24FK7QW8XV5N3PB` / `aws_secret_access_key=P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ`:

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIAZ24FK7QW8XV5N3PB
Resource_type: Access key
File: /tmp/th_fixtures/encoded_b64.txt
Line: 1
```

**Answer.** Base64-encoding a credential provides **no** protection — TruffleHog decodes and re-scans it, and the finding surfaces under `Decoder Type: BASE64`. (Encoding only defeats detection if the base64 run is < 20 chars, decodes to non-ASCII, or no longer contains a keyword after decoding.)

---

### Q3 — Why are credentials in test fixtures "in the right format" never flagged?

**Mechanism.** The AWS detector's `Raw` value is the **access-key ID** (see the `Raw result:` line in every capture). After results are produced, the engine runs `FilterKnownFalsePositives` (called at `pkg/engine/engine.go:1142`, guarded by `if !e.retainFalsePositives {` at `:1141`), which calls `IsKnownFalsePositive`. That function returns true when the lowercased value **contains** any default term — `pkg/detectors/falsepositives.go:97-98`:

```go
for fp := range falsePositives {
    fps := string(fp)
    if strings.Contains(lower, fps) {
        return true, "contains term: " + fps
    }
```

The default terms are `pkg/detectors/falsepositives.go:17-18`:

```go
DefaultFalsePositives = map[FalsePositive]struct{}{
    "example": {}, "xxxxxx": {}, "aaaaaa": {}, "abcde": {}, "00000": {}, "sample": {}, "*****": {},
```

The canonical AWS documentation credential — access-key ID `AKIAIOSFODNN7EXAMPLE`, secret `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — lowercases to `akiaiosfodnn7example`, which **contains** `example`. So it is filtered as a known false positive. (This is the AWS-documented example pair, which is exactly what tends to appear in fixtures and docs.)

Crucially this filter runs **after** the result exists, and the engine skips it when `retainFalsePositives` is set from `--results=filtered_unverified` — `pkg/engine/engine.go:317-318` and `:1141-1142` (guard at `:1141`, call at `:1142`):

```go
if _, ok = results["filtered_unverified"]; ok {
    engine.retainFalsePositives = ok            // :318
...
if !e.retainFalsePositives {                                                       // :1141 (guard)
    results = detectors.FilterKnownFalsePositives(ctx, detector.Detector, results)  // :1142 (call)
}
```

**Observed — the example key: default vs. false-positives retained:**

Default (`--no-verification`) → **nothing is printed to stdout**; the verbatim stderr summary line reports zero findings (note the comma-separated JSON context; timestamp and `scan_duration` vary per run):

```
2026-07-01T06:26:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.055558ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

With `--no-verification --results=filtered_unverified` → it comes back:

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLE
Resource_type: Access key
File: /tmp/th_fixtures/example_fixture.txt
Line: 2
```

**Answer.** Example/fixture credentials are correctly *matched* but then **dropped by the engine's known-false-positive filter** because the value contains a term like `example`. They are recoverable with `--results=filtered_unverified` — proof that they were detected and only *filtered*, not missed.

---

### Q4 — What triggers "verification has been disabled … for your safety"?

**Mechanism.** When a chunk is matched by **more than one detector** and the `--allow-verification-overlap` flag is off, the engine routes the chunk to a verification-overlap worker — `pkg/engine/engine.go:795-796`:

```go
matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
if len(matchingDetectors) > 1 && !e.verificationOverlap {
```

If two different detectors report the **same value** (exact match, or Levenshtein similarity > 0.9), it is treated as a duplicate — `pkg/engine/engine.go:887-911`:

```go
func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
    const similarityThreshold = 0.9           // :888
    ...
    similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())  // :911
```

and the result's verification error is set to `errOverlap` — `pkg/engine/engine.go:988`:

```go
res.SetVerificationError(errOverlap)
```

The message text is two string literals **concatenated** — `pkg/engine/engine.go:39-42`:

```go
var errOverlap = errors.New(
    "More than one detector has found this result. For your safety, verification has been disabled." +
        "You can override this behavior by using the --allow-verification-overlap flag.",
)
```

Note the concatenation joins `disabled.` and `You` with **no space** — the output literally reads `disabled.You`. Verification is disabled so TruffleHog does not send the same candidate secret to multiple providers' verification endpoints.

**Observed — a value matched by both the AWS detector and a custom "shadow" detector** (`--config=aws_overlap.yaml --no-verification`). Both results are always reported (the finding **count is deterministic** — the scan always reports two unverified secrets); what is *not* fixed between runs is **which** of the two results carries the `Verification issue` line (see the non-determinism note below). The warning is rendered by `pkg/output/plain.go:57` (`"Verification issue: %s\n"`). The following is a representative run — the common case:

```
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: AKIAZ24FK7QW8XV5N3PB:P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ
Name: aws-overlap-shadow
File: /tmp/th_fixtures/aws_overlap.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ24FK7QW8XV5N3PB
Resource_type: Access key
File: /tmp/th_fixtures/aws_overlap.txt
Line: 1
```

The verbatim summary line (stderr) confirms both results are reported — `unverified_secrets: 2` (the leading RFC3339 timestamp and `scan_duration` vary per run; every other field, including `bytes` and the counts, reproduces exactly):

```
2026-07-01T06:26:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 75, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.493409ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Non-determinism — which result carries the warning.** The overlap worker loops over the chunk's matched detectors — `pkg/engine/engine.go:932-933`. Whichever detector is processed **first** seeds the `chunkSecrets` map and is queued for normal output; the detector processed **second** is detected as a likely-duplicate, has its verification error set to `errOverlap` (`pkg/engine/engine.go:988`), and is emitted **immediately** via `processResult` — so the result carrying the warning is the one that **prints first**. The iteration order over the matched detectors is not fixed between runs, so which detector receives the warning varies. Across **12 consecutive runs** of the exact command above, the warning landed on **CustomRegex 10 times and on AWS 2 times** (in every run the warning-carrying result was the one printed first). The block above shows the common case — it should **not** be read as "the AWS result always carries the warning"; either detector may.

Re-running with `--allow-verification-overlap` **removes** the `Verification issue` line entirely; both detectors report normally (in that run the AWS result printed first, then CustomRegex — again reflecting the non-fixed ordering, but with no warning on either):

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ24FK7QW8XV5N3PB
Resource_type: Access key
File: /tmp/th_fixtures/aws_overlap.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: AKIAZ24FK7QW8XV5N3PB:P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ
Name: aws-overlap-shadow
File: /tmp/th_fixtures/aws_overlap.txt
Line: 1
```

**Answer.** The warning appears whenever **two or more detectors match the same (or near-identical) value** in a chunk. TruffleHog suppresses verification to avoid sending one secret to multiple providers' endpoints. Override with `--allow-verification-overlap`.

---

### Q5 — Where exactly is the boundary between "caught" and "slips through," and why?

A credential is reported only if it clears **every** gate below, in order. Each row cites the code that enforces it.

| # | Gate | Enforced at | Slips through if… |
|---|------|-------------|-------------------|
| 1 | Keyword `AKIA`/`ABIA`/`ACCA` present | `accesskey.go:70-76` | no keyword in the (decoded) chunk |
| 2 | ID + secret within one ±1024-byte span | `multi_part_credential_provider.go:8`; `ahocorasickcore.go:88` (vs default `:155`) | secret is > 1024 bytes from the keyword |
| 3 | `idPat` and `SecretPat` both match | `accesskey.go:65`; `common.go:10` | value doesn't match the regex shape |
| 4 | ID entropy ≥ 3.0 **and** secret entropy ≥ 4.25 | `accesskey.go:122,132`; `common.go:6-7` | either entropy is below threshold (**dropped pre-result**) |
| 5 | (unverified) secret not hex `[a-f0-9]{40}` | `accesskey.go:202`; `utils.go:47` | unverified secret looks like a 40-char hex hash |
| 6 | value not a known false positive | `falsepositives.go:17-18,97`; engine `:1141-1142` | value contains `example`/`sample`/`xxxxxx`/… (**recoverable** via `--results=filtered_unverified`) |
| 7 | value not a cross-detector overlap duplicate | `engine.go:796,887,988` | 2+ detectors match same value → verification disabled (still reported) |

The regexes themselves define the "correct format":

```
idPat     (accesskey.go:65):  \b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b
SecretPat (common.go:10):     (?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)
```

**The critical distinction:** gate 4 (entropy) is **detector-internal** and drops candidates **before** a result object is created, so `--results=filtered_unverified` **cannot** recover them. Gate 6 (known-false-positive) is **engine-level** and runs **after** the result exists, so `--results=filtered_unverified` **can** recover it. This asymmetry is why an `example` key can be brought back but a low-entropy key cannot (see Q3 vs. Q7).

---

### Q6 — Actual scan output: detected vs. missed/filtered

**Detected** — `entropy_above.txt` (`--no-verification`):

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ24FK7QW8XV5N3PB
Resource_type: Access key
File: /tmp/th_fixtures/entropy_above.txt
Line: 2
```

**Missed / filtered** — the `example` key (`example_fixture.txt`) by default prints nothing to stdout; the verbatim stderr summary line reports zero findings (timestamp and `scan_duration` vary per run):

```
2026-07-01T06:26:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.055558ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Derived summary** (not raw CLI output) — findings tally across the fixture set, aggregated from each scan's `unverified_secrets` count (all `--no-verification`; `+filtered` = also with `--results=filtered_unverified`). Verbatim per-fixture summary lines for the highlighted cases (proximity in Q1, the `example` key in Q3/Q6, and the entropy boundary in Q7) appear in those sections:

| Fixture | ID / secret | Findings | +filtered |
|---------|-------------|----------|-----------|
| `entropy_above.txt` | `AKIAZ24FK7QW8XV5N3PB` / secret H=4.2939 | **1** | 1 |
| `entropy_below.txt` | same ID / secret H=4.2342 | **0** | **0** (pre-result) |
| `example_fixture.txt` | `AKIAIOSFODNN7EXAMPLE` / `wJalr…EXAMPLEKEY` | **0** | **1** (recovered) |
| `lowid.txt` | `AKIAAAAAAAAAAAAAAAAA` (H=0.5690) | **0** | **0** (pre-result) |
| `hexsecret.txt` | secret `da39a3ee…afd80709` (H=3.7373) | **0** | **0** |
| `alla.txt` | secret 40×`a` (H=0.0) | **0** | — |
| `proximity_close.txt` | gap ~24 B | **1** | — |
| `proximity_far.txt` | gap 2805 B > 1024 | **0** | **0** |

---

### Q7 — What happens right at the entropy threshold?

**Mechanism.** The secret gate is `pkg/detectors/aws/access_keys/accesskey.go:132`:

```go
if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
    continue
}
```

with `RequiredSecretEntropy = 4.25` (`pkg/detectors/aws/common.go:7`) and the ID gate `RequiredIdEntropy = 3.0` (`:6`, enforced at `accesskey.go:122`). `StringShannonEntropy` is standard per-rune Shannon entropy in bits — `pkg/detectors/falsepositives.go:136-151`:

```go
func StringShannonEntropy(input string) float64 {
    ...
    for _, count := range chars {
        probability := count * inverseTotal
        entropy += probability * math.Log2(probability)
    }
    return -entropy
}
```

**Observed at the boundary.** Two fixtures share the same passing ID (`AKIAZ24FK7QW8XV5N3PB`, H=4.1219 ≥ 3.0) and differ only in the secret's entropy, straddling 4.25. The blocks below are verbatim stderr summary lines (timestamp and `scan_duration` vary per run). Below-threshold secret `fJAFNsa03DDFF0fGDdG66qFBJ3D5maa2mNBqMEBc` (H=4.2342 < 4.25) → **no** finding:

```
2026-07-01T06:26:17Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.260464ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Above-threshold secret `P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ` (H=4.2939 ≥ 4.25) → **one** finding:

```
2026-07-01T06:26:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.984313ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

And critically, the below-threshold case stays at `unverified_secrets: 0` **even with `--results=filtered_unverified`**:

```
2026-07-01T06:26:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.901932ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

because the entropy gate is detector-internal (pre-result). Contrast the low-entropy **ID** case `lowid.txt` (`AKIAAAAAAAAAAAAAAAAA`, H=0.5690 < 3.0): 0 findings, and still 0 with `--results=filtered_unverified` — the ID gate also drops it before a result exists.

**Reference entropy values** (computed with TruffleHog's exact formula):

| Value | Length | Shannon entropy | Gate |
|-------|--------|-----------------|------|
| `AKIAIOSFODNN7EXAMPLE` | 20 | 3.6842 | ID ≥ 3.0 ✓ |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | 40 | 4.6628 | secret ≥ 4.25 ✓ |
| `AKIAZ24FK7QW8XV5N3PB` | 20 | 4.1219 | ID ≥ 3.0 ✓ |
| `P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ` | 40 | 4.2939 | secret ≥ 4.25 ✓ |
| `fJAFNsa03DDFF0fGDdG66qFBJ3D5maa2mNBqMEBc` | 40 | 4.2342 | secret < 4.25 ✗ |
| `AKIAAAAAAAAAAAAAAAAA` | 20 | 0.5690 | ID < 3.0 ✗ |
| `da39a3ee5e6b4b0d3255bfef95601890afd80709` | 40 | 3.7373 | secret < 4.25 ✗ (also hex FP) |
| 40 × `a` | 40 | 0.0000 | secret < 4.25 ✗ |

> Note the `example` key *passes* both entropy gates (ID 3.6842 ≥ 3.0, secret 4.6628 ≥ 4.25); it is dropped only by the "contains `example`" rule (Q3) — which is why retaining false positives brings it back, while a sub-entropy secret cannot be recovered.

**Answer.** The 4.25 secret-entropy threshold is a hard cutoff: 4.2342 → nothing, 4.2939 → a finding. Because the entropy check happens inside the detector before a result exists, `--results=filtered_unverified` cannot recover sub-threshold values (unlike the `example` false-positive case).

---

## 3. Consolidated boundaries — caught vs. slips through, and why

| Situation | Result | Root cause (`file:line`) | Recoverable with `--results=filtered_unverified`? |
|-----------|--------|--------------------------|--------------------------------------------------|
| ID + secret adjacent, high entropy | **Caught** | passes all gates | n/a |
| Secret > 1024 B from `AKIA` keyword | Slips | window `multi_part_credential_provider.go:8`; `ahocorasickcore.go:88` | No (never produced) |
| No `AKIA`/`ABIA`/`ACCA` keyword | Slips | prefilter `accesskey.go:70-76` | No |
| Base64-encoded (ASCII, run ≥ 20) | **Caught** (`Decoder Type: BASE64`) | `decoders.go:11-14`; `base64.go:36-46` | n/a |
| Secret entropy < 4.25 | Slips | gate `accesskey.go:132`; `common.go:7` | **No** (detector-internal, pre-result) |
| ID entropy < 3.0 | Slips | gate `accesskey.go:122`; `common.go:6` | **No** (pre-result) |
| Unverified secret is hex `[a-f0-9]{40}` | Slips | `accesskey.go:202`; `utils.go:47` | No |
| Value contains `example`/`sample`/… | Slips (filtered) | `falsepositives.go:17-18,97`; engine `:1141-1142` | **Yes** (engine-level) |
| Same value found by 2+ detectors | Caught, but **verification disabled** | `engine.go:796,887,988` | n/a (still reported) |

---

## 4. Reproduction appendix

**Build** (Go toolchain `go1.24.2`, per `go.mod`):

```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog .
```

**Fixtures** (created under `/tmp/th_fixtures`, *outside* the repository; deleted afterward). INI-style fixtures put the ID on line 2:

```
# entropy_above.txt / entropy_below.txt / example_fixture.txt
[default]
aws_access_key_id = <ID>
aws_secret_access_key = <SECRET>
```

| File | ID | Secret |
|------|----|--------|
| `entropy_above.txt` | `AKIAZ24FK7QW8XV5N3PB` | `P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ` (H=4.2939) |
| `entropy_below.txt` | `AKIAZ24FK7QW8XV5N3PB` | `fJAFNsa03DDFF0fGDdG66qFBJ3D5maa2mNBqMEBc` (H=4.2342) |
| `example_fixture.txt` | `AKIAIOSFODNN7EXAMPLE` | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| `lowid.txt` | `AKIAAAAAAAAAAAAAAAAA` | `P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ` |
| `hexsecret.txt` | `AKIAZ24FK7QW8XV5N3PB` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `alla.txt` | `AKIAZ24FK7QW8XV5N3PB` | 40 × `a` |
| `proximity_close.txt` | `AKIAZ24FK7QW8XV5N3PB` | secret ~24 B later |
| `proximity_far.txt` | `AKIAZ24FK7QW8XV5N3PB` (byte 0) | secret ~2825 B later (gap 2805 > 1024) |
| `encoded_b64.txt` | base64 of `aws_access_key_id=AKIAZ24FK7QW8XV5N3PB\naws_secret_access_key=P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ` | — |

`encoded_b64.txt` payload (single line, no plaintext `AKIA`):

```
YXdzX2FjY2Vzc19rZXlfaWQ9QUtJQVoyNEZLN1FXOFhWNU4zUEIKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5PVAwVFR2WXZ1dVFEZVYyMkhWRFh1NVhsMFljTVp2TXh2dnBDZUNWTlEK
```

Custom "shadow" detector for the overlap demo, `aws_overlap.yaml`:

```yaml
detectors:
  - name: aws-overlap-shadow
    keywords:
      - AKIA
    regex:
      pair: '([A-Z0-9]{20}:[A-Za-z0-9]{40})'
```

with `aws_overlap.txt`:

```
credentials: AKIAZ24FK7QW8XV5N3PB:P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ
```

**Scan commands used** (detection demonstrated offline with `--no-verification`; overlap demonstrated with a custom detector, so no claim depends on live AWS STS):

```bash
/tmp/trufflehog filesystem /tmp/th_fixtures/entropy_above.txt  --no-update --no-verification
/tmp/trufflehog filesystem /tmp/th_fixtures/example_fixture.txt --no-update --no-verification
/tmp/trufflehog filesystem /tmp/th_fixtures/example_fixture.txt --no-update --no-verification --results=filtered_unverified
/tmp/trufflehog filesystem /tmp/th_fixtures/encoded_b64.txt    --no-update --no-verification
/tmp/trufflehog filesystem /tmp/th_fixtures/aws_overlap.txt    --no-update --config=/tmp/th_fixtures/aws_overlap.yaml --no-verification
/tmp/trufflehog filesystem /tmp/th_fixtures/aws_overlap.txt    --no-update --config=/tmp/th_fixtures/aws_overlap.yaml --no-verification --allow-verification-overlap
```

Relevant CLI flags — `main.go`: `--no-verification` (:59), `--results` (:61, "Defaults to verified,unverified,unknown."), `--allow-verification-overlap` (:65), `--filter-entropy` (:67, "Start with 3.0.").

**External corroboration (code remains the source of truth).** AWS's own documentation confirms both the example pair and the prefix format used above:

- **Example pair** — access-key ID `AKIAIOSFODNN7EXAMPLE`, secret `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — appears in the AWS IAM User Guide, *"Manage access keys for IAM users"* (`https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html`) and in the *AWS SDKs and Tools Reference*, *"AWS access keys"* (`https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html`).
- **Prefix format** — access-key IDs beginning with `AKIA` are long-term credentials and those beginning with `ASIA` are temporary (AWS STS) credentials — is documented in the *AWS STS API Reference*, *"GetAccessKeyInfo"* (`https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html`) and the AWS IAM User Guide, *"Secure access keys"* (`https://docs.aws.amazon.com/IAM/latest/UserGuide/securing_access-keys.html`).

Both are consistent with the detector's `idPat` (`(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}`, a 20-character ID) and its 40-character `SecretPat`. (These references corroborate the code; the repository source remains the authoritative source of truth for TruffleHog's behavior.)

**Cleanup.** All fixtures, helper scripts, and the binary live outside the repository (`/tmp/…`) and are removed after investigation; `git status --porcelain` remains empty aside from this document.
