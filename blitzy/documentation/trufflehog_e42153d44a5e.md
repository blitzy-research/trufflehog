# TruffleHog Scanning Behavior: Five Questions, Answered From the Running Code

This document answers five recurring questions from a security engineer who is
evaluating TruffleHog v3 for a scanning pipeline and has observed behavior that
looked confusing or inconsistent:

1. Why are valid AWS credentials **detected in some files but completely missed or reported differently in others** — and why is the outcome consistent?
2. Does **encoding** sensitive data before committing "add a layer of protection" against the scanner?
3. Why do some credentials in **test fixtures never get flagged even though they follow the right format**?
4. What triggers the CI warning about **"verification disabled for safety"** on certain findings?
5. **Where are the boundaries** — what gets caught versus what slips through, and what happens *right at* a threshold?

Every answer below is written **from what the scanner actually did**, not from
reading the source alone. For each behavioral claim you will find: the exact
command that was run, the verbatim output line it produced, and the exact source
literal (`file:line`) that governs the behavior.

---

## Methodology & Environment

**Run-first.** The scanner was built and executed before any conclusion was
written. Each claim is paired with **one captured output line** and **one source
literal**.

**Build.** TruffleHog was compiled from the checked-out commit with the Go
toolchain declared by the module (`go.mod` declares `go 1.23.1` with
`toolchain go1.24.2`):

```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog .
```

The build exits `0` and produces a working binary that reports version `dev`:

```
$ /tmp/trufflehog --version
trufflehog dev
```

(The binary observed here is `194,308,770` bytes; the exact byte count is not
meaningful — it is a build artifact.)

**Probe files.** All probe fixtures live **outside the repository** under
`/tmp/th_probe/`, and every scan targets a single small file so results are
isolated. All temporary artifacts are deleted at the end (see *Cleanup &
Verification*); the source repository is left unmodified.

**Safety: every credential shown is a crafted, non-live test value.** All AWS
access-key IDs, AWS secret keys, and Postman (`PMAK-…`) tokens in this document
were **fabricated** solely to exercise TruffleHog's *format* gates (prefix,
length, entropy) — none is a real, active, or provisioned credential, and none
grants access to any account. For that reason nearly every scan is run with
`--no-verification` (part of COMMON, below), so no candidate is ever sent to a
provider API. The **only** exception is the Q4 verification-overlap demonstration,
which *intentionally* leaves verification enabled (it omits `--no-verification`)
because the behavior being explained — the overlap safety guard — exists on the
verification path; even there the tokens are crafted and, being non-live, simply
fail verification.

**Common flags.** Unless a run explicitly needs the default output set, scans use
this flag set, referred to below as **COMMON**:

```
--no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
```

Where a run must use the **DEFAULT** `--results`, the `--results` flag is omitted
entirely — the default is `verified,unverified,unknown`
(`main.go:61`: `"...Defaults to verified,unverified,unknown."`).

**Result states** (`main.go:61`, `main.go:985`):

- `verified` — confirmed valid by the provider's API.
- `unverified` — detected, but verification was not performed.
- `unknown` — verification was attempted but errored.
- `filtered_unverified` — an unverified result that *would have been filtered out*, retained for inspection. Requesting this state has an important side effect used throughout this document (see Q3).

**A note on volatile output.** Lines such as timestamps, `source_manager_worker_id`,
`scan_duration`, and `VerificationTimeSpentMS` change from run to run. They are
reproduced as observed; only the non-volatile content (raw results, detector/decoder
types, secret counts, warning text) carries meaning.

---

## The End-to-End Decision Flow

Almost every behavior in this document is explained by a single ordered pipeline.
A candidate secret must pass **every** gate below, in order, to be reported:

```mermaid
flowchart TD
    A[Raw chunk] --> B[Decoder chain: UTF8, Base64, UTF16, EscapedUnicode]
    B --> C{Keyword present? AKIA / ABIA / ACCA}
    C -- No --> X[Discarded: detector never runs — Q1 miss / Q2 no-decoder]
    C -- Yes --> D{idPat and SecretPat exact regex match?}
    D -- No --> X2[No result — e.g. 39-char secret, Q1/Q5 boundary]
    D -- Yes --> E{Entropy >= 3.0 id and 4.25 secret?}
    E -- No --> X3[Skipped — Q5 boundary]
    E -- Yes --> F{Known false positive? wordlist / DefaultFalsePositives / trufflehog:ignore}
    F -- Yes --> X4[Filtered — Q3 test fixtures]
    F -- No --> G{Same secret matched by more than one detector?}
    G -- Yes --> H[SetVerificationError errOverlap — Q4 'verification disabled for safety']
    G -- No --> I[Reported result: verified / unverified / unknown]
```

Node-by-node:

- **A → B — Decoding.** Each raw chunk is passed through an ordered decoder chain; every decoded variant is scanned. *(Q2)*
- **C — Keyword prefilter.** A detector only runs if one of its literal keywords appears in the chunk. This is the outermost hard gate. *(Q1, Q5)*
- **D — Exact regex.** The AWS access-key ID and secret must match precise regexes, including an **exactly-40-character** secret. *(Q1, Q5)*
- **E — Entropy floors.** The ID must reach Shannon entropy `3.0` and the secret `4.25`. *(Q1, Q5)*
- **F — False-positive filtering.** Placeholder/dictionary values and `trufflehog:ignore` lines are removed after detection. *(Q3)*
- **G → H — Verification overlap.** If more than one detector claims the same value, verification is disabled for safety and the finding carries a warning. *(Q4)*
- **I — Report.** Surviving results are printed with their verification state.

---

## Q1 — Deterministic "detected vs. missed / reported differently" for AWS credentials

> **"When I scan certain files, valid AWS credentials get detected perfectly, but
> in other files with what appear to be the same credentials, they're completely
> missed or reported differently."** … **"I initially thought it might be random,
> but it seems consistent, the same file always produces the same result."**

Detection is not random. An AWS access key must clear **three deterministic
gates**, each a pure function of the input bytes. If any gate fails, the key is
"missed"; the *reason* for the miss depends on which gate stopped it.

### The three gates

**(a) The Aho-Corasick keyword prefilter — the outermost hard gate.**
A detector never runs unless one of its literal keywords is present in the chunk.
The AWS detector's keywords are `AKIA`, `ABIA`, `ACCA`:

```go
// pkg/detectors/aws/access_keys/accesskey.go:70
func (s scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
	}
}
```

Those keywords are compiled into an Aho-Corasick trie
(`pkg/engine/ahocorasick/ahocorasickcore.go:127` `prefilter ahocorasick.Trie`;
built at `:159` via `ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()`),
and the engine only dispatches a chunk to detectors whose keywords match
(`pkg/engine/engine.go:795` `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)`).

**Normalization before the regexes.** Once the prefilter dispatches the chunk to
the AWS detector, the very first thing `FromData` does — *before* `idPat`/`SecretPat`
are applied — is URL-decode the chunk text, so a credential whose base64 `+` / `/`
/ `=` characters were percent-encoded (for example because it was copied out of a
URL or a URL-encoded config value) is still normalized into the exact bytes the
regexes expect:

```go
// pkg/detectors/aws/access_keys/accesskey.go:108
dataStr = aws.UrlEncodedReplacer.Replace(dataStr)
```

`UrlEncodedReplacer` is a `strings.Replacer` (`pkg/detectors/aws/utils.go:35`) that
rewrites `%2B`/`%2b` → `+`, `%2F`/`%2f` → `/`, and `%3d`/`%3D` → `=`:

```go
// pkg/detectors/aws/utils.go:35
var UrlEncodedReplacer = strings.NewReplacer(
	"%2B", "+",
	"%2b", "+",
	"%2F", "/",
	"%2f", "/",
	"%3d", "=",
	"%3D", "=",
)
```

This is one concrete way "the same credential" can be **reported differently** or
**missed** between files: a percent-encoded secret is normalized into a match here,
while any other transform the replacer does not cover (see Q2's "no decoder"
boundary) is left untouched and never reaches the regexes.

**(b) Exact regex matching.** If the prefilter passes, two regexes must match
(against the URL-normalized `dataStr` above).
The access-key ID must match `idPat`:

```go
// pkg/detectors/aws/access_keys/accesskey.go:65
idPat = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b`)
```

and the secret must match `SecretPat` — **exactly 40** base64 characters,
bounded by non-base64 characters:

```go
// pkg/detectors/aws/common.go:10
var SecretPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)`)
```

**(c) Shannon-entropy floors.** Surviving matches must clear entropy floors,
enforced inside the detector's `FromData`:

```go
// pkg/detectors/aws/access_keys/accesskey.go:122
if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy {
	continue
}
// pkg/detectors/aws/access_keys/accesskey.go:132
if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
	continue
}
```

with the floors defined as:

```go
// pkg/detectors/aws/common.go:6
RequiredIdEntropy     = 3.0
// pkg/detectors/aws/common.go:7
RequiredSecretEntropy = 4.25
```

### Detected vs. missed — the exact same secret, one changed byte

Two probe files, identical except for the **first letter of the access-key ID**.
`q1_detected.txt` uses a well-formed ID (`AKIA…`); `q1_missed_nokeyword.txt`
changes it to `BKIA…`, so **no** keyword (`AKIA`/`ABIA`/`ACCA`) is present. The
secret is byte-for-byte identical in both files.

`q1_detected.txt`:

```
[default]
aws_access_key_id = AKIAZ7Q3RB5XW2YT9NKD
aws_secret_access_key = wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5u
```

`q1_missed_nokeyword.txt`:

```
[default]
aws_access_key_id = BKIAZ7Q3RB5XW2YT9NKD
aws_secret_access_key = wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5u
```

**DETECTED** — command and verbatim output:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q1_detected.txt \
    --no-verification --no-update --no-color \
    --results=verified,unverified,unknown,filtered_unverified

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q1_detected.txt
Line: 2
```

…and the metrics line reports one finding:

```
2026-07-01T23:06:24Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.008048ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**MISSED** — same command against the `BKIA…` file. There is **no `Found` line at
all**, and the metrics report zero findings:

```
2026-07-01T23:06:26Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.610619ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Why.** The ID begins with `B`, so none of the keywords `AKIA`/`ABIA`/`ACCA`
appear in the chunk. The Aho-Corasick prefilter therefore never routes the chunk
to the AWS detector, and the regex/entropy gates never even run. This is the
"completely missed" case — a single byte outside the keyword set is enough. (Q5
demonstrates the other two gates producing misses of their own.)

### Why it is deterministic

The prefilter, the two regexes, and the entropy checks are **pure functions of the
chunk bytes** — there is no randomness anywhere in the detection path. The entropy
function simply counts runes and sums probabilities:

```go
// pkg/detectors/falsepositives.go:136
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

Running the detected file **three times** yields byte-identical results — only the
volatile timestamp and `scan_duration` differ (every `Raw result`,
`unverified_secrets` count, and `verification_caching` block is identical):

```bash
for i in 1 2 3; do echo "--- run $i ---"; /tmp/trufflehog filesystem /tmp/th_probe/q1_detected.txt \
  --no-verification --no-update --no-color \
  --results=verified,unverified,unknown,filtered_unverified 2>&1 \
  | grep -E "Raw result|finished scanning"; done
```

```
--- run 1 ---
Raw result: AKIAZ7Q3RB5XW2YT9NKD
2026-07-01T23:06:53Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.646301ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
--- run 2 ---
Raw result: AKIAZ7Q3RB5XW2YT9NKD
2026-07-01T23:06:55Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.677163ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
--- run 3 ---
Raw result: AKIAZ7Q3RB5XW2YT9NKD
2026-07-01T23:06:56Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.036823ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

That is exactly the "same file always produces the same result" behavior observed:
identical inputs → identical detection outcome.

### Entropy context for the detected pair

Using an exact replica of `StringShannonEntropy` (`pkg/detectors/falsepositives.go:136`),
the detected file's values clear both floors:

| Value | Shannon entropy | Floor | Passes? |
|-------|-----------------|-------|---------|
| `AKIAZ7Q3RB5XW2YT9NKD` (ID) | `4.1219` | `3.0` (`common.go:6`) | ✅ |
| `wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5u` (secret) | `5.1719` | `4.25` (`common.go:7`) | ✅ |

### "Reported differently"

The same secret can also surface under a **different `Decoder Type`**. In the
output above the `Decoder Type` is `PLAIN`; when the same key is base64- or
UTF-16-encoded it is reported under `BASE64` or `UTF16` instead (see Q2). That is
one concrete way "the same credential" is "reported differently" between files.

---

## Q2 — Does encoding "add a layer of protection"?

> **"Some of our developers encode sensitive data before committing (thinking it
> adds a layer of protection), and I'm wondering if that's somehow fooling the
> scanner."**

**Short answer: no — not for any encoding TruffleHog has a decoder for.** Before
detection runs, every chunk is passed through a fixed, ordered decoder chain, and
**each decoded variant is scanned independently**. Encoding only hides a secret if
the scanner has *no* decoder for that encoding.

### The decoder chain

```go
// pkg/decoders/decoders.go:8
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

Each decoder advertises a type, which is what appears on the `Decoder Type:` line
of a finding (`pkg/output/plain.go:64` `printer.Printf("Decoder Type: %s\n", out.DecoderType)`):

| Decoder | Type constant | `file:line` |
|---------|---------------|-------------|
| UTF8 (baseline / plaintext) | `DecoderType_PLAIN` | `pkg/decoders/utf8.go:13` |
| Base64 | `DecoderType_BASE64` | `pkg/decoders/base64.go:31` |
| UTF-16 | `DecoderType_UTF16` | `pkg/decoders/utf16.go:15` |
| Escaped unicode (`\uXXXX`) | `DecoderType_ESCAPED_UNICODE` | `pkg/decoders/escaped_unicode.go:29` |

The engine applies the chain in a **single pass** over each chunk — every decoder
is called on the chunk, and any decoder that does not understand the chunk returns
`nil` and is skipped:

```go
// pkg/engine/engine.go:784
for _, decoder := range e.decoders {
	decoded := decoder.FromChunk(chunk)
	...
	if decoded == nil {
		// This means that the decoder didn't understand this chunk and isn't applicable to it.
		continue
	}
	matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
	...
}
```

### The same key, four encodings, same result

Each probe encodes the **same** AWS key from Q1. Every one surfaces the identical
`Raw result` under a different `Decoder Type` — encoding did not hide anything.

**PLAIN** (baseline, `q2_plain_reference.txt`):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_plain_reference.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q2_plain_reference.txt
Line: 2

2026-07-01T23:07:04Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.404617ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**BASE64** (`q2_base64.txt` — the whole credentials blob base64-encoded):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_base64.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q2_base64.txt
Line: 2

2026-07-01T23:07:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 117, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.066281ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

> **Reproducibility note.** `q2_base64.txt` is the base64 of the plaintext blob
> encoded **without line wrapping** (Python's `base64.b64encode`, equivalent to
> `base64 -w0`). Default GNU `base64` wraps at 76 columns; the inserted newline
> (`0x0A`) would split the encoding across lines and prevent the Base64 decoder
> from recovering the key — so the single-line, no-wrap form is what produced the
> `Decoder Type: BASE64` result above.

**UTF16** (`q2_utf16.txt` — see the layout nuance below):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_utf16.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: UTF16
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q2_utf16.txt
Line: 1

2026-07-01T23:07:07Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.635018ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**ESCAPED_UNICODE** (`q2_escaped_unicode.txt` — the ID and secret written as
`\u0041\u004b\u0049\u0041…` escapes):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_escaped_unicode.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: ESCAPED_UNICODE
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q2_escaped_unicode.txt
Line: 1

2026-07-01T23:07:12Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 406, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.375624ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Conclusion:** base64, UTF-16, and `\u`-escaped encodings do **not** protect the
secret. TruffleHog decodes each and re-scans, surfacing the identical
`Raw result: AKIAZ7Q3RB5XW2YT9NKD` under a different `Decoder Type`.

### Honest nuances (reported exactly as observed)

The decoder layer has two edge behaviors worth showing, because both produce a
**miss** and both are instructive about *how* decoding works.

**1) UTF-16 layout and word boundaries.** The UTF-16 decoder only keeps bytes that
pass `isPrintableByte`:

```go
// pkg/decoders/utf8.go:85
func isPrintableByte(c byte) bool { return c > 31 && c < 127 }
```

Because a newline (`0x0A`) is `< 32`, it is **dropped** during UTF-16 decoding
(`pkg/decoders/utf16.go:36` `utf16ToUTF8`). A first attempt using a **multi-line**
INI file encoded as UTF-16LE was therefore **missed**:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_utf16_multiline.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:07:09Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 113, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.150725ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

After newline-stripping, the access-key ID ran directly into the next token
(`…YT9NKDaws_secret_access_key…`), so the trailing `\b` word boundary in `idPat`
(`accesskey.go:65`) failed. Switching to a **space-separated single line** (spaces
are `0x20`, which survive `isPrintableByte`) restored a valid word boundary — that
is the `q2_utf16.txt` file that produced the `Decoder Type: UTF16` success above
(`"unverified_secrets": 1`). Same secret, same encoding; only the whitespace
layout changed the outcome.

**2) A UTF-16 BOM defeats the UTF-16 decoder here.** Prepending a UTF-16LE byte-
order mark (`0xFF 0xFE`) to the exact content that succeeded above causes a
**miss**:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q2_utf16_bom.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:07:11Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 432, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.288721ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The reason is ordering plus a shared buffer. `UTF8` runs **first**
(`decoders.go:11`) on a shared `*sources.Chunk`. The BOM makes the bytes invalid
UTF-8, so `UTF8.FromChunk` rewrites the chunk **in place**:

```go
// pkg/decoders/utf8.go:23
if !utf8.Valid(chunk.Data) {
	chunk.Data = extractSubstrings(chunk.Data)
	return decodableChunk
}
```

`extractSubstrings` (`pkg/decoders/utf8.go:45`) replaces every non-printable byte —
including the interleaved `NUL` (`0x00`) bytes that the UTF-16 decoder relies on,
and the `0xFF/0xFE` BOM — with the Unicode replacement character `U+FFFD`. By the
time `UTF16.FromChunk` (`pkg/decoders/utf16.go:18`) runs on the same, now-mangled
buffer, its high-byte-zero condition (`utf16.go:36-51`) no longer holds and it
cannot recover the key.

### "No decoder = slips through"

This is the honest boundary of Q2. The decoder chain is exactly
`[UTF8, Base64, UTF16, EscapedUnicode]` and nothing more. An encoding for which
**no decoder exists** — a custom/proprietary transform, ROT13, or any format not
in that list — would never be decoded, so the underlying secret would not be
scanned and could evade detection. Encoding a secret in a format the scanner
*knows* is not protection; encoding it in a format the scanner does *not* know is
the only case where encoding actually hides it.

> **Note on iterative decoding / `--max-decode-depth`.** Some external
> documentation and newer TruffleHog releases describe a `--max-decode-depth` flag
> that re-feeds each decoder's output back through all decoders. **That flag does
> not exist at this revision.** A search of the entire tree for
> `max-decode-depth` / `DecodeDepth` returns nothing, and decoding here is the
> single pass shown at `pkg/engine/engine.go:784` (the only `*-max-depth` flag
> present is `--archive-max-depth` at `main.go:79`, which governs archive
> extraction, not decoding). So at this commit, a secret that requires *two*
> layers of decoding (e.g. base64-of-base64) is not surfaced by the default chain.


---

## Q3 — Why some test-fixture credentials "never get flagged even though they follow the right format"

> **"explain why some credentials in our test fixtures never get flagged even
> though they follow the right format."**

These fixtures *do* follow the right format — they pass the keyword prefilter,
`idPat`/`SecretPat`, and the AWS entropy floors. They are removed **after
detection** by a false-positive filtering layer, or suppressed inline. There are
several distinct mechanisms; each is named and demonstrated below.

### The false-positive filtering layer

After a detector produces results, the engine (by default) removes known false
positives:

```go
// pkg/engine/engine.go:1141
if !e.retainFalsePositives {
	results = detectors.FilterKnownFalsePositives(ctx, detector.Detector, results)
}
// pkg/engine/engine.go:1145 (the opt-in global entropy filter — see Q5)
if e.filterEntropy != 0 {
	results = detectors.FilterResultsWithEntropy(ctx, results, e.filterEntropy, e.retainFalsePositives)
}
```

`FilterKnownFalsePositives` (`pkg/detectors/falsepositives.go:177`) uses
`GetFalsePositiveCheck` (`:70`). The AWS detector defines no custom false-positive
checker, so it falls back to `IsKnownFalsePositive` on the raw match — which for
AWS is the `AKIA…` ID:

```go
// pkg/detectors/falsepositives.go:77
return IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)
```

**The `DefaultFalsePositives` set — all 7 values:**

```go
// pkg/detectors/falsepositives.go:17
DefaultFalsePositives = map[FalsePositive]struct{}{
	"example": {}, "xxxxxx": {}, "aaaaaa": {}, "abcde": {}, "00000": {}, "sample": {}, "*****": {},
}
```

**The four embedded wordlists**, consulted by `IsKnownFalsePositive`
(`pkg/detectors/falsepositives.go:85`):

```go
// pkg/detectors/falsepositives.go:35
//go:embed "fp_badlist.txt"
// pkg/detectors/falsepositives.go:37
//go:embed "fp_words.txt"
// pkg/detectors/falsepositives.go:39
//go:embed "fp_programmingbooks.txt"
// pkg/detectors/falsepositives.go:41
//go:embed "fp_uuids.txt"
```

`IsKnownFalsePositive` lowercases the match and checks, in order: an exact map hit
(`:92` `"matches term: "`), a substring `strings.Contains` (`:98`
`"contains term: "`), then an Aho-Corasick match against the embedded wordlists
(`:104` `"matches wordlist: "`).

### Demonstration 1 — a value that *contains* `example`

`q3_example.txt` uses the canonical AWS documentation example. Its ID
`AKIAIOSFODNN7EXAMPLE` (entropy `3.6842` ≥ `3.0`) and secret
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (entropy `4.6628` ≥ `4.25`, exactly 40
chars — the `/` is allowed by `SecretPat`'s `[A-Za-z0-9+/]{40}`) pass every
detection gate:

```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

With the **DEFAULT** result set (no `--results` flag) it is **filtered — zero
findings**:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q3_example.txt --no-verification --no-update --no-color
2026-07-01T23:08:09Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.044584ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The lowercased ID `akiaiosfodnn7example` **contains** `"example"`, which is in
`DefaultFalsePositives` (`falsepositives.go:18`), so `FilterKnownFalsePositives`
removes it.

**Proof that it passed every detection gate:** requesting `filtered_unverified`
(part of **COMMON**) makes the same key reappear:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q3_example.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLE
Resource_type: Access key
File: /tmp/th_probe/q3_example.txt
Line: 2

2026-07-01T23:08:11Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.873012ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The reason this works is a specific side effect: requesting `filtered_unverified`
sets `retainFalsePositives = true`, which **skips** `FilterKnownFalsePositives`:

```go
// pkg/engine/engine.go:317
if _, ok = results["filtered_unverified"]; ok {
	engine.retainFalsePositives = ok
}
```

So the fixture "follows the right format" (visible under `filtered_unverified`) but
is dropped by the false-positive layer under the default result set.

### Demonstration 2 — a value that matches an embedded wordlist

`q3_wordlist.txt` uses ID `AKIACONFIG1234567890` (entropy `4.1219` ≥ `3.0`). The
term `config` is present in the embedded badlist:

```
$ sed -n '6p' pkg/detectors/fp_badlist.txt
config
```

With the **DEFAULT** result set it is **filtered**:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q3_wordlist.txt --no-verification --no-update --no-color
2026-07-01T23:08:13Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.066672ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

and with **COMMON** (`filtered_unverified`) it reappears — again proving it passed
every detection gate:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q3_wordlist.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIACONFIG1234567890
Resource_type: Access key
File: /tmp/th_probe/q3_wordlist.txt
Line: 2

2026-07-01T23:08:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.770598ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Here the removal comes from the embedded wordlist path
(`IsKnownFalsePositive` → `"matches wordlist: "`, `falsepositives.go:104`), not
from the `DefaultFalsePositives` map.

### Demonstration 3 — inline `trufflehog:ignore`

`q3_ignore.txt` carries a trailing `# trufflehog:ignore` on each secret-bearing
line:

```
[default]
aws_access_key_id = AKIAZ7Q3RB5XW2YT9NKD # trufflehog:ignore
aws_secret_access_key = wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5u # trufflehog:ignore
```

This key is the fully-valid, high-entropy Q1 key. Yet even with **COMMON**
(including `filtered_unverified`) it is **suppressed — zero findings**:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q3_ignore.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:08:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 156, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.433875ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

`trufflehog:ignore` suppresses the secret on its line. Note the contrast with
Demonstrations 1 and 2: `filtered_unverified` brings back false-positive-filtered
results, but it does **not** bring back a `trufflehog:ignore`-suppressed result —
these are different mechanisms.

**Where this lives in source.** The ignore tag is a single constant:

```go
// pkg/engine/engine.go:547
const ignoreTag = "trufflehog:ignore"
```

When the engine computes a result's line number in `FragmentLineOffset`, it checks
whether the text on that same line contains `ignoreTag`, and if so returns
`true` in its second return value (meaning "ignore this result"):

```go
// pkg/engine/engine.go:1262
// If the line contains the ignore tag, we should ignore the result.
endLine := bytes.Index(after, []byte("\n"))
if endLine == -1 {
	endLine = len(after)
}
// pkg/engine/engine.go:1267
if bytes.Contains(after[:endLine], []byte(ignoreTag)) {
	return lineNumber, true
}
```

That `true` becomes `ignoreLinePresent` back in the detection path, which triggers
an **early return** that drops the result **before it is ever reported** — which is
why `filtered_unverified` cannot bring it back (the result never enters the result
set in the first place):

```go
// pkg/engine/engine.go:1173
if ignoreLinePresent {
	return
}
```

This is a genuinely different mechanism from false-positive filtering: false
positives are produced and then removed (and `retainFalsePositives` can keep them),
whereas a `trufflehog:ignore` result is discarded at the source before filtering
runs at all.

### The always-on AWS entropy gate is *not* the same as the opt-in filter

Two entropy mechanisms exist and must not be conflated:

- The **AWS-internal** entropy gates (`accesskey.go:122` and `:132`) run
  **unconditionally** inside `FromData` — a low-entropy candidate never becomes a
  result at all.
- The **global, opt-in** `FilterResultsWithEntropy` (`falsepositives.go:154`,
  invoked at `engine.go:1146`) runs **only** when `--filter-entropy` is supplied,
  and logs `"Filtered out result with low entropy"` (`falsepositives.go:163`) for
  each result it removes.

Q5 demonstrates the always-on AWS gate producing a miss even when the global
filter is disabled.

### Summary

A test-fixture credential is not flagged (under the default result set) when its
`AKIA…` ID **matches or contains** a `DefaultFalsePositives` entry, **matches an
embedded wordlist** term, or the line carries `trufflehog:ignore`. All of these
act *after* the format checks succeed — which is exactly why the fixtures "follow
the right format" yet "never get flagged."


---

## Q4 — What triggers "verification disabled for safety"

> **"our CI logs sometimes show warnings about \"verification disabled for
> safety\" on certain findings. I have no idea what triggers that or why
> verification would be disabled."**

That warning is TruffleHog's **verification-overlap** guard. It fires when **more
than one detector matches the same result** in a chunk. The finding is **still
reported** (as unverified) — only its *verification* is disabled.

### The exact message

The warning text is the `errOverlap` error, built by concatenating two string
literals:

```go
// pkg/engine/engine.go:39
var errOverlap = errors.New(
	"More than one detector has found this result. For your safety, verification has been disabled." +
		"You can override this behavior by using the --allow-verification-overlap flag.",
)
```

Note the two literals are joined with **no space** after `disabled.` — the
rendered message is, verbatim:

```
More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
```

### How the overlap is detected

When a chunk matches more than one detector and overlap is not already allowed, it
is routed to a dedicated worker:

```go
// pkg/engine/engine.go:795
matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)
if len(matchingDetectors) > 1 && !e.verificationOverlap {
	...
}
```

The guard reads the engine's internal `verificationOverlap` field
(`pkg/engine/engine.go:180`), which is populated from the public config field:

```go
// pkg/engine/engine.go:139
// VerificationOverlap determines whether the scanner will attempt to verify candidate secrets
// that have been detected by multiple detectors.
// By default, it is set to true.
VerificationOverlap bool
```

Reported exactly as observed: although that comment says *"By default, it is set to
true,"* the CLI wires this field **directly from the `--allow-verification-overlap`
flag** (`main.go:528` `VerificationOverlap:      *allowVerificationOverlap`), and
that flag is a plain `Bool()` that defaults to `false` (`main.go:65`). So when the
CLI is run **without** the flag, `e.verificationOverlap` is `false`,
`!e.verificationOverlap` is `true`, and the overlap guard **fires by default** —
which is exactly the Q4-A behavior observed below. Passing
`--allow-verification-overlap` sets the field to `true` and disables the guard
(Q4-B).

Inside the overlap path, results from different detectors are compared with a
Levenshtein similarity check:

```go
// pkg/engine/engine.go:887
func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
	const similarityThreshold = 0.9
	...
	if similarity > similarityThreshold {
		...
	}
}
```

An exact match counts as a duplicate; otherwise the `strutil` similarity must
exceed `0.9` (`pkg/engine/engine.go:888`, `:914`). When the overlap worker
(`verificationOverlapWorker`, `pkg/engine/engine.go:924`) confirms the duplicate,
it attaches the error:

```go
// pkg/engine/engine.go:988
res.SetVerificationError(errOverlap)
```

`SetVerificationError` / `VerificationError()` live on the result type
(`pkg/detectors/detectors.go:126`, `:133`), and the plain printer renders the
error in **yellow**:

```go
// pkg/output/plain.go:20
yellowPrinter    = color.New(color.FgYellow)
// pkg/output/plain.go:57
yellowPrinter.Printf("Verification issue: %s\n", out.VerificationError)
```

### Reproducing it

To make two different detectors match the **same** token, we scan a Postman API
key with a small custom detector that also matches the `PMAK-…` pattern. The
built-in Postman detector uses keyword `PMAK-` and
`keyPat = \b(PMAK-[a-zA-Z-0-9]{59})\b` (`pkg/detectors/postman/postman.go:29`,
`:35`).

`q4_secret.txt`:

```
POSTMAN_API_KEY="PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r"
```

`q4_overlap_detectors.yaml`:

```yaml
detectors:
  - name: acme-internal-token
    keywords:
      - PMAK
    regex:
      token: 'PMAK-[a-zA-Z0-9]{59}'
```

**Q4-A — no override.** Both detectors match the identical token, so the overlap
guard fires:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q4_secret.txt \
    --config /tmp/th_probe/q4_overlap_detectors.yaml \
    --no-update --no-color \
    --results=verified,unverified,unknown,filtered_unverified

Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: /tmp/th_probe/q4_secret.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: acme-internal-token
File: /tmp/th_probe/q4_secret.txt
Line: 1
```

**Both** findings are reported (`"unverified_secrets": 2`) — the guard
suppresses *verification*, not the *finding*. The metrics line from this run:

```
2026-07-01T23:08:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.459454ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The stable, reproducible evidence that the overlap guard fired is the
`Verification issue:` warning line itself (grepped below), not the
`VerificationTimeSpentMS` value. That timer is **volatile** in the no-override
case: across five repeats of this exact command it was observed as
`0, 157, 0, 0, 138` — a low, non-deterministic value rather than a fixed `0`, so
it must **not** be relied on as proof. (The exact cause of the small non-zero
readings is not established here from the source; only the observed volatility is
reported.) A more stable signal in the metrics is `verification_caching` `"Misses"`,
which was `1` here with the guard active versus `2` with the override (one
fewer verification attempt because the overlapping result is not verified).

**Q4-B — with `--allow-verification-overlap`.** Adding the override (and leaving
verification enabled) removes the warning:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q4_secret.txt \
    --config /tmp/th_probe/q4_overlap_detectors.yaml \
    --allow-verification-overlap \
    --no-update --no-color \
    --results=verified,unverified,unknown,filtered_unverified

Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
Name: acme-internal-token
File: /tmp/th_probe/q4_secret.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: Postman
Decoder Type: PLAIN
Raw result: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
File: /tmp/th_probe/q4_secret.txt
Line: 1

2026-07-01T23:08:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "154.379292ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":150}}
```

With the override there is **no `Verification issue:` line**, and **both**
findings are still printed. (Detector order between the two `Found` blocks is
not guaranteed — here the CustomRegex result printed first and Postman second,
the reverse of the no-override run above; only the presence/absence of the
warning and the two findings is meaningful.)

The clearest reproducible evidence is a `grep` of the two captured outputs for
the warning line — present without the flag, absent with it:

```bash
$ grep -c 'For your safety, verification has been disabled' q4_A.out
$ grep -c 'For your safety, verification has been disabled' q4_B.out
```

```
1
0
```

and both runs report two findings either way:

```bash
$ grep -c 'Found unverified result' q4_A.out
$ grep -c 'Found unverified result' q4_B.out
```

```
2
2
```

The two metrics lines as captured (the `VerificationTimeSpentMS` and
`scan_duration` values are volatile — see below):

```
A (no override):          2026-07-01T23:08:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "5.459454ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
B (--allow-...-overlap):  2026-07-01T23:08:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 83, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "154.379292ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":150}}
```

The `VerificationTimeSpentMS` counter is **not** a reliable proof of "no
verification": in the no-override case it is volatile (`0, 157, 0, 0, 138`
across five runs) rather than a fixed `0`. What *is* stable is that the
override run performs strictly more verification work — `verification_caching`
`"Misses"` was `2` with the override versus `1` without it (the overlapping
result is verified only once the guard is lifted).

The override flag is defined at `main.go:65`:

```
--allow-verification-overlap   "Allow verification of similar credentials across detectors"
```

### Behavior across output formats (reported honestly)

The overlap error is surfaced differently depending on the output printer:

- **plain** — yellow `Verification issue:` line (`pkg/output/plain.go:57`), shown above.
- **json** (`--json`) — a `VerificationError` field, emitted `omitempty` (`pkg/output/json.go:45`, populated at `:25`/`:67`).
- **legacy JSON** (`--json-legacy`) — the `LegacyJSONOutput` struct (`pkg/output/legacy_json.go:229-238`) defines only `Branch`/`Commit`/`CommitHash`/`Date`/`Diff`/`Path`/`PrintDiff`/`Reason`/`StringsFound` and has **no** `VerificationError` field at all (a search of the whole file for `VerificationError` returns zero matches), so the overlap error text cannot appear in this format.
- **github-actions** (`--github-actions`) — renders `verifiedStatus` (`pkg/output/github_actions.go:47`) and a message (`:68`/`:70`), but not the overlap error text.

### Why verification is disabled (rationale)

When multiple detectors claim the same value, TruffleHog routes it to
`verificationOverlapWorker`, which runs detection with `verify=false` and attaches
`errOverlap`. The finding is still surfaced so you don't lose visibility — only
*verification* is suppressed. The safety rationale (this framing is from the
project's public discussion of the feature, not this repository's source): it
prevents a malicious or overreaching detector from exfiltrating a secret by
"verifying" it against an attacker-controlled endpoint when several detectors
claim the same value. `--allow-verification-overlap` opts back into cross-detector
verification.


---

## Q5 — Where the boundaries are; behavior "right at the boundary"

> **"I'm trying to understand where the boundaries are, what gets caught versus
> what slips through, and why. I want to see the actual scan output for cases that
> get detected versus cases that get missed, so I can understand the difference.
> If there are thresholds involved, show me what happens right at the boundary."**

There are three concrete gates with sharp boundaries. Each probe below isolates
**exactly one variable** so the observed difference is attributable to one gate.
All Q5 probes use **COMMON**. Two properties of COMMON matter here, and they are
**independent** mechanisms (not the same switch): (1) COMMON **omits**
`--filter-entropy`, so the *global* entropy filter `FilterResultsWithEntropy`
**never runs** — it is gated on `e.filterEntropy != 0` (`engine.go:1145-1146`); and
(2) COMMON's `filtered_unverified` sets `retainFalsePositives`
(`engine.go:317-318`), which skips the *false-positive* filter
`FilterKnownFalsePositives` (`engine.go:1141`). Neither of those touches the AWS
detector's own entropy check — so every Q5 miss below is produced by the
**always-on AWS-internal gates**, not by any global/opt-in filter.

### Boundary 1 — the exact 40-character secret length (`SecretPat`)

`SecretPat` requires **exactly 40** base64 characters (`pkg/detectors/aws/common.go:10`).
Two files differ only in the secret's length: 40 vs. 39 characters, same ID.

| | `q5_len40.txt` (40 chars) | `q5_len39.txt` (39 chars) |
|---|---|---|
| secret | `wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5u` | `wK8fZ2pN5xQ7rL3vB9mT1cV4dY6hG0jS8aP2eR5` |
| result | **DETECTED** | **MISSED** |

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q5_len40.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q5_len40.txt
Line: 2

2026-07-01T23:10:13Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.489386ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q5_len39.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:10:14Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 115, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "6.232091ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The 39-character secret has **high** Shannon entropy (`5.1316`), so entropy is not
the cause — the miss is purely the length gate. One character short of 40 and
`SecretPat` does not match.

### Boundary 2 — the secret entropy floor `4.25` (`RequiredSecretEntropy`)

`RequiredSecretEntropy = 4.25` (`pkg/detectors/aws/common.go:7`), enforced at
`pkg/detectors/aws/access_keys/accesskey.go:132`. Two 40-character secrets (same
ID, same length) sit on either side of the floor:

| | `q5_entropy_below.txt` | `q5_entropy_above.txt` |
|---|---|---|
| secret | `dsjrAvfdssugldrwcsbtgpvrnykosoljhzfwyhcs` | `minpepfaxjwethkkoltcqgmfhncubprrkfndcitc` |
| Shannon entropy | `4.1964` | `4.2776` |
| vs. floor `4.25` | below | at/above |
| result | **MISSED** | **DETECTED** |

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q5_entropy_below.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:10:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.775912ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q5_entropy_above.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ7Q3RB5XW2YT9NKD
Resource_type: Access key
File: /tmp/th_probe/q5_entropy_above.txt
Line: 2

2026-07-01T23:10:18Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.476476ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

A difference of `0.0812` in entropy — `4.1964` vs. `4.2776`, straddling `4.25` —
is the entire difference between missed and detected. (The ID entropy floor is
`RequiredIdEntropy = 3.0`, `pkg/detectors/aws/common.go:6`, checked at
`accesskey.go:122`; the shared ID `AKIAZ7Q3RB5XW2YT9NKD` has entropy `4.1219`, so
it clears the ID floor in both cases.)

### Boundary 3 — the keyword prefilter as the outermost hard gate

The prefilter (`pkg/engine/ahocorasick/ahocorasickcore.go:127`) is the first gate;
nothing downstream runs without a keyword. Reusing the Q1 `BKIA…` file
(`q1_missed_nokeyword.txt`) — a fully valid, high-entropy, 40-character secret,
whose only defect is that the ID prefix is not `AKIA`/`ABIA`/`ACCA`:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/q1_missed_nokeyword.txt --no-verification --no-update --no-color --results=verified,unverified,unknown,filtered_unverified
2026-07-01T23:06:26Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 116, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.610619ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

No keyword → the AWS detector never runs → no regex or entropy check ever happens.
This is the hardest boundary: it precedes every other gate.

### The key insight: always-on internal gate vs. opt-in global filter

The entropy-below miss above is significant precisely because the **global**
entropy filter was **never running in the first place**. COMMON does not pass
`--filter-entropy`, so `e.filterEntropy` is `0` and the guard `if e.filterEntropy != 0`
is false — `FilterResultsWithEntropy` is skipped entirely:

```go
// pkg/engine/engine.go:1145
if e.filterEntropy != 0 {
	results = detectors.FilterResultsWithEntropy(ctx, results, e.filterEntropy, e.retainFalsePositives)
}
```

(To be exact: it is the **absence of `--filter-entropy`** that keeps the global
entropy filter off, **not** `filtered_unverified`. COMMON's `filtered_unverified`
only sets `retainFalsePositives` (`engine.go:317-318`), which skips
`FilterKnownFalsePositives` — the *false-positive* filter — and has no effect on
the entropy filter.) The secret was still missed even with the global entropy
filter switched off entirely. That proves the AWS entropy check is **unconditional
inside `FromData`** (`accesskey.go:132`) — a *different* mechanism from the opt-in
`--filter-entropy` global filter (`main.go:67`:
`"Filter unverified results with Shannon entropy. Start with 3.0."`). This is the
core distinction the question asks for:

- **Always-on, AWS-internal** entropy gates (`accesskey.go:122`, `:132`): a
  low-entropy candidate never becomes a result. Cannot be turned off by result
  flags.
- **Opt-in, global** `FilterResultsWithEntropy` (`engine.go:1146`): runs only with
  `--filter-entropy`, and applies to unverified results across detectors.

### Side-by-side summary

| Probe | Isolated variable | Value | Gate | Outcome |
|-------|-------------------|-------|------|---------|
| `q5_len40.txt` | secret length | 40 | `SecretPat` (`common.go:10`) | **DETECTED** |
| `q5_len39.txt` | secret length | 39 | `SecretPat` (`common.go:10`) | **MISSED** |
| `q5_entropy_above.txt` | secret entropy | `4.2776` | `RequiredSecretEntropy=4.25` (`common.go:7`) | **DETECTED** |
| `q5_entropy_below.txt` | secret entropy | `4.1964` | `RequiredSecretEntropy=4.25` (`common.go:7`) | **MISSED** |
| `q1_missed_nokeyword.txt` | ID keyword | `BKIA…` | keyword prefilter (`ahocorasickcore.go:127`) | **MISSED** |


---

## Supporting CLI Flags

The flags that govern the behaviors above, quoted from `main.go`:

| Flag | `file:line` | Description (verbatim) |
|------|-------------|------------------------|
| `--no-verification` | `main.go:59` | `"Don't verify the results."` |
| `--results` | `main.go:61` | `"Specifies which type(s) of results to output: verified, unknown, unverified, filtered_unverified. Defaults to verified,unverified,unknown."` |
| `--no-color` | `main.go:62` | `"Disable colorized output"` |
| `--allow-verification-overlap` | `main.go:65` | `"Allow verification of similar credentials across detectors"` |
| `--filter-unverified` | `main.go:66` | `"Only output first unverified result per chunk per detector if there are more than one results."` |
| `--filter-entropy` | `main.go:67` | `"Filter unverified results with Shannon entropy. Start with 3.0."` |
| `--config` | `main.go:70` | `"Path to configuration file."` |
| `--no-update` | `main.go:73` | `"Don't check for updates."` |
| `--fail` | `main.go:74` | `"Exit with code 183 if results are found."` |
| `--json` | `main.go:55` | `"Output in JSON format."` (short `-j`) |
| `--json-legacy` | `main.go:56` | `"Use the pre-v3.0 JSON format..."` |
| `--github-actions` | `main.go:57` | `"Output in GitHub Actions format."` |

**Result-state semantics** (`main.go:61`, `main.go:985`): `verified` = confirmed
valid by the provider's API; `unknown` = verification errored; `unverified` =
detected but not verified; `filtered_unverified` = a would-be-filtered unverified
result, retained for inspection (and, as shown in Q3, requesting it sets
`retainFalsePositives=true`, skipping `FilterKnownFalsePositives`).

> **`--max-decode-depth` is not present at this revision.** External docs describe
> it as `"Maximum depth of iterative decoding. Each decoder's output is fed back
> through all decoders, up to this limit."`, but a search of the tree for
> `max-decode-depth` returns nothing here; decoding is the single pass shown at
> `pkg/engine/engine.go:784` (Q2). The only `*-max-depth` flag present is
> `--archive-max-depth` (`main.go:79`), which governs archive extraction, not
> decoding.

---

## Reasoning Threads

- **Determinism (Q1).** Identical inputs always produce identical results because the keyword prefilter, the regexes, and the entropy checks are pure functions of the chunk bytes — there is no RNG in the detection path. Proven by three identical runs whose only difference was `scan_duration`.
- **Decode-before-detect ordering (Q2).** Decoders run in a fixed order, UTF-8 first (`decoders.go:10`, `// UTF8 must be first for duplicate detection`); each returns `nil` when its format is absent; every non-`nil` decoded variant is re-scanned. Because UTF-8 runs first on a shared buffer and can rewrite it in place, a UTF-16 BOM defeats the UTF-16 decoder here. Only encodings for which a decoder exists are surfaced.
- **Filtering precedence (Q3/Q5).** The always-on AWS-internal entropy gates (`accesskey.go:122`, `:132`) are distinct from the opt-in global `FilterResultsWithEntropy` (`engine.go:1146`) and from the default-on `FilterKnownFalsePositives` (`engine.go:1142`). Requesting `filtered_unverified` skips the last of these; it does not skip `trufflehog:ignore` or the always-on AWS gates.
- **Overlap safety (Q4).** An overlapping finding is still reported (unverified) but carries `errOverlap`; the guard is on by default and is lifted by `--allow-verification-overlap`.
- **Boundary integrity (Q5).** Each probe isolates one variable so the observed difference is attributable to exactly one gate: length (40 vs. 39), secret entropy (`4.2776` vs. `4.1964`), or keyword presence (`AKIA` vs. `BKIA`).

---

## Coverage Pass

Each named item from the five questions, confirmed present and answered (with the
governing source `file:line`). Every ✔ below corresponds to prose, a captured
output block, or a cited literal actually contained in this document.

**Q1 — deterministic detected vs. missed AWS credentials:**

- Aho-Corasick keyword prefilter requiring `AKIA`/`ABIA`/`ACCA` ✔ (`accesskey.go:70`, `ahocorasickcore.go:127`, `engine.go:795`)
- `idPat` regex ✔ (`accesskey.go:65`)
- `SecretPat` exact 40-char regex ✔ (`common.go:10`)
- `RequiredIdEntropy = 3.0` ✔ (`common.go:6`)
- `RequiredSecretEntropy = 4.25` ✔ (`common.go:7`)
- Entropy enforcement lines ✔ (`accesskey.go:122`, `accesskey.go:132`)
- **URL-decode normalization before the regexes** ✔ (`accesskey.go:108` `dataStr = aws.UrlEncodedReplacer.Replace(dataStr)`; replacer `utils.go:35`)
- Determinism proof (3 identical runs) ✔
- Detected + missed output, verbatim ✔

**Q2 — encoding is not protection / decoder chain:**

- Decoder chain order `[UTF8, Base64, UTF16, EscapedUnicode]` + UTF8-first comment ✔ (`decoders.go:8-14`)
- `PLAIN` output, verbatim ✔
- `BASE64` output, verbatim (+ no-wrap generation note) ✔
- `UTF16` output, verbatim ✔
- `ESCAPED_UNICODE` output, verbatim ✔
- Unsupported / "no decoder = slips through" ✔
- `--max-decode-depth` addressed (absent at this revision; single-pass decoding) ✔
- Honest UTF-16 newline & BOM nuances (observed misses) ✔

**Q3 — format-valid fixtures never flagged:**

- `DefaultFalsePositives` — all 7 values ✔ (`falsepositives.go:17-18`)
- Four embedded wordlists `fp_badlist.txt` / `fp_words.txt` / `fp_programmingbooks.txt` / `fp_uuids.txt` ✔ (`falsepositives.go:35/37/39/41`)
- `IsKnownFalsePositive` ✔ (`falsepositives.go:85`)
- `FilterKnownFalsePositives` default-on ✔ (`engine.go:1141`)
- `FilterResultsWithEntropy` opt-in + `"Filtered out result with low entropy"` log line ✔ (`falsepositives.go:154/163`)
- **`trufflehog:ignore` inline suppression, grounded in source** ✔ (`engine.go:547` `ignoreTag`, `engine.go:1262-1268` line detection, `engine.go:1173-1174` early return)
- AWS always-on entropy gates distinct from global filter ✔
- Filtered under DEFAULT vs. shown under `filtered_unverified`, verbatim ✔

**Q4 — verification disabled for safety:**

- Exact `errOverlap` string incl. the missing space after `disabled.` ✔ (`engine.go:39-42`)
- ">1 detector matched the same result" trigger ✔
- `likelyDuplicate` / Levenshtein `similarityThreshold = 0.9` ✔ (`engine.go:887`)
- `verificationOverlapWorker` / `SetVerificationError` ✔ (`detectors.go:126`)
- **`VerificationOverlap` config field** ✔ (`engine.go:139-142`; internal field `engine.go:180`; CLI wiring `main.go:65`/`main.go:528`)
- Yellow `Verification issue:` render ✔ (`plain.go:57`)
- `--allow-verification-overlap` override ✔
- Warning **present without** the flag / **absent with** it — verbatim `grep -c` output (`1` / `0`) ✔
- **Both findings still reported** either way — verbatim `grep -c` output (`2` / `2`) + full Q4-B output block ✔
- Output-format honesty: JSON `VerificationError` field (`json.go`), **legacy JSON has no such field** (`legacy_json.go:229-238`, zero `VerificationError` matches), GitHub Actions (`github_actions.go`) ✔
- External safety rationale, framed as external ✔

**Q5 — thresholds and boundary behavior:**

- `3.0` ID floor ✔ (`common.go:6`)
- `4.25` secret floor ✔ (`common.go:7`)
- Exact 40-character secret gate ✔ (`common.go:10`)
- Keyword hard gate ✔ (`ahocorasickcore.go:127`)
- At-boundary 39-vs-40 output, verbatim ✔
- Entropy below (`4.1964`) vs. at/above (`4.2776`) the `4.25` floor, verbatim ✔
- **Internal-vs-global entropy distinction, corrected** ✔ — the global `FilterResultsWithEntropy` is inactive because `--filter-entropy` is **omitted** (`e.filterEntropy == 0`, `engine.go:1145-1146`), **not** because of `filtered_unverified` (which only sets `retainFalsePositives`, `engine.go:317-318`); the AWS-internal entropy gate (`accesskey.go:132`) is always-on

**Cross-cutting:** every AWS/Postman token shown is a crafted, non-live test value
(see *Methodology → Safety*); every behavioral claim is paired with one verbatim
captured output line and one exact source literal; no output block uses ellipses
or placeholders.

---

## Cleanup & Verification

**The source repository was never modified.** The build (`go build`) and every
scan targeted files under `/tmp`; no file under `pkg/`, `main.go`, `go.mod`, or
`go.sum` was touched. After the investigation, all transient artifacts — the
`/tmp/th_probe/*` probes, the `/tmp/trufflehog` binary, and captured output under
`/tmp/th_out/*` — are removed.

Verification that the source tree is unmodified (an empty result means clean):

```bash
$ git status --porcelain -- pkg/ main.go go.mod go.sum
```

returns **empty** — no source file was changed. The only addition to the
repository is this document, under `blitzy/documentation/`.

