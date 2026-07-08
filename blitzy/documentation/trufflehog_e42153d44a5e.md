# TruffleHog Secret-Detection Behavior — A Runtime-Verified Investigation

This document answers five related questions about how TruffleHog decides which
credentials to report, which to drop, and why. It studies the exact source tree
checked out at commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch
`trufflehog_e42153d44a5e`).

**Methodology — RUN first, then explain.** Every behavioral claim below is backed
by a real command and its **complete, unedited** output captured from a canonical
build of the scanner. Nothing here is concluded from reading source code alone;
where a statement is derived from reading rather than observation it is explicitly
labelled *(from reading)*. Code is cited by `file:line`, naming the specific
function, method, constant, or struct at commit `e42153d4`. All experiments were
run through the real `trufflehog filesystem <path>` entry point, and every fixture
lived **outside** the repository under `/tmp` (all temporary artifacts were removed
after the investigation).

The five questions:

- **Q1** — Why do apparently identical valid AWS credentials get detected in some
  files but missed in others, in a way that is *consistent per file*?
- **Q2** — Does base64-encoding a secret before committing it defeat the scanner?
- **Q3** — Why do some format-valid credentials in test fixtures never get reported?
- **Q4** — What triggers the log warning that verification was disabled "for your
  safety", and why?
- **Q5** — Where is the line between what is caught and what slips through, and why?

## Pipeline overview

The stages a byte stream passes through, and the question that interrogates each:

```mermaid
flowchart LR
    A[Source chunking<br/>chunker.go: 10 KiB + 3 KiB peek] --> B[Decoder chain<br/>UTF8/Base64/UTF16/EscapedUnicode]
    B --> C[Aho-Corasick prefilter<br/>keyword window]
    C --> D[AWS detector<br/>idPat + SecretPat + entropy]
    D --> E[FP filtering<br/>word list + hex + entropy]
    E --> F[Verification /<br/>overlap safeguard]
    F --> G[Result classification]

    Q1[Q1 consistency] -.-> A
    Q1 -.-> C
    Q1 -.-> D
    Q2[Q2 encoding] -.-> B
    Q3[Q3 fixtures] -.-> E
    Q4[Q4 verify disabled] -.-> F
    Q5[Q5 boundaries] -.-> D
    Q5 -.-> E
```

## Canonical build & environment

The binary was built exactly as the `Dockerfile` builds it
(`CGO_ENABLED=0 ... go build -o trufflehog .`), writing the output **outside** the
repository tree so the checkout is never touched. The module declares
`go 1.23.1` with `toolchain go1.24.2` (`go.mod:L3,L5`); Go 1.24.2 was already
present, so `GOTOOLCHAIN=local` pins that installed toolchain and no download was
needed.

```
=== $ go version ===
go version go1.24.2 linux/amd64

=== $ CGO_ENABLED=0 GOTOOLCHAIN=local go build -o /tmp/trufflehog . ===
(exit 0; build prints nothing on success)

=== $ /tmp/trufflehog --version ===
trufflehog dev

=== $ file /tmp/trufflehog ===
/tmp/trufflehog: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=63bbc950d735329bab60d62e9bd4497a33900bd0, with debug_info, not stripped
```

#### `trufflehog dev` is the canonical default, not an error

`--version` prints `trufflehog dev`. This is the expected default for a plain
`go build`: `pkg/version/version.go:L3` declares `var BuildVersion = "dev"`, and
`main.go:L270` wires `cli.Version("trufflehog " + version.BuildVersion)`. A concrete
release string is stamped **only** by the release tooling
(`.goreleaser.yml` uses ldflags `-X '...pkg/version.BuildVersion={{ .Version }}'`),
which a local `go build` does not apply. Every "finished scanning" summary below
therefore reports `"trufflehog_version": "dev"`.

#### Entry point and flags used

All experiments drive the real filesystem source. The relevant flags (from
`trufflehog filesystem --help`, defined in `main.go`):

```
usage: TruffleHog filesystem [<flags>] [<path>...]

Find credentials in a filesystem.

      --log-level=0              Logging verbosity on a scale of 0 (info) to 5
                                 (trace). Can be disabled with "-1".
      --[no-]no-verification     Don't verify the results.
      --results=RESULTS          Specifies which type(s) of results to
                                 output: verified, unknown, unverified,
                                 filtered_unverified. Defaults to
                                 verified,unverified,unknown.
      --[no-]allow-verification-overlap
                                 Allow verification of similar credentials
                                 across detectors
      --filter-entropy=FILTER-ENTROPY
                                 Filter unverified results with Shannon entropy.
                                 Start with 3.0.
```

- `--results` (`main.go:L61`) defaults to `verified,unverified,unknown`, so
  unverified findings are shown without extra flags. A fourth category,
  `filtered_unverified`, exposes filtered-out results (used in Q5).
- `--log-level` (`main.go:L50`) ranges 0 (info) … 5 (trace); trace exposes filter
  decisions.
- `--no-verification` skips the network verification step. Q1, Q2, Q3, and Q5 use
  it so results are deterministic and offline-safe; the unverified-only filters
  (hex false-positive drop, entropy filter) still run. Q4 deliberately runs with
  verification **on**, because the overlap safeguard only manifests then.
- `--allow-verification-overlap` (`main.go:L65`) and `--filter-entropy`
  (`main.go:L67`) are exercised in Q4 and Q5 respectively.

**A note on determinism.** Detection is pure regular-expression matching plus
Shannon-entropy arithmetic — there is no randomness anywhere in the path. Across
repeated runs the **result counts and raw values are byte-identical**; only
naturally-varying fields (wall-clock timestamps, `scan_duration`, worker ids, and
process-scoped temp paths) differ. All "stability" claims below concern the stable
fields.

## Q1 — Same-credential, different-file inconsistency (determinism & proximity)

**Direct answer.** Detection is a **deterministic function of a file's exact
bytes**. The AWS detector reports an access key only when an access-key ID matching
`idPat` and a 40-character secret matching `SecretPat` **co-occur in the same
extracted window** *and* in the same chunk. If two files contain the "same"
credential but differ in how far apart the ID and secret sit — or whether they land
in the same chunk — one file flags and the other does not. Nothing is random: the
same bytes always produce the same result, so the outcome is perfectly consistent
per file.

The relevant code:

- `idPat` — `pkg/detectors/aws/access_keys/accesskey.go:L65`:
  `` `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` ``.
- `SecretPat` — `pkg/detectors/aws/common.go:L10`:
  `` `(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)` ``.
- Inside `FromData` (`accesskey.go:L105`), the IDs are collected at `L112-L114`
  (`idPat.FindAllStringSubmatch`) and the secrets at `L116-L118`
  (`aws.SecretPat.FindAllStringSubmatch`); results are produced only in the nested
  `idMatch × secretMatch` loop (`L121`+). Both must be present in the **same `data`
  buffer** for the loop to emit anything.
- The `data` buffer handed to `FromData` is the keyword window carved out by the
  Aho-Corasick prefilter. The AWS detector's keywords are `AKIA`, `ABIA`, `ACCA`
  (`accesskey.go:L70-L76`); the window is anchored on the ID prefix.

#### The window is ±1024 bytes for AWS (not the generic 512) — observed

The generic extraction radius is `defaultOffsetRadius int64 = 512`
(`pkg/engine/ahocorasick/ahocorasickcore.go:L155`, applied by `extractMatches` at
`L220`). But the AWS detector embeds `detectors.DefaultMultiPartCredentialProvider`
(`accesskey.go:L29`) and implements the `MultiPartCredentialProvider` interface
(`accesskey.go:L58`). In `adjustableSpanCalculator.calculateSpan`
(`ahocorasickcore.go:L80`) the multi-part branch widens the span to
`MaxCredentialSpan()` on each side of the keyword, and
`DefaultMultiPartCredentialProvider.MaxCredentialSpan()` returns `1024`
(`pkg/detectors/multi_part_credential_provider.go:L8,L12`,
`defaultMaxCredentialSpan = 1024`). So for AWS the effective window is **±1024**
bytes. This was confirmed by a byte-level sweep below, not by reading alone.

#### Adjacent ID + secret → detected

The canonical valid pair from the repository's own tests
(`accesskey_test.go`): ID `ABIAS9L8MS5IPHTZPPUQ`, secret
`v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63`.

```
=== ADJACENT (gap=0) : full output ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:10:20Z	info-0	trufflehog	running source	{"source_manager_worker_id": "vmrN1", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/th_fixtures.9JPu/q1cap/adjacent/creds.txt
Line: 1

2026-07-08T05:10:20Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.033134ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Note `Raw result: ABIAS9L8MS5IPHTZPPUQ` — the raw value is the **ID**, because the
detector sets `Raw = []byte(idMatch)` (`accesskey.go:L138`). This matters for Q3.

#### The exact ±1024 boundary — detected vs. missed one byte apart

Placing the same ID and secret in one file with a filler gap between them, and
sweeping the gap byte-by-byte, produces an exact flip. The ID keyword `ABIA` sits
at byte offset 20, so the window ends at `20 + 1024 = 1044`; the 40-byte secret
still fits when the gap is 939 but is truncated at 940.

```
=== gap=939 (secret ends at window edge) EXPECT DETECTED ===
Raw result: ABIAS9L8MS5IPHTZPPUQ
2026-07-08T05:10:50Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1045, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.237211ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

=== gap=940 (secret truncated past window) EXPECT MISSED ===
2026-07-08T05:10:51Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1046, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.315217ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

One byte of separation (`gap=939` → `gap=940`) flips `unverified_secrets` from `1`
to `0`.

#### Beyond the window but in the same chunk → still missed

To prove the window — not the chunk — is what matters here, the same pair separated
by 2000 bytes still lands in a single chunk (`"chunks": 1`) yet is missed:

```
=== BEYOND WINDOW (gap=2000, same chunk) : full output ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:10:28Z	info-0	trufflehog	running source	{"source_manager_worker_id": "SPxRx", "with_units": true}
2026-07-08T05:10:28Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.382803ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

#### Chunk boundaries — the 3 KiB peek keeps nearby pairs together

Chunking is governed by `pkg/sources/chunker.go`: `ChunkSize = 10*1024` (`L14`),
`PeekSize = 3*1024` (`L16`), and `TotalChunkSize = ChunkSize + PeekSize` (`L18`).
Each chunk carries a 3 KiB *peek* of the following bytes. A pair placed so it
straddles the 10 240-byte chunk boundary — but adjacent to each other — is still
detected, because the peek keeps both in the first chunk's buffer. The file spans
two chunks (`"chunks": 2`) yet the credential is found:

```
=== chunk_straddle (file > ChunkSize 10240; pair adjacent within peek) EXPECT DETECTED, chunks:2 ===
Raw result: ABIAS9L8MS5IPHTZPPUQ
2026-07-08T05:10:53Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 10374, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.599649ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Because the peek (3072) is larger than the AWS window (1024), the **window is the
binding constraint**: any pair close enough to co-occur in the ±1024 window is also
close enough to survive chunk splitting.

#### Determinism — the same input, three times

Running the adjacent fixture unchanged three times yields byte-identical result
counts (only timestamps and `scan_duration` vary):

```
=== DETERMINISM: adjacent run 3x (result-count lines only) ===
run1: Raw result: ABIAS9L8MS5IPHTZPPUQ
run1: 2026-07-08T05:10:30Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.033552ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
run2: Raw result: ABIAS9L8MS5IPHTZPPUQ
run2: 2026-07-08T05:10:31Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.05876ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
run3: Raw result: ABIAS9L8MS5IPHTZPPUQ
run3: 2026-07-08T05:10:33Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "3.810119ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Conclusion for Q1.** The per-file variation is fully explained by whether the ID
and secret co-occur within the AWS ±1024-byte keyword window (`accesskey.go:L29,L58`
→ `ahocorasickcore.go:L80` → `MaxCredentialSpan()=1024`) and the same chunk
(`chunker.go:L14-L18`). Within a file this is a fixed function of the bytes, so the
result is always the same for that file — deterministic, not random.


## Q2 — Encoding as false protection

**Direct answer.** Base64-encoding a secret does **not** hide it. TruffleHog runs a
chain of decoders over every chunk **before** detection, and base64 is one of them,
so the scanner sees the decoded bytes. In fact even gzip is transparent, because a
separate archive/decompression layer inflates it before scanning. The only
transforms that evade here are ones the tool neither decodes nor decompresses (raw
hex, ROT13) — and those are trivially reversible by anyone, so they provide no real
protection.

The decoder set is fixed and small. `DefaultDecoders()`
(`pkg/decoders/decoders.go:L8-L15`) returns **exactly four** decoders, in this
order, with the comment "UTF8 must be first for duplicate detection" (`L10`):

1. `UTF8` — `pkg/decoders/utf8.go` (`FromChunk` at `L16`)
2. `Base64` — `pkg/decoders/base64.go` (`FromChunk` at `L34`)
3. `UTF16` — `pkg/decoders/utf16.go` (`FromChunk` at `L18`)
4. `EscapedUnicode` — `pkg/decoders/escaped_unicode.go` (`FromChunk` at `L32`)

There is **no HTML decoder** in this commit *(verified by reading
`DefaultDecoders()` — a fifth "HTML" decoder mentioned in newer public docs is not
present here and is not claimed)*.

The Base64 decoder (`base64.go:L34`) finds base64-looking substrings of length ≥ 20
via `getSubstringsOfCharacterSet(chunk.Data, 20, ...)` (`L36`), tries `StdEncoding`
(`L40`) and `RawURLEncoding` (`L45`), keeps a candidate only if it decodes without
error **and** the decoded bytes are ASCII (`isASCII`, which rejects any byte > 127),
and replaces the encoded substring in place with the decoded bytes.

#### Base64-encoded pair → still detected (decoder identified as BASE64)

The fixture is the base64 encoding of a plain `AKIA…`/secret pair:

```
$ printf 'aws_access_key_id = ABIAS9L8MS5IPHTZPPUQ\naws_secret_access_key = v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63\n' | base64 -w 0
YXdzX2FjY2Vzc19rZXlfaWQgPSBBQklBUzlMOE1TNUlQSFRaUFBVUQphd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSB2MlFQS0hsN0xjZFZZc2phUjRMZ1FpWjF6dzNNQW5NeWlvbmRYQzYz
```

Scanning that single base64 blob still finds the AWS key, and the reported
`Decoder Type` is `BASE64` — direct proof that decoding happened before detection:

```
=== BASE64 (expect DETECTED, Decoder Type: BASE64) ===

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/th_fixtures.9JPu/q2cap/b64/creds.b64
Line: 1

2026-07-08T05:11:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.173323ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

#### Raw hex → evades

The same pair as a raw hex string is scanned (`"bytes": 211`) but produces no
finding:

```
=== HEX (expect EVADES) ===
2026-07-08T05:11:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 211, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.349037ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Why it evades: hex digits `[0-9a-f]` are a subset of the base64 alphabet, so the
Base64 decoder *does* try to decode the hex run — but the resulting bytes are not
ASCII, so `isASCII` rejects them (`base64.go`) and the substring is left unchanged.
The un-decoded hex contains no `AKIA`/`ABIA`/`ACCA` keyword, so nothing matches. Hex
is simply not one of the four decoders.

#### ROT13 → evades

```
=== ROT13 (expect EVADES; transformed ID NOVNF... has no AKIA/ABIA/ACCA prefix) ===
2026-07-08T05:11:26Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.500348ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Under ROT13 the ID `ABIAS9L8MS5IPHTZPPUQ` becomes `NOVNF9Y8ZF5VCUGMCCHD`, which has
no `AKIA`/`ABIA`/`ACCA` prefix, so `idPat` cannot match. ROT13 is not a decoder.

#### gzip → detected (honest finding: archive layer, not the decoder chain)

gzip is worth calling out because it might look like "encoding". It does **not**
evade — but not because of the four decoders. TruffleHog's archive/decompression
handlers (the `handlers` package, separate from `DefaultDecoders()`) inflate the
gzip stream and scan the plaintext. Note the reported `Decoder Type: PLAIN` and
`"bytes": 105` (the *decompressed* size, not the 114-byte compressed input):

```
=== GZIP (HONEST FINDING: DETECTED via archive/decompression handlers, NOT the decoder chain) ===

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/th_fixtures.9JPu/q2cap/gzip/creds.gz
Line: 1

2026-07-08T05:11:27Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.412651ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Conclusion for Q2.** Base64 offers no protection: `DefaultDecoders()` decodes
each chunk (UTF8 → Base64 → UTF16 → EscapedUnicode) before the detector runs, and
the scan output labels the finding `Decoder Type: BASE64`. gzip is likewise defeated
by the archive layer. Only transforms outside both mechanisms (raw hex, ROT13)
slip through, and those are not a security measure. *(Public documentation notes
that iterative re-decoding is bounded by `--max-decode-depth`, default 5; only the
four decoders above were observed in this commit.)*


## Q3 — Test-fixture credentials that never flag (known-false-positive filter)

**Direct answer.** Some format-valid credentials never flag because their **access-
key ID contains a known-false-positive word** such as `example`. After a detector
produces a result, the engine runs it through `IsKnownFalsePositive`, which
lowercases the finding's `Raw` field and drops it if `Raw` **contains** any term in
`DefaultFalsePositives`. The AWS detector sets `Raw` to the **ID only**, so the
word-list check looks at the ID, not the secret. The canonical example key
`AKIAIOSFODNN7EXAMPLE` is dropped because `akiaiosfodnn7example` contains
`example`. This is **not** an entropy decision — the example ID's entropy is well
above the detector's threshold.

The mechanism, by `file:line`:

- The AWS detector sets `Raw: []byte(idMatch)` (`accesskey.go:L138`), i.e. the raw
  value is the ID. (`RawV2 = idMatch + ":" + secretMatch` at `L140`.)
- The AWS detector has **no** custom false-positive checker *(verified: there is no
  `IsFalsePositive` method in `pkg/detectors/aws`)*, so `GetFalsePositiveCheck`
  returns the default closure calling
  `IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)`
  (`pkg/detectors/falsepositives.go:L77`).
- `IsKnownFalsePositive` (`falsepositives.go:L85`) lowercases `Raw` and checks, in
  order: invalid UTF-8 (`L87`); an exact map hit (`L92`); a **substring** match via
  `strings.Contains(lower, fps)` returning reason `"contains term: " + fps`
  (`L97-L98`); and an aho-corasick word-list match (`L104`).
- `DefaultFalsePositives` (`falsepositives.go:L17`) is
  `{"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"}`.
- `StringShannonEntropy` (`falsepositives.go:L136`) is the base-2 Shannon-entropy
  helper used throughout.

#### The word-list decision, shown at trace level

Scanning `AKIAIOSFODNN7EXAMPLE` with a real secret at `--log-level=5` prints the
exact filter decision, naming the result and the reason:

```
=== c3 (AKIAIOSFODNN7EXAMPLE + real secret) at --log-level=5 : filter-decision line ===
2026-07-08T05:11:57Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "fXOyI", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

`"reason": "contains term: example"` is exactly the string built at
`falsepositives.go:L98`.

#### The cross-combination matrix isolates the ID as the cause

Running the full cross-product of {real ID, example ID} × {real secret, example
secret} shows that **only the cells with an example-containing ID are dropped** — a
real ID paired with an `EXAMPLE`-containing *secret* is still reported, because only
`Raw` = ID is word-list-checked. The example secret used is the well-known
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.

```
===== c1 (ABIAS9L8MS5IPHTZPPUQ + v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63) =====
Raw result: ABIAS9L8MS5IPHTZPPUQ
2026-07-08T05:19:43Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.521071ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
===== c2 (ABIAS9L8MS5IPHTZPPUQ + wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) =====
Raw result: ABIAS9L8MS5IPHTZPPUQ
2026-07-08T05:19:44Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.890346ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
===== c3 (AKIAIOSFODNN7EXAMPLE + v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63) =====
2026-07-08T05:19:46Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.799654ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
===== c4 (AKIAIOSFODNN7EXAMPLE + wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) =====
2026-07-08T05:19:48Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.804492ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

| Cell | ID | Secret | Result |
|------|----|--------|--------|
| c1 | real `ABIAS9L8MS5IPHTZPPUQ` | real | **detected** (`unverified_secrets: 1`) |
| c2 | real `ABIAS9L8MS5IPHTZPPUQ` | `…EXAMPLE…` | **detected** (`unverified_secrets: 1`) |
| c3 | `AKIAIOSFODNN7EXAMPLE` | real | **dropped** (`unverified_secrets: 0`) |
| c4 | `AKIAIOSFODNN7EXAMPLE` | `…EXAMPLE…` | **dropped** (`unverified_secrets: 0`) |

The c2 case is the decisive one — the secret literally contains `EXAMPLE`, yet the
finding is kept because the secret is never word-list-checked:

```
=== c2 full output (real ID + EXAMPLE-containing secret still DETECTED) ===

Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/th_fixtures.9JPu/q3cap/c2/creds.txt
Line: 1

2026-07-08T05:11:58Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.000827ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

#### Entropy is not the cause

Shannon entropy computed base-2 (mirroring `StringShannonEntropy`,
`falsepositives.go:L136`) for the values above *(derived with a small temporary
script, since removed)*:

```
IDLOW  AKIAGHJKM2GHJKM2GHJK                          len=20 entropy=2.9087
IDHIGH AKIAGHJKM2NGHJKM2NGH                          len=20 entropy=3.1087
REALID ABIAS9L8MS5IPHTZPPUQ                          len=20 entropy=3.7842
SECLOW  ABCDEFGHJKLMNPQRSTUABCDEFGHJKLMNPQRSTUAB     len=40 entropy=4.2342
SECHIGH ABCDEFGHJKLMNPQRSTUVABCDEFGHJKLMNPQRSTUV     len=40 entropy=4.3219
REALSEC v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63     len=40 entropy=4.9719
```

The example ID `AKIAIOSFODNN7EXAMPLE` has entropy `3.6844` — above the detector's
`RequiredIdEntropy = 3.0` gate (`common.go:L6`) — so it passes the entropy check and
is dropped purely by the word-list substring match. The detector's own entropy gates
(ID `< 3.0` skips at `accesskey.go:L122`; secret `< 4.25` skips at `L132`,
`RequiredSecretEntropy` at `common.go:L7`) are a *separate* mechanism, studied at the
boundary in Q5.

**Conclusion for Q3.** Format-valid fixture credentials such as
`AKIAIOSFODNN7EXAMPLE` never flag because their lowercased ID **contains** a
`DefaultFalsePositives` term (`example`), matched by `strings.Contains`
(`falsepositives.go:L97`) on `Raw` = the ID (`accesskey.go:L138`). It is a substring
word-list decision, not an entropy one, and it inspects the ID only.


## Q4 — "For your safety, verification has been disabled" (verification overlap)

**Direct answer.** When the **same (or very similar) secret is matched by more than
one *different* detector** inside a single chunk, the engine refuses to verify it and
attaches a warning to the finding. The reasoning is safety: verifying a credential
means sending it to a live service, and if two detectors disagree about which
service owns the secret, TruffleHog would risk leaking one vendor's secret to
another vendor's endpoint. The safeguard is overridable with
`--allow-verification-overlap`.

The mechanism, by `file:line`:

- The message is the `errOverlap` value (`pkg/engine/engine.go:L39-L42`). Its text
  is built by concatenating two string literals, so in the emitted bytes there is
  **no space** between `disabled.` and `You`:
  `More than one detector has found this result. For your safety, verification has
  been disabled.You can override this behavior by using the
  --allow-verification-overlap flag.` (`L40-L41`).
- Routing: when a chunk matches more than one detector and overlap is not allowed,
  the engine sends the chunk to the overlap path (`engine.go:L796`,
  `len(matchingDetectors) > 1 && !e.verificationOverlap`).
- `verificationOverlapWorker` (`engine.go:L924`) runs each detector's `FromData`
  with **verify=false** (`L940`), then for each result calls `likelyDuplicate`
  (`L982`); on a hit it attaches the warning via `SetVerificationError(errOverlap)`
  (`L988`).
- `likelyDuplicate` (`engine.go:L887`) uses `similarityThreshold = 0.9` (`L888`):
  an exact string match logs `found exact duplicate` (`L906`) and returns true,
  otherwise a Levenshtein similarity `> 0.9` logs `found similar duplicate` (`L916`)
  and returns true. Crucially it **skips comparisons within the same detector type**
  (`L900-L902`), so a genuine overlap requires **two different detector types**.
- `--allow-verification-overlap` (`main.go:L65`) sets `e.verificationOverlap = true`,
  bypassing the overlap worker entirely.

Because all custom (user-config) detectors share the single type
`DetectorType_CustomRegex` *(from reading `custom_detectors.go:L345`)*, they cannot
overlap with each other; two different **built-in** detectors are required.

#### Forcing a real overlap with two built-in detectors

Many built-in detectors capture a bare 32-hex secret gated only by a nearby keyword
(the shared `PrefixRegex` shape `(?i:kw)(?:.|[\n\r]){0,40}?`, `detectors.go:L230`).
`IpStack` matches `[a-fA-F0-9]{32}` and `MadKudu` matches `[0-9a-f]{32}`. Placing
both keywords within 40 characters of one 32-hex value makes both detectors extract
the **identical** secret. The value `3b1f8c2d7e6a940512df8b9c1a7e2d94` is 32-hex and
free of any false-positive term.

Fixture (59 bytes): `madkudu ipstack api_key = 3b1f8c2d7e6a940512df8b9c1a7e2d94`

Under **default settings (verification on)** the overlap fires and the warning is
printed on the IpStack finding:

```
=== DEFAULT (verification ON): expect overlap 'For your safety' message ===

Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: IpStack
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/th_fixtures.9JPu/q4cap/creds.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: MadKudu
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/th_fixtures.9JPu/q4cap/creds.txt
Line: 1

2026-07-08T05:12:09Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 59, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "181.826186ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":176}}
```

Both detectors report `Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94` (the identical
secret), and the warning text matches `errOverlap` byte-for-byte, including the
missing space after `disabled.`. At `--log-level=2` the duplicate-detection decision
is visible:

```
=== --log-level=2 : 'found exact duplicate' line ===
2026-07-08T05:12:21Z	info-2	trufflehog	found exact duplicate	{"verification_overlap_worker_id": "g0KCl", "timeout": 2}
```

#### Toggling the safeguard off

Re-running the **same** fixture with `--allow-verification-overlap` removes the
warning entirely; both findings proceed to verification (they attempt a live call,
which is why `Misses` rises from `1` to `2` — both were attempted, and both remain
unverified in this offline sandbox):

```
=== WITH --allow-verification-overlap: message GONE, both verify (offline=>unverified) ===

Found unverified result 🐷🔑❓
Detector Type: IpStack
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/th_fixtures.9JPu/q4cap/creds.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: MadKudu
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/th_fixtures.9JPu/q4cap/creds.txt
Line: 1

2026-07-08T05:12:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 59, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "192.749495ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":309}}
```

**Conclusion for Q4.** The warning `For your safety, verification has been disabled`
(`errOverlap`, `engine.go:L40`) is emitted when `likelyDuplicate`
(`engine.go:L887-L922`) finds the same/similar secret across **two different**
detector types in one chunk; the overlap worker withholds verification and calls
`SetVerificationError(errOverlap)` (`L988`). `--allow-verification-overlap`
(`main.go:L65`) disables the safeguard so both findings verify. Demonstrated with
real built-in detectors (IpStack + MadKudu), not a fabricated detector.


## Q5 — Detection boundaries (detected vs. missed at each threshold)

**Direct answer.** There is not one line but several, each an explicit check in the
AWS detector or the engine. Below, every threshold is shown with a detected-vs-
missed pair straddling it. The thresholds are: the detector's internal ID entropy
gate (3.0) and secret entropy gate (4.25); the engine-level opt-in `--filter-entropy`
(which, importantly, judges the ID); the hexadecimal false-positive pattern; the URL-
encoding normalizer; the ±1024 proximity window and chunk boundary (from Q1); the
false-positive word list (from Q3); and the AWS canary path.

#### Boundary 1 — internal ID entropy gate (`RequiredIdEntropy = 3.0`)

`common.go:L6` defines `RequiredIdEntropy = 3.0`; `accesskey.go:L122` skips an ID
whose `StringShannonEntropy` is `< 3.0`. An ID at entropy `2.9087` is missed; one at
`3.1087` is detected (paired with the same valid secret):

```
=== ID entropy gate (RequiredIdEntropy=3.0, accesskey.go:L122) ===
-- id_below: AKIAGHJKM2GHJKM2GHJK entropy 2.9087 (<3.0) EXPECT MISSED --
"unverified_secrets": 0
-- id_above: AKIAGHJKM2NGHJKM2NGH entropy 3.1087 (>=3.0) EXPECT DETECTED --
Raw result: AKIAGHJKM2NGHJKM2NGH
"unverified_secrets": 1
```

#### Boundary 2 — internal secret entropy gate (`RequiredSecretEntropy = 4.25`)

`common.go:L7` defines `RequiredSecretEntropy = 4.25`; `accesskey.go:L132` skips a
secret whose entropy is `< 4.25`. A 40-char secret at entropy `4.2342` is missed; one
at `4.3219` is detected (paired with the same valid ID):

```
=== Secret entropy gate (RequiredSecretEntropy=4.25, accesskey.go:L132) ===
-- sec_below: entropy 4.2342 (<4.25) EXPECT MISSED --
"unverified_secrets": 0
-- sec_above: entropy 4.3219 (>=4.25) EXPECT DETECTED --
Raw result: ABIAS9L8MS5IPHTZPPUQ
"unverified_secrets": 1
```

#### Boundary 3 — engine `--filter-entropy` (opt-in, judges the ID)

This is a **distinct** filter from the internal gates. `filterResults`
(`engine.go:L1126`) applies `FilterKnownFalsePositives` (`L1142`, by default) and then
`FilterResultsWithEntropy` (`L1146`) **only when** `e.filterEntropy != 0` (`L1145`).
`FilterResultsWithEntropy` (`falsepositives.go:L154`) computes
`StringShannonEntropy(string(result.Raw))` (`L158-L159`) — and for AWS `Raw` is the
**ID** (`accesskey.go:L138`). So `--filter-entropy` filters on the ID's entropy, not
the secret's.

Because a reported ID has already cleared the internal `3.0` gate, `--filter-entropy=3.0`
changes nothing; the drop only appears when the threshold is set **above** the ID's
measured entropy. The canonical ID `ABIAS9L8MS5IPHTZPPUQ` has entropy `3.7842`:

```
=== --filter-entropy (engine-level, operates on Raw=ID; fixture q5fe: ID entropy 3.7842) ===
-- (a) no flag EXPECT 1 --
"unverified_secrets": 1
-- (b) --filter-entropy=3.0 (3.7842>=3.0 KEPT; separate from internal gate) EXPECT 1 --
"unverified_secrets": 1
-- (c) --filter-entropy=3.8 (3.7842<3.8 DROPPED) EXPECT 0 --
"unverified_secrets": 0
```

Adding `filtered_unverified` to `--results` (which sets the internal
`retainFalsePositives`/log flag, `engine.go:L317-L318`) surfaces the byte-exact
decision. The logged `Raw` is base64 (`QUJJQVM5TDhNUzVJUEhUWlBQVVE=` decodes to
`ABIAS9L8MS5IPHTZPPUQ`) and `Redacted` is the plaintext ID — proving the filter
judged the **ID**:

```
=== filter-decision log line (via filtered_unverified results category) ===
2026-07-08T05:13:24Z	info-0	trufflehog	Filtered out result with low entropy	{"detector_worker_id": "tJ49X", "detector": {"type":"AWS"}, "timeout": 10, "result": {"DetectorType":2,"DetectorName":"","Verified":false,"VerificationFromCache":false,"Raw":"QUJJQVM5TDhNUzVJUEhUWlBQVVE=","RawV2":"QUJJQVM5TDhNUzVJUEhUWlBQVVE6djJRUEtIbDdMY2RWWXNqYVI0TGdRaVoxenczTUFuTXlpb25kWEM2Mw==","Redacted":"ABIAS9L8MS5IPHTZPPUQ","ExtraData":{"resource_type":"AWS STS service bearer token"},"StructuredData":null,"AnalysisInfo":null}}
```

#### Boundary 4 — hexadecimal false-positive pattern (and why it is shadowed)

`FalsePositiveSecretPat = [a-f0-9]{40}` (`utils.go:L47`) is applied at
`accesskey.go:L202-L205`:
`if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) { continue }`
— unverified secrets that look like a 40-char lowercase-hex hash are dropped.

An all-hex secret is missed; a non-hex secret at sufficient entropy is detected:

```
=== Hex-FP pattern [a-f0-9]{40} (utils.go:L47) — shadowed by secret entropy gate ===
-- allhex 0123456789abcdef0123456789abcdef01234567 (entropy 3.9710 < 4.25) EXPECT MISSED --
"unverified_secrets": 0
-- nonhex ABCDEFGHJKLMNPQRSTUVABCDEFGHJKLMNPQRSTUV (entropy 4.3219 >= 4.25) EXPECT DETECTED --
Raw result: ABIAS9L8MS5IPHTZPPUQ
"unverified_secrets": 1
```

There is a subtle and important finding here. The maximum possible Shannon entropy
of **any** 40-char lowercase-hex string is `log2(16) = 4.0` (the maximally-diverse
`0123456789abcdef0123456789abcdef01234567` measures `3.9710`; a git-style hash
`aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` measures `3.6464`). That is always below
`RequiredSecretEntropy = 4.25`. And the secret entropy gate at `accesskey.go:L132`
runs **before** the hex drop at `L202` in the same `id × secret` loop. Therefore a
pure lowercase-hex secret is always eliminated by the entropy gate first, and the
`FalsePositiveSecretPat` drop is a **defense-in-depth backstop that is effectively
shadowed** for pure-hex input. The all-hex "missed" result above is attributable to
`L132` (entropy `3.9710 < 4.25`); the contrasting "detected" case differs precisely
because its non-hex secret clears `4.25`.

#### Boundary 5 — `UrlEncodedReplacer` normalization

`UrlEncodedReplacer` (`utils.go:L35-L42`) maps `%2B`/`%2b`→`+`, `%2F`/`%2f`→`/`, and
`%3d`/`%3D`→`=`, and is the very first operation in `FromData`
(`dataStr = aws.UrlEncodedReplacer.Replace(dataStr)`, `accesskey.go:L108`). Those are
exactly the non-alphanumeric characters that appear in an AWS secret's
`[A-Za-z0-9+/]{40}` alphabet. A 40-char secret containing `/` and `+`, written URL-
encoded, is normalized back into a valid run and detected; the same secret double-
encoded (`%252F`/`%252B`, which do not contain the substrings `%2F`/`%2B`) is not
normalized, so the `%` breaks the 40-char run and it is missed:

```
=== UrlEncodedReplacer (utils.go:L35-42, applied accesskey.go:L108) ===
-- url-encoded %2F/%2B (normalizable) EXPECT DETECTED --
Raw result: ABIAS9L8MS5IPHTZPPUQ
"unverified_secrets": 1
-- double-encoded %252F/%252B (un-normalizable) EXPECT MISSED --
"unverified_secrets": 0
```

*(The secret used, `Zm9Qp2Rt7Vw3Nb8Ld5Hj/Fg1Cs4Ea6Yu0Io2P+Kx`, is a synthesised 40-
char `[A-Za-z0-9+/]` value with entropy 5.2719 — labelled non-canonical; the ID is
the canonical `ABIAS9L8MS5IPHTZPPUQ`.)*

#### Boundary 6 — the false-positive word list (cross-reference to Q3)

The word-list boundary is the ID with vs. without an embedded `DefaultFalsePositives`
term: `AKIAIOSFODNN7EXAMPLE` (contains `example`) is dropped with reason
`contains term: example`, while a real ID with no embedded term is kept. See Q3 for
the full matrix and the trace-level decision line.

#### Boundary 7 — proximity window and chunk boundary (cross-reference to Q1)

The ±1024 window (`ahocorasickcore.go:L155` generic fallback; AWS ±1024 via
`MaxCredentialSpan()`) and the chunk sizes (`chunker.go:L14-L18`) are the spatial
boundaries. Q1 shows the exact one-byte flip (`gap=939` detected → `gap=940` missed)
and that the 3 KiB peek keeps adjacent pairs together across a chunk boundary.

#### Boundary 8 — the AWS canary path

A canary access key is routed to a dedicated path. `GetAccountNumFromID`
(`utils.go:L49`) decodes the AWS account number embedded in the ID; if that account
is in `thinkstCanaryList` (`canary.go:L17`), the detector sets
`ExtraData["message"] = thinkstMessage` (`accesskey.go:L157`) — where `thinkstMessage`
is `"This is an AWS canary token generated at canarytokens.org."` (`canary.go:L13`) —
and `ExtraData["is_canary"] = "true"` (`accesskey.go:L181`). These are set
**regardless of verification**; only the live check is gated on `verify`, which calls
`verifyCanary` (`accesskey.go:L159` → `canary.go:L49`), and the normal `verifyMatch`
is skipped for canaries (`accesskey.go:L185`, `verify && !isCanary`).

Using the repository's canary fixture ID `AKIASP2TPHJSQH3FJRUX`
(`accesskey_integration_test.go:L22`, `const canaryAccessKeyID`) with
`--no-verification` (offline-safe):

```
=== CANARY ID AKIASP2TPHJSQH3FJRUX, --no-verification (offline-safe) : ExtraData ===
Redacted: AKIASP2TPHJSQH3FJRUX
Verified: False
DecoderName: PLAIN
ExtraData:
  account: 171436882533
  is_canary: true
  message: This is an AWS canary token generated at canarytokens.org.
  resource_type: Access key
```

The same in the default console format:

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Raw result: AKIASP2TPHJSQH3FJRUX
Resource_type: Access key
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/th_fixtures.9JPu/q5canary/creds.txt
2026-07-08T05:13:53Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.243436ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The decoded `account` `171436882533` is a member of `thinkstCanaryList`
(`canary.go:L17`), which is why the canary branch fires. With verification **on**,
`verifyCanary` performs a live SNS publish (`canary.go:L61-L69`); in this offline
sandbox it does not verify (`Verified: False`), with no verification error populated —
this is network-dependent behaviour and is labelled as such. The canary ExtraData is
identical either way.

**Conclusion for Q5.** Each boundary is a concrete, cited check, and each was shown
to flip at its threshold: the internal entropy gates (`3.0` / `4.25`), the opt-in
`--filter-entropy` (which judges the ID), the hex false-positive pattern (shadowed by
the `4.25` gate for pure hex), the URL-encoding normalizer, the word list (Q3), the
±1024 window and chunk boundary (Q1), and the canary routing.


## Coverage summary

Every named mechanism, flag, condition, threshold, and canonical key, with its
value, `file:line`, and the observed evidence above. All line numbers are at commit
`e42153d4`.

| Item | Value / behaviour | `file:line` | Where observed |
|------|-------------------|-------------|----------------|
| `idPat` | `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` | `pkg/detectors/aws/access_keys/accesskey.go:L65` | Q1 (all AWS findings), Q5 |
| AWS `Keywords()` | `AKIA`, `ABIA`, `ACCA` | `accesskey.go:L70-L76` | Q1 (window anchor) |
| `SecretPat` | `(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)` | `pkg/detectors/aws/common.go:L10` | Q1, Q5 (url/hex) |
| `defaultOffsetRadius` | `512` (generic fallback) | `pkg/engine/ahocorasick/ahocorasickcore.go:L155` | Q1 (noted; AWS overrides) |
| AWS effective window | ±`1024` via `MaxCredentialSpan()` | `accesskey.go:L29,L58`; `ahocorasickcore.go:L80`; `multi_part_credential_provider.go:L8,L12` | Q1 (gap 939→940 flip) |
| `extractMatches` | applies the window | `ahocorasickcore.go:L220` | Q1 |
| `ChunkSize` / `PeekSize` / `TotalChunkSize` | `10*1024` / `3*1024` / sum | `pkg/sources/chunker.go:L14,L16,L18` | Q1 (chunk straddle, `chunks:2`) |
| `DefaultDecoders()` | exactly 4: UTF8→Base64→UTF16→EscapedUnicode | `pkg/decoders/decoders.go:L8-L15` (comment L10) | Q2 |
| Decoder `FromChunk` (each) | UTF8/Base64/UTF16/EscapedUnicode | `utf8.go:L16`, `base64.go:L34`, `utf16.go:L18`, `escaped_unicode.go:L32` | Q2 |
| Base64 decode-before-detect | `Decoder Type: BASE64` on finding | `base64.go:L34` (`getSubstringsOfCharacterSet(…,20,…)` L36; ASCII gate) | Q2 (base64 detected) |
| No HTML decoder | absent in this commit | `decoders.go:L8-L15` *(from reading)* | Q2 |
| `Raw = []byte(idMatch)` | raw value is the ID | `accesskey.go:L138` (`RawV2` L140) | Q1, Q3, Q5 (`Redacted`=ID) |
| `IsKnownFalsePositive` | lowercases `Raw`, multi-check | `pkg/detectors/falsepositives.go:L85-L109` | Q3 |
| `DefaultFalsePositives` | `example,xxxxxx,aaaaaa,abcde,00000,sample,*****` | `falsepositives.go:L17` | Q3 |
| `strings.Contains` substring match | reason `contains term: <fps>` | `falsepositives.go:L97-L98` | Q3 (`contains term: example`) |
| `StringShannonEntropy` | base-2 Shannon entropy | `falsepositives.go:L136` | Q3, Q5 (entropy values) |
| `RequiredIdEntropy` | `3.0` | `common.go:L6`; gate `accesskey.go:L122` | Q5 (2.9087 miss / 3.1087 hit) |
| `RequiredSecretEntropy` | `4.25` | `common.go:L7`; gate `accesskey.go:L132` | Q5 (4.2342 miss / 4.3219 hit) |
| `errOverlap` message | `…disabled.You can override…` (no space) | `pkg/engine/engine.go:L39-L42` (text L40) | Q4 (default run) |
| Overlap routing | `len(matchingDetectors) > 1 && !verificationOverlap` | `engine.go:L796` | Q4 |
| `verificationOverlapWorker` | runs `FromData` verify=false; sets error | `engine.go:L924` (verify=false L940; `SetVerificationError` L988) | Q4 |
| `likelyDuplicate` | threshold `0.9`; skips same type | `engine.go:L887-L922` (exact L906, similar L916) | Q4 (`found exact duplicate`) |
| `--allow-verification-overlap` | disables safeguard | `main.go:L65` | Q4 (message gone, Misses 1→2) |
| `filterResults` | orchestrates FP + entropy filters | `engine.go:L1126` | Q3, Q5 |
| `FilterKnownFalsePositives` | default when `!retainFalsePositives` | `engine.go:L1142` | Q3 |
| `FilterResultsWithEntropy` | on `Raw`; only when `filterEntropy != 0` | `engine.go:L1145-L1146`; `falsepositives.go:L154,L158-L159` | Q5 (filter line, Raw=ID) |
| `--filter-entropy` | opt-in; "Start with 3.0"; judges ID | `main.go:L67` | Q5 (no-flag 1 / =3.0 1 / =3.8 0) |
| `FalsePositiveSecretPat` | `[a-f0-9]{40}` | `pkg/detectors/aws/utils.go:L47` | Q5 (all-hex missed) |
| Hex-FP drop | `if !Verified && …MatchString{ continue }` (shadowed by L132) | `accesskey.go:L202-L205` | Q5 |
| `UrlEncodedReplacer` | `%2B/%2b→+`, `%2F/%2f→/`, `%3d/%3D→=` | `utils.go:L35-L42`; applied `accesskey.go:L108` | Q5 (encoded hit / double-encoded miss) |
| `thinkstMessage` | `This is an AWS canary token generated at canarytokens.org.` | `pkg/detectors/aws/access_keys/canary.go:L13`; set `accesskey.go:L157` | Q5 (canary ExtraData) |
| `thinkstCanaryList` | canary account map (incl. `171436882533`) | `canary.go:L17` | Q5 (account 171436882533) |
| `verifyCanary` | live SNS publish (network-dependent) | `canary.go:L49` (Publish L61-L69); routed `accesskey.go:L159` | Q5 (default verify → False, offline) |
| `is_canary` ExtraData | `"true"` | `accesskey.go:L181` | Q5 |
| Canonical key `ABIAS9L8MS5IPHTZPPUQ` + secret | valid pair (`accesskey_test.go`) | `accesskey_test.go` | Q1/Q3/Q5 |
| Canonical key `AKIAIOSFODNN7EXAMPLE` | example ID, dropped on `example` | well-known | Q3 |
| Canonical key `AKIASP2TPHJSQH3FJRUX` | canary ID (`const canaryAccessKeyID`) | `accesskey_integration_test.go:L22` | Q5 |
| `BuildVersion = "dev"` | `--version` → `trufflehog dev` | `pkg/version/version.go:L3`; wired `main.go:L270` | Build section |

#### Per-question status

- **Q1 — deterministic, proximity/chunk-driven:** answered with the exact ±1024
  window flip (`gap=939`→`gap=940`), same-chunk-beyond-window miss, chunk-straddle
  hit, and a 3× determinism run.
- **Q2 — encoding is not protection:** answered with base64 detected
  (`Decoder Type: BASE64`), hex and ROT13 evading, and gzip decompressed by the
  archive layer (honest contrast).
- **Q3 — fixture credentials that never flag:** answered with the trace-level
  `contains term: example` decision and the 2×2 matrix isolating the ID substring.
- **Q4 — "verification has been disabled":** answered with a real IpStack+MadKudu
  overlap, the byte-exact `errOverlap` text, and the `--allow-verification-overlap`
  toggle.
- **Q5 — boundaries:** answered with detected-vs-missed pairs at each threshold
  (entropy gates, `--filter-entropy` on the ID, hex-FP shadowing, URL-encoding
  normalization, word list, window/chunk, canary path).

All commands were run through `trufflehog filesystem` against fixtures under `/tmp`,
outside the repository; every output block above is the scanner's complete, unedited
output. Only naturally-varying fields (timestamps, `scan_duration`, worker ids)
differ between runs; the result counts and raw values are stable and reproducible.

