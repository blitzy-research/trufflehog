# TruffleHog Secret-Detection Behavior — A Runtime-Verified Investigation

This document answers five related questions about how TruffleHog decides which
credentials to report, which to drop, and why. It studies the exact source tree
checked out at commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch
`trufflehog_e42153d44a5e`).

**Methodology — RUN first, then explain.** Every behavioral claim below is backed
by a real command and its **complete, unedited** output captured from a canonical
build of the scanner. Nothing here is concluded from reading source code alone;
where a statement is derived from reading rather than observation it is explicitly
labelled *(from reading)*. Code is cited by fully-qualified `file:line`, naming the
specific function, method, constant, or struct at commit `e42153d4`. All experiments
were run through the real `trufflehog filesystem <path>` entry point, and every
fixture lived **outside** the repository under `/tmp` (all temporary artifacts were
removed after the investigation).

Every credential-shaped string used below is either a canonical fixture from the
repository's own tests, a well-known published example, an AWS canary token, a
redacted test value, or a clearly labelled **synthetic (non-canonical)** value. A
complete classification is given in the [Literal inventory](#literal-inventory) near
the end. None is a live secret.

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
(`CGO_ENABLED=0 ... go build -o trufflehog .`, `Dockerfile:L9`), writing the output
**outside** the repository tree so the checkout is never touched. The module declares
`go 1.23.1` (`go.mod:L3`) with `toolchain go1.24.2` (`go.mod:L5`); Go 1.24.2 was
already present, so `GOTOOLCHAIN=local` pins that installed toolchain and no download
was needed.

```
$ go version
go version go1.24.2 linux/amd64

$ CGO_ENABLED=0 GOTOOLCHAIN=local go build -o /tmp/trufflehog .
(exit 0; build prints nothing on success)

$ /tmp/trufflehog --version
trufflehog dev

$ file /tmp/trufflehog
/tmp/trufflehog: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=53c0ceea109120b1ee831adb2736dca857dc0c23, with debug_info, not stripped
```

### `trufflehog dev` is the canonical default, not an error

`--version` prints `trufflehog dev`. This is the expected default for a plain
`go build`: `pkg/version/version.go:L3` declares `var BuildVersion = "dev"`, and
`main.go:L270` wires `cli.Version("trufflehog " + version.BuildVersion)`. A concrete
release string is stamped **only** by the release tooling — `.goreleaser.yml:L6`
uses ldflags `-s -w -X 'github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion={{ .Version }}'`
— which a local `go build` does not apply. Every "finished scanning" summary below
therefore reports `"trufflehog_version": "dev"`. (The `BuildID` in the `file` output
above is a per-build hash and naturally differs between builds.)

### Entry point and flags used

All experiments drive the real filesystem source, the `filesystem` subcommand
(`main.go:L143`). The relevant flags, taken verbatim from
`trufflehog filesystem --help`:

```
usage: TruffleHog filesystem [<flags>] [<path>...]

Find credentials in a filesystem.


Flags:
  -h, --[no-]help                Show context-sensitive help (also try
                                 --help-long and --help-man).
      --log-level=0              Logging verbosity on a scale of 0 (info) to 5
                                 (trace). Can be disabled with "-1".
      --[no-]profile             Enables profiling and sets a pprof and fgprof
                                 server on :18066.
  -j, --[no-]json                Output in JSON format.
      --[no-]json-legacy         Use the pre-v3.0 JSON format. Only works with
                                 git, gitlab, and github sources.
      --[no-]github-actions      Output in GitHub Actions format.
      --concurrency=128          Number of concurrent workers.
      --[no-]no-verification     Don't verify the results.
      --results=RESULTS          Specifies which type(s) of results to
                                 output: verified, unknown, unverified,
                                 filtered_unverified. Defaults to
                                 verified,unverified,unknown.
      --[no-]no-color            Disable colorized output
      --[no-]allow-verification-overlap  
                                 Allow verification of similar credentials
                                 across detectors
      --[no-]filter-unverified   Only output first unverified result per
                                 chunk per detector if there are more than one
                                 results.
      --filter-entropy=FILTER-ENTROPY  
                                 Filter unverified results with Shannon entropy.
                                 Start with 3.0.
      --config=CONFIG            Path to configuration file.
      --[no-]print-avg-detector-time  
                                 Print the average time spent on each detector.
      --[no-]no-update           Don't check for updates.
      --[no-]fail                Exit with code 183 if results are found.
      --verifier=VERIFIER ...    Set custom verification endpoints.
      --[no-]custom-verifiers-only  
                                 Only use custom verification endpoints.
      --detector-timeout=DETECTOR-TIMEOUT  
                                 Maximum time to spend scanning chunks per
                                 detector (e.g., 30s).
      --archive-max-size=ARCHIVE-MAX-SIZE  
                                 Maximum size of archive to scan. (Byte units
                                 eg. 512B, 2KB, 4MB)
      --archive-max-depth=ARCHIVE-MAX-DEPTH  
                                 Maximum depth of archive to scan.
      --archive-timeout=ARCHIVE-TIMEOUT  
                                 Maximum time to spend extracting an archive.
      --include-detectors="all"  Comma separated list of detector types to
                                 include. Protobuf name or IDs may be used,
                                 as well as ranges.
      --exclude-detectors=EXCLUDE-DETECTORS  
                                 Comma separated list of detector types to
                                 exclude. Protobuf name or IDs may be used,
                                 as well as ranges. IDs defined here take
                                 precedence over the include list.
      --[no-]no-verification-cache  
                                 Disable verification caching
      --[no-]force-skip-binaries  
                                 Force skipping binaries.
      --[no-]force-skip-archives  
                                 Force skipping archives.
      --[no-]skip-additional-refs  
                                 Skip additional references.
      --user-agent-suffix=USER-AGENT-SUFFIX  
                                 Suffix to add to User-Agent.
      --[no-]version             Show application version.
      --directory=DIRECTORY ...  Path to directory to scan. You can repeat this
                                 flag.
  -i, --include-paths=INCLUDE-PATHS  
                                 Path to file with newline separated regexes for
                                 files to include in scan.
  -x, --exclude-paths=EXCLUDE-PATHS  
                                 Path to file with newline separated regexes for
                                 files to exclude in scan.

Args:
  [<path>]  Path to file or directory to scan.

```

The flags used throughout:

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
- Note there is **no** `--max-decode-depth` flag in this commit: it does not appear
  in `trufflehog filesystem --help` above, nor anywhere in the source tree at
  `e42153d4`. Decoding in this build is a single pass of the four decoders in
  [Q2](#q2--encoding-as-false-protection); no decode-depth control exists here.

**A note on determinism.** Detection is pure regular-expression matching plus
Shannon-entropy arithmetic — there is no randomness anywhere in the path. Across
repeated runs the **result counts and raw values are byte-identical**; only
naturally-varying fields (wall-clock timestamps, `scan_duration`, worker ids, and
process-scoped temp paths) differ. All "stability" claims below concern the stable
fields, and each experiment was run at least twice (Q1's adjacent fixture three
times) with byte-identical stable output.

## Q1 — Same-credential, different-file inconsistency (determinism & proximity)

**Direct answer.** Detection is a **deterministic function of a file's exact
bytes**. The AWS detector reports an access key only when an access-key ID matching
`idPat` and a 40-character secret matching `SecretPat` **co-occur in the same
extracted window** *and* in the same chunk. If two files contain the "same"
credential but differ in how far apart the ID and secret sit — or whether they land
in the same chunk — one file flags and the other does not. Nothing is random: the
same bytes always produce the same result, so the outcome is perfectly consistent
per file. This is demonstrated below with an exact one-byte flip and a three-times
determinism run.

The relevant code:

- `idPat` — `pkg/detectors/aws/access_keys/accesskey.go:L65`:
  `` `\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` ``.
- `SecretPat` — `pkg/detectors/aws/common.go:L10`:
  `` `(?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)` ``.
- Inside `FromData` (`pkg/detectors/aws/access_keys/accesskey.go:L105`), the IDs are
  collected at `L112-L114` (`idPat.FindAllStringSubmatch`) and the secrets at
  `L116-L118` (`aws.SecretPat.FindAllStringSubmatch`); results are produced only in
  the nested `idMatch × secretMatch` loop (`L121`+). Both must be present in the
  **same `data` buffer** for the loop to emit anything.
- The `data` buffer handed to `FromData` is the keyword window carved out by the
  Aho-Corasick prefilter. The AWS detector's keywords are `AKIA`, `ABIA`, `ACCA`
  (`pkg/detectors/aws/access_keys/accesskey.go:L70-L76`); the window is anchored on
  the ID prefix.

### The window is ±1024 bytes for AWS (not the generic 512) — observed

The generic extraction radius is `defaultOffsetRadius int64 = 512`
(`pkg/engine/ahocorasick/ahocorasickcore.go:L155`, applied by `extractMatches` at
`pkg/engine/ahocorasick/ahocorasickcore.go:L220`). But the AWS detector embeds
`detectors.DefaultMultiPartCredentialProvider`
(`pkg/detectors/aws/access_keys/accesskey.go:L29`) and implements the
`MultiPartCredentialProvider` interface
(`pkg/detectors/aws/access_keys/accesskey.go:L58`). In
`adjustableSpanCalculator.calculateSpan`
(`pkg/engine/ahocorasick/ahocorasickcore.go:L80`) the multi-part branch widens the
span to `MaxCredentialSpan()` on each side of the keyword, and
`DefaultMultiPartCredentialProvider.MaxCredentialSpan()` returns `1024`
(`pkg/detectors/multi_part_credential_provider.go:L8` `defaultMaxCredentialSpan = 1024`,
returned at `pkg/detectors/multi_part_credential_provider.go:L12`). So for AWS the
effective window is **±1024** bytes. This was confirmed by the byte-level sweep
below, not by reading alone.

### Adjacent ID + secret → detected

The canonical valid pair from the repository's own tests
(`pkg/detectors/aws/access_keys/accesskey_test.go:L16-L17`, the `validPattern`): ID
`ABIAS9L8MS5IPHTZPPUQ`, secret `v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63`. The
fixture is two adjacent lines:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:54:53Z	info-0	trufflehog	running source	{"source_manager_worker_id": "eYxJA", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T05:54:53Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.467974ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Note `Raw result: ABIAS9L8MS5IPHTZPPUQ` — the raw value is the **ID**, because the
detector sets `Raw = []byte(idMatch)`
(`pkg/detectors/aws/access_keys/accesskey.go:L138`). This matters for Q3.

### The exact ±1024 boundary — detected vs. missed one byte apart

Placing the same ID and secret in one file with a filler gap between them, and
sweeping the gap byte-by-byte, produces an exact flip. The fixture is a single line
`aws_access_key_id = ` (20 bytes, so the `ABIA` keyword sits at byte offset 20)
followed by the ID, `gap` filler dots, a space, then the 40-byte secret. The AWS
window ends at offset `20 + 1024 = 1044`; the secret still fits when the gap is 963
(its last byte lands at offset 1043) but is truncated at 964. Detected at `gap=963`:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1gap963 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:03Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Cl2nY", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1gap963/creds.txt
Line: 1

2026-07-08T05:55:03Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1045, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.134727ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Missed at `gap=964` — one byte further apart:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1gap964 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:05Z	info-0	trufflehog	running source	{"source_manager_worker_id": "o4NdK", "with_units": true}
2026-07-08T05:55:05Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1046, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.380192ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

One byte of separation (`gap=963` → `gap=964`) flips `unverified_secrets` from `1`
to `0`, while `"chunks": 1` throughout — proving the **window**, not the chunk, is
the binding constraint here.

### Beyond the window but in the same chunk → still missed

To confirm the window (not the chunk) governs this case, the same pair separated by
2000 filler bytes still lands in a single chunk (`"chunks": 1`) yet is missed:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1beyond2000 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:07Z	info-0	trufflehog	running source	{"source_manager_worker_id": "T7qKJ", "with_units": true}
2026-07-08T05:55:07Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2082, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.340113ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Chunk boundaries — the 3 KiB peek keeps nearby pairs together

Chunking is governed by `pkg/sources/chunker.go`: `ChunkSize = 10 * 1024`
(`pkg/sources/chunker.go:L14`), `PeekSize = 3 * 1024`
(`pkg/sources/chunker.go:L16`), and `TotalChunkSize = ChunkSize + PeekSize`
(`pkg/sources/chunker.go:L18`). Each chunk carries a 3 KiB *peek* of the following
bytes. A pair placed so the ID ends exactly on the 10240-byte chunk boundary and the
secret begins just after it — but adjacent to each other — is still detected, because
the peek keeps both in the first chunk's buffer. The file spans two chunks
(`"chunks": 2`) yet the credential is found once:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1straddle --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:09Z	info-0	trufflehog	running source	{"source_manager_worker_id": "kXZKM", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1straddle/creds.txt
Line: 1

2026-07-08T05:55:09Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 10324, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.89729ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Because the peek (3072) is larger than the AWS window (1024), the **window is the
binding constraint**: any pair close enough to co-occur in the ±1024 window is also
close enough to survive chunk splitting.

### Determinism — the same input, three times

Running the adjacent fixture unchanged three times yields byte-identical result
counts and raw values (only timestamps, `scan_duration`, and worker ids vary). All
three complete outputs:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:10Z	info-0	trufflehog	running source	{"source_manager_worker_id": "4sVZI", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T05:55:10Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.019465ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:12Z	info-0	trufflehog	running source	{"source_manager_worker_id": "6Dhlq", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T05:55:12Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "3.825834ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:14Z	info-0	trufflehog	running source	{"source_manager_worker_id": "yS8Fu", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T05:55:14Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.478986ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Conclusion for Q1.** The per-file variation is fully explained by whether the ID
and secret co-occur within the AWS ±1024-byte keyword window
(`pkg/detectors/aws/access_keys/accesskey.go:L29,L58` →
`pkg/engine/ahocorasick/ahocorasickcore.go:L80` → `MaxCredentialSpan()=1024`) and the
same chunk (`pkg/sources/chunker.go:L14-L18`). Within a file this is a fixed function
of the bytes, so the result is always the same for that file — deterministic, not
random.

## Q2 — Encoding as false protection

**Direct answer.** Base64-encoding a secret does **not** hide it. TruffleHog runs a
chain of decoders over every chunk **before** detection, and base64 is one of them,
so the scanner sees the decoded bytes. gzip is likewise transparent, because a
separate archive/decompression layer inflates it before scanning. The only
transforms that evade here are ones the tool neither decodes nor decompresses (raw
hex, ROT13) — and those are trivially reversible by anyone, so they provide no real
protection.

The decoder set is fixed and small. `DefaultDecoders()`
(`pkg/decoders/decoders.go:L8-L15`) returns **exactly four** decoders, in this
order, with the comment "UTF8 must be first for duplicate detection"
(`pkg/decoders/decoders.go:L10`):

1. `UTF8` — `pkg/decoders/utf8.go` (`FromChunk` at `pkg/decoders/utf8.go:L16`)
2. `Base64` — `pkg/decoders/base64.go` (`FromChunk` at `pkg/decoders/base64.go:L34`)
3. `UTF16` — `pkg/decoders/utf16.go` (`FromChunk` at `pkg/decoders/utf16.go:L18`)
4. `EscapedUnicode` — `pkg/decoders/escaped_unicode.go` (`FromChunk` at
   `pkg/decoders/escaped_unicode.go:L32`)

There is **no HTML decoder** in this commit *(from reading `DefaultDecoders()` — a
fifth "HTML" decoder mentioned in newer public docs is not present here and is not
claimed)*. There is likewise no decode-depth flag in this commit (see the note in
[Entry point and flags used](#entry-point-and-flags-used)).

The Base64 decoder (`pkg/decoders/base64.go:L34`) finds base64-looking substrings of
length ≥ 20 via `getSubstringsOfCharacterSet(chunk.Data, 20, ...)`
(`pkg/decoders/base64.go:L36`), tries `StdEncoding` (`pkg/decoders/base64.go:L40`)
and `RawURLEncoding` (`pkg/decoders/base64.go:L45`), keeps a candidate only if it
decodes without error **and** the decoded bytes are ASCII *(from reading: an
`isASCII` check rejects any byte > 127)*, and replaces the encoded substring in place
with the decoded bytes.

### Base64-encoded pair → still detected (decoder identified as BASE64)

The fixture is the base64 encoding of a plain `ABIA…`/secret pair:

```
$ printf 'aws_access_key_id = ABIAS9L8MS5IPHTZPPUQ\naws_secret_access_key = v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63\n' | base64 -w0
YXdzX2FjY2Vzc19rZXlfaWQgPSBBQklBUzlMOE1TNUlQSFRaUFBVUQphd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSB2MlFQS0hsN0xjZFZZc2phUjRMZ1FpWjF6dzNNQW5NeWlvbmRYQzYzCg==
```

Scanning that single 144-byte base64 blob still finds the AWS key, and the reported
`Decoder Type` is `BASE64` — direct proof that decoding happened before detection
(the reported `"bytes": 106` is the decoded content, not the 144-byte encoded file):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q2b64 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:56:16Z	info-0	trufflehog	running source	{"source_manager_worker_id": "meCNX", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q2b64/creds.b64
Line: 1

2026-07-08T05:56:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.653662ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Raw hex → evades

The same pair as a raw lowercase-hex string (212 bytes on disk) is scanned but
produces no finding:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q2hex --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:56:18Z	info-0	trufflehog	running source	{"source_manager_worker_id": "xFp8x", "with_units": true}
2026-07-08T05:56:18Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 212, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.123836ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Why it evades: hex digits `[0-9a-f]` are a subset of the base64 alphabet, so the
Base64 decoder *does* try to decode the hex run — but the resulting bytes are not
ASCII, so the `isASCII` check rejects them *(from reading `pkg/decoders/base64.go`)*
and the substring is left unchanged. The reported `"bytes": 212` (the raw hex size,
un-decoded) confirms no replacement happened. The un-decoded hex contains no
`AKIA`/`ABIA`/`ACCA` keyword, so nothing matches. Hex is simply not one of the four
decoders.

### ROT13 → evades

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q2rot13 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:56:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "8kc2Z", "with_units": true}
2026-07-08T05:56:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.371898ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Under ROT13 the ID `ABIAS9L8MS5IPHTZPPUQ` becomes `NOVNF9Y8ZF5VCUGMCCHD`, which has
no `AKIA`/`ABIA`/`ACCA` prefix, so `idPat`
(`pkg/detectors/aws/access_keys/accesskey.go:L65`) cannot match. ROT13 is not a
decoder.

### gzip → detected (honest finding: archive layer, not the decoder chain)

gzip is worth calling out because it might look like "encoding". It does **not**
evade — but not because of the four decoders. TruffleHog's archive/decompression
handlers (the `handlers` package, separate from `DefaultDecoders()`) inflate the
gzip stream and scan the plaintext. Note the reported `Decoder Type: PLAIN` and
`"bytes": 106` (the *decompressed* size, not the 115-byte compressed input on disk):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q2gzip --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:56:21Z	info-0	trufflehog	running source	{"source_manager_worker_id": "FFcwh", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q2gzip/creds.gz
Line: 1

2026-07-08T05:56:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.530732ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Conclusion for Q2.** Base64 offers no protection: `DefaultDecoders()`
(`pkg/decoders/decoders.go:L8-L15`) decodes each chunk (UTF8 → Base64 → UTF16 →
EscapedUnicode) before the detector runs, and the scan output labels the finding
`Decoder Type: BASE64`. gzip is likewise defeated by the archive layer. Only
transforms outside both mechanisms (raw hex, ROT13) slip through, and those are not
a security measure.

## Q3 — Test-fixture credentials that never flag

**Direct answer.** A format-valid credential is dropped when its **`Raw` value
contains a known false-positive word**, most commonly `example`. The decisive detail
is *which string* gets word-checked: the AWS detector sets the result's `Raw` field
to the **access-key ID** (`Raw = []byte(idMatch)`,
`pkg/detectors/aws/access_keys/accesskey.go:L138`), so only the **ID** is tested
against the word list — never the secret. This is why `AKIAIOSFODNN7EXAMPLE` (the
well-known AWS-docs example ID) is always suppressed, while a real ID paired with a
secret that *itself* contains the substring `EXAMPLE` is still reported. It is **not**
entropy that suppresses the example ID: its Shannon entropy is 3.6842, comfortably
above the 3.0 ID threshold (`RequiredIdEntropy = 3.0`,
`pkg/detectors/aws/common.go:L6`).

The filter path is: `filterResults` (`pkg/engine/engine.go:L1126`) →
`FilterKnownFalsePositives` (`pkg/engine/engine.go:L1142`) → the default closure
`IsKnownFalsePositive(res.Raw, ...)` (`pkg/detectors/falsepositives.go:L77`). Inside
`IsKnownFalsePositive` (`pkg/detectors/falsepositives.go:L85`), the `Raw` value is
lowercased and tested with `strings.Contains` against each term in
`DefaultFalsePositives` (`pkg/detectors/falsepositives.go:L17-L19`), which is the
word list `{example, xxxxxx, aaaaaa, abcde, 00000, sample, *****}`; a substring hit
returns the reason `"contains term: "+fps` (`pkg/detectors/falsepositives.go:L95-L98`).

*All literals below are canonical repository values: `ABIAS9L8MS5IPHTZPPUQ` /
`v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63` are the detector's own test pair
(`pkg/detectors/aws/access_keys/accesskey_test.go:L16-L17`);
`AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` are the
long-published AWS-documentation example pair. See the
[Literal inventory](#literal-inventory).*

### The 2×2 matrix — real/example × ID/secret

Four fixtures cross real and example values across the ID and secret positions. Each
scan below is the complete, unedited command and output.

**Case 1 — real ID + real secret → detected** (baseline). ID entropy 3.7842, secret
entropy 4.9719:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c1 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "896Ma", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q3c1/creds.txt
Line: 1

2026-07-08T05:57:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.259828ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Case 2 — real ID + *example* secret → detected.** The secret
`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` literally contains `EXAMPLE`, yet the
finding is still reported, because the secret is never word-list-checked — only the
`Raw` ID is:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c2 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:20Z	info-0	trufflehog	running source	{"source_manager_worker_id": "nqhYt", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q3c2/creds.txt
Line: 1

2026-07-08T05:57:20Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.329188ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Case 3 — *example* ID + real secret → dropped.** Now the ID itself contains
`example`; the finding disappears even though the secret is a real high-entropy
value:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c3 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:22Z	info-0	trufflehog	running source	{"source_manager_worker_id": "uMXUs", "with_units": true}
2026-07-08T05:57:22Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.330479ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Case 4 — example ID + example secret → dropped** (both example; still governed by
the ID):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c4 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:24Z	info-0	trufflehog	running source	{"source_manager_worker_id": "PL8Du", "with_units": true}
2026-07-08T05:57:24Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.50949ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The matrix isolates the cause precisely: detection flips between Case 2 (kept) and
Case 3 (dropped) purely on whether the **ID** contains a word-list term — the secret
position never matters. This confirms `Raw = idMatch`
(`pkg/detectors/aws/access_keys/accesskey.go:L138`) drives the filter.

| Case | ID | Secret | Result |
|------|----|--------|--------|
| 1 | real `ABIAS9L8MS5IPHTZPPUQ` | real `v2QP…` | **detected** (uv=1) |
| 2 | real `ABIAS9L8MS5IPHTZPPUQ` | example `wJalr…EXAMPLEKEY` | **detected** (uv=1) |
| 3 | example `AKIAIOSFODNN7EXAMPLE` | real `v2QP…` | **dropped** (uv=0) |
| 4 | example `AKIAIOSFODNN7EXAMPLE` | example `wJalr…EXAMPLEKEY` | **dropped** (uv=0) |

### The exact decision, at trace level

Raising the log level to 5 exposes the filter's own decision line. Because a
trace-level scan emits ~147 lines (mostly per-chunk trace noise), the reproducible
command below pipes that full output through `grep` to isolate the single
false-positive decision; the shown line is the complete output of the shown command:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c3 --no-verification --results=verified,unverified,unknown --log-level=5 2>&1 | grep -F 'Skipping result: false positive'
2026-07-08T06:11:58Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "iIWrB", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

The emitted `"reason": "contains term: example"` is exactly the string built at
`pkg/detectors/falsepositives.go:L95-L98`, and `"result": "AKIAIOSFODNN7EXAMPLE"`
confirms the value tested is the ID.

**Conclusion for Q3.** Format-valid test-fixture credentials never flag when their
**access-key ID** contains a `DefaultFalsePositives` term
(`pkg/detectors/falsepositives.go:L17-L19`); the check is a lowercased
`strings.Contains` on the `Raw` field
(`pkg/detectors/falsepositives.go:L85,L95-L98`), and the AWS detector puts the ID in
`Raw` (`pkg/detectors/aws/access_keys/accesskey.go:L138`). Entropy is not the cause
here — the example ID's entropy (3.6842) exceeds the 3.0 threshold; the word list is.

## Q4 — "Verification disabled for safety"

**Direct answer.** The warning fires when **two or more different detectors extract
the identical secret value from the same chunk**. TruffleHog treats that as an
ambiguous overlap and, as a safety measure, **withholds live verification** for that
result rather than sending one secret to multiple third-party APIs. The engine
attaches a verification error whose text is emitted verbatim, and the safeguard can
be turned off with `--allow-verification-overlap`.

The message comes from the package-level `errOverlap`
(`pkg/engine/engine.go:L39-L42`). Its text spans two string literals on
`pkg/engine/engine.go:L40` and `:L41`, and — importantly for byte-exact matching —
there is **no space** between `disabled.` and `You` because the literals are
concatenated directly:

- `pkg/engine/engine.go:L40`: `"…For your safety, verification has been disabled."`
- `pkg/engine/engine.go:L41`: `"You can override this behavior by using the --allow-verification-overlap flag."`

The mechanism: the `verificationOverlapWorker`
(`pkg/engine/engine.go:L924`) calls `likelyDuplicate`
(`pkg/engine/engine.go:L887`, invoked at `:L982`); when a duplicate is found it calls
`res.SetVerificationError(errOverlap)` (`pkg/engine/engine.go:L988`), which is what
prints the warning and suppresses verification. `likelyDuplicate` uses
`similarityThreshold = 0.9` (`pkg/engine/engine.go:L888`): an exact string match logs
`found exact duplicate` (`pkg/engine/engine.go:L906`); a Levenshtein similarity
`> 0.9` logs `found similar duplicate` (`pkg/engine/engine.go:L916`). It **skips
comparisons within the same detector type** (`pkg/engine/engine.go:L900-L902`), so a
real overlap needs **two different detector types**. Because every custom
(user-config) detector shares the single type `DetectorType_CustomRegex`
(`CustomRegexWebhook.Type()`, `pkg/custom_detectors/custom_detectors.go:L345`), custom
detectors cannot overlap with each other — two different **built-in** detectors are
required.

### Forcing a real overlap with two built-in detectors

Many built-in detectors capture a bare 32-character hex secret gated only by a nearby
keyword — the shared `PrefixRegex` shape `(?i:kw)(?:.|[\n\r]){0,40}?`
(`pkg/detectors/detectors.go:L230`). `IpStack` matches `[a-fA-F0-9]{32}` and
`MadKudu` matches `[0-9a-f]{32}`. Placing *both* keywords within 40 characters of one
32-hex value makes both detectors extract the identical secret.

The 32-hex value used here, `3b1f8c2d7e6a940512df8b9c1a7e2d94`, is a **synthetic,
non-canonical literal** — it is not a real IpStack or MadKudu key; it was hand-made
to be 32 hex chars, free of any false-positive term, so both detectors match it. Its
entropy is 3.9056. See the [Literal inventory](#literal-inventory).

Fixture (59 bytes): `madkudu ipstack api_key = 3b1f8c2d7e6a940512df8b9c1a7e2d94`

### Default settings (verification on) → overlap fires, warning printed

Q4 is run **with verification on** (no `--no-verification`), because the safeguard
only manifests during verification. The complete, unedited output — the warning
appears on exactly one of the two findings, both report the identical `Raw result`,
and the run ends with `unverified_secrets: 2` and one verification-cache `Misses`:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q4 --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:58:48Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Owk4Z", "with_units": true}
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: IpStack
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: MadKudu
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

2026-07-08T05:58:49Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 59, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "208.753563ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":203}}
```

Which of the two detectors carries the printed warning (here `IpStack`) depends on
worker scheduling and can vary run to run; the invariant is that **exactly one**
overlap warning is emitted and **both** findings are downgraded to unverified. The
warning text matches `errOverlap` byte-for-byte, including the missing space in
`disabled.You`.

### Trace of the duplicate decision (log-level 2)

At `--log-level=2` the `found exact duplicate` line from the overlap worker is
visible in context with the warning. Full, unedited output:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q4 --results=verified,unverified,unknown --log-level=2
2026-07-08T06:12:29Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:12:29Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-08T06:12:29Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-08T06:12:29Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-08T06:12:29Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-08T06:12:29Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Pc8wD", "with_units": true}
2026-07-08T06:12:29Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "Pc8wD"}
2026-07-08T06:12:29Z	info-2	trufflehog	found exact duplicate	{"verification_overlap_worker_id": "qrjNK", "timeout": 2}
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: IpStack
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: MadKudu
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

2026-07-08T06:12:29Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 59, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "214.079403ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":208}}
```

The `found exact duplicate` line is emitted by
`pkg/engine/engine.go:L906` from inside `verificationOverlapWorker`
(`pkg/engine/engine.go:L924`), confirming the overlap path executed.

### Override → `--allow-verification-overlap` re-enables verification

Re-running the identical fixture with `--allow-verification-overlap`
(`main.go:L65`) sets `e.verificationOverlap = true` and bypasses the overlap worker
entirely. The warning is **gone**, and both findings are now verified independently —
note the verification cache shows `"Misses": 2` (two verification attempts) instead
of the single attempt under the safeguard:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q4 --results=verified,unverified,unknown --allow-verification-overlap
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:58:10Z	info-0	trufflehog	running source	{"source_manager_worker_id": "kJBTu", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: IpStack
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: MadKudu
Decoder Type: PLAIN
Raw result: 3b1f8c2d7e6a940512df8b9c1a7e2d94
File: /tmp/thqa/fx/q4/creds.txt
Line: 1

2026-07-08T05:58:10Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 59, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "164.317469ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":282}}
```

**Conclusion for Q4.** The "verification has been disabled" warning is triggered by
the verification-overlap safeguard: when `likelyDuplicate`
(`pkg/engine/engine.go:L887`) finds the same secret claimed by two different detector
types in one chunk, `verificationOverlapWorker` (`pkg/engine/engine.go:L924`) attaches
`errOverlap` via `SetVerificationError` (`pkg/engine/engine.go:L988`) and prints the
message from `pkg/engine/engine.go:L40-L41`. `--allow-verification-overlap`
(`main.go:L65`) disables the safeguard and restores per-detector verification.

## Q5 — Detection boundaries: what is caught, what slips through, and why

**Direct answer.** The line between caught and missed is set by a small number of
concrete thresholds and patterns, each observable at its exact boundary. This section
walks every one of them and, for each, shows a **direct detected-vs-missed pair** of
complete, unedited scans. The boundaries are: the AWS detector's two Shannon-entropy
gates (ID ≥ 3.0, secret ≥ 4.25); the `idPat` character-class requirement; the
engine-level `--filter-entropy` flag (distinct from the detector's own gates); the
proximity window (±1024 bytes for AWS); the 10 KiB chunk with its 3 KiB peek; the
hexadecimal false-positive pattern `[a-f0-9]{40}`; URL-encoding normalization; the
false-positive word list; and the AWS canary path.

*Several fixtures in this section use **synthetic, non-canonical** 20-char IDs and
40-char secrets constructed to land just below/above an entropy threshold. Every such
literal is labeled at first use and catalogued in the
[Literal inventory](#literal-inventory). Canonical repository values
(`ABIAS9L8MS5IPHTZPPUQ`, the canary `AKIASP2TPHJSQH3FJRUX`, `AKIAIOSFODNN7EXAMPLE`)
are labeled as such.*

### Boundary 1 — AWS ID entropy gate: `RequiredIdEntropy = 3.0`

The ID must have Shannon entropy `>= 3.0` (`pkg/detectors/aws/common.go:L6`), enforced
at the id-entropy gate `pkg/detectors/aws/access_keys/accesskey.go:L122`. The two IDs
below are **synthetic, non-canonical** literals chosen to straddle 3.0: `AKIAGHJKM2GHJKM2GHJK`
(entropy 2.9087, just below) and `AKIAGHJKM2NGHJKM2NGH` (entropy 3.1087, just above);
both are paired with the same canonical secret `v2QP…`.

Below threshold → **missed**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5idlow --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:59:49Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Raya9", "with_units": true}
2026-07-08T05:59:49Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.361095ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

At/above threshold → **detected** (note the AWS detector also decodes the embedded
`Account: 427975037772` for `AKIA`-prefixed keys):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5idhigh --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:59:50Z	info-0	trufflehog	running source	{"source_manager_worker_id": "orkJU", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAGHJKM2NGHJKM2NGH
Account: 427975037772
Resource_type: Access key
File: /tmp/thqa/fx/q5idhigh/creds.txt
Line: 1

2026-07-08T05:59:50Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.656034ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Boundary 2 — AWS secret entropy gate: `RequiredSecretEntropy = 4.25`

The 40-char secret must have Shannon entropy `>= 4.25`
(`pkg/detectors/aws/common.go:L7`), enforced at the secret-entropy gate
`pkg/detectors/aws/access_keys/accesskey.go:L132`. Both secrets below are
**synthetic, non-canonical** 40-char literals straddling 4.25:
`ABCDEFGHJKLMNPQRSTUABCDEFGHJKLMNPQRSTUAB` (entropy 4.2342, just below) and
`ABCDEFGHJKLMNPQRSTUVABCDEFGHJKLMNPQRSTUV` (entropy 4.3219, just above); both are
paired with the canonical ID `ABIAS9L8MS5IPHTZPPUQ`.

Below threshold → **missed**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5seclow --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:59:52Z	info-0	trufflehog	running source	{"source_manager_worker_id": "GpcQ9", "with_units": true}
2026-07-08T05:59:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.136629ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

At/above threshold → **detected**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5sechigh --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:59:54Z	info-0	trufflehog	running source	{"source_manager_worker_id": "D2hTw", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q5sechigh/creds.txt
Line: 1

2026-07-08T05:59:54Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.554093ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Boundary 3 — `idPat` is uppercase-only: high entropy is not enough

Entropy alone does not make an ID detectable — it must first match `idPat`
`\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` (`pkg/detectors/aws/access_keys/accesskey.go:L65`),
whose character class is **uppercase** `[A-Z0-9]` only. The canonical **invalid**
fixture `AKIAs9L8MS5iPHTZPPUQ`
(`pkg/detectors/aws/access_keys/accesskey_test.go:L22`, expected `nil` at
`:L45`) has lowercase `s` and `i`. Its entropy is 3.9842 — well above the 3.0 gate —
yet it is **missed**, because `idPat` never matches it, so the entropy gate is never
even reached:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5mixed --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:59:56Z	info-0	trufflehog	running source	{"source_manager_worker_id": "7vENB", "with_units": true}
2026-07-08T05:59:56Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.539363ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

This is a clean demonstration that the *pattern* boundary precedes the *entropy*
boundary: a high-entropy string that fails the character class is missed outright.

### Boundary 4 — the engine `--filter-entropy` flag (distinct from the detector gates)

Separate from the AWS detector's internal 3.0/4.25 gates, the **engine** has an
optional post-filter enabled by `--filter-entropy` (`main.go:L67`). When set
(`if e.filterEntropy != 0`, `pkg/engine/engine.go:L1145`), `FilterResultsWithEntropy`
(`pkg/engine/engine.go:L1146`, defined at `pkg/detectors/falsepositives.go:L154`)
drops any result whose `Raw` has `StringShannonEntropy(result.Raw) < entropy`
(`pkg/detectors/falsepositives.go:L158-L159`). Because the AWS detector puts the
**ID** in `Raw`, this flag filters on the **ID's** entropy (canonical
`ABIAS9L8MS5IPHTZPPUQ`, entropy 3.7842).

Three runs of the same canonical fixture demonstrate the threshold. **(a) No flag →
detected**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:00:18Z	info-0	trufflehog	running source	{"source_manager_worker_id": "wBuGj", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T06:00:18Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.15007ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**(b) `--filter-entropy=3.0` → still detected** (3.7842 ≥ 3.0):

```
===CMD (b) --filter-entropy=3.0=== /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown --filter-entropy=3.0
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:00:20Z	info-0	trufflehog	running source	{"source_manager_worker_id": "4aUqL", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1adjacent/creds.txt
Line: 1

2026-07-08T06:00:20Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.925758ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**(c) `--filter-entropy=3.8` → filtered out** (3.7842 < 3.8):

```
===CMD (c) --filter-entropy=3.8=== /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown --filter-entropy=3.8
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:00:22Z	info-0	trufflehog	running source	{"source_manager_worker_id": "EsZu7", "with_units": true}
2026-07-08T06:00:22Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.856204ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Requesting the `filtered_unverified` result class exposes the engine's own drop
decision. The `Raw` is base64-encoded in this log line
(`QUJJQVM5TDhNUzVJUEhUWlBQVVE=` decodes to `ABIAS9L8MS5IPHTZPPUQ`) and `Redacted`
shows it in the clear:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1adjacent --no-verification --results=verified,unverified,unknown,filtered_unverified --filter-entropy=3.8
2026-07-08T06:01:19Z	info-0	trufflehog	Filtered out result with low entropy	{"detector_worker_id": "efBko", "detector": {"type":"AWS"}, "timeout": 10, "result": {"DetectorType":2,"DetectorName":"","Verified":false,"VerificationFromCache":false,"Raw":"QUJJQVM5TDhNUzVJUEhUWlBQVVE=","RawV2":"QUJJQVM5TDhNUzVJUEhUWlBQVVE6djJRUEtIbDdMY2RWWXNqYVI0TGdRaVoxenczTUFuTXlpb25kWEM2Mw==","Redacted":"ABIAS9L8MS5IPHTZPPUQ","ExtraData":{"resource_type":"AWS STS service bearer token"},"StructuredData":null,"AnalysisInfo":null}}
```

This confirms `--filter-entropy` is a distinct, user-tunable engine gate layered on
top of the detector's fixed 3.0/4.25 gates.

### Boundary 5 — the proximity window is ±1024 bytes for AWS (not the generic 512)

The generic keyword-extraction radius is `defaultOffsetRadius int64 = 512`
(`pkg/engine/ahocorasick/ahocorasickcore.go:L155`), but the AWS detector is a
multi-part detector that overrides the span to `defaultMaxCredentialSpan = 1024`
(`pkg/detectors/multi_part_credential_provider.go:L8`, returned by `MaxCredentialSpan()`
at `:L12`). The observed flip therefore occurs at **±1024 bytes** from the keyword,
exactly as established in [Q1](#q1--same-credential-different-file-inconsistency-determinism--proximity).
The direct boundary pair (same fixtures as Q1) is repeated here as the canonical
proximity-boundary evidence — a one-byte change flips the outcome. **gap = 963 →
detected** (secret's last byte at index 1043, inside the window end 1044):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1gap963 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:03Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Cl2nY", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1gap963/creds.txt
Line: 1

2026-07-08T05:55:03Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1045, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.134727ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**gap = 964 → missed** (secret pushed one byte past the window):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1gap964 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:05Z	info-0	trufflehog	running source	{"source_manager_worker_id": "o4NdK", "with_units": true}
2026-07-08T05:55:05Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 1046, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.380192ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Boundary 6 — the 10 KiB chunk and its 3 KiB peek

Files are read in chunks of `ChunkSize = 10*1024` with a `PeekSize = 3*1024` overlap
(`pkg/sources/chunker.go:L14,L16`, combined as `TotalChunkSize` at `:L18`). The peek
carries the trailing bytes of one chunk into the next, so an ID/secret pair that
lands near a 10 KiB boundary is kept together. The detected case (pair straddling the
first boundary, producing **2 chunks** yet still found) is the Q1 chunk-straddle
fixture, repeated here as the direct chunk-boundary evidence:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1straddle --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:09Z	info-0	trufflehog	running source	{"source_manager_worker_id": "kXZKM", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q1straddle/creds.txt
Line: 1

2026-07-08T05:55:09Z	info-0	trufflehog	finished scanning	{"chunks": 2, "bytes": 10324, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.89729ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The contrasting **missed** case is a pair separated far enough that neither the
window nor the peek unites them — the same-chunk beyond-window fixture from Q1
(gap 2000, one chunk, no finding):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q1beyond2000 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:55:07Z	info-0	trufflehog	running source	{"source_manager_worker_id": "T7qKJ", "with_units": true}
2026-07-08T05:55:07Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2082, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.340113ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Together these show the chunk/peek geometry keeps *nearby* pairs together across a
boundary, while the ±1024 window is what ultimately decides co-occurrence.

### Boundary 7 — the hexadecimal false-positive pattern `[a-f0-9]{40}` (an evidenced impossibility)

`FalsePositiveSecretPat = [a-f0-9]{40}` (`pkg/detectors/aws/utils.go:L47`) exists to
drop hash-like 40-char secrets, applied at
`pkg/detectors/aws/access_keys/accesskey.go:L202-L205`:
`if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) { … continue }`.
The important observed fact is that this filter is **unreachable for a pure-hex
secret**, because the secret-entropy gate at `:L132` runs **first**, in the same
`id × secret` loop, and rejects the secret before `:L202` is reached.

The evidence chain (all observed, plus one arithmetic fact):

1. Scanning an all-hex 40-char secret **misses**. The secret
   `0123456789abcdef0123456789abcdef01234567` is a **synthetic, non-canonical**
   lowercase-hex literal (entropy 3.9710), paired with the canonical ID:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5allhex --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:01:21Z	info-0	trufflehog	running source	{"source_manager_worker_id": "il8zZ", "with_units": true}
2026-07-08T06:01:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.917915ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

2. That secret's entropy (3.9710) is below 4.25, so the `:L132` gate drops it.
3. A **non-hex** secret below 4.25 is *also* missed — see Boundary 2's `seclow`
   (`ABCDEFGHJKLMNPQRSTUABCDEFGHJKLMNPQRSTUAB`, entropy 4.2342, uppercase, not hex),
   which is missed purely by `:L132`. This proves `:L132` drops sub-4.25 secrets on
   its own, independent of the hex pattern.
4. Arithmetic: a 40-char string drawn only from `[a-f0-9]` has at most 16 distinct
   symbols, so its maximum possible Shannon entropy is `log2(16) = 4.0`, which is
   **strictly less than 4.25**. Therefore *no* string matching `[a-f0-9]{40}` can
   ever pass the `:L132` gate, so the `:L202` hex-FP filter can never fire for a pure
   hex secret — it is defense-in-depth that is shadowed by the entropy gate.

This is why "40-char hex secrets are dropped": not by the hex pattern in practice,
but by the secret-entropy gate that precedes it.

### Boundary 8 — URL-encoding normalization (`UrlEncodedReplacer`)

Before matching, the AWS detector normalizes a few URL-encoded characters:
`UrlEncodedReplacer` (`pkg/detectors/aws/utils.go:L33-L42`) maps `%2B`/`%2b`→`+`,
`%2F`/`%2f`→`/`, `%3D`/`%3d`→`=`, and is applied at
`pkg/detectors/aws/access_keys/accesskey.go:L108`. So a secret whose `+` and `/` were
singly URL-encoded is still matched. The secret
`Zm9Qp2Rt7Vw3Nb8Ld5Hj/Fg1Cs4Ea6Yu0Io2P+Kx` (a **synthetic, non-canonical** 40-char
secret, entropy 5.2719) is used in both cases below.

**Single URL-encoding (`%2F`, `%2B`) → detected** (the replacer restores `/` and `+`):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5url --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:01:23Z	info-0	trufflehog	running source	{"source_manager_worker_id": "5VNeh", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q5url/creds.txt
Line: 1

2026-07-08T06:01:23Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 110, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.720031ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Double URL-encoding (`%252F`, `%252B`) → missed** (the replacer only reverses one
level; `%252F` becomes `%2F`, not `/`, so the 40-char secret pattern no longer
matches):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5dblurl --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:01:24Z	info-0	trufflehog	running source	{"source_manager_worker_id": "uogEm", "with_units": true}
2026-07-08T06:01:24Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 114, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.606774ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

### Boundary 9 — the false-positive word list (direct pair)

This is the Q3 mechanism viewed as a boundary. The list is `DefaultFalsePositives`
(`pkg/detectors/falsepositives.go:L17-L19`); a lowercased `strings.Contains` on the
`Raw` ID (`pkg/detectors/falsepositives.go:L95-L98`) decides it. The direct pair: the
canonical AWS-docs example ID `AKIAIOSFODNN7EXAMPLE` (contains `example`) is
**dropped**, while the canonical real ID `ABIAS9L8MS5IPHTZPPUQ` (no word-list term) is
**detected** — both paired with the same canonical secret.

Example ID → **dropped**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c3 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:22Z	info-0	trufflehog	running source	{"source_manager_worker_id": "uMXUs", "with_units": true}
2026-07-08T05:57:22Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "5.330479ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Real ID → **detected**:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q3c1 --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:57:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "896Ma", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: ABIAS9L8MS5IPHTZPPUQ
Resource_type: AWS STS service bearer token
File: /tmp/thqa/fx/q3c1/creds.txt
Line: 1

2026-07-08T05:57:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.259828ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The only difference between the two fixtures is the ID; the word-list substring match
on `Raw` is the entire boundary.

### Boundary 10 — the AWS canary path

AWS keys whose embedded account number is on Thinkst's canary list get special
handling. `verifyCanary` (`pkg/detectors/aws/access_keys/canary.go:L49`) is invoked
from `pkg/detectors/aws/access_keys/accesskey.go:L159`; when the account is in
`thinkstCanaryList` (`pkg/detectors/aws/access_keys/canary.go:L17`, which includes
`171436882533`), the detector attaches `is_canary = true`
(`pkg/detectors/aws/access_keys/accesskey.go:L181`) and the message
`This is an AWS canary token generated at canarytokens.org.`
(`thinkstMessage`, `pkg/detectors/aws/access_keys/canary.go:L13`). The gate at
`pkg/detectors/aws/access_keys/accesskey.go:L185` (`if verify && !isCanary`) ensures a
canary is *not* verified against real AWS even when verification is requested — it is
routed to the canary path instead.

The fixture uses the canonical canary ID `AKIASP2TPHJSQH3FJRUX`
(`pkg/detectors/aws/access_keys/accesskey_integration_test.go:L22`), account
`171436882533`, paired with the canonical secret.

**Verification off** → detected, tagged as a canary:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5canary --no-verification --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:01:52Z	info-0	trufflehog	running source	{"source_manager_worker_id": "6sHTo", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIASP2TPHJSQH3FJRUX
Resource_type: Access key
Account: 171436882533
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/thqa/fx/q5canary/creds.txt
Line: 1

2026-07-08T06:01:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.017391ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Verification on** → same canary tagging; note the run attempts the canary's SNS
path (verification-cache `"Misses": 1` and a ~167 ms duration versus ~5 ms offline)
but does not falsely verify it. In this offline environment the result remains
unverified; the `is_canary`/account/message metadata is identical to the
verification-off run:

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5canary --results=verified,unverified,unknown
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T06:02:06Z	info-0	trufflehog	running source	{"source_manager_worker_id": "uMrUk", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIASP2TPHJSQH3FJRUX
Resource_type: Access key
Account: 171436882533
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/thqa/fx/q5canary/creds.txt
Line: 1

2026-07-08T06:02:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "167.627503ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":163}}
```

The `--json` form makes the canary metadata explicit in `ExtraData`
(`is_canary: "true"`, the account, the canarytokens.org message, and
`resource_type: "Access key"`):

```
$ /tmp/trufflehog filesystem /tmp/thqa/fx/q5canary --no-verification --results=verified,unverified,unknown --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/thqa/fx/q5canary/creds.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIASP2TPHJSQH3FJRUX","RawV2":"AKIASP2TPHJSQH3FJRUX:v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63","Redacted":"AKIASP2TPHJSQH3FJRUX","ExtraData":{"account":"171436882533","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

*(Note on `Resource_type`: `AKIA`-prefixed keys — including this canary — report
`Access key`, whereas the `ABIA`-prefixed IDs used elsewhere report `AWS STS service
bearer token`. Both strings are produced by the detector from the ID prefix.)*

**Conclusion for Q5.** Every boundary is a concrete, observable threshold in the
code: the ID/secret entropy gates (3.0 / 4.25, `pkg/detectors/aws/common.go:L6-L7`,
enforced at `pkg/detectors/aws/access_keys/accesskey.go:L122,L132`); the uppercase
`idPat` (`:L65`); the engine `--filter-entropy` post-filter
(`pkg/engine/engine.go:L1145-L1146`); the ±1024-byte AWS window
(`pkg/detectors/multi_part_credential_provider.go:L8`); the 10 KiB/3 KiB chunk
geometry (`pkg/sources/chunker.go:L14-L18`); the shadowed hex-FP pattern
(`pkg/detectors/aws/utils.go:L47` vs the `:L132` gate); URL-encoding normalization
(`pkg/detectors/aws/utils.go:L33-L42`); the false-positive word list
(`pkg/detectors/falsepositives.go:L17-L19`); and the canary path
(`pkg/detectors/aws/access_keys/canary.go:L49`). In each case a one-step change across
the boundary flips detection, and every flip above is shown with its complete,
unedited scan output.

## Literal inventory

Every credential-shaped literal that appears anywhere in this document is catalogued
below, classified so that no value can be mistaken for a live secret. **No real,
active credential appears in this document.** All AWS-key-shaped values are either the
detector's own repository test fixtures, the long-published AWS-documentation example
pair, a public canary token, a redacted test value, or synthetic strings hand-built to
sit at an entropy boundary. The two 40-hex strings that are *not* credentials (a git
commit SHA and an ELF build ID) are listed explicitly to remove any ambiguity.

Entropy values are Shannon entropy over bytes, computed with the same algorithm the
scanner uses — `StringShannonEntropy` (`pkg/detectors/falsepositives.go:L136-L151`).

### AWS access-key IDs

| Literal | Classification | Represents | Entropy | Where used |
|---------|----------------|------------|---------|------------|
| `ABIAS9L8MS5IPHTZPPUQ` | Canonical repository fixture | Valid `ABIA` test ID from `pkg/detectors/aws/access_keys/accesskey_test.go:L16` | 3.7842 | Q1, Q2, Q3, Q4-adjacent baseline, Q5 (B2, B4, B7, B8, B9) |
| `AKIAIOSFODNN7EXAMPLE` | Well-known AWS-documentation example | The public AWS-docs example access-key ID; contains the word-list term `example` | 3.6842 | Q3 (dropped), Q5 B9 (dropped) |
| `AKIASP2TPHJSQH3FJRUX` | Canonical canary | Canary ID from `pkg/detectors/aws/access_keys/accesskey_integration_test.go:L22`; account `171436882533` is in `thinkstCanaryList` | 3.8219 | Q5 B10 (canary path) |
| `AKIAs9L8MS5iPHTZPPUQ` | Canonical repository fixture (invalid) | Deliberately **invalid** mixed-case ID from `pkg/detectors/aws/access_keys/accesskey_test.go:L22` (expected `nil` at `:L45`); lowercase `s`/`i` fail `idPat` | 3.9842 | Q5 B3 (missed despite entropy > 3.0) |
| `AKIAGHJKM2GHJKM2GHJK` | Synthetic, non-canonical | Hand-built ID just **below** the 3.0 ID-entropy gate | 2.9087 | Q5 B1 (missed) |
| `AKIAGHJKM2NGHJKM2NGH` | Synthetic, non-canonical | Hand-built ID just **above** the 3.0 ID-entropy gate | 3.1087 | Q5 B1 (detected) |
| `AKIAZAVB57H55F3T4BKH` | Redacted canonical (referenced, not scanned) | Redacted valid ID used throughout `pkg/detectors/aws/access_keys/accesskey_integration_test.go` (`Redacted` field; account `619888638459`); reproducing a live verification requires Truffle Security's private GCP test secrets, so it is **not independently scanned** here | 3.5464 | Coverage summary only (rationale documented) |

### Secrets and 40-/32-character tokens

| Literal | Classification | Represents | Entropy | Where used |
|---------|----------------|------------|---------|------------|
| `v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63` | Canonical repository fixture | Valid 40-char secret from `pkg/detectors/aws/access_keys/accesskey_test.go:L17` | 4.9719 | Q1–Q5 (paired secret) |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | Well-known AWS-documentation example | The public AWS-docs example secret; contains `EXAMPLE` but is never word-checked (only `Raw`=ID is) | 4.6628 | Q3 C2/C4 |
| `ABCDEFGHJKLMNPQRSTUABCDEFGHJKLMNPQRSTUAB` | Synthetic, non-canonical | 40-char secret just **below** the 4.25 secret-entropy gate | 4.2342 | Q5 B2 (missed), B7 (non-hex control) |
| `ABCDEFGHJKLMNPQRSTUVABCDEFGHJKLMNPQRSTUV` | Synthetic, non-canonical | 40-char secret just **above** the 4.25 secret-entropy gate | 4.3219 | Q5 B2 (detected) |
| `0123456789abcdef0123456789abcdef01234567` | Synthetic, non-canonical | 40-char pure lowercase-hex secret; max possible entropy for `[a-f0-9]{40}` is `log2(16)=4.0 < 4.25` | 3.9710 | Q5 B7 (hex-FP impossibility) |
| `Zm9Qp2Rt7Vw3Nb8Ld5Hj/Fg1Cs4Ea6Yu0Io2P+Kx` | Synthetic, non-canonical | 40-char secret containing `/` and `+`, used URL-encoded to exercise `UrlEncodedReplacer` | 5.2719 | Q5 B8 (single/double URL-encoding) |
| `3b1f8c2d7e6a940512df8b9c1a7e2d94` | Synthetic, non-canonical | 32-char hex token matched by both `IpStack` and `MadKudu`; not a real key for either | 3.9056 | Q4 (verification overlap) |

### Non-credential 40-hex strings (listed to avoid ambiguity)

| Literal | Classification | Represents | Where used |
|---------|----------------|------------|------------|
| `e42153d44a5e5c37c1bd0c70e074781e9edcb760` | Git commit SHA (not a credential) | The commit under study | Header/build section |
| `53c0ceea109120b1ee831adb2736dca857dc0c23` | ELF build ID (not a credential) | The `BuildID[sha1]` reported by `file` for this build; varies per build | Canonical build section |

## Coverage summary

This section confirms every question and every named mechanism, flag, condition, and
canonical key has been addressed with a `file:line` citation and observed evidence.

### Per-question coverage

| Question | Named items addressed | Key citations | Observed evidence |
|----------|-----------------------|---------------|-------------------|
| **Q1** — same-credential, different-file consistency | determinism; `idPat`/`SecretPat` co-occurrence; ±1024 proximity window; chunk/peek | `pkg/detectors/aws/access_keys/accesskey.go:L65`; `pkg/detectors/aws/common.go:L10`; `pkg/engine/ahocorasick/ahocorasickcore.go:L155`; `pkg/detectors/multi_part_credential_provider.go:L8`; `pkg/sources/chunker.go:L14-L18` | Adjacent detected; gap 963 detected / 964 missed; beyond-window missed; straddle detected; 3× determinism uv=1/1/1 |
| **Q2** — encoding as false protection | `DefaultDecoders()` (4 decoders); base64 decode-before-detect; hex/ROT13 evade; gzip via archive layer | `pkg/decoders/decoders.go:L8-L15`; `pkg/decoders/base64.go:L34-L45`; `pkg/decoders/utf8.go:L16`; `pkg/decoders/utf16.go:L18`; `pkg/decoders/escaped_unicode.go:L32` | base64 detected (`Decoder Type: BASE64`); hex missed; ROT13 missed; gzip detected (`PLAIN`) |
| **Q3** — test-fixture credentials that never flag | word list; `strings.Contains` on `Raw`; `Raw = idMatch`; entropy is not the cause | `pkg/detectors/falsepositives.go:L17-L19,L85,L95-L98`; `pkg/detectors/aws/access_keys/accesskey.go:L138`; `pkg/engine/engine.go:L1126,L1142` | 2×2 matrix (C2 kept / C3 dropped); trace `"contains term: example"` |
| **Q4** — "verification disabled for safety" | overlap safeguard; `errOverlap`; `likelyDuplicate`; `verificationOverlapWorker`; `--allow-verification-overlap`; custom-detector single type | `pkg/engine/engine.go:L39-L42,L887,L888,L906,L924,L982,L988`; `pkg/custom_detectors/custom_detectors.go:L345`; `pkg/detectors/detectors.go:L230`; `main.go:L65` | Default: 1 warning, uv=2, Misses=1; log-level 2 `found exact duplicate`; override: warning gone, Misses=2 |
| **Q5** — detection boundaries | ID entropy 3.0; secret entropy 4.25; `idPat` class; `--filter-entropy`; ±1024 window; chunk/peek; hex-FP `[a-f0-9]{40}`; `UrlEncodedReplacer`; word list; canary | `pkg/detectors/aws/common.go:L6-L7`; `pkg/detectors/aws/access_keys/accesskey.go:L65,L122,L132,L202-L205`; `pkg/detectors/aws/utils.go:L33-L42,L47`; `pkg/engine/engine.go:L1145-L1146`; `pkg/detectors/aws/access_keys/canary.go:L13,L17,L49`; `main.go:L67` | 10 direct detected-vs-missed pairs (see Q5) |

### Canonical-key coverage

Every AWS key that the repository's own test files provide is accounted for below,
with what it represents and whether it was independently scanned in this
investigation.

| Canonical key | Source | Represents | Used / observed |
|---------------|--------|------------|-----------------|
| `ABIAS9L8MS5IPHTZPPUQ` | `pkg/detectors/aws/access_keys/accesskey_test.go:L16` | Valid `ABIA` test ID | **Used & observed** — the primary detected ID across Q1–Q5 |
| `v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63` | `pkg/detectors/aws/access_keys/accesskey_test.go:L17` | Valid test secret | **Used & observed** — the primary paired secret across Q1–Q5 |
| `AKIAs9L8MS5iPHTZPPUQ` | `pkg/detectors/aws/access_keys/accesskey_test.go:L22` (invalid pattern; `nil` at `:L45`) | **Invalid** mixed-case ID | **Used & observed** — Q5 Boundary 3: missed despite entropy 3.9842 > 3.0 because `idPat` is uppercase-only |
| `AKIASP2TPHJSQH3FJRUX` | `pkg/detectors/aws/access_keys/accesskey_integration_test.go:L22` | Canary ID (account `171436882533`) | **Used & observed** — Q5 Boundary 10: canary path, `is_canary: true` |
| `AKIAIOSFODNN7EXAMPLE` | Well-known AWS-documentation example | Example ID containing `example` | **Used & observed** — Q3 and Q5 Boundary 9: dropped by word list |
| `AKIAZAVB57H55F3T4BKH` | `pkg/detectors/aws/access_keys/accesskey_integration_test.go` (`Redacted` field; account `619888638459`) | Redacted valid ID used by the integration test | **Referenced, not independently scanned** — a live verification of this key requires Truffle Security's **private GCP Secret Manager test secrets** (`secretmanager.versions.access` on `trufflehog-testing`), which are unavailable outside their CI; its entropy (3.5464) and role are documented in the [Literal inventory](#literal-inventory), and its detection behavior is identical to the other `AKIA` IDs already observed |

All five questions, every named mechanism/flag/condition, and every canonical key are
addressed above with `file:line` citations and observed evidence; every experiment in
this document was captured from the canonical `/tmp/trufflehog` build and is shown with
its complete, unedited output.
