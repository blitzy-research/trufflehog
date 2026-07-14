# TruffleHog v3 — Investigation of Four Deterministic Scanning Behaviors (source commit e42153d44a5e)

This document answers, from **observed runtime behavior**, four questions about how the TruffleHog v3 secret scanner treats AWS (and a few other) credentials: (Q1) why valid AWS credentials are detected in some files but *completely missed or reported differently* in others, even though the behavior is deterministic and *the same file always produces the same result*; (Q2) whether developers who *encode sensitive data before committing it* thereby fool the scanner; (Q3) why some test-fixture credentials that *follow the right format* are never flagged; and (Q4) what triggers the CI-log warning that *verification was disabled for safety*. Every behavioral claim below is backed by the exact command that produced it and its complete, unedited output, and is grounded to a specific `file:line` in the source.

- **Module under test:** `github.com/trufflesecurity/trufflehog/v3` `[go.mod:L1]`.
- **Language / toolchain:** language floor `go 1.23.1`, pinned `toolchain go1.24.2` `[go.mod:L3-L5]`; all builds and runs used `go1.24.2` with `GOTOOLCHAIN=local` — the project's own documented toolchain (evidence in Section 1).
- **Source baseline commit:** `e42153d44a5e` is the **TruffleHog source tree under investigation**, i.e. the *source baseline* — **not** the current repository `HEAD`. `git rev-parse --short e42153d44a5e` resolves to `e42153d4` (shown in Section 7). The only change to the repository relative to that baseline is this single documentation file, regardless of how many documentation commits refine it: `git diff --name-only e42153d4..HEAD` lists exactly that one file.

## Methodology

**Run-first chronology (Observed process).** This investigation was performed by **building and running the scanner first**, capturing the complete output of each command, and only then writing this document from that captured output — never from code-reading alone. Every transcript below is the literal, unedited output of the command shown immediately above it — with standard error and standard output merged exactly as a terminal interleaves them (the startup banner and the `running source` / `finished scanning` log lines are emitted to stderr) — and contains no editorial annotations, paraphrase, or elision. A few commands deliberately end in a shell `; echo "exit: $?"` so the process exit status is itself emitted by the command shown. The fixtures were produced by the deterministic generator commands shown alongside each scenario; ephemeral fields vary per run exactly as described in the transcription note below.

Every observation was produced through the **canonical `trufflehog filesystem` entry point** in its **default configuration** — no debug hooks, mocks, bypasses, or synthetic stand-ins. Fixtures were crafted under `/tmp` (outside the source tree) to isolate one boundary variable at a time, and each scenario was executed against a freshly built binary at `/tmp/trufflehog_bin`. Observational flags (e.g. `--no-verification`, `--results=filtered_unverified`, `--scan-entire-chunk`, `--allow-verification-overlap`) are used **only to reveal or contrast a boundary**; the default behavior is always shown first. Deterministic claims (Q1) were confirmed by scanning the *same unchanged* input repeatedly.

**Observed vs Inferred.** Throughout, facts read directly from captured command output are labelled **Observed**. Statements derived from reading the source (a threshold, a code path, a cause that cannot be isolated purely at runtime) are labelled **Inferred (source-derived)** and grounded to a `file:line`. Where the checked-out code diverges from newer public documentation, the divergence is flagged explicitly (see Q2).

> **Note on transcription.** In the scan outputs below, the two structured log lines (`running source` and `finished scanning`) are **TAB-separated** between fields, exactly as emitted; the tabs are preserved verbatim. Ephemeral fields (timestamps, `source_manager_worker_id`, `scan_duration`, `VerificationTimeSpentMS`) necessarily differ from run to run — the values shown are from the specific run whose command is quoted.

## Section 1 — Build & Invocation

**Toolchain (Observed).** The build used the project's pinned toolchain; `GOTOOLCHAIN=local` means the installed `go1.24.2` is used directly with no auto-download, and the existing module graph is consumed as-is:

```
$ go version
go version go1.24.2 linux/amd64
$ go env GOVERSION GOTOOLCHAIN CGO_ENABLED
go1.24.2
local
1
$ go mod verify
all modules verified
```

**Build command and binary (Observed).** Built from the repository root; the result is a large, statically linked ELF (`CGO_ENABLED=0`):

```
$ CGO_ENABLED=0 go build -o /tmp/trufflehog_bin . ; echo "build exit: $?"
build exit: 0
$ ls -la /tmp/trufflehog_bin
-rwxr-xr-x 1 root root 194310114 Jul 14 00:05 /tmp/trufflehog_bin
$ file /tmp/trufflehog_bin
/tmp/trufflehog_bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=647d18d17c6d615d756fef8c66aba25b13c6c24d, with debug_info, not stripped
```

**Observed:** the build exits `0` and produces a ~186 MB (194,310,114-byte) statically linked binary at `/tmp/trufflehog_bin`. On this warm module cache (already populated during environment setup, confirmed by `go mod verify` → "all modules verified" above), an incremental relink measured a few seconds; no cold-cache figure is asserted here because it was not independently measured. The file's SHA1 `BuildID` and the `ls -la` modification time are per-build artifacts of the Go linker and filesystem and therefore differ on each rebuild (a re-run will show a different BuildID and timestamp), whereas the binary size (194,310,114 bytes) and its runtime behavior are stable. **No dependency was added, upgraded, downgraded, or removed.**

**Version banner (Observed).**

```
$ /tmp/trufflehog_bin --version
trufflehog dev
```

The version string `trufflehog dev` is a **source-build artifact** (a build from source with no VCS-stamped release version); it is **not** a released version number and should not be mistaken for one. **Inferred (source-derived):** the version is wired by `cli.Version("trufflehog " + version.BuildVersion)` `[main.go:L270]`, and the literal `"dev"` comes from `var BuildVersion = "dev"` `[pkg/version/version.go:L3]`.

**Startup banner (scope).** On a **default plain-text scan run** — i.e. every scan transcript in this document — TruffleHog prints the following banner to **stderr** before any results. **Inferred (source-derived):** it is emitted by `fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")` `[main.go:L498]`:

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

This banner is specific to the plain-text scan path; the `--version`, `--help`, error, and `--json` output paths do not emit it.

**Default `--results` value (Observed, verbatim from `filesystem --help`):**

```
$ /tmp/trufflehog_bin filesystem --help 2>&1 | grep -A3 -- --results
      --results=RESULTS          Specifies which type(s) of results to
                                 output: verified, unknown, unverified,
                                 filtered_unverified. Defaults to
                                 verified,unverified,unknown.
```

The default output classes are `verified,unverified,unknown` and therefore **exclude** `filtered_unverified` `[main.go:L61]`. This default is pivotal for Q3: findings suppressed by the false-positive layer fall into the `filtered_unverified` class, which is not printed unless explicitly requested.

**Canonical entry point.** `[main.go:L143]` defines the command `filesystemScan = cli.Command("filesystem", "Find credentials in a filesystem.")` and `[main.go:L144]` its positional argument `filesystemPaths = filesystemScan.Arg("path", "Path to file or directory to scan.").Strings()`. All observations below invoke `/tmp/trufflehog_bin filesystem <path>`.

**Observational flags used (only to reveal boundaries, never as remediation), each grounded:** `--no-update` (skip the self-update check, for clean offline output) `[main.go:L73]`, `--no-verification` (deterministic offline output with no network verification) `[main.go:L59]`, `--results=filtered_unverified` `[main.go:L61]`, `--scan-entire-chunk` (Hidden, default `false`) `[main.go:L68]`, and `--allow-verification-overlap` `[main.go:L65]`. Two further flags exist and are named for completeness: `--filter-unverified` `[main.go:L66]` and `--compare-detection-strategies` (Hidden, default `false`) `[main.go:L69]`.

## Section 2 — Q1: Detected in some files, missed or reported differently in others (deterministically)

**Answer in brief (Observed + Inferred).** The AWS access-key pipeline is a chain of *independent gates*: keyword pre-filter → id regex → secret regex (exactly 40 chars) → ID↔secret proximity window → entropy floors → false-positive filter (Q3). A credential is reported **only if every gate passes**. Because every gate is a fixed threshold or exact pattern with **no randomness**, the outcome is fully determined by the input — so *the same file always produces the same result*, yet two files that "look the same" to a human diverge the moment one of them trips a gate. Below, each gate is isolated with its own `/tmp` fixture (generation command shown), the canonical command, and its complete output. The shared baseline values are the 20-character id `AKIAZ3JQK7X1YWVUT5RQ` and the 40-character secret `wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h`.

### Q1-pipeline — Source-to-report flow: where each Q1 boundary lives (`filesystem` → chunk → decode → detect → filter → verify → print)

Before isolating the individual gates, this subsection traces the exact code path a byte travels through under `trufflehog filesystem`, so each Q1 boundary below can be pinned to the stage that enforces it. Every step is **Inferred (source-derived)** from the checked-out code; the byte counts it produces are corroborated by the **Observed** `bytes` field of the Q1 transcripts (e.g. `bytes: 2632` for the 2632-byte `beyond_span.txt` in Q1-E, `bytes: 106` for the 106-byte baseline in Q1-A), which confirms whole small files arrive in a single chunk.

1. **Filesystem source walks the path and emits chunks.** `Source.scanFile` `[pkg/sources/filesystem/filesystem.go:L163]` builds a `chunkSkel := &sources.Chunk{…}` carrying the source metadata and the `Verify` flag `[pkg/sources/filesystem/filesystem.go:L181-L194]`, then hands the open file to the handler layer: `return handlers.HandleFile(fileCtx, inputFile, chunkSkel, sources.ChanReporter{Ch: chunksChan})` `[pkg/sources/filesystem/filesystem.go:L196]`. This is the canonical entry every `filesystem` scan uses.

2. **Handler dispatch (default vs. archive).** `handlers.HandleFile` `[pkg/handlers/handlers.go:L344]` picks a handler with `selectHandler` `[pkg/handlers/handlers.go:L308]`, `:L387` — the **default** (non-archive) handler for ordinary files `[pkg/handlers/handlers.go:L320]`, or an **archive** handler for compressed inputs `[pkg/handlers/handlers.go:L318]` (the branch that makes Q2-G's `.gz` credential detectable). It then delegates to `handler.HandleFile(processingCtx, rdr)` `[pkg/handlers/handlers.go:L388]` and funnels the produced pieces to the reporter via `handleChunksWithError(processingCtx, dataOrErrChan, chunkSkel, reporter)` `[pkg/handlers/handlers.go:L390]`.

3. **The default handler chunks the stream.** `defaultHandler.HandleFile` `[pkg/handlers/default.go:L39]` → `handleNonArchiveContent` `[pkg/handlers/default.go:L94]` creates the reader `chunkReader := sources.NewChunkReader()` `[pkg/handlers/default.go:L109]`, ranges over it `for data := range chunkReader(ctx, reader)` `[pkg/handlers/default.go:L110]`, and copies each piece out with `dataOrErr.Data = data.Bytes()` `[pkg/handlers/default.go:L121]`.

4. **Chunk sizing — the 10 KiB + 3 KiB window (binary units).** `NewChunkReader` `[pkg/sources/chunker.go:L67-L71]` returns a reader whose loop `[pkg/sources/chunker.go:L119-L127]` reads up to `ChunkSize` new bytes with `io.ReadFull` `[pkg/sources/chunker.go:L123]` and then appends a look-ahead of the next bytes with `chunkReader.Peek(...)` `[pkg/sources/chunker.go:L125-L126]`. The constants are **binary** KiB, not decimal KB: `ChunkSize = 10 * 1024` = **10 KiB = 10240 bytes** `[pkg/sources/chunker.go:L14]`, `PeekSize = 3 * 1024` = **3 KiB = 3072 bytes** `[pkg/sources/chunker.go:L16]`, and `TotalChunkSize = ChunkSize + PeekSize` = **13 KiB = 13312 bytes** `[pkg/sources/chunker.go:L18]`. So each chunk carries 10 KiB of *new* data plus a 3 KiB overlap into the following bytes. This overlap is why a credential straddling a 10 KiB boundary is still seen intact (the peek pulls the continuation into the same chunk), and — combined with the 1024-byte ID↔secret span of Q1-E — why the proximity gate is evaluated *within* a single 13 KiB chunk. All Q1/Q2/Q3 fixtures here are far below 10 KiB, so each is exactly one chunk (`"chunks": 1` in every transcript).

5. **Decode, then detect.** Back in the engine, each chunk is run through the four decoders in fixed order — outer loop `for chunk := range e.ChunksChan()` `[pkg/engine/engine.go:L781]`, inner loop `for _, decoder := range e.decoders` calling `decoded := decoder.FromChunk(chunk)` `[pkg/engine/engine.go:L784-L786]` (the shared-mutating-chunk mechanism of §3 / Q2-I) — and the decoded view is matched with `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` `[pkg/engine/engine.go:L795]`. `FindDetectorMatches` is where the **keyword pre-filter** (Q1-C: no `AKIA`/`ABIA`/`ACCA` ⇒ the AWS detector never runs) and the **detection-span window** (Q1-E: the ±1024-byte slice around the keyword) live, before the AWS detector's own gates — `idPat` shape, the exactly-40-character `SecretPat`, and the entropy floors (Q1-A/D/F) — decide whether a candidate is produced.

6. **False-positive filter, then the overlap/verify gate.** A surviving candidate is passed through the default false-positive check (Q3) and then the verification-overlap gate `if len(matchingDetectors) > 1 && !e.verificationOverlap {` `[pkg/engine/engine.go:L796]` (Q4) before any verification request is made.

7. **The printer emits the fields every transcript shows.** Results are rendered by the plain printer: the `✅ Found verified result` header `[pkg/output/plain.go:L52]` or the `Found unverified result` header `[pkg/output/plain.go:L55]`, an optional `Verification issue:` line for `VerificationError` `[pkg/output/plain.go:L56-L58]` (Q4's overlap warning), and the `Detector Type:` `[pkg/output/plain.go:L63]`, `Decoder Type:` `[pkg/output/plain.go:L64]`, and `Raw result:` `[pkg/output/plain.go:L65]` fields quoted throughout this document.

The determinism the user observes falls straight out of this flow: every stage is a fixed size, an exact pattern, or a constant threshold with **no randomness**, so a given file's bytes always traverse the same gates to the same verdict (the only run-to-run variation is cosmetic — print order under Q1-G's map/goroutine nondeterminism and the ephemeral log fields noted in the Methodology).

### Q1-A — Baseline: a well-formed credential is detected

Fixture generation (Observed command):

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'; SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = %s\naws_secret_access_key = %s\n' "$ID" "$SEC" > /tmp/thq1/detected.txt
```

Default configuration (verification **on**):

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/detected.txt --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:10Z	info-0	trufflehog	running source	{"source_manager_worker_id": "IYPj2", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/detected.txt
Line: 1

2026-07-13T18:52:10Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "141.457656ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":136}}
```

Same file with `--no-verification` (used for all subsequent Q1 runs to keep output deterministic and offline):

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/detected.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:12Z	info-0	trufflehog	running source	{"source_manager_worker_id": "rlQb9", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/detected.txt
Line: 1

2026-07-13T18:52:12Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.527976ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the credential is reported as `Detector Type: AWS`, `Decoder Type: PLAIN`, `Raw result: AKIAZ3JQK7X1YWVUT5RQ`, `unverified_secrets: 1`. Under the default (verification-on) run, one network verification was attempted (`"Misses":1`, `"VerificationTimeSpentMS":136`) but the synthetic key is not live, so it stays *unverified*; with `--no-verification` no attempt is made (`"Misses":0`, `"VerificationTimeSpentMS":0`) and the finding is otherwise identical.

**Inferred (source-derived) — the gate chain that passed here:** the keyword pre-filter matched `"AKIA"` `[pkg/detectors/aws/access_keys/accesskey.go:L70-L76]`; the id regex `idPat = \b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` `[pkg/detectors/aws/access_keys/accesskey.go:L65]` matched the 20-char id; the secret regex `SecretPat` `[pkg/detectors/aws/common.go:L10]` matched the 40-char secret; both cleared the entropy floors `RequiredIdEntropy = 3.0` / `RequiredSecretEntropy = 4.25` `[pkg/detectors/aws/common.go:L6-L7]` enforced at `[pkg/detectors/aws/access_keys/accesskey.go:L122]` and `[pkg/detectors/aws/access_keys/accesskey.go:L132]`; and the emitted `Result.Raw` is the id `[pkg/detectors/aws/access_keys/accesskey.go:L138]`.

### Q1-B — Determinism: the same file always produces the same result

The unchanged baseline file is scanned three times in a row; the command emits its own `=== run N ===` separators (so the separators are genuinely part of the captured output, not added afterward):

```
$ for i in 1 2 3; do echo "=== run $i ==="; /tmp/trufflehog_bin filesystem /tmp/thq1/detected.txt --no-update --no-verification; done
=== run 1 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:13Z	info-0	trufflehog	running source	{"source_manager_worker_id": "wKiJf", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/detected.txt
Line: 1

2026-07-13T18:52:13Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.269058ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
=== run 2 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:15Z	info-0	trufflehog	running source	{"source_manager_worker_id": "8bilE", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/detected.txt
Line: 1

2026-07-13T18:52:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.852356ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
=== run 3 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:17Z	info-0	trufflehog	running source	{"source_manager_worker_id": "cmriz", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/detected.txt
Line: 1

2026-07-13T18:52:17Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.35601ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** across all three runs the **core result lines** — the `Found unverified result` header, `Detector Type: AWS`, `Decoder Type: PLAIN`, `Raw result: AKIAZ3JQK7X1YWVUT5RQ`, `Resource_type: Access key`, `File`, `Line` — are **byte-identical**, along with `"chunks": 1, "bytes": 106, "unverified_secrets": 1`. Only ephemeral fields differ (`source_manager_worker_id`, timestamp, `scan_duration`). This is the direct runtime confirmation of the user's observation. **Inferred:** determinism follows from the pipeline having no randomized decision points — every gate above is a fixed threshold or exact regex.

### Q1-C — Keyword pre-filter: no `AKIA`/`ABIA`/`ACCA` ⇒ the AWS detector never runs

Fixture generation — a real 40-char secret plus an id-shaped token, but **no** AWS keyword substring:

```bash
SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'token_id = ZZZZ11112222333344445\ncredential = %s\n' "$SEC" > /tmp/thq1/no_keyword.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/no_keyword.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:36Z	info-0	trufflehog	running source	{"source_manager_worker_id": "IHzq6", "with_units": true}
2026-07-13T18:52:36Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 87, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.570984ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** no finding (`unverified_secrets: 0`) even though a valid 40-char secret is present in the file. **Inferred:** TruffleHog runs a detector only when one of its `Keywords()` is present in the chunk. The AWS access-key `Keywords()` are exactly `"AKIA"`, `"ABIA"`, `"ACCA"` `[pkg/detectors/aws/access_keys/accesskey.go:L70-L76]`; the Aho-Corasick pre-filter — `FindDetectorMatches` runs `ac.prefilter.Match(bytes.ToLower(chunkData))` `[pkg/engine/ahocorasick/ahocorasickcore.go:L241-L242]` — therefore never invokes the AWS detector's `FromData` for this file, so the secret is invisible. This is one primary cause of *completely missed*.

### Q1-D — The exactly-40-character secret boundary (`SecretPat`)

Two fixtures differing by a single trailing character (`${SEC%?}` removes the last byte):

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'; SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = %s\naws_secret_access_key = %s\n' "$ID" "$SEC"      > /tmp/thq1/secret40.txt   # 40-char secret
printf 'aws_access_key_id = %s\naws_secret_access_key = %s\n' "$ID" "${SEC%?}"  > /tmp/thq1/secret39.txt   # 39-char secret
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/secret40.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "lvaot", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/secret40.txt
Line: 1

2026-07-13T18:52:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.526219ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/thq1/secret39.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:20Z	info-0	trufflehog	running source	{"source_manager_worker_id": "wGXYk", "with_units": true}
2026-07-13T18:52:20Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.369944ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the 40-char file yields exactly one finding (`unverified_secrets: 1`, `bytes: 106`) — the full `Found unverified result` block names `Raw result: AKIAZ3JQK7X1YWVUT5RQ`; the 39-char file yields none (`unverified_secrets: 0`, `bytes: 105`). **Inferred:** `SecretPat = (?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)` `[pkg/detectors/aws/common.go:L10]` captures **exactly 40** base64-class characters and is anchored by boundary assertions on each side (a non-base64 character, or the start `\A` / end `\z` of the input). A 39-character run cannot satisfy `{40}`, so no secret match is produced and the detector emits no result; the boundary assertions also stop a longer run from yielding a 40-char sub-match unless it is flanked by a boundary. This is why credentials that "look the same" but differ by one secret character diverge deterministically.

### Q1-E — The 1024-byte ID↔secret credential span

Two fixtures place the id and secret adjacent (≈62 bytes) versus separated by ~2.5 KiB of filler (2569 filler bytes; ≈2632-byte file):

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'; SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf '%s\n%s\n' "$ID" "$SEC" > /tmp/thq1/within_span.txt
{ printf '%s\n' "$ID"; head -c 2569 < /dev/zero | tr '\0' 'x'; printf '\n%s\n' "$SEC"; } > /tmp/thq1/beyond_span.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/within_span.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:26Z	info-0	trufflehog	running source	{"source_manager_worker_id": "rNwPg", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/within_span.txt
Line: 1

2026-07-13T18:52:26Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.840921ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/thq1/beyond_span.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:27Z	info-0	trufflehog	running source	{"source_manager_worker_id": "lVBz9", "with_units": true}
2026-07-13T18:52:27Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2632, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.096209ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/thq1/beyond_span.txt --no-update --no-verification --scan-entire-chunk
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:29Z	info-0	trufflehog	running source	{"source_manager_worker_id": "TJRoQ", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq1/beyond_span.txt
Line: 1

2026-07-13T18:52:29Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 2632, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.463141ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the within-span file (`unverified_secrets: 1`, `bytes: 62`) is detected; the beyond-span file (`unverified_secrets: 0`, `bytes: 2632`) is **not** detected; re-running the **same** beyond-span file with `--scan-entire-chunk` **does** detect it (`unverified_secrets: 1`, same `bytes: 2632`). **Inferred:** the AWS detector is a multi-part credential provider with `defaultMaxCredentialSpan = 1024` `[pkg/detectors/multi_part_credential_provider.go:L8]`. By default the Aho-Corasick core feeds the detector only a window around the matched keyword (`calculateSpan`) `[pkg/engine/ahocorasick/ahocorasickcore.go:L79-L111]`; `--scan-entire-chunk` `[main.go:L68]` makes the engine install the whole-chunk span calculator — `if e.scanEntireChunk { ahoCOptions = append(ahoCOptions, ahocorasick.WithSpanCalculator(new(ahocorasick.EntireChunkSpanCalculator))) }` `[pkg/engine/engine.go:L525-L526]` — whose `EntireChunkSpanCalculator.calculateSpan` returns the entire chunk as the span `[pkg/engine/ahocorasick/ahocorasickcore.go:L61-L63]`. When the id and secret are more than 1024 bytes apart they never appear in the same window, so no `(id, secret)` pair is formed and the credential is deterministically missed — the second primary cause of *completely missed*.

### Q1-F — Entropy floors (`RequiredIdEntropy` 3.0 / `RequiredSecretEntropy` 4.25)

One fixture uses a shape-valid but low-entropy id; the other a shape/length-valid but low-entropy secret:

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'; SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = AKIAAAAAAAAAAAAAAAAA\naws_secret_access_key = %s\n' "$SEC" > /tmp/thq1/lowent_id.txt
printf 'aws_access_key_id = %s\naws_secret_access_key = aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaA\n' "$ID" > /tmp/thq1/lowent_secret.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/lowent_id.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:39Z	info-0	trufflehog	running source	{"source_manager_worker_id": "1t9Xn", "with_units": true}
2026-07-13T18:52:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.574228ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/thq1/lowent_secret.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:41Z	info-0	trufflehog	running source	{"source_manager_worker_id": "nI1r0", "with_units": true}
2026-07-13T18:52:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.750119ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** neither file produces a finding (`unverified_secrets: 0` in both), despite the id matching the `(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}` idPat shape `[pkg/detectors/aws/access_keys/accesskey.go:L65]` and the secret being a 40-char base64-class run. **Inferred:** the floors `RequiredIdEntropy = 3.0` and `RequiredSecretEntropy = 4.25` `[pkg/detectors/aws/common.go:L6-L7]` are enforced by `detectors.StringShannonEntropy` at `[pkg/detectors/aws/access_keys/accesskey.go:L122]` (id) and `[pkg/detectors/aws/access_keys/accesskey.go:L132]` (secret). Computed with TruffleHog's own `StringShannonEntropy` `[pkg/detectors/falsepositives.go:L136-L150]`, the low-entropy id `AKIAAAAAAAAAAAAAAAAA` ≈ **0.569** (< 3.0) and the low-entropy secret ≈ **1.000** (< 4.25), whereas the baseline id ≈ **4.022** and baseline secret ≈ **5.172** clear both floors. (Entropy magnitudes are Inferred — computed via the source formula — because the scanner does not print them; the finding/no-finding outcome is Observed.)

### Q1-G — "Reported differently" (1): canary tokens

The id embeds an account number that is on TruffleHog's built-in Thinkst canary list; the secret is the standard 40-char value:

```bash
SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = AKIAAYLPMN5HAAISUO2M\naws_secret_access_key = %s\n' "$SEC" > /tmp/thq1/canary.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/canary.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:46Z	info-0	trufflehog	running source	{"source_manager_worker_id": "lB1R8", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAYLPMN5HAAISUO2M
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
Resource_type: Access key
Account: 052310077262
File: /tmp/thq1/canary.txt
Line: 1

2026-07-13T18:52:46Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.017111ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** still `Detector Type: AWS`, but the finding now carries extra fields — `Message: This is an AWS canary token generated at canarytokens.org.`, `Is_canary: true`, `Account: 052310077262`. **Inferred:** the detector decodes the account number from the id and, when that account is in `thinkstCanaryList` `[pkg/detectors/aws/access_keys/canary.go:L17-L28]` (which contains `"052310077262"` at `[pkg/detectors/aws/access_keys/canary.go:L18]`), attaches `thinkstMessage` `[pkg/detectors/aws/access_keys/canary.go:L13]` and sets `Is_canary`. So an identically-formatted key is *reported differently* purely because its embedded account matches a known canary account.

**Canary determinism and ExtraData ordering (honest nondeterminism note).** The same canary file is scanned four times:

```
$ for i in 1 2 3 4; do echo "=== run $i ==="; /tmp/trufflehog_bin filesystem /tmp/thq1/canary.txt --no-update --no-verification; done
=== run 1 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:56:43Z	info-0	trufflehog	running source	{"source_manager_worker_id": "dDe92", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAYLPMN5HAAISUO2M
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
Resource_type: Access key
Account: 052310077262
File: /tmp/thq1/canary.txt
Line: 1

2026-07-13T18:56:43Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.770629ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
=== run 2 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:56:45Z	info-0	trufflehog	running source	{"source_manager_worker_id": "MBEgI", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAYLPMN5HAAISUO2M
Resource_type: Access key
Account: 052310077262
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/thq1/canary.txt
Line: 1

2026-07-13T18:56:45Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.050304ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
=== run 3 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:56:47Z	info-0	trufflehog	running source	{"source_manager_worker_id": "LSsCl", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAYLPMN5HAAISUO2M
Is_canary: true
Resource_type: Access key
Account: 052310077262
Message: This is an AWS canary token generated at canarytokens.org.
File: /tmp/thq1/canary.txt
Line: 1

2026-07-13T18:56:47Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.262599ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
=== run 4 ===
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:56:49Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Rdd4A", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAYLPMN5HAAISUO2M
Is_canary: true
Resource_type: Access key
Account: 052310077262
Message: This is an AWS canary token generated at canarytokens.org.
File: /tmp/thq1/canary.txt
Line: 1

2026-07-13T18:56:49Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.460129ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the **core result lines** (the `Found unverified result` header, `Detector Type: AWS`, `Decoder Type: PLAIN`, `Raw result: AKIAAYLPMN5HAAISUO2M`) are **byte-identical** across all four runs, but the **order** of the ExtraData fields (`Message`, `Is_canary`, `Resource_type`, `Account`) **varies** — three distinct orderings appear across the four runs shown. **Inferred:** the default printer renders ExtraData with `for k, v := range r.Result.ExtraData` `[pkg/output/plain.go:L67]`, and Go randomizes map-iteration order, so the field *ordering* is nondeterministic while the *finding itself* is deterministic. This is called out explicitly so the ordering variation is not misread as a "different result"; the detection outcome still satisfies *the same file always produces the same result*.

### Q1-H — "Reported differently" (2): `ASIA` session keys route to a different detector

Changing the id prefix from `AKIA` to `ASIA` and adding a session token:

```bash
SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = ASIAZ3JQK7X1YWVUT5RQ\naws_secret_access_key = %s\naws_session_token = YXdzFXEf6plMpJP5M8xfUlHkiBO1azGphPbEQ4ZxIu8UgABAE6Cq09d3w6yOko4khvSebcjQks8Ln8vnRnzTZZX37WDXEAd4nounI1LNUoMx\n' "$SEC" > /tmp/thq1/asia_session.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq1/asia_session.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:53Z	info-0	trufflehog	running source	{"source_manager_worker_id": "RmzSo", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWSSessionKey
Decoder Type: PLAIN
Raw result: ASIAZ3JQK7X1YWVUT5RQ
File: /tmp/thq1/asia_session.txt
Line: 1

2026-07-13T18:52:53Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 235, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.71502ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the `Detector Type` is now `AWSSessionKey` (not `AWS`), with `Raw result: ASIAZ3JQK7X1YWVUT5RQ`. **Inferred:** `ASIA` is handled by a **separate** detector whose id regex `idPat = \b((?:ASIA)[A-Z0-9]{16})\b` `[pkg/detectors/aws/session_keys/sessionkey.go:L61]` and single keyword `"ASIA"` `[pkg/detectors/aws/session_keys/sessionkey.go:L67-L69]` differ from the access-key detector; its `Result.Raw` is the id `[pkg/detectors/aws/session_keys/sessionkey.go:L115-L119]` (`Raw` at `[pkg/detectors/aws/session_keys/sessionkey.go:L117]`). The session detector imposes **two additional gates** the access-key detector does not: (a) a session-token entropy floor `< 4.5` `[pkg/detectors/aws/session_keys/sessionkey.go:L108]`, and (b) `checkSessionToken` `[pkg/detectors/aws/session_keys/sessionkey.go:L291-L297]`, which **rejects** the token unless it contains the marker `"YXdz"` **or** `"Jb3JpZ2luX2Vj"` **and** does **not** contain the secret. The fixture's token begins with `YXdz` precisely to pass gate (b). This is why an `ASIA` credential is *reported differently* (as `AWSSessionKey`), and why an `ASIA` id lacking a qualifying session token would be missed by this detector.

## Section 3 — Q2: Does encoding a secret before committing fool the scanner?

**Answer in brief (Observed + Inferred).** Usually **no**. Every chunk is passed once through a **fixed, ordered list of four decoders** — UTF-8, Base64, UTF-16, Escaped-Unicode — and each decoded view is scanned. Base64 that forms a long-enough, ASCII-decoding run is transparently defeated (the finding is reported with `Decoder Type: BASE64`). Encoding evades detection only at specific boundaries: the base64 run is **broken** by whitespace, is **too short** (≤ 20 charset characters), **decodes to non-ASCII/binary**, or uses a scheme **outside the four decoders** (e.g. raw hex). Separately, `.gz` input is transparently handled by the **archive layer** (decompressed before scanning), so gzip does not hide a secret either — but via a different mechanism than the decoder pipeline. Each case is demonstrated below.

**Inferred (source-derived) — the decoder pipeline.** For each chunk the engine performs **one ordered traversal** of the four decoders: the outer loop `for chunk := range e.ChunksChan() {` `[pkg/engine/engine.go:L781]` obtains a chunk pointer, and the inner loop `for _, decoder := range e.decoders {` `[pkg/engine/engine.go:L784]` calls `decoded := decoder.FromChunk(chunk)` `[pkg/engine/engine.go:L786]`. It is "single-pass" only in the narrow sense that the loop is **not restarted with its own output** and **no decoder is applied twice** — there is no iterative-depth re-feeding at this commit (see Q2-H). It is **not** isolated per decoder, however: the **same `chunk` pointer** is handed to every decoder `[pkg/engine/engine.go:L786]`, and each decoder that succeeds **mutates `chunk.Data` in place** — `Base64.FromChunk` ends with `chunk.Data = result.Bytes()` `[pkg/decoders/base64.go:L67]` and `UTF16.FromChunk` with `chunk.Data = utf16Data` `[pkg/decoders/utf16.go:L28]`. Because the order is fixed as `UTF8 → Base64 → UTF16 → EscapedUnicode`, a decoder that runs **later** operates on the bytes an **earlier** decoder produced. Consequently a two-layer encoding whose layers map onto **two different** decoders in that order (e.g. base64-of-UTF-16) *is* unwrapped within the single traversal, whereas a two-layer encoding that would need the **same** decoder twice (e.g. base64-of-base64) is *not* — both are demonstrated in **Q2-I**. `DefaultDecoders()` returns exactly four decoders in a fixed order, UTF-8 first "for duplicate detection": `&UTF8{}, &Base64{}, &UTF16{}, &EscapedUnicode{}` `[pkg/decoders/decoders.go:L11-L14]` (comment at `[pkg/decoders/decoders.go:L10]`), behind the `Decoder` interface `[pkg/decoders/decoders.go:L25-L28]`.

### Q2-A — Baseline: plaintext credential (`Decoder Type: PLAIN`)

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'; SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = %s\naws_secret_access_key = %s\n' "$ID" "$SEC" > /tmp/thq2/plain.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq2/plain.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "wYW3h", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq2/plain.txt
Line: 1

2026-07-13T18:52:55Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.10561ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the plaintext credential is detected as `Decoder Type: PLAIN` (`bytes: 106`). This is the control for the encoded cases below.

### Q2-B — Base64 is transparently defeated (`Decoder Type: BASE64`)

The plaintext file is base64-encoded to a single unbroken line:

```bash
base64 -w0 /tmp/thq2/plain.txt > /tmp/thq2/base64.txt; printf '\n' >> /tmp/thq2/base64.txt
```

```
$ cat /tmp/thq2/base64.txt
YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBWjNKUUs3WDFZV1ZVVDVSUQphd3Nfc2VjcmV0X2FjY2Vzc19rZXkgPSB3SmExclhVdG5GRU1JN0syTURiTmdRcFo4c1QzdVZXeFljNURlRjZoCg==
$ /tmp/trufflehog_bin filesystem /tmp/thq2/base64.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:57Z	info-0	trufflehog	running source	{"source_manager_worker_id": "ID054", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq2/base64.txt
Line: 1

2026-07-13T18:52:57Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 107, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.632301ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the fixture (shown by `cat`) is one continuous base64 string; the scanner **still finds the credential**, now reported as `Decoder Type: BASE64`, `Raw result: AKIAZ3JQK7X1YWVUT5RQ` (`bytes: 107`). Encoding did **not** protect it. **Inferred:** `Base64.FromChunk` `[pkg/decoders/base64.go:L34]` extracts contiguous runs of the base64 character set longer than the `20`-character threshold via `getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)` `[pkg/decoders/base64.go:L36]`, decodes each with `base64.StdEncoding` `[pkg/decoders/base64.go:L40]` and then `base64.RawURLEncoding` `[pkg/decoders/base64.go:L45]`, and keeps a decode only when it is non-empty and `isASCII` `[pkg/decoders/base64.go:L74]`. The whole line is one long run that decodes to ASCII, so the plaintext credential is reconstructed and scanned.

### Q2-C — Evasion 1: broken base64 (whitespace splits the run)

The same base64 is folded into 16-character groups separated by spaces:

```bash
base64 -w0 /tmp/thq2/plain.txt | fold -w16 | paste -sd' ' - > /tmp/thq2/b64_broken.txt
```

```
$ cat /tmp/thq2/b64_broken.txt
YXdzX2FjY2Vzc19r ZXlfaWQgPSBBS0lB WjNKUUs3WDFZV1ZV VDVSUQphd3Nfc2Vj cmV0X2FjY2Vzc19r ZXkgPSB3SmExclhV dG5GRU1JN0syTURi TmdRcFo4c1QzdVZX eFljNURlRjZoCg==
$ /tmp/trufflehog_bin filesystem /tmp/thq2/b64_broken.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:52:59Z	info-0	trufflehog	running source	{"source_manager_worker_id": "arzKh", "with_units": true}
2026-07-13T18:52:59Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 153, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.302415ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** no finding (`unverified_secrets: 0`, `bytes: 153`). **Inferred:** inserting spaces every 16 characters breaks the single base64 run into 16-character fragments, each **below** the 20-character threshold at `[pkg/decoders/base64.go:L36]`, so no substring is passed to the decoder — the secret survives encoded and is missed.

### Q2-D — Evasion 2: base64 run too short (≤ 20 characters)

```bash
printf 'AKIA1234' | base64 -w0 > /tmp/thq2/b64_short.txt; printf '\n' >> /tmp/thq2/b64_short.txt
```

```
$ cat /tmp/thq2/b64_short.txt
QUtJQTEyMzQ=
$ /tmp/trufflehog_bin filesystem /tmp/thq2/b64_short.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:02Z	info-0	trufflehog	running source	{"source_manager_worker_id": "6zAwb", "with_units": true}
2026-07-13T18:53:02Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 13, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.264183ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the encoded token `QUtJQTEyMzQ=` (12 characters) yields no finding (`unverified_secrets: 0`, `bytes: 13`). **Inferred:** the entire encoded run is only 12 characters, below the `20` threshold `[pkg/decoders/base64.go:L36]`, so it is never decoded. Short base64 spans are therefore invisible regardless of their decoded content.

### Q2-E — Evasion 3: base64 that decodes to non-ASCII/binary

A long, valid base64 run whose decoded bytes are non-ASCII (0xC8–0xE5):

```bash
python3 -c "import base64,sys; sys.stdout.write(base64.b64encode(bytes(range(0xC8,0xE6))).decode())" > /tmp/thq2/nonascii.txt; printf '\n' >> /tmp/thq2/nonascii.txt
```

```
$ cat /tmp/thq2/nonascii.txt
yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl
$ python3 -c "import base64; print(base64.b64decode(open('/tmp/thq2/nonascii.txt').read().strip())[:8].hex())"
c8c9cacbcccdcecf
$ /tmp/trufflehog_bin filesystem /tmp/thq2/nonascii.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:06Z	info-0	trufflehog	running source	{"source_manager_worker_id": "MfaA6", "with_units": true}
2026-07-13T18:53:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 41, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.171881ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the `python3` check confirms the run decodes to bytes beginning `c8c9cacbcccdcecf` (all > 0x7F); the scan yields no finding (`unverified_secrets: 0`, `bytes: 41`). **Inferred:** even though the run exceeds 20 characters and is valid base64, the decoded bytes fail `isASCII` `[pkg/decoders/base64.go:L74]` (any byte `> unicode.MaxASCII` i.e. `> 127` `[pkg/decoders/base64.go:L76]`), so the decode is discarded and never scanned. Encoding binary/non-ASCII payloads thus evades the base64 decoder.

### Q2-F — Evasion 4: an unsupported encoding (raw hex)

The plaintext is hex-encoded (a scheme with **no** decoder in the four-decoder set). The **complete** fixture is shown (no elision):

```bash
python3 -c "import sys; sys.stdout.write(open('/tmp/thq2/plain.txt','rb').read().hex())" > /tmp/thq2/hex.txt; printf '\n' >> /tmp/thq2/hex.txt
```

```
$ cat /tmp/thq2/hex.txt
6177735f6163636573735f6b65795f6964203d20414b49415a334a514b37583159575655543552510a6177735f7365637265745f6163636573735f6b6579203d20774a6131725855746e46454d49374b324d44624e6751705a387354337556577859633544654636680a
$ /tmp/trufflehog_bin filesystem /tmp/thq2/hex.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:09Z	info-0	trufflehog	running source	{"source_manager_worker_id": "zrG6h", "with_units": true}
2026-07-13T18:53:09Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 213, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.182957ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the full 212-character hex string is present in the file, yet the scan yields no finding (`unverified_secrets: 0`, `bytes: 213`). **Inferred:** there is **no hex decoder** among the four `[pkg/decoders/decoders.go:L11-L14]`. The hex alphabet `[0-9a-f]` is a subset of the base64 charset, so the base64 decoder does treat the hex text as a candidate run — but base64-decoding hex *text* does not reconstruct the original ASCII credential (the literal `AKIAZ3JQK7X1YWVUT5RQ` never appears in any decoded view), so nothing matches. An encoding outside the supported set is the clearest way encoding *can* hide a secret.

### Q2-G — gzip: defeated by the archive layer, not the decoder pipeline

```bash
gzip -c /tmp/thq2/plain.txt > /tmp/thq2/cred.gz
```

```
$ python3 -c "d=open('/tmp/thq2/cred.gz','rb').read(); print('magic:', d[:2].hex()); print('literal AKIA present:', b'AKIAZ3JQK7X1YWVUT5RQ' in d)"
magic: 1f8b
literal AKIA present: False
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq2/cred.gz --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:13Z	info-0	trufflehog	running source	{"source_manager_worker_id": "3CncX", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq2/cred.gz
Line: 1

2026-07-13T18:53:13Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.672865ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the raw `.gz` bytes begin with the gzip magic `1f8b` and do **not** contain the literal credential (`literal AKIA present: False`); nevertheless the scan **detects** the credential as `Decoder Type: PLAIN` (`bytes: 106`). **Inferred:** this detection does **not** come from the decoder pipeline — it comes from the filesystem source's **archive handler**, which recognizes `.gz` (`newArchiveHandler()` `[pkg/handlers/handlers.go:L318]`; the `.gz` format is noted in the handler comment at `[pkg/handlers/handlers.go:L305]`) and decompresses it before chunking. `archiveHandler.HandleFile` `[pkg/handlers/archive.go:L64]` calls `openArchive` `[pkg/handlers/archive.go:L111]`, which for a `case archives.Decompressor:` `[pkg/handlers/archive.go:L137]` decompresses the stream and recursively feeds the result back for scanning `[pkg/handlers/archive.go:L138-L159]`. After decompression the plaintext credential is scanned normally (hence `PLAIN`). So gzip does not hide the secret either, but the mechanism is archive decompression, distinct from the four-decoder pipeline.

### Q2-H — Version divergence flag: no HTML decoder, no `--max-decode-depth` at this commit

```
$ /tmp/trufflehog_bin filesystem --max-decode-depth=5 /tmp/thq2/plain.txt --no-update ; echo "exit: $?"
trufflehog_bin: error: unknown long flag '--max-decode-depth', try --help
exit: 1
$ /tmp/trufflehog_bin filesystem --help-long 2>&1 | grep -icE "decode|html"
0
```

**Observed:** `--max-decode-depth=5` is rejected with `error: unknown long flag '--max-decode-depth'` (exit `1`), and `filesystem --help-long` contains **zero** lines matching `decode` or `html`. **Inferred:** newer public documentation describes a fifth "HTML" decoder and iterative decoding governed by `--max-decode-depth` (default 5) — for example the TruffleHog project's DeepWiki "Scanning Process" reference, the `--max-decode-depth=5` entry in distribution help text (such as the Kali Linux TruffleHog man page and MegaLinter's flag reference), and the `max-decode-depth` flag defined in `main.go` on the project's upstream `main` branch. **Neither exists at commit `e42153d44a5e`:** `DefaultDecoders()` returns exactly four decoders `[pkg/decoders/decoders.go:L11-L14]` and decoding is a **single ordered traversal with no iterative-depth re-feeding** `[pkg/engine/engine.go:L784-L786]` — the decoders still chain *within* that one traversal through the shared, mutating chunk (Q2-I), but the loop is never restarted with its own output and `--max-decode-depth` does not exist here. This document describes the four-decoder, single-traversal behavior actually present and flags the divergence per the methodology.

### Q2-I — Decoder chaining through the shared, mutating chunk (base64-of-UTF-16 vs base64-of-base64)

Because the four decoders share one `chunk` pointer and each rewrites `chunk.Data` **in place** (§3 intro), a decoder that runs **later** in the fixed order `UTF8 → Base64 → UTF16 → EscapedUnicode` operates on the bytes an **earlier** decoder produced, within the *same* single traversal `[pkg/engine/engine.go:L781]`, `:L784-L786`. A two-layer encoding is therefore transparent **when its two layers map onto two different decoders in that order**, and opaque when it would require the same decoder twice. Both are shown below built from the *same* baseline credential.

**Chained (defeated): base64-of-UTF-16.** The plaintext credential (id and secret separated by a single `;`) is encoded to UTF-16LE and then base64-encoded to one unbroken line:

```bash
python3 -c "import base64; open('/tmp/thq2/nested_b64_utf16.txt','w').write(base64.b64encode(('aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ;aws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h').encode('utf-16le')).decode() + '\n')"
```

```
$ cat /tmp/thq2/nested_b64_utf16.txt
YQB3AHMAXwBhAGMAYwBlAHMAcwBfAGsAZQB5AF8AaQBkACAAPQAgAEEASwBJAEEAWgAzAEoAUQBLADcAWAAxAFkAVwBWAFUAVAA1AFIAUQA7AGEAdwBzAF8AcwBlAGMAcgBlAHQAXwBhAGMAYwBlAHMAcwBfAGsAZQB5ACAAPQAgAHcASgBhADEAcgBYAFUAdABuAEYARQBNAEkANwBLADIATQBEAGIATgBnAFEAcABaADgAcwBUADMAdQBWAFcAeABZAGMANQBEAGUARgA2AGgA
$ /tmp/trufflehog_bin filesystem /tmp/thq2/nested_b64_utf16.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T23:56:15Z	info-0	trufflehog	running source	{"source_manager_worker_id": "s7IMq", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: UTF16
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq2/nested_b64_utf16.txt
Line: 1

2026-07-13T23:56:15Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 105, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.78615ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the credential is found and reported as **`Decoder Type: UTF16`** (`Raw result: AKIAZ3JQK7X1YWVUT5RQ`, `unverified_secrets: 1`, `bytes: 105`) even though the file on disk is a single base64 line. **Inferred (source-derived):** within the one traversal, `Base64.FromChunk` decodes the base64 run to the UTF-16LE bytes and writes them back via `chunk.Data = result.Bytes()` `[pkg/decoders/base64.go:L67]` (the UTF-16LE of ASCII passes `isASCII` `[pkg/decoders/base64.go:L41]`, `:L46` because its interleaved `0x00` bytes are ≤ 127); that base64 *view* itself does not match AWS, since the interleaved nulls break the id/secret regexes. Next in the fixed order, `UTF16.FromChunk` reads the **already-mutated** `chunk.Data` and converts UTF-16LE → UTF-8 via `chunk.Data = utf16Data` `[pkg/decoders/utf16.go:L28]`, reconstructing the clean `aws_access_key_id = … ; aws_secret_access_key = …` text, which the AWS detector then matches — hence the `UTF16` decoder label rather than `BASE64`.

**Why a `;` separator (Observed edge condition).** `utf16ToUTF8` keeps only printable bytes (`isPrintableByte` at `[pkg/decoders/utf16.go:L40]`, `:L45`), so a newline between the two `aws_…` lines is **dropped** during the UTF-16 → UTF-8 conversion, merging the two tokens and destroying the boundary the AWS regexes need. The identical fixture whose separator is a **newline** instead of `;` — differing at exactly one byte (verified: the two plaintexts are both 105 characters and differ only at index 40, `';'` vs `'\n'`) — is therefore missed:

```bash
python3 -c "import base64; open('/tmp/thq2/nested_b64_utf16_nl.txt','w').write(base64.b64encode(('aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ\naws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h').encode('utf-16le')).decode() + '\n')"
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq2/nested_b64_utf16_nl.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-14T00:02:18Z	info-0	trufflehog	running source	{"source_manager_worker_id": "bn7A9", "with_units": true}
2026-07-14T00:02:18Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 104, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.524436ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the newline-separated variant yields **no finding** (`unverified_secrets: 0`, `bytes: 104` — one fewer byte because the single newline was dropped during UTF-16 → UTF-8). The one deterministic difference from the detected case is the separator byte.

**Not chained (opaque): base64-of-base64.** The same credential is base64-encoded **twice**:

```bash
printf 'aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ\naws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h\n' | base64 -w0 | base64 -w0 > /tmp/thq2/double_b64.txt; printf '\n' >> /tmp/thq2/double_b64.txt
```

```
$ cat /tmp/thq2/double_b64.txt
WVhkelgyRmpZMlZ6YzE5clpYbGZhV1FnUFNCQlMwbEJXak5LVVVzM1dERlpWMVpWVkRWU1VRcGhkM05mYzJWamNtVjBYMkZqWTJWemMxOXJaWGtnUFNCM1NtRXhjbGhWZEc1R1JVMUpOMHN5VFVSaVRtZFJjRm80YzFRemRWWlhlRmxqTlVSbFJqWm9DZz09
$ /tmp/trufflehog_bin filesystem /tmp/thq2/double_b64.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T23:56:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "qoJxE", "with_units": true}
2026-07-13T23:56:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 145, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.438719ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** double-base64 yields **no finding** (`unverified_secrets: 0`, `bytes: 145`). **Inferred (source-derived):** the base64 decoder runs **once** in the traversal `[pkg/engine/engine.go:L784-L786]`; its single decode of the outer layer yields the *inner* base64 text (still ASCII, so it is kept and written back to `chunk.Data`, which is why `bytes` reports the 145-byte inner layer rather than the 193-byte file), but nothing re-feeds that inner text to the base64 decoder a second time and no other decoder in the fixed set decodes base64. The credential therefore stays one base64 layer deep and is never reconstructed — the concrete meaning of "no iterative-depth re-decoding" at this commit (contrast the newer `--max-decode-depth`, Q2-H).

### Q2-J — URL-encoded base64 is normalized before matching (`UrlEncodedReplacer`)

A base64-class secret that has been URL-/percent-encoded (so `+` → `%2B`, `/` → `%2F`, `=` → `%3D`) is **normalized back inside the AWS detector** before its regexes run, so percent-encoding does not hide it either. The fixture is an ordinary credential whose 40-character secret carries `%2B` and `%2F` in place of a literal `+` and `/`:

```bash
printf '%s\n%s\n' 'aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ' 'aws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWx%2Bc5%2FeF6h' > /tmp/thq2/urlenc.txt
```

```
$ cat /tmp/thq2/urlenc.txt
aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ
aws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWx%2Bc5%2FeF6h
$ /tmp/trufflehog_bin filesystem /tmp/thq2/urlenc.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-14T00:01:10Z	info-0	trufflehog	running source	{"source_manager_worker_id": "I1wEH", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
File: /tmp/thq2/urlenc.txt
Line: 1

2026-07-14T00:01:10Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 110, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.086782ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** the credential is detected as **`Decoder Type: PLAIN`** (`Raw result: AKIAZ3JQK7X1YWVUT5RQ`, `unverified_secrets: 1`, `bytes: 110`) even though the on-disk secret literally contains `%2Bc5%2F`. **Inferred (source-derived):** the decoder pipeline plays no part here — the bytes are plain ASCII, so the scanned view is `PLAIN`; instead the AWS access-key detector normalizes the data *before* matching, `dataStr = aws.UrlEncodedReplacer.Replace(dataStr)` `[pkg/detectors/aws/access_keys/accesskey.go:L108]` (the session-key detector does the same at `[pkg/detectors/aws/session_keys/sessionkey.go:L75]`). `UrlEncodedReplacer` is a `strings.NewReplacer` mapping `%2B`/`%2b` → `+`, `%2F`/`%2f` → `/`, and `%3D`/`%3d` → `=` `[pkg/detectors/aws/utils.go:L35-L41]`, with the intent stated in the comment "helps capture base64-encoded results that may be url-encoded" `[pkg/detectors/aws/utils.go:L33]`. After replacement the secret reads `wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWx+c5/eF6h` — exactly 40 base64-class characters — so `SecretPat` `[pkg/detectors/aws/common.go:L10]` matches and the credential is reported.

## Section 4 — Q3: Why some correctly-formatted test-fixture credentials are never flagged

**Answer in brief (Observed + Inferred).** There are **two distinct reasons**, and they behave differently under `--results=filtered_unverified`:

1. **Known false positive — matched, then suppressed.** A result *is* created, but its raw value contains a filtered term (an example/sample token, a common English word, or a known UUID). The default false-positive filter drops it, so it is hidden by default but **revealed** by `--results=filtered_unverified`. The canonical AWS documentation key `AKIAIOSFODNN7EXAMPLE` is exactly this case.
2. **Rejected by an earlier detector gate — no result is ever created.** The candidate fails one of the detector's own gates (e.g. the 4.25 secret-entropy floor) *before* any result exists, so there is nothing for the false-positive layer to retain. Such a credential produces **no finding/result even with** `--results=filtered_unverified`. A pure-hex "secret" is this case.

**Inferred (source-derived) — the false-positive layer.** For a detector that does not implement a custom checker, the engine applies `GetFalsePositiveCheck` `[pkg/detectors/falsepositives.go:L70]`, which calls `IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)` `[pkg/detectors/falsepositives.go:L77]`. `IsKnownFalsePositive` `[pkg/detectors/falsepositives.go:L85]` lowercases the value `[pkg/detectors/falsepositives.go:L89]`, returns true on an exact match against `DefaultFalsePositives` `[pkg/detectors/falsepositives.go:L91-L92]`, then on a substring **"contains term"** match `[pkg/detectors/falsepositives.go:L97-L98]`, then on the embedded word lists `[pkg/detectors/falsepositives.go:L101-L105]`. `DefaultFalsePositives` `[pkg/detectors/falsepositives.go:L17]` includes `"example"`, `"sample"`, `"xxxxxx"`, `"aaaaaa"`, etc. `[pkg/detectors/falsepositives.go:L18]`; the word lists are embedded via `go:embed` `[pkg/detectors/falsepositives.go:L35-L42]`. Filtered results are removed unless retained: `if !e.retainFalsePositives { results = detectors.FilterKnownFalsePositives(ctx, detector.Detector, results) }` `[pkg/engine/engine.go:L1141-L1142]`, and `--results=filtered_unverified` sets `engine.retainFalsePositives = ok` `[pkg/engine/engine.go:L317-L318]` (field wired from `LogFilteredUnverified` `[pkg/engine/engine.go:L239]`).

### Q3-A — Known false positive: `AKIAIOSFODNN7EXAMPLE` (matched, then suppressed)

The canonical AWS documentation key, with a valid 40-char secret:

```bash
SEC='wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h'
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = %s\n' "$SEC" > /tmp/thq3/example_key.txt
```

Default configuration — the finding is suppressed:

```
$ /tmp/trufflehog_bin filesystem /tmp/thq3/example_key.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:16Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Eus2j", "with_units": true}
2026-07-13T18:53:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.612667ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Same file with `--results=filtered_unverified` — the suppressed finding is revealed:

```
$ /tmp/trufflehog_bin filesystem /tmp/thq3/example_key.txt --no-update --no-verification --results=filtered_unverified
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:18Z	info-0	trufflehog	running source	{"source_manager_worker_id": "h2ScI", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLE
Resource_type: Access key
File: /tmp/thq3/example_key.txt
Line: 1

2026-07-13T18:53:18Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.660171ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** by default the file yields **no finding** (`unverified_secrets: 0`); adding `--results=filtered_unverified` reveals exactly the same credential — `Detector Type: AWS`, `Raw result: AKIAIOSFODNN7EXAMPLE` (`unverified_secrets: 1`). The before/after toggling of a single flag proves the finding was *created and then filtered*, not *never matched*. **Inferred:** the AWS detector's `Result.Raw` is the id `[pkg/detectors/aws/access_keys/accesskey.go:L138]`, i.e. `AKIAIOSFODNN7EXAMPLE`; `IsKnownFalsePositive` lowercases it to `akiaiosfodnn7example` `[pkg/detectors/falsepositives.go:L89]` and the "contains term" loop `[pkg/detectors/falsepositives.go:L97]` matches the substring `"example"` (a member of `DefaultFalsePositives` `[pkg/detectors/falsepositives.go:L18]`), returning `true, "contains term: example"` `[pkg/detectors/falsepositives.go:L98]`. That is why the default classes hide it and `filtered_unverified` shows it.

### Q3-B — Rejected earlier: a pure-hex "secret" (no result is ever created)

A valid id paired with a 40-character all-hex secret:

```bash
ID='AKIAZ3JQK7X1YWVUT5RQ'
printf 'aws_access_key_id = %s\naws_secret_access_key = a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\n' "$ID" > /tmp/thq3/hash_secret.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq3/hash_secret.txt --no-update --no-verification
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "YKlOA", "with_units": true}
2026-07-13T18:53:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.518813ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/thq3/hash_secret.txt --no-update --no-verification --results=filtered_unverified
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:21Z	info-0	trufflehog	running source	{"source_manager_worker_id": "V4HhS", "with_units": true}
2026-07-13T18:53:21Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.15061ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Observed:** this file yields **no finding under the default classes and no finding under `--results=filtered_unverified`** (both `unverified_secrets: 0`). This is the key contrast with Q3-A: `filtered_unverified` does **not** reveal it. **Inferred:** the secret is rejected by the **secret-entropy floor** *before* any result is constructed — `if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy { continue }` `[pkg/detectors/aws/access_keys/accesskey.go:L132]` with `RequiredSecretEntropy = 4.25` `[pkg/detectors/aws/common.go:L7]`. A pure-hex string draws from a 16-symbol alphabet, whose maximum Shannon entropy is `log2(16) = 4.0`; the specific value here computes to ≈ **3.971** (via `StringShannonEntropy` `[pkg/detectors/falsepositives.go:L136-L150]`), so **every** pure-hex 40-char secret is below 4.25 and is dropped at the entropy gate. Because no result is ever created, there is nothing for the false-positive layer to retain, so `filtered_unverified` shows nothing. (There is *also* a hex-specific safety net `FalsePositiveSecretPat = [a-f0-9]{40}` `[pkg/detectors/aws/utils.go:L47]` applied to unverified results at `[pkg/detectors/aws/access_keys/accesskey.go:L202]`, but for pure hex the entropy floor already rejects the candidate first, so that net is not what fires here.)

**Why test fixtures in particular.** Fixtures overwhelmingly use either the literal AWS `AKIAIOSFODNN7EXAMPLE` key (Q3-A: matched then suppressed) or obviously-dummy secrets such as repeated characters or hex hashes (Q3-B: rejected at an entropy/word gate). Both classes therefore stay unflagged by default — the first recoverable via `filtered_unverified`, the second not, exactly as observed.

## Section 5 — Q4: What triggers "verification has been disabled for safety"?

**Answer in brief (Observed + Inferred).** When **more than one detector** matches the **same candidate value**, TruffleHog disables verification for the overlapping result and attaches a warning, so it does not send an ambiguous secret to a verification endpoint that may belong to the wrong service. The behavior is overridable with `--allow-verification-overlap`. Below, a single 32-character token is crafted so that two different detectors (`ShodanKey` and `TomorrowIO`) both match it.

> **Synthetic-data notice.** The 32-character token `aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj` used here is **synthetic and inert** — it is a randomly composed string, not a real Shodan or Tomorrow.io API key. It is used only to trip the multi-detector overlap path with controlled data.

**Inferred (source-derived) — the overlap gate.** In the decoder loop, `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` `[pkg/engine/engine.go:L795]` is followed by the gate `if len(matchingDetectors) > 1 && !e.verificationOverlap {` `[pkg/engine/engine.go:L796]`, whose body routes the results to `verificationOverlapWorker` `[pkg/engine/engine.go:L924]`. There, when a result is judged a `likelyDuplicate` `[pkg/engine/engine.go:L887]` — i.e. their `similarity` is **strictly greater than** the `similarityThreshold` of `0.9`: `if similarity > similarityThreshold` `[pkg/engine/engine.go:L914]` (threshold at `[pkg/engine/engine.go:L888]`) — the engine calls `res.SetVerificationError(errOverlap)` `[pkg/engine/engine.go:L988]`. That is a **single positional argument** (`errOverlap`); the method signature is `func (r *Result) SetVerificationError(err error, secrets ...string)` `[pkg/detectors/detectors.go:L126]`, whose variadic `secrets` is unused at this call site. The warning text is `errOverlap` `[pkg/engine/engine.go:L39-L42]`, and the printer renders it via `Verification issue: %s` `[pkg/output/plain.go:L57]`.

**The two overlapping detectors (Inferred).** `ShodanKey` uses `keyPat = PrefixRegex(["shodan"]) + \b([a-zA-Z0-9]{32})\b` `[pkg/detectors/shodankey/shodankey.go:L25]` with keyword `"shodan"` `[pkg/detectors/shodankey/shodankey.go:L30-L32]` and `Raw` = the 32-char match `[pkg/detectors/shodankey/shodankey.go:L45]`; `TomorrowIO` uses `keyPat = PrefixRegex(["tomorrow"]) + \b([a-zA-Z0-9]{32})\b` `[pkg/detectors/tomorrowio/tomorrowio.go:L24]` with keyword `"tomorrow"` `[pkg/detectors/tomorrowio/tomorrowio.go:L29-L31]` and `Raw` = the 32-char match `[pkg/detectors/tomorrowio/tomorrowio.go:L44]`. Both share the identical `[a-zA-Z0-9]{32}` shape, so the single token matches both and produces two results with the **same** `Raw` — the overlap condition.

### Q4-A — Default: overlap disables verification and attaches the warning

Fixture generation (keywords `shodan` and `tomorrow` plus the shared 32-char token):

```bash
printf 'shodan tomorrow apikey = aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj\n' > /tmp/thq4/overlap.txt
```

```
$ /tmp/trufflehog_bin filesystem /tmp/thq4/overlap.txt --no-update
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:26Z	info-0	trufflehog	running source	{"source_manager_worker_id": "P4yQp", "with_units": true}
Found unverified result 🐷🔑❓
Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
Detector Type: TomorrowIO
Decoder Type: PLAIN
Raw result: aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj
File: /tmp/thq4/overlap.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: ShodanKey
Decoder Type: PLAIN
Raw result: aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj
File: /tmp/thq4/overlap.txt
Line: 1

2026-07-13T18:53:27Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 58, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "153.334464ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":147}}
```

**Observed:** two findings are printed, both with `Raw result: aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj` — one `TomorrowIO` and one `ShodanKey` — and exactly one of them carries `Verification issue: More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.` The summary shows `unverified_secrets: 2`, `verified_secrets: 0`, `"Misses":1`. (The two detectors' print order, and which result carries the warning, vary run-to-run — see the byte-check note below and the map/goroutine nondeterminism already documented in Q1-G.)

### Q4-B — Override: `--allow-verification-overlap` re-enables verification

Same unchanged fixture, with the override flag:

```
$ /tmp/trufflehog_bin filesystem /tmp/thq4/overlap.txt --no-update --allow-verification-overlap
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:53:28Z	info-0	trufflehog	running source	{"source_manager_worker_id": "nx2Ib", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: ShodanKey
Decoder Type: PLAIN
Raw result: aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj
File: /tmp/thq4/overlap.txt
Line: 1

Found unverified result 🐷🔑❓
Detector Type: TomorrowIO
Decoder Type: PLAIN
Raw result: aB3xK9mZ2pQ7wL5nR8tV4yUcD1eF0gHj
File: /tmp/thq4/overlap.txt
Line: 1

2026-07-13T18:53:28Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 58, "verified_secrets": 0, "unverified_secrets": 2, "scan_duration": "193.008482ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":328}}
```

**Observed:** the same two results are printed, **neither** carries a `Verification issue` line, and the summary now shows `"Misses":2` (still `verified_secrets: 0`). **Inferred (source-derived):** `"Misses"` is the verification-cache *miss* counter — the number of verification **attempts** that were not served from cache, **not** the number of successful verifications. It is incremented by `v.metrics.AddResultCacheMisses(1)` on the cache-miss branch `[pkg/verificationcache/verification_cache.go:L96]` (the cache-hit branch instead calls `AddResultCacheHits(1)` `[pkg/verificationcache/verification_cache.go:L93]`); the counter is the `ResultCacheMisses atomic.Int32` field `[pkg/verificationcache/in_memory_metrics.go:L14]` updated by `AddResultCacheMisses` `[pkg/verificationcache/in_memory_metrics.go:L31-L33]`, which the CLI reads as `Misses: verificationCacheMetrics.ResultCacheMisses.Load()` `[main.go:L559]` and emits inside the `verification_caching` object of the `finished scanning` summary `[main.go:L566-L574]`. With the override, both overlapping results are sent for verification (2 attempts, `Misses:2`); by default the overlapping duplicate's verification is skipped, so fewer attempts occur (`Misses:1`). `verified_secrets` stays `0` throughout because the synthetic token is not a real key for either service — i.e. verification was *attempted for both detectors*, not *successful*.

> **Security warning (do not misuse the override).** `--allow-verification-overlap` re-enables verification for a candidate that matched multiple detectors, which means TruffleHog will send that candidate to **both** detectors' **real** verification endpoints (here, the Shodan API **and** the Tomorrow.io API). **Inferred (source-derived):** with verification enabled, `ShodanKey` issues `GET https://api.shodan.io/api-info?key=<token>` `[pkg/detectors/shodankey/shodankey.go:L74]` and `TomorrowIO` — gated on `if verify {` `[pkg/detectors/tomorrowio/tomorrowio.go:L47]` — issues `GET https://api.tomorrow.io/v4/alerts?apikey=<token>` `[pkg/detectors/tomorrowio/tomorrowio.go:L48]`, each dispatched via `client.Do(req)` `[pkg/detectors/shodankey/shodankey.go:L79]`, `[pkg/detectors/tomorrowio/tomorrowio.go:L52]`. That is exactly the risk the safety default prevents: an ambiguous or maliciously-shaped secret could be transmitted to a third-party service that is not its true owner. Use this flag **only** with controlled/synthetic test data, **never** on unknown or live findings.

### Q4-C — Byte-check: the warning text has no space after "disabled."

**Observed:** the warning string contains the exact substring `disabled.You` (no space), and `disabled. You` (with a space) appears zero times:

```
$ /tmp/trufflehog_bin filesystem /tmp/thq4/overlap.txt --no-update 2>&1 | grep -o 'disabled.You'
disabled.You
$ /tmp/trufflehog_bin filesystem /tmp/thq4/overlap.txt --no-update 2>&1 | grep -c 'disabled. You'
0
```

**Inferred:** `errOverlap` concatenates two string literals whose adjacent ends are `verification has been disabled.` and `You can override` `[pkg/engine/engine.go:L40-L41]` — joined with no separating space, producing the literal `disabled.You` seen in the output. This is reported exactly as observed, including the missing space.

## Section 6 — Coverage Pass

Every mechanism, function, flag, file, and named example referenced by the four questions is addressed above and grounded below to a full repository path and exact line(s) at commit `e42153d44a5e`. Facts labelled **Observed** come from the transcripts; **Inferred (source-derived)** statements are the code-grounded causes. The `--version` banner shows `trufflehog dev` (a source-build artifact, not a release).

**CLI entry point & flags (`main.go`, `pkg/version/version.go`)**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| `filesystem` command + positional `path` arg | `main.go:L143` (arg `main.go:L144`) | §1 |
| `--results` (default `verified,unverified,unknown`) | `main.go:L61` | §1, Q3-A/B |
| `--allow-verification-overlap` | `main.go:L65` | Q4-B |
| `--filter-unverified` | `main.go:L66` | §1 |
| `--scan-entire-chunk` (Hidden) | `main.go:L68` | Q1-E |
| `--compare-detection-strategies` (Hidden) | `main.go:L69` | §1 |
| `--no-verification` | `main.go:L59` | Q1–Q3 runs |
| `--no-update` | `main.go:L73` | all runs |
| Version wiring via `cli.Version` and `BuildVersion = "dev"` | `main.go:L270`, `pkg/version/version.go:L3` | §1 |
| Startup banner to stderr | `main.go:L498` | §1 |
| Module path & toolchain | `go.mod:L1`, `go.mod:L3-L5` | header, §1 |

**Q1 — chunking, keyword pre-filter, span, patterns, entropy, canary, session**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| `ChunkSize` (10 KiB = 10240 B), `PeekSize` (3 KiB = 3072 B), `TotalChunkSize` (13 KiB = 13312 B) | `pkg/sources/chunker.go:L14`, `:L16`, `:L18`; `NewChunkReader` `:L67-L71`; read/peek loop `:L119-L127` | Q1-pipeline |
| Filesystem source → handler entry (`scanFile` builds `chunkSkel`, calls `handlers.HandleFile`) | `pkg/sources/filesystem/filesystem.go:L163`, `:L181-L194`, `:L196` | Q1-pipeline |
| Handler dispatch (`selectHandler` default/archive; delegate + funnel chunks) | `pkg/handlers/handlers.go:L308`, `:L344`, `:L387-L390` | Q1-pipeline, Q2-G |
| Default handler chunking (`NewChunkReader`, range, `data.Bytes()`) | `pkg/handlers/default.go:L39`, `:L94`, `:L109-L110`, `:L121` | Q1-pipeline |
| Keyword pre-filter (`FindDetectorMatches` → `prefilter.Match`) | `pkg/engine/ahocorasick/ahocorasickcore.go:L241-L242` | Q1-C |
| Windowed span calculator (`calculateSpan`) | `pkg/engine/ahocorasick/ahocorasickcore.go:L79-L111` | Q1-E |
| Entire-chunk span calculator (`EntireChunkSpanCalculator.calculateSpan`; installed when `--scan-entire-chunk`) | `pkg/engine/ahocorasick/ahocorasickcore.go:L61-L63`, `pkg/engine/engine.go:L525-L526` | Q1-E |
| `defaultMaxCredentialSpan = 1024` | `pkg/detectors/multi_part_credential_provider.go:L8` | Q1-E |
| AWS access-key id regex `idPat` | `pkg/detectors/aws/access_keys/accesskey.go:L65` | Q1-A |
| AWS access-key `Keywords()` (AKIA/ABIA/ACCA) | `pkg/detectors/aws/access_keys/accesskey.go:L70-L76` | Q1-A, Q1-C |
| Id-entropy gate | `pkg/detectors/aws/access_keys/accesskey.go:L122` | Q1-F |
| Secret-entropy gate | `pkg/detectors/aws/access_keys/accesskey.go:L132` | Q1-F, Q3-B |
| `Result.Raw = idMatch` | `pkg/detectors/aws/access_keys/accesskey.go:L138` | Q1-A, Q3-A |
| `RequiredIdEntropy = 3.0`, `RequiredSecretEntropy = 4.25` | `pkg/detectors/aws/common.go:L6`, `:L7` | Q1-F, Q3-B |
| `SecretPat` (exactly 40 chars, boundary-anchored) | `pkg/detectors/aws/common.go:L10` | Q1-D |
| `thinkstMessage`, `thinkstKnockoffsMessage` | `pkg/detectors/aws/access_keys/canary.go:L13`, `:L14` | Q1-G |
| `thinkstCanaryList` (incl. `052310077262`) | `pkg/detectors/aws/access_keys/canary.go:L17-L28` (entry `:L18`) | Q1-G |
| `GetAccountNumFromID` (account decode) | `pkg/detectors/aws/utils.go:L49` | Q1-G |
| Session-key id regex `idPat` (ASIA) | `pkg/detectors/aws/session_keys/sessionkey.go:L61` | Q1-H |
| Session-key `sessionPat` | `pkg/detectors/aws/session_keys/sessionkey.go:L62` | Q1-H |
| Session-key `Keywords()` (ASIA) | `pkg/detectors/aws/session_keys/sessionkey.go:L67-L69` | Q1-H |
| Session-token entropy floor (< 4.5) | `pkg/detectors/aws/session_keys/sessionkey.go:L108` | Q1-H |
| Session-key `Result.Raw = idMatch` | `pkg/detectors/aws/session_keys/sessionkey.go:L115-L119` (`Raw` `:L117`) | Q1-H |
| `checkSessionToken` (marker OR-gate + secret-containment reject) | `pkg/detectors/aws/session_keys/sessionkey.go:L291-L297` | Q1-H |

**Q2 — decoder pipeline, base64 internals, gzip archive layer, version divergence**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| Engine decoder loop (one ordered traversal; same `chunk` pointer reused across decoders) | `pkg/engine/engine.go:L781`, `:L784-L786` | §3 intro, Q2-H, Q2-I |
| In-place chunk mutation enabling later-decoder chaining (`chunk.Data = …`) | `pkg/decoders/base64.go:L67`, `pkg/decoders/utf16.go:L28` | §3 intro, Q2-I |
| `DefaultDecoders()` four decoders (UTF-8 first) | `pkg/decoders/decoders.go:L11-L14` (comment `:L10`) | §3 intro, Q2-F |
| `Decoder` interface | `pkg/decoders/decoders.go:L25-L28` | §3 intro |
| UTF-8 / UTF-16 / Escaped-Unicode decoders (`FromChunk`) | `pkg/decoders/utf8.go:L16`, `pkg/decoders/utf16.go:L18`, `pkg/decoders/escaped_unicode.go:L32` | §3 intro |
| `b64Charset`, `b64EndChars` | `pkg/decoders/base64.go:L17`, `:L18` | Q2-B |
| `Base64.FromChunk` | `pkg/decoders/base64.go:L34` | Q2-B |
| `getSubstringsOfCharacterSet` 2nd arg `20` (>20 threshold) | `pkg/decoders/base64.go:L36` | Q2-B/C/D |
| `base64.StdEncoding`, `base64.RawURLEncoding` | `pkg/decoders/base64.go:L40`, `:L45` | Q2-B |
| `isASCII`, `unicode.MaxASCII` (127) | `pkg/decoders/base64.go:L74`, `:L76` | Q2-E |
| `UrlEncodedReplacer` (URL-encoded normalization, applied before AWS matching) | `pkg/detectors/aws/utils.go:L33`, `:L35-L41`; call sites `pkg/detectors/aws/access_keys/accesskey.go:L108`, `pkg/detectors/aws/session_keys/sessionkey.go:L75` | Q2-J |
| gzip archive selection `newArchiveHandler()` (.gz) | `pkg/handlers/handlers.go:L318` (comment `:L305`), `HandleFile` `:L344` | Q2-G |
| `archiveHandler.HandleFile` / `openArchive` | `pkg/handlers/archive.go:L64`, `:L111` | Q2-G |
| Decompressor case + recursive feed | `pkg/handlers/archive.go:L137`, `:L138-L159` | Q2-G |
| Divergence: no HTML decoder / no `--max-decode-depth` | `pkg/decoders/decoders.go:L11-L14`, `pkg/engine/engine.go:L784-L786` | Q2-H |

**Q3 — false-positive suppression and the earlier entropy gate**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| `DefaultFalsePositives` (incl. `example`, `sample`, `xxxxxx`, `aaaaaa`, `00000`) | `pkg/detectors/falsepositives.go:L17-L18` | Q3-A |
| Embedded word lists (`fp_badlist.txt`, `fp_words.txt`, `fp_programmingbooks.txt`, `fp_uuids.txt`) | `pkg/detectors/falsepositives.go:L35-L42` (`go:embed`) | Q3 intro |
| `GetFalsePositiveCheck` (default checker) | `pkg/detectors/falsepositives.go:L70` (calls `:L77`) | Q3 intro |
| `IsKnownFalsePositive` | `pkg/detectors/falsepositives.go:L85` | Q3 intro |
| Lowercase + "matches term" exact match | `pkg/detectors/falsepositives.go:L89`, `:L91-L92` | Q3-A |
| "contains term" substring match | `pkg/detectors/falsepositives.go:L97-L98` | Q3-A |
| Word-list match | `pkg/detectors/falsepositives.go:L101-L105` | Q3 intro |
| `StringShannonEntropy` (entropy formula) | `pkg/detectors/falsepositives.go:L136-L150` | Q1-F, Q3-B |
| AWS `FalsePositiveSecretPat` (hex-40 net) | `pkg/detectors/aws/utils.go:L47` (applied `pkg/detectors/aws/access_keys/accesskey.go:L202`) | Q3-B |
| `LogFilteredUnverified` → `retainFalsePositives` | `pkg/engine/engine.go:L116`, `:L239` | Q3 intro |
| `filtered_unverified` sets `retainFalsePositives` | `pkg/engine/engine.go:L317-L318` | Q3-A |
| Filter application `FilterKnownFalsePositives` | `pkg/engine/engine.go:L1141-L1142` | Q3 intro |

**Q4 — verification-overlap safety gate**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| `errOverlap` message (concatenated literals → `disabled.You`) | `pkg/engine/engine.go:L39-L42` (`:L40-L41`) | Q4-A, Q4-C |
| Overlap gate `len(matchingDetectors) > 1 && !e.verificationOverlap` | `pkg/engine/engine.go:L795-L796` | Q4 intro |
| `verificationOverlapWorker` | `pkg/engine/engine.go:L924` | Q4 intro |
| `likelyDuplicate` + `similarityThreshold = 0.9` | `pkg/engine/engine.go:L887`, `:L888` | Q4 intro |
| Strictly-greater comparison `similarity > similarityThreshold` | `pkg/engine/engine.go:L914` | Q4 intro |
| `SetVerificationError(errOverlap)` (single arg) | `pkg/engine/engine.go:L988` | Q4 intro |
| `SetVerificationError` signature (variadic unused) | `pkg/detectors/detectors.go:L126` | Q4 intro |
| `PrefixRegex` helper | `pkg/detectors/detectors.go:L230` | Q4 intro |
| ShodanKey `keyPat` / `Keywords` / `Raw` | `pkg/detectors/shodankey/shodankey.go:L25`, `:L30-L32`, `:L45` | Q4 intro |
| TomorrowIO `keyPat` / `Keywords` / `Raw` | `pkg/detectors/tomorrowio/tomorrowio.go:L24`, `:L29-L31`, `:L44` | Q4 intro |

**Default printer (`pkg/output/plain.go`) — output fields quoted throughout**

| Named item | Grounding (path:line) | Addressed in |
|---|---|---|
| `Found verified result` / `Found unverified result` headers | `pkg/output/plain.go:L52`, `:L55` | all |
| `Verification issue: %s` line | `pkg/output/plain.go:L57` | Q4-A |
| `Detector Type` / `Decoder Type` / `Raw result` | `pkg/output/plain.go:L63-L65` | all |
| ExtraData iteration (map-order nondeterminism) | `pkg/output/plain.go:L67` | Q1-G |

**Named user examples**

| Example (user's words) | Where demonstrated |
|---|---|
| *completely missed* | Q1-C (keyword absent), Q1-E (ID↔secret > 1024 B) |
| *reported differently* | Q1-G (canary token), Q1-H (`ASIA` → `AWSSessionKey`) |
| *the same file always produces the same result* | Q1-B (3-run determinism), Q1-G (canary core lines stable) |
| developers *encode sensitive data before committing it* | Q2-B (base64), Q2-C/D/E/F (evasions), Q2-G (gzip) |
| `AKIAIOSFODNN7EXAMPLE` | Q3-A |
| *verification disabled for safety* | Q4-A/B/C |

## Section 7 — Repository State & Cleanup

**Repository state (Observed).** Commit `e42153d44a5e` is the **TruffleHog source baseline** — it is *not* the current `HEAD`. The working tree is clean and the only change relative to the baseline is this single documentation file:

```
$ git rev-parse --short e42153d44a5e   # TruffleHog source baseline
e42153d4
$ git status --porcelain            # (no output below = clean working tree)
$ git diff --name-only e42153d4..HEAD
blitzy/documentation/trufflehog_e42153d44a5e.md
```

This confirms the read-only scope: **no existing TruffleHog source file was modified**, and the sole addition to the repository is `blitzy/documentation/trufflehog_e42153d44a5e.md`. (The full `HEAD` hash and insertion count are intentionally not quoted here, as they change when this document is finalized; the stable facts above — source baseline `e42153d4`, empty status, single-file name-only diff — are what establish the governance claim.)

**Cleanup (Observed).** Every temporary artifact used for the investigation lived under `/tmp` (outside the source tree): the compiled binary `/tmp/trufflehog_bin`, the crafted fixtures under `/tmp/thq1`–`/tmp/thq4` plus the early scratch directory `/tmp/thfix`, and the generator/driver scripts (which lived inside `/tmp/thq2`). All were removed, leaving the repository unchanged:

```
$ rm -rf /tmp/thq1 /tmp/thq2 /tmp/thq3 /tmp/thq4 /tmp/thfix /tmp/trufflehog_bin
$ ls -d /tmp/thq1 /tmp/thq2 /tmp/thq3 /tmp/thq4 /tmp/thfix /tmp/trufflehog_bin 2>&1
ls: cannot access '/tmp/thq1': No such file or directory
ls: cannot access '/tmp/thq2': No such file or directory
ls: cannot access '/tmp/thq3': No such file or directory
ls: cannot access '/tmp/thq4': No such file or directory
ls: cannot access '/tmp/thfix': No such file or directory
ls: cannot access '/tmp/trufflehog_bin': No such file or directory
```

Because these artifacts are outside the repository, their removal does not affect any tracked file — the clean `git status` above is the authoritative confirmation that the source tree is byte-for-byte unchanged apart from this document.

---

*All behavioral claims in this document were produced by building the scanner from source (`CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .`) with the project's pinned `go1.24.2` toolchain and running the canonical `trufflehog filesystem` entry point in its default configuration; each transcript is the complete, unedited output of the command shown immediately above it (standard error and standard output merged, with no editorial annotations; ephemeral fields such as timestamps, worker ids, and durations vary per run, as noted in the Methodology).*

