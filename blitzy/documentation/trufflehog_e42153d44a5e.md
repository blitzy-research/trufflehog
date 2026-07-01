# TruffleHog v3 — Secret Detection Architecture (Onboarding Q&A)

This document is an onboarding architecture explainer for the
[`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog)
repository. The module path is `github.com/trufflesecurity/trufflehog/v3`
(`go.mod:1`), and every observation below was made against the exact HEAD commit
`e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch `trufflehog_e42153d44a5e`).

It answers five question-groups about how TruffleHog v3 performs secret
detection. It was written **run-first, write-second**: the tool was built from
source and executed across the exact modes each question implies, and the real
output was captured. Every factual claim is backed either by an exact
`file:line` citation into the source tree or by a **verbatim** sample of
observed runtime output, and each output sample is paired with the exact command
that produced it.

**Authoritative source of truth.** The built binary and the source code at this
commit are authoritative. Public documentation (README, `pkg.go.dev`, third-party
write-ups) was consulted only to validate framing; wherever a public figure
disagrees with observed behavior (most notably the published detector count),
the empirically observed value at this commit is used and cited.

> **A note on the reproduced commands.** The upstream question prompts referred
> to a `filesystem --path <dir>` form. The `filesystem` source at this commit
> takes the scan path as a **positional argument** (`main.go:144`,
> `filesystemScan.Arg("path", ...)`), so the reproducible commands below use
> `filesystem <path>` (no `--path` flag). Log timestamps (`ts`) and worker IDs
> in the captured output are non-deterministic and differ per run.

---

## Preamble — Build & Run

**Toolchain.** The module declares a minimum language version of `go 1.23.1`
(`go.mod:3`) and pins a build toolchain of `toolchain go1.24.2` (`go.mod:5`). Go
**1.24.2** was installed and used for all observations.

**Build command (static binary).** The repository convention is a
`CGO_ENABLED=0` static build. The `Dockerfile` sets `ENV CGO_ENABLED=0`
(`Dockerfile:5`) and builds with `go build -o trufflehog .` (`Dockerfile:9`);
the `Makefile` uses `CGO_ENABLED=0 go run . …` / `CGO_ENABLED=0 go install .`
(`Makefile:48-52`, `Makefile:17-18`). Following that convention, the binary used
throughout this document was built from the repository root with:

```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .
```

This produces a self-contained static ELF (no dynamic detector loading — see
Q5). The binary reports its version as `trufflehog dev` because it is built
outside the release pipeline.

**Synthetic test corpus.** A temporary, mixed-file-type repository was created
**outside** the source tree, under `/tmp/th_obs/testrepo`, containing:

| File | Content |
|------|---------|
| `secret.txt` | A GitHub personal-access-token (`ghp_…`) |
| `aws_creds.txt` | An AWS access-key ID + secret-access-key pair |
| `config.env` | A Postgres connection URI and an HTTPS-credential URI |
| `app.go` | A Go source file (plain text, no secrets) |
| `blob.bin` | 4 KiB of random bytes (a binary blob) |
| `nested/deep/nested_secret.txt` | A GitHub PAT in a nested subdirectory |
| `archived.zip` | A ZIP archive containing a GitHub PAT |

Two constraints shaped the corpus: (1) the `zip` and `file` CLI utilities were
not assumed present, so the ZIP archive was produced with **Python's `zipfile`**
module; and (2) all credentials use **genuinely high-entropy** values, because
low-entropy placeholders are dropped by TruffleHog's false-positive filtering
(demonstrated in Q4). The credential values are synthetic test tokens, not real
accounts; any secret material in captured output is shown redacted as
`<redacted>`.

All build artifacts, the corpus, and observation scripts live only under `/tmp`
and were removed at completion; the source repository is never modified.

---

## Q1 — Startup & Detector Loading

> "Build from source and run a basic scan: what happens during startup? Are
> detector configurations loaded from files or compiled in? What initialization
> messages appear about which detectors get registered?"

**Sub-parts:** (a) what happens during startup; (b) are detector configurations
loaded from files or compiled in; (c) what initialization messages report which
detectors get registered.

### (a) What happens during startup

The entrypoint is a [kingpin](https://github.com/alecthomas/kingpin) CLI app
constructed at `main.go:47`:

```go
cli = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")
```

When a scan subcommand runs, `main.go` builds an `engine.Engine`, wiring the
detector set (see (b)) and then starting the engine. The engine's
`setDefaults` fills in unset options and, at the end, logs
`"default engine options set"` (`engine.go:373`). The engine then logs
`"engine initialized"` (`engine.go:521`), builds its Aho-Corasick keyword
prefilter — logging `"setting up aho-corasick core"` (`engine.go:529`) and
`"set up aho-corasick core"` (`engine.go:531`) — and finally launches its worker
pools (detailed in Q2). The Aho-Corasick "core" is the keyword prefilter built
from the compiled-in detector set: each detector contributes `Keywords()`
(`detectors.go:24`) that are used to cheaply route chunks to candidate detectors.

### (b) Detector configurations are compiled in, not loaded from files

The engine is constructed in `main.go` with its detector slice supplied
**in code**:

```go
Detectors:                append(defaults.DefaultDetectors(), conf.Detectors...),
```
(`main.go:519`)

The default set comes from `defaults.DefaultDetectors()` (`defaults.go:1704`),
which immediately delegates to `buildDetectorList()` (`defaults.go:1705`, defined
at `defaults.go:839`). `buildDetectorList()` is a **Go slice literal** of
detector struct instances:

```go
func buildDetectorList() []detectors.Detector {
	return []detectors.Detector{
		&abyssale.Scanner{},
		// …
		&zulipchat.Scanner{},
	}
}
```
(`defaults.go:839-1701`; first element `&abyssale.Scanner{}` at `defaults.go:840`,
last two `&zonkafeedback.Scanner{}` / `&zulipchat.Scanner{}` at
`defaults.go:1699-1700`)

No file is read to populate this list — it is a compile-time literal, so the
**detectors are compiled into the binary**. The `conf.Detectors` that is
*appended* comes from an **optional** `--config=<file>` (`main.go:519`;
`--config` flag shown in `--help`, Q5): that file only *augments* the defaults
with user-defined custom detectors. In other words, the default detector set is
never file-driven; the only file-based path is the optional custom-detector
config.

**Detector count.** At this commit, `buildDetectorList()` contains **831 active
default detectors**. This was counted directly from the slice literal
(`defaults.go:840-1700`): 829 entries of the form `&pkg.Scanner{}` plus 2
constructor-style entries (`aws_access_keys.New()`, `aws_session_keys.New()`),
with 28 further entries commented out (inactive). Public sources quote varying
figures (600+, 700+, 800+) and are therefore **not** authoritative for a specific
commit; the empirical **831** at `e42153d44a5e` is used here, derived from the
source itself.

### (c) Initialization messages (verbatim)

The four engine-initialization messages are emitted at verbosity `V(4)`
(`engine.go:373/521/529/531`) and the four worker-pool messages at `V(2)`
(`engine.go:663/678/693/708`). Running a basic filesystem scan at
`--log-level=5` with JSON logging enabled produces the following **verbatim**
startup sequence:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --log-level=5 --no-verification
```

```json
{"level":"info-4","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"default engine options set"}
{"level":"info-4","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"engine initialized"}
{"level":"info-4","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"setting up aho-corasick core"}
{"level":"info-4","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"set up aho-corasick core"}
{"level":"info-2","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-01T05:14:26Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

The JSON log format is selected by `--json`: `main.go:332` sets
`logFormat := log.WithConsoleSink` and `main.go:333-334` switches it to
`log.WithJSONSink` when `--json` is passed. **Without** `--json` the same
messages appear in the default tab-delimited console format, e.g.:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --log-level=5 --no-verification
```

```
2026-07-01T05:14:24Z	info-4	trufflehog	default engine options set
2026-07-01T05:14:24Z	info-4	trufflehog	engine initialized
2026-07-01T05:14:24Z	info-4	trufflehog	setting up aho-corasick core
2026-07-01T05:14:25Z	info-4	trufflehog	set up aho-corasick core
2026-07-01T05:14:25Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-01T05:14:25Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-01T05:14:25Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-01T05:14:25Z	info-2	trufflehog	starting notifier workers	{"count": 128}
```

**About those `count` values.** The counts are host-dependent. Worker-pool sizes
derive from the effective concurrency, which defaults to `runtime.NumCPU()`
(`main.go:58`, `--concurrency` flag `.Default(strconv.Itoa(runtime.NumCPU()))`).
The formula, read from `engine.go`, is: scanner workers `= concurrency`
(`engine.go:663`), detector workers `= concurrency × 8`
(`engine.go:676`; the multiplier default of 8 is set in `setDefaults` at
`engine.go:345`), verificationOverlap workers `= concurrency × 1`
(`engine.go:693`), and notifier
workers `= concurrency × 1` (`engine.go:708`). On the observation host Go's
`runtime.NumCPU()` reported **128**, yielding **128 / 1024 / 128 / 128** exactly
as shown. On a host with a different CPU count the numbers scale accordingly
(e.g. 8 CPUs → 8 / 64 / 8 / 8); the *relationship* is invariant.

**Answer to (b), explicitly:** detectors are **compiled in** — a Go slice literal
returned by `buildDetectorList()` (`defaults.go:839`). They are **not** loaded
from configuration files. The only file-based detector path is the optional
`--config` file used to add *custom* detectors on top of the compiled-in
defaults.

---

## Q2 — Verification Architecture (HTTP libraries + parallelism)

> "Examine the build dependencies — are there HTTP client libraries suggesting
> network verification? When running a scan and watching process activity, does
> verification happen in parallel or sequentially?"

**Sub-parts:** (a) which build dependencies are HTTP client libraries suggesting
network verification; (b) does verification happen in parallel or sequentially.

### (a) HTTP client libraries in the build dependencies

`go.mod` declares HTTP client libraries whose sole purpose is issuing live
verification requests:

- `github.com/hashicorp/go-retryablehttp v0.7.7` (`go.mod:63`, a **direct**
  dependency) — an HTTP client that automatically retries transient failures.
- `github.com/hashicorp/go-cleanhttp v0.5.2 // indirect` (`go.mod:231`) — provides
  clean, isolated `http.Transport`s (no shared global state).

These back the shared HTTP client constructors in `pkg/common/http.go`, which
detectors use when verifying a candidate secret against a provider's API:

- `ConstantResponseHttpClient` (`http.go:111`)
- `PinnedRetryableHttpClient` (`http.go:159`)
- `RetryableHTTPClient` (`http.go:180`)
- `SaneHttpClient` (`http.go:223`)

The presence of a *retrying* HTTP client plus a *clean-transport* library is a
strong structural signal that verification is performed by real network calls to
provider APIs (for example, the AWS detector calls the STS `GetCallerIdentity`
API; a GitHub token is checked against the GitHub API).

**The verification trigger.** Every detector implements the `Detector` interface
(`detectors.go:19`). Its central method carries a `verify bool` parameter:

```go
FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
```
(`detectors.go:21`)

When `verify` is `true`, the detector makes the network call; when `false`
(i.e. `--no-verification`), it only reports the candidate without contacting the
provider.

### (b) Verification is parallel, not sequential

The engine starts **four concurrent goroutine pools** in `startWorkers`
(`engine.go:646`). Each pool logs its size at startup (the same four `V(2)` lines
seen in Q1):

- `"starting scanner workers"` (`engine.go:663`) — enumerate & chunk sources.
- `"starting detector workers"` (`engine.go:678`) — run detectors on chunks; this
  is where verification happens.
- `"starting verificationOverlap workers"` (`engine.go:693`) — handle chunks
  matched by multiple detectors.
- `"starting notifier workers"` (`engine.go:708`) — report results.

Detector verification runs inside `detectorWorker` (`engine.go:1036`), of which
there are `concurrency × 8` instances (1024 on the observation host — see Q1).
Because there are many detector-worker goroutines all calling `FromData(…, verify=true, …)`
concurrently, **verification is parallel/concurrent, not sequential.**

**Verbatim evidence #1 — live network calls actually happen.** Running with
verification enabled, the Postgres and URI detectors attempted real DNS
resolution for the hostnames in the corpus's connection strings and surfaced the
resolver's error verbatim in each finding's `VerificationError` field:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --detector-timeout=5s
```

```
Postgres  VerificationError = "lookup db.example.com on 34.118.224.10:53: no such host"
URI       VerificationError = "lookup internal.example.com on 34.118.224.10:53: no such host"
```

(The full Postgres finding, including this `VerificationError`, is shown verbatim
in Q3.) DNS lookups against the pod resolver `34.118.224.10:53` are unambiguous
proof that verification is a live network operation.

**Verbatim evidence #2 — verification is measurably concurrent.** The same scan
was timed with verification off and on. With `--no-verification` the scan
finished in `8.581503ms`; with verification enabled it finished in
`255.892046ms`:

```bash
# verification OFF
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --no-verification
```

```json
{"level":"info-0","ts":"2026-07-01T05:14:28Z","logger":"trufflehog","msg":"finished scanning","chunks":7,"bytes":9305,"verified_secrets":0,"unverified_secrets":6,"scan_duration":"8.581503ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

```bash
# verification ON (with a per-detector timeout)
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --detector-timeout=5s
```

```json
{"level":"info-0","ts":"2026-07-01T05:14:30Z","logger":"trufflehog","msg":"finished scanning","chunks":7,"bytes":9305,"verified_secrets":0,"unverified_secrets":6,"scan_duration":"255.892046ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":6,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":550}}
```

Two facts in that verification-on line prove concurrency:

1. `"VerificationTimeSpentMS":550` is the **aggregate** verification time across
   all attempts, yet the wall-clock `"scan_duration":"255.892046ms"` is far
   smaller. The only way aggregate work (550 ms) can complete in ~256 ms of wall
   clock is if verification attempts ran **in parallel**.
2. `"verification_caching":{…,"Misses":6}` shows all six candidate secrets were
   dispatched for verification (they missed the cache), each on a detector worker.

Measured absolute timings are host- and network-dependent and vary run to run
(both values above came from the same matched comparison); the qualitative
result — verification adds a large, concurrently-incurred network cost on top of
the ~9 ms detection-only baseline — is stable.

**Answer to (b), explicitly:** verification happens **in parallel**, executed by
a pool of `concurrency × 8` detector-worker goroutines (`engine.go:678`,
`engine.go:1036`), not one credential at a time.


---

## Q3 — JSON Output Schema

> "Run a scan with JSON output: what is the actual schema for a finding? Are
> there fields for verification status, confidence scores, or metadata about
> where secrets were found?"

**Sub-parts:** (a) the actual finding schema under `--json`; (b) fields for
verification status, confidence scores, and provenance metadata.

### (a) The finding schema

Findings are serialized by `JSONPrinter.Print` (`json.go:19`). It builds an
anonymous struct literal beginning at `json.go:27` (`v := &struct { … }`) and
emits it via `json.Marshal(v)` (`json.go:75`) followed by
`fmt.Println(string(out))` (`json.go:81`). The struct defines **16 fields**
(`json.go:27-83`), in this order:

| # | Field | Type | Notes |
|---|-------|------|-------|
| 1 | `SourceMetadata` | `*source_metadatapb.MetaData` | Provenance — *where* the secret was found |
| 2 | `SourceID` | `sources.SourceID` | Numeric source ID |
| 3 | `SourceType` | `sourcespb.SourceType` | Enum (e.g. `15` = filesystem) |
| 4 | `SourceName` | `string` | e.g. `"trufflehog - filesystem"` |
| 5 | `DetectorType` | `detectorspb.DetectorType` | Enum (e.g. `8` = Github) |
| 6 | `DetectorName` | `string` | `= r.DetectorType.String()` |
| 7 | `DetectorDescription` | `string` | Human-readable detector description |
| 8 | `DecoderName` | `string` | `= r.DecoderType.String()` (e.g. `"PLAIN"`) |
| 9 | `Verified` | `bool` | **Verification status** |
| 10 | `VerificationError` | `string` | `` `json:",omitempty"` `` — present only when non-empty |
| 11 | `VerificationFromCache` | `bool` | Whether the verification result was cached |
| 12 | `Raw` | `string` | Raw secret material |
| 13 | `RawV2` | `string` | Composite raw identifier (multi-part secrets) |
| 14 | `Redacted` | `string` | Redacted display form |
| 15 | `ExtraData` | `map[string]string` | Detector-specific extra key/values |
| 16 | `StructuredData` | `*detectorspb.StructuredData` | Structured payload (e.g. found in TLS certs); `null` if none |

**Verbatim finding.** A basic `--json` scan of the corpus emits one JSON object
per finding. Here is a real GitHub finding (the raw token is redacted for safety;
everything else is verbatim):

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --no-verification
```

```json
{
  "SourceMetadata": {
    "Data": {
      "Filesystem": {
        "file": "/tmp/th_obs/testrepo/secret.txt",
        "line": 1
      }
    }
  },
  "SourceID": 1,
  "SourceType": 15,
  "SourceName": "trufflehog - filesystem",
  "DetectorType": 8,
  "DetectorName": "Github",
  "DetectorDescription": "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources.",
  "DecoderName": "PLAIN",
  "Verified": false,
  "VerificationFromCache": false,
  "Raw": "<redacted>",
  "RawV2": "",
  "Redacted": "",
  "ExtraData": {
    "rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
    "version": "2"
  },
  "StructuredData": null
}
```

Note that `VerificationError` does **not** appear in this object: the field is
declared with a `json:",omitempty"` struct tag (`json.go:45`), and because this
run used `--no-verification` the error string was empty and `omitempty` dropped
it. So the *struct* has 16 fields, but a finding with no verification error
renders **15** keys.

**Verbatim finding with `VerificationError` present.** Re-running with
verification enabled, the Postgres finding carries the DNS error from Q2, which
shows exactly where `VerificationError` sits in the schema — between `Verified`
and `VerificationFromCache`, matching `json.go:44-46`:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --detector-timeout=5s
```

```json
{
  "SourceMetadata": {
    "Data": {
      "Filesystem": {
        "file": "/tmp/th_obs/testrepo/config.env",
        "line": 1
      }
    }
  },
  "SourceID": 1,
  "SourceType": 15,
  "SourceName": "trufflehog - filesystem",
  "DetectorType": 968,
  "DetectorName": "Postgres",
  "DetectorDescription": "Postgres connection string containing credentials",
  "DecoderName": "PLAIN",
  "Verified": false,
  "VerificationError": "lookup db.example.com on 34.118.224.10:53: no such host",
  "VerificationFromCache": false,
  "Raw": "<redacted>",
  "RawV2": "<redacted>",
  "Redacted": "",
  "ExtraData": {
    "sslmode": "<unset>"
  },
  "StructuredData": null
}
```

### (b) Verification status, confidence scores, and provenance — explicitly

- **Verification status field:** it is **`Verified`** — a **boolean**
  (`json.go:44`; `"Verified": false` above). Live verification errors are
  reported separately in `VerificationError` (`json.go:45`, omitempty), and
  cache provenance for the verification result in `VerificationFromCache`
  (`json.go:46`).
- **Confidence / score field:** **there is none.** No numeric confidence, score,
  or probability field exists anywhere in the serialized struct (`json.go:27-83`).
  TruffleHog's model is binary — a secret is either `Verified` (true/false) — not
  a scored likelihood. This is stated as an explicit absence: the question's
  "confidence scores" have **no** corresponding field.
- **Provenance metadata (where the secret was found):** it is **`SourceMetadata`**
  (`json.go:29`). For a filesystem scan it nests a `Filesystem` object carrying
  the absolute `file` path and the 1-based `line` number, e.g.
  `{"Data":{"Filesystem":{"file":"…/secret.txt","line":1}}}`. That shape is
  defined in `proto/source_metadata.proto`: `message Filesystem {`
  (`source_metadata.proto:87`) with `string file = 1;`
  (`source_metadata.proto:88`) and `int64 line = 4;` (`source_metadata.proto:91`).

**Enum cross-references** for the values observed above:

- `"SourceType": 15` ↔ `SOURCE_TYPE_FILESYSTEM = 15;` (`sources.proto:30`).
- `"DetectorType": 8` (Github) ↔ `Github = 8;` (`detectors.proto:24`);
  `968` (Postgres) ↔ `Postgres = 968;` (`detectors.proto:980`). (Observed values
  for the other corpus findings: `AWS = 2` / `detectors.proto:18`; `URI = 17` /
  `detectors.proto:33`.)
- `"DecoderName": "PLAIN"` ↔ the `DecoderType` enum `PLAIN = 1;` (`detectors.proto:9`),
  with `BASE64 = 2;` (`detectors.proto:10`) and `UTF16 = 3;` (`detectors.proto:11`).
  Decoder names originate from `pkg/decoders/` (`utf8.go`, `base64.go`,
  `utf16.go`, `escaped_unicode.go`); a plain-text hit reports `"PLAIN"`.


---

## Q4 — Repository Traversal & File Selection

> "Scan a test repo with mixed file types and check the verbose logs: how does
> TruffleHog decide which files to scan versus skip?"

**Sub-part:** how TruffleHog decides which files to scan vs skip, as evidenced by
the verbose logs.

File selection is a pipeline of decisions: walk the tree → skip non-regular
files → apply include/exclude path filters → detect MIME type → route by type
(recurse into archives, chunk everything else). Each stage is cited below and
then shown in verbatim `--log-level=5` output.

### The decision pipeline (with citations)

1. **Directory walk.** The filesystem source walks a directory with
   `fs.WalkDir(os.DirFS(path), ".", func(...) error { … })` (`filesystem.go:125`),
   visiting every entry beneath the scan root.

2. **Skip non-regular files.** A path argument that is a symlink (i.e. not a
   regular file) is skipped with the log line
   `logger.Info("skipping, not a regular file", "path", cleanPath)`
   (`filesystem.go:101`, guarded by the `os.ModeSymlink` check at
   `filesystem.go:100`). Symlinks encountered *during* the walk are likewise
   skipped: `scanFile` returns the sentinel `skipSymlinkErr`
   (`filesystem.go:161` defines it; `filesystem.go:169-170` returns it on
   `os.ModeSymlink`). *(In the default units-based enumeration path a symlink
   passed as an argument is enumerated as a scan "unit" rather than routed through
   the `filesystem.go:101` branch, so that exact log line was not triggered at
   runtime in this environment; the skip logic is nonetheless present at the cited
   lines.)*

3. **Include/exclude path filter.** During the walk each path is checked against
   an optional filter: `if s.filter != nil && !s.filter.Pass(fullPath) { … }`
   (`filesystem.go:134`). The filter is built from the `-i/--include-paths` and
   `-x/--exclude-paths` files via
   `common.FilterFromFiles(conn.IncludePathsFile, conn.ExcludePathsFile)`
   (`filesystem.go:75`). Excluded directories short-circuit with `fs.SkipDir`.

4. **MIME detection.** Selected files are routed by content type using
   `github.com/gabriel-vasile/mimetype` (`handlers.go:12`). Detection reads a
   magic-number buffer — "A buffer of 512 bytes is used since many file formats
   store their magic numbers within the first 512 bytes." (`handlers.go:91`) — and
   calls `mimetype.Detect(buffer)` (`handlers.go:98`) or, for streams,
   `mimetype.DetectReader(fReader)` (`handlers.go:127`).

5. **Archive handling (recursion).** Archives are recursively unpacked and their
   contents scanned, unless skipping is requested. The set of MIME types that
   bypass the archiver is `skipArchiverMimeTypes` (looked up at `handlers.go:151`,
   defined at `handlers.go:266`), and archive scanning can be disabled with the
   option `func WithSkipArchives(skip bool)` (`handlers.go:212`, documented at
   `handlers.go:210-211`) — surfaced on the CLI as `--force-skip-archives`
   (see Q5).

6. **Binary handling.** Binary content is recognized (e.g. as
   `application/octet-stream`). The `SkipBinaries` option
   (`sources.go:227`, documented at `sources.go:226`) — CLI
   `--force-skip-binaries` — governs whether binaries are dropped; the git source
   logs `logger.V(5).Info("skipping binary file", …)` when it does so
   (`git.go:648`, also `git.go:877`). In the **default filesystem scan** binaries
   are **not** skipped: a blob detected as `application/octet-stream` is still
   chunked and scanned (verbatim below).

### Verbatim verbose observations

All of the following came from:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/testrepo --json --log-level=5 --no-verification
```

**MIME type is detected per file** (the `mime` field on each file's completion
log). Across the corpus:

```
app.go            => text/plain; charset=utf-8
aws_creds.txt     => text/plain; charset=utf-8
config.env        => text/plain; charset=utf-8
nested_secret.txt => text/plain; charset=utf-8
secret.txt        => text/plain; charset=utf-8
archived.zip      => application/zip
blob.bin          => application/octet-stream
```

**Archives are recursively unpacked, tracked by a `depth` counter.** The ZIP is
opened at `depth:0`, its inner file `archived_secret.txt` (62 bytes) is processed
at `depth:1`, and processing unwinds `depth:1` → `depth:0`:

```json
{"level":"info-4","ts":"2026-07-01T05:20:27Z","logger":"trufflehog","msg":"Starting archive processing","source_manager_worker_id":"GVlyd","unit_kind":"unit","unit":"/tmp/th_obs/testrepo/archived.zip","path":"/tmp/th_obs/testrepo/archived.zip","mime":"application/zip","timeout":60,"depth":0}
{"level":"info-4","ts":"2026-07-01T05:20:27Z","logger":"trufflehog","msg":"Starting archive processing","source_manager_worker_id":"GVlyd","unit_kind":"unit","unit":"/tmp/th_obs/testrepo/archived.zip","path":"/tmp/th_obs/testrepo/archived.zip","mime":"application/zip","timeout":60,"filename":"archived_secret.txt","size":62,"depth":1}
{"level":"info-4","ts":"2026-07-01T05:20:27Z","logger":"trufflehog","msg":"Finished archive processing","source_manager_worker_id":"GVlyd","unit_kind":"unit","unit":"/tmp/th_obs/testrepo/archived.zip","path":"/tmp/th_obs/testrepo/archived.zip","mime":"application/zip","timeout":60,"filename":"archived_secret.txt","size":62,"depth":1}
{"level":"info-4","ts":"2026-07-01T05:20:27Z","logger":"trufflehog","msg":"Finished archive processing","source_manager_worker_id":"GVlyd","unit_kind":"unit","unit":"/tmp/th_obs/testrepo/archived.zip","path":"/tmp/th_obs/testrepo/archived.zip","mime":"application/zip","timeout":60,"depth":0}
```

Recursion is confirmed by results: the GitHub PAT hidden inside the ZIP **and**
the one in `nested/deep/nested_secret.txt` were both reported, so archive
contents and nested directories are scanned, not skipped.

**A binary blob is detected as `application/octet-stream` yet still chunked.**
`blob.bin` is not skipped in a default filesystem scan; it is opened and its
chunks are processed:

```json
{"level":"info-5","ts":"2026-07-01T05:20:28Z","logger":"trufflehog","msg":"dataErrChan closed, all chunks processed","source_manager_worker_id":"L5uHl","unit_kind":"unit","unit":"/tmp/th_obs/testrepo/blob.bin","path":"/tmp/th_obs/testrepo/blob.bin","mime":"application/octet-stream","timeout":60}
```

**Low-quality candidates are dropped by false-positive filtering.** This is the
mechanism that would discard low-entropy placeholder secrets. A crafted
GitHub-format token whose body contains the word `example` is filtered out with
the reason `contains term: example`:

```bash
/tmp/trufflehog_bin filesystem /tmp/th_obs/fptest --json --log-level=5 --no-verification
```

```json
{"level":"info-4","ts":"2026-07-01T05:20:30Z","logger":"trufflehog","msg":"Skipping result: false positive","verification_overlap_worker_id":"y3EE6","timeout":2,"result":"<redacted>","reason":"contains term: example"}
```

That log is emitted at `falsepositives.go:194`
(`ctx.Logger().V(4).Info("Skipping result: false positive", …, "reason", reason)`),
and the reason string is built at `falsepositives.go:98`
(`"contains term: " + fps`). The trigger set `DefaultFalsePositives` —
`{"example","xxxxxx","aaaaaa","abcde","00000","sample","*****"}` — is defined at
`falsepositives.go:17`. This is exactly why the main corpus uses genuinely
high-entropy credentials: low-entropy placeholders are dropped here before they
can be reported.

**Summary of the scan/skip decision.** A file is **scanned** if it survives the
walk (regular file), passes the include/exclude filter, and is chunkable after
MIME detection — with archives recursed into by content type. A file (or path)
is **skipped** if it is a symlink/non-regular file (`filesystem.go:100-101`,
`filesystem.go:169-170`), fails the include/exclude filter
(`filesystem.go:134`), is an archive when archives are disabled
(`handlers.go:212`), or is a binary when `SkipBinaries` is enabled
(`sources.go:227`). Individual *results* are additionally dropped by
false-positive filtering (`falsepositives.go:194`). By default, binaries are
scanned (not skipped), as shown above.


---

## Q5 — Detector Architecture & Help

> "When compiling the project, are detectors separate plugins or embedded
> modules? Running the binary with a help flag, what does it show about available
> detection capabilities?"

**Sub-parts:** (a) are detectors separate plugins or embedded modules; (b) what
`--help` shows about detection capabilities.

### (a) Detectors are embedded modules, not plugins

Detectors are ordinary Go types that implement the `Detector` interface
(`type Detector interface {` at `detectors.go:19`) and are **linked into a single
static binary**. Two independent facts establish this:

1. **No plugin machinery exists.** A repository-wide search of the Go source
   found **zero** occurrences of `plugin.Open` and **zero** imports of the Go
   standard-library `"plugin"` package (both counts verified `= 0`). Go's dynamic
   plugin system is the only built-in way to load code at runtime, and it is not
   used anywhere. There is therefore no runtime plugin loading — detectors cannot
   be "separate plugins."

2. **Detectors are a compile-time slice literal.** As established in Q1, the
   active detector set is the Go slice literal returned by `buildDetectorList()`
   (`defaults.go:839`), instantiated as struct values (`&abyssale.Scanner{}`, …)
   at compile time. Combined with the `CGO_ENABLED=0` static build
   (`Dockerfile:5`), every one of the 831 detectors is compiled directly into the
   binary.

**Answer to (a), explicitly:** detectors are **embedded modules** (compiled-in Go
packages), **not** separate/runtime-loaded plugins.

### (b) What `--help` advertises about detection capabilities

The binary's top-level help enumerates the available scan **sources** and the
detector-selection **flags**. It exposes **16 top-level commands**: 15
source-scan subcommands plus `analyze`. The 15 source subcommands are defined in
`main.go` via `cli.Command(...)`: `git` (`main.go:93`), `github`
(`main.go:106`), `github-experimental` (`main.go:124`), `gitlab`
(`main.go:133`), `filesystem` (`main.go:143`), `s3` (`main.go:152`), `gcs`
(`main.go:162`), `syslog` (`main.go:174`), `circleci` (`main.go:181`), `docker`
(`main.go:184`), `travisci` (`main.go:188`), `postman` (`main.go:192`),
`elasticsearch` (`main.go:216`), `jenkins` (`main.go:228`), and `huggingface`
(`main.go:234`). The 16th command, `analyze`, is registered via
`analyzeCmd = analyzer.Command(cli)` (`main.go:255`), which calls
`app.Command("analyze", "Analyze API keys for fine-grained permissions information.")`
(`pkg/analyzer/cli.go:51`); it analyzes a key's permissions rather than scanning
a source. (kingpin also lists a built-in `help` command, which is not one of the
16.)

The detector-**selection** flags shown in help are:

- `--results` — `cli.Flag("results", "Specifies which type(s) of results to output: verified, unknown, unverified, filtered_unverified. Defaults to verified,unverified,unknown.")` (`main.go:61`).
- `--include-detectors` — defaults to `"all"` (`main.go:81`).
- `--exclude-detectors` — (`main.go:82`); per its help text, IDs excluded here take precedence over the include list.

**Verbatim `--help` output.** The following is the complete, unedited output
(exit code `0`):

```bash
/tmp/trufflehog_bin --help
```

```
usage: TruffleHog [<flags>] <command> [<args> ...]

TruffleHog is a tool for finding credentials.


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

Commands:
help [<command>...]
    Show help.

git [<flags>] <uri>
    Find credentials in git repositories.

github [<flags>]
    Find credentials in GitHub repositories.

github-experimental --repo=REPO [<flags>]
    Run an experimental GitHub scan. Must specify at least one experimental
    sub-module to run: object-discovery.

gitlab --token=TOKEN [<flags>]
    Find credentials in GitLab repositories.

filesystem [<flags>] [<path>...]
    Find credentials in a filesystem.

s3 [<flags>]
    Find credentials in S3 buckets.

gcs [<flags>]
    Find credentials in GCS buckets.

syslog [<flags>]
    Scan syslog

circleci --token=TOKEN
    Scan CircleCI

docker --image=IMAGE [<flags>]
    Scan Docker Image

travisci --token=TOKEN
    Scan TravisCI

postman [<flags>]
    Scan Postman

elasticsearch [<flags>]
    Scan Elasticsearch

jenkins --url=URL [<flags>]
    Scan Jenkins

huggingface [<flags>]
    Find credentials in HuggingFace datasets, models and spaces.

analyze
    Analyze API keys for fine-grained permissions information.
```

Note the help does **not** print the individual 831 detector names; detection
capability is instead selected wholesale via `--include-detectors` /
`--exclude-detectors` (which accept detector protobuf names, IDs, or ID ranges),
and the *source* to scan is chosen via one of the 16 subcommands above. It also
advertises the traversal controls seen in Q4 — `--force-skip-binaries`,
`--force-skip-archives`, `--archive-max-depth` — and the verification controls
seen in Q2 — `--no-verification`, `--detector-timeout`, `--no-verification-cache`.


---

## Coverage Pass

A final pass over each question and its sub-parts, confirming each was answered
and pointing to where.

**Q1 — Startup & Detector Loading**

- (a) *What happens during startup?* — Answered in Q1(a): kingpin app
  (`main.go:47`) → engine build → `setDefaults` → engine-init log lines
  (`engine.go:373/521/529/531`) → Aho-Corasick prefilter → worker pools.
- (b) *Loaded from files or compiled in?* — Answered explicitly in Q1(b) and
  restated at the end of Q1: **compiled in** (slice literal `buildDetectorList()`,
  `defaults.go:839`); `--config` only augments with custom detectors.
- (c) *What initialization messages report which detectors get registered?* —
  Answered in Q1(c) with the verbatim 8-line startup sequence (JSON and console
  forms) and the detector count of **831** (`defaults.go:840-1700`).

**Q2 — Verification Architecture**

- (a) *HTTP client libraries suggesting network verification?* — Answered in
  Q2(a): `go-retryablehttp v0.7.7` (`go.mod:63`) + `go-cleanhttp v0.5.2`
  (`go.mod:231`), plus the `pkg/common/http.go` constructors.
- (b) *Parallel or sequential?* — Answered explicitly in Q2(b): **parallel** —
  four worker pools (`engine.go:646/663/678/693/708`), verification in
  `detectorWorker` (`engine.go:1036`), with verbatim DNS errors and the
  `VerificationTimeSpentMS:550` > `scan_duration:255.892046ms` concurrency proof.

**Q3 — JSON Output Schema**

- (a) *Actual finding schema?* — Answered in Q3(a): the 16-field struct
  (`json.go:27-83`) tabulated, plus two verbatim finding objects (15 keys without
  a verification error, 16 with).
- (b) *Verification status / confidence / provenance fields?* — Answered
  explicitly in Q3(b): verification status = **`Verified` (boolean)**
  (`json.go:44`); **NO confidence/score field exists** anywhere in the struct
  (`json.go:27-83`); provenance = **`SourceMetadata`** (`json.go:29`;
  `source_metadata.proto:87-91`).

**Q4 — Repository Traversal & File Selection**

- *How does it decide which files to scan vs skip?* — Answered in Q4 as a cited
  pipeline (walk `filesystem.go:125` → non-regular/symlink skip
  `filesystem.go:100-101,169-170` → include/exclude filter `filesystem.go:134,75`
  → MIME detection `handlers.go:91/98/127` → archive recursion
  `handlers.go:151/212/266` → binary handling `git.go:648`, `sources.go:227`),
  with verbatim MIME map, archive `depth` recursion, octet-stream-still-chunked,
  and false-positive drop (`falsepositives.go:98/194`).

**Q5 — Detector Architecture & Help**

- (a) *Plugins or embedded modules?* — Answered explicitly in Q5(a):
  **embedded modules**; **zero** `plugin.Open` and **zero** stdlib `"plugin"`
  imports (both verified `= 0`); compile-time slice literal (`defaults.go:839`)
  in a `CGO_ENABLED=0` static binary.
- (b) *What does `--help` show about detection capabilities?* — Answered in
  Q5(b): full verbatim `--help`; **16 top-level commands** (15 sources +
  `analyze`, cited to `main.go:93-234` and `pkg/analyzer/cli.go:51`) and the
  selection flags `--results` (`main.go:61`), `--include-detectors`
  (`main.go:81`), `--exclude-detectors` (`main.go:82`).

**Read-only constraint upheld.** No existing repository file was modified. The
only file added is this document (`blitzy/documentation/trufflehog_e42153d44a5e.md`).
The compiled binary, the synthetic corpus, and all observation scripts lived
exclusively under `/tmp` (outside the repository) and were removed at completion,
leaving the source tree in its original `git`-clean state.

