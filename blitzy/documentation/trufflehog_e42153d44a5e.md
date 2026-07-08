# TruffleHog Onboarding Q&A — Secret‑Detection Architecture

**Branch:** `trufflehog_e42153d44a5e` · **HEAD:** `e42153d4` · **Module:** `github.com/trufflesecurity/trufflehog/v3` [go.mod:L1]

This document answers five onboarding questions about how TruffleHog's secret‑detection
engine behaves. Every behavioral claim below was produced by **actually building the tool
from source and running it**, and each is paired with the *complete, unedited* output and
the exact command that produced it. Claims that are derived only from reading the code
(and could not be observed at runtime) are explicitly labeled **(inferred from reading)**.
Code claims cite `file:line` against HEAD `e42153d4`.

## How the evidence was produced (canonical, default configuration)

- **Toolchain:** Go **1.24.2** — the version pinned by the project (`toolchain go1.24.2`
  [go.mod:L5]; `go 1.23.1` [go.mod:L3]). `go version` → `go version go1.24.2 linux/amd64`.
- **Build (canonical, exactly as a normal user would):**
  ```
  CGO_ENABLED=0 go build -o /tmp/trufflehog .
  ```
  This is the same invocation the project's own tooling uses: the `Dockerfile` builds with
  `CGO_ENABLED=0` [Dockerfile:L5] and `go build -o trufflehog .` [Dockerfile:L9] on
  `golang:bullseye` [Dockerfile:L1], shipping on `alpine:3.21` [Dockerfile:L11]; the
  `Makefile` `install:` target is `CGO_ENABLED=0 go install .` [Makefile:L17-L18] and its
  `run:` target is `CGO_ENABLED=0 go run . git file://. --json` [Makefile:L48-L49]
  (`run-debug:`/`dogfood:` add `--log-level=2` [Makefile:L14-L15,L51-L52]). The build
  succeeds and produces a ~194 MB static binary (`194309218` bytes). Building to `/tmp`
  keeps the repository byte‑for‑byte unchanged.
- **Host:** `runtime.NumCPU()` = **128** (measured by a 3‑line probe compiled with the same
  toolchain; see *Methodology*). This value — not the shell's `nproc` — is what drives
  concurrency, because `--concurrency` defaults to `runtime.NumCPU()` [main.go:L58], and it
  is confirmed by `--help` printing `--concurrency=128`. All worker counts below therefore
  scale from 128. If you run on a host with a different CPU count, expect the same
  *relationships* (e.g., detector workers = `NumCPU × 8`) with different absolute numbers.
- **Target:** a throwaway fixture under `/tmp/thog_fixture` containing mixed file types with
  planted **non‑real** secrets (a GitHub‑style token, the well‑known AWS documentation
  example key, a 4 KB random binary, a real 1×1 PNG, and a Python source file). The fixture
  and all scripts live outside the repository and are removed afterward.

> Note on the fixture token: the planted GitHub token is a randomly generated, **non‑real**
> value (it verifies to `false`; its 36‑character body — `ghp_` followed by 36 random
> `[a-zA-Z0-9]` characters — matches the GitHub detector's regex but authenticates to
> nothing). Because it is synthetic and harmless, it is shown **in full, exactly as emitted**
> in every output block below; nothing is redacted or edited.

---

## Q1 — Startup & detector registration

> *"If I build it from source and run a basic scan, what happens during startup? Does it load detector configurations from files, or are they compiled in? What initialization messages appear about which detectors get registered?"*

### Direct answers

1. **Detectors are compiled into the binary — they are NOT loaded from configuration
   files.** The full set is returned by `func DefaultDetectors() []detectors.Detector`
   [pkg/engine/defaults/defaults.go:L1704], which wraps `buildDetectorList()`
   [pkg/engine/defaults/defaults.go:L839] (a hard‑coded Go slice literal that constructs one
   instance of every detector package imported at compile time) and then auto‑initializes
   any detector implementing the `EndpointCustomizer`/`CloudProvider` interfaces
   [pkg/engine/defaults/defaults.go:L1708-L1717]. The engine uses this compiled‑in set
   **only when the caller supplies none**:
   `if len(e.detectors) == 0 { e.detectors = defaults.DefaultDetectors() }`
   [pkg/engine/engine.go:L362-L363]. A `--config` flag exists [main.go:L70] (detailed in Q5) but it adds
   *custom* detectors on top of the compiled‑in set; it is not the source of the built‑in
   detectors.

2. **Scale:** `pkg/detectors/` contains **845** detector subdirectories
   (`find pkg/detectors -mindepth 1 -maxdepth 1 -type d | wc -l` → `845`) — i.e., the
   "800+ detectors" scale, all compiled in.

3. **What startup does:** the process parses the CLI with `alecthomas/kingpin`
   (`cli = kingpin.New("TruffleHog", "TruffleHog is a tool for finding credentials.")`
   [main.go:L47]), wires the version string via
   `cli.Version("trufflehog " + version.BuildVersion)` [main.go:L270], prints a version
   banner at verbosity 2 (`logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))`
   [main.go:L410]), then constructs the engine, which launches four worker pools before it
   begins enumerating the source.

4. **The version of a from‑source build is `trufflehog dev`** — this is CANONICAL, not a
   defect. `var BuildVersion = "dev"` [pkg/version/version.go:L3] is the default; a real
   semantic version is injected only by release (goreleaser/ldflags) builds. Because the
   build is unstamped, the self‑updater is also disabled — the updater's fetcher is set to nil
   for a `dev` build: `if version.BuildVersion == "dev" { updateCfg.Fetcher = nil }`
   [main.go:L360-L362].

5. **No per‑detector "registered" messages appear.** Registration is a compile‑time slice,
   not a runtime event, so there is nothing logged like "registered detector X." The only
   count‑bearing startup lines are the four `starting … workers` lines. This is a plain
   negative result: if you are looking for a per‑detector registration log, there is none.

6. **CLI flag defaults relevant to startup:** `--log-level` defaults to `"0"` (info)
   [main.go:L50]; `--concurrency` defaults to `runtime.NumCPU()` [main.go:L58].

### Observed startup output

Command (verification is ON by default):

```
/tmp/trufflehog filesystem /tmp/thog_fixture --json --log-level=2
```

Complete stderr (structured logs), unedited:

```
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
{"level":"info-0","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"Tze5J","with_units":true}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"enumerating source","source_manager_worker_id":"Tze5J"}
{"level":"info-0","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"finished scanning","chunks":4,"bytes":9095,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"180.492988ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":283}}
```

### Cause → effect

- The banner `"trufflehog dev"` is emitted by `logger.V(2).Info(fmt.Sprintf("trufflehog %s", version.BuildVersion))` [main.go:L410]; `version.BuildVersion` is `"dev"` [pkg/version/version.go:L3], hence `dev`. It also appears as `"trufflehog_version":"dev"` in the closing `finished scanning` summary.
- The four `starting … workers` lines are logged at `V(2)` as the engine boots its pools:
  scanner [pkg/engine/engine.go:L663], detector [pkg/engine/engine.go:L678],
  verificationOverlap [pkg/engine/engine.go:L693], notifier [pkg/engine/engine.go:L708].
  (Corroborated by `docs/concurrency.md`, which shows `e.startWorkers()` starting these four
  worker types, and by `docs/process_flow.md`, which frames the pipeline as Source
  Decomposition → Chunk‑to‑Detector Matching → Secret Detection → Result Notification.)
- Because there is no configuration‑file load step for detectors, no file‑read or
  registration log precedes the worker lines — consistent with the compiled‑in design in
  `DefaultDetectors()` [pkg/engine/defaults/defaults.go:L1704].

---

## Q2 — Verification (dependencies + concurrency)

> *"When I examine the build dependencies, are there HTTP client libraries suggesting network verification? If I run a scan and watch the process activity, does the architecture show verification happening in parallel or sequentially?"*

### Direct answers

1. **Yes — there is an HTTP client dependency that indicates live network verification.**
   The relevant module is `github.com/hashicorp/go-retryablehttp v0.7.7` [go.mod:L63], an
   HTTP client with automatic retries — exactly what live credential verification against
   provider APIs needs. Supporting code: `func SaneHttpClient()`
   [pkg/common/http.go:L223], which sets `httpClient.Timeout = DefaultResponseTimeout` where
   `const DefaultResponseTimeout = 5 * time.Second` [pkg/common/http.go:L209]; and the
   detector‑side `const DefaultResponseTimeout = 10 * time.Second`
   [pkg/detectors/http.go:L18]. (Corroborated by the official "Introducing TruffleHog v3"
   write‑up, which states verification issues live provider API calls, e.g. validating an
   AWS key via `GetCallerIdentity` — but the code and observed behavior above are the source
   of truth.)

2. **Verification runs in PARALLEL, not sequentially.** Verification is performed *inside*
   the detector‑worker pool, and that pool is deliberately over‑provisioned. In
   `setDefaults()`:
   - base concurrency defaults to `runtime.NumCPU()`
     (`e.concurrency = numCPU` [pkg/engine/engine.go:L337-L341]);
   - the detector‑worker multiplier defaults to **8** with the explicit rationale
     *"bound by net i/o so it's higher than other workers"*
     [pkg/engine/engine.go:L343-L345];
   - the notification and verification‑overlap multipliers each default to **1**
     [pkg/engine/engine.go:L348-L349, L352-L353].

   The detector‑worker count is computed as
   `numWorkers := e.concurrency * e.detectorWorkerMultiplier`
   [pkg/engine/engine.go:L676]. So `NumCPU × 8` verifications can proceed concurrently.

### Observed concurrency (same run as Q1)

```
/tmp/trufflehog filesystem /tmp/thog_fixture --json --log-level=2
```

The worker lines (stderr) show the parallel pools directly:

```
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

### Cause → effect

- `starting detector workers count=1024` = `128 × 8` (host `runtime.NumCPU()` = 128 ×
  `detectorWorkerMultiplier` = 8 [pkg/engine/engine.go:L343-L345,L676]). Since verification
  happens inside these workers, up to 1024 verifications can be in flight at once — the
  architecture is parallel, not sequential.
- `scanner` = 128 = `e.concurrency` [pkg/engine/engine.go:L663]; `verificationOverlap` =
  128 = `e.concurrency × 1` [pkg/engine/engine.go:L691]; `notifier` = 128 =
  `e.notificationWorkerMultiplier × e.concurrency` [pkg/engine/engine.go:L706]. All three
  1× pools equal `NumCPU`.
- **Stability:** the counts are structurally identical across two consecutive runs of the
  same command (see *Methodology*): `128 / 1024 / 128 / 128` both times.
- **Supporting dependencies** for the verification/dedup machinery (inferred from reading
  `go.mod`, not from a runtime log): `github.com/hashicorp/golang-lru/v2 v2.0.7`
  [go.mod:L64] backs the verification cache (surfaced at runtime as the
  `verification_caching` object in the `finished scanning` line above);
  `github.com/adrg/strutil v0.3.1` [go.mod:L19] provides Levenshtein similarity for the
  verification‑overlap logic; and `go.uber.org/automaxprocs v1.6.0` [go.mod:L104] makes
  `GOMAXPROCS` container‑aware. The structured logger itself is
  `go.uber.org/zap v1.27.0` [go.mod:L106].

---

## Q3 — JSON output schema

> *"If I run a scan with JSON output, what's the actual schema for a finding? Are there fields for verification status, confidence scores, or metadata about where secrets were found?"*

### Direct answers

- **Verification status — YES.** The schema has `Verified bool`, plus `VerificationError string`
  (tagged `json:",omitempty"`, so it is omitted when empty) and `VerificationFromCache bool`.
- **Confidence score — NO.** There is **no numeric confidence‑score field** anywhere in the
  printed finding. (Stated plainly as a negative result.)
- **Location metadata — YES.** Every finding carries `SourceMetadata`, whose shape is
  **source‑dependent** (details below).

### Schema source and the full field list

The `--json` output is produced by
`func (p *JSONPrinter) Print(_ context.Context, r *detectors.ResultWithMetadata) error`
[pkg/output/json.go:L19], which assigns `v` an anonymous struct value whose declaration
begins at [pkg/output/json.go:L27], `json.Marshal`s it [pkg/output/json.go:L75], and prints
it with `fmt.Println(string(out))` [pkg/output/json.go:L81]. That struct declares **16
top‑level fields, in this exact order** (each field's exact Go declaration is reproduced in
the table below):

| # | Field | Go type | Notes |
|---|-------|---------|-------|
| 1 | `SourceMetadata` | `*source_metadatapb.MetaData` | location/provenance (see below) |
| 2 | `SourceID` | `sources.SourceID` | ID the API uses to map secrets to sources |
| 3 | `SourceType` | `sourcespb.SourceType` | enum (e.g. `SOURCE_TYPE_FILESYSTEM = 15` [proto/sources.proto:L30], git = 16 [proto/sources.proto:L31]) |
| 4 | `SourceName` | `string` | e.g. `"trufflehog - filesystem"` |
| 5 | `DetectorType` | `detectorspb.DetectorType` | enum (e.g. `AWS = 2` [proto/detectors.proto:L18], `Github = 8` [proto/detectors.proto:L24], `PrivateKey = 15` [proto/detectors.proto:L31]) |
| 6 | `DetectorName` | `string` | `r.DetectorType.String()` |
| 7 | `DetectorDescription` | `string` | human description of the detector |
| 8 | `DecoderName` | `string` | e.g. `PLAIN` |
| 9 | `Verified` | `bool` | **verification status** |
| 10 | `VerificationError` | `string` `json:",omitempty"` | present only if verification errored |
| 11 | `VerificationFromCache` | `bool` | whether the verified result came from cache |
| 12 | `Raw` | `string` | raw secret data |
| 13 | `RawV2` | `string` | raw identifier combining ID + secret (multi‑part secrets) |
| 14 | `Redacted` | `string` | redacted form for display |
| 15 | `ExtraData` | `map[string]string` | detector‑specific extras |
| 16 | `StructuredData` | `*detectorspb.StructuredData` | structured payload (e.g. keys found in files) |

Two related‑but‑distinct definitions inform this schema (inferred from reading the
`.proto` files): the low‑level detector `message Result` [proto/detectors.proto:L1038] is
what a detector returns internally, while the printed JSON above is the *presentation*
struct assembled by the printer. `SourceMetadata` is the protobuf `message MetaData`
[proto/source_metadata.proto:L367], a `oneof` over source types.

### Observed finding (the planted GitHub token in `sub/.env`)

Command (stdout only):

```
/tmp/trufflehog filesystem /tmp/thog_fixture --json --log-level=2
```

Complete finding as printed, exactly as emitted (unedited):

```
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/thog_fixture/sub/.env","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":8,"DetectorName":"Github","DetectorDescription":"GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"ghp_C5kCdDZpSBtPxRi9pd2NephKWEHNagqr2hGm","RawV2":"","Redacted":"","ExtraData":{"rotation_guide":"https://howtorotate.com/docs/tutorials/github/","version":"2"},"StructuredData":null}
```

### Cause → effect and the source‑dependent location shape

- **Verification status** is visible directly: `"Verified":false` and
  `"VerificationFromCache":false`. `"VerificationError"` is **absent** from this finding —
  precisely because it is tagged `json:",omitempty"` [pkg/output/json.go:L45] and no
  verification error occurred. This finding is therefore a clean demonstration of that
  field's conditional behavior.
- **No confidence field appears** — consistent with the struct having none.
- **Location metadata** is the `SourceMetadata` object. For the **filesystem** source it is
  `message Filesystem` [proto/source_metadata.proto:L87], observed here as
  `{"file":"/tmp/thog_fixture/sub/.env","line":1}`. For the **git** source it is
  `message Git` [proto/source_metadata.proto:L94], which additionally carries
  `commit`, `email`, `repository`, and `timestamp`. The README documents a git‑source
  example (reading, not observed here). It is quoted **verbatim** below from the project's
  own `README.md` [README.md:L226]; its credential values are the project's *public* test
  keys (committed on purpose to `github.com/trufflesecurity/test_keys`), reproduced unedited:

  ```
  {"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303ffbf8fb1c2c1914e8dda7d0121633aca","file":"keys","email":"counter \u003ccounter@counters-MacBook-Air.local\u003e","repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:17:40 -0700 PDT","line":4}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIAYVP4CIPPERUVIFXG","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","arn":"arn:aws:iam::595918472158:user/canarytokens.com@@mirux23ppyky6hx3l6vclmhnj","user_id":"AIDAYVP4CIPPJ5M54LRCY"},"StructuredData":null}
  ```

  That README example shows a **`"Verified":true`** shape and the richer git metadata
  (`commit`/`email`/`repository`/`timestamp`/`line`), contrasting with the filesystem
  finding observed above (`{file, line}` only). Note the README example predates a few
  current fields (it omits `DetectorDescription`, `VerificationError`,
  `VerificationFromCache`, and `RawV2`); the live 16‑field finding above is authoritative for
  this build.
- `ExtraData` here carries the GitHub detector's `rotation_guide` and `version` keys — the
  same `"rotation_guide": "https://howtorotate.com/docs/tutorials/github/"` that the detector
  sets in code [pkg/detectors/github/v2/github.go:L63].


---

## Q4 — Repository traversal & skip decisions

> *"If I scan a test repo with mixed file types and check verbose logs, what does it reveal about how TruffleHog decides which files to scan versus skip?"*

### Direct answer

TruffleHog decides scan‑vs‑skip by the **detected MIME type**, *not* by the filename. The
gate lives in the default handler:

```
if common.SkipFile(mimeExt) || common.IsBinary(mimeExt) {
    ctx.Logger().V(3).Info("skipping file: extension is ignored", "ext", mimeExt)
```

[pkg/handlers/default.go:L101-L102]. The `mimeExt` it checks is the *canonical extension of
the sniffed MIME type*, set as `mimeExt: r.mime.Extension()`
[pkg/handlers/handlers.go:L76] (and identically in `newMimeTypeReader` at
[pkg/handlers/handlers.go:L100]), where the type is produced by
`mime := mimetype.Detect(buffer)` [pkg/handlers/handlers.go:L98] on the file's leading bytes. `SkipFile()` [pkg/common/vars.go:L122] looks the extension up in
the `ignoredExtensions` map [pkg/common/vars.go:L10] (images/audio/video/documents/fonts —
including `png`, `jpg`, `gif`, `svg`, `mp4`, `pdf`, `ttf`, …), and `IsBinary()`
[pkg/common/vars.go:L129] looks it up in the `binaryExtensions` map
[pkg/common/vars.go:L80] (`class`, `dll`, `exe`, `bin`, `so`, `o`, `a`, `dylib`, `pyc`, …).
Because both helpers compute the extension from their argument and the argument is the
**detected‑MIME** extension, the on‑disk filename is never consulted for this decision.

### Both paths exercised (observation — reported, not "fixed")

- `image.png` → sniffed `image/png` → `mime.Extension()` = `.png` → `png` ∈
  `ignoredExtensions` → **SKIPPED**.
- `blob.bin` → sniffed `application/octet-stream` → `mime.Extension()` = `""` (octet‑stream
  has no canonical extension) → `SkipFile("")` = `false` and `IsBinary("")` = `false` →
  **SCANNED**, even though `"bin"` *is* present in `binaryExtensions`. This is the crux: the
  `.bin` filename is irrelevant; only the detected type's canonical extension matters.
- `creds.txt`, `sub/.env`, `app.py` → sniffed `text/plain; charset=utf-8` → **SCANNED**.
  (Note: TruffleHog's `mimetype` library classifies `app.py` as `text/plain`, unlike the
  shell `file` command which reports `text/x-script.python`; the tool's own detection is
  what governs.)

### Observed per‑file decisions

Command:

```
/tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=5
```

This run exits 0 and prints the one reportable finding to **stdout** while all traversal
decisions go to **stderr**. Both streams are shown complete and unedited (the non‑real
GitHub token is shown in full, exactly as emitted).

Complete stdout (unedited) — the single unverified finding:

```
Found unverified result 🐷🔑❓
Detector Type: Github
Decoder Type: PLAIN
Raw result: ghp_C5kCdDZpSBtPxRi9pd2NephKWEHNagqr2hGm
Rotation_guide: https://howtorotate.com/docs/tutorials/github/
Version: 2
File: /tmp/thog_fixture/sub/.env
Line: 1

```

Complete stderr (unedited) — all 161 lines captured at `--log-level=5` (trace); the 128
`finished scanning chunks` lines are one per scanner worker (= `runtime.NumCPU()` = 128):

```
2026-07-08T05:31:33Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:31:33Z	info-4	trufflehog	default engine options set
2026-07-08T05:31:33Z	info-4	trufflehog	engine initialized
2026-07-08T05:31:33Z	info-4	trufflehog	setting up aho-corasick core
2026-07-08T05:31:33Z	info-4	trufflehog	set up aho-corasick core
2026-07-08T05:31:33Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-08T05:31:33Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-08T05:31:33Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-08T05:31:33Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-08T05:31:33Z	info-0	trufflehog	running source	{"source_manager_worker_id": "pLp82", "with_units": true}
2026-07-08T05:31:33Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "pLp82"}
2026-07-08T05:31:33Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py", "path": "/tmp/thog_fixture/app.py"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py", "path": "/tmp/thog_fixture/app.py", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt"}
2026-07-08T05:31:33Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin"}
2026-07-08T05:31:33Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt", "path": "/tmp/thog_fixture/creds.txt"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin", "path": "/tmp/thog_fixture/blob.bin"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png"}
2026-07-08T05:31:33Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env", "path": "/tmp/thog_fixture/sub/.env"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt", "path": "/tmp/thog_fixture/creds.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin", "path": "/tmp/thog_fixture/blob.bin", "mime": "application/octet-stream", "timeout": 60}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env", "path": "/tmp/thog_fixture/sub/.env", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "05Aoi"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "UfBuS"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5a65V"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EGVz1"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "qi5yz"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tdgOq"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "FNxdL"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pTHcb"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "15Wl2"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "3Ao2k"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xlvpp"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "NF92p"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IobDX"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CM3QH"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "s1oyu"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "U3uVM"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DnRla"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "fqDqV"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QYvJK"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "BpFSw"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QO2l5"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "altO9"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Z51z0"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "jy2Hv"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Dk6Bq"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5z8AE"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IsyIM"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AwyMa"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "z7oQk"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ngcaD"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "SiPpa"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QrdP9"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Qlcqa"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5dmWd"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DV0Nn"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0Jkov"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0bb26"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "EkD6v"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "b7cNR"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "rCAI4"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QJt1d"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "67Amx"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bufZo"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ysUOl"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "oNdne"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "901PC"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OCWM5"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "RB8oA"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "V7Toz"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "acIih"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "yxbKq"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xNp5G"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OWpqk"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "uYisi"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "MHp4Q"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "mruHv"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zkcnf"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "jYA44"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "VAfsj"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dd1B9"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "8LBjK"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ev00B"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "xUpDm"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "lA266"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "viHTO"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "M7sar"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CzxuL"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dz4Ql"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tCdFh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DHJMr"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0WFOZ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "oi7aP"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5zWCk"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "21zKx"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dBhSx"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zzDQo"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vAiV5"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "6WXur"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dMGcG"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "aVvbT"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "k28lF"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "1HqEv"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AoN3h"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5BAcj"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tpMzy"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "I5GUJ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vt2yf"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "70nM5"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CZAm0"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "3ueOj"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "aiP9o"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "hKWzn"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DeaoT"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "X1l1x"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Om9Ny"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Cpb1f"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "B561p"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pacoh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "T1MEd"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "djWEQ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "3uBUT"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bbm6K"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZZWqH"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "4XBRm"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "O176z"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "dWTeh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "TAtlh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XZzh2"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "VZB9Q"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tHMEj"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "WOBXZ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XRsNM"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "YLzTy"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bCNGh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "10W8j"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "z9N9T"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "m72LD"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0XmCQ"}
2026-07-08T05:31:33Z	info-3	trufflehog.aws	Failed to decode account number	{"detector_worker_id": "EWS9T", "detector": {"type":"AWS"}, "timeout": 10, "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "deeoJ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "opgDL"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "6KOxh"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ARzhJ"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "BfH1t"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DF23E"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tw7ah"}
2026-07-08T05:31:33Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "EWS9T", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "UyybM"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "8Ksvj"}
2026-07-08T05:31:33Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CwTNT"}
2026-07-08T05:31:33Z	info-4	trufflehog	link is empty, skipping update	{"detector_worker_id": "EoUHr", "detector": {"type":"Github","version":2}, "timeout": 10}
2026-07-08T05:31:33Z	info-0	trufflehog	finished scanning	{"chunks": 4, "bytes": 9095, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "7.967848ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Highlighted subset — the decisive per‑file scan/skip lines extracted from the complete
stderr above (`grep -E "scanning file|skipping file: extension is ignored|dataErrChan closed, all chunks processed"`):

```
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py", "path": "/tmp/thog_fixture/app.py"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py", "path": "/tmp/thog_fixture/app.py", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt", "path": "/tmp/thog_fixture/creds.txt"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin", "path": "/tmp/thog_fixture/blob.bin"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png"}
2026-07-08T05:31:33Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env", "path": "/tmp/thog_fixture/sub/.env"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt", "path": "/tmp/thog_fixture/creds.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin", "path": "/tmp/thog_fixture/blob.bin", "mime": "application/octet-stream", "timeout": 60}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env", "path": "/tmp/thog_fixture/sub/.env", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-08T05:31:33Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
2026-07-08T05:31:33Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "pLp82", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60}
```

The `mime` field on the `info-5` lines is the ground truth for what was detected: `app.py`,
`creds.txt`, `sub/.env` → `text/plain; charset=utf-8`; `blob.bin` →
`application/octet-stream`; `image.png` → `image/png`. Only `image.png` produced a
`skipping file: extension is ignored` line (with `"mime": "image/png"`, `"ext": ".png"`);
`blob.bin` did not, so it was scanned.

### Verbosity threshold (proven)

The skip message is emitted at **`V(3)`** [pkg/handlers/default.go:L102], so it only appears
at `--log-level=3` or higher. Running the same scan at each level and counting the skip lines with `grep -c` proves the
threshold. Exact commands and their complete output:

`--log-level=2` (verification off), then count the skip lines in its stderr:

```
$ /tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=2 2>/tmp/l2.stderr
$ grep -c "skipping file: extension is ignored" /tmp/l2.stderr
0
```

The complete `--log-level=2` stderr (10 lines) contains no per‑file skip line at all:

```
2026-07-08T05:32:17Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:32:17Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-08T05:32:17Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-08T05:32:17Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-08T05:32:17Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-08T05:32:17Z	info-0	trufflehog	running source	{"source_manager_worker_id": "bsLyq", "with_units": true}
2026-07-08T05:32:17Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "bsLyq"}
2026-07-08T05:32:17Z	info-0	trufflehog	finished scanning	{"chunks": 4, "bytes": 9095, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "7.754884ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

`--log-level=3`, then the same count:

```
$ /tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=3 2>/tmp/l3.stderr
$ grep -c "skipping file: extension is ignored" /tmp/l3.stderr
1
```

The complete `--log-level=3` stderr (22 lines); the single skip line for `image.png` now
appears (a plain `grep` for it at `--log-level=2` returns nothing and exits 1):

```
2026-07-08T05:32:19Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T05:32:19Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-08T05:32:19Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-08T05:32:19Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-08T05:32:19Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-08T05:32:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "KnBxs", "with_units": true}
2026-07-08T05:32:19Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "KnBxs"}
2026-07-08T05:32:19Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py"}
2026-07-08T05:32:19Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/app.py", "path": "/tmp/thog_fixture/app.py"}
2026-07-08T05:32:19Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin"}
2026-07-08T05:32:19Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/blob.bin", "path": "/tmp/thog_fixture/blob.bin"}
2026-07-08T05:32:19Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png"}
2026-07-08T05:32:19Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env"}
2026-07-08T05:32:19Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt"}
2026-07-08T05:32:19Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png"}
2026-07-08T05:32:19Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/sub/.env", "path": "/tmp/thog_fixture/sub/.env"}
2026-07-08T05:32:19Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/creds.txt", "path": "/tmp/thog_fixture/creds.txt"}
2026-07-08T05:32:19Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
2026-07-08T05:32:19Z	info-3	trufflehog.aws	Failed to decode account number	{"detector_worker_id": "rlvmc", "detector": {"type":"AWS"}, "timeout": 10, "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"}
2026-07-08T05:32:19Z	info-0	trufflehog	finished scanning	{"chunks": 4, "bytes": 9095, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "8.612309ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

So the skip‑line count is **0 at `--log-level=2`** and **1 at `--log-level=3`** — the
`image.png` skip line:

```
2026-07-08T05:32:19Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "KnBxs", "unit_kind": "unit", "unit": "/tmp/thog_fixture/image.png", "path": "/tmp/thog_fixture/image.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
```

### Other graded skip logs (enumerated)

Different skip reasons are logged at different verbosities across the codebase:

- Archive handling: size‑exceeds‑max at **V(2)** [pkg/handlers/archive.go:L199];
  extension‑ignored at **V(3)** [pkg/handlers/archive.go:L205]; directory/symlink at **V(4)**
  [pkg/handlers/archive.go:L188].
- Filesystem source: a non‑regular file is logged with
  `logger.Info("skipping, not a regular file", "path", cleanPath)` at **Info/V(0)**
  [pkg/sources/filesystem/filesystem.go:L101] — so that particular skip is visible even at
  default verbosity.
- Git source: when a binary file is skipped it logs at **V(5)** the message
  `skipping binary file` with structured fields `commit` and `path`
  [pkg/sources/git/git.go:L648-L650] (a second such call is at [pkg/sources/git/git.go:L877];
  the related `handling binary file` message is at [pkg/sources/git/git.go:L1242]).


---

## Q5 — Detector architecture (plugins vs. modules) & help output

> *"When I compile the project, are the detectors separate plugins or embedded modules? If I run the binary with a help flag, what information does it show about available detection capabilities?"*

### Direct answer

Detectors are **statically compiled‑in Go modules, not dynamically loaded plugins.** There
is no Go `plugin` machinery anywhere in the tree, and the single `.so` string that exists is
a test fixture name, not a loaded library.

### Evidence (observed via grep)

```
grep -rn "plugin.Open\|plugin.Lookup" --include=*.go .
```

returns **nothing** (exit code 1 — no matches). A search for the standard‑library
`"plugin"` import likewise returns nothing. The only `.so` reference in the repository is a
test fixture filename:

```
grep -rn "\.so" pkg/handlers/handlers_test.go
504:			fileName:       "unsupported.so",
```

i.e. `fileName: "unsupported.so"` [pkg/handlers/handlers_test.go:L504] — used to assert that
an unsupported archive type is handled gracefully, *not* to load a plugin. Instead, every
detector package is imported directly and instantiated in the compiled‑in list
`buildDetectorList()` / `DefaultDetectors()` [pkg/engine/defaults/defaults.go:L839,L1704],
spanning the **845** detector subdirectories under `pkg/detectors/`. (Inferred from reading:
new detectors are added as modules implementing a common detector interface — see
`hack/docs/Adding_Detectors_external.md` — rather than shipped as external plugins.)

### `--version`

```
/tmp/trufflehog --version
```
```
trufflehog dev
```

(Canonical for a from‑source build — see Q1.)

### `--help` — what it reveals about detection capabilities

```
/tmp/trufflehog --help
```

Complete flag list (unedited):

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

### Detection‑relevant items in the help output (enumerated)

- **Output/format:** `-j/--json`, `--json-legacy`, `--github-actions`, `--no-color`.
- **Verification control:** `--no-verification` (turn verification off), `--verifier` (custom
  verification endpoints), `--custom-verifiers-only`, `--no-verification-cache`,
  `--allow-verification-overlap`.
- **Result selection/filtering:** `--results` (accepts `verified`, `unknown`, `unverified`,
  `filtered_unverified`; default `verified,unverified,unknown`), `--filter-unverified`,
  `--filter-entropy` (Shannon entropy; "Start with 3.0"), `--fail` (exit code 183 if results
  found).
- **Detector selection:** `--include-detectors="all"` and `--exclude-detectors` — both take a
  comma‑separated list of detector types by **protobuf name or ID, including ranges**; IDs in
  the exclude list take precedence. `--config` [main.go:L70] adds *custom* detectors from a
  file on top of the compiled‑in set: the file is parsed by `config.Read`
  [pkg/config/config.go:L18], each YAML entry becomes a detector via `NewWebhookCustomRegex`
  [pkg/config/config.go:L36], and the engine appends them to the built‑ins with
  `append(defaults.DefaultDetectors(), conf.Detectors...)` [main.go:L519] (the config file is
  read at [main.go:L461-L463]).
- **Concurrency/limits:** `--concurrency=128` (the host default, = `runtime.NumCPU()`),
  `--detector-timeout`, `--archive-max-size`, `--archive-max-depth`, `--archive-timeout`,
  `--force-skip-binaries`, `--force-skip-archives`, `--skip-additional-refs`.
- **Misc:** `--log-level`, `--profile`, `--print-avg-detector-time`, `--no-update`,
  `--user-agent-suffix`, `--version`.
- **Commands shown** (17 total, including the built‑in `help`): the **16** scan/analyze
  commands `git`, `github`, `github-experimental`, `gitlab`, `filesystem`, `s3`, `gcs`,
  `syslog`, `circleci`, `docker`, `travisci`, `postman`, `elasticsearch`, `jenkins`,
  `huggingface`, `analyze`; plus the `help` command (which prints this help output, not a
  scan source).

### What `--help` does NOT show (plain negatives)

- It does **not** enumerate the 845 individual detectors by name. There is no "list
  detectors" output; you select detectors indirectly via `--include-detectors` /
  `--exclude-detectors` by protobuf name/ID/range.
- It does **not** list every flag: `--only-verified` is declared `.Hidden().Bool()`
  [main.go:L60] (and consumed at [main.go:L502]), so it is intentionally omitted from
  `--help`. (`--help-long`/`--help-man` expose per‑command flags but still do not enumerate
  detectors.)

---

## Methodology

### Exact commands used

- **Toolchain check:** `go version` → `go version go1.24.2 linux/amd64` (pinned
  `toolchain go1.24.2` [go.mod:L5]).
- **Build (canonical):** `CGO_ENABLED=0 go build -o /tmp/trufflehog .` → 194309218‑byte
  binary; the source tree is untouched because the output goes to `/tmp`.
- **Host CPU probe:** a 3‑line Go program (`runtime.NumCPU()`) compiled with the same
  toolchain printed `runtime.NumCPU() = 128`. This is the value that drives concurrency
  (`--concurrency` default = `runtime.NumCPU()` [main.go:L58]); it is confirmed by
  `--help` showing `--concurrency=128`. (The shell's `nproc` reported `4` under this
  container's cgroup/affinity view, but the Go runtime — and therefore the tool — uses 128;
  the worker counts confirm 128 is authoritative.)
- **Q1/Q2/Q3:** `/tmp/trufflehog filesystem /tmp/thog_fixture --json --log-level=2`
  (verification ON).
- **Q4:** `/tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=5`,
  plus the same scan at `--log-level=2` and `--log-level=3` for the verbosity proof.
- **Q1/Q5:** `/tmp/trufflehog --version` and `/tmp/trufflehog --help`.
- **Q5 architecture:** `grep -rn "plugin.Open\|plugin.Lookup" --include=*.go .` (no matches),
  `grep -rn "\.so" pkg/handlers/handlers_test.go` (only `unsupported.so`), and
  `find pkg/detectors -mindepth 1 -maxdepth 1 -type d | wc -l` → `845`.

### Two‑run stability confirmation (worker counts)

The `--json --log-level=2` scan was run twice with identical input. The `starting … workers`
lines were structurally identical across both runs (host `runtime.NumCPU()` = 128):

Run 1:

```
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:09Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

Run 2:

```
{"level":"info-2","ts":"2026-07-08T05:31:11Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:11Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-08T05:31:11Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-08T05:31:11Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

Counts: scanner `128`, detector `1024` (= 128 × 8), verificationOverlap `128`, notifier
`128` — identical both times. (Only the timestamps and `scan_duration` differ; the magnitudes
are stable.)

### Known‑false‑positive filter (why a finding may not appear)

At `--log-level=5` the AWS documentation example key planted in `creds.txt` was detected and
then dropped as a false positive:

```
2026-07-08T05:31:33Z	info-4	trufflehog	Skipping result: false positive	{"detector_worker_id": "EWS9T", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

This is `detectors.FilterKnownFalsePositives` [pkg/engine/engine.go:L1142] at work: low‑entropy
/ well‑known example secrets (e.g. `AKIAIOSFODNN7EXAMPLE`, or all‑zero tokens) are filtered,
which is why the fixture's *reportable* finding is the high‑entropy, non‑real GitHub token in
`sub/.env` rather than the AWS example key. This matters for reproducing a finding.

### Documentation vs. code discrepancy (reported, not changed)

`CONTRIBUTING.md` (§"Choose an appropriate verbosity level" [CONTRIBUTING.md:L29]) gives the
example `Logger().V(2).Info("skipping file: extension is ignored", "ext", mimeExt)`
[CONTRIBUTING.md:L38] — i.e. it cites **V(2)**. The actual code emits that message at
**V(3)** [pkg/handlers/default.go:L102]. The verbosity proof above (0 skip lines at
`--log-level=2`, 1 at `--log-level=3`) confirms the code's V(3) behavior is authoritative.
Per the read‑only scope, this is documented as an observation; neither file was modified.

### Read‑only verification & cleanup

All build artifacts (`/tmp/trufflehog`), the CPU probe (`/tmp/numcpu`), the fixture
(`/tmp/thog_fixture`), and all captured‑output scratch files live **outside** the repository
under `/tmp` and were removed after use. The only change to the repository is the addition of
this document under the new `blitzy/` tree. This is confirmed directly by capturing the
read‑only verification commands and their real output.

`git status --porcelain` prints **nothing** — the working tree is clean, with no uncommitted
changes and no leftover temporary artifacts inside the repository:

```
$ git status --porcelain
$
```

The only file that differs from the pre‑task baseline (`e42153d4`, the HEAD before this task)
is this document — `git diff --name-status e42153d4..HEAD`:

```
$ git diff --name-status e42153d4..HEAD
A	blitzy/documentation/trufflehog_e42153d44a5e.md
```

Excluding the new `blitzy/` tree, the diff against the baseline is **empty** — i.e. no
TruffleHog source, reference, dependency, or build file was modified:

```
$ git diff --name-only e42153d4..HEAD -- . ':(exclude)blitzy/**'
$
```

The repository is therefore left byte‑for‑byte unchanged apart from this document.

### External corroboration (code + observed behavior remain authoritative)

The official "Introducing TruffleHog v3" write‑up (trufflesecurity.com) and the community
engine wiki describe the same model observed here — an engine coordinating worker pools,
detectors preflighted by a fast keyword prefilter (`github.com/BobuSumisu/aho-corasick v1.0.3`
[go.mod:L17]) before regex, and verification via live provider API calls — but the code
references and captured output in this document are the source of truth.

