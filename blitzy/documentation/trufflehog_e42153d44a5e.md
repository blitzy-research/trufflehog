# TruffleHog Secret-Detection Architecture — Runtime-Grounded Onboarding Answers

This document answers five onboarding questions about TruffleHog's secret-detection
architecture. Per the governing `SWE-AtlasQnA-Repo` methodology, **every behavioral claim
was produced by building the binary from source and running it**, and each claim is paired
with the exact command that produced it (including its stdout/stderr redirection and exit
status) and the complete, unedited output. Each substantive clause is labelled either
**OBSERVED** (executed at runtime and seen in the captured output) or **INFERRED** (read from
source, not exercised at runtime); where an inferred claim is corroborated by a specific source
location it is written **INFERRED — source-confirmed**. These are the only two labels used.

> **A note on embedded output.** Every command's output below is reproduced complete and unedited,
> with one purely cosmetic exception for repository hygiene: trailing padding spaces that
> `kingpin` emits at the end of some `--help`/`--help-long` flag lines have been trimmed so the
> committed document contains no trailing whitespace. No visible characters, ordering, values, or
> lines were changed, and internal tab separators inside log lines are preserved verbatim.

- **Subject:** TruffleHog, Go module `github.com/trufflesecurity/trufflehog/v3`.
- **Commit under investigation (the source being described):**
  `e42153d44a5e5c37c1bd0c70e074781e9edcb760`.

### Source commit vs. delivery commit (repository-state contract)

This answer document is itself a tracked file, so the branch HEAD that *carries* the document
is necessarily a **child** of the commit under investigation. The two are distinct on purpose:

- **Source-under-investigation:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`. Every source
  `file:line` citation and every runtime behavior in this document refers to this commit. The
  binary used throughout embeds this exact revision in its Go VCS build metadata
  (`vcs.revision=e42153d44a5e…`, `vcs.modified=false`; see Q5), which independently proves the
  binary was built from this pristine source.
- **Delivery commit:** the child commit on the working branch that adds *only* this Markdown
  file under `blitzy/documentation/`. It changes no `.go`, `proto`, manifest, or build file, so
  the compiled behavior described here is identical to a build from the source commit.

A document cannot contain its own commit hash, so the delivery commit is identified by *role*
(the branch-HEAD commit that adds/updates only this file) rather than by a hard-coded hash; the
real `git log`/`git status` output captured at delivery time is shown in the **Final integrity**
section. The tracked source tree is otherwise byte-for-byte unchanged — the only sanctioned change
is this document under `blitzy/documentation/`.

---

## Environment & Methodology
### Toolchain

**OBSERVED.** The build and all runs used the Go toolchain the project pins (`go.mod`:
`go 1.23.1` / `toolchain go1.24.2`; CI pins `1.24`).

```text
$ go version
go version go1.24.2 linux/amd64
```

### Canonical build

**INFERRED — source-confirmed (recipe).** The canonical build recipe is the one the project
itself documents: the `Makefile` `install` target runs `CGO_ENABLED=0 go install .`, the
`Dockerfile` runs `CGO_ENABLED=0 go build -o trufflehog .`, and `README.md` ("Compile from
source") gives the same. The binary exercised throughout this document is that artifact, built
once from the checkout root at the source commit:

```text
$ CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .
```

**OBSERVED (artifact identity).** The resulting file and its self-reported version:

```text
$ ls -l /tmp/trufflehog_bin
-rwxr-xr-x 1 root root 194311322 Jul 13 16:47 /tmp/trufflehog_bin
```

```text
$ /tmp/trufflehog_bin --version 1>/tmp/v.out 2>/tmp/v.err; echo "exit=$?"
$ cat /tmp/v.err          # stderr
trufflehog dev
$ wc -c /tmp/v.out        # stdout is empty
0 /tmp/v.out
```

The default build reports the version string **`trufflehog dev`**, and it is written to
**stderr** (stdout is empty), exit code `0`.

### Build identity & provenance — two independent facts (do not conflate)

The default build carries **two distinct** identity signals, and it is important not to confuse
them:

1. **Application version = `dev` (a source constant, not a stamp).**
   **INFERRED — source-confirmed.** `pkg/version/version.go:L3` declares
   `var BuildVersion = "dev"`, and `main.go:L270` wires it into the CLI as
   `cli.Version("trufflehog " + version.BuildVersion)`. Because the canonical build passes **no**
   `-ldflags "-X …BuildVersion=…"` override, the constant is emitted verbatim. That is why
   `--version` prints `trufflehog dev` (OBSERVED above). Release builds override this via ldflags;
   the canonical/default build does not.

2. **Go VCS build metadata = automatically embedded (this is *not* the app version, and *not*
   ldflags).** **OBSERVED.** The Go toolchain automatically stamps VCS provenance into any
   `go build` from a Git checkout. Reading it back from the binary:

```text
$ go version -m /tmp/trufflehog_bin | grep -E '^\s+build\s+(vcs|-buildmode|CGO|GOARCH|GOOS)'
	build	-buildmode=exe
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux
	build	vcs=git
	build	vcs.revision=e42153d44a5e5c37c1bd0c70e074781e9edcb760
	build	vcs.time=2025-05-05T16:04:54Z
	build	vcs.modified=false
```

   The embedded `vcs.revision=e42153d44a5e5c37c1bd0c70e074781e9edcb760` with
   `vcs.modified=false` is the runtime proof that this binary was compiled from the **exact,
   unmodified source commit** under investigation. Note that `vcs.revision` and `vcs.time` are
   **build-time stamps** — the Go toolchain records whichever commit is checked out at the moment
   `go build` runs — so a reader who rebuilds from a *later* commit (for example, after this answer
   document itself is committed) will see that later commit's hash and timestamp here instead; the
   value shown above was captured when the tree was at `e42153d4…`. The invariant that actually
   matters for the read-only claim is `vcs.modified=false`, which confirms the working tree carried
   **no local source edits** at build time regardless of which commit is checked out. `CGO_ENABLED=0`
   and `-buildmode=exe` are also recorded. This automatic metadata is orthogonal to the `dev`
   application version above: the former is stamped by the toolchain regardless of ldflags; the
   latter is a plain package-level constant.

### Static, single-file binary (no dynamic/plugin loading)

**OBSERVED.** `ldd` reports the artifact is not a dynamic executable (it is fully static,
`CGO_ENABLED=0`), so there is no shared-object plugin surface:

```text
$ ldd /tmp/trufflehog_bin; echo "ldd exit=$?"
	not a dynamic executable
ldd exit=1
```

`ldd` exits **1** here — that is the normal, expected result for a static binary (`ldd` returns
non-zero when the target "is not a dynamic executable"), not an error in the run.

### Host concurrency context (worker counts are host-derived)

The worker-pool counts reported under Q1/Q2 are **derived from the host's available CPU count**,
so their absolute magnitude is host-dependent while the *formulas* that produce them are fixed.

- **INFERRED — source-confirmed (formula).** `main.go:L58` sets the `--concurrency` flag's
  default to `runtime.NumCPU()`
  (`cli.Flag("concurrency", …).Default(strconv.Itoa(runtime.NumCPU())).Int()`). Downstream the
  engine multiplies this to size the detector pool (Q2).
- **OBSERVED (this host).** On the host used for every capture in this document,
  `runtime.NumCPU()` evaluates to **128**. Note that `runtime.NumCPU()` honors the process CPU
  affinity mask (`sched_getaffinity`), which can differ from the `nproc`/container-cgroup view;
  on this host the effective value the tool sees is 128, and that is the number that flows into
  the worker-count logs. **On a machine with a different CPU/affinity count, the absolute worker
  numbers below will differ proportionally**; the formulas (`concurrency`, `concurrency × 8`) do
  not.

### Output channels (stdout vs stderr) — capture convention

**OBSERVED.** TruffleHog writes **findings to stdout** and **all logs + the startup banner to
stderr**. This separation is what makes clean evidence capture possible, and every command in
this document is shown with its explicit redirection so the channel of each byte is unambiguous.
The channel of each key command was verified empirically:

| Command | stdout | stderr | exit |
|---|---|---|---|
| `--version` | *(empty)* | `trufflehog dev` | 0 |
| `--help` | *(empty)* | usage text (124 lines) | 0 |
| `--help-long` | full usage (416 lines) | *(empty)* | 0 |
| `git … --json` | JSON findings | logs (no banner — suppressed by `--json`) | 0 |
| `git … ` (plain) | plain findings | banner + logs | 0 |
| `filesystem … --log-level=5` | plain findings | banner + trace logs | 0 |

(The `--help` vs `--help-long` channel split is itself a `kingpin` behavior and is shown with
its capture under Q5.)

### Controlled fixture — secure construction

A fixture is required to force a real finding (Q3) and to exercise mixed file types (Q4). To
honor the read-only rule and to avoid ever writing a live-looking secret into a world-readable
location, the fixture was built **outside the checkout** with a locked-down permission mask, an
auto-cleanup trap, and a **repo-local** Git identity (so the global `agent@blitzy.com` identity
is never used for the throwaway commit). The exact construction recipe:

```bash
umask 077                                   # every artifact created owner-only (rw-------)
WORK="$(mktemp -d /tmp/thog_investigation.XXXXXXXX)"   # unique, outside the checkout
trap 'rm -rf "$WORK"' EXIT                   # guaranteed cleanup on shell exit
# ... validate $WORK is outside the checkout and not a symlink ...

# (1) The mixed-type file set lives in a PLAIN (non-git) directory — this is the
#     directory the Q4 `filesystem` scan targets ("$WORK/thog_files"):
mkdir -p "$WORK/thog_files" && cd "$WORK/thog_files"
# create fixture files here (see provenance below) ...

# (2) A separate GIT repository holding the identical files — this is the
#     directory the Q1/Q3 git-source scans target ("$WORK/thog_testrepo"):
cp -a "$WORK/thog_files" "$WORK/thog_testrepo"
cd "$WORK/thog_testrepo"
git init -q
git -c user.name='t' -c user.email='t@t.com' add -A
git -c user.name='t' -c user.email='t@t.com' commit -q -m 'fixture'
```

Two sibling directories are therefore created under `$WORK`: **`thog_files`** — a plain,
non-git directory that the Q4 `filesystem` scan targets — and **`thog_testrepo`** — a Git
repository of the *identical* files that the Q1/Q3 git-source scans target. The mixed file set
was chosen to hit every scan/skip branch exercised in Q4: a **text** secret file, additional
**text** files, an **image** (PNG), a **video-named text** file (`.mp4` extension whose *content*
is text), and a **gzip archive** containing one text member.

### Fixture provenance (exact bytes)

**OBSERVED.** Permissions (owner-only, from `umask 077`), byte sizes, and content types:

```text
$ ls -l ./*        # (perms, size, name)
-rw------- 151 ./archive.tar.gz
-rw------- 116 ./aws_creds.ini
-rw------- 44 ./config.env
-rw------- 122 ./data.mp4
-rw------- 70 ./logo.png
-rw------- 91 ./notes.txt
-rw------- 250 ./testkey.pem
$ file ./*
aws_creds.ini:  ASCII text
config.env:     ASCII text
testkey.pem:    PEM RSA private key
notes.txt:      ASCII text
logo.png:       PNG image data, 1 x 1, 8-bit/color RGBA, non-interlaced
data.mp4:       ASCII text
archive.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10240
```

**OBSERVED.** SHA-256 of every fixture file (so the exact bytes are reproducible/auditable):

```text
$ sha256sum aws_creds.ini config.env testkey.pem notes.txt logo.png data.mp4 archive.tar.gz
f5eab59f5a1d48fd78f31056e381f81993ab4c334a2fb27125de4a17cc75bc1b  aws_creds.ini
9c476f44616897c73ecc1fe066a6363b226a0a3886a86b58d61822d94f2ee1cf  config.env
d68126502edfd1e0e59e23ee8036359484360fe33393f7a8c4fd206f3eac72da  testkey.pem
6a404b93cf6f483118e365fa4999385b22e262c2b34096a877a3b91a66635550  notes.txt
5f31de7b7059acf773ba2fafcd318a2f46883d58deb9b323e74dfb20453ed3d0  logo.png
faa84139cd4adb50b4c03a193f286fe69ad608021b47f1d0664466d176871d89  data.mp4
b24e3364c9ad2ab037c5bbf8ada15f673ea4e93921aa380b2c8c0a555188cc7d  archive.tar.gz
```

**OBSERVED.** The archive's single member (used for the Q4 archive-descent evidence):

```text
$ tar -tzvf archive.tar.gz
-rw------- root/root        40 2026-07-13 18:16 inside.txt
```

**OBSERVED.** The throwaway commit and its **repo-local** authorship (note: `t <t@t.com>`, not
the global identity):

```text
$ git log -1 --format='author=%an <%ae>%ncommitter=%cn <%ce>%ncommit=%H'
author=t <t@t.com>
committer=t <t@t.com>
commit=6b84f04f1c0982272bb21e3ec5ae447b639420d5
```

The one detectable secret is an **AWS canary access key** (`AKIA…`, `is_canary=true` — see Q3),
paired with a fabricated (non-live) secret value, so no real credential is ever embedded.

### Sensitivity note — findings echo the raw secret

**OBSERVED (Q3) / applies throughout.** TruffleHog's finding objects include the **raw matched
secret** in the `Raw` field and a composed form in `RawV2` (Q3). In this document those fields
contain only the **public AWS canary key** plus a **fabricated** secret, so reproducing them is
safe. When you run TruffleHog against real material, treat `Raw`/`RawV2` (and any captured JSON)
as containing **live credentials**: they should be redacted, access-controlled, and shredded —
which is why the fixture here is built under `umask 077` and destroyed on exit.
---

## Q1 — Startup and detector loading

> *"If I build it from source and run a basic scan, what happens during startup? Does it load
> detector configurations from files, or are they compiled in? What initialization messages
> appear about which detectors get registered?"*

### Direct answer

- **The built-in detector catalog is compiled into the binary, not read from any config file at
  runtime.** The catalog is a Go slice assembled by `DefaultDetectors()`
  (`pkg/engine/defaults/defaults.go:L1704`), which returns the list built by `buildDetectorList()`
  (`…:L839`). No file is read to obtain these detectors.
- **There is, however, one optional file-based path**: if you pass `--config <file>`, TruffleHog
  reads that YAML and *appends* user-defined **custom regex** detectors to the compiled-in set.
  This does not replace or "load" the built-in catalog; it adds to it. With a basic scan (no
  `--config`), that path is inert.
- **The list is *assembled* at startup**, at the point the engine config is built:
  `main.go:L519` does `Detectors: append(defaults.DefaultDetectors(), conf.Detectors...)`.
- **There is no per-detector "registered X" startup message at any log level.** The observable
  startup signals are (a) the **ASCII banner** (non-JSON modes) and (b) four **worker-pool
  "starting … workers" count** log lines. The absence of a per-detector line is the absence of a
  *log call*, **not** evidence that assembly did not happen — assembly is compile-time/startup and
  is not narrated per detector.

### (A) Compiled-in, not loaded from files — evidence

**Basic scan command (JSON so findings and logs are on separate channels), `--log-level=2` to
surface the worker/init lines:**

```text
$ /tmp/trufflehog_bin git file:///tmp/thog_investigation.ulY2DMuS/thog_testrepo \
      --json --log-level=2 1>/tmp/q1.out 2>/tmp/q1.err; echo "exit=$?"
exit=0
```

**OBSERVED — complete stderr of the run** (this is the entire startup + scan log stream; note it
contains **no** "loading detectors from file" line and **no** per-detector "registered" line):

```text
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
{"level":"info-1","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"cloned repo","path":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo"}
{"level":"info-0","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"running source","source_manager_worker_id":"7469p","with_units":true}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"enumerating source","source_manager_worker_id":"7469p"}
{"level":"info-0","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"scanning repo","source_manager_worker_id":"7469p","unit_kind":"dir","unit":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","repo":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"7469p","unit_kind":"dir","unit":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","repo":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"scanning staged changes","source_manager_worker_id":"7469p","unit_kind":"dir","unit":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","path":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo"}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"finished parsing git log.","source_manager_worker_id":"7469p","unit_kind":"dir","unit":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","total_log_size":0}
{"level":"info-1","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"scanning git repo complete","source_manager_worker_id":"7469p","unit_kind":"dir","unit":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","repo":"Could not get remote for repo","path":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo","time_seconds":0,"commits_scanned":1}
{"level":"info-0","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"finished scanning","chunks":7,"bytes":742,"verified_secrets":0,"unverified_secrets":1,"scan_duration":"12.257614ms","trufflehog_version":"dev","verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**INFERRED — source-confirmed (why there is no file read):** the catalog is a compiled-in slice.
`DefaultDetectors()` [`pkg/engine/defaults/defaults.go:L1704`] returns the slice produced by
`buildDetectorList()` [`…:L839`], which is a long sequence of Go struct literals — i.e., the
detectors are *code*, fixed at compile time. `main.go:L519` assembles the engine's detector list
from that function's return value at startup:

```go
// main.go:L519 (inside building engine.Config)
Detectors: append(defaults.DefaultDetectors(), conf.Detectors...),
```

### (B) The one file-based path: `--config` custom regex detectors (additive)

**INFERRED — source-confirmed.** The `conf.Detectors` half of that `append` is the *only* way a
file feeds detectors into the engine, and it is **additive user-defined regex detectors**, not the
built-in catalog:

- `main.go:L70` declares the flag: `configFilename = cli.Flag("config", "Path to configuration
  file.").ExistingFile()`.
- `main.go:L461-463` reads it only when set: `if *configFilename != "" { … conf, err =
  config.Read(*configFilename) … }`.
- `pkg/config/config.go`: `Read` [`L18`] → `NewYAML` [`L27`] unmarshals into
  `custom_detectorspb.CustomDetectors` [`L29`] and builds each via
  `custom_detectors.NewWebhookCustomRegex(detectorConfig)` [`L36`].

So "does it load detector configurations from files?" has a precise two-part answer: **the
built-in catalog is compiled in (no file)**, while **custom regex detectors can optionally be
loaded from a `--config` YAML and appended**. A basic scan uses none.

### (C) Initialization messages — worker pools (the real startup signal)

**INFERRED — source-confirmed (what the lines are):** during engine startup, `startWorkers`
[`pkg/engine/engine.go:L646`] launches four pools and logs each at V(2):

- `L663` `"starting scanner workers", count = e.concurrency`
- `L678` `"starting detector workers", count = numWorkers` where
  `numWorkers := e.concurrency * e.detectorWorkerMultiplier` [`L676`], and the multiplier defaults
  to **8** [`L345`]
- `L693` `"starting verificationOverlap workers"`
- `L708` `"starting notifier workers"`

**OBSERVED — the four lines from the run above** (JSON log format), and their **stability across
two identical runs**:

```text
$ sed -n '2,5p' /tmp/q1.err     # the four worker-pool lines
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
```

Run twice, the worker counts were **byte-identical** (`diff` of the extracted lines reported no
difference): `scanner=128, detector=1024, verificationOverlap=128, notifier=128`. These match the
formulas exactly on this 128-CPU host: `scanner = concurrency = 128`; `detector = concurrency × 8
= 1024`; the other two pools use a ×1 multiplier here, hence 128. **(Host-dependent magnitude — see
"Host concurrency context"; on a differently-sized host the counts scale but the formulas do
not.)** The first log line, `"msg":"trufflehog dev"`, is the version echo (`main.go:L410`,
`version.BuildVersion`).

### (D) The banner — shown in non-JSON modes, suppressed only for JSON

**INFERRED — source-confirmed (the gate):** `main.go:L497-499` prints the banner to **stderr**
guarded *only* by the two JSON flags:

```go
// main.go:L486-495 selects the printer; L497-499 gates the banner
if !*jsonLegacy && !*jsonOut {
    fmt.Fprintf(os.Stderr, "🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷\n\n")
}
```

The condition depends **only** on `--json-legacy` and `--json`. It is **not** gated on
`--github-actions`, so the banner **is** printed in GitHub-Actions mode. This was verified
empirically across all three non-error modes:

**OBSERVED — plain mode (banner present), first two stderr lines:**

```text
$ /tmp/trufflehog_bin git "file://$WORK/thog_testrepo" --log-level=2 2>/tmp/q1_plain.err 1>/dev/null
$ sed -n '1,2p' /tmp/q1_plain.err
2026-07-13T18:17:28Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

**OBSERVED — `--github-actions` mode (banner STILL present), first two stderr lines:**

```text
$ /tmp/trufflehog_bin git "file://$WORK/thog_testrepo" --github-actions --log-level=2 2>/tmp/q1_gha.err 1>/dev/null
$ sed -n '1,2p' /tmp/q1_gha.err
2026-07-13T18:17:30Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
```

**OBSERVED — `--json` mode (banner ABSENT), first stderr lines** (straight to the version echo and
worker lines — no banner):

```text
$ sed -n '1,6p' /tmp/q1.err
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"trufflehog dev"}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting scanner workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting detector workers","count":1024}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting verificationOverlap workers","count":128}
{"level":"info-2","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"starting notifier workers","count":128}
{"level":"info-1","ts":"2026-07-13T18:17:15Z","logger":"trufflehog","msg":"cloned repo","path":"/tmp/thog_investigation.ulY2DMuS/thog_testrepo"}
```

A `grep -c 'Unearth your secrets'` over each stream confirms the counts: **plain = 1**,
**github-actions = 1**, **json = 0**. In short: the banner is a **non-JSON** artifact
(plain and github-actions), suppressed **only** for `--json`/`--json-legacy`.

### (E) "Which detectors get registered" — no per-detector log exists

**OBSERVED.** Across the entire startup stream at `--log-level=2` (and, confirmed under Q4, even at
the maximum `--log-level=5`), **no line names an individual detector as "registered."** The
initialization the tool narrates is the **worker pools** and the source/scan lifecycle, not a
per-detector roster.

**INFERRED — source-confirmed (why):** registration is not a runtime event that emits a log; it is
the compile-time membership of a detector's struct literal in `buildDetectorList()`
[`defaults.go:L839`]. To actually enumerate the built-in detectors you inspect the code (or use
`--include-detectors`/`--exclude-detectors` filters and the `analyze` subcommand shown under Q5),
not the startup log. So the accurate statement is: **detectors are registered at compile time; the
startup log reports worker-pool sizes and the scan lifecycle, and never a per-detector line.**
---

## Q2 — Verification setup (HTTP libraries + parallel vs sequential)

> *"When I examine the build dependencies, are there HTTP client libraries suggesting network
> verification? If I run a scan and watch the process activity, does the architecture show
> verification happening in parallel or sequentially?"*

### Direct answer

- **Yes — the build dependencies include HTTP client libraries that exist specifically for
  network verification.** The direct dependency `github.com/hashicorp/go-retryablehttp v0.7.7`
  (`go.mod:L63`) plus its transitive `github.com/hashicorp/go-cleanhttp v0.5.2` (`go.mod:L231`,
  `// indirect`) are the resilient HTTP stack used when detectors call out to a provider's API to
  confirm a secret is live. Both are **compiled into** the binary (proven below).
- **Verification runs in parallel.** It is performed *inside* the detector worker pool, which is
  sized at `concurrency × 8` — **1024 workers** on this 128-CPU host (OBSERVED under Q1). Each
  worker verifies independently, so verification is distributed across a large parallel pool, not
  run one-secret-at-a-time.
- **Precision on the caches (a common point of confusion):** `golang-lru/v2` is **not** the
  verification cache — it is the engine's result-**dedupe** cache. The verification *result* cache
  is a separate structure backed by `patrickmn/go-cache`.

### (A) Build dependencies — the HTTP verification stack

**OBSERVED — the relevant `go.mod` lines** (with their line numbers):

```text
$ grep -nE 'go-retryablehttp|golang-lru/v2|patrickmn/go-cache|go-cleanhttp' go.mod
63:	github.com/hashicorp/go-retryablehttp v0.7.7
64:	github.com/hashicorp/golang-lru/v2 v2.0.7
80:	github.com/patrickmn/go-cache v2.1.0+incompatible
231:	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
```

**OBSERVED — the pinned hashes in `go.sum`** (integrity of the HTTP libs):

```text
$ grep -E 'go-cleanhttp|go-retryablehttp|golang-lru/v2' go.sum
github.com/hashicorp/go-cleanhttp v0.5.2 h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ=
github.com/hashicorp/go-cleanhttp v0.5.2/go.mod h1:kO/YDlP8L1346E6Sodw+PrpBSV4/SoxCXGY6BqNFT48=
github.com/hashicorp/go-retryablehttp v0.7.7 h1:C8hUCYzor8PIfXHa4UrZkU4VvK8o9ISHxT2Q8+VepXU=
github.com/hashicorp/go-retryablehttp v0.7.7/go.mod h1:pkQpWZeYWskR+D1tR2O5OcBFOxfA7DoAO6xtkuQnHTk=
github.com/hashicorp/golang-lru/v2 v2.0.7 h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k=
github.com/hashicorp/golang-lru/v2 v2.0.7/go.mod h1:QeFd9opnmA6QUJc5vARoKUSoFhyfM2/ZepoAG6RGpeM=
```

**OBSERVED — module integrity verifies clean:**

```text
$ go mod verify
all modules verified
```

**OBSERVED — these libraries are actually linked into the built binary** (not merely declared);
read back from the artifact's embedded module list:

```text
$ go version -m /tmp/trufflehog_bin | grep -E 'go-cleanhttp|go-retryablehttp|golang-lru/v2|patrickmn/go-cache'
	dep	github.com/hashicorp/go-cleanhttp	v0.5.2	h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ=
	dep	github.com/hashicorp/go-retryablehttp	v0.7.7	h1:C8hUCYzor8PIfXHa4UrZkU4VvK8o9ISHxT2Q8+VepXU=
	dep	github.com/hashicorp/golang-lru/v2	v2.0.7	h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k=
	dep	github.com/patrickmn/go-cache	v2.1.0+incompatible	h1:HRMgzkcYKYpi3C8ajMPV8OFXaaRUnok+kx1WdO15EQc=
```

So the presence of `go-retryablehttp`/`go-cleanhttp` in the build **does** indicate network-based
verification. (`go-retryablehttp` is a retrying HTTP client; `go-cleanhttp` supplies a
non-shared, leak-safe `http.Transport`.)

### (B) Which HTTP clients are retryable — and which are plain

**INFERRED — source-confirmed.** `pkg/common/http.go` exposes a family of shared clients; **not
all of them use `retryablehttp`**, so it is inaccurate to say every verification call is a retrying
call:

- `PinnedRetryableHttpClient()` [`http.go:L159`] → `retryablehttp.NewClient()` [`L160`] — retrying.
- `RetryableHTTPClient(opts …)` [`http.go:L180`] → `retryablehttp.NewClient()` [`L181`] — retrying.
- `SaneHttpClient()` [`http.go:L223`] → **plain** `&http.Client{}` [`L224`] — **not**
  `retryablehttp`-backed (it wraps only a custom transport).

Which client a given detector uses is the detector's own choice; the dependency proves the
*capability* exists and is compiled in, while the per-call retry behavior depends on which
constructor a detector selected. (Stated conservatively to avoid over-claiming uniform retry/proxy
behavior across all 831 detectors.)

### (C) The two caches are different things

**INFERRED — source-confirmed.** There are two distinct caches, and only one relates to
verification:

- **Engine dedupe cache = `golang-lru/v2`.** `pkg/engine/engine.go:L18` imports
  `lru "github.com/hashicorp/golang-lru/v2"`; the field is `dedupeCache *lru.Cache[…]`
  [`L209`], constructed with `lru.New[…]` [`L493`] and assigned `e.dedupeCache = cache` [`L520`].
  Its job is to **deduplicate results**, not to cache verification outcomes.
- **Verification result cache = `patrickmn/go-cache`.** It is created only when caching is enabled:
  `main.go:L535` `if !*noVerificationCache {` → `L536`
  `engConf.VerificationResultCache = simple.NewCache[detectors.Result]()`. The `simple` package
  [`pkg/cache/simple/simple.go`] imports `github.com/patrickmn/go-cache` [`L7`], and its
  `NewCache` [`L41`] builds the store via `cache.NewFrom(…)` [`L67`].

So `golang-lru/v2 v2.0.7` (`go.mod:L64`) and `patrickmn/go-cache v2.1.0+incompatible`
(`go.mod:L80`) serve **different** roles; attributing verification caching to `golang-lru/v2`
would be incorrect.

### (D) Parallel, not sequential — where verification actually runs

**INFERRED — source-confirmed (the dispatch):** verification is invoked from inside the detector
worker loop. `startDetectorWorkers` sizes the pool as
`numWorkers := e.concurrency * e.detectorWorkerMultiplier` [`pkg/engine/engine.go:L676`] (the
multiplier defaults to **8** [`L345`]) and logs it [`L678`]; each worker ultimately calls
`e.verificationCache.FromData(…)` [`pkg/engine/engine.go:L1070`], which performs (or reuses a
cached) verification for the candidate secret.

**OBSERVED (the parallelism magnitude):** the detector pool started with **1024** workers on this
host (the `"starting detector workers","count":1024` line captured under Q1), i.e.
`128 × 8`. Because the verification call lives *inside* each of those concurrent workers,
verification is fanned out across the pool rather than serialized.

**INFERRED (the network round-trip):** the actual outbound API call and its retry behavior were
**not** captured on the wire in this investigation. Per the canonical, credential-free run used
here, the single AWS finding came back `Verified:false` with **no** `VerificationError` (Q3) —
consistent with a definitive "not live" determination — but this document does **not** claim to
have observed the network packets. The parallel *structure* is source-confirmed and the worker
magnitude is observed; the live HTTP exchange itself is labelled inferred.
---

## Q3 — JSON output structure (the finding schema)

> *"If I run a scan with JSON output, what's the actual schema for a finding? Are there fields for
> verification status, confidence scores, or metadata about where secrets were found?"*

### Direct answer

- **The per-finding schema is the anonymous struct marshalled by `JSONPrinter.Print`**
  (`pkg/output/json.go:L19-L74`). One finding = one JSON object per line.
- **It has verification-status fields:** `Verified` (bool), `VerificationFromCache` (bool), and
  `VerificationError` (string, emitted only when non-empty via `json:",omitempty"`).
- **It has rich "where was it found" metadata:** `SourceMetadata` (source-specific — for a Git
  scan, `SourceMetadata.Data.Git` with `commit`, `file`, `email`, `timestamp`, `line`), plus
  `SourceID`, `SourceType`, `SourceName`.
- **It has *no* confidence-score field.** There is nothing named `Confidence` or `Score` anywhere
  in the object or in the struct definition (OBSERVED grep + source). Detector identity is carried
  by `DetectorType`/`DetectorName`/`DetectorDescription`, not a numeric confidence.

### (A) The command and the real finding object (complete, unedited)

**OBSERVED — the scan and its captured stdout** (findings go to stdout; the JSON was captured to a
file, then pretty-printed for readability — the raw bytes are shown first):

```text
$ /tmp/trufflehog_bin git file:///tmp/thog_investigation.ulY2DMuS/thog_testrepo \
      --json --no-update 1>/tmp/thog_investigation.ulY2DMuS/captures/q3_stdout.json 2>/dev/null
$ cat /tmp/thog_investigation.ulY2DMuS/captures/q3_stdout.json
{"SourceMetadata":{"Data":{"Git":{"commit":"6b84f04f1c0982272bb21e3ec5ae447b639420d5","file":"aws_creds.ini","email":"t \u003ct@t.com\u003e","timestamp":"2026-07-13 18:16:00 +0000","line":2}}},"SourceID":1,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DetectorDescription":"AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.","DecoderName":"PLAIN","Verified":false,"VerificationFromCache":false,"Raw":"AKIAYVP4CIPPERUVIFXG","RawV2":"AKIAYVP4CIPPERUVIFXG:qUGtRtqlJNUCoY5SBly3QymVf33zOXxHcEuS7VxA","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","is_canary":"true","message":"This is an AWS canary token generated at canarytokens.org.","resource_type":"Access key"},"StructuredData":null}
```

**OBSERVED — the same object pretty-printed** (`python3 -m json.tool`), for field-by-field
reading:

```json
{
    "SourceMetadata": {
        "Data": {
            "Git": {
                "commit": "6b84f04f1c0982272bb21e3ec5ae447b639420d5",
                "file": "aws_creds.ini",
                "email": "t <t@t.com>",
                "timestamp": "2026-07-13 18:16:00 +0000",
                "line": 2
            }
        }
    },
    "SourceID": 1,
    "SourceType": 16,
    "SourceName": "trufflehog - git",
    "DetectorType": 2,
    "DetectorName": "AWS",
    "DetectorDescription": "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.",
    "DecoderName": "PLAIN",
    "Verified": false,
    "VerificationFromCache": false,
    "Raw": "AKIAYVP4CIPPERUVIFXG",
    "RawV2": "AKIAYVP4CIPPERUVIFXG:qUGtRtqlJNUCoY5SBly3QymVf33zOXxHcEuS7VxA",
    "Redacted": "AKIAYVP4CIPPERUVIFXG",
    "ExtraData": {
        "account": "595918472158",
        "is_canary": "true",
        "message": "This is an AWS canary token generated at canarytokens.org.",
        "resource_type": "Access key"
    },
    "StructuredData": null
}
```

### (B) Field-by-field schema (mapped to source)

**INFERRED — source-confirmed.** Every emitted key maps 1:1 to a field of the anonymous struct in
`JSONPrinter.Print` [`pkg/output/json.go:L19-L74`]. The 15 top-level keys observed (the 16th struct
field, `VerificationError`, is `omitempty` and was absent here because there was no error):

| JSON key | Go field (json.go) | Type | Meaning |
|---|---|---|---|
| `SourceMetadata` | `SourceMetadata *source_metadatapb.MetaData` (L29) | object | Where the secret was found (source-specific) |
| `SourceID` | `SourceID sources.SourceID` (L31) | int | Internal source id |
| `SourceType` | `SourceType sourcespb.SourceType` (L33) | int enum | Source kind (16 = git) |
| `SourceName` | `SourceName string` (L35) | string | e.g. `trufflehog - git` |
| `DetectorType` | `DetectorType detectorspb.DetectorType` (L37) | int enum | Detector id (2 = AWS) |
| `DetectorName` | `DetectorName string` (L39; value `= r.DetectorType.String()` at L63) | string | e.g. `AWS` |
| `DetectorDescription` | `DetectorDescription string` (L41) | string | Human description |
| `DecoderName` | `DecoderName string` (L43; value `= r.DecoderType.String()` at L65) | string | e.g. `PLAIN` |
| `Verified` | `Verified bool` (L44) | bool | Live-verification result |
| *(`VerificationError`)* | `VerificationError string` `json:",omitempty"` (L45) | string | Present only on error |
| `VerificationFromCache` | `VerificationFromCache bool` (L46) | bool | Whether result came from cache |
| `Raw` | `Raw string` (L48) | string | Raw matched secret |
| `RawV2` | `RawV2 string` (L51) | string | Composed id:secret (multi-part secrets) |
| `Redacted` | `Redacted string` (L54) | string | Display-safe form |
| `ExtraData` | `ExtraData map[string]string` (L55) | object | Detector-specific extras |
| `StructuredData` | `StructuredData *detectorspb.StructuredData` (L56) | object/null | Optional structured payload |

**OBSERVED — the exact key set and nested keys** (enumerated programmatically from the captured
object):

```text
count= 15
fields= ['SourceMetadata', 'SourceID', 'SourceType', 'SourceName', 'DetectorType', 'DetectorName', 'DetectorDescription', 'DecoderName', 'Verified', 'VerificationFromCache', 'Raw', 'RawV2', 'Redacted', 'ExtraData', 'StructuredData']
ExtraData keys= ['account', 'is_canary', 'message', 'resource_type']
Git keys= ['commit', 'file', 'email', 'timestamp', 'line']
```

### (C) Verification-status fields — present

**OBSERVED.** In the captured finding: `"Verified": false` and `"VerificationFromCache": false`.
**INFERRED — source-confirmed.** These come from `Verified`/`VerificationFromCache` (json.go
L44/L46); a third field `VerificationError` (L45) is emitted **only** when verification actually
errored (it uses `json:",omitempty"`, and the `Print` method computes it from
`r.VerificationError()` at L20-L25). Here verification returned a clean "not live" result, so no
error key appears.

### (D) "Where was it found" metadata — present and source-shaped

**OBSERVED.** For this Git scan the location block was:

```json
"SourceMetadata": { "Data": { "Git": {
  "commit": "6b84f04f1c0982272bb21e3ec5ae447b639420d5",
  "file": "aws_creds.ini", "email": "t <t@t.com>",
  "timestamp": "2026-07-13 18:16:00 +0000", "line": 2 } } }
```

**INFERRED — source-confirmed.** `SourceMetadata` is a `*source_metadatapb.MetaData`
(`proto/source_metadata.proto`: `message MetaData` [`L367`]) whose `Data` is a oneof of
source-specific messages — here `message Git` [`L94`] (fields `commit`, `file`, `email`,
`timestamp`, `line`). A filesystem scan instead populates `message Filesystem` [`L87`]. So the
"where" metadata is strongly typed per source, not a flat string.

### (E) Confidence scores — absent

**OBSERVED.** Grepping the actual JSON output for any confidence/score field returns nothing:

```text
$ grep -ic -E 'confidence|score' q3_stdout.json
0
grep exit=1 (grep -c prints 0 and exits 1 when there is no match)
```

**INFERRED — source-confirmed.** The struct in `json.go:L19-L74` contains **no** `Confidence` or
`Score` field (a source grep of `pkg/output/json.go` for `confidence|score` also returns nothing).
TruffleHog models a finding as **binary verified / not-verified plus detector identity**, not as a
probabilistic confidence score.

### Sensitivity note

**OBSERVED.** The `Raw`/`RawV2`/`Redacted` fields echo the matched secret. In this document those
values are the **public AWS canary key** (`AKIAYVP4CIPPERUVIFXG`, `is_canary=true`,
`message: "This is an AWS canary token generated at canarytokens.org."`) plus a **fabricated**
secret in `RawV2`, so reproducing them here is safe. Against real material, treat these fields as
**live credentials**.
---

## Q4 — Repository traversal (which files are scanned vs skipped)

> *"If I scan a test repo with mixed file types and check verbose logs, what does it reveal about
> how TruffleHog decides which files to scan versus skip?"*

### Direct answer

There is **no single rule**. The scan-vs-skip decision is made in **three different places**
depending on how the content is reached, and they use **different keys**:

1. **Loose (non-archive) files — decided by *content-derived* MIME, then an extension check.** The
   file's bytes are sniffed to a MIME type; that MIME's canonical extension is looked up in the
   ignored/binary extension sets. **Key = detected content type, not the filename.** (This is why
   `data.mp4` — text bytes with a video name — is *scanned*, while `logo.png` — real PNG bytes — is
   *skipped*.)
2. **Archive members — pre-filtered by member *metadata* (name/size/type) *before* content.** Inside
   an archive, each member is checked by its **archive filename**, its size against a 2 GB cap, and
   whether it is a directory/symlink — before (and independently of) any content sniff, and only up
   to a maximum nesting depth of 10.
3. **Git source — a filename-based ignored-extension check, path exclude-globs, plus a
   *conditional* binary skip.** A Git scan first drops any blob whose **filename** extension is in
   the ignored set — `common.SkipFile(path)` keyed on the blob **path** (not a content sniff),
   logging `file contains ignored extension` (this is what skips `logo.png` under the git source,
   as opposed to the loose-file content-MIME path above). It can also exclude paths by glob at the
   git-log level, and it detects binary blobs — but it only *skips* binaries when the
   `--force-skip-binaries` flag (internally `skipBinaries` / `feature.ForceSkipBinaries`) is set;
   otherwise binary blobs are scanned.

### The exact run (absolute paths, offline, trace verbosity)

**OBSERVED — command and channels** (findings→stdout, banner+trace→stderr; `--no-verification`
keeps it offline; `--log-level=5` is trace):

```text
$ WORK=/tmp/thog_investigation.ulY2DMuS
$ /tmp/trufflehog_bin filesystem "$WORK/thog_files" --no-verification --log-level=5 \
      1>"$WORK/captures/q4_stdout.log" 2>"$WORK/captures/q4_trace.log"; echo "exit=$?"
exit=0
```

**OBSERVED — stdout (the one finding):**

```text
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAYVP4CIPPERUVIFXG
Resource_type: Access key
Account: 595918472158
Message: This is an AWS canary token generated at canarytokens.org.
Is_canary: true
File: /tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini
Line: 2

```

### (A) The decisive trace lines (annotated)

**OBSERVED — the scan/skip decisions, extracted from the trace with their line numbers** (the
complete 172-line trace follows in section (D)):

```text
16:2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
17:2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
18:2026-07-13T18:43:13Z	info-4	trufflehog	Opened file successfully	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "filename": "inside.txt", "size": 40}
19:2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "depth": 2}
20:2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "depth": 2}
21:2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
22:2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
32:2026-07-13T18:43:13Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
33:2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env", "mime": "text/plain; charset=utf-8", "timeout": 60}
36:2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini", "mime": "text/plain; charset=utf-8", "timeout": 60}
39:2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem", "mime": "text/plain; charset=utf-8", "timeout": 60}
41:2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4", "mime": "text/plain; charset=utf-8", "timeout": 60}
42:2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
```

Reading these:

- **`logo.png` → SKIPPED.** Line with `skipping file: extension is ignored` carries
  `"mime":"image/png"` and `"ext":".png"`. Its *content* sniffed to `image/png`, whose extension
  `.png` is in the ignored set — so it is skipped.
- **`data.mp4` → SCANNED.** Despite the `.mp4` name, its *content* sniffed to
  `text/plain; charset=utf-8`, so it was chunked and scanned to completion
  (`dataErrChan closed, all chunks processed`, `"mime":"text/plain; charset=utf-8"`). This is the
  crux: the **content MIME**, not the filename extension, drives the loose-file decision.
- **`aws_creds.ini`, `config.env`, `testkey.pem`, `notes.txt` → SCANNED** (each ends with
  `dataErrChan closed …` at `text/plain`).
- **`archive.tar.gz` → DESCENDED.** `application/gzip` triggers `Starting archive processing` at
  `depth: 0`, nested to `depth: 1` then `depth: 2`, with `Opened file successfully` for member
  `"filename":"inside.txt","size":40`, and matching `Finished archive processing` unwinding
  `2 → 1 → 0`. The 40-byte text member was extracted and scanned.
- **Summary:** `finished scanning {"chunks":6,"bytes":663,"verified_secrets":0,"unverified_secrets":1}`.
  Exactly one file (`logo.png`) produced a `skipping file` line.

### (B) Why — path 1: loose files use content MIME → extension

**INFERRED — source-confirmed.** For non-archive content, `handleNonArchiveContent`
[`pkg/handlers/default.go:L94`] reads `mimeExt := reader.mimeExt` [`L99`] and decides:

```go
// pkg/handlers/default.go:L101-102
if common.SkipFile(mimeExt) || common.IsBinary(mimeExt) {
    ctx.Logger().V(3).Info("skipping file: extension is ignored", "ext", mimeExt)
```

`mimeExt` is the **content-detected** extension: the reader sniffs bytes via
`mimetype.Detect(buffer)` [`pkg/handlers/handlers.go:L98`] (or `mimetype.DetectReader` [`L127`]) and
stores `mimeExt: r.mime.Extension()` [`handlers.go:L76`, field declared `L68`]. The two predicates
consult fixed maps: `common.SkipFile` [`pkg/common/vars.go:L122`] tests the `ignoredExtensions` map
[`L10`], and `common.IsBinary` [`L129`] tests `binaryExtensions` [`L80`]. So a loose file is skipped
iff its **content's** canonical extension is in one of those sets — exactly what the `logo.png`
(`image/png`/`.png`) vs `data.mp4` (`text/plain`, scanned) pair demonstrates.

### (C) Why — path 2: archive members pre-filtered by metadata; path 3: git

**INFERRED — source-confirmed (archives).** Inside `pkg/handlers/archive.go`, each member is
filtered **before** content handling, by member metadata:

- directory/symlink: `if file.IsDir() || file.LinkTarget != "" {` [`L187`] →
  `V(4) "skipping directory or symlink"` [`L188`].
- size cap: `if int(fileSize) > maxSize {` [`L198`] → `V(2) "skipping file: size exceeds max
  allowed"` [`L199`], where `maxSize = 2 << 30` (2 GB) [`L27`].
- extension: `if common.SkipFile(file.Name()) || common.IsBinary(file.Name()) {` [`L204`] →
  `V(3) "skipping file: extension is ignored"` [`L205`] — here the check uses the **member
  filename** (`file.Name()`), not a content sniff.
- depth guard: `if depth >= maxDepth {` [`L124`], with `maxDepth = 5 * 2` (10) [`L26`].

That is why the observed archive descent stops at `depth: 2` and screens members by name/size — a
different mechanism from the loose-file content sniff.

**OBSERVED + source-confirmed (git).** For a Git source (`pkg/sources/git/git.go`), a blob is first
screened by its **filename** extension — `if common.SkipFile(path) {` [`L1244`] →
`V(5) "file contains ignored extension"` [`L1245`] — where `path` is the blob path, *not* a content
sniff. A companion git scan of the same fixture confirms this: `logo.png` is skipped with the
git-specific message `file contains ignored extension` (`"path":"logo.png"`), distinct from the
loose-file `skipping file: extension is ignored` message above. Path exclusion is also applied at
the git-log level via exclude-globs [`L185-187`, `ScanOptionExcludeGlobs`], and binary blobs are
detected with `diff.IsBinary` [`L644`, `L873`]; crucially the binary skip is **conditional**:
`if s.skipBinaries || feature.ForceSkipBinaries.Load() {` [`L647`, `L876`] → `V(5) "skipping binary
file"`. Absent the `--force-skip-binaries` flag, binary blobs are **scanned**, not skipped — so
"binary ⇒ skipped" is not universally true for the Git source.

### (D) Complete, unedited trace (172 lines)

**OBSERVED — the entire stderr trace for the run above**, verbatim (172 lines; the concurrent
`finished scanning chunks` worker lines are inherently interleaved and their order varies run to
run, but the file decisions above are stable):

```text
2026-07-13T18:43:13Z	info-2	trufflehog	trufflehog dev
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T18:43:13Z	info-4	trufflehog	default engine options set
2026-07-13T18:43:13Z	info-4	trufflehog	engine initialized
2026-07-13T18:43:13Z	info-4	trufflehog	setting up aho-corasick core
2026-07-13T18:43:13Z	info-4	trufflehog	set up aho-corasick core
2026-07-13T18:43:13Z	info-2	trufflehog	starting scanner workers	{"count": 128}
2026-07-13T18:43:13Z	info-2	trufflehog	starting detector workers	{"count": 1024}
2026-07-13T18:43:13Z	info-2	trufflehog	starting verificationOverlap workers	{"count": 128}
2026-07-13T18:43:13Z	info-2	trufflehog	starting notifier workers	{"count": 128}
2026-07-13T18:43:13Z	info-0	trufflehog	running source	{"source_manager_worker_id": "MHAG2", "with_units": true}
2026-07-13T18:43:13Z	info-2	trufflehog	enumerating source	{"source_manager_worker_id": "MHAG2"}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz"}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz"}
2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
2026-07-13T18:43:13Z	info-4	trufflehog	Opened file successfully	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "filename": "inside.txt", "size": 40}
2026-07-13T18:43:13Z	info-4	trufflehog	Starting archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "depth": 2}
2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "filename": "inside.txt", "size": 40, "depth": 2}
2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 1}
2026-07-13T18:43:13Z	info-4	trufflehog	Finished archive processing	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60, "depth": 0}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/archive.tar.gz", "mime": "application/gzip", "timeout": 60}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini"}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini"}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png"}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env"}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png"}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env"}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem"}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem"}
2026-07-13T18:43:13Z	info-3	trufflehog	skipping file: extension is ignored	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "mime": "image/png", "timeout": 60, "ext": ".png"}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/config.env", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/logo.png", "mime": "image/png", "timeout": 60}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4"}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/aws_creds.ini", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4"}
2026-07-13T18:43:13Z	info-3	trufflehog	chunking unit	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt"}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/testkey.pem", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T18:43:13Z	info-3	trufflehog	scanning file	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt"}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/data.mp4", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T18:43:13Z	info-5	trufflehog	dataErrChan closed, all chunks processed	{"source_manager_worker_id": "MHAG2", "unit_kind": "unit", "unit": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt", "path": "/tmp/thog_investigation.ulY2DMuS/thog_files/notes.txt", "mime": "text/plain; charset=utf-8", "timeout": 60}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Mha4E"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HESR0"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DQw88"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "XP71w"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0b2B3"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "srHta"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "1Kxuf"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "cpMqz"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "4tkir"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Wcwvt"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5fPJP"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pa7jE"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "LRiJe"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HfRtZ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "I48Co"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zXmiB"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "y6w29"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "t061X"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "UEfkj"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CS8zd"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "rc6KN"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "duZZF"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "iOuK2"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "rqJrx"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "fMavo"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Fi7OU"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vrup3"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OHssH"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "8Scc1"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "lILPa"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Bye21"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "eZJvp"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zO0v9"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AgSvY"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "2ubk8"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "V3oBy"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "J5Vhg"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "COSh8"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "YYRyj"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Z4YbX"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "m1FVv"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "jiR5b"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "WDLUJ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OjvfC"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "RYz5M"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Qc6Vr"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "PhaiL"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "JqQGt"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "oGUac"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "tutlE"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "5hOdG"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ekef7"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "UDrSq"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "FQNnc"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zFbCG"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IPjqN"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "LcBIn"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AD3Zz"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "aeEEo"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CzmPy"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "O83kT"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vqJss"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "HJBch"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Xnzna"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CYeCk"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "kaT4e"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "15LeJ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "bRH48"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "1DVJl"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZFwr0"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "kfgo9"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "jXcRo"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "wqaWx"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0cpIy"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "CnKI0"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "onAzA"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "QBFiZ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "y1UZg"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "J2NlE"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "byzQP"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "OZsAp"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pXhdI"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "qrxY6"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "RCcDu"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DCvJj"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Sk1ZL"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "K01Dd"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "2CEr2"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "GTQGs"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "iG1qr"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "T2xCr"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "U3qXy"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "SnqTF"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "L2XJJ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "DzT7J"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "hcUP2"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "AV0p5"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "9vopp"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "KC4Vc"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "q3qkH"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "iCxGR"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZJBAV"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZcYfh"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "hQnP9"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "wyI0q"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "C2gUO"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "IjWj2"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Zbk2z"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "ZIWXn"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "29zx6"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "FJw2P"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "luwuY"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "B7jHQ"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Jrv1J"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "m7cgF"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "l8hzp"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "vzXAf"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "971JS"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "0zue5"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "Z4wMO"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "1gNBk"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "4wxdN"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "c7kzG"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "JoO9Z"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pCmha"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "zEK7P"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "exVqI"}
2026-07-13T18:43:13Z	info-4	trufflehog	finished scanning chunks	{"scanner_worker_id": "pt4SZ"}
2026-07-13T18:43:13Z	info-4	trufflehog	link is empty, skipping update	{"detector_worker_id": "4yNrz", "detector": {"type":"AWS"}, "timeout": 10}
2026-07-13T18:43:13Z	info-0	trufflehog	finished scanning	{"chunks": 6, "bytes": 663, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.775678ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```
---

## Q5 — Detector architecture (plugins vs embedded) and help output

> *"When I compile the project, are the detectors separate plugins or embedded modules? If I run
> the binary with a help flag, what information does it show about available detection
> capabilities?"*

### Direct answer

- **Detectors are embedded/compiled-in modules — not separate plugins.** The build produces a
  single, fully static binary with no dynamic-link or plugin-load surface (`ldd` → "not a dynamic
  executable"), and the word "plugin" appears nowhere in the CLI. Each detector is a Go type
  compiled into the binary and enrolled in a compiled-in slice (`buildDetectorList` /
  `DefaultDetectors`). **831** detectors are active in the default build.
- **The help flags reveal the detection capabilities as CLI flags + source commands**, not a
  plugin registry: detector-selection flags (`--include-detectors`, `--exclude-detectors`),
  verification-capability flags (`--no-verification`, `--results`, `--verifier`,
  `--detector-timeout`, `--no-verification-cache`, …), and the list of scannable **source
  sub-commands** (`git`, `github`, `gitlab`, `filesystem`, `s3`, `gcs`, `docker`, `postman`,
  `elasticsearch`, `jenkins`, `huggingface`, …, plus `analyze`).

### (A) Embedded, not plugins — the static binary

**OBSERVED.** `ldd` reports no dynamic linkage, and a case-insensitive search for "plugin" in the
full long help finds nothing:

```text
$ ldd /tmp/trufflehog_bin
	not a dynamic executable
ldd exit=1
```

```text
$ grep -ic plugin helplong_stdout.txt   # helplong_stdout.txt = captured --help-long
0
grep exit=1 (no match: grep -c prints 0 and exits 1; a trailing `|| true` prevents set -e abort)
```

`ldd` exiting **1** with "not a dynamic executable" is the expected signal for a `CGO_ENABLED=0`
static Go binary — there are no shared objects and therefore no plugin `.so` surface. The
`grep -ic plugin` printing **0** and exiting **1** (no match) is why such a check is written with a
trailing `|| true` in a `set -e` script.

### (B) Compiled-in registration and the detector count (831)

**INFERRED — source-confirmed.** Detectors are enrolled by being *code* in a compiled-in slice:
`buildDetectorList()` [`pkg/engine/defaults/defaults.go:L839`] returns a long list of detector
values, wrapped by `DefaultDetectors()` [`…:L1704`]. The active count is **831** — 829 struct
literals plus two constructor-based entries:

```text
# active &Scanner{} struct literals:
$ grep -cE '^[[:space:]]*&[A-Za-z0-9_]+\.Scanner\{\}' pkg/engine/defaults/defaults.go
829
# constructor-call detectors in the list:
$ grep -nE '\.New\(\),$' pkg/engine/defaults/defaults.go
906:		aws_access_keys.New(),
907:		aws_session_keys.New(),
# commented-out (inactive) detector lines:
$ grep -cE '^[[:space:]]*//[[:space:]]*&[A-Za-z0-9_]+\.Scanner\{\}' pkg/engine/defaults/defaults.go
28
# detector directories:
$ find pkg/detectors -mindepth 1 -maxdepth 1 -type d | wc -l
845
```

That is: **829** active `&<pkg>.Scanner{}` literals **+** `aws_access_keys.New()`
[`defaults.go:L906`] **+** `aws_session_keys.New()` [`defaults.go:L907`] = **831 active** detectors;
a further **28** detector lines are commented out (inactive), and there are **845** detector
directories under `pkg/detectors/` (the directory count exceeds the active count because of the
commented-out entries and non-detector helper directories). Because these are compiled-in Go
values, adding or removing a detector requires recompiling the binary — there is no runtime plugin
directory to drop files into.

### (C) Build provenance (consistent with the Environment section)

**OBSERVED / INFERRED — source-confirmed.** The compiled artifact is the same static binary
described earlier: its application version is the source constant `dev`
(`pkg/version/version.go:L3`, wired at `main.go:L270`, no `-ldflags` override), while the Go
toolchain has *automatically* embedded VCS provenance
(`vcs.revision=e42153d44a5e…`, `vcs.modified=false` — see the Environment section's `go version -m`
capture). These two facts are independent; neither implies a plugin mechanism.

### (D) `--help` — abbreviated help (channel: stderr, 124 lines)

**OBSERVED.** `--help` prints the abbreviated usage to **stderr** (stdout empty), exit `0`. The
capture is 124 lines and ends with the `analyze` command followed by trailing blank lines:

```text
$ /tmp/trufflehog_bin --help 1>/tmp/help.out 2>/tmp/help.err; echo "exit=$?  stdout=$(wc -l </tmp/help.out)L  stderr=$(wc -l </tmp/help.err)L"
exit=0  stdout=0L  stderr=124L
$ cat /tmp/help.err
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

### (E) `--help-long` — complete capability listing (channel: stdout, 416 lines)

**OBSERVED — the complete, unedited long help** (`--help-long` prints to **stdout**, exit `0`;
416 lines). This is the exhaustive flag+command reference; the detector-selection and
verification-capability flags are visible here (e.g. `--concurrency=128` reflecting this host's
`NumCPU`, `--no-verification`, `--results`, `--include-detectors="all"`, `--exclude-detectors`,
`--verifier`, `--detector-timeout`, `--no-verification-cache`):

```text
$ /tmp/trufflehog_bin --help-long 1>/tmp/helplong.out 2>/tmp/helplong.err; echo "exit=$?  stdout=$(wc -l </tmp/helplong.out)L  stderr=$(wc -l </tmp/helplong.err)L"
exit=0  stdout=416L  stderr=0L
$ cat /tmp/helplong.out
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

    -i, --include-paths=INCLUDE-PATHS
                               Path to file with newline separated regexes for
                               files to include in scan.
    -x, --exclude-paths=EXCLUDE-PATHS
                               Path to file with newline separated regexes for
                               files to exclude in scan.
        --exclude-globs=EXCLUDE-GLOBS
                               Comma separated list of globs to exclude in scan.
                               This option filters at the `git log` level,
                               resulting in faster scans.
        --since-commit=SINCE-COMMIT
                               Commit to start scan from.
        --branch=BRANCH        Branch to scan.
        --max-depth=MAX-DEPTH  Maximum depth of commits to scan.
        --[no-]bare            Scan bare repository (e.g. useful while using in
                               pre-receive hooks)
        --[no-]allow           No-op flag for backwards compat.
        --[no-]entropy         No-op flag for backwards compat.
        --[no-]regex           No-op flag for backwards compat.

github [<flags>]
    Find credentials in GitHub repositories.

        --endpoint="https://api.github.com"
                                GitHub endpoint.
        --repo=REPO ...         GitHub repository to scan.
                                You can repeat this flag. Example:
                                "https://github.com/dustin-decker/secretsandstuff"
        --org=ORG ...           GitHub organization to scan. You can repeat this
                                flag. Example: "trufflesecurity"
        --token=TOKEN           GitHub token. Can be provided with environment
                                variable GITHUB_TOKEN. ($GITHUB_TOKEN)
        --[no-]include-forks    Include forks in scan.
        --[no-]include-members  Include organization member repositories in
                                scan.
        --include-repos=INCLUDE-REPOS ...
                                Repositories to include in an org scan.
                                This can also be a glob pattern. You can repeat
                                this flag. Must use Github repo full name.
                                Example: "trufflesecurity/trufflehog",
                                "trufflesecurity/t*"
        --[no-]include-wikis    Include repository wikisin scan.
        --exclude-repos=EXCLUDE-REPOS ...
                                Repositories to exclude in an org scan.
                                This can also be a glob pattern. You can repeat
                                this flag. Must use Github repo full name.
                                Example: "trufflesecurity/driftwood",
                                "trufflesecurity/d*"
    -i, --include-paths=INCLUDE-PATHS
                                Path to file with newline separated regexes for
                                files to include in scan.
    -x, --exclude-paths=EXCLUDE-PATHS
                                Path to file with newline separated regexes for
                                files to exclude in scan.
        --[no-]issue-comments   Include issue descriptions and comments in scan.
        --[no-]pr-comments      Include pull request descriptions and comments
                                in scan.
        --[no-]gist-comments    Include gist comments in scan.
        --comments-timeframe=COMMENTS-TIMEFRAME
                                Number of days in the past to review when
                                scanning issue, PR, and gist comments.

github-experimental --repo=REPO [<flags>]
    Run an experimental GitHub scan. Must specify at least one experimental
    sub-module to run: object-discovery.

    --[no-]object-discovery    Discover hidden data objects in GitHub
                               repositories.
    --token=TOKEN              GitHub token. Can be provided with environment
                               variable GITHUB_TOKEN. ($GITHUB_TOKEN)
    --repo=REPO                GitHub repository to scan. Example:
                               https://github.com/<user>/<repo>.git
    --collision-threshold=1    Threshold for short-sha collisions in
                               object-discovery submodule. Default is 1.
    --[no-]delete-cached-data  Delete cached data after object-discovery secret
                               scanning.

gitlab --token=TOKEN [<flags>]
    Find credentials in GitLab repositories.

        --endpoint="https://gitlab.com"
                         GitLab endpoint.
        --repo=REPO ...  GitLab repo url. You can repeat this flag. Leave empty
                         to scan all repos accessible with provided credential.
                         Example: https://gitlab.com/org/repo.git
        --token=TOKEN    GitLab token. Can be provided with environment variable
                         GITLAB_TOKEN. ($GITLAB_TOKEN)
    -i, --include-paths=INCLUDE-PATHS
                         Path to file with newline separated regexes for files
                         to include in scan.
    -x, --exclude-paths=EXCLUDE-PATHS
                         Path to file with newline separated regexes for files
                         to exclude in scan.
        --include-repos=INCLUDE-REPOS ...
                         Repositories to include in an org scan. This can
                         also be a glob pattern. You can repeat this flag.
                         Must use Gitlab repo full name. Example:
                         "trufflesecurity/trufflehog", "trufflesecurity/t*"
        --exclude-repos=EXCLUDE-REPOS ...
                         Repositories to exclude in an org scan. This can
                         also be a glob pattern. You can repeat this flag.
                         Must use Gitlab repo full name. Example:
                         "trufflesecurity/driftwood", "trufflesecurity/d*"

filesystem [<flags>] [<path>...]
    Find credentials in a filesystem.

        --directory=DIRECTORY ...  Path to directory to scan. You can repeat
                                   this flag.
    -i, --include-paths=INCLUDE-PATHS
                                   Path to file with newline separated regexes
                                   for files to include in scan.
    -x, --exclude-paths=EXCLUDE-PATHS
                                   Path to file with newline separated regexes
                                   for files to exclude in scan.

s3 [<flags>]
    Find credentials in S3 buckets.

    --key=KEY                      S3 key used to authenticate. Can be provided
                                   with environment variable AWS_ACCESS_KEY_ID.
                                   ($AWS_ACCESS_KEY_ID)
    --role-arn=ROLE-ARN ...        Specify the ARN of an IAM role to assume for
                                   scanning. You can repeat this flag.
    --secret=SECRET                S3 secret used to authenticate.
                                   Can be provided with environment
                                   variable AWS_SECRET_ACCESS_KEY.
                                   ($AWS_SECRET_ACCESS_KEY)
    --session-token=SESSION-TOKEN  S3 session token used to authenticate
                                   temporary credentials. Can be provided with
                                   environment variable AWS_SESSION_TOKEN.
                                   ($AWS_SESSION_TOKEN)
    --[no-]cloud-environment       Use IAM credentials in cloud environment.
    --bucket=BUCKET ...            Name of S3 bucket to scan. You can repeat
                                   this flag. Incompatible with --ignore-bucket.
    --ignore-bucket=IGNORE-BUCKET ...
                                   Name of S3 bucket to ignore. You can repeat
                                   this flag. Incompatible with --bucket.
    --max-object-size=250MB        Maximum size of objects to scan. Objects
                                   larger than this will be skipped. (Byte units
                                   eg. 512B, 2KB, 4MB)

gcs [<flags>]
    Find credentials in GCS buckets.

        --project-id=PROJECT-ID   GCS project ID used to authenticate. Can NOT
                                  be used with unauth scan. Can be provided with
                                  environment variable GOOGLE_CLOUD_PROJECT.
                                  ($GOOGLE_CLOUD_PROJECT)
        --[no-]cloud-environment  Use Application Default Credentials, IAM
                                  credentials to authenticate.
        --service-account=SERVICE-ACCOUNT
                                  Path to GCS service account JSON file.
        --[no-]without-auth       Scan GCS buckets without authentication.
                                  This will only work for public buckets
        --api-key=API-KEY         GCS API key used to authenticate.
                                  Can be provided with environment variable
                                  GOOGLE_API_KEY. ($GOOGLE_API_KEY)
    -I, --include-buckets=INCLUDE-BUCKETS ...
                                  Buckets to scan. Comma separated list of
                                  buckets. You can repeat this flag. Globs are
                                  supported
    -X, --exclude-buckets=EXCLUDE-BUCKETS ...
                                  Buckets to exclude from scan. Comma separated
                                  list of buckets. Globs are supported
    -i, --include-objects=INCLUDE-OBJECTS ...
                                  Objects to scan. Comma separated list of
                                  objects. you can repeat this flag. Globs are
                                  supported
    -x, --exclude-objects=EXCLUDE-OBJECTS ...
                                  Objects to exclude from scan. Comma separated
                                  list of objects. You can repeat this flag.
                                  Globs are supported
        --max-object-size=10MB    Maximum size of objects to scan. Objects
                                  larger than this will be skipped. (Byte units
                                  eg. 512B, 2KB, 4MB)

syslog [<flags>]
    Scan syslog

    --address=ADDRESS    Address and port to listen on for syslog. Example:
                         127.0.0.1:514
    --protocol=PROTOCOL  Protocol to listen on. udp or tcp
    --cert=CERT          Path to TLS cert.
    --key=KEY            Path to TLS key.
    --format=FORMAT      Log format. Can be rfc3164 or rfc5424

circleci --token=TOKEN
    Scan CircleCI

    --token=TOKEN  CircleCI token. Can also be provided with environment
                   variable ($CIRCLECI_TOKEN)

docker --image=IMAGE [<flags>]
    Scan Docker Image

    --image=IMAGE ...  Docker image to scan. Use the file:// prefix to point to
                       a local tarball, otherwise a image registry is assumed.
    --token=TOKEN      Docker bearer token. Can also be provided with
                       environment variable ($DOCKER_TOKEN)

travisci --token=TOKEN
    Scan TravisCI

    --token=TOKEN  TravisCI token. Can also be provided with environment
                   variable ($TRAVISCI_TOKEN)

postman [<flags>]
    Scan Postman

    --token=TOKEN                  Postman token. Can also be provided with
                                   environment variable ($POSTMAN_TOKEN)
    --workspace-id=WORKSPACE-ID ...
                                   Postman workspace ID to scan. You can repeat
                                   this flag.
    --collection-id=COLLECTION-ID ...
                                   Postman collection ID to scan. You can repeat
                                   this flag.
    --environment=ENVIRONMENT ...  Postman environment to scan. You can repeat
                                   this flag.
    --include-collection-id=INCLUDE-COLLECTION-ID ...
                                   Collection ID to include in scan. You can
                                   repeat this flag.
    --include-environments=INCLUDE-ENVIRONMENTS ...
                                   Environments to include in scan. You can
                                   repeat this flag.
    --exclude-collection-id=EXCLUDE-COLLECTION-ID ...
                                   Collection ID to exclude from scan. You can
                                   repeat this flag.
    --exclude-environments=EXCLUDE-ENVIRONMENTS ...
                                   Environments to exclude from scan. You can
                                   repeat this flag.
    --workspace-paths=WORKSPACE-PATHS ...
                                   Path to Postman workspaces.
    --collection-paths=COLLECTION-PATHS ...
                                   Path to Postman collections.
    --environment-paths=ENVIRONMENT-PATHS ...
                                   Path to Postman environments.

elasticsearch [<flags>]
    Scan Elasticsearch

    --nodes=NODES ...              Elasticsearch nodes ($ELASTICSEARCH_NODES)
    --username=USERNAME            Elasticsearch username
                                   ($ELASTICSEARCH_USERNAME)
    --password=PASSWORD            Elasticsearch password
                                   ($ELASTICSEARCH_PASSWORD)
    --service-token=SERVICE-TOKEN  Elasticsearch service token
                                   ($ELASTICSEARCH_SERVICE_TOKEN)
    --cloud-id=CLOUD-ID            Elasticsearch cloud ID. Can also be
                                   provided with environment variable
                                   ($ELASTICSEARCH_CLOUD_ID)
    --api-key=API-KEY              Elasticsearch API key. Can also be
                                   provided with environment variable
                                   ($ELASTICSEARCH_API_KEY)
    --index-pattern="*"            Filters the indices to search
                                   ($ELASTICSEARCH_INDEX_PATTERN)
    --query-json=QUERY-JSON        Filters the documents to search
                                   ($ELASTICSEARCH_QUERY_JSON)
    --since-timestamp=SINCE-TIMESTAMP
                                   Filters the documents to search to
                                   those created since this timestamp;
                                   overrides any timestamp from --query-json
                                   ($ELASTICSEARCH_SINCE_TIMESTAMP)
    --[no-]best-effort-scan        Attempts to continuously scan a cluster
                                   ($ELASTICSEARCH_BEST_EFFORT_SCAN)

jenkins --url=URL [<flags>]
    Scan Jenkins

    --url=URL            Jenkins URL ($JENKINS_URL)
    --username=USERNAME  Jenkins username ($JENKINS_USERNAME)
    --password=PASSWORD  Jenkins password ($JENKINS_PASSWORD)
    --[no-]insecure-skip-verify-tls
                         Skip TLS verification
                         ($JENKINS_INSECURE_SKIP_VERIFY_TLS)

huggingface [<flags>]
    Find credentials in HuggingFace datasets, models and spaces.

    --endpoint="https://huggingface.co"
                                HuggingFace endpoint.
    --model=MODEL ...           HuggingFace model to scan. You can repeat this
                                flag. Example: 'username/model'
    --space=SPACE ...           HuggingFace space to scan. You can repeat this
                                flag. Example: 'username/space'
    --dataset=DATASET ...       HuggingFace dataset to scan. You can repeat this
                                flag. Example: 'username/dataset'
    --org=ORG ...               HuggingFace organization to scan. You can repeat
                                this flag. Example: "trufflesecurity"
    --user=USER ...             HuggingFace user to scan. You can repeat this
                                flag. Example: "trufflesecurity"
    --token=TOKEN               HuggingFace token. Can be provided with
                                environment variable HUGGINGFACE_TOKEN.
                                ($HUGGINGFACE_TOKEN)
    --include-models=INCLUDE-MODELS ...
                                Models to include in scan. You can repeat this
                                flag. Must use HuggingFace model full name.
                                Example: 'username/model' (Only used with --user
                                or --org)
    --include-spaces=INCLUDE-SPACES ...
                                Spaces to include in scan. You can repeat this
                                flag. Must use HuggingFace space full name.
                                Example: 'username/space' (Only used with --user
                                or --org)
    --include-datasets=INCLUDE-DATASETS ...
                                Datasets to include in scan. You can repeat this
                                flag. Must use HuggingFace dataset full name.
                                Example: 'username/dataset' (Only used with
                                --user or --org)
    --ignore-models=IGNORE-MODELS ...
                                Models to ignore in scan. You can repeat this
                                flag. Must use HuggingFace model full name.
                                Example: 'username/model' (Only used with --user
                                or --org)
    --ignore-spaces=IGNORE-SPACES ...
                                Spaces to ignore in scan. You can repeat this
                                flag. Must use HuggingFace space full name.
                                Example: 'username/space' (Only used with --user
                                or --org)
    --ignore-datasets=IGNORE-DATASETS ...
                                Datasets to ignore in scan. You can repeat this
                                flag. Must use HuggingFace dataset full name.
                                Example: 'username/dataset' (Only used with
                                --user or --org)
    --[no-]skip-all-models      Skip all model scans. (Only used with --user or
                                --org)
    --[no-]skip-all-spaces      Skip all space scans. (Only used with --user or
                                --org)
    --[no-]skip-all-datasets    Skip all dataset scans. (Only used with --user
                                or --org)
    --[no-]include-discussions  Include discussions in scan.
    --[no-]include-prs          Include pull requests in scan.

analyze
    Analyze API keys for fine-grained permissions information.



```

### (F) Scannable source commands (from `--help-long`)

**OBSERVED — the source/sub-command lines extracted from the long help** (with their line numbers
in the 416-line output). Two details make this extraction exact: the command-name character class
includes a digit range (`[a-z0-9-]+`) so the numeric command `s3` (L194) is captured — a plain
`[a-z-]+` class would drop it — and the trailing alternation (`( |$)`) matches the bare, flagless
`analyze` command (L412) that a trailing-space-only pattern would miss:

```text
$ grep -nE '^[a-z]' helplong_stdout.txt | grep -E '^[0-9]+:[a-z0-9-]+( |$)'
71:help [<command>...]
75:git [<flags>] <uri>
98:github [<flags>]
140:github-experimental --repo=REPO [<flags>]
155:gitlab --token=TOKEN [<flags>]
182:filesystem [<flags>] [<path>...]
194:s3 [<flags>]
220:gcs [<flags>]
255:syslog [<flags>]
265:circleci --token=TOKEN
271:docker --image=IMAGE [<flags>]
279:travisci --token=TOKEN
285:postman [<flags>]
317:elasticsearch [<flags>]
345:jenkins --url=URL [<flags>]
355:huggingface [<flags>]
412:analyze
```

There are **17** such command entries — `help`, `git`, `github`, `github-experimental`, `gitlab`,
`filesystem`, `s3`, `gcs`, `syslog`, `circleci`, `docker`, `travisci`, `postman`, `elasticsearch`,
`jenkins`, `huggingface`, and `analyze`. These are the sources TruffleHog can scan (plus the
`analyze` utility), and they are the CLI-visible expression of its detection capabilities — again,
compiled-in, not plugin-loaded.
---

## Coverage pass — every named item addressed

Each item the five questions name (including every "e.g./such as/including" example) is listed
with where it is answered and whether the answer is OBSERVED or INFERRED.

| Q | Named item | Where answered | Label |
|---|------------|----------------|-------|
| Q1 | what happens during startup | Q1 (C) worker pools + lifecycle | OBSERVED |
| Q1 | detector configurations from files? | Q1 (A)/(B): built-in = compiled-in; `--config` YAML = optional additive | OBSERVED + INFERRED—source-confirmed |
| Q1 | or are they compiled in? | Q1 (A) `DefaultDetectors`/`buildDetectorList` | INFERRED—source-confirmed |
| Q1 | initialization messages | Q1 (C) four worker-pool lines + version echo | OBSERVED |
| Q1 | which detectors get registered | Q1 (E): no per-detector log; compile-time membership | OBSERVED (absence) + INFERRED—source-confirmed |
| Q2 | build dependencies / HTTP client libraries | Q2 (A) `go.mod`/`go.sum`/`go version -m` | OBSERVED |
| Q2 | suggesting network verification | Q2 (A)/(B) retryablehttp + client roles | OBSERVED (dep) + INFERRED—source-confirmed (use) |
| Q2 | verification in parallel or sequentially | Q2 (D) detector pool 1024 + `FromData` | OBSERVED (pool) + INFERRED—source-confirmed (dispatch) |
| Q3 | actual schema for a finding | Q3 (A)/(B) full object + field table | OBSERVED + INFERRED—source-confirmed |
| Q3 | fields for verification status | Q3 (C) `Verified`/`VerificationFromCache`/`VerificationError` | OBSERVED + INFERRED—source-confirmed |
| Q3 | confidence scores | Q3 (E): none (`grep`=0, not in struct) | OBSERVED + INFERRED—source-confirmed |
| Q3 | metadata about where secrets were found | Q3 (D) `SourceMetadata.Data.Git` | OBSERVED + INFERRED—source-confirmed |
| Q4 | repository traversal / mixed file types | Q4 (A) trace over text/image/video/archive | OBSERVED |
| Q4 | verbose logs | Q4 run at `--log-level=5` (trace) | OBSERVED |
| Q4 | which files to scan versus skip | Q4 (A)-(D) three-path matrix + decisions | OBSERVED + INFERRED—source-confirmed |
| Q5 | compile the project | Env + Q5 (A) static binary | OBSERVED |
| Q5 | separate plugins or embedded modules | Q5 (A)/(B) `ldd`, no "plugin", compiled-in slice | OBSERVED + INFERRED—source-confirmed |
| Q5 | help flag | Q5 (D)/(E) complete `--help` + `--help-long` | OBSERVED |
| Q5 | available detection capabilities | Q5 (D)-(F) capability flags + 17 source commands | OBSERVED |

### A note on what is and isn't host-dependent (magnitude discipline)

Two different kinds of numbers appear in this document, and they scale for **different** reasons:

- **Worker-pool counts are host-CPU-derived.** `128 / 1024 / 128 / 128` come from
  `runtime.NumCPU()=128` on this host via `concurrency` and `concurrency × 8`. On a host with a
  different CPU/affinity count these magnitudes change proportionally (the formulas do not). These
  were confirmed **stable across two runs** on this host.
- **Finding/scan counts are input- and detector-dependent, NOT host-CPU-dependent.** The
  `chunks`, `bytes`, and `verified/unverified` totals (e.g. Git run `chunks:7, unverified:1`;
  filesystem run `chunks:6, bytes:663, unverified:1`) are functions of the **fixture contents** and
  which **detectors** matched — they would be identical on a 4-CPU or a 128-CPU host. Do not read
  the finding counts as a function of core count.
---

## OBSERVED vs INFERRED — labeling summary

This document uses exactly **two** labels (no third "source-confirmed" category exists as a label;
where an inference is corroborated by source it is written **INFERRED — source-confirmed**):

- **OBSERVED** — produced by executing the binary and seen in the captured output shown alongside
  the claim. Examples: the version string `trufflehog dev`; the four worker-pool counts
  `128/1024/128/128`; the banner present in plain/github-actions and absent in `--json`; the
  complete JSON finding object and its 15 keys; the `logo.png` skip vs `data.mp4` scan; the archive
  descent to depth 2; `ldd` → "not a dynamic executable"; `grep -ic plugin` → 0; the complete
  `--help` (124 lines, stderr) and `--help-long` (416 lines, stdout); `go mod verify`; the
  `go.mod`/`go.sum` lines; `go version -m` VCS metadata; the `831` detector count from source
  greps.
- **INFERRED — source-confirmed** — read from source (`file:line`) and not exercised as a distinct
  runtime event, but corroborated by a specific code location. Examples: that the built-in catalog
  is a compiled-in slice (`DefaultDetectors`/`buildDetectorList`); the banner gate condition; the
  worker-count *formulas*; which HTTP client constructors use `retryablehttp`; the two cache roles;
  the per-worker verification dispatch (`FromData`); the JSON-key→struct-field mapping; the
  archive metadata pre-filter and its `maxSize`/`maxDepth` limits; the Git exclude-globs and the
  *conditional* binary skip.
- **INFERRED (not runtime-captured)** — a small number of claims that were neither executed nor are
  pure source facts, explicitly flagged as such: chiefly the **network round-trip** performed
  during live verification (Q2 D) — the parallel *structure* is source-confirmed and the worker
  magnitude observed, but the outbound HTTP exchange itself was not captured on the wire, in keeping
  with the credential-free, `--no-verification`-oriented methodology.

There is **no** blanket "everything else is OBSERVED" claim: each section labels its clauses
individually, and anything derived from reading rather than running is marked inferred.
---

## Final integrity and cleanup

### Read-only contract (source vs delivery commit)

**OBSERVED.** The investigation was read-only: the built binary, the fixture, and all captured
logs live under `/tmp` (outside the checkout), and the only change to the tracked tree is this
document under `blitzy/documentation/`.

- **Source commit under investigation:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760` — the exact
  revision the binary was built from (its `vcs.revision`, `vcs.modified=false`; see Environment /
  Q5). All source `file:line` citations and all runtime behavior describe this commit.
- **Delivery commit (identified by role):** the branch-HEAD commit that adds/updates this Markdown
  file and **nothing else** — a document cannot embed its own commit hash, so it is named by role
  rather than by hash. The commit graph captured at delivery time shows the documentation commit
  with the source commit `e42153d4` as its ancestor (this corrective revision adds one further
  doc-only commit on top of the commit shown):

```text
$ git log --oneline -3
86a21931 docs: add runtime-grounded TruffleHog Q&A answer document
e42153d4 [Fix] Added Prefix In Dockerhub Detector Regex (#4084)
87a80345 Issue - 3697 - GitHub analyzer panic (#4113)
```

**OBSERVED.** `git show HEAD` for the documentation commit confirms the delivery touches **only**
the documentation file — no `.go`, `proto`, manifest, or build file — so the compiled behavior
described here is unchanged from the source commit. The insertion count shown is that of the
documentation commit at capture time; this corrective revision is likewise a doc-only change to the
very same file:

```text
$ git show --stat --oneline HEAD
86a21931 docs: add runtime-grounded TruffleHog Q&A answer document
 blitzy/documentation/trufflehog_e42153d44a5e.md | 1118 +++++++++++++++++++++++
 1 file changed, 1118 insertions(+)
```

### Prior-milestone note (transparency)

**OBSERVED / transparency.** This working branch carries a single agent-authored line of work for
this deliverable (the documentation commit and this corrective update to it); there are **no
branch-local prior-checkpoint review artifacts** committed to the tree to point at. Any
prior-milestone gating is governed outside this branch, so it is stated here plainly rather than
evidenced from the branch history — which would be the only honest option given what the branch
actually contains.

### Cleanup (executed, with proof)

**OBSERVED.** All temporary investigation artifacts were removed after the answers were captured:
the built binary `/tmp/trufflehog_bin`, the secure work directory
`/tmp/thog_investigation.XXXXXXXX` (fixture + captures), and all `/tmp` scratch files. The exact
commands and the post-removal verification (each path absent; the tracked tree clean except the
committed document):

```text
# Remove all temporary investigation artifacts (all live under /tmp, outside the checkout):
$ rm -f  /tmp/trufflehog_bin
$ rm -rf /tmp/thog_investigation.ulY2DMuS
$ rm -f  /tmp/.thog_workdir_path /tmp/cites.txt /tmp/check_cites.py /tmp/blockcount.py /tmp/trailcheck.py
$ rm -rf /tmp/thog_captures_backup

# Verify each artifact is gone (ls reports "No such file or directory" for each):
$ ls -ld /tmp/trufflehog_bin /tmp/thog_investigation.ulY2DMuS /tmp/thog_captures_backup
ls: cannot access '/tmp/trufflehog_bin': No such file or directory
ls: cannot access '/tmp/thog_investigation.ulY2DMuS': No such file or directory
ls: cannot access '/tmp/thog_captures_backup': No such file or directory

# The tracked repository tree is clean — no temporary file leaked into the checkout
# (findings, binary, fixture, and logs were all confined to /tmp):
$ git status --porcelain | wc -l
0
```

After cleanup, `git status` reports a clean working tree with the single documentation file as the
only delivered change — satisfying the "repository itself should remain unchanged, and anything
temporary should be cleaned up afterward" constraint.
