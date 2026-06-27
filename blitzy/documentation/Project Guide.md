# Blitzy Project Guide

> **Project:** TruffleHog Detection Architecture — Onboarding Q&A Documentation
> **Branch:** `blitzy-25efedd0-75d5-4eda-b205-c6664f1fd38c` &nbsp;•&nbsp; **Base commit:** `e42153d44a5e`
> **Color legend:** <span style="color:#5B39F3">**Completed / AI Work = Dark Blue (#5B39F3)**</span> &nbsp;|&nbsp; Remaining / Not Completed = White (#FFFFFF) &nbsp;|&nbsp; <span style="color:#B23AF2">Headings/Accents = Violet-Black (#B23AF2)</span> &nbsp;|&nbsp; <span style="color:#A8FDD9">Highlight = Mint (#A8FDD9)</span>

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a single, code-grounded Markdown document that answers an onboarding engineer's questions about TruffleHog's secret-detection architecture. TruffleHog is an open-source secrets scanner written in Go. The deliverable answers five question clusters — startup & detector registration, verification setup & concurrency, JSON output schema, repository traversal & file filtering, and detector architecture & CLI capabilities — with every claim grounded in the actual source code (102 inline `[path:locator]` citations) and corroborated by output captured from a binary built and run from the exact source tree. The target audience is engineers onboarding to TruffleHog. The entire TruffleHog source tree was treated as read-only and remains byte-for-byte unchanged.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextSize':'14px','pieLegendTextSize':'14px'}}}%%
pie showData title AAP-Scoped Completion — 90.0% Complete
    "Completed Work (AI)" : 18
    "Remaining Work" : 2
```

| Metric | Hours |
|---|---|
| **Total Hours** | **20.0** |
| **Completed Hours (AI + Manual)** | **18.0** (AI: 18.0, Manual: 0.0) |
| **Remaining Hours** | **2.0** |
| **Percent Complete** | **90.0%** |

> **Completion formula (PA1, AAP-scoped):** `18.0 / (18.0 + 2.0) = 18.0 / 20.0 = 90.0%`. The percentage measures only work scoped in the Agent Action Plan (AAP) plus path-to-production activities. All remaining work is human review/merge of a documentation artifact whose scope explicitly forbids any code/test/config changes.

### 1.3 Key Accomplishments

- ✅ Authored the sole AAP deliverable, `blitzy/documentation/trufflehog_e42153d44a5e.md` (294 lines), at the exact required path and branch-derived filename.
- ✅ Answered all **five** question clusters, each as a `Question → Findings → Rationale` section with embedded evidence.
- ✅ Grounded every factual claim in code: **102** `[path:locator]` citations spanning ~12 authoritative source files.
- ✅ Built TruffleHog from source (Go 1.24.2; `CGO_ENABLED=0 go build ./...` → 1005 packages, exit 0; 194,308,498-byte binary) and captured live runtime evidence (verbose, `--json`, `--help`/`--help-long` scans).
- ✅ Triangulated the two central conclusions — **detectors are compiled in (no plugins)** and **there is no confidence-score field** — across code, protobuf schemas, and runtime output.
- ✅ Left the TruffleHog source tree **byte-for-byte unchanged** (only one additive file under `blitzy/`) and cleaned up all temporary artifacts.
- ✅ Passed autonomous validation: 100% citation accuracy, 100% runtime reproduction, whole-tree compile clean, markdown structurally valid (6 well-formed JSON blocks, balanced fences).

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| _None_ — the deliverable is complete, accurate, committed, and the repo is pristine. The only outstanding work is routine human review/sign-off (see §1.6 and §2.2). | None blocking | — | — |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| _N/A_ | _N/A_ | **No access issues identified.** The task is read-only against a local source tree; the build uses the pre-installed Go 1.24.2 toolchain and `go mod verify` reports "all modules verified." No external credentials, registries, or services are required for the deliverable. | Resolved | — |

> Note: the full Go test suite (out of scope) is CI-only — it requires `-tags=sources` and GCP workload-identity that are unavailable locally — but this does not affect the documentation deliverable, which adds no tests.

### 1.6 Recommended Next Steps

1. **[Medium]** Have a TruffleHog-familiar engineer read through all five answer sections and confirm technical accuracy, clarity, and completeness (≈1.0h).
2. **[Medium]** Spot-check ~10–15 of the 102 citations against the pinned commit `e42153d44a5e` to confirm line numbers (≈0.5h).
3. **[Low]** Approve the pull request and merge the document into the destination branch (≈0.5h).
4. **[Low]** (Optional) If the doc will be maintained against future TruffleHog versions, record a regeneration note so line-number citations can be refreshed when the upstream code moves.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---|---|
| Build environment & compile-from-source | 1.5 | Confirm Go 1.24.2 toolchain; `go mod download`/`go mod verify`; `CGO_ENABLED=0 go build ./...` (1005 packages); produce the 194 MB binary [AAP build prerequisite] |
| Runtime observation & evidence capture | 2.0 | Seed a mixed-file-type throwaway repo; run verbose `--log-level=5` git scan, `--json` filesystem scan, `--json` git scan, and `--help`/`--help-long`; capture outputs [AAP §0.5.1 ground truth] |
| Source-code investigation & citation synthesis | 3.5 | Read ~12 authoritative files across 32 `pkg/` sub-packages; reconcile runtime logs with code; attach 102 `[path:locator]` citations [AAP §0.2 scope discovery] |
| §1 Startup & Detector Registration | 1.0 | Compiled-in proof (`buildDetectorList`/`DefaultDetectors`), `--config`-only-for-custom, captured V(4) startup logs, banner caveat [AAP R1 / §0.5.5.1] |
| §2 Verification Setup & Concurrency | 1.5 | go.mod HTTP libs, `detectorWorkerMultiplier=8`, four-pool model, captured worker counts, mermaid diagram, `NumCPU()` analysis [AAP R2 / §0.5.5.2] |
| §3 JSON Output Schema | 1.5 | 15-field anonymous-struct enumeration, no-confidence triangulation, two captured findings (filesystem + git) [AAP R3 / §0.5.5.3] |
| §4 Repository Traversal & File Filtering | 1.0 | `ignoredExtensions` vs `binaryExtensions`, `SkipFile`/`IsBinary`, `HandleBinary`, captured V(5) skip logs, false-positive filtering [AAP R4 / §0.5.5.4] |
| §5 Detector Architecture & CLI Help | 1.0 | `Detector` interface + companions, no-plugin proof, 16 source subcommands, 12 detection flags, `--help-long` excerpt [AAP R5 / §0.5.5.5] |
| Methodology preamble + Pipeline orientation + Summary table | 1.0 | Commit-pin/environment preamble, four-stage pipeline overview, final summary table [AAP §0.5.1 / §0.6.2] |
| Cleanup + repo-pristine verification + commit | 1.0 | Remove temporary artifacts; verify `git status` clean; commit deliverable at correct path/name [AAP §0.7 / §0.8.1] |
| Autonomous validation | 3.0 | 100% citation re-verification, runtime reproduction, whole-tree compile, markdown structural validation, scope/cleanliness check, QA-precision refinement commit [Path-to-production: validation] |
| **Total** | **18.0** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---|---|
| Human SME technical accuracy review of all five answer sections (closes residual accuracy risk R3) | 1.0 | Medium |
| Citation spot-check of ~10–15 of 102 citations against pinned commit `e42153d44a5e` | 0.5 | Medium |
| Pull-request approval & merge into destination branch | 0.5 | Low |
| **Total** | **2.0** | |

> **Cross-section integrity:** §2.1 total (18.0) + §2.2 total (2.0) = 20.0 = Total Hours in §1.2. §2.2 total (2.0) = Remaining Hours in §1.2 = "Remaining Work" in §7 pie chart.

---

## 3. Test Results

For a code-grounded documentation deliverable, the equivalent of "tests" is Blitzy's autonomous validation activity: (a) verifying every code citation against the actual source at the pinned commit, (b) reproducing every claimed runtime observation from a freshly built binary, (c) compiling the whole tree, and (d) validating markdown/JSON structure. **All values below originate from Blitzy's autonomous validation logs for this project.** The deliverable is a Markdown document; it contains **no unit tests**, and the AAP explicitly forbids adding tests or code to the source tree — therefore there are zero failing tests in scope.

| Test Category | Framework / Method | Total Checks | Passed | Failed | Coverage % | Notes |
|---|---|---|---|---|---|---|
| Code Citation Verification | `grep` / manual diff vs source @ `e42153d4` | 102 | 102 | 0 | 100% | Every `[path:locator]` citation across all 5 sections confirmed exact (15 independently re-verified this session) |
| Runtime Reproduction | TruffleHog binary built from source | 6 | 6 | 0 | 100% | Startup logs; four worker-pool counts; binary-skip logs; false-positive skip; filesystem finding (15 keys); git provenance |
| Whole-Tree Compilation | `CGO_ENABLED=0 go build ./...` | 1005 | 1005 | 0 | 100% | 1005 Go packages compiled, exit 0; `go mod verify` = "all modules verified" |
| Markdown Structural Validation | Python JSON parse + fence balance | 6 | 6 | 0 | 100% | 6 embedded JSON blocks well-formed (3 single objects + 3 NDJSON log blocks); 20 code fences balanced |

> **Integrity note (Rule 3):** No tests were authored for this task and none were run outside Blitzy's autonomous validation pipeline. "Coverage %" here denotes the fraction of in-scope claims/citations verified, not source-code line coverage (which is not meaningful for a documentation artifact).

---

## 4. Runtime Validation & UI Verification

**Runtime health** (TruffleHog built and exercised from the pinned source tree):

- ✅ **Build from source** — `CGO_ENABLED=0 go build -o /tmp/trufflehog .` produced a 194,308,498-byte static binary; `--version` → `trufflehog dev`.
- ✅ **Verbose git scan** (`git file:///tmp/testrepo --json --log-level=5 --no-update`) — emitted the engine/aho-corasick startup sequence (V4) and the four worker-pool start lines (V2: scanner=128, detector=1024, verificationOverlap=128, notifier=128).
- ✅ **JSON filesystem scan** (`filesystem .../creds.txt --json`) — produced the 15-field finding reproduced byte-for-byte in the document.
- ✅ **JSON git scan** — produced commit-level `SourceMetadata` provenance (commit/file/email/timestamp/line).
- ✅ **`--help` / `--help-long`** — surfaced 16 source subcommands and 12 detection-relevant global flags.
- ✅ **Binary/skip behavior** — `image.png` triggered `handling binary file` then `file contains ignored extension`; the seeded `example` token triggered `Skipping result: false positive`.
- ✅ **Repository pristine after run** — `git status --porcelain` empty; all temporary artifacts removed.

**UI verification:** ⚠ **Not applicable.** TruffleHog is a CLI tool and the deliverable is a Markdown document; there is no graphical user interface to verify. CLI surface (subcommands/flags) is validated under "Runtime health" above.

---

## 5. Compliance & Quality Review

Cross-mapping of AAP deliverables and rules ("SWE-AtlasQnA-Repo") to outcomes:

| AAP / Rule Requirement | Benchmark | Status | Evidence |
|---|---|---|---|
| Create exactly one named document | `blitzy/documentation/trufflehog_e42153d44a5e.md` | ✅ Pass | File exists (294 lines); `git diff` shows one added file |
| Answer all five question clusters | 5 sections, each Question/Findings/Rationale | ✅ Pass | §1–§5 present with all subsections |
| Code is the source of truth | Inline `[path:locator]` citations | ✅ Pass | 102 citations; 100% verified exact |
| Provide rationale | Explicit reasoning per answer | ✅ Pass | "Rationale" subsection in every section |
| Build and run to analyze | Live runtime evidence | ✅ Pass | Binary built; verbose/JSON/help runs captured |
| Do not modify the source repository | 0 source-file changes | ✅ Pass | `git diff e42153d4 --name-status` = single added file; go.mod/go.sum unchanged |
| Add no other code/tests/config | Only the doc added | ✅ Pass | 0 non-`blitzy/` files changed |
| Clean up temporary artifacts | Repo pristine | ✅ Pass | `git status` clean; binary/test repo/logs removed |
| Pin conclusions to commit `e42153d4` | Version-correct citations | ✅ Pass | Methodology states the commit pin; line numbers valid at commit |
| Destination placement under `blitzy/documentation/` | Correct path | ✅ Pass | Confirmed on disk |

**Fixes applied during autonomous validation:** the QA-precision commit `49c31d54` ("docs: scope plugin textual-occurrence claim to fix QA precision finding") tightened the §5 plugin claim to acknowledge two textual, non-Go occurrences of the string "plugin" while preserving the core conclusion (no Go plugin loading). **Outstanding compliance items:** human SME sign-off (§2.2) — process gate only, no content defect identified.

---

## 6. Risk Assessment

> Context: this is a **read-only documentation task** — the TruffleHog source is byte-for-byte unchanged, `go.mod`/`go.sum` are unchanged, and **no executable artifact ships**. Most traditional software risks are therefore Not Applicable; the residual profile is dominated by low-severity documentation-drift items.

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Citation line-number drift if the doc is read against a non-pinned TruffleHog version | Technical | Low | Medium | Commit pin `e42153d44a5e` stated prominently; line numbers declared valid only at that commit | ✅ Mitigated |
| Environment-specific worker-pool counts (scanner=128 / detector=1024) misread as absolute constants | Technical | Low | Medium | Doc explicitly explains the `runtime.NumCPU()` derivation (`concurrency × 8`) and that values scale with host CPU | ✅ Mitigated |
| Subtle inaccuracy in an answer | Technical / Quality | Low | Low | 100% autonomous citation re-verification + runtime reproduction + independent spot-check; residual closed by human SME review | ⚠ Open (closed by §2.2 review) |
| Embedded example secrets in captured findings (`AKIAI…`, `ghp_example…`) | Security | Low (Informational) | Low | Both are seeded **non-functional** throwaway test values (`Verified:false`; the GH token contains the false-positive term "example") — not live credentials | ✅ Mitigated |
| Vulnerabilities from code/dependency/config changes | Security | N/A | N/A | No source/dependency/config changed; `go mod verify` = "all modules verified"; go.sum unmodified | ✅ Not Applicable |
| Runtime failure / missing monitoring / deployment gaps | Operational | N/A | N/A | Deliverable is a static Markdown file — no service, runtime, health check, or deployment | ✅ Not Applicable |
| Untested external integrations / missing credentials / network config | Integration | N/A | N/A | Read-only task; the deliverable has zero runtime dependencies or external couplings | ✅ Not Applicable |

**Overall residual risk: LOW.** Only the residual-accuracy item is genuinely open, and it is closed by the planned human review.

---

## 7. Visual Project Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextSize':'14px','pieLegendTextSize':'14px'}}}%%
pie showData title Project Hours Breakdown (Total 20.0h)
    "Completed Work" : 18
    "Remaining Work" : 2
```

**Remaining hours by category** (from §2.2; sums to 2.0h = "Remaining Work" above):

| Category | Hours | Priority |
|---|---|---|
| SME technical accuracy review | 1.0 | Medium |
| Citation spot-check | 0.5 | Medium |
| PR approval & merge | 0.5 | Low |

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#B23AF2','pie3':'#A8FDD9'}}}%%
pie showData title Remaining Work by Category (2.0h)
    "SME accuracy review" : 1.0
    "Citation spot-check" : 0.5
    "PR approval & merge" : 0.5
```

> **Integrity (Rule 1):** "Remaining Work" = 2.0h here = §1.2 Remaining Hours = §2.2 "Hours" sum. "Completed Work" = 18.0h = §1.2 Completed Hours = §2.1 "Hours" sum.

---

## 8. Summary & Recommendations

**Achievements.** The project is **90.0% complete** on an AAP-scoped basis (18.0 of 20.0 hours). The single mandated deliverable — a code-grounded onboarding Q&A document answering all five TruffleHog architecture question clusters — is authored, committed, and independently verified accurate. Every conclusion is backed by a source citation and, where useful, by output captured from a binary built from the exact pinned commit. The two headline findings (detectors are **compiled in, not plugins**, and there is **no confidence-score field** anywhere) are triangulated across Go source, protobuf schemas, and live runtime output.

**Remaining gaps.** The remaining 2.0 hours (10.0%) are entirely **human path-to-production gates**: a subject-matter-expert accuracy review, a citation spot-check, and PR approval/merge. There are **no code defects, no failing tests in scope, and no blocking issues** — the AAP explicitly forbids any code/test/config change, so no engineering rework remains.

**Critical path to production.** SME review → citation spot-check → merge. All three are low-effort and non-blocking.

**Production-readiness assessment.** The artifact is **production-ready pending routine human sign-off.** Risk is LOW: the source tree is byte-for-byte unchanged, no executable ships, dependencies are unmodified and verified, and embedded example secrets are non-functional. Recommended success metric: the reviewer confirms the five answers are accurate against the pinned commit and approves the merge.

| Metric | Value |
|---|---|
| AAP-scoped completion | 90.0% |
| Completed / Total hours | 18.0 / 20.0 |
| Remaining hours | 2.0 (human review/merge) |
| Blocking issues | 0 |
| Failing tests in scope | 0 |
| Source files modified | 0 |
| Overall residual risk | Low |

---

## 9. Development Guide

This guide explains how to rebuild TruffleHog and re-derive/verify the document's evidence. **Every command below was tested this session and leaves the repository byte-for-byte pristine.** Run all commands from the repository root unless noted.

### 9.1 System Prerequisites

- **OS:** Linux or macOS (validated on Linux x86-64).
- **Go toolchain:** **1.24.2** (matches `go.mod`: `go 1.23.1` / `toolchain go1.24.2`). Verify:
  ```bash
  go version          # expect: go version go1.24.2 ...
  ```
- **Git:** 2.x (validated with 2.51.0): `git --version`
- **Disk:** ≈2 GB free (the static binary alone is ~194 MB, plus the Go build cache).

### 9.2 Environment Setup

```bash
# From the repository root (destination branch already checked out):
cd /path/to/repo
git status --porcelain    # expect: empty (clean tree)
export CGO_ENABLED=0      # build a static binary
```
No application environment variables are required to build or to run the scans used for the documentation evidence.

### 9.3 Dependency Installation

```bash
go mod download           # download module dependencies (do NOT use 'go mod download all')
go mod verify             # expect: "all modules verified"
```
> ⚠ Use `go mod download`, **never** `go mod download all` — the latter can pollute `go.sum`.

### 9.4 Build

```bash
# Fast sanity check (compiles a single library package; produces no artifact):
CGO_ENABLED=0 go build ./pkg/common/

# Whole-tree compile (validates all 1005 packages):
CGO_ENABLED=0 go build ./...

# Build the CLI binary OUTSIDE the source tree (keeps the repo clean):
CGO_ENABLED=0 go build -o /tmp/trufflehog .
/tmp/trufflehog --version     # expect: trufflehog dev
```

### 9.5 Reproduce the Runtime Observations

```bash
# 1) Seed a throwaway test repo with mixed file types (outside the source tree):
mkdir -p /tmp/testrepo && cd /tmp/testrepo
printf 'AKIAI136580GT7ZIQ2WP\nh8PcopRiorHfddHdLSHVY9QSDZgszKHe5mdlkKx9\n' > creds.txt
echo '# readme' > README.md
echo 'ghp_exampleexampleexampleexampleexample1234' > example-token.txt
printf '\x89PNG\r\n\x1a\n' > image.png        # minimal PNG signature
git init -q && git add -A && git -c user.email=t@t.t -c user.name=t commit -qm seed

# 2) Verbose git scan — startup logs + worker-pool counts + binary skip:
/tmp/trufflehog git file:///tmp/testrepo --json --log-level=5 --no-update

# 3) JSON filesystem scan — the 15-field finding schema:
/tmp/trufflehog filesystem /tmp/testrepo/creds.txt --json --no-update

# 4) CLI capability surface:
/tmp/trufflehog --help
/tmp/trufflehog --help-long
```

### 9.6 Verify the Document

```bash
# Validate every embedded JSON block (single objects + NDJSON log lines):
python3 - <<'PY'
import re, json
s=open("blitzy/documentation/trufflehog_e42153d44a5e.md").read()
for i,b in enumerate(re.findall(r"```json\n(.*?)```", s, re.S),1):
    w=b.strip()
    if w.startswith('"SourceMetadata"') and not w.startswith('{'): w="{"+w+"}"
    try: json.loads(w); print(f"block {i}: object OK")
    except Exception:
        ls=[l for l in w.splitlines() if l.strip()]
        ok=sum(1 for l in ls if (json.loads(l) or True))
        print(f"block {i}: NDJSON {ok}/{len(ls)} OK")
PY

# Spot-check a few citations against the pinned source:
grep -n "func buildDetectorList" pkg/engine/defaults/defaults.go   # expect L839
grep -n "detectorWorkerMultiplier = 8" pkg/engine/engine.go        # expect L345
grep -ci confidence pkg/output/json.go proto/detectors.proto       # expect 0
```

### 9.7 Mandatory Cleanup

```bash
cd /path/to/repo
rm -rf /tmp/trufflehog /tmp/testrepo /tmp/*.log
git status --porcelain        # expect: empty (repo pristine)
```

### 9.8 Troubleshooting

- **Different worker-pool counts than the doc** — expected. Counts derive from `runtime.NumCPU()`; the detector pool is `concurrency × 8`. They scale with the host CPU count.
- **No banner in JSON mode** — expected. The `🐷🔑🐷` banner is gated by `if !*jsonLegacy && !*jsonOut`, so `--json` suppresses it.
- **Scan tries to reach the network** — pass `--no-update` for fully offline runs; verification calls only fire for `--results` that need them and can be disabled with `--no-verification`.
- **Full `go test ./...` fails locally** — expected and out of scope; the suite is CI-only (`-tags=sources` + GCP workload-identity). The documentation task adds no tests.
- **`go.sum` changed after dependency commands** — you likely ran `go mod download all`; revert `go.sum` and use `go mod download` instead.

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---|---|
| `go version` | Confirm Go 1.24.2 toolchain |
| `go mod download` / `go mod verify` | Fetch & verify module dependencies |
| `CGO_ENABLED=0 go build ./...` | Compile all 1005 packages |
| `CGO_ENABLED=0 go build -o /tmp/trufflehog .` | Build the CLI binary (outside the repo) |
| `/tmp/trufflehog git file://… --json --log-level=5 --no-update` | Verbose git scan (startup + worker logs) |
| `/tmp/trufflehog filesystem … --json --no-update` | JSON finding schema |
| `/tmp/trufflehog --help` / `--help-long` | CLI capability surface |
| `git diff e42153d4 --name-status` | Confirm only the doc was added |
| `git status --porcelain` | Confirm pristine tree |

### B. Port Reference

No network ports are required to build the binary or to run the filesystem/git scans used as documentation evidence (`--no-update` keeps runs offline). TruffleHog's verification engine makes outbound HTTPS (443) calls to provider APIs only when live verification is enabled; none of the documentation scans depend on inbound ports.

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (only added file) |
| `pkg/engine/defaults/defaults.go` | Compiled-in detector registration (`buildDetectorList` L839, `DefaultDetectors` L1704) |
| `pkg/engine/engine.go` | Worker pools (`detectorWorkerMultiplier=8` L345; `numWorkers` L676); verification call (L1070) |
| `pkg/detectors/detectors.go` | `Detector` interface (L19) and `Result` struct (L87) |
| `pkg/output/json.go` | JSON finding serializer (`Print` L19) |
| `proto/detectors.proto` / `proto/source_metadata.proto` | `Result` message (L1038) / location metadata |
| `pkg/common/vars.go` | `SkipFile` (L122), `IsBinary` (L129) |
| `pkg/sources/git/git.go` | Git traversal & binary-skip logging |
| `go.mod` | Go versions + HTTP libs (`go-retryablehttp` L63) |
| `main.go` | CLI flags & source subcommands |

### D. Technology Versions

| Component | Version |
|---|---|
| Go (declared / toolchain) | 1.23.1 / 1.24.2 |
| Go (installed & used) | 1.24.2 |
| Git | 2.51.0 |
| TruffleHog module | `github.com/trufflesecurity/trufflehog/v3` |
| TruffleHog binary `--version` | `trufflehog dev` |
| `github.com/hashicorp/go-retryablehttp` | v0.7.7 |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `CGO_ENABLED` | `0` | Produce a static binary; matches the documented build |
| `GOFLAGS` | (unset / default) | No special flags required for the build |

> No application runtime environment variables are needed for the documentation deliverable.

### F. Developer Tools Guide

- **Go toolchain** — build (`go build`), dependency management (`go mod download`/`verify`), compile checks.
- **TruffleHog CLI** — `git`, `filesystem` subcommands with `--json`, `--log-level`, `--no-update`, `--help`/`--help-long` for evidence capture.
- **Git** — scope verification (`git diff`, `git status`, `git log`).
- **Python 3** — quick JSON-block / fence validation of the markdown deliverable.

### G. Glossary

| Term | Meaning |
|---|---|
| AAP | Agent Action Plan — the authoritative project scope |
| Detector | A compiled Go module implementing the `Detector` interface that finds (and optionally verifies) a class of secret |
| Compiled-in | Bound at build time via Go `import` (vs. dynamically loaded plugins) |
| Verification | A live API call confirming whether a detected secret is active |
| NDJSON | Newline-delimited JSON — TruffleHog's `--json` log/finding stream format |
| Path-to-production | Standard activities (here, human review/merge) required to ship the AAP deliverables |
| Pinned commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` — the source state all citations are valid against |