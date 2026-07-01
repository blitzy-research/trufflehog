# Blitzy Project Guide — TruffleHog Startup-Behavior Documentation

> Branch: `blitzy-b80da8a6-c640-4d47-b442-c0989d243171` · HEAD `0fe2905e` · Base `e42153d4`
> Deliverable: `blitzy/documentation/trufflehog_e42153d44a5e.md`
>
> **Legend (Blitzy brand colors):** <span style="color:#5B39F3">■ Completed / AI Work — Dark Blue `#5B39F3`</span> · <span style="color:#B23AF2">□ Remaining / Not Completed — White `#FFFFFF`</span> (rendered with a border for visibility)

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a single, run-grounded technical narrative — `blitzy/documentation/trufflehog_e42153d44a5e.md` — that explains how the open-source secret-scanner **TruffleHog** behaves from the instant its Go binary starts through the printing of a scan result. It is written for engineers and maintainers who need to understand runtime behavior (not a file-by-file code tour) and answers four questions: **(a)** configuration handling, **(b)** engine initialization, **(c)** detector preparation, and **(d)** component communication. Every claim is anchored to verbatim captured output or an exact `file:line` reference, produced by actually building and running the tool. The change is isolated, additive, and read-only: exactly one new file, zero source modifications.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#333333'}}}%%
pie showData title Completion Status — 92.2% Complete
    "Completed Work (AI) — 23.5h" : 23.5
    "Remaining Work — 2.0h" : 2.0
```

| Metric | Hours | Notes |
|--------|-------|-------|
| **Total Hours** | **25.5** | AAP-scoped authoring/investigation + path-to-production |
| **Completed Hours (AI + Manual)** | **23.5** | 100% AI (Blitzy agents); 0 manual to date |
| **Remaining Hours** | **2.0** | Human review gate only (no code/deploy work) |
| **Percent Complete** | **92.2%** | 23.5 ÷ 25.5 = 92.2% (AAP-scoped, PA1 methodology) |

> **Calculation:** `Completion % = Completed ÷ (Completed + Remaining) = 23.5 ÷ 25.5 = 92.16% ≈ 92.2%`.

### 1.3 Key Accomplishments

- ✅ **Deliverable authored and committed** — `blitzy/documentation/trufflehog_e42153d44a5e.md` (409 lines, 4,357 words, 28 balanced code fences, 5 tables) created across 3 clean `agent@blitzy.com` commits.
- ✅ **All four sub-questions answered** — dedicated sections for (a) configuration, (b) engine init, (c) detector prep, (d) communication, each with verbatim output + `file:line` citations + explicit reasoning, plus a 19-row coverage-pass table and a closing recap.
- ✅ **Run-first methodology honored** — binary built (`CGO_ENABLED=0 go build`, exit 0) and executed with the repo's own debug convention (`--log-level=2`) and max verbosity (`--log-level=5`); worker counts **128 / 1024 / 128 / 128** and the full ordered lifecycle trace captured verbatim.
- ✅ **Exact grounding** — ~90 `file:line` anchors across 18 reference files; independent spot-check of ~20 anchors found **all exact** (including the maintainer-doc heading `#### Chunk to Detector Matching` and the verbatim `_(Aho-Corsick)_` annotation).
- ✅ **Read-only scope preserved** — `git diff` vs base shows only the one added file (409 insertions, 0 deletions); zero source/test/config/build/CI files touched; working tree clean.
- ✅ **Safety proven empirically** — `--no-verification` dry runs made **zero** outbound verification calls; scanning the deliverable itself yields `verified_secrets: 0` (no live credential present).

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| _None_ | No blocking issues. The module builds clean, runs reproduce exactly, citations are verified, and the repo is pristine. | — | — |

> There are **no critical unresolved issues**. The single outstanding activity is the standard human review/merge gate (Section 1.6, Section 2.2).

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| _None identified_ | — | Build, run, and validation completed fully offline with the bundled Go toolchain; no external credentials or services were required for this read-only documentation task. | N/A | — |

> **No access issues identified.** The pre-existing 41 external-service-dependent test failures in the baseline (GCP/AWS/live DB/HTTP) are environmental and out of scope; they are not access issues introduced by this work and cannot be affected by a markdown-only change.

### 1.6 Recommended Next Steps

1. **[High]** Human SME reads the deliverable and confirms all four sub-questions are answered; spot-checks a sample of the `file:line` citations against source (≈1.5h).
2. **[High]** _(within step 1)_ Optionally re-run the two documented dry-run commands to reconfirm the verbatim output blocks and the `verified_secrets: 0` safety property.
3. **[Medium]** Approve and merge the PR (single additive file, no conflicts expected) into the target branch (≈0.5h).
4. **[Low, optional]** Cross-link the new document from the `docs/` index or README architecture section for discoverability (out of AAP scope — would modify existing files).
5. **[Low, optional]** Add a periodic citation re-verification step to guard against `file:line` drift after future upstream refactors.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Environment setup & binary build | 1.0 | Verify Go `go1.24.2` toolchain; `CGO_ENABLED=0 go build -o trufflehog .` (exit 0); confirm `./trufflehog --version` → `trufflehog dev`. Prerequisite for the run-first methodology. |
| Safe dry-run investigation & capture | 2.5 | Design Run A (`--log-level=2`) and Run B (`--log-level=5`, `--results=…`); craft throwaway inputs; capture verbatim stderr/stdout; grep-based safety evidence (0 outbound calls, `finished scanning chunks`=128). |
| §0 Overview / Environment / Methodology | 2.5 | Environment table; "why these flags" rationale; captured-evidence blocks; the `runtime.NumCPU()=128` vs shell `nproc=4` grounding note. |
| (a) Configuration handling section | 2.5 | kingpin parse (`main.go:301`); `--log-level=2`≡`--debug` mapping (`:304-323`); `info-N` prefix (`log.go:123`); logger (`:336`); `engine.Config` assembly (`:513-533`), incl. `Verify:!*noVerification` (`:520`). |
| (b) Engine initialization section | 3.0 | `NewEngine→setDefaults→initialize→Start→startWorkers` chain; worker-count table (128/1024/128/128 = NumCPU×{1,8,1,1}); channel-buffer table (NumCPU×{50,25,50}); reasoning. |
| (c) Detector preparation section | 2.0 | `DefaultDetectors()` (`defaults.go:1704`); subtractive include/exclude filtering; `Detector` interface (`detectors.go:19-26`); Aho-Corasick core build (`engine.go:529-531`); reasoning. |
| (d) Component communication section | 3.0 | `Source→Unit→Chunk` decomposition (`source_manager.go:402/531/557`, `filesystem.go:179`); buffered-channel worker pipeline ASCII diagram; MIME/handlers; PlainPrinter render (`plain.go:55`); final summary; reasoning. |
| Verbosity map + Coverage table + Closing | 2.0 | `V(n)`→`info-N` mapping table; 19-row coverage-pass table (every observed line → `file:line` → sub-question); per-sub-question closing recap. |
| Citation exactness & grounding pass | 2.0 | Verify ~90 `file:line` anchors and verbatim quotes across 18 reference files; ensure no paraphrased values. |
| Final validation, fixes & commit | 3.0 | Independent build+run reproduction (4 gates); full citation audit; fix 2 heading-citation precision defects; commit `0fe2905e`; leave repo pristine. |
| **Total** | **23.5** | **Matches Completed Hours in Section 1.2** |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human SME documentation review (verify 4 sub-questions answered; spot-check citations & runtime claims; confirm no live secret) | 1.5 | High |
| PR approval & merge into target branch (additive, no conflicts; no deployment) | 0.5 | Medium |
| **Total** | **2.0** | **Matches Remaining Hours in Section 1.2 and Section 7 pie** |

> Optional enhancements (cross-linking from a docs index, a CI markdown link-checker, periodic citation re-verification) are **outside AAP scope** and carry **0 AAP hours** — they are intentionally excluded from this total to preserve cross-section integrity.

### 2.3 Hours Reconciliation

| Check | Result |
|-------|--------|
| Section 2.1 total (Completed) | 23.5h |
| Section 2.2 total (Remaining) | 2.0h |
| 2.1 + 2.2 = Total Project Hours | 23.5 + 2.0 = **25.5h** ✓ (matches Section 1.2) |
| Completion % = 23.5 ÷ 25.5 | **92.2%** ✓ (matches Sections 1.2, 7, 8) |

---

## 3. Test Results

All checks below originate from **Blitzy's autonomous validation logs** for this branch and were **independently reproduced** during this assessment (host `go1.24.2 linux/amd64`). The in-scope deliverable is a markdown document with no unit tests of its own; the applicable checks are compilation, runtime execution, offline unit suites for the referenced packages, structural well-formedness, citation exactness, and a security self-scan.

| Test Category | Framework / Tool | Total | Passed | Failed | Coverage % | Notes |
|---------------|------------------|-------|--------|--------|-----------|-------|
| Compilation | `go build` / `go vet` | 3 | 3 | 0 | n/a | `go build -o trufflehog .` (exit 0); `go build ./...` (exit 0); `go vet` on referenced pkgs (exit 0) |
| Runtime execution | `trufflehog` CLI | 4 | 4 | 0 | n/a | `--version`; Run A (`--log-level=2`); Run B (`--log-level=5`); final confirmation — all exit 0 |
| Unit tests (referenced pkgs, offline) | `go test` | 4 | 4 | 0 | pkg-level | `pkg/config`, `pkg/log`, `pkg/context`, `pkg/engine/ahocorasick` all `ok` (exit 0) |
| Structural well-formedness | Markdown lint (structural) | 2 | 2 | 0 | 100% | 28 balanced code fences; 5 valid tables |
| Citation exactness audit | Source cross-reference | ~90 | ~90 | 0 | 100% | ~90 `file:line` anchors verified exact; 2 heading-citation defects found & fixed |
| Observed-output reproduction | Runtime diff | 8+ | 8+ | 0 | n/a | worker counts 128/1024/128/128; ordered trace; `finished scanning chunks`=128; byte counts; PlainPrinter block — all reproduced |
| Security self-scan | `trufflehog` filesystem | 1 | 1 | 0 | n/a | Scanning the deliverable → `verified_secrets: 0` (no live credential; only intentional fake token flagged unverified) |

**Out-of-scope / environmental (not attributable to this work):** The setup baseline has 41 failing tests that are exclusively external-service-dependent (GCP Secret Manager IAM, AWS, live MySQL/Postgres, a remote APK 404, one timing-sensitive HTTP-retry test). These are pre-existing and environmental; a markdown-only change cannot affect them. **Zero regressions** are attributable to this project.

---

## 4. Runtime Validation & UI Verification

No UI is involved (CLI/documentation task). Runtime health was validated by executing the freshly built binary.

- ✅ **Build** — `CGO_ENABLED=0 go build -o trufflehog .` → exit 0 (static binary ≈186–194 MB). **Operational**
- ✅ **Version** — `./trufflehog --version` → `trufflehog dev`, exit 0. **Operational**
- ✅ **Run A (debug dry-run)** — `filesystem <dir> --no-verification --log-level=2` → exit 0; emits `starting {scanner,detector,verificationOverlap,notifier} workers` with counts **128 / 1024 / 128 / 128** and `finished scanning`. **Operational**
- ✅ **Run B (max verbosity)** — `--log-level=5 --results=verified,unverified,unknown` → exit 0; full ordered trace (`default engine options set` → `engine initialized` → `setting up`/`set up aho-corasick core` → `chunking unit` → `scanning file` → `dataErrChan closed` mime=`text/plain; charset=utf-8` → `link is empty`) and STDOUT `Found unverified result 🐷🔑❓` (Github / PLAIN). **Operational**
- ✅ **Concurrency grounding** — `runtime.NumCPU()` = 128 on host (shell `nproc`=4); `setDefaults` confirms concurrency=NumCPU, detector multiplier=8, others=1 → 128/1024/128/128. **Operational**
- ✅ **Safety (API integration outcome)** — outbound-verification markers (`verifying`/`http request`/`dialing`/`api.github`) count = **0**; no live credential-verification network calls made. **Operational**
- ✅ **Repository state** — `git status --porcelain` empty; only the gitignored `trufflehog` binary untracked. **Operational**

---

## 5. Compliance & Quality Review

Cross-mapping the AAP's binding rules ("SWE-AtlasQnA-Repo" + prompt directives) to observed compliance:

| AAP Requirement / Rule | Benchmark | Status | Evidence |
|------------------------|-----------|--------|----------|
| Deliverable at mandated path/name | `blitzy/documentation/trufflehog_e42153d44a5e.md` | ✅ Pass | File exists (35,525 bytes); `git diff` shows it as the sole addition |
| Investigate by RUNNING code first | Build+run before writing | ✅ Pass | Binary built (exit 0); Runs A & B captured verbatim in §0.3 |
| Quote observed output verbatim | Real logs/values w/ producing command | ✅ Pass | Verbatim stderr/stdout blocks; measured bytes/durations/counts |
| Answer every sub-question | (a)/(b)/(c)/(d) + coverage pass | ✅ Pass | Four dedicated sections + 19-row coverage table + closing recap |
| Be exact & grounded (`file:line`) | No paraphrased values | ✅ Pass | ~90 anchors; ~20 spot-checked all exact (2 defects fixed in `0fe2905e`) |
| Provide reasoning/rationale | "Why" behind each answer | ✅ Pass | Explicit "Reasoning" paragraphs in (b), (c), (d) |
| Read-only scope | No existing file modified; no code added | ✅ Pass | 409 insertions / 0 deletions; 1 file (A); zero source changes |
| No file-by-file summary | Behavioral narrative | ✅ Pass | Structured by runtime behavior, not file enumeration |
| Safe dry run | `--no-verification`, minimal input | ✅ Pass | 0 outbound calls; throwaway `/tmp` inputs; binary gitignored |
| Leave repo pristine | Temp artifacts removed | ✅ Pass | Working tree clean post-validation |
| Toolchain compatibility | `go1.24.2` per `go.mod:5` | ✅ Pass | `go version` = `go1.24.2`; no manifest changes |

**Fixes applied during autonomous validation:** two heading-citation precision defects corrected in commit `0fe2905e` — L284 `"Chunk to Detector Matching (Aho-Corasick)"` → exact heading `"Chunk to Detector Matching"`; L354 hyphenated `"Chunk-to-Detector Matching"` → `"Chunk to Detector Matching"`.

**Outstanding compliance items:** none. All binding rules satisfied.

---

## 6. Risk Assessment

Overall risk posture is **LOW** — a read-only, additive, documentation-only change with zero source impact. No High or Medium severity risks.

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Host-specific worker counts (tied to `runtime.NumCPU()`) may differ on a reader's machine | Technical | Low | Medium | Doc explicitly explains counts scale as `NumCPU × {1,8,1,1}` (§0.1 + (b) reasoning) | Mitigated |
| `file:line` citation drift after future upstream refactors | Technical | Low | Medium | Citations are commit-scoped (base `e42153d4`); coverage-pass table eases re-verification | Accepted |
| Non-deterministic per-run fields (timestamps, worker-ids, durations, extra-data field order) | Technical | Low | High | Doc caveats "timestamps/worker-ids/durations are per-run and will differ" | Mitigated |
| Token-like strings present in the document | Security | Low | Low | AWS key = public documentation example (recognized false positive); `ghp_…` = fake/non-live. Self-scan → `verified_secrets: 0` | Mitigated (verified) |
| Reproduction requires the Go `go1.24.2` toolchain | Operational | Low | Low | Section 9 documents prerequisites and tested build/run commands | Mitigated |
| Pre-existing external-service test failures (41) in baseline | Integration | Low | N/A (pre-existing) | Out of scope; environmental; markdown-only change cannot affect them; zero regressions | Accepted |

---

## 7. Visual Project Status

**Project hours — completed vs remaining** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#333333'}}}%%
pie showData title Project Hours Breakdown
    "Completed Work" : 23.5
    "Remaining Work" : 2.0
```

**Remaining hours by category (Section 2.2):**

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'xyChart': {'plotColorPalette':'#5B39F3'}}}}%%
xychart-beta
    title "Remaining Hours by Category"
    x-axis ["SME Review (High)", "PR Approval & Merge (Medium)"]
    y-axis "Hours" 0 --> 2
    bar [1.5, 0.5]
```

> **Integrity:** "Remaining Work" = **2.0h** here equals Section 1.2 Remaining Hours and the Section 2.2 total. "Completed Work" = **23.5h** equals Section 1.2 Completed Hours and the Section 2.1 total. Completion = 23.5 ÷ 25.5 = **92.2%**.

---

## 8. Summary & Recommendations

**Achievements.** The project is **92.2% complete** (23.5 of 25.5 AAP-scoped hours). The mandated deliverable — a run-grounded behavioral narrative of TruffleHog's startup — is fully authored, committed (`0fe2905e`), and validated. All four sub-questions are answered with verbatim observed output, ~90 exact `file:line` citations, and explicit reasoning. The change is perfectly isolated: one new file, 409 insertions, zero source modifications, clean working tree.

**Remaining gaps.** The only outstanding work is the **human review gate** (2.0h): an SME documentation review (1.5h) and PR approval/merge (0.5h). No engineering, configuration, integration, or deployment work remains — consistent with the AAP's documentation-only scope (no approval/deployment/rollout steps required).

**Critical path to production.** SME review → PR approval → merge. No blockers; no conflicts expected (additive, isolated file).

**Success metrics (all met):** deliverable at mandated path ✓; four sub-questions answered ✓; run-first evidence captured ✓; citations exact ✓; read-only scope preserved ✓; safe dry run (0 outbound calls) ✓; repo pristine ✓.

**Production readiness.** **Ready for human review and merge.** The autonomous validation gates (compilation, runtime, exactness, safety) all pass and were independently reproduced. Completion is held at 92.2% because human sign-off is a genuine, still-pending gate (never reported as 100% pre-review).

| Metric | Value |
|--------|-------|
| AAP-scoped completion | 92.2% |
| Completed / Total hours | 23.5 / 25.5 |
| Remaining hours | 2.0 (human review gate) |
| Files changed | 1 added (409 insertions, 0 deletions) |
| Source files modified | 0 |
| Blocking issues | 0 |
| Risk posture | Low (all categories) |

---

## 9. Development Guide

How to build, run, and reproduce the evidence behind the deliverable. All commands were executed and verified on `go1.24.2 linux/amd64`; the repository is left pristine (the built binary is gitignored at `.gitignore:7`).

### 9.1 System Prerequisites

- **Go toolchain `go1.24.2`** (module declares `go 1.23.1` with `toolchain go1.24.2` at `go.mod:3`/`:5`).
- **git**; ~**2 GB** free disk (static binary ≈186–194 MB).
- Linux or macOS. **No CGO / system libraries** required (`CGO_ENABLED=0`).

### 9.2 Environment Setup

```bash
# Ensure Go is on PATH and correct
export PATH=$PATH:/usr/local/go/bin
go version                     # expect: go version go1.24.2 linux/amd64

# From the repository root:
git rev-parse --abbrev-ref HEAD   # blitzy-b80da8a6-c640-4d47-b442-c0989d243171
```

No environment variables are required for a safe dry run. (Optional: `--config <file.yaml>` contributes additional detectors; filters are subtractive only.)

### 9.3 Dependency Installation

No manual step — `go build` resolves and verifies modules from `go.sum`. Key pins (`go.mod`): `kingpin/v2 v2.4.0`, `go-logr/logr v1.4.2`, `go.uber.org/zap v1.27.0`, `BobuSumisu/aho-corasick v1.0.3`, `automaxprocs v1.6.0`, `gabriel-vasile/mimetype v1.4.9`.

### 9.4 Build

```bash
CGO_ENABLED=0 go build -o trufflehog .   # exit 0; produces ./trufflehog (gitignored)
```

### 9.5 Verification

```bash
./trufflehog --version                   # expect: trufflehog dev
```

### 9.6 Example Usage — the two safe dry runs

```bash
# RUN A — debug logging (repo convention --log-level=2). Safe: --no-verification => 0 outbound calls.
mkdir -p /tmp/th_demo
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n' > /tmp/th_demo/creds.txt
./trufflehog filesystem /tmp/th_demo --no-verification --log-level=2
# Expect (verbatim, minus per-run timestamps/ids):
#   info-2 starting scanner workers             {"count": 128}
#   info-2 starting detector workers            {"count": 1024}
#   info-2 starting verificationOverlap workers {"count": 128}
#   info-2 starting notifier workers            {"count": 128}
#   info-0 finished scanning {"chunks":1,"verified_secrets":0,"unverified_secrets":0,...}

# RUN B — print an unverified finding.
mkdir -p /tmp/th_demo3
printf 'token: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n' > /tmp/th_demo3/secrets.yaml
./trufflehog filesystem /tmp/th_demo3 --no-verification --results=verified,unverified,unknown --log-level=2
# Expect STDOUT:
#   Found unverified result 🐷🔑❓
#   Detector Type: Github
#   Decoder Type: PLAIN
#   Raw result: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
#   File: /tmp/th_demo3/secrets.yaml
#   Line: 1

# Makefile equivalents of the debug convention:
make run-debug     # == CGO_ENABLED=0 go run . git file://. --json --log-level=2  (Makefile:51-52)
make dogfood       # same command                                                 (Makefile:14-15)

# Cleanup (keep the tree pristine)
rm -rf /tmp/th_demo /tmp/th_demo3 ./trufflehog
git status --porcelain    # expect: empty
```

### 9.7 Troubleshooting

- **`go: command not found`** → `export PATH=$PATH:/usr/local/go/bin`; confirm `go version` is `go1.24.2`.
- **Worker counts aren't 128/1024/128/128** → expected. Counts = `runtime.NumCPU() × {1,8,1,1}`; `NumCPU` is host-dependent and may differ from shell `nproc` (cgroup quota vs logical CPUs). The detector-pool ratio (**8×**) always holds.
- **No result printed** → add `--results=verified,unverified,unknown`; under `--no-verification`, findings are reported as *unverified* (verified path `plain.go:52`, unverified `plain.go:55`).
- **`file:line` citations look off** → they are pinned to source at base commit `e42153d4`; on a newer checkout, re-locate via the strings in the deliverable's coverage-pass table.
- **Verify no live secret leaked** → scan the doc itself: `./trufflehog filesystem <dir-with-doc> --no-verification` → `verified_secrets: 0`.

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `CGO_ENABLED=0 go build -o trufflehog .` | Build the static binary (exit 0) |
| `./trufflehog --version` | Print version (`trufflehog dev`) |
| `./trufflehog filesystem <dir> --no-verification --log-level=2` | Safe debug dry-run (Run A) |
| `./trufflehog filesystem <dir> --no-verification --results=verified,unverified,unknown --log-level=5` | Max-verbosity dry-run (Run B) |
| `make run-debug` / `make dogfood` | Repo debug convention (`--log-level=2`) |
| `go test ./pkg/config/... ./pkg/log/... ./pkg/context/... ./pkg/engine/ahocorasick/...` | Offline unit suites for referenced pkgs (all `ok`) |
| `git diff --stat e42153d4 HEAD` | Confirm sole added file |
| `git status --porcelain` | Confirm clean tree |

### B. Port Reference

Not applicable — the tool is a CLI scanner; the documented `filesystem` dry runs open **no network ports** and make **no outbound calls** (`--no-verification`).

### C. Key File Locations

| Path | Role |
|------|------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (sole committed change) |
| `main.go` | CLI parse, verbosity mapping, logger, `engine.Config` assembly, scan dispatch |
| `pkg/engine/engine.go` | Engine construction, worker-pool sizing, channel allocation, Aho-Corasick build |
| `pkg/engine/defaults/defaults.go` | `DefaultDetectors()` (`:1704`) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `NewAhoCorasickCore` keyword prefilter |
| `pkg/config/config.go`, `pkg/config/detectors.go` | Optional YAML config; subtractive detector filtering |
| `pkg/detectors/detectors.go` | `Detector` interface (`:19-26`) |
| `pkg/sources/source_manager.go`, `pkg/sources/filesystem/filesystem.go` | Source→Unit→Chunk decomposition; per-file scanning |
| `pkg/handlers/handlers.go`, `pkg/output/plain.go` | MIME/chunk handling; `PlainPrinter` result rendering |
| `pkg/log/log.go`, `pkg/context/context.go` | `zap`+`logr` logger; context logger with `V(n)` verbosity |
| `docs/process_flow.md`, `docs/concurrency.md` | Maintainer architecture references |

### D. Technology Versions

| Component | Version | Source |
|-----------|---------|--------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | `go.mod:1` |
| Go directive / toolchain | `go 1.23.1` / `go1.24.2` | `go.mod:3` / `go.mod:5` |
| kingpin/v2 | 2.4.0 | `go.mod` |
| go-logr/logr | 1.4.2 | `go.mod` |
| go.uber.org/zap | 1.27.0 | `go.mod` |
| BobuSumisu/aho-corasick | 1.0.3 | `go.mod` |
| go.uber.org/automaxprocs | 1.6.0 | `go.mod` |
| gabriel-vasile/mimetype | 1.4.9 | `go.mod` |
| Build version string | `dev` | surfaces as `trufflehog dev` |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `CGO_ENABLED` | `0` | Static build, no C toolchain needed |
| `PATH` | include `/usr/local/go/bin` | Locate the `go` binary |

> No runtime application environment variables are required for the documented safe dry runs.

### F. Developer Tools Guide

| Tool | Use |
|------|-----|
| `--log-level=N` | Verbosity 0 (info) → 5 (trace); the `info-N` prefix encodes the emitting `V(n)` level (`pkg/log/log.go:123`) |
| `--no-verification` | Disable live credential verification (sets `Verify=false`, `main.go:520`) — makes any scan a safe dry run |
| `--results=verified,unverified,unknown` | Select which result classes are printed |
| `--config <file.yaml>` | Contribute additional detectors (subtractive filters only) |
| `go vet` | Static analysis on referenced packages (exit 0) |

### G. Glossary

| Term | Meaning |
|------|---------|
| **Chunk** | A bounded slice of source bytes handed to the scanner/detector pipeline |
| **Unit** | A discrete enumerable item within a source (e.g., a single file) before chunking |
| **Detector** | A component implementing `FromData`/`Keywords`/`Type` that extracts (and optionally verifies) a credential |
| **Aho-Corasick core** | A keyword→detector prefilter automaton built from all detectors' `Keywords()` to route chunks efficiently |
| **Verification** | The optional live check of a found credential; disabled by `--no-verification` (yielding *unverified* results) |
| **`info-N` prefix** | Log prefix encoding the `logr` `V(n)` verbosity level (negated zap level) |
| **Worker pool** | A group of goroutines (scanner/detector/verificationOverlap/notifier) sized as `concurrency × multiplier` |