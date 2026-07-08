# Blitzy Project Guide — TruffleHog Onboarding Q&A Documentation

> **Project:** Evidence-grounded onboarding reference for TruffleHog's secret-detection architecture
> **Branch:** `blitzy-14d86ea2-559a-48e3-b47a-6f8b493259fc`  •  **Base:** `trufflehog_e42153d44a5e`  •  **HEAD:** `6e22d61965a1634b162b2c3255fe7cd8dbe1cfa6`
> **Deliverable:** `blitzy/documentation/trufflehog_e42153d44a5e.md`
> **Task type:** Read-only, investigate-by-running documentation (rule set **SWE-AtlasQnA-Repo**)

**Legend / Blitzy Brand Colors:** Completed / AI Work = Dark Blue `#5B39F3` · Remaining / Not Completed = White `#FFFFFF` · Headings / Accents = Violet-Black `#B23AF2` · Highlight = Mint `#A8FDD9`

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a single, evidence-grounded onboarding document that answers five investigative question clusters about TruffleHog's secret-detection architecture. Every answer is derived from actually building the tool from source (Go 1.24.2, `CGO_ENABLED=0 go build`) and observing real runtime behavior — startup and detector registration, network-verification dependencies and concurrency, the JSON finding schema, repository traversal/skip decisions, and the compiled-in detector architecture. The audience is engineers onboarding to TruffleHog who need a factual, reproducible reference. The scope is strictly read-only: the entire TruffleHog source tree is left byte-for-byte unchanged, and the sole written artifact is one markdown document with `file:line` citations and complete unedited command output.

### 1.2 Completion Status

The completion percentage is computed with the PA1 AAP-scoped, hours-based methodology: `Completed Hours / (Completed Hours + Remaining Hours)`.

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextColor':'#B23AF2'}}}%%
pie showData title Completion — 90.6% Complete
    "Completed Work (AI) — #5B39F3" : 29
    "Remaining Work — #FFFFFF" : 3
```

**Center label:** **90.6% Complete**

| Metric | Hours |
|--------|-------|
| **Total Hours** | **32.0** |
| **Completed Hours (AI + Manual)** | **29.0** (AI 29.0 + Manual 0.0) |
| **Remaining Hours** | **3.0** |
| **Percent Complete** | **90.6%** |

> **Calculation:** 29.0 / (29.0 + 3.0) = 29 / 32 = 0.90625 → **90.6% complete**.

### 1.3 Key Accomplishments

- ✅ Built the canonical from-source binary (`CGO_ENABLED=0 go build -o /tmp/trufflehog .`) with the pinned Go 1.24.2 toolchain; reproduced the exact **194,309,218-byte** binary.
- ✅ Answered **Q1 (startup & detector registration):** confirmed detectors are **compiled-in** via `DefaultDetectors()` [pkg/engine/defaults/defaults.go:L1704], captured the `trufflehog dev` banner and worker-pool startup lines.
- ✅ Answered **Q2 (verification deps + concurrency):** identified `go-retryablehttp v0.7.7` [go.mod:L63] and proved **parallel** detector verification (128×8 = **1024** workers, multiplier 8 "bound by net i/o" [pkg/engine/engine.go:L343-345]).
- ✅ Answered **Q3 (JSON schema):** enumerated all **16** finding fields; explicit results — verification status **YES** (`Verified`), confidence score **NO**, location metadata **YES** (`SourceMetadata`).
- ✅ Answered **Q4 (traversal/skip):** proved scan-vs-skip keys off **detected MIME**, not filename (`image.png` skipped; `blob.bin` scanned as `application/octet-stream`); captured the `V(3)` skip log.
- ✅ Answered **Q5 (architecture + help):** confirmed **no plugin loader** exists (statically compiled-in modules); captured `--version` and `--help` output.
- ✅ Ran a full independent final validation: all documented magnitudes reproduced and stable across ≥2 runs; **zero factual errors** found in the deliverable.
- ✅ Preserved the read-only constraint: `git status --porcelain` empty; only the one documentation file added; zero source files changed.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| _None blocking._ Deliverable is authored, committed, and fully validated with zero factual errors. | No release-blocking impact. | — | — |
| Human SME sign-off not yet recorded (acceptance gate) | Non-blocking; required for formal acceptance | Human reviewer (SME) | ~2.0h |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| GCP Secret Manager (maintainer-only) | Cloud credentials | Required by ~34 analyzer + 5 source test packages in the **broader Go source suite** (explicitly **out of scope** for this read-only doc task) | Not required for this deliverable; out of scope | TruffleHog maintainers |
| Upstream APK fixture URL (`TestAPKHandler`) | Third-party network fixture | Dead upstream URL causes a pre-existing, out-of-scope test failure | Not required for this deliverable; out of scope | TruffleHog maintainers |

> No access issues prevent building, running, validating, or delivering this documentation artifact. The items above pertain only to the out-of-scope upstream Go test suite and are recorded for transparency.

### 1.6 Recommended Next Steps

1. **[High]** Human SME technical review of `blitzy/documentation/trufflehog_e42153d44a5e.md` for accuracy, exhaustiveness, and tone (~2.0h).
2. **[Medium]** Final read-only integrity re-check (`git status --porcelain` empty; only the one file added) and PR merge/publish (~1.0h).
3. **[Low]** Assign a documentation owner to refresh `file:line` citations when TruffleHog HEAD advances (tracked as a follow-up; out of the 32h scope).
4. **[Low]** (Optional, upstream) Triage the pre-existing, credential-gated Go source test failures — not caused by, and not in scope for, this task.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All completed components trace to AAP-scoped deliverables (the answer document, the five question clusters, the methodology/evidence rules) and the autonomous validation that produced them.

| Component | Hours | Description |
|-----------|-------|-------------|
| Environment setup & canonical build | 2.0 | Install/verify Go 1.24.2 toolchain; `go mod verify`; `CGO_ENABLED=0 go build` of the canonical binary; capture `--version`/`--help`. |
| Test fixture engineering | 1.5 | Build `/tmp` mixed-file-type target (creds.txt, sub/.env, app.py, blob.bin, real image.png) with planted non-real secrets guaranteeing a finding + a skip. |
| Q1 — Startup & detector registration | 3.0 | Trace CLI/version bootstrap; prove compiled-in `DefaultDetectors()`; capture startup banner + worker-pool lines; `file:line` citations. |
| Q2 — Verification deps + concurrency | 2.5 | Identify `go-retryablehttp`; analyze worker-pool multiplier (8×); prove parallel verification (1024 workers); supporting-dep citations. |
| Q3 — JSON schema + 16-field reconciliation | 3.5 | Run `--json`; capture finding; enumerate all 16 fields against the printer struct + protobufs; answer verification/confidence/metadata explicitly. |
| Q4 — Repository traversal / skip decisions | 4.5 | Scan mixed types at `--log-level=5`; prove MIME-driven scan-vs-skip; capture V(3) skip log; verbosity-threshold proof; handler/vars citations. |
| Q5 — Detector architecture + help output | 3.0 | Prove no plugin loader (grep); confirm statically compiled-in modules; capture `--version`/`--help`; command/flag enumeration. |
| Methodology, evidence & stability | 2.5 | Exact commands, ≥2-run stability, FilterKnownFalsePositives note, CONTRIBUTING V(2)-vs-code V(3) discrepancy, external corroboration. |
| Code-review refinement pass (commit c3a4ae2d) | 2.0 | Address code-review findings; tighten citations and wording. |
| Unedited-output refinement pass (commit 6e22d619) | 1.5 | Replace redacted output with actual unedited output per evidence rules. |
| Final autonomous validation | 3.0 | Independent build/run; reproduce every documented observation; 5 production-readiness gates; read-only integrity confirmation. |
| **Total Completed** | **29.0** | **Sum of all completed AAP-scoped + validation hours (matches Section 1.2).** |

### 2.2 Remaining Work Detail

All remaining work is human-only acceptance work (review + merge). Each item traces to path-to-production acceptance of the AAP deliverable.

| Category | Hours | Priority |
|----------|-------|----------|
| Human SME technical review & acceptance of the deliverable | 2.0 | High |
| Final read-only integrity re-check & PR merge/publish | 1.0 | Medium |
| **Total Remaining** | **3.0** | **(matches Section 1.2 and Section 7)** |

### 2.3 Hours Reconciliation

- **Completed (2.1 total):** 29.0h
- **Remaining (2.2 total):** 3.0h
- **Total Project Hours (1.2):** 29.0 + 3.0 = **32.0h**
- **Percent Complete:** 29.0 / 32.0 = **90.6%**

> Cross-section integrity: 2.1 total (29.0) + 2.2 total (3.0) = 32.0 = Section 1.2 Total. Remaining (3.0) is identical in Sections 1.2, 2.2, and 7.

---

## 3. Test Results

This is a documentation deliverable (markdown) with **no unit tests of its own**. Blitzy's autonomous validation "test" suite for this task is the **reproduction of every documented observation** against a live from-source build and the source tree. All results below originate from Blitzy's autonomous validation logs for this project.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|-----------|-------|
| Build / compilation | `go build` (CGO_ENABLED=0) | 1 | 1 | 0 | n/a | Exit 0; reproduced exact 194,309,218-byte binary. |
| Dependency integrity | `go mod verify` | 1 | 1 | 0 | n/a | "all modules verified". |
| Q1 startup/registration reproduction | Live runtime + source citation | 6 | 6 | 0 | 100% | Banner, 4 worker pools (128/1024/128/128), compiled-in registry, no per-detector log. |
| Q2 verification deps + concurrency reproduction | Live runtime + source citation | 4 | 4 | 0 | 100% | go-retryablehttp dep, timeouts, 8× multiplier, 1024 workers, parallel. |
| Q3 JSON schema reproduction | Live runtime + source citation | 5 | 5 | 0 | 100% | 16-field struct match, live 15-key finding, Verified/confidence/metadata answers, proto citations. |
| Q4 traversal/skip reproduction | Live runtime + source citation | 6 | 6 | 0 | 100% | MIME-driven decisions, V(3) skip log, verbosity threshold, 161-line stderr, handler/vars citations. |
| Q5 architecture + help reproduction | Live runtime + source citation | 4 | 4 | 0 | 100% | No plugin loader (grep exit 1), .so test fixture only, --version/--help content. |
| Methodology & stability reproduction | Live runtime + source citation | 1 | 1 | 0 | 100% | ≥2-run stability of worker counts; CONTRIBUTING V(2)-vs-code V(3) discrepancy confirmed. |
| Read-only integrity | `git status` / `git diff` | 3 | 3 | 0 | n/a | Clean tree; only 1 file added; zero source files changed. |
| Self-gate (TruffleHog on the deliverable) | `trufflehog --results=verified --fail` | 1 | 1 | 0 | n/a | Exit 0; 0 verified secrets in the doc. |
| **Total** | — | **32** | **32** | **0** | **100%** | All autonomous validation checks passed. |

> **Out-of-scope note (transparency):** The broader TruffleHog **Go source test suite** (not part of this task's gate) reports ~898 ok / ~80 fail / ~66 no-test. The ~80 failures are **pre-existing** and **credential/environment-gated** (GCP Secret Manager analyzer + source packages, timing-flaky HTTP-retry test, a dead upstream APK fixture URL). They are **not caused by this task**, do **not** affect the deliverable, and **cannot** be fixed without maintainer credentials and without violating the mandatory read-only scope. Detector integration tests are behind `//go:build detectors` (excluded by default).

---

## 4. Runtime Validation & UI Verification

TruffleHog is a CLI; there is **no UI** in scope. Runtime validation below is derived from live from-source execution captured in Blitzy's autonomous logs.

- ✅ **Operational** — Build: `CGO_ENABLED=0 go build -o /tmp/trufflehog .` → exit 0, 194,309,218-byte binary.
- ✅ **Operational** — Version: `/tmp/trufflehog --version` → `trufflehog dev` (canonical from-source build; `BuildVersion="dev"` [pkg/version/version.go:L3]).
- ✅ **Operational** — Help: `/tmp/trufflehog --help` → shows `--concurrency=128`, `--log-level=0`, `--json`, `--no-verification`, `--results`, and the command list.
- ✅ **Operational** — Startup/worker pools (`filesystem <dir> --json --log-level=2`) → banner `trufflehog dev` + scanner=128, detector=1024, verificationOverlap=128, notifier=128 (stable across ≥2 runs).
- ✅ **Operational** — JSON finding (Q3) → one Github finding emitted; `Verified:false`, `VerificationFromCache:false`, 15 JSON keys (`VerificationError` omitted via `omitempty`).
- ✅ **Operational** — Traversal/skip (Q4, `--no-verification --log-level=5`) → `image.png` skipped (`skipping file: extension is ignored`, `mime:image/png`) at `info-3`; `blob.bin` scanned as `application/octet-stream`; text files scanned. 161 stderr lines.
- ✅ **Operational** — Verbosity threshold → 0 skip lines at `--log-level=2`; 1 skip line at `--log-level=3` (confirms skip log emits at `V(3)`).
- ✅ **Operational** — Concurrency (Q2) → detector workers = NumCPU(128) × 8 = 1024 → parallel verification.
- ✅ **Operational** — Architecture (Q5) → `grep` for `plugin.Open`/`plugin.Lookup`/stdlib `plugin` import returns nothing (exit 1); detectors statically compiled-in.
- ✅ **Operational** — API integration outcomes → live verification uses provider HTTP calls via `go-retryablehttp`; with `--no-verification` no network calls are made (deterministic findings).
- ✅ **Operational** — Read-only integrity → `git status --porcelain` empty; `git diff --name-status e42153d4..HEAD` shows only `A blitzy/documentation/trufflehog_e42153d44a5e.md`.

---

## 5. Compliance & Quality Review

Cross-mapping of AAP deliverables and the **SWE-AtlasQnA-Repo** rule set to Blitzy's quality/compliance benchmarks. All fixes were applied during autonomous authoring/validation.

| AAP / Rule Requirement | Benchmark | Status | Progress | Notes |
|------------------------|-----------|--------|----------|-------|
| Single branch-named deliverable in `blitzy/documentation/` | Deliverable rule | ✅ Pass | 100% | `blitzy/documentation/trufflehog_e42153d44a5e.md` created; parent dirs added. |
| Q1 answered exhaustively (startup/registration) | Coverage | ✅ Pass | 100% | Compiled-in registry + banner + worker pools + negatives. |
| Q2 answered exhaustively (verification deps + concurrency) | Coverage | ✅ Pass | 100% | HTTP dep + 8× multiplier + 1024 parallel workers. |
| Q3 answered exhaustively (JSON schema) | Coverage | ✅ Pass | 100% | 16 fields; explicit Verified=YES / confidence=NO / metadata=YES. |
| Q4 answered exhaustively (traversal/skip) | Coverage | ✅ Pass | 100% | MIME-driven decisions; scan + skip paths both exercised. |
| Q5 answered exhaustively (architecture + help) | Coverage | ✅ Pass | 100% | No plugin loader; compiled-in modules; help/version captured. |
| Build & run BEFORE writing ("run first, then write") | Investigation rule | ✅ Pass | 100% | Binary built/run first; answers written from observation. |
| Default/canonical configuration + exact commands reported | Investigation rule | ✅ Pass | 100% | `CGO_ENABLED=0 go build`; exact invocations recorded. |
| Observe true magnitude; stable across ≥2 runs | Investigation rule | ✅ Pass | 100% | 128/1024/128/128 stable over multiple runs. |
| Actual, unedited output included for each claim | Evidence rule | ✅ Pass | 100% | Commit 6e22d619 replaced redacted with unedited output. |
| Label inferred vs observed; `file:line` for code claims | Evidence rule | ✅ Pass | 100% | Citations exact; inference labeled where applicable. |
| Report discrepancies as observed (not "fixed") | Evidence rule | ✅ Pass | 100% | CONTRIBUTING V(2) vs code V(3) surfaced as observation. |
| Read-only: no source file modified | Scope rule | ✅ Pass | 100% | Zero source files changed; clean tree. |
| No code added beyond the answer document | Scope rule | ✅ Pass | 100% | Only the markdown file committed. |
| Temporary scripts/fixtures removed | Scope rule | ✅ Pass | 100% | All `/tmp` artifacts cleaned; repo byte-for-byte unchanged. |
| Deliverable passes TruffleHog's own verified-secret gate | Security/quality | ✅ Pass | 100% | `--results=verified --fail` → exit 0. |
| Human SME acceptance sign-off | Acceptance gate | ⬜ Pending | 0% | Requires human reviewer (Section 1.6 / 2.2). |

**Fixes applied during autonomous validation:** replaced redacted output with actual unedited output (6e22d619); addressed code-review findings and tightened citations (c3a4ae2d). **Outstanding item:** human SME acceptance sign-off only.

---

## 6. Risk Assessment

Risks assessed across PA3 categories (Technical, Security, Operational, Integration). Given the read-only, documentation-only nature of the task, all risks are **Low** severity.

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|-----------|--------|
| R1 — Documentation drift as TruffleHog HEAD advances (`file:line` may shift) | Technical | Low | Medium | Doc pins base/HEAD commit; frames relationships over absolute line numbers. | Mitigated |
| R2 — Host-dependent magnitudes (128/1024 derived from `NumCPU=128`) | Technical | Low | High | Doc states counts scale from `NumCPU` and gives the formula `NumCPU × 8`. | Mitigated |
| R3 — No automated regression guard for the doc's claims | Technical | Low | Low | Claims are reproducible via the exact commands recorded in the doc. | Accepted |
| R4 — Planted example secrets (non-real `ghp_` token + AWS doc key) | Security | Low | Low | Token is synthetic and verifies false; deliverable passes `--results=verified --fail`. | Mitigated |
| R5 — Introduced attack surface / new CVEs | Security | Low (info) | Low | Read-only task; no dependency changes; `go mod verify` passes. | Closed / N-A |
| R6 — Reproducibility requires pinned Go 1.24.2 | Operational | Low | Low | Doc records the exact toolchain version and all commands. | Mitigated |
| R7 — No maintenance owner for the doc | Operational | Low | Medium | Assign a documentation owner during review (Section 1.6 step 3). | Open (human) |
| R8 — Pre-existing, out-of-scope Go source test failures (~80) | Integration | Low | Medium | Attributed as pre-existing, credential/environment-gated, out of scope; documented transparently. | Documented / Accepted |
| R9 — No build graph / external consumers of the artifact | Integration | Low (info) | Low | Standalone markdown participates in no build graph. | Closed / N-A |

---

## 7. Visual Project Status

### 7.1 Project Hours Breakdown (Completed vs Remaining)

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieSectionTextColor':'#B23AF2'}}}%%
pie showData title Project Hours — 90.6% Complete
    "Completed Work" : 29
    "Remaining Work" : 3
```

- **Completed Work:** 29 h (Dark Blue `#5B39F3`)
- **Remaining Work:** 3 h (White `#FFFFFF`)
- **Total:** 32 h

### 7.2 Remaining Hours by Category (from Section 2.2)

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#A8FDD9','pieStrokeColor':'#B23AF2','pieSectionTextColor':'#B23AF2'}}}%%
pie showData title Remaining Work by Category (3 h total)
    "SME technical review & acceptance [High]" : 2
    "Integrity re-check & PR merge/publish [Medium]" : 1
```

> **Integrity check:** "Remaining Work" (3) in the pie chart equals Remaining Hours in Section 1.2 (3.0) and the sum of the Section 2.2 Hours column (2.0 + 1.0 = 3.0).

---

## 8. Summary & Recommendations

**Achievements.** The project delivers a complete, evidence-grounded onboarding document answering all five question clusters about TruffleHog's secret-detection architecture. Every behavioral claim is backed by unedited captured output and exact `file:line` citations, produced by building the tool from source (Go 1.24.2) and observing real runtime behavior. The deliverable was authored across three agent commits, refined for code-review findings and unedited output, and then independently validated with zero factual errors.

**Remaining gaps.** No engineering gaps remain in the AAP scope. The only outstanding work is **human acceptance**: an SME technical review (2.0h) and a final read-only integrity re-check plus PR merge/publish (1.0h) — totaling the 3.0 remaining hours.

**Critical path to production.** SME review → integrity re-check → merge/publish. There are no compilation, test, or configuration blockers on the critical path for this documentation deliverable.

**Success metrics.** All 32 autonomous validation checks passed (100%); worker-pool magnitudes stable across ≥2 runs; deliverable passes TruffleHog's own verified-secret gate; repository left byte-for-byte unchanged apart from the single committed document.

**Production readiness assessment.** The deliverable is **production-ready at 90.6% complete** (per Section 1.2). The remaining 9.4% represents human acceptance work only (review + merge), not additional engineering. Recommendation: proceed to SME review and merge.

| Metric | Value |
|--------|-------|
| AAP-scoped completion | **90.6%** |
| Total / Completed / Remaining hours | **32.0 / 29.0 / 3.0** |
| Autonomous validation checks | **32 passed / 0 failed** |
| Factual errors found in deliverable | **0** |
| Source files changed (read-only constraint) | **0** |
| Production readiness | **Ready — pending human acceptance** |

---

## 9. Development Guide

This guide reproduces the investigation: build TruffleHog from source, run the observation scans, and verify the read-only constraint. All commands were tested during autonomous validation.

### 9.1 System Prerequisites

- **OS:** Linux (validated on Ubuntu 25.10 container) or macOS.
- **Go toolchain:** **Go 1.24.2** (pinned via `toolchain go1.24.2` in `go.mod:L5`). Building with a different minor version may re-resolve the toolchain.
- **Git** (with the repository checked out at branch `blitzy-14d86ea2-559a-48e3-b47a-6f8b493259fc`).
- **Disk:** ~500 MB free (the static binary is ~194 MB).
- **Network:** required only for live verification runs (omit with `--no-verification` for deterministic, offline findings).

### 9.2 Environment Setup

```bash
# Confirm the Go toolchain version (must be 1.24.x)
go version
# → go version go1.24.2 linux/amd64

# From the repository root, verify module integrity
go mod verify
# → all modules verified
```

### 9.3 Build (Canonical, From Source)

```bash
# Build the canonical binary exactly as a normal user would (static, CGO disabled).
# Build OUTSIDE the repo (/tmp) to preserve the read-only constraint.
CGO_ENABLED=0 go build -o /tmp/trufflehog .
# → exit 0; produces a ~194,309,218-byte binary

# Confirm the from-source version banner
/tmp/trufflehog --version
# → trufflehog dev
```

### 9.4 Create a Throwaway Observation Target (outside the repo)

```bash
mkdir -p /tmp/thog_fixture/sub
# A finding source: a non-real GitHub token (verifies false)
printf 'GITHUB_TOKEN=ghp_C5kCdDZpSBtPxRi9pd2NephKWEHNagqr2hGm\n' > /tmp/thog_fixture/sub/.env
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n'            > /tmp/thog_fixture/creds.txt
printf 'print("hello")\n'                                     > /tmp/thog_fixture/app.py
# A random binary → detected as application/octet-stream (SCANNED)
head -c 4096 /dev/urandom                                     > /tmp/thog_fixture/blob.bin
# A real 1x1 PNG → detected as image/png (SKIPPED)
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82' > /tmp/thog_fixture/image.png
```

### 9.5 Run the Observation Scans

```bash
# Q1 / Q2 / Q3 — startup banner, worker pools, and a JSON finding (verification ON)
/tmp/trufflehog filesystem /tmp/thog_fixture --json --log-level=2
# stderr → "trufflehog dev", then worker pools:
#   starting scanner workers            count:128
#   starting detector workers           count:1024   (= NumCPU 128 x 8)
#   starting verificationOverlap workers count:128
#   starting notifier workers           count:128
# stdout → one JSON finding: DetectorName "Github", "Verified":false, 15 keys

# Q4 — per-file scan-vs-skip decisions (verification OFF, max verbosity)
/tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=5
# stderr includes:
#   info-3 skipping file: extension is ignored  {"path":".../image.png","mime":"image/png","ext":".png"}
#   (blob.bin is NOT skipped → scanned as application/octet-stream)

# Verbosity threshold proof (skip log emits at V(3))
/tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=2 2>&1 | grep -c "skipping file"   # → 0
/tmp/trufflehog filesystem /tmp/thog_fixture --no-verification --log-level=3 2>&1 | grep -c "skipping file"   # → 1

# Q5 — help output and architecture confirmation
/tmp/trufflehog --help
grep -rEn "plugin\.(Open|Lookup)" .    # → no matches (exit 1): no dynamic plugin loader
```

### 9.6 Verification Steps

- **Build success:** `echo $?` is `0` immediately after `go build`; binary size ≈ 194 MB.
- **Version:** `/tmp/trufflehog --version` prints `trufflehog dev`.
- **Worker pools stable:** re-run the `--log-level=2` scan; `detector workers count` remains `NumCPU × 8` (1024 on a 128-CPU host).
- **Skip decision:** the `--log-level=5` run logs `skipping file: extension is ignored` for `image.png` and does **not** skip `blob.bin`.

### 9.7 Read-Only Integrity Check (must remain clean)

```bash
# From the repository root — the tree must be byte-for-byte unchanged apart from the doc
git status --porcelain --untracked-files=all
# → (empty)

git diff --name-status e42153d4..HEAD
# → A  blitzy/documentation/trufflehog_e42153d44a5e.md   (only)

git diff --name-only e42153d4..HEAD -- . ':(exclude)blitzy/**'
# → (empty)  — zero source files changed
```

### 9.8 Cleanup

```bash
rm -rf /tmp/thog_fixture /tmp/trufflehog
```

### 9.9 Troubleshooting

- **`go build` re-downloads a toolchain / version mismatch:** ensure Go 1.24.x is active (`go version`); the module pins `toolchain go1.24.2`.
- **No skip line appears:** you likely ran at `--log-level=2`; the skip log emits at `V(3)` — use `--log-level=3` or higher.
- **`blob.bin` was scanned, not skipped:** expected — skip decisions key off the *detected* MIME (`application/octet-stream`), not the `.bin` filename.
- **`--version` shows `dev`, not a semver:** expected for a from-source build; a real version appears only in release (goreleaser/ldflags) builds.
- **Findings show `"Verified":false`:** expected for planted non-real secrets, or when running with `--no-verification`.
- **Working tree not clean:** ensure build output and fixtures live under `/tmp`, never inside the repository.

---

## 10. Appendices

### Appendix A — Command Reference

| Command | Purpose |
|---------|---------|
| `go version` | Confirm Go 1.24.2 toolchain. |
| `go mod verify` | Verify dependency integrity ("all modules verified"). |
| `CGO_ENABLED=0 go build -o /tmp/trufflehog .` | Canonical from-source build (static binary, outside the repo). |
| `/tmp/trufflehog --version` | Print version banner (`trufflehog dev`). |
| `/tmp/trufflehog --help` | Show flags, commands, and detection-selection options. |
| `/tmp/trufflehog filesystem <dir> --json --log-level=2` | Startup banner, worker pools, JSON findings (Q1/Q2/Q3). |
| `/tmp/trufflehog filesystem <dir> --no-verification --log-level=5` | Per-file scan/skip decisions (Q4). |
| `grep -rEn "plugin\.(Open|Lookup)" .` | Confirm no dynamic plugin loader (Q5). |
| `git status --porcelain --untracked-files=all` | Read-only integrity check (must be empty). |
| `git diff --name-status e42153d4..HEAD` | Confirm only the doc was added. |

### Appendix B — Port Reference

| Port | Service | Notes |
|------|---------|-------|
| `18066` | pprof / debug HTTP server | Optional profiling endpoint exposed by TruffleHog when enabled; not required for scanning. |

> TruffleHog is a stateless batch CLI; it does not open a listening port for normal scans. All findings are emitted to stdout.

### Appendix C — Key File Locations

| Path | Relevance |
|------|-----------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (only file created). |
| `main.go` | CLI entry point, flags, version wiring. |
| `pkg/version/version.go` | `BuildVersion = "dev"` (L3). |
| `pkg/engine/engine.go` | Worker-pool sizing; default-detector application. |
| `pkg/engine/defaults/defaults.go` | `DefaultDetectors()` compiled-in registry (L1704). |
| `pkg/output/json.go` | JSON printer / 16-field finding struct. |
| `proto/detectors.proto` | `Result` message + `DetectorType` enum. |
| `proto/source_metadata.proto` | Location/provenance metadata fields. |
| `pkg/handlers/default.go` | Skip gate + V(3) skip log. |
| `pkg/handlers/handlers.go` | MIME detection; `mimeExt = mime.Extension()`. |
| `pkg/common/vars.go` | `ignoredExtensions` / `binaryExtensions` maps. |
| `go.mod` | Pinned toolchain + dependency versions. |

### Appendix D — Technology Versions

| Component | Version | Source |
|-----------|---------|--------|
| Go toolchain | 1.24.2 | `go.mod:L5` |
| Go language | 1.23.1 | `go.mod:L3` |
| github.com/alecthomas/kingpin/v2 | 2.4.0 | `go.mod:L20` (CLI parsing) |
| github.com/hashicorp/go-retryablehttp | 0.7.7 | `go.mod:L63` (HTTP verification) |
| github.com/gabriel-vasile/mimetype | 1.4.9 | `go.mod:L47` (MIME detection) |
| github.com/BobuSumisu/aho-corasick | 1.0.3 | `go.mod:L17` (keyword prefilter) |
| go.uber.org/zap | 1.27.0 | `go.mod:L106` (logging) |
| google.golang.org/protobuf | 1.36.6 | `go.mod:L114` (Result message) |
| github.com/go-git/go-git/v5 | 5.13.2 | `go.mod:L50` (git traversal) |
| github.com/hashicorp/golang-lru/v2 | 2.0.7 | `go.mod:L64` (verification cache) |
| github.com/adrg/strutil | 0.3.1 | `go.mod:L19` (Levenshtein dedup) |
| go.uber.org/automaxprocs | 1.6.0 | `go.mod:L104` (container-aware concurrency) |

### Appendix E — Environment Variable / Flag Reference

| Flag / Var | Default | Purpose |
|------------|---------|---------|
| `CGO_ENABLED` | `0` (for build) | Static, dependency-free binary. |
| `--concurrency` | `runtime.NumCPU()` | Base concurrency; detector workers = concurrency × 8. |
| `--log-level` | `0` | Verbosity 0–5; skip log requires `≥3`. |
| `--json` | off | Emit findings as JSON. |
| `--no-verification` | off | Skip live provider verification (deterministic, offline). |
| `--results` | (all) | Filter output (e.g., `verified`); `--fail` sets non-zero exit on match. |
| `--only-verified` | hidden | Legacy/hidden alias (`.Hidden()` in `main.go:L60`). |

### Appendix F — Developer Tools Guide

- **Structured logging:** `go.uber.org/zap`; verbosity 0–5 documented in `CONTRIBUTING.md`. Note the documented discrepancy: CONTRIBUTING cites the skip message at `V(2)`, while the code emits it at `V(3)` (`pkg/handlers/default.go:L102`) — reported as an observation, not changed.
- **Canonical recipes:** `Makefile` (`install`, `run`, `run-debug`, `dogfood`) and `Dockerfile` (`CGO_ENABLED=0 go build -o trufflehog .`).
- **Static architecture check:** `grep -rn "plugin.Open\|plugin.Lookup"` returns nothing → detectors are compiled-in, not dynamically loaded plugins.
- **False-positive filtering:** `FilterKnownFalsePositives` (`pkg/engine/engine.go:L1142`).

### Appendix G — Glossary

| Term | Definition |
|------|------------|
| **Detector** | A statically compiled-in Go module implementing a common interface that recognizes and (optionally) verifies a specific secret type. |
| **Verification** | A live provider API call (via `go-retryablehttp`) that confirms whether a candidate secret is active. |
| **Compiled-in registry** | The full detector set returned by `DefaultDetectors()`, embedded in the binary at build time (not loaded from config). |
| **Worker pool** | Concurrent goroutine set; detector pool is sized `NumCPU × 8` ("bound by net i/o"). |
| **MIME-driven skip** | Scan-vs-skip decisions keyed off the *detected* MIME type, not the filename extension. |
| **Finding** | A single detected secret with metadata, serialized as one JSON object (16-field schema). |
| **`dev` version** | The `BuildVersion` default for any from-source (non-release) build. |
| **Read-only task** | Scope in which the source tree must remain byte-for-byte unchanged apart from the one documentation file. |

---

*Generated by the Blitzy Platform. Completion metrics are AAP-scoped per the PA1 hours-based methodology. Colors: Completed `#5B39F3` · Remaining `#FFFFFF`.*