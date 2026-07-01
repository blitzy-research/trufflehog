# Blitzy Project Guide — TruffleHog AWS Detection Q&A Investigation

> Branch: `blitzy-249ade05-6463-409d-8735-0dcc6a48e683` · Base: `e42153d4` · HEAD: `7f839e19`
> Deliverable: `blitzy/documentation/trufflehog_e42153d44a5e.md` · Module: `github.com/trufflesecurity/trufflehog/v3`

---

## 1. Executive Summary

### 1.1 Project Overview

This project is a **read-only question-and-answer investigation** of the TruffleHog v3 codebase. A security team evaluating TruffleHog observed that valid-looking AWS credentials are detected in some files but missed or reported differently in others, and asked for a mechanistic, evidence-backed explanation. The deliverable is a single authoritative markdown document that answers seven sub-questions (detection inconsistency, encoding, unflagged fixtures, "verification disabled" warnings, catch-vs-slip boundaries, real scan output, and entropy thresholds). Each factual claim is grounded in an exact `file:line` citation and each behavioral claim in verbatim output captured from a freshly built binary. Governed by rule **SWE-AtlasQnA-Repo**, the task changes **zero production code** — the only added artifact is the answer document.

### 1.2 Completion Status

```mermaid
%%{init: {"theme": "base", "themeVariables": {"pie1": "#5B39F3", "pie2": "#FFFFFF", "pieStrokeColor": "#B23AF2", "pieOuterStrokeColor": "#B23AF2", "pieSectionTextColor": "#B23AF2", "pieTitleTextSize": "18px", "pieLegendTextColor": "#B23AF2"}}}%%
pie showData
    title Completion Status — 90.9% Complete
    "Completed Work (hrs)" : 20
    "Remaining Work (hrs)" : 2
```

| Metric | Value |
|--------|-------|
| **Total Hours** | 22 |
| **Completed Hours (AI + Manual)** | 20 (AI: 20 · Manual: 0) |
| **Remaining Hours** | 2 |
| **Percent Complete** | **90.9%** |

> Completion is computed on AAP scope only: `Completed / (Completed + Remaining) = 20 / 22 = 90.9%`. All 12 AAP-specified requirements are complete; the 2 remaining hours are human path-to-production (SME review + acceptance/merge). Legend colors: **Completed = Dark Blue `#5B39F3`**, **Remaining = White `#FFFFFF`**.

### 1.3 Key Accomplishments

- ✅ Built the TruffleHog CLI from the branch (`CGO_ENABLED=0 go build`) and ran a **run-first** investigation, capturing real output *before* authoring.
- ✅ Answered all **seven** sub-questions (Q1–Q7), each pairing a source mechanism with verbatim observed CLI output.
- ✅ Every `file:line` citation verified **byte-accurate**; all key literals confirmed (`3.0`, `4.25`, `[a-f0-9]{40}`, `1024`, `512`, the `errOverlap` message).
- ✅ Reproduced all **8 Shannon-entropy values** by compiling and running the repo's actual `detectors.StringShannonEntropy`.
- ✅ Demonstrated the entropy boundary empirically (secret H=4.2342 → 0 findings vs H=4.2939 → 1 finding).
- ✅ Delivered a structurally valid 547-line document (36 balanced code fences, 1 mermaid diagram, 5 tables, UTF-8, LF-only).
- ✅ Upheld the read-only constraint: fixtures lived outside the repo and were deleted; `git status --porcelain` empty; `go.mod`/`go.sum` unchanged and verified.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| None | No blocking issues. The single in-scope deliverable is complete, committed, structurally valid, and validated against source and runtime. | — | — |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| No access issues identified | — | The investigation required only the local repo and Go toolchain (both available). AWS STS verification was intentionally avoided (`--no-verification`); the overlap demo used a local custom detector, so no external credentials were needed. | N/A | — |

### 1.6 Recommended Next Steps

1. **[High]** Have a security SME review the answer document for technical accuracy and confirm all seven sub-questions are answered to the user's satisfaction (~1.5h).
2. **[Medium]** Approve and merge the PR; confirm the repo's secret-scan CI passes on the doc (or allowlist the doc path if a stricter third-party scanner warns) (~0.5h).
3. **[Low, optional]** Add a maintenance note pinning citations to base commit `e42153d4` and prompting re-verification on TruffleHog version bumps (mitigates citation drift).
4. **[Low, optional]** If the organization runs a stricter secret scanner, add the doc path to its allowlist (the AWS-format strings are non-functional examples).

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Build & run-first environment setup | 1.0 | Built the CLI (`CGO_ENABLED=0 go build -o /tmp/trufflehog .`); verified it runs (`trufflehog dev`). Maps to AAP run-first methodology. |
| Source-code analysis & exact citation extraction | 4.0 | Read the cross-cutting detection pipeline across the 11 reference files (engine, decoders, AWS detector, false-positives, entropy, Aho-Corasick, output) to extract exact literals and `file:line` references. |
| Q1–Q7 run-first experimentation | 6.0 | Crafted ~9 fixtures (incl. entropy-boundary calibration straddling 4.25), a custom "shadow" detector config, and ran multi-flag scans; captured verbatim output for every sub-question. |
| Web research & external corroboration | 1.0 | Confirmed the canonical AWS example pair and `AKIA`/`ASIA` prefix format against AWS docs; corroborated the verification-overlap behavior. |
| Answer document authoring | 5.5 | Wrote the 547-line document: pipeline mermaid diagram, TL;DR, seven Q&A sections, consolidated boundaries table, and reproduction appendix, integrating citations with verbatim output. |
| Iterative review & rework (3 commits) | 2.0 | Refined across commits `3e1aeeb4` → `7305f7d8` → `7f839e19` (initial draft, addressing review findings, adding per-section mechanism to Q5/Q6). |
| Cleanup & read-only verification | 0.5 | Removed all temp fixtures/scripts/binary; confirmed `git status --porcelain` empty and `go mod verify` clean. |
| **Total Completed** | **20.0** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human SME technical review & sign-off (verify Q1–Q7 answered; spot-check citations; confirm example strings are non-functional; confirm mermaid renders) | 1.5 | High |
| Final acceptance & merge/close-out (approve PR; confirm secret-scan CI passes; merge to target branch) | 0.5 | Medium |
| **Total Remaining** | **2.0** | |

> Optional risk-mitigation items (citation-drift note, secret-scan allowlist) are **out of AAP scope** and intentionally **excluded** from the 2.0h total to preserve cross-section integrity.

### 2.3 Hours Reconciliation

| Check | Result |
|-------|--------|
| Section 2.1 total (Completed) | 20.0h |
| Section 2.2 total (Remaining) | 2.0h |
| 2.1 + 2.2 = Section 1.2 Total | 20 + 2 = 22h ✓ |
| Completion % = 20 / 22 | 90.9% ✓ |
| Remaining matches Section 1.2, 2.2, and Section 7 | 2.0h in all three ✓ |

---

## 3. Test Results

The deliverable is a Markdown document, so it has no unit-test suite. The applicable validation for a run-first Q&A document is **exactness of citations/literals/entropy** and **verbatim runtime reproduction**. The table below aggregates the checks executed by Blitzy's autonomous validation systems for this project.

| Test Category | Framework / Tool | Total | Passed | Failed | Coverage % | Notes |
|---------------|------------------|-------|--------|--------|-----------|-------|
| Build validation | `go build` (go1.24.2) | 1 | 1 | 0 | 100% | `CGO_ENABLED=0 go build` exit 0; binary reports `trufflehog dev`. |
| CLI runtime reproduction | `trufflehog filesystem` | 15 | 15 | 0 | 100% | Every Q1–Q7 verbatim output block reproduced (proximity close/far/filtered, determinism ×3, BASE64, example default/recovered, overlap ±warning, entropy above/below/filtered, low-ID). |
| Citation accuracy | grep vs on-disk source | 11 | 11 | 0 | 100% | `file:line` citations byte-accurate across all 11 reference files (Blitzy verified all; this assessment independently spot-checked 8). |
| Literal verification | manual vs source | 8 | 8 | 0 | 100% | `3.0`, `4.25`, `[a-f0-9]{40}`, `1024`, `512`, `idPat`, `SecretPat`, `errOverlap` text. |
| Shannon-entropy reproduction | `detectors.StringShannonEntropy` | 8 | 8 | 0 | 100% | All 8 values reproduced by compiling & running the actual repo function. |
| Markdown structural validation | `grep` / `file` / `git diff --check` | 5 | 5 | 0 | 100% | Fence balance (36 blocks), UTF-8, LF-only, no whitespace errors, Q1–Q7 coverage. |
| Repository cleanliness | `git status` / `go mod verify` | 3 | 3 | 0 | 100% | Clean status, single-file diff, `go.mod`/`go.sum` unchanged & verified. |
| **Total** | | **51** | **51** | **0** | **100%** | |

> **Integrity note:** All rows above originate from Blitzy's autonomous validation logs for this project (build, scans, citation/literal/entropy checks, structural checks). Separately, the setup logs reported **41 pre-existing external/environment test failures** in unrelated packages (GCP/GCS credential tests, external 404 fixtures, DB golden-file drift, flaky timing). These are **out of scope** and **not attributable** to this branch, which changes no code.

---

## 4. Runtime Validation & UI Verification

TruffleHog is a **Go command-line tool** — there is no web/GUI surface, so browser-based UI verification is not applicable. Runtime validation focused on the compiled CLI and the observed detection behavior.

**Build & CLI health**
- ✅ **Operational** — `CGO_ENABLED=0 go build -o /tmp/trufflehog .` completes with exit 0.
- ✅ **Operational** — `/tmp/trufflehog --version` reports `trufflehog dev`.

**Detection behavior (reproduced during this assessment)**
- ✅ **Operational** — Detected case: `entropy_above.txt` → `Detector Type: AWS`, `Decoder Type: PLAIN`, `Raw result: AKIAZ24FK7QW8XV5N3PB`, `Line: 2`.
- ✅ **Operational** — Filtered case: `example_fixture.txt` (default) → 0 findings; with `--results=filtered_unverified` → recovers `AKIAIOSFODNN7EXAMPLE`.
- ✅ **Operational** — Encoding: Base64-only fixture surfaces under `Decoder Type: BASE64`.
- ✅ **Operational** — Overlap: 2-detector fixture reproduces the verbatim `Verification issue: … verification has been disabled.You …` warning.
- ✅ **Operational** — Entropy boundary: secret H=4.2342 → 0 findings; H=4.2939 → 1 finding.

**Terminal-UI output strings** — the human-readable strings (`Found unverified result`, `Verification issue`, `Decoder Type`, `Raw result`) render from `pkg/output/plain.go` as documented.

**API / external integrations**
- ⚠ **Partial (by design)** — Live AWS STS verification was **not** exercised; detection was demonstrated with `--no-verification` and overlap via a local custom detector. No claim in the document depends on live credential validation.

---

## 5. Compliance & Quality Review

The governing rule **SWE-AtlasQnA-Repo** defines the quality benchmarks for this Q&A deliverable. All mandates were met.

| Benchmark (rule mandate) | Requirement | Status | Evidence / Progress |
|--------------------------|-------------|--------|---------------------|
| Output location | New doc `<branch>.md` in `blitzy/documentation/` | ✅ Pass | `blitzy/documentation/trufflehog_e42153d44a5e.md` created & committed. |
| Investigate by running first | Build & run before writing; capture real output | ✅ Pass | Binary built; Q1–Q7 output captured from fixtures before authoring. |
| Quote observed output verbatim | Verbatim output; show producing command | ✅ Pass | Each Q section shows verbatim stderr/stdout + the exact command in the appendix. |
| Answer every part | Decompose & answer each sub-question; coverage pass | ✅ Pass | All seven Q1–Q7 sections present + consolidated boundaries table. |
| Be exact & grounded | Exact literals with `file:line`; never paraphrase values | ✅ Pass | Citations byte-accurate; literals `3.0`, `4.25`, `[a-f0-9]{40}`, `1024`, `512`, `AKIAIOSFODNN7EXAMPLE`. |
| Scope (read-only) | No source edits; remove temp scripts | ✅ Pass | `git status` clean; single-file diff; temp artifacts deleted. |
| Repository integrity | `go.mod`/`go.sum`/CI untouched | ✅ Pass | `go mod verify` all modules verified; 0 non-doc files changed. |
| Document structure | Well-formed Markdown | ✅ Pass | 36 balanced code fences, 1 mermaid, 5 tables, UTF-8, LF-only, `git diff --check` clean. |

**Fixes applied during autonomous validation:** None to the deliverable — the document was already accurate on validation; every claim was verified/reproduced. The only correction was to a validator-side throwaway fixture (a missing separator before `AKIA` that broke the `\b` word boundary), which does not affect the committed document.

**Outstanding items:** SME sign-off (Section 1.6, item 1) — a human quality gate, not a defect.

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Citation/line-number drift if upstream source changes | Technical | Low | Medium | Citations pinned to base commit `e42153d4`; re-verify on TruffleHog version bumps | Accepted / Documented |
| No automated regression test for a Markdown deliverable | Technical | Low | Low | Reproduction appendix + validator reproduced all 8 entropy values and all runtime output | Mitigated |
| Doc contains AWS-format example strings (could trip a naive scanner) | Security | Low | Low–Medium | Strings are AWS-published example / low-entropy / synthetic-unverifiable; TruffleHog verified-only self-scan exits 0 | Mitigated |
| No production credentials / live AWS calls involved | Security | Info | — | Detection via `--no-verification`; overlap via local shadow detector | N/A (by design) |
| Repo secret-scan CI could warn on the doc on PR | Operational | Low | Low | TruffleHog verified-only scan passes; allowlist doc path if a stricter scanner warns | Open (confirm on PR) |
| Documentation staleness / no maintenance owner | Operational | Low | Medium | Doc records module/branch context; treat as an as-of-commit artifact | Accepted |
| Mermaid diagram may not render in some viewers | Integration | Low | Low–Medium | GitHub renders mermaid natively; diagram supplements the prose | Mitigated |
| No external service/API integration in scope | Integration | Info | — | Zero runtime dependencies; integrates with nothing | N/A (by design) |

**Overall posture: LOW.** This is a read-only, additive, single-document deliverable with no code, dependencies, or deployment surface. Residual risks are documentation-hygiene items.

---

## 7. Visual Project Status

**Project hours breakdown** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {"theme": "base", "themeVariables": {"pie1": "#5B39F3", "pie2": "#FFFFFF", "pieStrokeColor": "#B23AF2", "pieOuterStrokeColor": "#B23AF2", "pieSectionTextColor": "#B23AF2", "pieTitleTextSize": "16px", "pieLegendTextColor": "#B23AF2"}}}%%
pie showData
    title Project Hours Breakdown
    "Completed Work" : 20
    "Remaining Work" : 2
```

**Remaining hours by category** (from Section 2.2):

```mermaid
%%{init: {"theme": "base", "themeVariables": {"xyChart": {"plotColorPalette": "#5B39F3"}}}}%%
xychart-beta
    title "Remaining Hours by Category"
    x-axis ["SME Review (High)", "Acceptance/Merge (Med)"]
    y-axis "Hours" 0 --> 2
    bar [1.5, 0.5]
```

> **Integrity check:** Pie "Remaining Work" = 2 = Section 1.2 Remaining Hours = sum of Section 2.2 Hours column (1.5 + 0.5). Pie "Completed Work" = 20 = Section 2.1 total. ✓

---

## 8. Summary & Recommendations

**Achievements.** The project delivers exactly what the AAP scoped: one authoritative, run-first answer document that explains — with byte-accurate source citations and verbatim runtime output — why TruffleHog's AWS detection looks inconsistent. All seven sub-questions are answered, the entropy boundary is demonstrated empirically, and the read-only constraint is provably upheld (`git status` clean, single-file diff, `go.mod`/`go.sum` verified unchanged).

**Remaining gaps.** None technical. The **2 remaining hours** are a human quality gate: SME review of the document and PR acceptance/merge. There is no code to deploy, no dependency to configure, and no CI pipeline to build for a Q&A document.

**Critical path to production.** (1) SME reads and signs off on the document → (2) PR approved and secret-scan CI confirmed green on the doc → (3) merge to the target branch. Estimated 2 hours total.

**Production-readiness assessment.** The single in-scope deliverable is **production-ready**: present, committed (`HEAD 7f839e19`), structurally valid, and 100% accurate against both source and freshly captured runtime output.

| Success metric | Target | Actual |
|----------------|--------|--------|
| Sub-questions answered | 7 / 7 | 7 / 7 ✓ |
| Citations byte-accurate | 100% | 100% ✓ |
| Entropy values reproduced | 8 / 8 | 8 / 8 ✓ |
| Production code changed | 0 files | 0 files ✓ |
| Repository clean | `git status` empty | empty ✓ |
| **AAP-scoped completion** | — | **90.9%** |

The project is **90.9% complete**; the remaining 9.1% (2 hours) is entirely human review and merge.

---

## 9. Development Guide

This guide reproduces the investigation environment. **Every command below was tested in the assessment environment.**

### 9.1 System Prerequisites

- **Go** 1.23.1+ (this repo's `toolchain` is `go1.24.2`; verified `go version go1.24.2 linux/amd64`).
- **git** 2.x (verified 2.51.0).
- **OS:** Linux or macOS. **Disk:** ~2 GB free for the build cache and the ~194 MB binary.
- **AWS credentials:** *not required* — detection is demonstrated with `--no-verification`.

### 9.2 Environment Setup

```bash
# From the repository root
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
export GOPATH=$HOME/go

# Confirm the toolchain and entrypoint
go version                 # -> go version go1.24.2 linux/amd64
head -1 go.mod             # -> module github.com/trufflesecurity/trufflehog/v3
```

No `.env` file or background services are required — this is a read-only Q&A investigation.

### 9.3 Build

```bash
# Build OUTSIDE the repo to keep the working tree clean
CGO_ENABLED=0 go build -o /tmp/trufflehog .
/tmp/trufflehog --version           # -> trufflehog dev
```

*Expected:* exit code 0; a ~194 MB binary at `/tmp/trufflehog`. The first build compiles dependencies and may take a minute; later builds are cached.

### 9.4 Run / Reproduce the Findings

```bash
# Create fixtures OUTSIDE the repository (read-only constraint)
mkdir -p /tmp/th_fixtures

# Detected case (secret entropy 4.2939 >= 4.25)
printf '[default]\naws_access_key_id = AKIAZ24FK7QW8XV5N3PB\naws_secret_access_key = P0TTvYvuuQDeV22HVDXu5Xl0YcMZvMxvvpCeCVNQ\n' > /tmp/th_fixtures/entropy_above.txt
/tmp/trufflehog filesystem /tmp/th_fixtures/entropy_above.txt --no-update --no-verification

# Example key: filtered by default, recovered with --results=filtered_unverified
printf '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /tmp/th_fixtures/example_fixture.txt
/tmp/trufflehog filesystem /tmp/th_fixtures/example_fixture.txt --no-update --no-verification
/tmp/trufflehog filesystem /tmp/th_fixtures/example_fixture.txt --no-update --no-verification --results=filtered_unverified
```

*Expected:* `entropy_above.txt` prints `Detector Type: AWS / Raw result: AKIAZ24FK7QW8XV5N3PB`; the example key prints nothing by default and reappears (`AKIAIOSFODNN7EXAMPLE`) under `--results=filtered_unverified`.

### 9.5 Verification Steps

```bash
# The repo must remain unchanged aside from the answer document
git status --porcelain                          # -> (empty)
git diff --name-status e42153d4..HEAD           # -> A blitzy/documentation/trufflehog_e42153d44a5e.md
wc -l blitzy/documentation/trufflehog_e42153d44a5e.md   # -> 547

# Clean up temp artifacts
rm -rf /tmp/th_fixtures /tmp/trufflehog
```

### 9.6 Reading the Deliverable

Open `blitzy/documentation/trufflehog_e42153d44a5e.md` in any mermaid-aware Markdown viewer (e.g., GitHub). It is self-contained: pipeline overview → Q1–Q7 → consolidated boundaries table → reproduction appendix.

### 9.7 Troubleshooting

- **`go: command not found`** → `export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin`.
- **Build is slow the first time** → dependency compilation; the module cache warms subsequent builds.
- **`proximity_close` fixture shows 0 findings** → ensure a separator (space/newline) precedes `AKIA`; concatenating directly to a prefix breaks `idPat`'s `\b` word boundary.
- **Mermaid diagram not rendering** → use a mermaid-aware viewer (GitHub renders it natively); the prose stands alone otherwise.
- **A secret scanner warns on the document** → the AWS-format strings are non-functional examples; TruffleHog's verified-only self-scan (`--results=verified --fail`) exits 0. Allowlist the doc path if a stricter scanner is used.

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `CGO_ENABLED=0 go build -o /tmp/trufflehog .` | Build the CLI (outside the repo) |
| `/tmp/trufflehog --version` | Confirm the build (`trufflehog dev`) |
| `/tmp/trufflehog filesystem <path> --no-update --no-verification` | Scan a file without live verification |
| `… --results=filtered_unverified` | Retain engine-level false positives (e.g., `example` keys) |
| `… --config=<yaml> --allow-verification-overlap` | Custom detector; disable overlap suppression |
| `git status --porcelain` | Confirm the working tree is clean |
| `git diff --name-status e42153d4..HEAD` | Confirm the single-file diff |
| `go mod verify` | Confirm `go.mod`/`go.sum` integrity |

### B. Port Reference

Not applicable — the deliverable is a document and the CLI performs local filesystem scans; **no network ports are opened or required**.

### C. Key File Locations

| Path | Role |
|------|------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (answer document) |
| `main.go` | CLI flag wiring (`--no-verification`, `--results`, `--filter-entropy`, `--allow-verification-overlap`) |
| `pkg/detectors/aws/access_keys/accesskey.go` | AWS detector: keywords, `idPat`, entropy gates, STS verify |
| `pkg/detectors/aws/common.go` | `RequiredIdEntropy=3.0`, `RequiredSecretEntropy=4.25`, `SecretPat` |
| `pkg/detectors/aws/utils.go` | URL-encoding replacer, hex FP pattern `[a-f0-9]{40}` |
| `pkg/detectors/falsepositives.go` | `DefaultFalsePositives`, `IsKnownFalsePositive`, `StringShannonEntropy` |
| `pkg/detectors/multi_part_credential_provider.go` | `defaultMaxCredentialSpan = 1024` |
| `pkg/decoders/decoders.go`, `pkg/decoders/base64.go` | Decoder ordering and Base64 logic |
| `pkg/engine/engine.go` | `errOverlap`, overlap routing, `filterResults`, `retainFalsePositives` |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword prefilter, `defaultOffsetRadius = 512` |
| `pkg/output/plain.go` | Human-readable output strings |

### D. Technology Versions

| Component | Version |
|-----------|---------|
| Go module | `github.com/trufflesecurity/trufflehog/v3` |
| Go language directive | `go 1.23.1` |
| Go toolchain | `go1.24.2` (verified `go1.24.2 linux/amd64`) |
| git | 2.51.0 |
| Binary version string | `trufflehog dev` |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `PATH` | `…:/usr/local/go/bin:$HOME/go/bin` | Locate the Go toolchain |
| `GOPATH` | `$HOME/go` | Go module/build cache location |
| `CGO_ENABLED` | `0` | Static build, matching the repo's Makefile/Dockerfile convention |

*No application secrets or service credentials are required for the investigation.*

### F. Developer Tools Guide

| Flag | Effect |
|------|--------|
| `--no-verification` | Skip live verification (no AWS STS calls) — used for all detection demos |
| `--results=filtered_unverified` | Sets `retainFalsePositives`, surfacing engine-filtered results (recovers `example` keys) |
| `--allow-verification-overlap` | Disables the overlap suppression, removing the "verification disabled" warning |
| `--filter-entropy` | Entropy filter ("Start with 3.0.") |
| `--config=<yaml>` | Load a custom detector (used for the overlap "shadow" demo) |
| `--no-update` | Skip self-update check during scans |

### G. Glossary

| Term | Definition |
|------|------------|
| **Aho-Corasick prefilter** | Keyword-matching stage that routes a chunk to a detector only if a keyword (`AKIA`/`ABIA`/`ACCA`) is present. |
| **Credential span / window** | The byte range around a keyword handed to the detector; AWS uses ±1024 bytes (vs the default ±512). |
| **Shannon entropy** | Per-character information measure (bits) used as an entropy gate; ID ≥ 3.0, secret ≥ 4.25. |
| **Known false positive** | A value dropped by the engine because it contains a default term (e.g., `example`); recoverable with `--results=filtered_unverified`. |
| **errOverlap** | The verification error set when 2+ detectors match the same value; triggers the "verification has been disabled" message. |
| **Detector-internal vs engine-level filter** | Entropy gates drop candidates *before* a result exists (unrecoverable); the false-positive filter runs *after* (recoverable). |
| **Run-first methodology** | Building and running the code to capture real output *before* writing the answer. |

---

*Blitzy Project Guide — Completed work `#5B39F3`, Remaining work `#FFFFFF`. AAP-scoped completion: **90.9%** (20 of 22 hours). Remaining 2 hours are human review and merge.*