# Blitzy Project Guide — TruffleHog v3 Scanning-Behavior Investigation

> **Deliverable:** `blitzy/documentation/trufflehog_e42153d44a5e.md`
> **Task type:** Read-only, runtime-grounded Q&A investigation + documentation
> **Branch:** `blitzy-566a1b7b-5661-433b-95ce-e29f8b189ba4`
> **Base → HEAD:** `e42153d44a5e` → `d48b33dc`

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a single, evidence-backed investigation document that explains four confusing, deterministic behaviors observed while evaluating TruffleHog v3 (a Go secret scanner) against purpose-built inputs. It is a strictly read-only documentation task: no scanner source file is modified. The audience is security engineers and developers who need to understand *why* the scanner detects credentials in some files but misses or reports them differently in others, whether encoding fools it, why test-fixture keys are never flagged, and what "verification disabled for safety" means. The document grounds every claim in actual runtime output plus exact `file:line` citations at commit `e42153d44a5e`, distinguishing observed from inferred results.

### 1.2 Completion Status

The project is **96.2% complete**. Completion is measured strictly against Agent Action Plan (AAP) scope plus path-to-production activities, using an hours-based methodology: **51.0** AI-completed hours out of **53.0** total hours (51.0 ÷ 53.0 = 96.2%). The remaining **2.0** hours are exclusively human path-to-production actions (stakeholder review and PR merge); no autonomous AAP-scoped work remains.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieTitleTextColor':'#B23AF2','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#000000'}}}%%
pie showData title Completion Status — 96.2% Complete
    "Completed Work (AI)" : 51
    "Remaining Work" : 2
```

| Metric | Hours |
|---|---|
| **Total Hours** | **53.0** |
| Completed Hours (AI + Manual) | 51.0 (AI: 51.0 · Manual: 0.0) |
| **Remaining Hours** | **2.0** |
| **Percent Complete** | **96.2%** |

> Color key — **Completed / AI Work = Dark Blue `#5B39F3`**; **Remaining / Not Completed = White `#FFFFFF`**.

### 1.3 Key Accomplishments

- ✅ Scanner built from source in default configuration: `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` → exit 0, reproducible **194,310,114-byte** static ELF; `--version` → `trufflehog dev` (expected source-build artifact).
- ✅ **Q1** answered with 8 boundary scenarios (A–H): keyword pre-filter, 40-vs-39-char `SecretPat`, 1024-byte credential span (within / beyond / `--scan-entire-chunk`), entropy floors, canary tokens, `ASIA` session keys.
- ✅ **Q2** answered with 10 scenarios (A–J): base64 defeated vs. evasion cases (short ≤20, non-ASCII, hex, gzip), decoder chaining, URL-encoding, and version divergence flagged.
- ✅ **Q3** answered with 2 scenarios (A–B): `AKIAIOSFODNN7EXAMPLE` suppressed by default, revealed via `--results=filtered_unverified`; pure-hex secret rejected pre-result.
- ✅ **Q4** answered with 3 scenarios (A–C): multi-detector overlap disables verification with the exact `errOverlap` warning; `--allow-verification-overlap` override demonstrated.
- ✅ **1,045-line** deliverable authored with 248 `file:line` citations, complete unedited command output per claim, clean observed(48)/inferred(39) labeling, 0 placeholders/TODO.
- ✅ Read-only mandate honored: `git diff` shows exactly one added file; source tree byte-for-byte pristine; all temporary artifacts cleaned.
- ✅ Five autonomous validation gates PASSED (build, doc-accuracy across 23 scenarios, citations, unit tests, coverage/integrity).

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| _None._ All AAP-scoped deliverables are complete and validated; zero fixes were required during final validation. | No release-blocking items | — | — |

### 1.5 Access Issues

| System / Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| Private GCP workload-identity | CI/build credential | The full `go test ./...` cannot complete locally because some analyzer/integration packages require private GCP workload-identity auth that is unavailable in this environment. **Out of AAP scope** for a read-only documentation task and unrelated to the documented behavior — all doc-relevant unit-test packages pass. | Accepted / Out of scope (0h) | Human reviewer (awareness only) |
| Go toolchain PATH | Local shell env | `go` is not on the default `PATH`; requires `export PATH=$PATH:/usr/local/go/bin` per shell. | Mitigated (documented in §9) | Developer |

### 1.6 Recommended Next Steps

1. **[High]** Human SME/stakeholder technical review and sign-off of `blitzy/documentation/trufflehog_e42153d44a5e.md` — verify accuracy, completeness, and clarity; optionally re-run a subset of the 23 reproductions.
2. **[Medium]** Approve and merge the PR (single additive Markdown file) to mainline.
3. **[Low]** Acknowledge the full-`go test` access issue (§1.5) as out-of-scope for this task; no action required.
4. **[Low]** Optionally remove the retained reference binary with `rm -f /tmp/trufflehog_bin`.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---:|---|
| Build foundation & environment setup | 1.5 | Compile scanner from source; verify `--version`, `filesystem --help`, `go mod verify` (AAP §0.5.1). |
| Q1 investigation (8 scenarios A–H) | 8.0 | Baseline detect, 3-run determinism, keyword pre-filter, 40-vs-39-char `SecretPat`, 1024-byte span ×3, entropy floors, canary, `ASIA` — mapped to chunker/ahocorasickcore/accesskey/canary/sessionkey/common. |
| Q2 investigation (10 scenarios A–J) | 8.0 | Plaintext, base64 defeat, broken base64, short ≤20, non-ASCII, hex, gzip, version divergence, decoder chaining, URL-encoding — mapped to decoders.go/base64.go/engine.go. |
| Q3 investigation (2 scenarios A–B) | 3.0 | `AKIAIOSFODNN7EXAMPLE` suppress/reveal; pure-hex rejection — mapped to falsepositives.go/aws/utils.go. |
| Q4 investigation (3 scenarios A–C) | 3.5 | Overlap disables verification; `--allow-verification-overlap` override; byte-check of warning text — mapped to engine.go `errOverlap`. |
| Deliverable authoring (1,045-line Markdown) | 10.0 | Per-question cause→effect explanations, complete unedited output + producing command, boundary demonstrations. |
| Coverage-pass matrix (Section 6 of doc) | 3.0 | Exhaustive matrix grounding ~100 named mechanisms/functions/flags/files to path:line. |
| Citation grounding & observed/inferred discipline | 3.0 | 248 `file:line` citations; 48 observed / 39 inferred labels. |
| QA remediation (3 iterative fix commits) | 4.0 | Citation precision, Section 7 governance reproducibility, F-DOC-1..5. |
| Final validation — 5 gates *(path-to-production)* | 6.0 | Build; 23-scenario doc-accuracy; 100+ citation checks; unit tests; coverage/integrity. |
| Cleanup & repository governance *(path-to-production)* | 1.0 | Pristine-tree confirmation; LF / `.gitattributes` / UTF-8 compliance; `/tmp` artifact removal. |
| **Total Completed** | **51.0** | Matches Completed Hours in §1.2. |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---:|---|
| Human SME/stakeholder review & sign-off of the deliverable | 1.5 | High |
| PR approval + merge to mainline | 0.5 | Medium |
| **Total Remaining** | **2.0** | — |

> Validation: Total of the Hours column (**2.0**) equals Remaining Hours in §1.2 and the "Remaining Work" value in §7. Access-issue for full `go test` is tracked at **0h** (out of scope) and is intentionally excluded.

### 2.3 Basis of Estimate & Confidence

- **Methodology:** PA1 (AAP-scoped) + PA2 (engineering-hours). Completion % = Completed ÷ (Completed + Remaining) = 51.0 ÷ 53.0 = **96.2%**.
- **Confidence:** *High* for completed work (all items independently corroborated: build reproduced, two scenarios re-run byte-for-byte, 6/6 citation spot-checks accurate). *High* for remaining work (both items are standard, well-scoped human actions).
- **Cap compliance:** 96.2% respects the "never claim 100% before human review" rule (max 99%).

---

## 3. Test Results

All entries below originate from Blitzy's autonomous validation logs for this project (independently corroborated firsthand this session). For a runtime-grounded documentation task, the "test suite" is the set of reproduction scenarios plus the project's own doc-relevant unit tests.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---|---|
| Runtime reproduction scenarios | `trufflehog filesystem` CLI (canonical) | 23 | 23 | 0 | Q1–Q4 boundaries | Q1 A–H (8), Q2 A–J (10), Q3 A–B (2), Q4 A–C (3); all reproduce documented stable output (only ephemeral timestamp/worker_id/scan_duration differ). |
| Determinism checks | Repeated identical runs | 3 | 3 | 0 | n/a | Q1-B byte-identical across 3 runs; I re-confirmed 2-run identity. |
| Doc-relevant unit tests | `go test` (CGO_ENABLED=0) | 8 pkgs | 8 | 0 | project-owned | `pkg/decoders`, `pkg/engine/ahocorasick`, `pkg/sources`, `pkg/detectors` (falsepositives/entropy), `aws/access_keys`, `aws/session_keys`, `shodankey`, `tomorrowio` — all `ok`. |
| Citation verification | Manual + automated in-range check | 248 | 248 | 0 | 100% | 0 missing files, 0 out-of-range; 6/6 core citations spot-checked accurate at `e42153d44a5e`. |
| Build verification | `go build` | 1 | 1 | 0 | n/a | Exit 0; reproducible 194,310,114-byte static ELF. |
| Inferred-value cross-checks | Source-formula verification | 5 | 5 | 0 | n/a | Shannon entropies (4.022/5.172/0.569/1.000/3.971) straddle floors 3.0/4.25; UTF-16 lengths verified. |

> **Integrity note (Rule 3):** every test above comes from Blitzy's autonomous execution/validation of this project. The full `go test ./...` was *not* run to completion because some analyzer/integration packages require private GCP auth (see §1.5) — this is out of scope for a read-only documentation task and unrelated to the documented behavior.

---

## 4. Runtime Validation & UI Verification

This deliverable is a Markdown document and the system under investigation is a **command-line scanner** — there is no graphical or web UI. Runtime validation therefore covers the scanner's CLI behavior that the document depends on.

- ✅ **Operational** — Build & binary: `go build` exit 0; static ELF, size stable at 194,310,114 bytes across clean rebuilds.
- ✅ **Operational** — Canonical entry point: `trufflehog filesystem [<flags>] [<path>...] — Find credentials in a filesystem.`
- ✅ **Operational** — Q1 baseline detect: fixture 106 bytes → `Detector Type: AWS`, `Decoder Type: PLAIN`, `Raw result: AKIAZ3JQK7X1YWVUT5RQ`, `Resource_type: Access key`, `Line: 1`; `chunks:1 bytes:106 unverified_secrets:1`.
- ✅ **Operational** — Q3 suppress/reveal: default `unverified_secrets: 0` (suppressed) → `--results=filtered_unverified` → `unverified_secrets: 1` (revealed).
- ✅ **Operational** — Determinism: repeated identical inputs yield byte-identical stable output (ephemeral fields excepted).
- ✅ **Operational** — Dependency integrity: `go mod verify` → `all modules verified`.
- ⚠ **Partial (by design)** — Live verification path: exercised via `--no-verification` for deterministic offline runs; live network verification of candidates is intentionally not invoked.
- ➖ **Not applicable** — Web/graphical UI: none exists for this CLI tool.

---

## 5. Compliance & Quality Review

Cross-mapping AAP deliverables and governing-rule directives to Blitzy quality benchmarks. Fixes applied during autonomous validation are noted; there are no outstanding items.

| Benchmark / AAP Directive | Status | Progress | Evidence / Notes |
|---|---|---|---|
| Read-only: zero source modifications | ✅ Pass | 100% | `git diff e42153d4..HEAD --name-status` = one added file only. |
| Deliverable naming & location | ✅ Pass | 100% | `blitzy/documentation/trufflehog_e42153d44a5e.md` (= source branch name). |
| Runtime-grounded (build & run before writing) | ✅ Pass | 100% | Built from source; 23 scenarios executed via canonical entry point. |
| Complete, unedited output + producing command | ✅ Pass | 100% | 114 balanced code fences; 0 elision markers (`// ...`). |
| Observed vs. inferred distinction | ✅ Pass | 100% | 48 observed / 39 inferred labels. |
| Exact `file:line` grounding | ✅ Pass | 100% | 248 citations; 0 missing, 0 out-of-range; 6/6 spot-checks accurate. |
| Coverage pass (every named item) | ✅ Pass | 100% | §6 exhaustive matrix over ~100 mechanisms/flags/files/examples. |
| Boundary / edge demonstrations | ✅ Pass | 100% | 40-vs-39 char, span within/beyond/scan-entire-chunk, evasions, hex rejection, overlap. |
| Determinism confirmed ≥2 runs | ✅ Pass | 100% | Q1-B byte-identical across 3 runs. |
| Version divergence flagged | ✅ Pass | 100% | No HTML decoder / no `--max-decode-depth` at this commit — explicitly noted (Q2). |
| Zero placeholders / TODO / FIXME | ✅ Pass | 100% | 0 occurrences. |
| Encoding & line endings | ✅ Pass | 100% | Pure LF, UTF-8, `.gitattributes`-compliant. |
| Cleanup of temporary artifacts | ✅ Pass | 100% | `/tmp` fixtures/scripts removed; repo pristine. |
| QA remediation resolved | ✅ Pass | 100% | 3 QA-fix commits (citation precision, §7 governance, F-DOC-1..5). |

---

## 6. Risk Assessment

All risks are **Low** severity, consistent with a read-only, fully-validated documentation task against a pristine source tree.

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Version divergence: doc describes commit `e42153d44a5e` (4 decoders, single-pass, no `--max-decode-depth`); newer releases add HTML decoder + iterative decoding. | Technical | Low | Medium | Divergence explicitly flagged in Q2; commit hash pinned throughout. | Mitigated / Documented |
| Ephemeral output fields (timestamp, worker_id, scan_duration, BuildID) differ per run; naive full-output diff may look like a mismatch. | Technical | Low | Low | Methodology transcription note enumerates ephemeral fields; compare stable fields only. | Mitigated |
| `ExtraData` map-order nondeterminism (Q1 canary) — Go map iteration order varies. | Technical | Low | Low | Honestly documented as nondeterministic; does not affect detection outcome. | Documented |
| Synthetic/example AWS keys embedded in the doc (`AKIAZ3…`, `AKIAIOSFODNN7EXAMPLE`). | Security | Low | Low | All keys synthetic/canonical-example and unverified (non-live); pre-commit TruffleHog hook would not trip. | Mitigated |
| Secret leakage into source tree. | Security | Low | Low | `git diff` = one Markdown file; no credentials added to source. | Clear |
| Build reproducibility depends on `go1.24.2` + warm module cache (cold build needs network). | Operational | Low | Low | `go.mod`/`go.sum` pin toolchain & deps; §9 documents the build. | Mitigated |
| `go` not on default `PATH` in fresh shells. | Operational | Low | Medium | §9 documents `export PATH=$PATH:/usr/local/go/bin`. | Mitigated |
| Full `go test ./...` blocked by private GCP workload-identity auth (analyzer/integration pkgs). | Integration | Low | n/a | Doc-relevant unit tests pass; unrelated to documented behavior; out of scope. | Accepted (out of scope) |
| Default verification path makes live network calls when `--no-verification` is omitted. | Integration | Low | Low | Doc uses `--no-verification` for deterministic offline runs; noted in §9. | Mitigated |

---

## 7. Visual Project Status

**Project hours breakdown** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`). "Remaining Work" = **2.0h**, identical to §1.2 and the §2.2 total.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieTitleTextColor':'#B23AF2','pieSectionTextColor':'#B23AF2','pieLegendTextColor':'#000000'}}}%%
pie showData title Project Hours Breakdown
    "Completed Work" : 51
    "Remaining Work" : 2
```

**Remaining work by priority** (High = Dark Blue `#5B39F3`, Medium = Mint `#A8FDD9`) — sums to 2.0h.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#A8FDD9','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieStrokeWidth':'2px'}}}%%
pie showData title Remaining Work by Priority (hours)
    "High — SME Review" : 1.5
    "Medium — PR Merge" : 0.5
```

**Completed effort by area** (all Dark Blue `#5B39F3` category — informational distribution of the 51.0 completed hours):

| Area | Hours |
|---|---:|
| Investigation (Q1–Q4) | 22.5 |
| Authoring + coverage + citations | 16.0 |
| QA remediation | 4.0 |
| Validation + build + cleanup | 8.5 |
| **Total** | **51.0** |

---

## 8. Summary & Recommendations

**Achievements.** The project delivered a comprehensive, runtime-grounded answer to all four TruffleHog v3 questions in a single 1,045-line document, with 248 `file:line` citations, complete unedited command output for every claim, explicit observed-vs-inferred labeling, and an exhaustive coverage pass. The scanner was built from source and every documented scenario reproduces its stated output. The read-only mandate was fully honored: the source tree is byte-for-byte pristine and exactly one file was added.

**Remaining gaps.** Only human path-to-production actions remain: SME review (1.5h) and PR merge (0.5h) — **2.0h** total. No autonomous, AAP-scoped work is outstanding.

**Critical path to production.** SME review → PR approval → merge. Because the change is a single additive Markdown file with no source impact, integration risk is minimal.

**Success metrics.** All five autonomous validation gates passed; 23/23 reproduction scenarios succeed; 248/248 citations in range; 8/8 doc-relevant unit-test packages `ok`; 0 placeholders/TODO.

**Production readiness.** The deliverable is **production-ready at 96.2% completion** (51.0h of 53.0h). The document is accurate, complete, and self-consistent; the only path-to-production steps are human review and merge. Recommendation: **proceed to SME review and merge.**

---

## 9. Development Guide

Every command below was executed firsthand and produced the documented output.

### 9.1 System Prerequisites

- **OS:** Linux x86-64 (validated on Ubuntu 25.10 container).
- **Go:** 1.24.2 (installed at `/usr/local/go`); `go.mod` declares `go 1.23.1` floor / `toolchain go1.24.2`.
- **Git:** any recent version (repository already checked out at branch `blitzy-566a1b7b-5661-433b-95ce-e29f8b189ba4`).
- **Disk:** ~500 MB (module cache + ~194 MB binary).
- **Network:** required only for a *cold* module cache on first build; not required to read the deliverable.

### 9.2 Environment Setup

```bash
# CRITICAL: `go` is not on the default PATH — set it in every fresh shell.
export PATH=$PATH:/usr/local/go/bin

# Verify the toolchain
go version              # => go version go1.24.2 linux/amd64
go env GOTOOLCHAIN      # => local

# Move to the repository root
cd /tmp/blitzy/trufflehog/blitzy-566a1b7b-5661-433b-95ce-e29f8b189ba4_17abfd
```

### 9.3 Dependency Installation

No dependency changes are introduced by this task. Verify the existing module graph is intact:

```bash
go mod verify          # => all modules verified
```

### 9.4 Build (Application Startup)

```bash
# Build the canonical scanner binary from the repository root
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .
echo "exit=$?"         # => exit=0
```

Expected: a statically-linked ELF of **194,310,114 bytes** (reproducible across clean rebuilds).

### 9.5 Verification Steps

```bash
/tmp/trufflehog_bin --version
# => trufflehog dev        (source-build artifact; NOT a bug — no VCS version is stamped)

/tmp/trufflehog_bin filesystem --help | head
# => filesystem [<flags>] [<path>...]  Find credentials in a filesystem.
```

### 9.6 Example Usage

**Q1 — baseline detection (AWS access key found):**

```bash
mkdir -p /tmp/thq1
printf 'aws_access_key_id = AKIAZ3JQK7X1YWVUT5RQ\naws_secret_access_key = wJa1rXUtnFEMI7K2MDbNgQpZ8sT3uVWxYc5DeF6h\n' > /tmp/thq1/creds.txt
/tmp/trufflehog_bin filesystem /tmp/thq1 --no-verification --no-update
```

Expected (stable fields):

```
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZ3JQK7X1YWVUT5RQ
Resource_type: Access key
Line: 1
...finished scanning  {"chunks": 1, "bytes": 106, "verified_secrets": 0, "unverified_secrets": 1, ...}
```

**Q3 — false-positive suppression (documentation example key):**

```bash
mkdir -p /tmp/thq3
printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /tmp/thq3/example.txt

# Default: suppressed (known false positive)
/tmp/trufflehog_bin filesystem /tmp/thq3 --no-verification --no-update            # => "unverified_secrets": 0

# Reveal suppressed finding
/tmp/trufflehog_bin filesystem /tmp/thq3 --no-verification --no-update --results=filtered_unverified   # => "unverified_secrets": 1
```

**Cleanup:**

```bash
rm -rf /tmp/thq1 /tmp/thq3
rm -f /tmp/trufflehog_bin        # optional: remove the reference binary
```

### 9.7 Troubleshooting

- **`go: command not found` (exit 127):** the toolchain is not on `PATH` — run `export PATH=$PATH:/usr/local/go/bin`.
- **`--version` prints `trufflehog dev`:** expected for a source build; no VCS version is stamped. Not an error.
- **Output "doesn't match" on re-run:** only ephemeral fields differ (`timestamp`, `worker_id`, `scan_duration`, `verification_caching`, `BuildID`). Compare stable fields (`Detector Type`, `Decoder Type`, `Raw result`, `chunks`, `bytes`).
- **Unexpected network calls / hangs:** you omitted `--no-verification`; the default path attempts live verification. Add `--no-verification` for deterministic offline runs.
- **Cold module cache build fails offline:** the first build needs network to fetch pinned modules (`go.sum`); subsequent builds are offline-capable.

---

## 10. Appendices

### A. Command Reference

| Purpose | Command |
|---|---|
| Set Go on PATH | `export PATH=$PATH:/usr/local/go/bin` |
| Toolchain check | `go version` |
| Build scanner | `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` |
| Version check | `/tmp/trufflehog_bin --version` |
| Verify modules | `go mod verify` |
| Baseline scan | `/tmp/trufflehog_bin filesystem <path> --no-verification --no-update` |
| Reveal filtered results | `… --results=filtered_unverified` |
| Scan whole chunk | `… --scan-entire-chunk` |
| Allow overlap verification | `… --allow-verification-overlap` |
| Confirm scope (diff) | `git diff e42153d4..HEAD --name-status` |
| Doc-relevant unit tests | `CGO_ENABLED=0 go test ./pkg/decoders/... ./pkg/engine/ahocorasick/... ./pkg/sources/... ./pkg/detectors/...` |

### B. Port Reference

Not applicable — TruffleHog `filesystem` is a command-line scanner with **no listening ports** and no server component.

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (1,045 lines, 95,536 bytes) |
| `main.go` | CLI entry point; flags `--results` (L61), `--allow-verification-overlap` (L65), `filesystem` command (L143–L150) |
| `pkg/sources/chunker.go` | `ChunkSize=10*1024`, `PeekSize=3*1024` (L13–L18) — Q1 |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword pre-filter + span calculators (L79–L111) — Q1 |
| `pkg/detectors/multi_part_credential_provider.go` | `defaultMaxCredentialSpan = 1024` (L8) — Q1 |
| `pkg/detectors/aws/common.go` | Entropy floors 3.0/4.25 (L6–L7); 40-char `SecretPat` (L10) — Q1 |
| `pkg/detectors/aws/access_keys/{accesskey,canary}.go` | AWS access-key detector & canary lists — Q1 |
| `pkg/detectors/aws/session_keys/sessionkey.go` | `ASIA` session-key detector — Q1 |
| `pkg/decoders/{decoders,base64,utf16,escaped_unicode,utf8}.go` | Four-decoder pipeline (L11–L15) — Q2 |
| `pkg/detectors/falsepositives.go` | `IsKnownFalsePositive` (L68–L107); word lists — Q3 |
| `pkg/detectors/aws/utils.go` | `FalsePositiveSecretPat` (L44–L47) — Q3 |
| `pkg/engine/engine.go` | Decoder loop (L784–L786); overlap gate + `errOverlap` (L39–L42, L796) — Q3/Q4 |
| `go.mod` | Module path & toolchain (`go 1.23.1` / `toolchain go1.24.2`) |

### D. Technology Versions

| Component | Version |
|---|---|
| Go toolchain | `go1.24.2` (GOTOOLCHAIN=local) |
| Go language floor | `go 1.23.1` |
| Module | `github.com/trufflesecurity/trufflehog/v3` |
| Binary | `trufflehog dev` (source build), 194,310,114-byte static ELF x86-64 |
| Base commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` |
| HEAD commit | `d48b33dc42d66efb209d2ab394293dd5b4dd05da` |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `PATH` | `…:/usr/local/go/bin` | Make the `go` toolchain callable. |
| `CGO_ENABLED` | `0` | Produce a static binary; matches the documented build. |
| `GOTOOLCHAIN` | `local` | Use the installed `go1.24.2`; no auto-download. |

### F. Developer Tools Guide

| Tool | Use |
|---|---|
| `go build` | Compile the scanner from source (`CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .`). |
| `go test` | Run doc-relevant package unit tests (see Appendix A). |
| `go mod verify` | Confirm the dependency graph is unchanged. |
| `git diff --name-status` | Prove read-only scope (single added file). |
| `git log --author=agent@blitzy.com` | Inspect the four authored commits. |
| The compiled `trufflehog` binary | Reproduce Q1–Q4 scenarios via the canonical `filesystem` entry point. |

### G. Glossary

| Term | Meaning (as used in this project) |
|---|---|
| **Chunk** | A fixed-size slice of scanned input (`ChunkSize=10KB` + `PeekSize=3KB`) fed through the pipeline. |
| **Decoder** | One of four transforms (UTF-8, Base64, UTF-16, Escaped-Unicode) applied once per chunk. |
| **Keyword pre-filter** | Aho-Corasick gate that runs a detector only when its keyword (e.g., `AKIA`) is present. |
| **Credential span** | The ±1024-byte window within which an ID and secret must co-occur for a multi-part detector. |
| **SecretPat** | Regex requiring an exactly 40-character AWS secret. |
| **Entropy floor** | Minimum Shannon entropy (ID 3.0 / secret 4.25) a candidate must exceed. |
| **False positive suppression** | Dropping results matching `DefaultFalsePositives`/word lists (e.g., contains "example"). |
| **filtered_unverified** | A `--results` class that surfaces unverified findings that would otherwise be filtered out. |
| **Verification overlap** | When >1 detector matches the same value; verification is disabled for safety (`errOverlap`). |
| **Canary token** | A tracked AWS key type that TruffleHog reports with a special message. |
| **Ephemeral fields** | Per-run output fields (timestamp, worker_id, scan_duration) excluded from determinism comparisons. |

---

*Colors used throughout — Completed/AI `#5B39F3` (Dark Blue) · Remaining `#FFFFFF` (White) · Headings/Accents `#B23AF2` (Violet-Black) · Highlight `#A8FDD9` (Mint). Cross-section integrity verified: §1.2 = §2.2 = §7 remaining (2.0h); §2.1 + §2.2 = 53.0h total; completion 96.2%.*
