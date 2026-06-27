# Blitzy Project Guide — TruffleHog Decoder/Overlap/Deduplication Investigation

> Investigative Code-Q&A deliverable (rule **SWE-AtlasQnA-Repo**) for pinned commit `e42153d44a5e`.
> Brand legend: <span title="#5B39F3">**Completed / AI Work = Dark Blue `#5B39F3`**</span> · **Remaining = White `#FFFFFF`** · Headings/Accents = `#B23AF2` · Highlight = `#A8FDD9`.

---

## 1. Executive Summary

### 1.1 Project Overview

This project answers an investigative question about **TruffleHog** (the open-source secret scanner): when one logical secret—an AWS access key—appears in multiple encoded forms (plain text, Base64, escaped-unicode) inside a single scanned file, how do the **decoder pipeline**, **verification-overlap detection**, and **result deduplication** interact to produce sometimes one result, sometimes two with different decoder types, and sometimes an overlap error? The target users are security engineers using TruffleHog who were confused by output that appeared inconsistent. The technical scope is read-only source analysis plus live runtime reproduction against pinned commit `e42153d44a5e`. The sole deliverable is one comprehensive, source-grounded, runtime-verified markdown document; **no source code is modified**.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'17px'}}}%%
pie showData title Completion — 94.0% (47h of 50h)
    "Completed Work (AI) — 47h" : 47
    "Remaining Work — 3h" : 3
```

| Metric | Value |
|---|---|
| **Total Hours** | **50.0** |
| Completed Hours — AI | 47.0 |
| Completed Hours — Manual (human) | 0.0 |
| **Completed Hours — Total** | **47.0** |
| **Remaining Hours** | **3.0** |
| **Percent Complete** | **94.0%** |

> Completion is computed per the AAP-scoped, hours-based methodology: `47 / (47 + 3) = 94.0%`. The 6% remaining is mandatory human-in-the-loop path-to-production work (review + merge), which cannot be automated.

### 1.3 Key Accomplishments

- ✅ Authored the sole deliverable `blitzy/documentation/trufflehog_e42153d44a5e.md` (869 lines) answering all six questions (R1–R6) with rationale.
- ✅ Cleanly separated the two mechanisms the user conflated: cross-**detector** verification **overlap** (Stage 3) vs cross-**decoder** result **deduplication** (Stage 4).
- ✅ Grounded every behavioral claim in source citations (~107 file:line references) — spot-checked against the pinned commit with **zero drift**.
- ✅ Built TruffleHog out-of-tree (`go1.24.2`, 194 MB binary) and empirically reproduced all three user-observed behaviors.
- ✅ Corroborated with the authoritative engine/decoder test suites (**65 tests, 0 failures**).
- ✅ Confirmed pinned-commit fidelity: single linear decoder pass; `--max-decode-depth` (iterative decoding) absent.
- ✅ Honored all constraints: **zero source files modified**, no extra code committed, test data removed, **working tree clean**.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| _None identified_ | No blocking issues. All cited tests pass, the build is clean, citations show zero drift, and the working tree is clean. | — | — |

> The only outstanding work is non-blocking, human-side review and merge (see §1.6 and §2.2).

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| _None_ | — | No access issues identified. The investigation is fully offline: the build uses the vendored/module dependencies, and all scans run with `--no-verification` (no third-party API calls, no credentials, no network egress). | N/A | — |

### 1.6 Recommended Next Steps

1. **[High]** Have a TruffleHog/Go-literate engineer perform an SME technical review of the deliverable — read it end-to-end and spot-check the ~107 citations against pinned commit `e42153d44a5e`.
2. **[Medium]** Independently re-run the reproduction scenarios (§8 of the deliverable) and the cited test suite to confirm the empirical claims on the reviewer's hardware.
3. **[Medium]** Approve and merge the documentation-only PR (working tree is already clean; exactly one file is added).

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---:|---|
| Decoder-pipeline source analysis (R1/R2) | 4.0 | `decoders.go` ordering `[UTF8,Base64,UTF16,EscapedUnicode]`; per-decoder `Type()`; Base64 gating/in-place replacement; `DecoderType` enum |
| Engine-pipeline source analysis (R3/R4/R5) | 8.0 | `scannerWorker` overlap trigger (L796), `verificationOverlapWorker` (L924–L1034), `likelyDuplicate` (L887–L921), `notifierWorker` dedup key (L1216), 4-stage channel wiring, worker-pool sizing |
| Supporting source analysis | 2.0 | `ahocorasickcore.go`, `docs/process_flow.md`, `main.go` flags, `output/json.go` |
| Build + toolchain | 1.0 | go1.24.2 toolchain; out-of-tree binary build |
| Empirical reproduction experiments | 7.0 | 3 user scenarios + JSON evidence + concurrency/non-determinism sampling |
| Test-suite corroboration | 1.5 | Run + interpret 5 cited engine test functions (11 cases) |
| Web-research corroboration | 2.0 | Overlap history (v3.67.0), flag semantics, issue #2888, README verification model |
| Authoring — R1/R2 decoder chain + enum (§3) | 3.0 | Decoder chain, per-decoder emissions, Base64 nuance, enum-to-JSON mapping |
| Authoring — R3 overlap mechanism (§4) | 2.5 | Trigger, overlap worker, `likelyDuplicate` gate, `errOverlap` outcome |
| Authoring — R4 dedup mechanism (§5) | 3.0 | Dedup cache, key composition, skip condition, `--results` classing, post-dedup metric |
| Authoring — R5 ordering (§6) | 1.5 | Stage-3-before-Stage-4 channel-wiring proof |
| Authoring — R6 one-vs-many + non-determinism (§7) | 3.0 | Line-number-in-key, label/count non-determinism, user's three observations |
| Authoring — exec summary + pipeline overview + mechanism separation (§1/§2) | 2.0 | TL;DR table, four-stage pipeline, mermaid flow |
| Authoring — reproduction appendix + rationale + flags + caveat (§8–§11) | 3.0 | Commands, JSON evidence, per-question "code as truth", CLI flags, version caveat |
| QA / review revision cycles | 2.5 | 3 follow-up commits (review findings, QA F1 `--concurrency=1` correction, QA findings) |
| Constraint compliance + cleanup + clean-tree verification | 1.0 | Out-of-tree artifacts, no source mods, naming/placement, cleanup |
| **Total Completed** | **47.0** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---:|---|
| SME Documentation Review & Citation Validation | 2.0 | High |
| Reproduction Re-Verification (build + scenarios + tests) | 0.5 | Medium |
| PR Sign-off & Merge | 0.5 | Medium |
| **Total Remaining** | **3.0** | |

> **Cross-check:** Section 2.1 (47.0h) + Section 2.2 (3.0h) = **50.0h** Total Project Hours (matches §1.2).

---

## 3. Test Results

All tests below originate from Blitzy's autonomous validation of this project and were re-executed this session against pinned commit `e42153d44a5e`. They constitute the **authoritative behavioral evidence** cited in the deliverable.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|:--:|---|
| Engine — cited behavioral tests | Go `testing` | 11 | 11 | 0 | N/A | `TestDefaultDecoders`, `TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, `TestVerificationOverlapChunkFalsePositive`, `TestLikelyDuplicate` (6 subtests). Evidence for R1/R3/R4/R6. |
| Decoders — unit suite | Go `testing` | 54 | 54 | 0 | N/A | Full `pkg/decoders` suite (incl. subtests): `TestUTF8_*`, `TestBase64_FromChunk`, `TestUTF16Decoder`, `TestUnicodeEscape_FromChunk`, `TestDLL`. Corroborates decoder `Type()`/gating for R1/R2. |
| **Total** | | **65** | **65** | **0** | **N/A** | **100% pass rate.** |

> **Coverage note:** Code-coverage percentage is **N/A** for this deliverable — it is a documentation artifact and authored **zero** production code. The meaningful metric is that **100% of the cited behavioral tests pass**, validating that the deliverable's claims match observed code behavior. Command: `CGO_ENABLED=0 go test ./pkg/engine ./pkg/decoders`.

---

## 4. Runtime Validation & UI Verification

This is a CLI tool with **no UI**; runtime validation focuses on the build, the binary, and the documented reproduction scenarios. All items below were executed this session.

**Build & Binary**
- ✅ **Operational** — `CGO_ENABLED=0 go build -o /tmp/trufflehog_build/trufflehog .` → exit 0; 194 MB binary, built **out-of-tree**.
- ✅ **Operational** — Binary runs (`trufflehog --version` → `trufflehog dev`).
- ✅ **Operational** — Flag fidelity: `--allow-verification-overlap`, `--filter-unverified`, `--no-verification`, `--results`, `--concurrency`, `--json`, `--config`, `--no-update` all present; `--max-decode-depth` correctly **absent** (single-linear-pass version caveat confirmed).

**Reproduction Scenarios (filesystem scans, JSON output, `--no-verification`)**
- ✅ **Operational** — In-repo read-only fixture (`pkg/engine/testdata/secrets.txt`): **2 results** (AWS `PLAIN`, SentryToken `PLAIN`) — corroborates `TestEngine_DuplicateSecrets`.
- ✅ **Operational** — Scenario A (same chunk): **count = 1** on every run; surviving `DecoderName` alternates `PLAIN`/`BASE64` (the label non-determinism of R6).
- ✅ **Operational** — Scenario B (different lines): **stable multi-result** across runs (`PLAIN@L1` + `BASE64` at distinct lines) — different `SourceMetadata` → different dedup keys → both kept.
- ✅ **Operational** — Scenario C (overlap): documented via custom detectors; results carry `errOverlap`; `--allow-verification-overlap` suppresses it.

**API Integration**
- ⚠ **Partial (by design)** — No live verification API calls were exercised; all scans use `--no-verification` to remain side-effect-free and offline, per the AAP. This is intentional and not a defect.

**Working Tree**
- ✅ **Operational** — `git status --porcelain` empty after build, tests, and reproduction (all artifacts out-of-tree; cleanup verified).

---

## 5. Compliance & Quality Review

Cross-mapping of AAP deliverables and governing-rule (SWE-AtlasQnA-Repo) requirements to verification status.

| Requirement (AAP / Rule) | Benchmark | Status | Evidence / Notes |
|---|---|:--:|---|
| Deliverable naming = `<branch>.md` | `trufflehog_e42153d44a5e.md` | ✅ Pass | Filename matches source branch exactly. |
| Placement in `blitzy/documentation/` | Correct directory | ✅ Pass | File present at `blitzy/documentation/trufflehog_e42153d44a5e.md`. |
| Comprehensive answer (R1–R6) | All six questions answered with rationale | ✅ Pass | §3 (R1/R2), §4 (R3), §5 (R4), §6 (R5), §7 (R6), per-question rationale §9. |
| Code as truth (citations) | Exact file:line citations | ✅ Pass | ~107 citations; spot-check zero drift (e.g., dedup key `engine.go:L1216`, overlap trigger `:L796`, enum `detectors.pb.go:L26-30`). |
| Provide rationale/thinking | Explicit reasoning | ✅ Pass | §9 "Code as truth" per-question rationale; TL;DR reasoning table in §1. |
| Build & run for evidence | Empirical reproduction | ✅ Pass | Out-of-tree build + 3 scenarios + in-repo scan reproduced this session. |
| Do **not** modify existing files | Zero source edits | ✅ Pass | `git diff e42153d4..HEAD` = 1 file added (+869/-0), 0 modifications. |
| No extra code committed | Only the markdown doc | ✅ Pass | No scripts/fixtures/helpers committed; binary + fixtures out-of-tree. |
| Remove test data / clean tree | Working tree clean | ✅ Pass | `/tmp/scratch` removed; `git status --porcelain` empty. |
| Pinned-commit fidelity | Single linear pass; no iterative decode | ✅ Pass | `--max-decode-depth` absent from help; §11 version caveat. |
| Mechanism separation | Overlap (cross-detector) vs dedup (cross-decoder) | ✅ Pass | §1 TL;DR table + dedicated §4/§5. |
| Markdown quality | Balanced fences, resolvable TOC | ✅ Pass | 84 balanced fences, 2 mermaid blocks, all 12 TOC anchors resolve. |

**Fixes applied during autonomous validation:** Across 3 QA-driven follow-up commits, the team addressed review findings and corrected an overstatement about `--concurrency=1` label stability (QA F1) — the doc now correctly distinguishes that `--concurrency=1` stabilizes the result **count** but **not** the surviving decoder-type **label** (the detector pool stays at `concurrency × 8` workers). **Outstanding compliance items:** none.

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|:--:|:--:|---|:--:|
| Citation line-number drift if read against a different commit (e.g., upstream `main`) | Technical | Low | Medium | Doc explicitly pins commit `e42153d44a5e` + §11 version caveat + appendix lists files consulted | Mitigated |
| Rare `count=2` notifier race not guaranteed to reproduce (hardware/scheduling dependent) | Technical | Low | Medium | Doc honestly frames it as sporadic/code-grounded; documents `--concurrency=1` behavior; separates label (always) vs count (rare) non-determinism | Mitigated/Accepted |
| No CI/test guards the prose; future source changes could silently invalidate claims | Technical | Low | Low | Scope frozen to pinned commit; version caveat | Accepted |
| Reproduction evidence embeds AWS-key-like tokens | Security | Informational | N/A | Verified benign: `AKIAIOSFODNN7EXAMPLE` is AWS's public **example** key; `AKIAWARWQKZNHMZBLY4I` is a **pre-existing** repo test fixture (`pkg/engine/testdata/secrets.txt`), not a new secret | Resolved |
| Documentation staleness as TruffleHog evolves (iterative decoding exists upstream) | Operational | Low | Medium | Explicit version caveat pins scope to `e42153d44a5e` | Mitigated |
| Discoverability — deliverable under `blitzy/documentation/` may differ from team conventions | Operational | Low | Low | Standard location per governing rule; linkable from a docs index if desired | Accepted |
| Re-running empirical evidence requires `go1.24.2` + building binary | Integration | Low | Low | Build command + toolchain documented (§8.0 of doc, §9 here) | Mitigated |
| Integration coupling (imports/build/config/CI) | Integration | None | N/A | Standalone markdown; `go.mod`/`go.sum` unchanged | N/A |

> **Overall risk posture: LOW.** No high or critical risks; no blockers. The single security-adjacent item is verified benign.

---

## 7. Visual Project Status

**Project Hours (Completed vs Remaining)** — Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeColor':'#B23AF2','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'17px'}}}%%
pie showData title Project Hours — 94.0% Complete
    "Completed Work" : 47
    "Remaining Work" : 3
```

**Remaining Hours by Category** (from §2.2):

```mermaid
xychart-beta
    title "Remaining Hours by Category (total 3.0h)"
    x-axis ["SME Review", "Repro Re-Verify", "PR Merge"]
    y-axis "Hours" 0 --> 2.5
    bar [2.0, 0.5, 0.5]
```

| Category | Hours | Priority |
|---|---:|:--:|
| SME Documentation Review & Citation Validation | 2.0 | High |
| Reproduction Re-Verification | 0.5 | Medium |
| PR Sign-off & Merge | 0.5 | Medium |
| **Total** | **3.0** | |

> **Integrity check:** "Remaining Work" = **3** in the pie chart equals the Remaining Hours in §1.2 and the sum of the §2.2 Hours column.

---

## 8. Summary & Recommendations

**Achievements.** The project delivers a single, authoritative, source-grounded and runtime-verified markdown document that resolves the user's confusion. It cleanly separates the two mechanisms that were being conflated—cross-**detector** verification **overlap** (Stage 3) and cross-**decoder** result **deduplication** (Stage 4)—and demonstrates that the user's "inconsistent" outcomes are deterministic consequences of **file structure**: which detectors fire on a chunk (overlap path) and which source line each decoded variant resolves to (the `SourceMetadata` component of the dedup key). It further documents the one genuine non-determinism—**which** decoder-type label survives a same-line collapse—and honestly characterizes a rare, code-grounded notifier race.

**Remaining gaps.** None on the autonomous side. The remaining **3.0 hours** are entirely human-in-the-loop path-to-production activities: SME technical review, independent reproduction re-verification, and PR sign-off/merge.

**Critical path to production.** SME review → reproduction confirmation → merge. There is no runtime service to deploy and no infrastructure to configure; "production" for this deliverable means the reviewed document is merged.

**Success metrics.** All six questions (R1–R6) answered with rationale ✅; ~107 citations with zero drift ✅; 65/65 cited tests passing ✅; zero source files modified ✅; working tree clean ✅.

**Production-readiness assessment.** The project is **94.0% complete**. The deliverable is production-ready from the autonomous standpoint—accurate, complete, citation-faithful, and fully constraint-compliant—pending the mandatory human review and merge.

| Metric | Value |
|---|---|
| Completion | 94.0% (47h / 50h) |
| Cited tests passing | 65 / 65 (0 failures) |
| Source files modified | 0 |
| Citations (zero drift) | ~107 |
| Overall risk | Low |

---

## 9. Development Guide

> All commands below were executed and verified this session. They are read-only with respect to the repository; the binary and any scratch fixtures live **outside** the repo tree so the working tree stays clean.

### 9.1 System Prerequisites

- **Go 1.24.2** (matches `go.mod` `toolchain go1.24.2`; the `go` directive is `1.23.1`). Verify: `go version` → `go version go1.24.2 linux/amd64`.
- **git** (repository already cloned at the project root).
- **Disk:** ~2 GB free for the ~194 MB binary plus the Go build cache.
- **OS:** Linux or macOS.
- **No** database, cache, message queue, or network service is required — the investigation runs fully offline with `--no-verification`.

### 9.2 Environment Setup

```bash
# From the repository root (branch: blitzy-0663c175-556d-40b3-a2e5-6ecb55a836c5, base commit e42153d4)
git status --porcelain          # expect EMPTY (clean working tree)
git log --oneline -1            # HEAD = 3c5849e0 (docs: address QA findings ...)
```

No environment variables are required for the read-only investigation.

### 9.3 Dependency Installation

```bash
go mod download                 # resolves existing modules from go.mod/go.sum; no new deps are added
```

### 9.4 Build (out-of-tree)

```bash
mkdir -p /tmp/trufflehog_build
CGO_ENABLED=0 go build -o /tmp/trufflehog_build/trufflehog .
# Expected: exit 0; binary ~194 MB. (The ./trufflehog name is .gitignore'd anyway, line 7.)
ls -lh /tmp/trufflehog_build/trufflehog
```

### 9.5 Run the Cited Tests (corroborating evidence)

```bash
# Full suites (expected: ok / PASS, 0 failures)
CGO_ENABLED=0 go test -timeout=10m ./pkg/engine ./pkg/decoders

# Just the authoritative behavioral tests, verbose:
CGO_ENABLED=0 go test -run 'TestDefaultDecoders|TestEngine_DuplicateSecrets|TestVerificationOverlapChunk|TestLikelyDuplicate' -v ./pkg/engine
```

### 9.6 Example Usage / Verification

```bash
# (a) Read-only scan of the committed in-repo fixture -> 2 results (AWS PLAIN + SentryToken PLAIN)
/tmp/trufflehog_build/trufflehog filesystem pkg/engine/testdata/secrets.txt \
  --no-verification --results=verified,unverified,unknown -j --no-update

# (b) Scenario A — same chunk -> count=1, label alternates PLAIN/BASE64 (run a few times)
#     Build an out-of-tree fixture with plaintext creds + a Base64 blob of the same creds adjacent.
mkdir -p /tmp/scratch/A
# ... write /tmp/scratch/A/creds.txt (plaintext + "blob=<base64-of-same-creds>") ...
/tmp/trufflehog_build/trufflehog filesystem /tmp/scratch/A \
  --no-verification --results=verified,unverified,unknown -j --no-update

# (c) Scenario B — different lines -> stable multi-result (PLAIN + BASE64 at distinct lines)
#     Same creds, then >13 KiB of filler, then the Base64 blob (pushes the variant to a different chunk/line).
mkdir -p /tmp/scratch/B
/tmp/trufflehog_build/trufflehog filesystem /tmp/scratch/B \
  --no-verification --results=verified,unverified,unknown -j --no-update

# Pin concurrency to stabilize the COUNT (not the label):
/tmp/trufflehog_build/trufflehog filesystem /tmp/scratch/A \
  --no-verification --results=verified,unverified,unknown -j --no-update --concurrency=1
```

### 9.7 Cleanup & Cleanliness Proof

```bash
rm -rf /tmp/scratch /tmp/trufflehog_build      # remove all out-of-tree artifacts
git status --porcelain                          # MUST be empty (no source modified, no stray fixtures)
```

### 9.8 Troubleshooting

- **`go build` fails on toolchain:** ensure `go version` reports `go1.24.2`; the module declares `toolchain go1.24.2`.
- **`--help` shows nothing when piped to `grep`:** kingpin prints help to **STDERR** — redirect first: `trufflehog --help 2>&1 | grep results`.
- **A flag isn't found by exact name:** kingpin renders booleans as `--[no-]<name>` and value flags as `--<name>=<VAL>`; match the displayed substring (e.g. `json`, `no-verification`, `--results`).
- **Expecting `--max-decode-depth`:** it does **not** exist at this commit (single linear decoder pass). Iterative decoding is a newer upstream feature, intentionally out of scope.
- **Scenario A label changes between runs:** expected — the surviving `DecoderName` is non-deterministic under concurrency. The rare `count=2` race is sporadic and **not guaranteed to reproduce**; `--concurrency=1` stabilizes the count (not the label).
- **Working tree shows changes:** ensure the binary and fixtures were created **outside** the repo tree (use `/tmp/...`).

---

## 10. Appendices

### A. Command Reference

| Purpose | Command |
|---|---|
| Verify Go toolchain | `go version` |
| Download modules | `go mod download` |
| Build (out-of-tree) | `CGO_ENABLED=0 go build -o /tmp/trufflehog_build/trufflehog .` |
| Run suites | `CGO_ENABLED=0 go test -timeout=10m ./pkg/engine ./pkg/decoders` |
| Run cited tests (verbose) | `go test -run 'TestDefaultDecoders\|TestEngine_DuplicateSecrets\|TestVerificationOverlapChunk\|TestLikelyDuplicate' -v ./pkg/engine` |
| Scan a path (JSON) | `trufflehog filesystem <dir> --no-verification --results=verified,unverified,unknown -j --no-update` |
| Stabilize count | append `--concurrency=1` |
| Allow overlap verification | append `--allow-verification-overlap` |
| Cleanliness proof | `git status --porcelain` (expect empty) |

### B. Port Reference

| Port | Purpose |
|---|---|
| _None_ | The investigation uses the `filesystem` source only; no ports are opened or required. |

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (only file added) |
| `pkg/decoders/decoders.go` | `DefaultDecoders()` ordering `[UTF8,Base64,UTF16,EscapedUnicode]` (L8–L16) — reference |
| `pkg/decoders/{utf8,base64,utf16,escaped_unicode}.go` | Per-decoder `Type()` and Base64 gating — reference |
| `pkg/pb/detectorspb/detectors.pb.go` | `DecoderType` enum (L26–L30) — reference |
| `pkg/engine/engine.go` | Overlap trigger (L796), overlap worker (L924–L1034), `likelyDuplicate` (L887–L921), notifier dedup key (L1216), `errOverlap` (L39–L42) — reference |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Multi-detector matching per chunk — reference |
| `pkg/engine/engine_test.go` | Cited behavioral tests — reference |
| `pkg/engine/testdata/secrets.txt` | Duplicate-secrets fixture — reference (read-only) |
| `docs/process_flow.md` | Four-stage pipeline narrative — reference |
| `main.go` | CLI flags (`--allow-verification-overlap`, `--filter-unverified`, …) — reference |

### D. Technology Versions

| Component | Version |
|---|---|
| Go (toolchain) | go1.24.2 |
| Go (module directive) | 1.23.1 |
| Module | `github.com/trufflesecurity/trufflehog/v3` |
| Pinned commit | `e42153d44a5e` |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 (dedup/verification LRU cache) |
| `github.com/adrg/strutil` | v0.3.1 (Levenshtein in `likelyDuplicate`) |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 (multi-pattern matching) |
| `github.com/alecthomas/kingpin/v2` | v2.4.0 (CLI flags) |

### E. Environment Variable Reference

| Variable | Required | Purpose |
|---|:--:|---|
| _None_ | — | No environment variables are needed for the read-only investigation (scans run with `--no-verification`). |
| `CGO_ENABLED=0` | Build-time (recommended) | Produces a static binary; used for the documented build command. |

### F. Developer Tools Guide

| Tool | Use |
|---|---|
| `go build` / `go test` | Build the binary and run the authoritative test suites |
| `trufflehog filesystem … -j` | Produce machine-parseable JSON for controlled experiments |
| `--results` / `--no-verification` / `--no-update` | Constrain output classes; keep scans offline and side-effect-free |
| `--concurrency=1` | Stabilize the result **count** (single notifier worker) for deterministic reproduction |
| `git status --porcelain` | Prove the working tree is clean after investigation |
| `python3 -c '... json.loads ...'` | Parse JSON scan output to tally result counts and `DecoderName`s |

### G. Glossary

| Term | Meaning |
|---|---|
| **Decoder pipeline** | Fixed chain `[UTF8, Base64, UTF16, EscapedUnicode]` applied in a single linear pass; each non-nil variant is scanned independently |
| **`DecoderType`** | Enum label on a result: `PLAIN`, `BASE64`, `UTF16`, `ESCAPED_UNICODE` (`UNKNOWN=0`) |
| **Verification overlap** | Cross-**detector** guard (Stage 3): when ≥2 distinct detectors match the same decoded chunk, verification is disabled and `errOverlap` is attached (unless `--allow-verification-overlap`) |
| **Deduplication** | Cross-**decoder** drop (Stage 4): the notifier's LRU cache keyed on `DetectorType + Raw + RawV2 + SourceMetadata` (excluding `DecoderType`) drops a later same-key result with a different decoder type |
| **`SourceMetadata`** | Result metadata including the filesystem **line number**; the lever that makes two encodings collapse (same line) or stay separate (different lines) |
| **`errOverlap`** | Sentinel verification error indicating multiple detectors matched one result |
| **`likelyDuplicate`** | Levenshtein-similarity gate (threshold 0.9) used in the overlap worker to flag cross-detector duplicates |
| **Label non-determinism** | Under concurrency, *which* decoder-type label survives a same-line collapse can vary run-to-run, even though the **count** is stable |
