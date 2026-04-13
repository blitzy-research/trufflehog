# Blitzy Project Guide

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a comprehensive investigation document explaining why TruffleHog's CLI filesystem scan (`trufflehog filesystem <path>`) reports more secret findings than an equivalent scan launched through the Go engine API (`engine.NewEngine` + `eng.ScanFileSystem`) on the same test directory. The deliverable is a single Markdown file (`blitzy/documentation/trufflehog_e42153d44a5e.md`) placed in the destination repository per the `SWE-AtlasQnA-Repo` implementation rule. The investigation is based purely on static source code analysis at commit `e42153d4` — no runtime instrumentation, no code modifications. Seven root causes were identified, ranked by impact, with the highest being the CLI's unconditional enabling of APK file handling via a process-global feature flag.

### 1.2 Completion Status

```mermaid
pie title Project Completion
    "Completed (17h)" : 17
    "Remaining (2h)" : 2
```

| Metric | Value |
|--------|-------|
| **Total Project Hours** | 19 |
| **Completed Hours (AI)** | 17 |
| **Remaining Hours** | 2 |
| **Completion Percentage** | 89.5% |

**Calculation:** 17 completed hours / (17 completed + 2 remaining) = 17/19 = 89.5% complete.

### 1.3 Key Accomplishments

- ✅ Created comprehensive 598-line investigation document with 7 sections, 23 headings, 28 code blocks, and 2 comparison tables
- ✅ Identified and documented 7 root causes for the CLI-vs-API finding-count discrepancy, each with severity rating and exact code-line evidence
- ✅ Produced complete parameter-by-parameter comparison of all `engine.Config` fields and process-global feature flags
- ✅ Documented the 4-layer detector filtering chain with code references
- ✅ Created API-parity code template with prioritized recommendations
- ✅ Verified all code references accurate against source (17 source files analyzed)
- ✅ Maintained repository integrity — zero modifications to existing source files
- ✅ Full build verification passes (`go build ./...` success, `go mod verify` all modules verified)
- ✅ All relevant package tests pass (10 packages tested)

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Pre-existing `TestAPKHandler` failure (external HTTP 404 from `github.com/joeleonjr/leakyAPK`) | None — not caused by this change; network-dependent test with unavailable external resource | Repository maintainers | N/A — requires upstream fix |
| Pre-existing `pkg/sources/circleci` test failure (GCP SecretManager permission denied) | None — not caused by this change; requires GCP IAM configuration | Repository maintainers | N/A — requires credential setup |

### 1.5 Access Issues

No access issues identified. The project is a documentation-only deliverable that does not require service credentials, API keys, or deployment infrastructure.

### 1.6 Recommended Next Steps

1. **[High]** Human peer review of the investigation document for technical accuracy — verify root cause analysis against source code
2. **[High]** Stakeholder review of API-parity recommendations for potential upstream adoption
3. **[Medium]** Consider whether `feature.EnableAPKHandler` should be defaulted to `true` in the engine's `setDefaults()` to eliminate the primary finding-count discrepancy
4. **[Low]** Review document formatting and editorial polish for publication

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Codebase investigation and source analysis | 6 | Deep analysis of 17 source files: main.go, pkg/engine/engine.go, pkg/engine/defaults/defaults.go, pkg/engine/filesystem.go, pkg/sources/source_manager.go, pkg/sources/filesystem/filesystem.go, pkg/handlers/handlers.go, pkg/handlers/apk.go, pkg/feature/feature.go, pkg/detectors/detectors.go, pkg/detectors/endpoint_customizer.go, pkg/decoders/decoders.go, pkg/config/config.go, pkg/config/detectors.go, pkg/engine/ahocorasick/ahocorasickcore.go, hack/snifftest/main.go, go.mod |
| Document — Executive Summary | 0.5 | 3-paragraph summary with root cause ranking and key finding |
| Document — Architecture Overview | 1.5 | 7-stage pipeline description with text data flow diagram |
| Document — Root Cause Analysis | 3 | 7 root causes with severity ratings, code snippets, exact line numbers, and impact analysis |
| Document — Parameter Comparison Tables | 1.5 | Complete engine.Config fields table (22 rows) and feature flags table (5 rows) |
| Document — Detector Participation Analysis | 1 | 4-layer filtering chain analysis with ParseDetectors behavior and existing API reference |
| Document — API-Parity Recommendations | 1 | CLI-equivalent Go code template and prioritized action table |
| Document — Conclusion | 0.5 | Synthesis of findings with architectural explanation |
| Code reference accuracy verification and fix | 1 | Verified all cited line numbers against source; applied accuracy fix for buildDetectorList() line range |
| Build and test validation | 0.5 | go build ./..., go mod verify, go test for 10 packages |
| Repository integrity verification | 0.5 | git diff, git status, confirmed no source file modifications |
| **Total** | **17** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human peer review of technical accuracy | 1 | High |
| Documentation refinements based on review | 0.5 | Medium |
| Final stakeholder approval | 0.5 | Medium |
| **Total** | **2** | |

---

## 3. Test Results

All tests listed originate from Blitzy's autonomous validation execution during this project session.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Unit — pkg/engine | Go test | Suite | ✅ All | 0 | N/A | PASS in 1.148s |
| Unit — pkg/engine/ahocorasick | Go test | Suite | ✅ All | 0 | N/A | PASS in 0.040s |
| Unit — pkg/engine/defaults | Go test | Suite | ✅ All | 0 | N/A | PASS in 0.682s |
| Unit — pkg/sources/filesystem | Go test | Suite | ✅ All | 0 | N/A | PASS in 0.688s |
| Unit — pkg/config | Go test | Suite | ✅ All | 0 | N/A | PASS in 0.040s |
| Unit — pkg/decoders | Go test | Suite | ✅ All | 0 | N/A | PASS in 0.039s |
| Unit — pkg/handlers (non-APK) | Go test | Suite | ✅ All | 0 | N/A | PASS in 2.384s (APK test excluded — pre-existing external resource failure) |
| Unit — pkg/detectors | Go test | Suite | ✅ All | 0 | N/A | PASS in 9.900s |
| Build — Full project | Go build | 1 | ✅ 1 | 0 | N/A | CGO_ENABLED=0 go build ./... — SUCCESS |
| Module verification | Go mod verify | 1 | ✅ 1 | 0 | N/A | All modules verified |

**Pre-existing failures (not caused by this change):**
- `pkg/handlers/apk_test.go:TestAPKHandler` — Downloads APK from `github.com/joeleonjr/leakyAPK` which returns HTTP 404. Network-dependent test.
- `pkg/sources/circleci` — GCP SecretManager permission denied. Credential-dependent test.

---

## 4. Runtime Validation & UI Verification

This project produces a documentation artifact only — no runtime application, UI, or API endpoints to validate.

**Build Health:**
- ✅ `go build ./...` — Compiles successfully with zero errors
- ✅ `go mod verify` — All module checksums verified
- ✅ `git status` — Clean working tree, no uncommitted changes

**Document Health:**
- ✅ File exists: `blitzy/documentation/trufflehog_e42153d44a5e.md` (598 lines, 34,649 bytes)
- ✅ Well-formed Markdown: 23 headings, 28 code blocks (all properly opened/closed), 49 table rows
- ✅ 7 document sections: Executive Summary, Architecture Overview, Root Cause Analysis, Parameter Comparison, Detector Participation, API-Parity Recommendations, Conclusion
- ✅ All code references verified accurate against source files at commit `e42153d4`

**Repository Integrity:**
- ✅ Only 1 file added (`A blitzy/documentation/trufflehog_e42153d44a5e.md`)
- ✅ Zero existing source files modified
- ✅ 2 commits on branch (document creation + accuracy fix)
- ✅ Net change: +598 lines added, 0 lines removed

---

## 5. Compliance & Quality Review

| AAP Requirement | Status | Evidence |
|----------------|--------|----------|
| Create `blitzy/documentation/trufflehog_e42153d44a5e.md` | ✅ Complete | File exists, 598 lines, 34,649 bytes |
| Executive Summary section | ✅ Complete | Section 1 in document |
| Architecture Overview with pipeline stages | ✅ Complete | Section 2 with 7-stage pipeline and data flow diagram |
| Root Cause Analysis — 7 root causes with code-line evidence | ✅ Complete | Section 3 with severity ratings, file paths, line numbers, code snippets |
| Parameter-by-parameter comparison table | ✅ Complete | Section 4 with engine.Config (22 fields) and feature flags (5 flags) |
| Detector Participation Analysis | ✅ Complete | Section 5 with 4-layer filtering chain |
| API-Parity Recommendations with code template | ✅ Complete | Section 6 with Go code template and priority table |
| Evidence-based conclusions with specific line numbers | ✅ Complete | All 7 root causes cite exact file:line references; accuracy fix applied |
| No modification of existing source files | ✅ Complete | `git diff e42153d4..HEAD --name-status` shows only `A blitzy/documentation/...` |
| No temporary files left behind | ✅ Complete | `git status` shows clean working tree |
| Static analysis only (no runtime instrumentation) | ✅ Complete | Document metadata states "Static source-code analysis only (no runtime data)" |
| Build verification — no compilation errors | ✅ Complete | `go build ./...` success, `go mod verify` passes |
| Test verification — no regressions | ✅ Complete | All 10 relevant packages pass; only pre-existing external failures |

**Autonomous Fixes Applied:**
- Accuracy fix commit (`de08715b`): Corrected `buildDetectorList()` line range from `11-1702` to `839-1702` in the document

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Code reference line numbers may drift with future commits | Technical | Low | Medium | Document states commit `e42153d4` as reference point; line numbers are accurate at that commit | Mitigated |
| Pre-existing `TestAPKHandler` external resource failure | Technical | Low | High | Not caused by this change; test depends on external GitHub-hosted APK that returns 404 | Accepted (out of scope) |
| Pre-existing GCP permission failures in circleci tests | Technical | Low | High | Not caused by this change; requires GCP IAM configuration | Accepted (out of scope) |
| Document may require updates if engine architecture changes | Operational | Low | Low | Document is scoped to commit `e42153d4`; future changes would require a separate investigation | Accepted |
| No security risks | Security | None | N/A | Documentation-only deliverable; no code execution, no credentials, no secrets | N/A |
| No integration risks | Integration | None | N/A | Single Markdown file; no service dependencies, APIs, or external integrations | N/A |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 17
    "Remaining Work" : 2
```

**Breakdown of Remaining Work (2 hours):**

| Task | Hours |
|------|-------|
| Human peer review of technical accuracy | 1 |
| Documentation refinements based on review | 0.5 |
| Final stakeholder approval | 0.5 |
| **Total** | **2** |

---

## 8. Summary & Recommendations

### Achievements

The project successfully delivered its sole AAP requirement: a comprehensive 598-line investigation document explaining why TruffleHog's CLI filesystem scan reports more findings than the Go engine API. The document identifies 7 root causes with evidence-based analysis traceable to specific Go source code locations, provides complete parameter comparison tables, documents the 4-layer detector filtering chain, and includes an API-parity code template. The project is **89.5% complete** (17 completed hours out of 19 total hours), with the remaining 2 hours consisting of human review activities.

### Remaining Gaps

The only remaining work items are human-dependent:
1. **Peer review** of the document's technical accuracy (1 hour) — verifying root cause analysis against source code
2. **Documentation refinements** based on reviewer feedback (0.5 hours)
3. **Stakeholder approval** for merge (0.5 hours)

### Critical Path to Production

This is a documentation-only deliverable with no deployment requirements. The critical path is:
1. Human reviewer validates technical accuracy of the 7 root causes
2. Reviewer approves or requests minor corrections
3. PR is merged

### Production Readiness Assessment

The deliverable is **ready for human review**. All automated validation gates are satisfied:
- Build passes with zero errors
- All relevant tests pass
- Repository integrity maintained (no source file modifications)
- Document is complete, well-structured, and all code references are verified accurate

### Key Investigation Finding

The primary driver of the CLI-vs-API finding-count discrepancy is `feature.EnableAPKHandler` — a process-global `atomic.Bool` that the CLI unconditionally sets to `true` at `main.go:458`, while the engine's `setDefaults()` cannot address it (it's outside the `Config` struct). This causes all `.apk` files to be silently skipped by API callers who don't set this flag, directly reducing finding counts for any filesystem scan containing Android application packages.

---

## 9. Development Guide

### 9.1 System Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.23.1+ (toolchain go1.24.2) | Build and test the TruffleHog project |
| Git | 2.x+ | Version control and branch management |

### 9.2 Environment Setup

```bash
# Clone and checkout the branch
git clone <repository-url>
cd trufflehog
git checkout blitzy-535d1ad2-2e32-4026-b9f3-2ff442011d44

# Verify Go version
go version
# Expected: go version go1.24.2 linux/amd64 (or compatible)
```

### 9.3 Dependency Verification

```bash
# Verify all module checksums
go mod verify
# Expected output: all modules verified
```

### 9.4 Build Verification

```bash
# Build all packages (no CGO for maximum portability)
CGO_ENABLED=0 go build ./...
# Expected: no output (success), exit code 0
```

### 9.5 Test Execution

```bash
# Test all relevant packages analyzed in the investigation
go test ./pkg/engine/...
# Expected: ok (pkg/engine, pkg/engine/ahocorasick, pkg/engine/defaults)

go test ./pkg/sources/filesystem/...
# Expected: ok pkg/sources/filesystem

go test ./pkg/config/...
# Expected: ok pkg/config

go test ./pkg/decoders/...
# Expected: ok pkg/decoders

go test ./pkg/detectors/... -count=1
# Expected: ok pkg/detectors (note: individual detector tests may require API credentials)

# Test handlers (excluding APK test which has pre-existing external failure)
go test -run "Test[^A]" ./pkg/handlers/...
# Expected: ok pkg/handlers
```

### 9.6 Viewing the Deliverable

```bash
# Verify the investigation document exists
ls -la blitzy/documentation/trufflehog_e42153d44a5e.md
# Expected: 598 lines, ~34KB

# View the document
cat blitzy/documentation/trufflehog_e42153d44a5e.md

# Verify document structure (section count)
grep "^## " blitzy/documentation/trufflehog_e42153d44a5e.md
# Expected: 7 top-level sections
```

### 9.7 Repository Integrity Verification

```bash
# Confirm only the documentation file was added
git diff e42153d4..HEAD --name-status
# Expected: A  blitzy/documentation/trufflehog_e42153d44a5e.md

# Confirm clean working tree
git status
# Expected: nothing to commit, working tree clean
```

### 9.8 Troubleshooting

| Issue | Resolution |
|-------|------------|
| `go: command not found` | Ensure Go 1.23.1+ is installed and `$GOPATH/bin` is in your `$PATH` |
| `TestAPKHandler` fails | Pre-existing issue — external APK resource at `github.com/joeleonjr/leakyAPK` returns HTTP 404; not related to this change |
| `pkg/sources/circleci` test fails | Pre-existing issue — requires GCP SecretManager IAM permissions; not related to this change |
| Module verification fails | Run `go mod download` to fetch all dependencies, then retry `go mod verify` |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `go build ./...` | Build all packages in the repository |
| `go mod verify` | Verify module checksums against go.sum |
| `go test ./pkg/engine/...` | Run engine package tests |
| `go test ./pkg/sources/filesystem/...` | Run filesystem source tests |
| `go test -run "Test[^A]" ./pkg/handlers/...` | Run handler tests excluding APK test |
| `git diff e42153d4..HEAD --name-status` | Show files changed since base commit |
| `git log --oneline e42153d4..HEAD` | Show commits on this branch |

### B. Key File Locations

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **Deliverable** — Investigation document |
| `main.go` | CLI entry point (analyzed, not modified) |
| `pkg/engine/engine.go` | Engine core — Config, NewEngine, setDefaults (analyzed) |
| `pkg/engine/defaults/defaults.go` | Default detector registry (analyzed) |
| `pkg/engine/filesystem.go` | Filesystem scan entry point (analyzed) |
| `pkg/sources/source_manager.go` | SourceManager with unit-based scanning (analyzed) |
| `pkg/sources/filesystem/filesystem.go` | Filesystem source implementation (analyzed) |
| `pkg/handlers/handlers.go` | File handlers with APK gate (analyzed) |
| `pkg/feature/feature.go` | Feature flags including EnableAPKHandler (analyzed) |
| `go.mod` | Go module manifest |

### C. Technology Versions

| Technology | Version | Notes |
|------------|---------|-------|
| Go | 1.23.1 | Module-specified minimum version |
| Go Toolchain | go1.24.2 | Build toolchain version |
| TruffleHog | v3 (commit `e42153d4`) | Base commit for investigation |
| License | AGPL-3.0 | Repository license |

### D. Glossary

| Term | Definition |
|------|------------|
| APK | Android Application Package — archive format for Android apps |
| Aho-Corasick | String-matching algorithm used for keyword detection in the scanning pipeline |
| Detector | A component implementing the `Detector` interface that extracts secrets from data chunks |
| EndpointCustomizer | Optional detector interface for configuring verification endpoints |
| Feature Flag | Process-global `atomic.Bool` in `pkg/feature/feature.go` controlling runtime behavior |
| SourceManager | Component that bridges the engine to source implementations, managing concurrency and scanning strategy |
| Source Unit | An individual scannable item (e.g., a single file) in the unit-based scanning path |
| setDefaults | Engine method (`engine.go:336-374`) that fills missing configuration with sensible defaults |