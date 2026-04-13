# Blitzy Project Guide

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a comprehensive investigative analysis of TruffleHog v3's internal runtime behavior across three interconnected subsystems: the decoder pipeline, the verification overlap detection mechanism, and the result deduplication cache. The analysis traces exact code paths to answer five specific questions about how the engine processes a file containing the same AWS access key in multiple encoded forms (plain text and Base64). The deliverable is a single 673-line Markdown document (`blitzy/documentation/trufflehog_e42153d44a5e.md`) containing evidence-based answers grounded in specific source file references. No existing source files were modified — this is a read-only analysis project.

### 1.2 Completion Status

```mermaid
pie title Completion Status
    "Completed (29h)" : 29
    "Remaining (4h)" : 4
```

| Metric | Value |
|--------|-------|
| **Total Project Hours** | 33 |
| **Completed Hours** | 29 |
| **Remaining Hours** | 4 |
| **Completion Percentage** | 87.9% |

**Calculation**: 29 completed hours / (29 + 4) total hours = 29 / 33 = 87.9% complete

### 1.3 Key Accomplishments

- [x] Created comprehensive 673-line analysis document (`blitzy/documentation/trufflehog_e42153d44a5e.md`)
- [x] Answered all 5 investigative questions with evidence-based reasoning tied to specific source file:line references
- [x] Traced complete pipeline flow: `scannerWorker` → `verificationOverlapWorker` → `detectorWorker` → `processResult` → `notifierWorker`
- [x] Documented decoder pipeline mechanics including critical chunk data mutation behavior
- [x] Analyzed deduplication key construction (`DetectorType + Raw + RawV2 + SourceMetadata`, excluding `DecoderType`)
- [x] Provided 3 detailed scenario walkthroughs (raw-only, Base64-only, both) with step-by-step tables
- [x] Created Mermaid data flow diagrams illustrating pipeline architecture
- [x] Compiled 37-row key code reference appendix
- [x] Verified all code references against actual source (second commit fixed Base64 threshold semantics)
- [x] Full codebase compilation verified: `CGO_ENABLED=0 go build ./...` — exit code 0
- [x] 189 relevant tests passed with 0 failures across `pkg/decoders`, `pkg/engine`, `pkg/engine/ahocorasick`
- [x] Clean working tree — no temporary test data, no out-of-scope modifications

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Line number references may drift with future commits | Code references in the analysis document could become stale if the upstream TruffleHog codebase receives updates to the analyzed files | Human Developer | Before merge if upstream has changed |
| No automated reference staleness detection | If `pkg/engine/engine.go` or `pkg/decoders/*.go` are modified upstream, the document's line references won't auto-update | Human Developer | Post-merge (low priority) |

### 1.5 Access Issues

No access issues identified. The project is a read-only analysis requiring only repository read access, which was fully available throughout the investigation.

### 1.6 Recommended Next Steps

1. **[High]** Human review of the analysis document for technical accuracy — verify that all 5 investigative answers correctly describe the runtime behavior
2. **[Medium]** Cross-reference document line numbers against the latest upstream commit to ensure no drift has occurred
3. **[Medium]** Peer review of scenario walkthroughs (Sections 8.1–8.3) to confirm logical correctness
4. **[Low]** Consider adding a CI check that validates referenced line numbers against actual source (optional long-term improvement)

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Code analysis and investigation | 8 | Deep analysis of `pkg/decoders/`, `pkg/engine/engine.go`, `pkg/engine/ahocorasick/`, `pkg/detectors/`, `pkg/pb/detectorspb/` — reading and tracing all relevant code paths |
| Q1: Decoder type reporting (Section 3) | 3 | Traced all 4 decoders (UTF8, Base64, UTF16, EscapedUnicode), documented `DefaultDecoders()` ordering, chunk mutation behavior, and `DecoderType` assignment |
| Q2: Overlap detection analysis (Section 4) | 3 | Traced Aho-Corasick matching, routing decision at `engine.go:796`, `verificationOverlapWorker`, and `likelyDuplicate` function |
| Q3: Deduplication behavior (Section 5) | 3 | Analyzed LRU cache structure, key construction at `engine.go:1216`, cache check logic at `engine.go:1217-1221`, documented truth table |
| Q4: Temporal ordering (Section 6) | 2 | Documented 5-stage pipeline sequence, established overlap detection precedes deduplication |
| Q5: Variable result count (Section 7) | 3 | Three scenarios with edge cases (cache eviction, `CleanResults`, concurrency effects) |
| Scenario walkthroughs (Section 8) | 2 | Step-by-step tables for Scenarios A, B, C with exact code references per step |
| Architecture diagrams | 1 | Mermaid flowchart of full pipeline data flow |
| Code reference appendix (Section 9) | 1 | 37-row reference table mapping components to file:line locations |
| Document structure and formatting | 1 | Table of contents, section organization, Markdown formatting, internal cross-references |
| Validation fix (commit 081ffbac) | 1 | Corrected Base64 threshold comparison semantics (`count > threshold` not `>=`) and Keywords() line range |
| Compilation and test verification | 0.5 | `go build ./...` verified, 189 tests executed and confirmed passing |
| Cleanup and compliance verification | 0.5 | Verified no temp files, no source modifications, clean git status |
| **Total Completed** | **29** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human review of analysis accuracy and technical correctness | 2 | Medium |
| Cross-reference line numbers against latest upstream commit | 1 | Low |
| Peer review of technical conclusions and scenario walkthroughs | 1 | Low |
| **Total Remaining** | **4** | |

**Validation**: 29 (completed) + 4 (remaining) = 33 (total project hours) ✅

---

## 3. Test Results

All tests listed below were executed by Blitzy's autonomous validation system during the project validation phase. No tests were modified or added — these are existing repository tests that validate the subsystems analyzed in the document.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Decoder Unit Tests (`pkg/decoders`) | Go `testing` | 54 | 54 | 0 | N/A | TestBase64_FromChunk (13 subtests), TestUnicodeEscape_FromChunk (5), TestUTF16Decoder (4), TestDLL (1), TestUTF8_FromChunk_ValidUTF8 (5), TestUTF8_FromChunk_InvalidUTF8 (21) |
| Engine Unit Tests (`pkg/engine`) | Go `testing` | 114 | 114 | 0 | N/A | Includes TestEngine_DuplicateSecrets, TestVerificationOverlapChunk, TestVerificationOverlapChunkFalsePositive, TestLikelyDuplicate (6 subtests), TestRetainFalsePositives, TestFragmentLineOffset, TestEngineLineVariations, and more |
| Aho-Corasick Unit Tests (`pkg/engine/ahocorasick`) | Go `testing` | 21 | 21 | 0 | N/A | TestAhoCorasickCore_MultipleCustomDetectorsMatchable, TestAhoCorasickCore_MultipleDetectorVersionsMatchable, TestAhoCorasickCore_NoDuplicateDetectorsMatched, TestFindDetectorMatches (17 subtests) |
| Build Verification | Go compiler | 1 | 1 | 0 | N/A | `CGO_ENABLED=0 go build ./...` — full codebase compilation, exit code 0 |
| **Totals** | | **190** | **190** | **0** | | **100% pass rate** |

---

## 4. Runtime Validation & UI Verification

### Compilation Status
- ✅ `CGO_ENABLED=0 go build ./...` — Full codebase compiles cleanly with exit code 0
- ✅ Go 1.24.2 toolchain available and operational

### Test Execution Status
- ✅ `pkg/decoders` — 54/54 tests passing (decoder pipeline fully operational)
- ✅ `pkg/engine` — 114/114 tests passing (engine subsystems including deduplication and overlap detection verified)
- ✅ `pkg/engine/ahocorasick` — 21/21 tests passing (keyword matching operational)

### Document Integrity Verification
- ✅ All code references in `trufflehog_e42153d44a5e.md` verified against actual source files
- ✅ `pkg/decoders/decoders.go:8-16` — DefaultDecoders ordering confirmed
- ✅ `pkg/engine/engine.go:1210-1221` — Deduplication key construction and cache check logic confirmed
- ✅ `pkg/engine/engine.go:777-800` — scannerWorker decoder iteration and routing confirmed
- ✅ `pkg/engine/engine.go:887-922` — likelyDuplicate function confirmed
- ✅ `pkg/engine/engine.go:1152-1187` — processResult DecoderType stamping confirmed
- ✅ `pkg/pb/detectorspb/detectors.pb.go:23-30` — DecoderType enum values confirmed
- ✅ `pkg/decoders/base64.go:67` — chunk.Data mutation confirmed

### Repository Integrity
- ✅ Working tree clean — no uncommitted changes
- ✅ Only 1 file changed from base branch: `blitzy/documentation/trufflehog_e42153d44a5e.md` (CREATED)
- ✅ No temporary test data files remaining
- ✅ No out-of-scope source file modifications

### UI Verification
- ⚠ Not applicable — This is a CLI-based Go application with no UI components. The deliverable is a Markdown document, not a UI feature.

---

## 5. Compliance & Quality Review

| Requirement | Source | Status | Evidence |
|-------------|--------|--------|----------|
| Create `trufflehog_e42153d44a5e.md` in `blitzy/documentation/` | AAP §0.1.2, SWE-AtlasQnA-Repo rule | ✅ Pass | File exists: `blitzy/documentation/trufflehog_e42153d44a5e.md` (673 lines) |
| Answer Q1: Decoder type reporting | AAP §0.1.1 | ✅ Pass | Document Section 3.5 provides complete answer with code references |
| Answer Q2: Overlap detection trigger conditions | AAP §0.1.1 | ✅ Pass | Document Section 4.5 provides complete answer with code references |
| Answer Q3: Deduplication behavior | AAP §0.1.1 | ✅ Pass | Document Section 5.4 provides complete answer with truth table |
| Answer Q4: Temporal ordering | AAP §0.1.1 | ✅ Pass | Document Section 6.2 provides complete answer with stage comparison table |
| Answer Q5: Variable result count | AAP §0.1.1 | ✅ Pass | Document Section 7.6 provides complete answer with edge cases |
| No source file modifications | AAP §0.1.2, §0.7.1 | ✅ Pass | `git diff --name-status` shows only 1 file (A = added), no M (modified) or D (deleted) entries |
| Evidence-based answers with file:line references | AAP §0.7.1 | ✅ Pass | Document contains 37-row code reference appendix; all sections reference specific files and line numbers |
| Cleanup of temporary test data | AAP §0.1.2, §0.7.1 | ✅ Pass | `git status` shows clean working tree; no temp files found |
| Markdown formatting consistent with `docs/` conventions | AAP §0.7.2 | ✅ Pass | Document uses proper headings, tables, code blocks, Mermaid diagrams |
| Scenario walkthroughs for all three cases | AAP §0.5.2 | ✅ Pass | Sections 8.1 (raw only), 8.2 (Base64 only), 8.3 (both) with step-by-step tables |
| Mermaid data flow diagrams | AAP §0.4.2 | ✅ Pass | Section 2.1 contains full pipeline flowchart |
| Full codebase compiles | Validation gate | ✅ Pass | `CGO_ENABLED=0 go build ./...` exit code 0 |
| All relevant tests pass | Validation gate | ✅ Pass | 189 tests passed, 0 failed across decoders, engine, ahocorasick |

### Fixes Applied During Validation

| Fix | Commit | Description |
|-----|--------|-------------|
| Base64 threshold semantics correction | `081ffbac` | Corrected the document's description of Base64 `getSubstringsOfCharacterSet` to accurately reflect the strict greater-than comparison (`count > threshold`) instead of greater-than-or-equal, and corrected the `Keywords()` line range reference |

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Line number references become stale after upstream commits | Technical | Medium | Medium | Document references specific line ranges; future upstream changes to `pkg/engine/engine.go` or `pkg/decoders/*.go` may shift these | Open — requires human monitoring |
| Analysis conclusions based on static code reading, not runtime instrumentation | Technical | Low | Low | All conclusions are traceable to specific code paths and verified against existing tests; runtime instrumentation would provide additional confidence but is not strictly necessary | Accepted |
| No sensitive data in the analysis document | Security | Low | Low | Document uses placeholder AWS key formats (e.g., `AKIA2OGYBAH6STMMNXNN`) from existing test fixtures, not real credentials | Mitigated |
| Document does not cover future engine refactors | Operational | Low | Medium | The analysis is a point-in-time snapshot of the codebase at the current commit; if the deduplication or overlap logic is refactored, the document will need updating | Accepted |
| No integration testing of the document's claims against a live TruffleHog scan | Integration | Low | Low | Existing unit tests (`TestEngine_DuplicateSecrets`, `TestVerificationOverlapChunk`, `TestLikelyDuplicate`) validate the same code paths analyzed in the document | Accepted |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 29
    "Remaining Work" : 4
```

**Completed**: 29 hours (87.9%) — All AAP deliverables implemented
**Remaining**: 4 hours (12.1%) — Human review and verification tasks

### Remaining Hours by Category

| Category | Hours |
|----------|-------|
| Human review of analysis accuracy | 2 |
| Cross-reference line numbers against upstream | 1 |
| Peer review of technical conclusions | 1 |
| **Total** | **4** |

---

## 8. Summary & Recommendations

### Achievements

The project successfully delivered a comprehensive 673-line investigative analysis document answering all five questions about TruffleHog v3's decoder pipeline, verification overlap detection, and result deduplication cache. The document is thoroughly evidence-based, with every conclusion traceable to specific source file and line number references. The analysis covers the complete pipeline flow from chunk ingestion through decoder iteration, Aho-Corasick matching, overlap detection routing, detector execution, result processing, and deduplication — providing detailed scenario walkthroughs for three distinct input configurations.

### Completion Status

The project is **87.9% complete** (29 hours completed out of 33 total hours). All AAP-scoped autonomous work has been delivered. The remaining 4 hours consist of human review and verification tasks that cannot be performed autonomously.

### Remaining Gaps

The remaining work is limited to standard human review activities:
- Technical accuracy review of the analysis conclusions (2 hours)
- Line number cross-referencing against the latest upstream commit (1 hour)
- Peer review of scenario walkthroughs and edge case analysis (1 hour)

### Critical Path to Production

1. **Technical review**: A developer familiar with TruffleHog's engine internals should review the document's 5 answers and verify they match their understanding of the runtime behavior.
2. **Line number verification**: If any upstream commits have modified the analyzed files since the analysis was performed, the line number references should be spot-checked.
3. **Merge**: Once reviewed, the PR can be merged. No deployment, infrastructure, or configuration changes are required.

### Production Readiness Assessment

The deliverable is **ready for human review and merge**. The document compiles (Markdown renders correctly), all referenced source code compiles cleanly, all 189 relevant tests pass, and no source files were modified. The working tree is clean with no temporary artifacts.

---

## 9. Development Guide

### System Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.24.2 (toolchain) / 1.23.1 (module) | Build and test the TruffleHog codebase |
| Git | 2.x+ | Version control |
| Linux/macOS | Any modern version | Development environment |

### Environment Setup

```bash
# 1. Clone the repository and switch to the feature branch
git clone <repository-url>
cd trufflehog
git checkout blitzy-6aecf900-2897-44e9-9027-7572f9626d9a

# 2. Verify Go installation
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
go version
# Expected output: go version go1.24.2 linux/amd64
```

### Dependency Installation

```bash
# Go modules are managed automatically. Verify dependencies:
go mod verify
# Expected output: all modules verified
```

### Build Verification

```bash
# Compile the entire codebase (no CGO for portability)
CGO_ENABLED=0 go build ./...
# Expected output: (no output on success, exit code 0)
```

### Test Execution

```bash
# Run all relevant tests for the analyzed subsystems
CGO_ENABLED=0 go test -timeout=5m -count=1 -v ./pkg/decoders/... ./pkg/engine/... ./pkg/engine/ahocorasick/...

# Run only the investigation-specific tests
CGO_ENABLED=0 go test -timeout=5m -v -run "TestEngine_DuplicateSecrets|TestVerificationOverlapChunk|TestLikelyDuplicate" ./pkg/engine/...
```

### Viewing the Deliverable

```bash
# View the analysis document
cat blitzy/documentation/trufflehog_e42153d44a5e.md

# Or use any Markdown viewer/renderer for better formatting
# The document includes Mermaid diagrams that render in GitHub/GitLab
```

### Verification Steps

```bash
# 1. Verify only the expected file was changed
git diff --name-status origin/trufflehog_e42153d44a5e...HEAD
# Expected: A    blitzy/documentation/trufflehog_e42153d44a5e.md

# 2. Verify no source files were modified
git diff --name-status origin/trufflehog_e42153d44a5e...HEAD | grep -v "^A"
# Expected: (no output — only additions, no modifications)

# 3. Verify clean working tree
git status
# Expected: nothing to commit, working tree clean

# 4. Verify document line count
wc -l blitzy/documentation/trufflehog_e42153d44a5e.md
# Expected: 673 blitzy/documentation/trufflehog_e42153d44a5e.md
```

### Troubleshooting

| Issue | Resolution |
|-------|------------|
| `go: command not found` | Ensure Go is installed and `$PATH` includes `/usr/local/go/bin` |
| Build fails with CGO errors | Use `CGO_ENABLED=0` prefix for all build/test commands |
| Tests timeout | Increase timeout: `-timeout=10m` |
| Mermaid diagrams not rendering | Use a Markdown viewer that supports Mermaid (GitHub, GitLab, VS Code with extension) |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `CGO_ENABLED=0 go build ./...` | Compile entire codebase without CGO |
| `CGO_ENABLED=0 go test -timeout=5m -count=1 ./pkg/decoders/...` | Run decoder tests |
| `CGO_ENABLED=0 go test -timeout=5m -count=1 ./pkg/engine/...` | Run engine tests |
| `CGO_ENABLED=0 go test -timeout=5m -count=1 ./pkg/engine/ahocorasick/...` | Run Aho-Corasick tests |
| `CGO_ENABLED=0 go test -timeout=5m -v -run "TestEngine_DuplicateSecrets" ./pkg/engine/...` | Run specific deduplication test |
| `CGO_ENABLED=0 go test -timeout=5m -v -run "TestVerificationOverlapChunk" ./pkg/engine/...` | Run specific overlap test |
| `CGO_ENABLED=0 go test -timeout=5m -v -run "TestLikelyDuplicate" ./pkg/engine/...` | Run specific similarity test |
| `git diff --name-status origin/trufflehog_e42153d44a5e...HEAD` | Verify changed files |
| `git status` | Verify clean working tree |

### B. Port Reference

Not applicable — this project does not introduce or modify any network services.

### C. Key File Locations

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **Deliverable** — Investigative analysis document (673 lines) |
| `pkg/decoders/decoders.go` | Decoder interface, DefaultDecoders() ordering |
| `pkg/decoders/utf8.go` | PLAIN decoder implementation |
| `pkg/decoders/base64.go` | BASE64 decoder implementation (chunk mutation at line 67) |
| `pkg/decoders/utf16.go` | UTF16 decoder implementation |
| `pkg/decoders/escaped_unicode.go` | EscapedUnicode decoder implementation |
| `pkg/engine/engine.go` | Core engine: scannerWorker, detectorWorker, verificationOverlapWorker, notifierWorker, dedupeCache |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Aho-Corasick keyword matching and detector dispatch |
| `pkg/detectors/detectors.go` | Result, ResultWithMetadata structs, CleanResults, CopyMetadata |
| `pkg/detectors/aws/access_keys/accesskey.go` | AWS access key detector (Keywords, idPat regex) |
| `pkg/pb/detectorspb/detectors.pb.go` | DecoderType protobuf enum |
| `main.go` | CLI entrypoint, `--allow-verification-overlap` flag |

### D. Technology Versions

| Technology | Version | Source |
|------------|---------|--------|
| Go (module) | 1.23.1 | `go.mod` line 3 |
| Go (toolchain) | 1.24.2 | `go.mod` line 5 |
| `hashicorp/golang-lru/v2` | v2.0.7 | `go.mod` — LRU cache for deduplication |
| `adrg/strutil` | v0.3.1 | `go.mod` — Levenshtein similarity for overlap detection |
| `BobuSumisu/aho-corasick` | v1.0.0 | `go.mod` — Aho-Corasick trie for keyword matching |
| `google.golang.org/protobuf` | v1.36.6 | `go.mod` — Protobuf runtime |

### E. Environment Variable Reference

| Variable | Purpose | Default |
|----------|---------|---------|
| `CGO_ENABLED` | Disable CGO for cross-platform builds | Set to `0` for all build/test commands |
| `PATH` | Must include Go binary directory | `/usr/local/go/bin:$HOME/go/bin:$PATH` |

### G. Glossary

| Term | Definition |
|------|------------|
| **DecoderType** | Protobuf enum indicating which decoder produced a result (PLAIN=1, BASE64=2, UTF16=3, ESCAPED_UNICODE=4) |
| **DecodableChunk** | Wrapper struct containing a source chunk and the DecoderType label from the decoder that processed it |
| **dedupeCache** | LRU cache in the notifier worker that prevents the same logical secret from being reported multiple times |
| **Deduplication key** | String composed of `DetectorType + Raw + RawV2 + SourceMetadata` — deliberately excludes DecoderType |
| **Overlap detection** | Mechanism that identifies when multiple detectors claim the same secret in the same chunk, preventing redundant verification |
| **likelyDuplicate** | Function using Levenshtein distance (threshold 0.9) to detect near-duplicate secrets across different detector types |
| **scannerWorker** | Engine goroutine that iterates decoders, performs Aho-Corasick matching, and routes chunks to overlap or detector channels |
| **notifierWorker** | Final pipeline stage that applies deduplication and dispatches results to the output |
| **verificationOverlapWorker** | Pipeline stage that handles chunks matched by multiple detectors, running detection without verification first |
| **Aho-Corasick** | Multi-pattern string matching algorithm used for efficient keyword prefiltering before detector execution |
| **errOverlap** | Sentinel error value attached to results where verification was skipped due to cross-detector overlap |