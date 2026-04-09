# Blitzy Project Guide — TruffleHog v3 Detection Architecture Documentation

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a comprehensive, code-grounded architecture exploration document for TruffleHog v3's internal detection system. The sole deliverable is a single Markdown file (`blitzy/documentation/trufflehog-detection-architecture-qna.md`) that answers five interconnected architectural questions for developers onboarding to the TruffleHog codebase: (1) detection startup and registration, (2) verification HTTP infrastructure, (3) JSON output schema, (4) repository traversal logic, and (5) detector architecture (plugin vs. embedded). The document is derived exclusively from static source code analysis with 78 source citations, 4 Mermaid diagrams, and zero modifications to the existing repository.

### 1.2 Completion Status

**Completion: 89.3%** (25 of 28 total hours completed)

| Metric | Value |
|--------|-------|
| **Total Project Hours** | 28 |
| **Completed Hours (AI)** | 25 |
| **Remaining Hours** | 3 |
| **Completion Percentage** | 89.3% |

**Calculation:** 25 completed hours / (25 completed + 3 remaining) = 25 / 28 = **89.3%**

```mermaid
pie title Project Completion Status
    "Completed (25h)" : 25
    "Remaining (3h)" : 3
```

### 1.3 Key Accomplishments

- ✅ Created 1028-line comprehensive architecture exploration document answering all 5 architectural questions
- ✅ 78 source citations with exact file paths and line numbers, all verified against the codebase
- ✅ 4 Mermaid diagrams: engine startup flow, verification concurrency model, file handling decision tree, detection pipeline
- ✅ Complete JSON output schema table documenting all 16 fields from `pkg/output/json.go`
- ✅ Verified 857 compiled-in detectors cataloged from `pkg/engine/defaults/defaults.go`
- ✅ Zero source code modifications — only the documentation file was added under `blitzy/documentation/`
- ✅ Code review fixes applied in second commit addressing 10 findings
- ✅ Working tree clean, branch pushed to origin

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Line numbers may drift if source code is modified | Low — citations become stale but document logic remains valid | Human Developer | Ongoing maintenance |

### 1.5 Access Issues

No access issues identified. The documentation file is a standalone Markdown file committed to the `blitzy/documentation/` directory. No external services, credentials, or special permissions are required.

### 1.6 Recommended Next Steps

1. **[High]** Review the documentation for technical accuracy and completeness against the current codebase state
2. **[High]** Verify Mermaid diagrams render correctly in GitHub's Markdown viewer
3. **[Medium]** Spot-check 5–10 source citations (file:line references) against the latest `main` branch
4. **[Low]** Apply any editorial or formatting refinements based on team style preferences
5. **[Low]** Consider linking the new document from `README.md` or `CONTRIBUTING.md` for discoverability

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Source Code Analysis & Discovery | 5.0 | Read and analyzed 20+ source files (main.go, pkg/engine/engine.go, pkg/engine/defaults/defaults.go, pkg/detectors/detectors.go, pkg/detectors/http.go, pkg/output/json.go, pkg/handlers/handlers.go, pkg/engine/ahocorasick/ahocorasickcore.go, pkg/config/config.go, pkg/decoders/decoders.go, pkg/feature/feature.go, and more) to extract architectural details |
| Section 1: Detection Architecture & Startup | 4.0 | Documented build process, init()/main()/run() startup sequence, NewEngine(), setDefaults(), DefaultDetectors() compiled-in registry, initialize(), and initialization messages table (13 sub-items) |
| Section 2: Verification Setup | 3.0 | Documented HTTP dependencies, dual HTTP client model, transport configuration, DefaultResponseTimeout, local IP blocking, parallel verification via N×8 detector workers, worker counts table, and verification caching (10 sub-items) |
| Section 3: Output Structure | 2.5 | Extracted complete 16-field JSON schema from pkg/output/json.go, documented Result and ResultWithMetadata structs, source metadata oneof, and created annotated JSON skeleton (7 sub-items) |
| Section 4: Repository Traversal | 3.0 | Documented Source→Unit→Chunk decomposition, HandleFile() entry point, MIME detection, selectHandler() routing, 30 skipArchiverMimeTypes entries, feature flags, archive handling, decoder pipeline, and verbose log messages (11 sub-items) |
| Section 5: Detector Architecture | 3.0 | Documented embedded vs. plugin answer, Detector interface, 7 optional interfaces, Aho-Corasick keyword prefiltering, 857 detector catalog, custom detectors via --config, and CLI help flags (8 sub-items) |
| Summary, Cross-References & Introduction | 1.0 | Created introduction with methodology/conventions, summary table answering all 5 questions, and cross-references to existing docs (concurrency.md, process_flow.md, CONTRIBUTING.md, CUSTOM_DETECTORS.md) |
| Quality Verification & Code Review | 2.0 | Verified all 78 source citations against actual codebase, confirmed line numbers match function definitions, applied 10 code review fixes in second commit |
| Mermaid Diagrams & Formatting | 1.5 | Created 4 Mermaid diagrams (engine startup flowchart, verification sequence diagram, file handling decision tree, detection pipeline flowchart) with GitHub-compatible syntax |
| **Total Completed** | **25.0** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human review of documentation accuracy and completeness | 1.5 | High |
| Line number refresh verification against latest codebase | 0.5 | Medium |
| Mermaid diagram rendering verification in GitHub | 0.5 | Medium |
| Editorial and formatting refinements from review | 0.5 | Low |
| **Total Remaining** | **3.0** | |

---

## 3. Test Results

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Documentation Accuracy | Manual Line Verification | 78 | 78 | 0 | 100% | All 78 source citations (file:line references) were verified against actual codebase content by Blitzy's validation agent |
| Content Completeness | AAP Checklist | 5 | 5 | 0 | 100% | All 5 architectural questions answered with code evidence, rationale, and Mermaid diagrams |
| Mermaid Syntax | Static Analysis | 4 | 4 | 0 | 100% | All 4 Mermaid diagram blocks validated for syntax correctness (flowchart TD, sequenceDiagram) |
| Repository Integrity | Git Diff | 1 | 1 | 0 | 100% | Confirmed zero source repository files modified; only `blitzy/documentation/` file added |

**Note:** This is a documentation-only task. No compilation, unit tests, integration tests, or runtime validation were applicable. The tests above reflect Blitzy's autonomous validation activities for documentation quality assurance.

---

## 4. Runtime Validation & UI Verification

This is a **documentation-only project** — no application runtime, API endpoints, or UI components were created or modified.

**Runtime Health:**
- ✅ Git repository state: clean working tree, branch up-to-date with origin
- ✅ Documentation file: 1028 lines, 50,850 bytes, properly formatted Markdown
- ✅ No temporary files or artifacts left in repository

**UI Verification:**
- N/A — No UI components in scope

**API Integration:**
- N/A — No API endpoints in scope

---

## 5. Compliance & Quality Review

| AAP Requirement | Status | Evidence |
|----------------|--------|----------|
| Create `blitzy/documentation/<name>.md` per SWE-AtlasQnA-Repo rule | ✅ Pass | File created at `blitzy/documentation/trufflehog-detection-architecture-qna.md` |
| Answer all 5 architectural questions | ✅ Pass | Sections 1–5 each address one question with code evidence and rationale |
| Base answers on code as truth, no assumptions | ✅ Pass | 78 source citations with file:line references, all verified against codebase |
| Provide thinking/rationale behind answers | ✅ Pass | Each section includes "Thinking/Rationale" paragraphs explaining why conclusions follow from code evidence |
| Do not modify any existing repository files | ✅ Pass | `git diff --name-status` shows only `A blitzy/documentation/trufflehog-detection-architecture-qna.md` |
| Clean up temporary scripts | ✅ Pass | No temporary scripts were created; working tree is clean |
| Include Mermaid diagrams (minimum 4) | ✅ Pass | 4 Mermaid diagrams: startup flow, verification concurrency, file handling, detection pipeline |
| Complete JSON schema table (16 fields) | ✅ Pass | Section 3.1 contains full 16-field table extracted from `pkg/output/json.go:27-74` |
| Cross-reference existing docs | ✅ Pass | Cross-references section cites `docs/concurrency.md`, `docs/process_flow.md`, `CONTRIBUTING.md`, `pkg/custom_detectors/CUSTOM_DETECTORS.md`, `examples/generic.yml` |
| Follow existing documentation style | ✅ Pass | Uses Mermaid syntax, heading hierarchy, fenced code blocks matching `docs/concurrency.md` conventions |
| Source citations use `Source: filepath:LineRange` format | ✅ Pass | Consistent citation format used throughout all sections |
| Terminology matches codebase | ✅ Pass | Uses "chunk", "detector", "source", "scanner worker" matching code nomenclature |

**Autonomous Fixes Applied:**
- Second commit (`a9832e00`) addressed 10 code review findings including citation accuracy refinements and formatting improvements

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Line numbers drift as source code evolves | Technical | Low | High | Document includes disclaimer noting line numbers are point-in-time; periodic refresh recommended | Open |
| Mermaid diagrams may not render in all Markdown viewers | Technical | Low | Low | Diagrams use standard GitHub-compatible Mermaid syntax; tested for syntax validity | Mitigated |
| Documentation becomes stale after major refactors | Operational | Medium | Medium | Cross-references to existing docs provide anchor points; recommend linking from CONTRIBUTING.md | Open |
| New detectors added without updating document's 857 count | Operational | Low | High | Document notes the count is point-in-time; consider adding automated count verification | Open |
| No security risks | Security | N/A | N/A | Documentation-only task; no code execution, no credentials, no network access | N/A |
| No integration risks | Integration | N/A | N/A | Standalone document with no external dependencies or integrations | N/A |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 25
    "Remaining Work" : 3
```

**Remaining Work Distribution:**

| Category | Hours |
|----------|-------|
| Human review of accuracy | 1.5 |
| Line number refresh | 0.5 |
| Mermaid rendering verification | 0.5 |
| Editorial refinements | 0.5 |
| **Total** | **3.0** |

---

## 8. Summary & Recommendations

### Achievement Summary

The project has achieved **89.3% completion** (25 of 28 total hours). The sole AAP deliverable — a comprehensive architecture exploration document for TruffleHog v3 — has been fully authored, verified, and committed. The document is 1028 lines covering all 5 architectural questions with 78 verified source citations, 4 Mermaid diagrams, a complete 16-field JSON output schema, and cross-references to existing documentation.

### Remaining Gaps

The 3 remaining hours represent path-to-production human review tasks: verifying documentation accuracy against the latest codebase (1.5h), confirming Mermaid diagram rendering in GitHub (0.5h), refreshing line numbers if code has changed (0.5h), and applying minor editorial fixes (0.5h). No AAP-scoped implementation work remains incomplete.

### Critical Path to Production

1. **Human technical review** — A developer familiar with TruffleHog's internals should review the document for accuracy, particularly the startup sequence walkthrough and verification concurrency model description
2. **GitHub rendering check** — Open the file in GitHub's web interface to verify all 4 Mermaid diagrams render correctly
3. **Merge PR** — Once review is complete, merge to make the document available to onboarding developers

### Production Readiness Assessment

The documentation deliverable is **ready for human review and merge**. All AAP requirements are satisfied: questions answered with code evidence, rationale provided, source citations verified, repository unchanged, and no temporary artifacts remaining. The document follows the established repository documentation conventions and requires only human validation before production use.

---

## 9. Development Guide

### 9.1 System Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Git | 2.x+ | Repository access and version control |
| Markdown viewer | Any | Viewing the documentation (GitHub renders natively) |
| Go | 1.23.1+ | Only needed if verifying source code references (not for the documentation itself) |

### 9.2 Repository Setup

```bash
# Clone the repository
git clone https://github.com/blitzy-research/trufflehog.git
cd trufflehog

# Switch to the feature branch
git checkout blitzy-8bbaed72-c2a0-4d0f-9d6b-e9fd9a541e89
```

### 9.3 Viewing the Documentation

The deliverable is located at:

```bash
# View the documentation file
cat blitzy/documentation/trufflehog-detection-architecture-qna.md

# Check file size and line count
wc -l blitzy/documentation/trufflehog-detection-architecture-qna.md
# Expected output: 1028 lines
```

For proper Mermaid diagram rendering, open the file in GitHub's web interface or use a Mermaid-capable Markdown previewer (e.g., VS Code with Mermaid extension).

### 9.4 Verifying Source Citations

To spot-check source citations referenced in the document:

```bash
# Example: Verify the init() function location
sed -n '259,261p' main.go
# Expected: func init() {

# Example: Verify NewEngine() location
sed -n '226,228p' pkg/engine/engine.go
# Expected: func NewEngine(ctx context.Context, cfg *Config) (*Engine, error) {

# Example: Verify detector count
grep -c 'Scanner{}' pkg/engine/defaults/defaults.go
# Expected: 857

# Example: Verify Detector interface
sed -n '19,29p' pkg/detectors/detectors.go
# Expected: type Detector interface { ... }

# Example: Verify JSON schema struct
sed -n '27,40p' pkg/output/json.go
# Expected: anonymous struct with SourceMetadata, SourceID, etc.
```

### 9.5 Verifying Repository Integrity

```bash
# Confirm only documentation file was changed
git diff --name-status origin/trufflehog_e42153d44a5e...HEAD
# Expected: A  blitzy/documentation/trufflehog-detection-architecture-qna.md

# Confirm clean working tree
git status
# Expected: nothing to commit, working tree clean

# Confirm no source files were modified
git diff origin/trufflehog_e42153d44a5e...HEAD --name-only | grep -v '^blitzy/'
# Expected: no output (empty)
```

### 9.6 Verifying Mermaid Diagrams

Count Mermaid diagram blocks:

```bash
grep -c '```mermaid' blitzy/documentation/trufflehog-detection-architecture-qna.md
# Expected: 4
```

The 4 diagrams are:
1. **Engine Startup Flow** — flowchart showing init() → main() → run() → NewEngine() → Start()
2. **Verification Concurrency Model** — sequence diagram showing parallel detector workers
3. **File Handling Decision Tree** — flowchart showing MIME detection → handler selection
4. **Detection Pipeline** — flowchart showing chunk → decoders → Aho-Corasick → detectors

### 9.7 Troubleshooting

| Issue | Resolution |
|-------|------------|
| Mermaid diagrams not rendering | Use GitHub web UI or install VS Code Mermaid extension; diagrams use standard `flowchart TD` and `sequenceDiagram` syntax |
| Line numbers don't match | Source code may have been modified since documentation was written; re-verify using `grep -n` to find current line numbers |
| File not found at expected path | Ensure you're on branch `blitzy-8bbaed72-c2a0-4d0f-9d6b-e9fd9a541e89`; file is at `blitzy/documentation/trufflehog-detection-architecture-qna.md` |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `git diff --name-status origin/trufflehog_e42153d44a5e...HEAD` | View all files changed on this branch |
| `wc -l blitzy/documentation/trufflehog-detection-architecture-qna.md` | Count documentation lines (expected: 1028) |
| `grep -c 'Scanner{}' pkg/engine/defaults/defaults.go` | Count compiled-in detectors (expected: 857) |
| `grep -c 'Source:' blitzy/documentation/trufflehog-detection-architecture-qna.md` | Count source citations (expected: 78) |
| `grep -c '```mermaid' blitzy/documentation/trufflehog-detection-architecture-qna.md` | Count Mermaid diagrams (expected: 4) |

### B. Key File Locations

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog-detection-architecture-qna.md` | **The deliverable** — architecture exploration document |
| `main.go` | TruffleHog CLI entrypoint (referenced extensively in Section 1) |
| `pkg/engine/engine.go` | Scan engine core (referenced in Sections 1, 2) |
| `pkg/engine/defaults/defaults.go` | Compiled-in detector registry (857 detectors) |
| `pkg/detectors/detectors.go` | Detector interface and Result structs (referenced in Sections 3, 5) |
| `pkg/detectors/http.go` | HTTP verification infrastructure (referenced in Section 2) |
| `pkg/output/json.go` | JSON output schema definition (referenced in Section 3) |
| `pkg/handlers/handlers.go` | File handling and MIME routing (referenced in Section 4) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword prefiltering trie (referenced in Section 5) |
| `docs/concurrency.md` | Existing concurrency documentation (cross-referenced) |
| `docs/process_flow.md` | Existing process flow documentation (cross-referenced) |

### C. Technology Versions

| Technology | Version | Source |
|------------|---------|--------|
| Go | 1.23.1 | `go.mod:3` |
| Go Toolchain | go1.24.2 | `go.mod:5` |
| Kingpin CLI | v2.4.0 | `go.mod` (github.com/alecthomas/kingpin/v2) |
| Aho-Corasick | v1.0.3 | `go.mod` (github.com/BobuSumisu/aho-corasick) |
| Module Path | `github.com/trufflesecurity/trufflehog/v3` | `go.mod:1` |

### D. Glossary

| Term | Definition |
|------|------------|
| **Chunk** | The smallest data block passed to detection; contains raw bytes, source metadata, and a verify flag |
| **Detector** | A Go module implementing the `Detector` interface that scans data chunks for specific secret patterns |
| **Scanner Worker** | A goroutine that decodes chunks and performs Aho-Corasick keyword matching |
| **Detector Worker** | A goroutine that runs matched detectors on chunks and performs HTTP verification |
| **Notifier Worker** | A goroutine that dispatches verified/unverified results to output printers |
| **Aho-Corasick** | An efficient multi-pattern string matching algorithm used to pre-filter chunks before detector evaluation |
| **Source** | A top-level data location (Git repo, GitHub org, filesystem, S3 bucket, etc.) |
| **Unit** | A natural subdivision of a source (individual repo, directory, etc.) |
| **Verification** | The process of confirming a detected secret is active by making an API call to the target service |
| **SSRF** | Server-Side Request Forgery — prevented by `WithNoLocalIP()` blocking connections to private IPs |
