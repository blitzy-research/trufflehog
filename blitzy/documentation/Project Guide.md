# Blitzy Project Guide — TruffleHog v3 Runtime Architecture Documentation

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a comprehensive runtime architecture and startup flow guide for TruffleHog v3, a secret detection tool. The sole deliverable is a single Markdown document (`blitzy/documentation/trufflehog_e42153d44a5e.md`) that explains how TruffleHog behaves at runtime — from binary startup through scan completion — grounded entirely in observable behavior: trace-level log output, initialization messages, and runtime signals. The document targets developers and security engineers who need to understand TruffleHog's internal architecture without modifying source code. No existing repository files were changed; this is a purely additive documentation effort.

### 1.2 Completion Status

```mermaid
pie title Project Completion Status
    "Completed (33h)" : 33
    "Remaining (4h)" : 4
```

| Metric | Value |
|--------|-------|
| **Total Project Hours** | 37 |
| **Completed Hours (AI)** | 33 |
| **Remaining Hours** | 4 |
| **Completion Percentage** | 89.2% |

**Calculation**: 33 completed hours / (33 + 4 remaining hours) = 33/37 = **89.2% complete**

### 1.3 Key Accomplishments

- [x] Created 1,107-line comprehensive runtime architecture document covering all 11 required sections and 24 documentation topics
- [x] Built TruffleHog binary from source and captured trace-level runtime output for evidence-based documentation
- [x] Created 4 Mermaid diagrams: startup flow chart, worker pool architecture, channel data flow, shutdown cascade
- [x] Documented all major runtime phases: CLI bootstrap, configuration handling, engine initialization, detector preparation, component communication, shutdown
- [x] Included 22+ explicit source code citations linking claims to specific files and line numbers
- [x] Produced full annotated log trace with per-line source attribution and phase tagging
- [x] Applied 6 code review fixes in a follow-up commit (detector count correction, log level fixes, diagram ordering, missing log messages, table consistency, line reference accuracy)
- [x] Zero placeholder content — no TODO, FIXME, TBD, or STUB markers in the deliverable
- [x] No source code files modified — fully compliant with the observational constraint

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Human peer review of technical accuracy not yet performed | Potential inaccuracies in runtime observations on different hardware configurations | Human Reviewer | 1–2 days |
| Mermaid diagram rendering not verified on GitHub | Diagrams may have rendering edge cases in GitHub's Mermaid renderer | Human Reviewer | 0.5 day |

### 1.5 Access Issues

No access issues identified. The project is a documentation-only task that reads existing source files and captures runtime output from a locally built binary. No external services, API keys, or special permissions are required.

### 1.6 Recommended Next Steps

1. **[High]** Conduct human peer review of all source code citations and line references to verify accuracy against the current codebase version
2. **[High]** Render the Markdown file on GitHub to verify all 4 Mermaid diagrams display correctly
3. **[Medium]** Spot-check worker counts and channel buffer sizes on different CPU configurations (e.g., 4-CPU, 16-CPU) to validate the scaling formulas documented
4. **[Low]** Review prose for minor formatting improvements and typo corrections
5. **[Low]** Consider adding the document to a centralized documentation index if one is established in the future

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Build and Runtime Observation | 2 | Built TruffleHog binary from source, ran trace-level scans to capture log output, verified runtime behavior across multiple configurations |
| Source Code Analysis | 4 | Read and analyzed 12+ source files (main.go, engine.go, defaults.go, decoders.go, ahocorasickcore.go, config.go, detectors.go, log.go, level.go, context.go, feature.go, source_manager.go) for documentation content |
| Documentation Planning | 1 | Designed 11-section document structure, planned Mermaid diagrams, identified 24 documentation topics |
| Section 1: Introduction and Objective | 0.5 | Wrote methodology, scope, and observational approach description |
| Section 2: Environment Setup and Build | 1 | Documented Go toolchain requirements, build commands, and dry-run scan flags |
| Section 3: CLI Bootstrap (3 subsections) | 3 | Documented init() flag normalization and TUI detection, main() logger creation and overseer decision, run() scan lifecycle orchestration |
| Section 4: Configuration Handling (3 subsections) | 2 | Documented log level configuration with zap inversion, feature flag initialization, YAML custom detector loading |
| Section 5: Engine Initialization (4 subsections) | 3 | Documented NewEngine(), setDefaults(), initialize() with channels/cache/Aho-Corasick, and observed initialization log messages |
| Section 6: Scanning Engine Startup (3 subsections) | 2 | Documented eng.Start(), worker sizing formulas with observed counts, and channel buffer architecture |
| Section 7: Detector Preparation (4 subsections) | 2.5 | Documented ~830 detector instantiation, include/exclude filtering, Aho-Corasick core construction, and decoder chain |
| Section 8: Component Communication (6 subsections) | 3 | Documented source manager, scanner workers, detector workers, verification overlap workers, notifier workers, and false positive filtering |
| Section 9: Scan Completion (2 subsections) | 1.5 | Documented eng.Finish() cascading close sequence and final metrics summary |
| Section 10: Annotated Log Trace | 2 | Created complete annotated trace-level log output with per-line source attribution |
| Mermaid Diagrams (4 diagrams) | 2 | Created startup flow chart, worker pool architecture, channel data flow sequence, and shutdown cascade sequence diagrams |
| Thinking and Rationale Section | 1.5 | Explained architectural design decisions for worker multipliers, decoder ordering, cascading close, Aho-Corasick prefilter, and overseer |
| Code Review Fixes | 1 | Addressed 6 code review findings: detector count, log level, diagram ordering, missing messages, table columns, line references |
| Autonomous Validation | 1 | Verified all source citations, log message accuracy, Mermaid syntax, and structural completeness |
| **Total** | **33** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Human peer review of documentation technical accuracy | 2 | High |
| Mermaid diagram rendering verification on GitHub | 0.5 | High |
| Source citation spot-check against current codebase | 1 | Medium |
| Minor formatting, typo review, and prose polish | 0.5 | Low |
| **Total** | **4** | |

---

## 3. Test Results

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Runtime Verification | Manual (Go binary execution) | 6 | 6 | 0 | 100% | Binary build, trace log capture, log sequence verification, worker count validation, channel buffer verification, final metrics output |
| Source Citation Accuracy | Manual (line-by-line check) | 22 | 22 | 0 | 100% | All source file and line references verified against actual source files |
| Document Structure | Manual (heading/section audit) | 11 | 11 | 0 | 100% | All 11 required sections present with correct headings and subsections |
| Mermaid Diagram Syntax | Manual (syntax review) | 4 | 4 | 0 | 100% | All 4 diagrams use valid Mermaid flowchart/sequenceDiagram syntax |
| Placeholder Detection | Automated (grep scan) | 1 | 1 | 0 | 100% | Zero TODO/FIXME/TBD/STUB/PLACEHOLDER stubs found (2 false positives in contextual text excluded) |
| Code Review Fixes | Manual (re-validation) | 6 | 6 | 0 | 100% | All 6 findings from code review addressed and verified in follow-up commit |

**Summary**: 50 total validation checks performed, 50 passed, 0 failed. All tests originate from Blitzy's autonomous validation process.

---

## 4. Runtime Validation & UI Verification

### Runtime Health

- ✅ **Go Binary Build**: `CGO_ENABLED=0 go build -o /tmp/trufflehog .` succeeded — ~194MB binary produced
- ✅ **Version Output**: `/tmp/trufflehog --version` reports `trufflehog dev` as documented
- ✅ **Trace-Level Log Sequence**: All documented log messages observed in correct order: `trufflehog dev` → `default engine options set` → `engine initialized` → `setting up aho-corasick core` → `set up aho-corasick core` → worker startups → source execution → `finished scanning`
- ✅ **Worker Counts**: Observed 128/1024/128/128 on 128-CPU system, consistent with documented formulas (concurrency × multiplier)
- ✅ **Final Metrics Output**: Confirmed chunks, bytes, verified/unverified secrets, scan duration, and verification cache metrics all present

### Document Verification

- ✅ **File Created**: `blitzy/documentation/trufflehog_e42153d44a5e.md` (1,107 lines, 53,904 bytes)
- ✅ **Heading Structure**: 1 H1, 12 H2, 40 H3 headings — proper hierarchy confirmed
- ✅ **Code Fences**: 104 balanced fence markers (52 open/close pairs)
- ✅ **Mermaid Blocks**: 4 Mermaid diagram blocks with valid syntax
- ✅ **Source Citations**: 22 explicit `Source:` references verified
- ✅ **Table Rows**: 75 table rows across 10+ tables
- ✅ **No Placeholders**: Zero TODO/FIXME/TBD/STUB markers

### Out-of-Scope Verification

- ✅ **No Source Modifications**: `git diff --name-status origin/trufflehog_e42153d44a5e..HEAD` shows only `A blitzy/documentation/trufflehog_e42153d44a5e.md` — no existing files modified
- ✅ **Git Status Clean**: Working tree is clean, all changes committed

---

## 5. Compliance & Quality Review

| Requirement | Source | Status | Evidence |
|-------------|--------|--------|----------|
| Create `trufflehog_e42153d44a5e.md` in `blitzy/documentation/` | AAP §0.1.2, §0.5.1 | ✅ Pass | File exists at correct path (1,107 lines) |
| No source file modifications | AAP §0.1.2, §0.10 | ✅ Pass | `git diff --name-status` shows only the new file |
| Observable-evidence-only approach | AAP §0.1.1 Req 4 | ✅ Pass | All sections cite log output and runtime signals; annotated trace in Section 10 |
| Not a file-by-file summary | AAP §0.1.2, §0.10 | ✅ Pass | Narrative-driven walkthrough organized by runtime phases, not by source files |
| Cover configuration handling | AAP §0.1.1 Req 3 | ✅ Pass | Section 4 covers log levels, feature flags, YAML custom detectors |
| Cover scanning engine initialization | AAP §0.1.1 Req 3 | ✅ Pass | Section 5 covers NewEngine, setDefaults, initialize, Aho-Corasick |
| Cover detector preparation | AAP §0.1.1 Req 3 | ✅ Pass | Section 7 covers ~830 detectors, filtering, Aho-Corasick, decoder chain |
| Cover component communication | AAP §0.1.1 Req 3 | ✅ Pass | Section 8 covers source manager, 4 worker types, channel data flow |
| Include source code citations | AAP §0.4.2 | ✅ Pass | 22+ explicit citations with file names and line numbers |
| Include 4 Mermaid diagrams | AAP §0.4.3, §0.7.3 | ✅ Pass | Startup flow, worker pool, channel data flow, shutdown cascade |
| Include annotated log trace | AAP §0.7.3 | ✅ Pass | Complete trace in Section 10 with per-line annotations |
| Include Thinking/Rationale section | AAP §0.1.2, §0.10 | ✅ Pass | Section 11 covers 6 architectural design decisions |
| 24 documentation topics at 100% coverage | AAP §0.7.1 | ✅ Pass | All 24 topics from gap analysis addressed |
| Follow existing documentation style | AAP §0.10 | ✅ Pass | Mermaid diagram conventions from docs/concurrency.md applied |
| Zero placeholder content | Quality Standards | ✅ Pass | grep scan confirms no TODO/FIXME/TBD/STUB markers |

**Compliance Score**: 15/15 requirements met (100%)

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Source code line references may drift as codebase evolves | Technical | Medium | High | Include function names alongside line numbers; reviewer should spot-check against current HEAD | Open — requires ongoing maintenance |
| Mermaid diagram rendering may vary across GitHub versions | Technical | Low | Low | Use standard Mermaid syntax; avoid advanced features; verify rendering after merge | Open — verify post-merge |
| Worker counts documented for specific CPU configurations may confuse readers on different hardware | Technical | Low | Medium | Document the sizing formula explicitly alongside observed counts; include both 8-CPU and 128-CPU examples | Mitigated — both configurations shown |
| Documentation could become stale as TruffleHog evolves | Operational | Medium | High | Note the binary version ("dev") and commit context; encourage periodic updates | Open — inherent to documentation |
| No automated link/reference validation in repository | Operational | Low | Medium | Repository lacks doc linting tools; rely on human review for broken references | Open — no toolchain exists |
| Detector count (~830) is a snapshot that changes with each release | Technical | Low | High | Document as "~830" with note that count depends on version | Mitigated — approximate language used |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 33
    "Remaining Work" : 4
```

### Remaining Work Distribution

| Category | Hours | Priority |
|----------|-------|----------|
| Human peer review of technical accuracy | 2 | 🔴 High |
| Mermaid diagram rendering verification | 0.5 | 🔴 High |
| Source citation spot-check | 1 | 🟡 Medium |
| Formatting and typo review | 0.5 | 🟢 Low |
| **Total Remaining** | **4** | |

---

## 8. Summary & Recommendations

### Achievements

The Blitzy autonomous agents successfully delivered a comprehensive 1,107-line runtime architecture and startup flow guide for TruffleHog v3. The document covers all 24 documentation topics identified in the gap analysis, including CLI bootstrap, configuration handling, engine initialization, detector preparation, component communication, and scan completion. Four Mermaid diagrams, 5+ reference tables, and a fully annotated log trace provide visual and evidence-based anchors for the narrative. All content is grounded in observable runtime behavior captured from trace-level logging, with 22+ source code citations verified against actual files.

The project is **89.2% complete** (33 hours completed out of 37 total hours). All AAP-scoped deliverables have been implemented. The remaining 4 hours represent path-to-production human review tasks: peer review of technical accuracy (2h), Mermaid rendering verification (0.5h), source citation spot-check (1h), and minor formatting review (0.5h).

### Remaining Gaps

The only remaining work is human review — no features, sections, or diagrams are missing from the deliverable. The documentation accurately reflects the codebase at the time of analysis, but source line references will require periodic updates as the codebase evolves.

### Production Readiness Assessment

The documentation deliverable is **ready for human review and merge**. All autonomous validation gates passed:
- ✅ Binary built and runtime behavior verified
- ✅ All source citations validated
- ✅ Document structure complete (11 sections, 4 diagrams, 5+ tables)
- ✅ Zero placeholder content
- ✅ No source code modifications
- ✅ Clean git status with all changes committed

### Recommendations

1. **Merge after human review** — The document is complete and ready for a technical reviewer to verify accuracy
2. **Establish periodic review cadence** — Schedule documentation updates when significant engine changes are merged
3. **Consider adding doc linting** — Adding a Markdown linter or link checker to CI would catch stale references automatically
4. **Link from CONTRIBUTING.md** — Consider adding a reference to this document from the contribution guide to help new contributors understand the runtime architecture

---

## 9. Development Guide

### System Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.24.2+ (toolchain) | Build TruffleHog binary from source |
| Git | 2.x+ | Clone repository and manage branches |
| OS | Linux (tested), macOS, Windows with WSL | Runtime environment |

### Environment Setup

1. **Clone the repository**:
```bash
git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog
git checkout trufflehog_e42153d44a5e
```

2. **Verify Go toolchain**:
```bash
go version
# Expected: go version go1.24.2 linux/amd64 (or newer)
```

3. **Build the binary** (for runtime observation only — no code changes needed):
```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog .
```
Expected output: No errors. Binary created at `/tmp/trufflehog` (~194MB).

4. **Verify the build**:
```bash
/tmp/trufflehog --version
# Expected: trufflehog dev
```

### Viewing the Documentation

The documentation file is a standalone Markdown document:

```bash
# View the file
cat blitzy/documentation/trufflehog_e42153d44a5e.md

# Or open in your preferred Markdown viewer
# The Mermaid diagrams render natively on GitHub
```

### Reproducing Runtime Observations

To reproduce the trace-level runtime observations documented in the guide:

```bash
# Create a test directory
mkdir -p /tmp/test-scan

# Run a trace-level filesystem scan
/tmp/trufflehog filesystem /tmp/test-scan \
  --no-verification --no-update --local-dev --log-level=5
```

Expected output includes the full log sequence documented in Section 10 of the guide:
```
info-2  trufflehog  trufflehog dev
info-4  trufflehog  default engine options set
info-4  trufflehog  engine initialized
info-4  trufflehog  setting up aho-corasick core
info-4  trufflehog  set up aho-corasick core
info-2  trufflehog  starting scanner workers    {"count": <NumCPU>}
info-2  trufflehog  starting detector workers   {"count": <NumCPU×8>}
...
info-0  trufflehog  finished scanning  {"chunks": 0, "bytes": 0, ...}
```

### Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `go: command not found` | Install Go 1.24.2+ from https://go.dev/dl/ and add to PATH |
| Build fails with dependency errors | Run `go mod download` to fetch all dependencies |
| Mermaid diagrams not rendering | View the file on GitHub.com, which has native Mermaid support |
| Binary reports wrong version | Ensure you're building from the correct branch; `dev` is expected for local builds |
| Log output missing V(4)/V(5) messages | Ensure `--log-level=5` flag is set; lower levels hide detailed messages |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `CGO_ENABLED=0 go build -o /tmp/trufflehog .` | Build TruffleHog binary from source |
| `/tmp/trufflehog --version` | Verify binary version |
| `/tmp/trufflehog --help` | Display full CLI help with all commands and flags |
| `/tmp/trufflehog filesystem /tmp/test-scan --no-verification --no-update --local-dev --log-level=5` | Trace-level dry-run filesystem scan |
| `/tmp/trufflehog filesystem /tmp/test-scan --no-verification --no-update --local-dev --log-level=5 --json` | JSON-mode trace-level scan |
| `git diff --name-status origin/trufflehog_e42153d44a5e..HEAD` | View files changed by Blitzy agents |

### B. Port Reference

No ports are used by this documentation-only project. TruffleHog is a CLI tool that does not expose network services during filesystem scanning.

### C. Key File Locations

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **Deliverable** — Runtime architecture and startup flow guide (1,107 lines) |
| `main.go` | CLI entry point — `init()`, `main()`, `run()` functions |
| `pkg/engine/engine.go` | Engine orchestration — `NewEngine()`, `Start()`, `Finish()` |
| `pkg/engine/defaults/defaults.go` | Default detector instantiation (~830 detectors) |
| `pkg/decoders/decoders.go` | Decoder chain (UTF-8, Base64, UTF-16, EscapedUnicode) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Aho-Corasick prefilter trie construction |
| `pkg/config/config.go` | YAML custom detector configuration loading |
| `pkg/log/log.go` | Logger construction (console/JSON sinks) |
| `pkg/log/level.go` | Log level configuration with zap inversion |
| `pkg/context/context.go` | Logging-aware context propagation |
| `pkg/feature/feature.go` | Atomic feature flags |
| `pkg/sources/source_manager.go` | Source execution orchestration |
| `docs/concurrency.md` | Existing worker pool architecture diagram (reference) |
| `docs/process_flow.md` | Existing pipeline stage flowcharts (reference) |

### D. Technology Versions

| Technology | Version | Source |
|------------|---------|--------|
| Go (module) | 1.23.1 | `go.mod:L3` |
| Go (toolchain) | 1.24.2 | `go.mod:L5` |
| kingpin/v2 (CLI framework) | v2.4.0 | `go.mod` dependency |
| zap (logging) | v1.27.0 | `go.mod` dependency |
| Mermaid (diagrams) | GitHub-native | Embedded in Markdown |
| TruffleHog | v3 (dev) | Built from source |

### E. Environment Variable Reference

| Variable | Purpose | Set By |
|----------|---------|--------|
| `TUI_PARENT` | Prevents recursive TUI launches during `syscall.Exec` re-execution | `init()` in `main.go` |
| `GOMAXPROCS` | Go runtime CPU limit (auto-tuned by `maxprocs.Set()`) | `init()` in `main.go` |
| `CGO_ENABLED` | Disable CGo for static binary compilation | Build command |

### G. Glossary

| Term | Definition |
|------|-----------|
| **Aho-Corasick** | String-matching algorithm that efficiently finds all occurrences of multiple patterns in a single pass over the input text |
| **Detector** | A module that identifies a specific type of secret (e.g., AWS keys, GitHub tokens) using regex patterns and optional live verification |
| **Chunk** | The smallest scannable unit of data (e.g., file contents, git diff hunks) |
| **Unit** | A natural subdivision of a source (e.g., a directory for filesystem, a repository for GitHub) |
| **Source** | A top-level data location to scan (filesystem, git repo, GitHub org, S3 bucket, etc.) |
| **Overseer** | A process supervision library that wraps the scan function for graceful restarts and auto-updates |
| **Scanner Worker** | Goroutine that receives chunks, applies decoders, and routes to detectors via Aho-Corasick keyword matching |
| **Detector Worker** | Goroutine that applies detector-specific regex matching and optional secret verification |
| **Verification Overlap Worker** | Goroutine that handles chunks matched by multiple detectors, disabling verification to prevent conflicting API calls |
| **Notifier Worker** | Goroutine that dispatches verified/unverified results to the configured output printer |
| **V(N)** | Zap verbosity level N — higher N means more verbose; controlled by `--log-level=N` |