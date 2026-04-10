# Blitzy Project Guide — TruffleHog v3 Runtime Pipeline Documentation

---

## 1. Executive Summary

### 1.1 Project Overview

This project creates a comprehensive technical investigation document answering six questions about TruffleHog v3's internal runtime detection pipeline behavior. The deliverable is a single new Markdown file (`blitzy/documentation/trufflehog_e42153d44a5e.md`, 767 lines) containing code-grounded answers about Aho-Corasick keyword loading, decoder pipeline sequencing, verification cache metrics, worker architecture multipliers, deduplication behavior, and detector timing output. Every answer cites specific source code locations and is supplemented with empirical runtime experiment output from a TruffleHog binary built from the repository source. This documentation fills critical gaps in the project's existing documentation, which only covers high-level architecture diagrams without runtime behavior details.

### 1.2 Completion Status

```mermaid
pie title Project Completion Status
    "Completed (34h)" : 34
    "Remaining (4h)" : 4
```

| Metric | Value |
|--------|-------|
| **Total Project Hours** | 38 |
| **Completed Hours (AI)** | 34 |
| **Remaining Hours** | 4 |
| **Completion Percentage** | 89.5% |

**Calculation:** 34 completed hours / (34 + 4) total hours = 89.5% complete

### 1.3 Key Accomplishments

- [x] Created comprehensive 767-line technical Q&A investigation document at `blitzy/documentation/trufflehog_e42153d44a5e.md`
- [x] Answered all 6 investigation areas with source code citations referencing specific files and line numbers
- [x] Executed 7 runtime experiments against a freshly-built TruffleHog binary (Go 1.24.2 toolchain)
- [x] Built 3 Mermaid diagrams: decoder pipeline flow, worker architecture with multipliers, deduplication decision flow
- [x] Verified all 22 source code citations against actual repository source at exact line numbers
- [x] Applied accuracy fix: corrected shared keyword detector count from 799 to 764 (with 67 sharing detectors)
- [x] Cleaned up all temporary artifacts (compiled binary, test data, helper Go programs)
- [x] Maintained zero modifications to existing source repository files (documentation-only change)
- [x] Included "Thinking / Rationale" sections for every investigation area as required

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Source code line numbers may drift with future commits | Documentation citations become stale as codebase evolves | Human Developer | Ongoing maintenance |
| Runtime experiment values are hardware/environment-dependent | Exact timing values (e.g., 139ms for AWS detector) will differ on different machines | Human Developer | At review time |
| Documentation not integrated into existing docs framework | File exists in `blitzy/documentation/` rather than `docs/` — no cross-linking with `docs/concurrency.md` or `docs/process_flow.md` | Human Developer | 1 hour if needed |

### 1.5 Access Issues

No access issues identified. The project involves only reading existing Go source files and creating a new Markdown documentation file. No external service credentials, third-party APIs, or special repository permissions were required.

### 1.6 Recommended Next Steps

1. **[High]** Have a Go/TruffleHog domain expert review the document for technical accuracy — especially the Aho-Corasick keyword counts, deduplication semantics, and verification cache lifecycle claims
2. **[High]** Verify that runtime experiment outputs are reproducible by rebuilding the binary and re-running at least the keyword counting and worker count experiments
3. **[Medium]** Confirm that the 22 source code line number citations still map to the correct code after any recent upstream merges
4. **[Low]** Consider integrating the document into the existing `docs/` directory structure or linking from `docs/concurrency.md` and `docs/process_flow.md`
5. **[Low]** Evaluate whether the investigation document should be maintained long-term or serves as a point-in-time reference

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Source Code Analysis | 6 | Deep reading of 10+ Go source files across `pkg/engine/`, `pkg/decoders/`, `pkg/verificationcache/`, `pkg/cache/`, and `main.go` to understand runtime behavior |
| Aho-Corasick Investigation | 3 | Keyword counting via custom Go program, shared keyword analysis, documentation with code citations |
| Decoder Pipeline Investigation | 3 | Tracing decode-before-match code path in `scannerWorker`, verbose scan output capture, Mermaid diagram |
| Verification Cache Investigation | 3 | 5-metric analysis, consecutive scan testing, cache persistence disproval, enable/disable comparison |
| Worker Architecture Investigation | 3 | Multiplier default extraction from `setDefaults`, goroutine count verification via `--log-level=2`, Mermaid diagram |
| Deduplication Investigation | 2.5 | LRU key format analysis from `notifierWorker`, cross-decoder dedup testing, Mermaid decision flow diagram |
| Detector Timing Investigation | 2 | Timing scope analysis from `detectChunk`, `--print-avg-detector-time` runtime capture |
| Document Composition & Formatting | 5.5 | Writing 767-line document with 6 structured sections, 22-entry citation table, markdown tables |
| Runtime Experiments | 3.5 | Building TruffleHog binary, creating test data files, executing 7 experiments with various flag combinations |
| Validation & Quality Fixes | 2 | Citation verification against actual source, 3 fix commits addressing QA findings and accuracy correction (799→764) |
| Artifact Cleanup | 0.5 | Removing compiled binary, test data directories, helper Go programs, verifying clean working tree |
| **Total** | **34** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Technical Accuracy Review | 2 | High — Domain expert should verify Aho-Corasick counts, dedup semantics, cache lifecycle claims |
| Runtime Experiment Reproducibility | 1 | Medium — Rebuild binary and re-run key experiments to confirm terminal outputs |
| Documentation Integration Planning | 1 | Low — Decide if document should move to `docs/` or link from existing architecture docs |
| **Total** | **4** | |

---

## 3. Test Results

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|------------|-------|
| Go Dependency Installation | `go mod download` | 1 | 1 | 0 | 100% | All Go module dependencies resolved successfully |
| Binary Compilation | `go build` | 1 | 1 | 0 | 100% | TruffleHog binary compiled cleanly with Go 1.24.2 toolchain |
| Keyword Count Experiment | Custom Go program | 1 | 1 | 0 | 100% | 831 detectors, 914 unique keywords, 32 shared, 67 sharing detectors |
| Worker Count Experiment | TruffleHog CLI (`--log-level=2 --concurrency=4`) | 1 | 1 | 0 | 100% | 4 scanner, 32 detector, 4 overlap, 4 notifier workers confirmed |
| Verbose Pipeline Trace | TruffleHog CLI (`--log-level=5`) | 1 | 1 | 0 | 100% | Decode-before-match architecture confirmed in log output |
| Verification Cache Experiment | TruffleHog CLI (consecutive scans) | 1 | 1 | 0 | 100% | Identical metrics across invocations; no persistence confirmed |
| Cache Disable Experiment | TruffleHog CLI (`--no-verification-cache`) | 1 | 1 | 0 | 100% | Misses=0 when cache disabled; VerificationTimeSpentMS still tracked |
| Cross-Decoder Dedup Experiment | TruffleHog CLI (plain+Base64 test data) | 1 | 1 | 0 | 100% | Same credential via two decoders reported once (dedup working) |
| Detector Timing Experiment | TruffleHog CLI (`--print-avg-detector-time`) | 1 | 1 | 0 | 100% | Only AWS shown (only detector with results); 139ms includes verification |
| Source Citation Verification | Manual line-number comparison | 22 | 22 | 0 | 100% | All 22 source citations verified against actual file content at exact line numbers |
| **Totals** | | **31** | **31** | **0** | **100%** | All validation checks passed |

---

## 4. Runtime Validation & UI Verification

### Runtime Health

- ✅ Go dependency resolution (`go mod download`) — all modules resolved without errors
- ✅ Binary compilation (`go build -o /tmp/trufflehog .`) — compiled cleanly using Go 1.24.2 toolchain
- ✅ TruffleHog filesystem scan execution — binary executes correctly with all flag combinations tested
- ✅ Structured log output — `--log-level=2` and `--log-level=5` produce expected worker startup and pipeline trace messages
- ✅ Cache metrics output — `verification_caching` JSON block appears in scan completion log with all 5 metrics
- ✅ Detector timing output — `--print-avg-detector-time` produces per-detector timing to stderr
- ✅ JSON output mode — `--json` flag produces valid JSON with `SourceMetadata` and `DecoderName` fields
- ✅ Artifact cleanup — all temporary files confirmed removed (binary, test data, helper programs)

### Documentation Output Verification

- ✅ File created at correct path: `blitzy/documentation/trufflehog_e42153d44a5e.md`
- ✅ Document structure: 6 investigation sections + Introduction + Source Citations
- ✅ Mermaid diagrams: 3 diagrams render correctly (decoder pipeline, worker architecture, dedup flow)
- ✅ Code blocks: 18 Go code excerpts + 8 terminal output blocks
- ✅ Source citation table: 22 entries with verified file paths and line ranges
- ✅ No existing repository files modified (git diff confirms only 1 new file added)
- ✅ Git working tree clean on correct branch `blitzy-06475e0e-5bac-4000-9e57-c5c681aed6e7`

### API / Integration Verification

- ⚠ Not applicable — this is a documentation-only project with no API endpoints or service integrations

---

## 5. Compliance & Quality Review

| AAP Requirement | Status | Evidence | Notes |
|-----------------|--------|----------|-------|
| Create `blitzy/documentation/trufflehog_e42153d44a5e.md` | ✅ Pass | File exists, 767 lines, 36,822 bytes | Committed in 4 commits |
| Answer Aho-Corasick keyword loading questions | ✅ Pass | Section 1: 914 unique keywords, 32 shared, 67 sharing detectors | Verified via custom Go program |
| Answer decoder pipeline sequencing questions | ✅ Pass | Section 2: decode-before-match confirmed with code path and verbose output | Mermaid diagram included |
| Answer verification cache metrics questions | ✅ Pass | Section 3: 5 metrics documented, consecutive scans tested, no persistence | Enable/disable comparison included |
| Answer worker architecture multiplier questions | ✅ Pass | Section 4: multiplier table (1/8/1/1), 44 goroutines at concurrency=4 | Mermaid diagram included |
| Answer deduplication behavior questions | ✅ Pass | Section 5: LRU key format, cross-decoder dedup logic, Postman exception | Mermaid decision flow included |
| Answer detector timing output questions | ✅ Pass | Section 6: only detectors with results shown, verification time included | stderr output confirmed |
| Run runtime experiments with actual terminal output | ✅ Pass | 7 experiments executed, 8 terminal output blocks in document | All outputs from real binary execution |
| Include source code citations with file paths and line numbers | ✅ Pass | 22-entry citation table, 6 per-section source references | All line numbers verified against source |
| Include thinking/rationale for each answer | ✅ Pass | Every section has "Thinking / Rationale" subsection | Code-grounded reasoning chains |
| Include Mermaid diagrams | ✅ Pass | 3 diagrams: decoder pipeline, worker architecture, dedup flow | Match AAP requirement of 3+ diagrams |
| Do not modify any existing source files | ✅ Pass | `git diff --name-only` shows only 1 new file added | Zero modifications to source |
| Clean up all temporary artifacts | ✅ Pass | No temp files found at `/tmp/trufflehog*`, `/tmp/count_*.go` | Verified post-cleanup |
| Base answers on code as truth (no assumptions) | ✅ Pass | Every claim cites specific file:line references | No unsupported claims found |
| Fix accuracy issues found during validation | ✅ Pass | Corrected shared keyword detector count: 799→764 | Commit `74b9c72b` |

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Source code line numbers drift as codebase evolves | Technical | Medium | High | Document the TruffleHog commit hash (base: `f2cab56d`) against which citations were verified; re-verify after major refactors | Open — requires ongoing maintenance |
| Runtime experiment timing values are environment-dependent | Technical | Low | High | Document that exact ms values will vary by hardware; focus on qualitative conclusions (e.g., "only detectors with results") rather than exact numbers | Mitigated — doc focuses on behavioral conclusions |
| Keyword and detector counts change as new detectors are added | Technical | Low | High | Document counts are point-in-time (831 detectors, 914 keywords); include method to re-derive counts via the custom Go program approach | Mitigated — methodology documented |
| Documentation exists outside `docs/` directory structure | Operational | Low | Medium | Consider moving to `docs/` or adding a cross-reference link from existing `docs/concurrency.md` and `docs/process_flow.md` | Open — human decision needed |
| No automated CI check for documentation accuracy | Operational | Medium | Medium | Consider adding a CI step that compiles the keyword-counting program or verifies line numbers are still valid | Open — enhancement opportunity |
| Mermaid diagram rendering varies by Markdown viewer | Technical | Low | Low | Diagrams use standard Mermaid syntax compatible with GitHub, GitLab, and VS Code Mermaid plugins | Mitigated — standard syntax used |
| No sensitive data exposure in documentation | Security | Low | Low | Document contains only synthetic test credentials (`AKIAIOSFODNN7REALKEY`) used in TruffleHog's own test infrastructure; no real secrets | Mitigated — synthetic data only |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 34
    "Remaining Work" : 4
```

### Remaining Hours by Category

| Category | Hours | Priority |
|----------|-------|----------|
| Technical Accuracy Review | 2 | 🔴 High |
| Runtime Experiment Reproducibility | 1 | 🟡 Medium |
| Documentation Integration Planning | 1 | 🟢 Low |
| **Total** | **4** | |

### AAP Requirement Status

```mermaid
pie title AAP Requirement Coverage
    "Completed (14/14)" : 14
    "Partially Completed" : 0
    "Not Started" : 0
```

---

## 8. Summary & Recommendations

### Achievements

The project has successfully delivered a comprehensive 767-line technical investigation document that answers all six questions about TruffleHog v3's runtime detection pipeline behavior. The document was produced through a rigorous methodology combining deep source code analysis (10+ Go files across 5 subsystems), custom Go program execution for keyword counting, and 7 empirical runtime experiments against a freshly-compiled TruffleHog binary. Every claim in the document cites specific source code file paths and line numbers, and all 22 citations were verified against the actual repository source during validation.

The project is **89.5% complete** (34 completed hours out of 38 total hours). All AAP-specified deliverables — the 6 investigation answers, runtime experiments with terminal output, source code citations, Mermaid diagrams, thinking/rationale sections, artifact cleanup, and the zero-modification constraint — are fully completed.

### Remaining Gaps

The 4 remaining hours consist entirely of human review and integration tasks:

1. **Technical Accuracy Review (2h):** A Go/TruffleHog domain expert should verify the Aho-Corasick keyword counts (914 unique / 32 shared), deduplication cross-decoder semantics, and verification cache lifecycle claims. While all claims are code-grounded and experimentally validated, expert review adds confidence.

2. **Runtime Experiment Reproducibility (1h):** The terminal outputs captured in the document should be spot-checked by rebuilding the binary and re-running at least the keyword counting and worker count experiments to confirm consistency.

3. **Documentation Integration (1h):** The document currently lives in `blitzy/documentation/` as specified. A decision is needed on whether to integrate it into the `docs/` directory alongside `concurrency.md` and `process_flow.md`, and whether to add cross-reference links.

### Production Readiness Assessment

The documentation deliverable is **production-ready for merge.** It is a self-contained, additive-only change (1 new file, 0 modifications) with no impact on the TruffleHog codebase, build system, or test infrastructure. The document can be merged as-is and refined through subsequent PRs if the reviewer identifies any technical inaccuracies.

### Success Metrics

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Investigation areas answered | 6 | 6 | ✅ Met |
| Runtime experiments executed | ≥6 | 7 | ✅ Exceeded |
| Source code citations | ≥10 | 22 | ✅ Exceeded |
| Mermaid diagrams | ≥3 | 3 | ✅ Met |
| Existing files modified | 0 | 0 | ✅ Met |
| Temporary artifacts remaining | 0 | 0 | ✅ Met |
| Validation fix commits | — | 3 | ✅ Quality maintained |

---

## 9. Development Guide

### System Prerequisites

| Software | Minimum Version | Purpose |
|----------|----------------|---------|
| Go | 1.23.1 (toolchain 1.24.2) | Building TruffleHog binary and running keyword counting programs |
| Git | 2.x | Repository cloning and branch management |
| Markdown viewer | Any (GitHub, VS Code, etc.) | Viewing the documentation with Mermaid diagram rendering |

### Environment Setup

```bash
# Clone the repository
git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog

# Checkout the documentation branch
git checkout blitzy-06475e0e-5bac-4000-9e57-c5c681aed6e7

# Verify Go toolchain (requires Go 1.23.1+, toolchain 1.24.2)
go version
# Expected output: go version go1.24.2 linux/amd64 (or similar)
```

### Dependency Installation

```bash
# Download all Go module dependencies
go mod download

# Verify dependency integrity
go mod verify
# Expected output: all modules verified
```

### Building TruffleHog (for experiment reproduction)

```bash
# Build the binary from source
go build -o /tmp/trufflehog .

# Verify the build
/tmp/trufflehog --version
# Expected output: trufflehog dev
```

### Viewing the Documentation

```bash
# The documentation file is located at:
cat blitzy/documentation/trufflehog_e42153d44a5e.md

# For best viewing experience, open in a Markdown viewer that supports Mermaid:
# - GitHub web UI (native Mermaid support)
# - VS Code with Mermaid extension
# - GitLab web UI (native Mermaid support)
```

### Reproducing Runtime Experiments

```bash
# Create test data directory
mkdir -p /tmp/trufflehog_test_data

# Create test file with a synthetic AWS key
echo 'AKIAIOSFODNN7REALKEY' > /tmp/trufflehog_test_data/test_secret.txt
echo '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' >> /tmp/trufflehog_test_data/test_secret.txt

# Experiment 1: Worker count verification
/tmp/trufflehog filesystem --no-update --log-level=2 --concurrency=4 \
    /tmp/trufflehog_test_data
# Expected: scanner=4, detector=32, overlap=4, notifier=4

# Experiment 2: Verbose pipeline trace
/tmp/trufflehog filesystem --no-update --log-level=5 --concurrency=2 \
    --no-verification --results=verified,unverified,unknown,filtered_unverified \
    /tmp/trufflehog_test_data/test_secret.txt

# Experiment 3: Verification cache metrics
/tmp/trufflehog filesystem --no-update --results=verified,unverified,unknown \
    /tmp/trufflehog_test_data/
# Run twice — metrics should be identical (cache does not persist)

# Experiment 4: Cache disabled comparison
/tmp/trufflehog filesystem --no-update --results=verified,unverified,unknown \
    --no-verification-cache /tmp/trufflehog_test_data/
# Expected: Misses=0 (cache not instantiated)

# Experiment 5: Detector timing
/tmp/trufflehog filesystem --no-update --print-avg-detector-time \
    --results=verified,unverified,unknown /tmp/trufflehog_test_data/
# Expected: Only "AWS: <duration>" shown

# Cleanup
rm -rf /tmp/trufflehog_test_data /tmp/trufflehog
```

### Troubleshooting

| Issue | Cause | Resolution |
|-------|-------|------------|
| `go build` fails with missing dependencies | Go modules not downloaded | Run `go mod download` first |
| `go: go.mod requires go >= 1.23.1` | Go version too old | Install Go 1.24.2 or later from golang.org |
| Mermaid diagrams not rendering | Viewer doesn't support Mermaid | Use GitHub web UI, VS Code with Mermaid plugin, or mermaid.live |
| Worker counts differ from documented values | Different `--concurrency` value or system CPU count | Explicitly set `--concurrency=4` to match documentation |
| Timing values differ from documented values | Hardware/network differences | Expected — focus on behavioral conclusions, not exact ms values |
| `--log-level=5` produces no decoder messages | Log level not verbose enough | Ensure `--log-level=5` (not `--log-level 5` — use `=` syntax) |

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `go build -o /tmp/trufflehog .` | Build TruffleHog binary from source |
| `go mod download` | Download all Go module dependencies |
| `go mod verify` | Verify dependency integrity checksums |
| `/tmp/trufflehog filesystem --no-update --log-level=2 --concurrency=4 <path>` | Scan with worker count logging |
| `/tmp/trufflehog filesystem --no-update --log-level=5 --concurrency=2 <path>` | Scan with full verbose pipeline trace |
| `/tmp/trufflehog filesystem --no-update --print-avg-detector-time <path>` | Scan with per-detector timing output |
| `/tmp/trufflehog filesystem --no-update --no-verification-cache <path>` | Scan with verification cache disabled |
| `/tmp/trufflehog filesystem --no-update --no-verification --results=verified,unverified,unknown,filtered_unverified <path>` | Scan without remote verification, showing all result types |
| `git diff --stat origin/trufflehog_e42153d44a5e...blitzy-06475e0e-5bac-4000-9e57-c5c681aed6e7` | View changes introduced by this branch |

### B. Port Reference

Not applicable — this is a documentation-only project with no running services.

### C. Key File Locations

| File | Purpose |
|------|---------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **Primary deliverable** — runtime pipeline investigation document (767 lines) |
| `pkg/engine/engine.go` | Core engine: workers, dedup, timing, scanner loop |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Aho-Corasick trie: keyword collection, detector matching |
| `pkg/engine/defaults/defaults.go` | Default detector registry (831 active detectors) |
| `pkg/decoders/decoders.go` | Decoder interface and ordering (UTF8, Base64, UTF16, EscapedUnicode) |
| `pkg/verificationcache/verification_cache.go` | Cache-aware verification with Blake2B key hashing |
| `pkg/verificationcache/in_memory_metrics.go` | 5 atomic metric counters for cache performance |
| `pkg/cache/simple/simple.go` | go-cache backed in-memory cache (12h default expiration) |
| `main.go` | CLI flags, engine configuration, scan execution, metrics output |
| `docs/concurrency.md` | Existing Mermaid diagram of worker types (reference only) |
| `docs/process_flow.md` | Existing Mermaid flowcharts for data flow (reference only) |

### D. Technology Versions

| Technology | Version | Source |
|------------|---------|--------|
| Go (minimum) | 1.23.1 | `go.mod` line 3 |
| Go (toolchain) | 1.24.2 | `go.mod` line 5 |
| TruffleHog | dev (source build) | Built from repository source |
| Aho-Corasick library | v1.0.3 (`github.com/BobuSumisu/aho-corasick`) | `go.mod` |
| HashiCorp LRU | v2 (`github.com/hashicorp/golang-lru/v2`) | `go.mod` |
| go-cache | latest (`github.com/patrickmn/go-cache`) | `go.mod` |
| Kingpin CLI | v2.4.0 (`github.com/alecthomas/kingpin/v2`) | `go.mod` |

### E. Environment Variable Reference

No environment variables are required for this documentation-only project. TruffleHog CLI flags were used directly for all runtime experiments.

### F. Developer Tools Guide

| Tool | Usage |
|------|-------|
| `go build` | Compile TruffleHog binary from source for experiment reproduction |
| `go run` | Execute standalone Go programs (e.g., keyword counting helper) |
| Mermaid Live Editor (`mermaid.live`) | Preview and debug Mermaid diagrams from the documentation |
| `git diff --stat` | Verify that only the documentation file was changed |
| `git log --oneline` | Review the 4 commits in the documentation branch |

### G. Glossary

| Term | Definition |
|------|------------|
| **Aho-Corasick trie** | A finite automaton data structure for simultaneous multi-pattern string matching; used by TruffleHog to prefilter chunks against 914 detector keywords in a single pass |
| **Detector** | A Go struct implementing the `detectors.Detector` interface that identifies a specific type of secret (e.g., AWS keys, GitHub tokens); 831 active detectors in default configuration |
| **Decoder** | A Go struct implementing the `decoders.Decoder` interface that transforms chunk data from an encoding (Base64, UTF16, etc.) to plaintext; 4 default decoders |
| **Verification cache** | An in-memory go-cache instance that stores detector `FromData` results keyed by Blake2B hash of (Raw + RawV2 + DetectorType) to avoid redundant remote verification calls within a single scan |
| **Dedup cache** | A HashiCorp LRU cache (512 entries) in the `notifierWorker` that prevents the same secret from being reported multiple times when discovered by different decoders |
| **Scanner worker** | A goroutine (count = concurrency) that receives chunks from `ChunksChan`, applies all decoders sequentially, and routes decoded chunks matching Aho-Corasick keywords to detector workers |
| **Detector worker** | A goroutine (count = concurrency × 8) that runs the actual detector logic (regex matching + remote verification) on decoded chunks |
| **Verification overlap worker** | A goroutine (count = concurrency × 1) that handles chunks requiring multi-detector verification to reduce duplicate remote calls |
| **Notifier worker** | A goroutine (count = concurrency × 1) that receives verified/unverified results, applies deduplication, and dispatches to output |
| **Backpressure** | The natural flow control provided by Go's buffered channels — when a channel buffer is full, the sending goroutine blocks until a receiver reads from the channel |