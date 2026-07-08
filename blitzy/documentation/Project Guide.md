# Blitzy Project Guide — TruffleHog Runtime Q&A (Secret-Detection Pipeline)

> **Deliverable branch:** `blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88` · **Canonical source commit:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760` · **HEAD:** `5e516a33`
> **Legend (Blitzy brand colors):** <span style="color:#5B39F3">■</span> Completed / AI Work = Dark Blue `#5B39F3` · <span style="color:#B23AF2">■</span> White = Remaining / Not Completed `#FFFFFF`

---

## 1. Executive Summary

### 1.1 Project Overview

This project is a **read-only runtime investigation and documentation** deliverable for **TruffleHog** (`github.com/trufflesecurity/trufflehog/v3`), a Go secret-detection CLI. The objective was to author **exactly one** Markdown answer document that resolves six precise technical questions (Q1–Q6) about the engine's runtime secret-detection pipeline — keyword/trie loading, decoder ordering, verification-cache behavior, worker concurrency, deduplication, and detector timing — with **every claim grounded in observed runtime output** and pinned to exact `file:line` citations. Target users are TruffleHog maintainers and engineers needing an authoritative, evidence-backed reference. The technical scope is strictly additive and non-invasive: one new document, **zero** modifications to any source file.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextSize':'14px','pieLegendTextSize':'14px'}}}%%
pie showData title Completion Status — 90.0% Complete
    "Completed (AI)" : 40.5
    "Remaining" : 4.5
```

| Metric | Hours |
|---|---|
| **Total Hours** | **45.0** |
| **Completed Hours (AI + Manual)** | **40.5** (AI: 40.5 · Manual: 0.0) |
| **Remaining Hours** | **4.5** |
| **Percent Complete** | **90.0%** |

> Completion is computed with the PA1 AAP-scoped methodology: `Completed ÷ (Completed + Remaining) = 40.5 ÷ 45.0 = 90.0%`. Every AAP-specified autonomous deliverable is complete, committed, and independently re-verified; the remaining 4.5 h is human acceptance review and merge of a read-only documentation artifact.

### 1.3 Key Accomplishments

- ✅ **Single deliverable created, correctly named & located** — `blitzy/documentation/trufflehog_e42153d44a5e.md` (1,449 lines), named for the source branch, under a newly created `blitzy/documentation/` directory.
- ✅ **All six question clusters answered** with exact command + complete unedited output + `file:line` citation + cause→effect explanation.
- ✅ **Every claim grounded in reproduced runtime evidence** — 116 unique `file:line` citations; independent citation scan found **0 out-of-range** across 164 references.
- ✅ **Read-only scope byte-for-byte perfect** — `git diff` vs canonical shows only the one added file; **0** source/test/config/docs files changed; all temporary harnesses and scratch inputs removed.
- ✅ **Flagship quantitative result independently reproduced** — Q1: **914** unique keywords / **955** additions / max fan-out **6** (`"azure"`), stable across runs.
- ✅ **Multi-condition coverage** — Q2 (runs A/B/C), Q3 (cross-invocation vs within-process), Q5 (combined + controls + secondary overlap), Q6 (matched vs unmatched + verify-time contrast), plus a Final Coverage Pass ticking every named dichotomy.
- ✅ **All quality gates pass on independent re-run** — build (exit 0), `go vet` (clean), and `go test` for all 6 cited packages (6/6 `ok`).

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| _None._ No compilation errors, no failing tests (cited packages), no runtime errors, no read-only violations. | N/A | N/A | N/A |

> There are **no critical unresolved issues**. The autonomous work is complete and validated; only human acceptance review and merge remain (see §1.6, §2.2).

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| Outbound verification APIs (detector endpoints) | Network egress | Container has no internet; default (ON) credential verification cannot reach remote endpoints, so verification-dependent runs stall unless `--no-verification` is used or the call times out. Does **not** affect the deliverable — no live/production credentials were in scope and Q3 within-process evidence was captured accordingly. | Mitigated (documented; `--no-verification`/`timeout` used for deterministic runs) | Reviewer / DevOps |
| Credential-gated test suites (`pkg/sources`, `pkg/analyzer/analyzers`) | Cloud credentials (GCP ADC, AWS tokens) | Excluded from CI/local runs by project convention; require live cloud credentials. Not part of the six cited packages and out of scope for this read-only doc task. | Known exclusion (not applicable to deliverable) | Maintainers |

> No repository-permission or service-credential access issue blocks review or merge of the deliverable itself.

### 1.6 Recommended Next Steps

1. **[High]** Conduct SME technical review & acceptance of `blitzy/documentation/trufflehog_e42153d44a5e.md` — verify each of the six answers, spot re-run the headline observations (Q1, Q4, Q3), and confirm a sample of citations resolve at the canonical commit.
2. **[Medium]** Approve and merge the single-file PR to the target branch after confirming read-only scope (`git diff e42153d44a5e..HEAD` lists only the deliverable).
3. **[Low]** Optionally add a host-portability note for readers on cgroup-CPU-honoring hosts (default-concurrency values differ; deterministic questions pin `--concurrency` and are unaffected).

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All completed work was performed autonomously by Blitzy agents (AI). Each component traces to a specific AAP requirement.

| Component | Hours | Description |
|---|---|---|
| Canonical build setup + build preamble + provenance note | 2.0 | Established canonical `go build`/`go run`, recorded exact commands, toolchain (`go1.24.2`), version stamp (`dev`), and provenance note distinguishing canonical source commit from doc-only commit (AAP 0.5.1, 0.8). |
| Pipeline reference diagram | 1.0 | Mermaid diagram summarizing Scanner→Overlap→Detector→Notifier relationships (Q2/Q4/Q5) (AAP 0.5.3). |
| Q1 — Unique keywords & sharing | 4.0 | In-package harness on `DefaultDetectors()`+`NewAhoCorasickCore()`; reported unique=914, additions=955, max fan-out 6 (`"azure"`); stability confirmed (AAP Q1). |
| Q2 — Decode-then-match ordering | 4.0 | Crafted plaintext+base64 input; runs A/B/C incl. `--log-level=5 --concurrency=1`; established BEFORE ordering (AAP Q2). |
| Q3 — Verification-cache metrics & persistence | 4.0 | Cross-invocation runs (no persistence) + within-process accrual (12/20); documented 5 metric fields (AAP Q3). |
| Q4 — Worker architecture & backpressure | 3.5 | `--concurrency=4` trace → 4/32/4/4; multipliers (detector ×8, notifier ×1, overlap ×1); bounded-channel backpressure reasoning (AAP Q4). |
| Q5 — Dedup LRU key & cross-decoder behavior | 4.0 | Combined plaintext+base64 reported ONCE; controls; secondary in-chunk overlap path documented; LRU key excludes `DecoderType` (AAP Q5). |
| Q6 — `--print-avg-detector-time` scope & verification inclusion | 4.5 | Conditions A (matched appears) & B (ran-but-empty absent) + verify-on/off timing contrast; only result-returning detectors listed; verification time included (AAP Q6). |
| Final Coverage Pass + read-only guarantee prose | 1.5 | Ticked every named dichotomy; documented provenance & read-only guarantee (AAP rules). |
| Read-only discipline + temporary-artifact cleanup | 1.0 | Isolated harnesses/scratch under `/tmp`; removed on completion; repo left byte-for-byte unchanged (AAP 0.3, 0.8). |
| Review-finding resolution & iterative revision (3 commits) | 6.0 | Major revision adding complete runtime evidence (+849/−229) plus Q2 threshold and provenance corrections. |
| Independent runtime re-verification / validation gates | 5.0 | Re-ran every observation; build/vet/test gates; citation-range integrity; confirmed all numbers. |
| **Total Completed** | **40.5** | |

### 2.2 Remaining Work Detail

All remaining work is human-side path-to-production (acceptance/merge of a read-only document). No remediation is required.

| Category | Hours | Priority |
|---|---|---|
| SME technical review & acceptance of the answer document (verify 6 answers, spot re-run headline observations, sample-check citations) | 3.0 | High |
| Incorporate SME review feedback / minor documentation corrections (contingency) | 1.0 | Low |
| PR approval & merge to target branch (confirm single-file diff / read-only scope) | 0.5 | Medium |
| **Total Remaining** | **4.5** | |

### 2.3 Hours Reconciliation

| Check | Result |
|---|---|
| Section 2.1 total (Completed) | 40.5 h |
| Section 2.2 total (Remaining) | 4.5 h |
| Section 2.1 + Section 2.2 | 45.0 h = **Total Hours (§1.2)** ✓ |
| Remaining consistent across §1.2 / §2.2 / §7 | 4.5 h ✓ |
| Completion % | 40.5 ÷ 45.0 = **90.0%** ✓ |

---

## 3. Test Results

All tests below originate from Blitzy's autonomous validation logs and were independently re-executed during this assessment against the cited packages backing the six questions. TruffleHog is a Go project; tests run via `go test`.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---|---|---|---|---|
| Unit — `pkg/engine/ahocorasick` (Q1) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 0.046 s; backs keyword/trie behavior. |
| Unit — `pkg/engine/defaults` (Q1) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 0.698 s; default detector population. |
| Unit — `pkg/decoders` (Q2) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 0.048 s; decoder ordering. |
| Unit — `pkg/verificationcache` (Q3) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 0.075 s; cache metrics/persistence. |
| Unit — `pkg/cache/simple` (Q3) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 0.003 s; in-memory `go-cache` store. |
| Unit — `pkg/engine` (Q2/Q4/Q5/Q6) | Go `testing` | Package suite | All | 0 | n/m | `ok` in 1.209 s; workers, dedup, timing. |
| Static analysis — `go vet` (cited pkgs) | `go vet` | 4 packages | Pass | 0 | — | Exit 0, clean (decoders, verificationcache, cache/simple, ahocorasick). |
| Build gate | `go build` | 1 | Pass | 0 | — | `CGO_ENABLED=0 go build .` exit 0 (~8 s); `--version` = `trufflehog dev`. |
| Runtime harness — Q1 keyword count | Go (in-package) | 1 | Pass | 0 | — | `unique=914 / additions=955 / max-fanout=6("azure")`, stable ×2. |
| Runtime CLI — Q4 worker counts | `trufflehog` CLI | 1 | Pass | 0 | — | `--concurrency=4` → 4/32/4/4 (scanner/detector/notifier/overlap). |
| Runtime CLI — Q6 detector timing | `trufflehog` CLI | 1 | Pass | 0 | — | `--print-avg-detector-time` lists only matched (`AWS: 548.694µs`). |

> **Summary:** 6/6 cited-package test suites pass (`ok`), `go vet` clean, build exit 0, and all runtime observations reproduced. `n/m` = coverage not separately measured for this read-only doc task (no new code introduced). The full `./...` suite intentionally excludes credential-gated `pkg/sources` and `pkg/analyzer/analyzers` (require GCP/AWS credentials) per project CI convention; those are outside the six cited packages and out of scope.

---

## 4. Runtime Validation & UI Verification

TruffleHog is a **command-line tool** — there is no graphical UI to verify. Runtime validation exercised each question's real code path via the CLI and in-package harnesses.

- ✅ **Build & version** — `CGO_ENABLED=0 go build .` exits 0; `./trufflehog --version` → `trufflehog dev`. **Operational.**
- ✅ **Filesystem scan** — completes and emits the end-of-scan snapshot (`finished scanning {chunks, bytes, verified_secrets, unverified_secrets, scan_duration, verification_caching{...}}`). **Operational.**
- ✅ **Q1 keyword/trie harness** — production `DefaultDetectors()`+`NewAhoCorasickCore()` yields 914 unique keywords / 955 additions; sharing proven (fan-out 6 on `"azure"`). **Operational.**
- ✅ **Q2 decode-then-match** — base64-only secret surfaces as `DecoderName=BASE64`, plaintext as `PLAIN`; decode precedes match. **Operational.**
- ✅ **Q3 verification cache** — cross-invocation runs show no persistence (identical Hits:0/Misses:N); within a process, hits accrue. **Operational.**
- ✅ **Q4 worker architecture** — `--concurrency=4` launches scanner=4, detector=32, notifier=4, verificationOverlap=4 (4/32/4/4). **Operational.**
- ✅ **Q5 cross-decoder dedup** — same credential in plaintext + base64 reported **once** (LRU key excludes `DecoderType`). **Operational.**
- ✅ **Q6 detector timing** — `--print-avg-detector-time` lists only result-returning detectors; verification time is included when verification is ON. **Operational.**
- ⚠ **Credential verification network calls** — outbound verification is unreachable in the offline container; deterministic runs use `--no-verification`/`timeout`. **Partial (environmental, expected, mitigated).**

---

## 5. Compliance & Quality Review

Cross-mapping of AAP deliverables and rules to their compliance status. All items validated during autonomous work and independently re-verified in this assessment.

| Benchmark / AAP Rule | Requirement | Status | Progress |
|---|---|---|---|
| Single deliverable, correctly named & located | Exactly one file `blitzy/documentation/trufflehog_e42153d44a5e.md` | ✅ Pass | 100% |
| Investigate by running first, then write | Every answer from captured runtime output | ✅ Pass | 100% |
| Magnitude/timing stability (≥2 runs) | Q1 counts, Q3/Q6 metrics stable | ✅ Pass | 100% |
| Run-to-run with identical input (Q3) | Same input across separate invocations | ✅ Pass | 100% |
| Real code path via real entry point | Default detectors + real CLI; no bypass | ✅ Pass | 100% |
| Canonical, default configuration; exact commands stated | Default config + only required flags; commands recorded | ✅ Pass | 100% |
| Exercise every condition (not just happy path) | Q3 A/B, Q5 combined/controls, Q6 A/B | ✅ Pass | 100% |
| Complete, unedited output for every claim, with command | Fenced raw output per condition | ✅ Pass | 100% |
| Answer every part / named item | Final Coverage Pass ticks all dichotomies | ✅ Pass | 100% |
| Exact & grounded (`file:line` + named symbol) | 116 citations; 0 out-of-range (of 164 checked) | ✅ Pass | 100% |
| Read-only scope (no source edits; cleanup) | 0 source files changed; artifacts removed | ✅ Pass | 100% |
| No dependency changes | `go.mod`/`go.sum` untouched; `go mod verify` OK | ✅ Pass | 100% |
| Build & static-analysis quality | `go build` exit 0; `go vet` clean | ✅ Pass | 100% |
| Test integrity (cited packages) | 6/6 package suites `ok` | ✅ Pass | 100% |

**Fixes applied during autonomous validation:** None required — the deliverable was already fully correct on independent re-verification (0 document edits, 0 source edits). **Outstanding compliance items:** None; only human acceptance review remains.

---

## 6. Risk Assessment

Overall risk posture: **LOW**. No high-probability or unmitigated risks. The single high-impact item (read-only integrity) is closed with very-low probability.

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Environment-dependent default values: Go `NumCPU()=128` in-container (cgroup `nproc=4` not honored) → default `--concurrency=128`, detector workers=1024 | Technical | Low | Medium | Doc explicitly documents `NumCPU` behavior and **pins** `--concurrency` for every deterministic question (Q4 → host-independent 4/32/4/4) | Mitigated |
| Citation/version drift if source evolves past the canonical commit | Technical | Low | Low | All citations pinned to `e42153d44a5e`; doc asserts identical resolution at that commit; 0 out-of-range verified across 164 references | Mitigated |
| Q1 magnitude (831 detectors / 914 keywords) is a point-in-time snapshot | Technical | Low | Low | Commit-pinned; determinism confirmed ×2 (assessment) / ×3 (validator) | Mitigated |
| Example credentials appear in captured output transcripts | Security | Low | Low | Only non-live example/test credentials (AWS canonical example keys, repo testdata); no real/production sources scanned (out of scope) | Mitigated |
| Default verification ON can trigger outbound API calls during scans | Security | Low | Low | Crafted inputs use non-live creds (verify fails harmlessly); `--no-verification` used for deterministic runs | Accepted |
| Read-only guarantee could be violated by a stray edit / temp artifact | Operational | High (impact) | Very Low | `git diff` vs canonical = only the deliverable (0 source changes); harnesses isolated under `/tmp` and removed; binary `.gitignore`d; clean tree re-verified | Closed |
| Reproducibility on a different host may yield different `NumCPU`-derived numbers | Operational | Low | Medium | Documented + deterministic `--concurrency` pinning + explicit reproduction commands | Mitigated |
| Dependence on third-party `aho-corasick` `AddStrings` semantics | Integration | Low | Low | Harness reads `len(keywordsToDetectors)` directly from production code (not library internals); confirmed via runtime + web research | Mitigated |
| Reproduction requires Go 1.24.2 toolchain | Integration | Low | Low | Toolchain pinned in `go.mod` (`go 1.23.1` / `toolchain go1.24.2`) and documented; build reproduced (exit 0) | Mitigated |

---

## 7. Visual Project Status

**Project hours — Completed vs Remaining** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextSize':'14px','pieLegendTextSize':'14px'}}}%%
pie showData title Project Hours Breakdown (Total 45.0h)
    "Completed Work" : 40.5
    "Remaining Work" : 4.5
```

**Remaining work by priority** (hours from §2.2, total 4.5 h):

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#A8FDD9','pie3':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px'}}}%%
pie showData title Remaining Hours by Priority
    "High — SME review & acceptance" : 3.0
    "Low — feedback/corrections (contingency)" : 1.0
    "Medium — PR approval & merge" : 0.5
```

> **Integrity check:** "Remaining Work" = 4.5 h equals §1.2 Remaining Hours and the sum of §2.2 (3.0 + 1.0 + 0.5). "Completed Work" = 40.5 h equals §1.2 Completed Hours and the sum of §2.1.

---

## 8. Summary & Recommendations

**Achievements.** The project is **90.0% complete** (40.5 of 45.0 hours). Blitzy agents autonomously delivered the single required artifact — `blitzy/documentation/trufflehog_e42153d44a5e.md` (1,449 lines) — comprehensively answering all six question clusters with reproduced runtime output and 116 exact `file:line` citations, across four commits (initial draft, a major evidence-adding revision, and two correctness refinements). Read-only scope is byte-for-byte perfect: zero source, test, config, dependency, or docs changes.

**Remaining gaps.** The outstanding 4.5 hours is entirely human path-to-production: SME technical review & acceptance (3.0 h), a contingency for minor corrections (1.0 h), and PR approval & merge (0.5 h). There is **no remediation work** — no compilation errors, no failing tests, no runtime errors, and no read-only violations.

**Critical path to production.** (1) SME reads and accepts the document, spot re-running the headline observations (Q1 → 914; Q4 → 4/32/4/4; Q3 → no cross-invocation persistence); (2) confirm the single-file diff and read-only scope; (3) approve and merge.

**Success metrics.** All six answers match the dichotomy each question asked; all magnitude/timing values stable across ≥2 runs; 0 out-of-range citations; build + `go vet` + 6/6 cited-package tests pass; repository unchanged except the one document.

**Production-readiness assessment.** For a read-only documentation deliverable, the artifact is **release-ready pending human sign-off**. Confidence is **High** — the flagship result and multiple runtime behaviors were independently reproduced during this assessment, and every quality gate passes.

| Metric | Value |
|---|---|
| Completion | 90.0% |
| Completed / Total hours | 40.5 / 45.0 |
| Remaining hours | 4.5 |
| Cited-package test suites passing | 6 / 6 |
| Source files modified | 0 |
| Out-of-range citations | 0 |
| Overall risk posture | Low |

---

## 9. Development Guide

How to build, run, reproduce the six observations, and troubleshoot. All commands were tested during this assessment. Run from the repository root: `/tmp/blitzy/trufflehog/blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88_33d3d3`.

### 9.1 System Prerequisites

- **OS:** Linux (x86-64). Validated in the canonical container (Ubuntu-based).
- **Go toolchain:** `go1.24.2` (module declares `go 1.23.1` / `toolchain go1.24.2`). Verify:
  ```bash
  go version
  # go version go1.24.2 linux/amd64
  ```
- **Git** (for provenance/diff checks). **CGO not required** (`CGO_ENABLED=0`).

### 9.2 Environment Setup

- No environment variables are required to build or run the deliverable's reproductions.
- Network is **not** required; keep credential verification **off** for deterministic runs (`--no-verification`) since the container is offline.
- Append `--no-update` to suppress the update-check network call.

### 9.3 Dependency Installation / Verification

Dependencies are vendored by Go modules; no installation step changes the tree. Verify integrity:
```bash
go mod verify
# all modules verified
```

### 9.4 Build

```bash
CGO_ENABLED=0 go build -o trufflehog .
echo $?          # 0
./trufflehog --version
# trufflehog dev
```
> The built `./trufflehog` binary is ignored by `.gitignore` and does not alter the tracked tree.

### 9.5 Reproduce the Six Observations

**Q1 — unique keywords & sharing (in-package harness, outside the tracked tree):**
```bash
WORK=/tmp/th_q1 && rm -rf "$WORK" && mkdir -p "$WORK" && cd "$WORK"
cat > go.mod <<EOF
module thq1
go 1.23.1
require github.com/trufflesecurity/trufflehog/v3 v3.0.0
replace github.com/trufflesecurity/trufflehog/v3 => /tmp/blitzy/trufflehog/blitzy-56ea4ebb-8c10-4340-bef0-fb6f0b932f88_33d3d3
EOF
cat > main.go <<'EOF'
package main
import (
    "fmt"
    ac "github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
    "github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)
func main() {
    core := ac.NewAhoCorasickCore(defaults.DefaultDetectors())
    m := core.KeywordsToDetectors()
    adds, shared, mx, mk := 0, 0, 0, ""
    for k, d := range m { adds += len(d); if len(d) > 1 { shared++ }; if len(d) > mx { mx, mk = len(d), k } }
    fmt.Printf("unique=%d additions=%d shared>1=%d max_fanout=%d(%q)\n", len(m), adds, shared, mx, mk)
}
EOF
GOFLAGS=-mod=mod go run .
# unique=914 additions=955 shared>1=32 max_fanout=6("azure")
cd / && rm -rf "$WORK"        # cleanup (preserve read-only scope)
```

**Q4 — worker counts at `--concurrency=4`:**
```bash
printf 'AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > /tmp/in.txt
./trufflehog filesystem /tmp/in.txt --concurrency=4 --log-level=5 --no-verification --no-update 2>&1 \
  | grep -E "starting (scanner|detector|notifier|verificationOverlap) workers"
# ... scanner workers count=4 / detector workers count=32 / notifier workers count=4 / verificationOverlap workers count=4
```

**Q6 — `--print-avg-detector-time` (only matched detectors appear):**
```bash
./trufflehog filesystem /tmp/in.txt --print-avg-detector-time --no-verification --no-update 2>&1 | tail -5
# Average detector time is the measurement ... when results are returned.
# AWS: 548.694µs
```

**Q3 — end-of-scan verification-cache metrics snapshot:**
```bash
./trufflehog filesystem /tmp/in.txt --no-verification --no-update 2>&1 | grep -o '"verification_caching":{[^}]*}'
# "verification_caching":{"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}
rm -f /tmp/in.txt
```
> For Q3's meaningful hit/miss numbers and Q6's ms-scale (verification-inclusive) timing, run with verification **ON** against a larger repeated-credential input; wrap with `timeout` since the container is offline. Q2/Q5 use a crafted file containing the same secret in plaintext and base64.

### 9.6 Verification Steps

```bash
# read-only scope: only the deliverable differs from canonical
git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760..HEAD
# A  blitzy/documentation/trufflehog_e42153d44a5e.md

# quality gates for cited packages
CGO_ENABLED=0 go vet ./pkg/decoders/ ./pkg/verificationcache/ ./pkg/cache/simple/ ./pkg/engine/ahocorasick/
CGO_ENABLED=0 go test ./pkg/engine/ahocorasick/ ./pkg/decoders/ ./pkg/verificationcache/ \
  ./pkg/cache/simple/ ./pkg/engine/defaults/ ./pkg/engine/
# all packages: ok
```

### 9.7 Example Usage (canonical run targets)

```bash
# Makefile:48-49 canonical run
CGO_ENABLED=0 go run . git file://. --json
# Makefile:51-52 run-debug (adds verbosity)
CGO_ENABLED=0 go run . git file://. --json --log-level=2
```

### 9.8 Troubleshooting

- **Scan hangs / very slow:** default verification is ON but the container is offline → add `--no-verification` or wrap with `timeout N`.
- **Worker counts look huge (e.g., detector=1024):** Go reports `NumCPU()=128` here, so default `--concurrency=128`. Pin `--concurrency=4` for deterministic counts (4/32/4/4).
- **Harness `go run` cannot find the module:** ensure the `replace` directive points at the repo root and run with `GOFLAGS=-mod=mod`.
- **Accidental tree pollution:** the built binary is `.gitignore`d; keep all harnesses/scratch files under `/tmp` and delete them — verify with `git status --porcelain` (should be empty).

---

## 10. Appendices

### A. Command Reference

| Purpose | Command |
|---|---|
| Go version | `go version` |
| Verify modules | `go mod verify` |
| Build | `CGO_ENABLED=0 go build -o trufflehog .` |
| Version | `./trufflehog --version` |
| Filesystem scan | `./trufflehog filesystem <path> --no-verification --no-update` |
| Worker trace (Q4) | `./trufflehog filesystem <path> --concurrency=4 --log-level=5 --no-verification --no-update` |
| Detector timing (Q6) | `./trufflehog filesystem <path> --print-avg-detector-time --no-update` |
| Read-only diff check | `git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760..HEAD` |
| Vet (cited pkgs) | `CGO_ENABLED=0 go vet ./pkg/decoders/ ./pkg/verificationcache/ ./pkg/cache/simple/ ./pkg/engine/ahocorasick/` |
| Test (cited pkgs) | `CGO_ENABLED=0 go test ./pkg/engine/ahocorasick/ ./pkg/decoders/ ./pkg/verificationcache/ ./pkg/cache/simple/ ./pkg/engine/defaults/ ./pkg/engine/` |

### B. Port Reference

| Port | Service | Notes |
|---|---|---|
| — | None | TruffleHog is a CLI; no network ports are opened for these observations. |

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (Q1–Q6 answers) |
| `main.go` | CLI entry point, flags, end-of-scan metrics snapshot, `printAverageDetectorTime` |
| `pkg/engine/engine.go` | Workers, channel sizing, notifier dedup (LRU key), detector timing |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `NewAhoCorasickCore`, `keywordsToDetectors`, `KeywordsToDetectors()` |
| `pkg/engine/defaults/defaults.go` | `DefaultDetectors()`, `buildDetectorList()` |
| `pkg/decoders/decoders.go` | `DefaultDecoders()` ordering |
| `pkg/verificationcache/verification_cache.go`, `in_memory_metrics.go` | Verification cache + metric fields |
| `pkg/cache/simple/simple.go` | In-memory `go-cache`-backed result store |

### D. Technology Versions

| Component | Version | Source |
|---|---|---|
| Go (module) | `go 1.23.1` | `go.mod:3` |
| Go (toolchain) | `go1.24.2` | `go.mod:5` |
| TruffleHog | `dev` (canonical commit `e42153d44a5e`) | `pkg/version/version.go:3` |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 | `go.mod` (Q1/Q2) |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 | `go.mod` (Q5) |
| `github.com/patrickmn/go-cache` | v2.1.0+incompatible | `go.mod` (Q3) |
| `github.com/adrg/strutil` | v0.3.1 | `go.mod` (Q5 secondary) |
| `golang.org/x/crypto` | v0.37.0 | `go.mod` (Q3, Blake2B key) |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `CGO_ENABLED` | `0` | Pure-Go static build (no C toolchain). |
| `GOFLAGS` | `-mod=mod` | Required only for the throwaway Q1/Q6 harness modules using a `replace` directive. |

### F. Developer Tools Guide

| Flag | Meaning |
|---|---|
| `--log-level` (0–5) | Verbosity; `5` = trace (shows worker startup / decoder activity). |
| `--debug` / `--trace` | Shortcuts for elevated verbosity. |
| `--concurrency=N` | Scanner worker count; multipliers derive detector/notifier/overlap pools. |
| `--no-verification` | Disable outbound credential verification (needed offline). |
| `--no-verification-cache` | Disable the verification result cache (Q3 default is ON). |
| `--print-avg-detector-time` | Print average time per **result-returning** detector to stderr (Q6). |
| `--no-update` | Skip the update-check network call. |

### G. Glossary

| Term | Definition |
|---|---|
| Aho-Corasick trie | Multi-pattern string-matching automaton used for fast keyword pre-filtering. |
| Keyword fan-out | Number of distinct detectors mapped to a single keyword (sharing indicator; max 6 on `"azure"`). |
| Decoder | Strategy that transforms chunk bytes (UTF8, Base64, UTF16, EscapedUnicode) **before** keyword matching. |
| Verification cache | In-memory (`go-cache`) store keyed by Blake2B(`Raw+RawV2+DetectorType`) that elides redundant remote verification within a process. |
| Dedupe LRU | `hashicorp/golang-lru/v2` cache (size 512) in the notifier keyed by `DetectorType+Raw+RawV2+SourceMetadata` (**excludes** `DecoderType`). |
| Backpressure | Producer blocking that arises from bounded buffered channels sized `defaultChannelBuffer × multiplier`. |
| Canonical commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` — the source commit against which all citations resolve. |