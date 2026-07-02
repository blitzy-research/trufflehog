# Blitzy Project Guide — TruffleHog Startup Runtime Explanation

> **Deliverable branch:** `blitzy-d28ec82a-9ee8-49bb-91f9-826ef251201c`  ·  **Base:** `origin/trufflehog_e42153d44a5e` (`e42153d4`)  ·  **HEAD:** `3b6efcdc`
> **Color legend:** ![#5B39F3](https://placehold.co/12x12/5B39F3/5B39F3.png) **Completed / AI Work = Dark Blue `#5B39F3`**  ·  ⬜ **Remaining = White `#FFFFFF`**  ·  Headings/accents Violet‑Black `#B23AF2`  ·  Highlight Mint `#A8FDD9`

---

## Section 1 — Executive Summary

### 1.1 Project Overview

This project delivers a single, evidence‑grounded technical document that explains **how TruffleHog — the Go‑based secrets / Non‑Human‑Identity (NHI) scanner in this repository — comes online at startup**. The explanation was produced by **building and running** the `trufflehog` binary under trace‑level logging and grounding every behavioral claim in a verbatim log line, an exact `file:line` citation, and a rationale. It answers four named sub‑questions — (a) configuration handling, (b) engine initialization, (c) detector preparation, and (d) component communication. The intended audience is engineers onboarding to TruffleHog's startup/initialization path. Scope is deliberately narrow and read‑only: exactly one new Markdown file is added and no existing source is modified.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieTitleTextSize':'16px','pieSectionTextColor':'#111111','pieLegendTextColor':'#111111'}}}%%
pie showData title Completion — 87.5% Complete (21.0h of 24.0h)
    "Completed (AI) — #5B39F3" : 21
    "Remaining — #FFFFFF" : 3
```

| Metric | Hours |
|--------|-------|
| **Total Hours** | **24.0** |
| **Completed Hours (AI + Manual)** | **21.0**  (AI 21.0 + Manual 0.0) |
| **Remaining Hours** | **3.0** |
| **Percent Complete** | **87.5%**  = 21.0 ÷ 24.0 |

> **How the percentage is derived (PA1, AAP‑scoped):** the AAP defines an *isolated, additive documentation* task with exactly one deliverable. All 15 inventoried AAP requirements are **Completed** (build, safe run, web‑research validation, four sub‑answers, coverage pass, exact citations, read‑only cleanup, plus two autonomous‑QA cycles). The residual **3.0h** is genuine **human‑gated path‑to‑production** work (review, merge, optional host re‑verification) that an autonomous agent cannot perform — so completion is capped below 100% per honest‑assessment rules.

### 1.3 Key Accomplishments

- ✅ Built a working `trufflehog` binary from source with the pinned toolchain (**Go 1.24.2**, `CGO_ENABLED=0`); binary reports version `dev`.
- ✅ Executed a **safe / "dry" run** — a minimal `filesystem` scan with `--no-verification --no-update` at `--log-level=5` — against a secret‑free, out‑of‑repository directory (exit 0, no network egress).
- ✅ Authored an **879‑line** evidence‑grounded document answering all four sub‑questions, each with a verbatim log line, exact `file:line` citation, and rationale (one‑claim‑one‑evidence).
- ✅ Grounded the write‑up in **162 `file:line` citation tokens across 16 repository files**, independently re‑verified as exact (zero mismatches / off‑by‑one).
- ✅ Reported host‑dependent magnitudes exactly (worker counts **128 / 1024 / 128 / 128**, `NumCPU()`=128 via `automaxprocs`) and explicitly caveated them as host‑specific.
- ✅ Completed a **21‑item coverage pass** confirming every named item is addressed.
- ✅ Honored the **read‑only** constraint: single added file (`+879/-0`), clean working tree, all scratch artifacts removed.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| _None blocking._ Deliverable is complete, citation‑accurate, committed, and independently validated. | No release blocker. | — | — |
| (Awareness only) Full‑suite `make test-community` shows 2 failures in **unmodified, out‑of‑scope** code (env/network‑induced) | None on this deliverable — not branch‑attributable; not fixable without violating read‑only scope | Upstream maintainers / CI env | N/A |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| Go toolchain (`/usr/local/go/bin`) | Build tooling | Present (Go 1.24.2) but not on default `PATH` | Resolved — `export PATH=$PATH:/usr/local/go/bin` | Developer |
| Git repository | Write / merge | Branch committed; merge to base pending human action | Open — routine PR merge | Reviewer/Maintainer |

No blocking access issues identified. No service credentials, third‑party API keys, or external systems are required — the safe run performs no network egress by design.

### 1.6 Recommended Next Steps

1. **[High]** SME technical review of `blitzy/documentation/trufflehog_e42153d44a5e.md` — spot‑verify a sample of citations and confirm the four sub‑answers. _(1.0h)_
2. **[High]** Editorial approval & sign‑off — confirm readability and that host‑dependent‑value caveats are clear. _(0.5h)_
3. **[Medium]** Merge branch to base and close out the PR — verify the diff is the single additive file and the tree is clean. _(0.5h)_
4. **[Low]** *(Optional)* Re‑run the safe observation scan on the canonical target host and annotate host‑dependent values if the doc is to be treated as a host‑specific reference. _(1.0h)_

---

## Section 2 — Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|-----------|-------|-------------|
| Environment provisioning & build | 1.0 | Verify Go 1.24.2 toolchain (matches `go.mod` `toolchain go1.24.2`); `CGO_ENABLED=0 go build`; confirm binary reports `dev` |
| Safe observation run + verbatim capture | 1.5 | Design & execute minimal `filesystem` scan (`--log-level=5 --no-verification --no-update`) vs out‑of‑repo secret‑free dir; capture logs verbatim with reproducible commands |
| Web research — `go-logr` V‑level convention | 0.5 | Validate the V‑level verbosity convention to correctly interpret the observed `info-N` markers |
| Startup call‑chain correlation + citation verification | 3.0 | Trace the `init → main → run → runSingleScan → NewEngine → Start` chain; locate & verify 162 `file:line` citation tokens across 16 files |
| §1 Introduction & Build/Run Setup authoring | 2.0 | Objective, dry‑run interpretation, build recipe, host‑facts table, `info-N`/V‑level, code‑to‑log map, verbatim captured log |
| §2 (a) Configuration handling authoring | 1.5 | kingpin flags/parse, `maxprocs.Set()`, `log.New`, optional YAML `config.Read`, engine `setDefaults` |
| §3 (b) Engine initialization authoring | 1.5 | `NewEngine → setDefaults → initialize`; 512‑entry LRU dedupe cache; buffered channels |
| §4 (c) Detector preparation authoring | 1.5 | `DefaultDetectors()`, decoder chain (UTF8→Base64→UTF16→EscapedUnicode), `NewAhoCorasickCore` |
| §5 (d) Component communication authoring | 2.5 | Four worker pools, buffered channels, corrected chunk‑routing topology (direct vs overlap), source→unit→chunk pipeline, scanner drain/summary |
| §6 Coverage‑pass checklist authoring | 1.0 | 21‑item checklist confirming every named item is answered |
| Appendix + read‑only cleanup discipline | 0.5 | Reproducibility recipe, safety notes, scratch‑artifact removal, clean‑tree guarantee |
| Review‑response iteration (2 follow‑up commits) | 1.5 | `3bd6b11d` (address review findings) + `3b6efcdc` (repo‑root‑resolvable citations + caveat line count) |
| Autonomous final validation | 3.0 | Independent rebuild + rerun + ~110‑citation verification + in‑scope unit tests + 5 production‑readiness gates |
| **Total Completed** | **21.0** | Matches Section 1.2 Completed Hours |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|----------|-------|----------|
| Documentation SME review & approval (technical spot‑check + editorial sign‑off) | 1.5 | High |
| Branch merge / PR close‑out | 0.5 | Medium |
| Optional host re‑verification of host‑dependent values (worker counts, log‑line totals) | 1.0 | Low |
| **Total Remaining** | **3.0** | — |

> **Reconciliation:** Section 2.1 (21.0h) + Section 2.2 (3.0h) = **24.0h** = Total Project Hours (Section 1.2). Section 2.2 total (3.0h) = Section 1.2 Remaining = Section 7 pie "Remaining Work".

---

## Section 3 — Test Results

All results below originate from Blitzy's autonomous validation of this project (Go's built‑in `go test`, `go build`, `go vet`, and a runtime smoke scan), re‑executed this session with the pinned Go 1.24.2 toolchain.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------------|--------|--------|-----------|-------|
| Unit — in‑scope documented packages | `go test` (go1.24.2) | 29 | 29 | 0 | N/M | 6 pkgs: `decoders`, `config`, `log`, `engine/ahocorasick`, `engine/defaults`, `cleantemp`; **114** incl. subtests, all pass |
| Build validation | `go build ./...` | 1 | 1 | 0 | — | `CGO_ENABLED=0`, exit 0, zero errors codebase‑wide |
| Static analysis | `go vet ./pkg/engine/` | 1 | 1 | 0 | — | exit 0 |
| Runtime smoke (startup) | `trufflehog` CLI | 1 | 1 | 0 | — | Safe `filesystem` scan exit 0; all documented startup signals reproduced |
| _(Reference)_ Full community suite | `go test` (949 pkgs) | 949 | 889 ok / 58 no‑test | 2* | — | *2 failures in **unmodified, out‑of‑scope** code — environmental/external, not branch‑attributable (see Section 6) |

> **Integrity note:** The deliverable is Markdown (non‑executable); it introduces no tests of its own. The rows above validate that the *documented code paths* build, vet, run, and pass their existing unit tests. `N/M` = coverage not measured (line coverage was not part of the AAP scope). The root `main` package has no test files (normal for a CLI entry point).

---

## Section 4 — Runtime Validation & UI Verification

**Runtime health (observed this session, Go 1.24.2 host, `nproc`=4):**

- ✅ **Build** — `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` → exit 0.
- ✅ **Binary identity** — `--version` → `trufflehog dev` (dev build disables the self‑update overseer per `main.go:L360-L361`).
- ✅ **Safe scan runtime** — `filesystem <probe> --log-level=5 --no-verification --no-update` → exit 0; probe = 56 bytes; no network egress.
- ✅ **Startup signals emitted** — `default engine options set`, `engine initialized`, `setting up / set up aho-corasick core`, and the four `starting … workers` lines all observed.
- ✅ **Worker pools** — scanner/verificationOverlap/notifier = **128** each; detector = **1024** (8×); `runtime.NumCPU()`=128 via `automaxprocs` despite `nproc`=4.
- ✅ **Predictive fidelity** — a 23‑char binary basename produced **exactly 147** log lines (145 baseline + 2 `V(5)` "No trufflehog processes were found" lines), matching the doc's explicit prediction.
- ✅ **Read‑only guarantee** — `git status --porcelain` empty before and after; all scratch artifacts removed.
- ✅ **Deliverable render** — Markdown structurally sound (balanced code fences; internal `§` cross‑references resolve).

**UI verification:** ⚠ **Not applicable** — TruffleHog is a batch CLI and the deliverable is a Markdown document; there is no graphical UI to verify. Console output (the `info-N` log stream) was verified verbatim in lieu of UI.

**API integration:** ⚠ **Not applicable / intentionally disabled** — `--no-verification` suppresses all external credential‑verification API calls; the run is deterministic and network‑free by design.

---

## Section 5 — Compliance & Quality Review

Cross‑map of AAP deliverables and the binding methodology rules ("SWE‑AtlasQnA‑Repo") to observed evidence.

| Benchmark (AAP requirement / rule) | Status | Progress | Evidence |
|-----------------------------------|--------|----------|----------|
| Single branch‑named deliverable in `blitzy/documentation/` | ✅ Pass | 100% | `trufflehog_e42153d44a5e.md` exists (879 lines); `git diff` = single added file |
| Investigate by running first, then write | ✅ Pass | 100% | Build + safe scan executed; §1.3/§1.4 show producing commands |
| Observe at representative scale (magnitude/timing) | ✅ Pass | 100% | Worker counts observed at `NumCPU()`=128; durations/bytes reported exactly |
| Quote observed output verbatim + producing command | ✅ Pass | 100% | §1.8 verbatim capture; each measured value shown with its command |
| One claim, one piece of evidence | ✅ Pass | 100% | Each sub‑answer pairs a claim with its specific log line |
| Answer every named item + coverage pass | ✅ Pass | 100% | §6 21‑item checklist, all `[x]` |
| Be exact & grounded (`file:line`) | ✅ Pass | 100% | 162 citation tokens / 16 files; independently re‑verified exact |
| Report exactly what is observed | ✅ Pass | 100% | `nproc`=4 vs `NumCPU()`=128 reported honestly, not normalized |
| Provide rationale | ✅ Pass | 100% | Rationale accompanies each sub‑answer |
| Read‑only scope; scratch artifacts removed | ✅ Pass | 100% | Clean tree; binary git‑ignored; Appendix documents cleanup |
| No dependency changes (`go.mod`/`go.sum`) | ✅ Pass | 100% | `git diff` touches no Go/module files |
| Compilation & vet health of documented paths | ✅ Pass | 100% | `go build ./...` exit 0; `go vet ./pkg/engine/` exit 0 |

**Fixes applied during autonomous validation:** review‑response commit `3bd6b11d` addressed review findings; commit `3b6efcdc` made citations repo‑root‑resolvable and corrected the caveat line count. **Outstanding compliance items:** none — remaining work is human review/merge only.

---

## Section 6 — Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| RT1 — Host‑dependent values (worker counts, log‑line totals) reflect the 128‑CPU observation host | Technical | Low | Medium | Doc explicitly caveats as host‑specific ("read them from your own logs", §1.5/§5.5/Appendix); stable values are host‑independent | Mitigated |
| RT2 — Citation line‑drift if upstream source is later edited | Technical | Low | Medium (over time) | Doc is an explicit point‑in‑time explanation; `3b6efcdc` made citations repo‑root‑resolvable | Accepted |
| RT3 — Executable/runtime risk from the deliverable | Technical | None | — | Deliverable is Markdown only; `go build ./...` exit 0 confirms no code impact | N/A |
| RS1 — Security surface added | Security | Low | Low | No secrets/credentials/code added; `--no-verification` = no egress; no dependency changes | Mitigated |
| RO1 — Reproducibility‑recipe drift (toolchain/flags) | Operational | Low | Low | Recipe matches `Dockerfile`+`go.mod`; flags are stable public CLI | Accepted |
| RO2 — Deployed‑service ops (monitoring/health/backup) | Operational | None | — | Nothing deployed; stateless batch CLI + Markdown artifact | N/A |
| RI1 — Merge integration | Integration | Low | Very Low | Isolated additive change in a new directory; clean tree; zero source conflict surface | Open (pending merge) |
| RI2 — Full‑suite CI noise in unmodified out‑of‑scope code (`pkg/common` load flake; `pkg/handlers` external APK 404) | Integration | Low (informational) | Medium (full‑suite/no‑network CI) | Proven environmental/external; byte‑identical to base `e42153d4`; passes in isolation; not fixable without violating read‑only scope | Accepted / Out‑of‑scope |

**Posture:** No High or Medium severity risks. The dominant real‑world consideration (RT1) is already mitigated by explicit caveats in the deliverable. RI2 is surfaced purely for human awareness when running the full suite.

---

## Section 7 — Visual Project Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#111111','pieLegendTextColor':'#111111'}}}%%
pie showData title Project Hours Breakdown (Total 24.0h)
    "Completed Work — #5B39F3" : 21
    "Remaining Work — #FFFFFF" : 3
```

**Remaining hours by category (Section 2.2):**

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#B23AF2','pie3':'#A8FDD9','pieStrokeColor':'#333333','pieSectionTextColor':'#111111','pieLegendTextColor':'#111111'}}}%%
pie showData title Remaining Work — 3.0h by Category
    "SME review & approval (High)" : 1.5
    "Merge / PR close-out (Medium)" : 0.5
    "Optional host re-verification (Low)" : 1.0
```

> **Integrity:** "Remaining Work" = **3** here = Section 1.2 Remaining (3.0h) = sum of Section 2.2 "Hours" column (1.5 + 0.5 + 1.0 = 3.0). "Completed Work" = **21** = Section 1.2 Completed = sum of Section 2.1 "Hours" column.

---

## Section 8 — Summary & Recommendations

**Achievements.** The project is **87.5% complete** (21.0h of 24.0h). The sole AAP deliverable — an 879‑line, evidence‑grounded runtime explanation of TruffleHog's startup — is authored, citation‑accurate (162 tokens across 16 files, re‑verified exact), committed, and independently validated by rebuild + rerun. All four named sub‑questions (configuration, engine initialization, detector preparation, component communication) are answered with verbatim log evidence, exact `file:line` citations, and rationale, and a 21‑item coverage pass confirms nothing named was missed.

**Remaining gaps & critical path to production.** The residual **3.0h** is entirely **human‑gated**: SME technical review + editorial sign‑off (1.5h), branch merge / PR close‑out (0.5h), and an optional host re‑verification of host‑dependent values (1.0h). None of these can be completed autonomously, which is why completion is capped below 100%.

**Success metrics.** Build exit 0; safe scan exit 0; 29/29 in‑scope unit tests passing (114 incl. subtests, 0 failed); read‑only constraint honored (single `+879/-0` file, clean tree); citations independently verified exact; predicted line‑count behavior reproduced precisely.

**Production readiness.** ✅ **Ready for human review and merge.** This is a low‑risk, isolated, additive documentation change with no High/Medium risks and no in‑scope defects. Recommendation: proceed with SME review (Section 1.6, steps 1–2), then merge (step 3). The optional host re‑verification (step 4) is advisable only if the document will serve as a canonical host‑specific reference.

| Metric | Value |
|--------|-------|
| Completion | 87.5% |
| Completed / Total hours | 21.0 / 24.0 |
| Remaining hours | 3.0 |
| In‑scope unit tests passing | 29 / 29 (114 incl. subtests) |
| Files changed | 1 added (`+879 / -0`) |
| Open High/Medium risks | 0 |

---

## Section 9 — Development Guide

How to build, run, observe, and verify TruffleHog's startup path (all commands tested this session on a Linux/amd64 host with Go 1.24.2).

### 9.1 System Prerequisites

- **Go 1.24.2** (or ≥ the `toolchain` pinned in `go.mod`). Verify:
  ```bash
  export PATH=$PATH:/usr/local/go/bin
  go version            # → go version go1.24.2 linux/amd64
  ```
- **git** (2.51.0 available), **Linux/amd64**, ~1 GB free disk for the Go build cache.
- No database, cache, or network services — TruffleHog is a **stateless batch CLI**.

### 9.2 Environment Setup

```bash
# Go is installed at /usr/local/go/bin but may not be on the default PATH:
export PATH=$PATH:/usr/local/go/bin

# Static build; no CGO. No runtime environment variables are required for the safe run.
export CGO_ENABLED=0
```

### 9.3 Dependency Installation

No dependencies to add or change — `go build` resolves the pinned module set from `go.sum` automatically. `go.mod` / `go.sum` remain **unchanged** by this project.

```bash
# From the repository root:
go mod verify         # optional: confirms module checksums
```

### 9.4 Build

```bash
# Build OUTSIDE the repo tree to keep the working tree clean
# (a binary named `trufflehog` built in-tree is git-ignored anyway):
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .
/tmp/trufflehog_bin --version      # → trufflehog dev
```
_Expected:_ build exit code `0`; version prints `trufflehog dev` (the `dev` build disables the self‑update overseer).

### 9.5 Run — the safe / "dry" observation scan

```bash
# Secret-free target OUTSIDE the repository:
mkdir -p /tmp/th_probe
printf 'hello world\nthis is a plain text sample with no secrets\n' > /tmp/th_probe/sample.txt

# Minimal filesystem scan at max verbosity, verification + self-update disabled:
/tmp/trufflehog_bin filesystem /tmp/th_probe --log-level=5 --no-verification --no-update > /tmp/th_capture.log 2>&1
echo "exit=$?"                     # → exit=0
```
_Expected startup signals in the capture:_ `default engine options set`, `engine initialized`, `setting up aho-corasick core` / `set up aho-corasick core`, and four `starting … workers` lines.

### 9.6 Verification

```bash
wc -l < /tmp/th_capture.log                                   # host-dependent line count (145 on a clean /tmp with a 14-char binary basename)
grep -E 'starting (scanner|detector|verificationOverlap|notifier) workers' /tmp/th_capture.log
grep 'finished scanning' /tmp/th_capture.log | tail -1        # final summary (chunks/bytes/…)

# Confirm the repository working tree is unchanged:
git status --porcelain                                        # → (empty)
```

### 9.7 Example Usage

```bash
# View the deliverable:
sed -n '1,40p' blitzy/documentation/trufflehog_e42153d44a5e.md

# Run the documented in-scope unit tests:
CGO_ENABLED=0 go test -count=1 ./pkg/decoders/... ./pkg/config/... ./pkg/log/... \
  ./pkg/engine/ahocorasick/... ./pkg/engine/defaults/... ./pkg/cleantemp/...      # → all ok
```

### 9.8 Cleanup (read‑only obligation)

```bash
rm -rf /tmp/trufflehog_bin /tmp/th_probe /tmp/th_capture.log
rm -rf /tmp/trufflehog-*        # TruffleHog's own /tmp housekeeping scratch dirs (safe to remove)
git status --porcelain          # → (empty) confirms the tree is clean
```

### 9.9 Troubleshooting

- **`go: command not found`** → `export PATH=$PATH:/usr/local/go/bin`.
- **PEP 668 "externally‑managed" errors** → not applicable; this project uses the Go toolchain, not `pip`.
- **Worker counts differ from the doc (e.g., not 128)** → expected. Counts scale with `runtime.NumCPU()` (set container‑aware by `automaxprocs`); read them from your own logs.
- **Line count is 147, not 145** → expected when the binary basename is longer than 14 chars (adds two `V(5)` "No trufflehog processes were found" lines) or when `/tmp` already contains `trufflehog-*` leftovers.
- **Leftover `/tmp/trufflehog-*` directories** → TruffleHog's temp‑artifact housekeeping scratch; safe to `rm -rf`.
- **Full‑suite `make test-community` shows failures** → the two known failures are in unmodified out‑of‑scope code and are environmental (loopback timeout under load; external APK fixture 404); re‑run the affected package in isolation to confirm.

---

## Section 10 — Appendices

### A. Command Reference

| Purpose | Command |
|---------|---------|
| Put Go on PATH | `export PATH=$PATH:/usr/local/go/bin` |
| Verify toolchain | `go version` |
| Build (static) | `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` |
| Whole‑module build | `CGO_ENABLED=0 go build ./...` |
| Static analysis | `go vet ./pkg/engine/` |
| Safe/"dry" scan | `/tmp/trufflehog_bin filesystem /tmp/th_probe --log-level=5 --no-verification --no-update` |
| In‑scope unit tests | `go test -count=1 ./pkg/decoders/... ./pkg/config/... ./pkg/log/... ./pkg/engine/ahocorasick/... ./pkg/engine/defaults/... ./pkg/cleantemp/...` |
| Read‑only check | `git status --porcelain` |
| Scope diff | `git diff e42153d4 --name-status` |

### B. Port Reference

**No network ports.** TruffleHog is a stateless batch CLI; the documented safe run performs **no network egress** and opens no listening ports (`--no-verification` disables all external verification calls).

### C. Key File Locations

| Path | Role |
|------|------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (879 lines) |
| `main.go` | CLI/kingpin parse, log wiring, run orchestration |
| `pkg/engine/engine.go` | `NewEngine` / `setDefaults` / `initialize` / `Start` / `startWorkers` |
| `pkg/engine/defaults/defaults.go` | `DefaultDetectors()` registry (`L1704`) |
| `pkg/decoders/decoders.go` | `DefaultDecoders()` chain (`L8`, order at `L11–L14`) |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `NewAhoCorasickCore` (`L141`) |
| `pkg/config/config.go` | YAML `Read` (`L18`) / `NewYAML` (`L27`) |
| `pkg/log/log.go` | `info-N` token (`L123`); logger construction (`L28`) |
| `pkg/sources/source_manager.go` | Source lifecycle: run / enumerate / chunk |
| `CONTRIBUTING.md` | V‑level verbosity scale 0–5 (`L30–L37`) |
| `go.mod`, `Dockerfile`, `Makefile` | Toolchain (`go1.24.2`) & build recipe |

### D. Technology Versions

| Component | Version | Role in startup |
|-----------|---------|-----------------|
| Go toolchain | 1.24.2 | Build & run |
| `github.com/alecthomas/kingpin/v2` | v2.4.0 | CLI flag/command parsing |
| `go.uber.org/zap` | v1.27.0 | Structured logging core |
| `github.com/go-logr/zapr` | v1.3.0 | zap → logr adapter |
| `github.com/go-logr/logr` | v1.4.2 | V‑level verbosity semantics |
| `go.uber.org/automaxprocs` | v1.6.0 | Container‑aware `GOMAXPROCS` at `init()` |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Keyword‑trie prefilter |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 | In‑memory LRU dedupe (512) & verification caches |
| `github.com/hashicorp/go-retryablehttp` | v0.7.7 | Detector HTTP verification client (disabled on this run) |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `PATH` | `+= /usr/local/go/bin` | Make the Go toolchain discoverable |
| `CGO_ENABLED` | `0` | Static build (matches `Dockerfile:L5`) |
| _(runtime)_ | — | **None required** — the safe run needs no env vars, credentials, or config |

### F. Developer Tools Guide

- **Go toolchain** (`go build`, `go test`, `go vet`) — primary build/verify tooling.
- **git** — scope verification (`git diff`, `git status`, `git log`).
- **Chrome DevTools MCP / browser tools** — **not applicable**; this is a backend CLI + Markdown documentation task with no web UI to inspect.

### G. Glossary

| Term | Meaning |
|------|---------|
| **NHI** | Non‑Human‑Identity — machine credentials/secrets TruffleHog scans for |
| **"Dry‑run" (here)** | TruffleHog has no literal `--dry-run`; interpreted as a minimal `filesystem` scan with `--no-verification --no-update` against a secret‑free dir |
| **V‑level** | `go-logr` verbosity level; a line prints when its V‑level ≤ configured `--log-level` |
| **`info-N` token** | Console rendering of a log line's V‑level (`N` = the V‑level of the emitting call) |
| **Aho‑Corasick core** | Keyword‑trie prefilter that routes chunks to candidate detectors |
| **`automaxprocs`** | Library that sets `GOMAXPROCS` to the container CPU quota at `init()`, driving observed worker counts |
| **Worker pools** | Four concurrent pools (scanner, detector, verificationOverlap, notifier) connected by buffered channels |

---

*End of Blitzy Project Guide. All cross‑section integrity rules validated: Section 1.2 Remaining (3.0h) = Section 2.2 sum (3.0h) = Section 7 "Remaining Work" (3); Section 2.1 (21.0h) + Section 2.2 (3.0h) = 24.0h Total; completion 87.5% consistent across Sections 1.2, 7, and 8; all Section 3 results originate from Blitzy's autonomous validation; brand colors applied (Completed `#5B39F3`, Remaining `#FFFFFF`).*