# Blitzy Project Guide

**Project:** Run-first investigation — Why TruffleHog reports the same AWS key inconsistently (plain text vs. Base64)
**Repository:** `trufflesecurity/trufflehog` (module `github.com/trufflesecurity/trufflehog/v3`)
**Branch:** `blitzy-65a86cd4-6510-4d0b-a224-2eb9465e278a` (base commit `e42153d4`, source branch `trufflehog_e42153d44a5e`)
**Deliverable:** `blitzy/documentation/trufflehog_e42153d44a5e.md`

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers a single, evidence-backed Markdown answer document that explains — from observed runtime behavior, not code reading alone — why TruffleHog produces inconsistent output when one file contains both a raw AWS access key and the same key in Base64-encoded form. The audience is engineers and security researchers who need an authoritative, reproducible explanation of TruffleHog's decoder pipeline, verification-overlap detection, and result deduplication at commit `e42153d4`. The scope is strictly read-only: the investigation builds and runs the real `trufflehog filesystem` entry point, captures unedited output, reproduces the reported nondeterminism, and grounds every claim in `file:line` references — persisting exactly one new document and modifying no source code.

### 1.2 Completion Status

The completion percentage is computed with the AAP-scoped, hours-based methodology (PA1): only work defined in the Agent Action Plan and its path-to-production activities are counted.

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeWidth":"2px","pieSectionTextColor":"#111111","pieTitleTextSize":"18px"}}}%%
pie showData title Project Completion — 90.0% Complete
    "Completed Work (hrs)" : 27
    "Remaining Work (hrs)" : 3
```

| Metric | Value |
|---|---|
| **Total Hours** | 30.0 |
| **Completed Hours (AI + Manual)** | 27.0 (27.0 AI + 0.0 Manual) |
| **Remaining Hours** | 3.0 |
| **Percent Complete** | **90.0%** |

Calculation: `Completion % = Completed ÷ Total × 100 = 27.0 ÷ 30.0 × 100 = 90.0%`.

### 1.3 Key Accomplishments

- ✅ Authored the single required deliverable at the exact mandated path/name: `blitzy/documentation/trufflehog_e42153d44a5e.md` (632 lines), and created the `blitzy/documentation/` directory.
- ✅ Followed the run-first methodology: built TruffleHog canonically (`CGO_ENABLED=0 go build -o trufflehog .`) and exercised the real `trufflehog filesystem` entry point — captured version banner (`trufflehog dev`, Go 1.24.3).
- ✅ Constructed six fixtures isolating every implied condition: plain text, Base64, Base64+plain on different lines, plain+Base64 collapsing to one line, escaped-Unicode, and a genuine multi-detector overlap case.
- ✅ Captured complete, unedited plain and JSON output for every condition, including the `Decoder Type:` / `DecoderName` fields.
- ✅ Reproduced the reported nondeterminism without stabilizing it: 30 identical runs of the collapse fixture (count always 1, surviving decoder type flips), 15 runs of the two-result fixture (stable at 2), and 12+12 runs toggling `--allow-verification-overlap`.
- ✅ Answered all six questions explicitly and by name, each with Direct Answer / Evidence (`file:line`) / Reasoning, and established the ordering conclusion: deduplication happens **after** overlap detection.
- ✅ Verified read-only compliance: `git diff e42153d4..HEAD` shows only the one document added (632 insertions, 0 source files touched); working tree clean.
- ✅ Independently validated by the autonomous Final Validator inside the canonical container image: 7/7 fixtures reproduced, 3/3 distributions reproduced, ~50/50 code citations accurate, relevant unit tests passing — zero edits required.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| None | No unresolved issues block release. The deliverable is complete, committed, validated, and read-only compliant. | — | — |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| No access issues identified | — | The task is a self-contained, read-only documentation investigation. No repository permissions, service credentials, or third-party API access were required; all runs used `--no-verification` (no network verification). | N/A | — |

### 1.6 Recommended Next Steps

1. **[High]** Review and merge the pull request (single new file, 0 source changes) to the target branch — 0.5h.
2. **[Medium]** Have a subject-matter expert sign off on the document's technical accuracy (verify Q1–Q6, spot-check `file:line` citations against commit `e42153d4`) — 2.0h.
3. **[Low]** Verify the Markdown renders correctly (Mermaid diagram, tables, code fences) in the docs viewer / GitHub preview — 0.5h.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All completed work traces to the single AAP deliverable and its run-first investigation sub-activities. All hours are autonomous (AI) work.

| Component | Hours | Description |
|---|---:|---|
| Codebase mechanism tracing & code citations | 6.0 | Read-only trace of the decoder → engine → output pipeline across ~12 files; ~50 `file:line` citations (decoder chain, overlap routing, `errOverlap`, `likelyDuplicate`, dedupe key, output printers, enum, CLI flags); analysis of the concurrent four-worker-pool model. |
| Canonical build & environment capture | 1.0 | Canonical build `CGO_ENABLED=0 go build -o trufflehog .` in the canonical container image; captured Go 1.24.3 toolchain, `trufflehog dev` version banner, binary, and worker-count startup logs. |
| Fixture construction (6 conditions) | 2.5 | Built plain text, Base64, Base64-first/plain-second, plain-first/Base64-second, escaped-Unicode (via iconv/xxd/sed), and a multi-detector overlap fixture (with a CustomRegex `--config` YAML), plus the AWS-doc example-key false-positive fixture — all outside the repository tree. |
| Per-condition runtime runs (plain + JSON) | 2.5 | Ran the real `trufflehog filesystem` entry point against every fixture in both plain and `--json` modes with `--no-verification --results=verified,unverified,unknown`; captured complete, unedited output. |
| Nondeterminism reproduction | 2.5 | Ran identical inputs repeatedly (30× collapse, 15× two-result, 12×+12× overlap toggle); parsed and tabulated the observed outcome distributions to reproduce (not stabilize) the reported inconsistency. |
| Answer-document authoring (632 lines) | 6.5 | Wrote the full document: title/scope, build/env, fixtures, per-condition runs, distributions, before/after counts, explicit Q1–Q6 answers (answer/evidence/reasoning), Mermaid mechanism flow, version-model caveat, coverage-pass table, read-only cleanup note. |
| Code-review-fix iteration | 2.0 | Addressed code-review findings in a second commit (`4419b073`) — refinements to citations, framing, and coverage. |
| Final autonomous validation | 4.0 | Independent reproduction of every runtime claim inside the canonical read-only image; ~50 citation verifications (zero discrepancies); relevant unit tests (`pkg/decoders`, `pkg/engine` overlap tests, AWS pattern) executed and passing; read-only guarantee re-verified. |
| **Total Completed** | **27.0** | |

### 2.2 Remaining Work Detail

All remaining work is path-to-production for a documentation deliverable (human review and merge). No code, configuration, integration, or deployment work remains.

| Category | Hours | Priority |
|---|---:|---|
| PR review & merge (deploy the doc = merge; single file, 0 source changes) | 0.5 | High |
| SME technical review / sign-off (verify Q1–Q6, spot-check citations at `e42153d4`) | 2.0 | Medium |
| Markdown rendering verification (Mermaid, tables, code fences) | 0.5 | Low |
| **Total Remaining** | **3.0** | |

**Hours reconciliation (integrity check):**

| Check | Result |
|---|---|
| Section 2.1 total (Completed) | 27.0 |
| Section 2.2 total (Remaining) | 3.0 |
| 2.1 + 2.2 = Total Project Hours (§1.2) | 27.0 + 3.0 = **30.0** ✓ |
| Remaining matches §1.2 and §7 | 3.0 = 3.0 = 3.0 ✓ |
| Completion % | 27.0 ÷ 30.0 = **90.0%** ✓ |

---

## 3. Test Results

All tests below originate from Blitzy's autonomous validation logs for this project. Two kinds of validation were performed: (a) the repository's existing Go unit tests covering the exact mechanisms the document cites, and (b) behavioral runtime reproductions of every documented condition through the real CLI. Because this is a strictly read-only documentation deliverable (no source code changed), code-coverage percentages were not the validation metric — pass/fail of the cited-mechanism tests and faithful runtime reproduction were. Coverage is therefore marked "N/A (read-only docs task)".

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---|---|
| Unit — Decoders (`pkg/decoders`) | Go `testing` | 6 | 6 | 0 | N/A (read-only docs task) | `utf8` (2), `utf16` (2), `base64` (1), `escaped_unicode` (1) — covers the four decoder types the document reports. |
| Unit — Engine verification-overlap (`pkg/engine`) | Go `testing` | 2 | 2 | 0 | N/A (read-only docs task) | `TestVerificationOverlapChunk` (cited at `engine_test.go:503`, `wantDupe=0`) and `TestVerificationOverlapChunkFalsePositive` (`:599`); the full `pkg/engine` package passed. |
| Unit — AWS detector pattern | Go `testing` | 1 | 1 | 0 | N/A (read-only docs task) | `TestAWS_Pattern` — validates the AWS access-key detection pattern used by the fixtures. |
| Behavioral — Fixture reproduction | `trufflehog filesystem` CLI | 7 | 7 | 0 | N/A | Fixtures (a) plaintext, (b) base64, (c) two-line 2-result, (d) two-line collapse, (e) escaped-Unicode, (f) multi-detector overlap, (g) example-key false positive — all reproduced with byte-matched stable JSON fields. |
| Behavioral — Nondeterminism distributions | `trufflehog filesystem` CLI (looped) | 3 | 3 | 0 | N/A | (d) 30 runs: count always 1, survivor decoder type varies; (c) 15 runs: stable at 2; (f) overlap toggle: errOverlap 12/12 without flag, 0/12 with flag. |
| Verification — Code citations | Manual + `git`/`grep` | ~50 | ~50 | 0 | N/A | ~50 `file:line` citations verified against commit `e42153d4`; zero discrepancies; quoted dedupe code block byte-identical to `engine.go:1216-1221`. |

**Aggregate:** 9 named Go unit tests passed (0 failed); 10 behavioral runtime reproductions passed (0 failed); ~50 citation checks passed (0 discrepancies). No failing tests.

---

## 4. Runtime Validation & UI Verification

This is a command-line investigation with no UI; "runtime validation" means the real `trufflehog filesystem` entry point was exercised and its output verified. There is no web interface, so UI verification is not applicable.

**Runtime health:**
- ✅ **Operational** — Canonical build succeeds: `CGO_ENABLED=0 go build -o trufflehog .` produces the binary; `--version` prints `trufflehog dev`.
- ✅ **Operational** — Real entry point runs: `trufflehog filesystem <dir> --no-verification --results=verified,unverified,unknown` scans and emits results for every fixture.
- ✅ **Operational** — Plain output surfaces `Detector Type:` and `Decoder Type:` (`PLAIN`, `BASE64`, `ESCAPED_UNICODE` observed).
- ✅ **Operational** — JSON output (`--json`) surfaces `DetectorName` / `DecoderName` and the `VerificationError` overlap message when applicable.
- ✅ **Operational** — Overlap toggle: `--allow-verification-overlap` cleanly suppresses `errOverlap` (0/12 runs with the flag vs 12/12 without).
- ✅ **Operational** — Deduplication behavior observed end-to-end: collapse fixture emits 1 result; two-line fixture emits 2; multi-detector fixture emits 2 (overlap disables verification but does not reduce the count).

**API / integration outcomes:**
- ⚠ **Partial (by design)** — Network verification is intentionally disabled (`--no-verification`); the synthetic AWS/Postman keys surface only as *unverified* results. No external API integration is in scope.

**UI verification:**
- N/A — No user interface; the deliverable is a Markdown document and a CLI investigation.

---

## 5. Compliance & Quality Review

This section cross-maps the AAP deliverables and the governing `SWE-AtlasQnA-Repo` rule to Blitzy's quality benchmarks. Because the task is read-only, "fixes applied during validation" were none — the autonomous validator reproduced every claim and found the document accurate.

| Requirement / Benchmark | Status | Progress | Evidence |
|---|---|---|---|
| Deliverable at `blitzy/documentation/<source_branch>.md` | ✅ Pass | 100% | `blitzy/documentation/trufflehog_e42153d44a5e.md` present and committed. |
| Run-first methodology (build & run before writing) | ✅ Pass | 100% | Doc §2 records canonical build + `trufflehog dev` banner; §4 shows CLI output. |
| Real entry point (`trufflehog filesystem`) | ✅ Pass | 100% | All runs invoke `trufflehog filesystem` (`main.go:143`); no bypass/synthetic interface. |
| Canonical/default configuration + exact commands | ✅ Pass | 100% | Exact build and invocation commands stated (§2); default flags plus `--results` to surface unverified keys. |
| Exhaustive condition coverage | ✅ Pass | 100% | Plain, Base64, escaped-Unicode; overlap present/absent; dedup collapse/no-collapse (fixtures a–f). |
| Reproduce inconsistency (not stabilize) | ✅ Pass | 100% | §5 distributions from repeated identical runs (30/15/12+12). |
| Observed, complete, unedited output for every claim | ✅ Pass | 100% | §4 includes full plain + JSON output per fixture. |
| Every claim grounded in `file:line` or observed output | ✅ Pass | 100% | ~50 citations; validator verified with zero discrepancies. |
| All six questions answered by name | ✅ Pass | 100% | §7 Q1–Q6, each Direct Answer / Evidence / Reasoning. |
| Dedup-vs-overlap ordering stated (after) | ✅ Pass | 100% | §7 Q5 + §7.1 flow: overlap pre-detection (`engine.go:796`), dedup post-detection (`engine.go:1216`). |
| Version-model caveat (single-pass 4-decoder; no `--max-decode-depth`/HTML) | ✅ Pass | 100% | §8. |
| Coverage pass (every named item) | ✅ Pass | 100% | §9 coverage table. |
| Read-only scope (no source modified; temp artifacts removed) | ✅ Pass | 100% | `git diff e42153d4..HEAD` = only the doc; §10 cleanup note; clean tree. |
| Markdown well-formed (fences balanced, LF endings) | ✅ Pass | 100% | 74 fence lines (balanced), 0 CRLF (matches `.gitattributes *.md text eol=lf`). |
| Fixes applied during autonomous validation | ✅ N/A | 100% | None required — document found accurate on independent reproduction. |

**Outstanding compliance items:** None. All benchmarks pass.

---

## 6. Risk Assessment

Risks are assessed across the PA3 categories. Because no source code, configuration, or dependencies changed, the risk surface is minimal and dominated by documentation accuracy and reproducibility.

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| T1 — Deduped-survivor decoder-type split varies run-to-run (doc shows 22/8; validator saw 25/5) | Technical | Low | High | Document frames the **count** as stable (always 1) and the split as an inherent arrival-order/concurrency race; it does not overclaim a fixed ratio. | Mitigated / Accepted |
| T2 — `file:line` citation drift if checked against a different commit | Technical | Low | Medium | Document header pins commit `e42153d4`; all ~50 citations scoped to it. | Mitigated |
| T3 — Worker counts (128 scanner / 1024 detector) are host-specific | Technical | Low | Medium | Document shows counts derive from `runtime.NumCPU()` and explains the derivation. | Mitigated |
| S1 — Synthetic AWS/Postman keys in the doc could trip a secret scanner | Security | Low | Low | Keys are synthetic, randomly generated, non-verifiable; runs use `--no-verification`; TruffleHog's own pre-commit hook uses `--results=verified` (won't flag unverifiable keys); doc states they are not real credentials. | Mitigated |
| O1 — Document not wired into a published docs-site navigation | Operational | Very Low | Low | The `blitzy/documentation/<branch>.md` path/name is the mandated convention, not a site page. | Accepted |
| I1 — Independent reproduction requires the canonical container image + Go 1.24.x | Integration | Low | Low | Doc §2 and the Development Guide (§9) give the exact image, build, and run commands. | Mitigated |

**Overall risk posture:** **Low.** Every identified risk is Low/Very-Low severity and already mitigated or accepted; none blocks release. No security, supply-chain, or regression risk exists because no code ships.

---

## 7. Visual Project Status

**Project hours breakdown** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeWidth":"2px","pieSectionTextColor":"#111111","pieTitleTextSize":"18px"}}}%%
pie showData title Project Hours Breakdown (Total 30.0h)
    "Completed Work" : 27
    "Remaining Work" : 3
```

**Remaining work by priority** (hours from Section 2.2; total = 3.0h):

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#B23AF2","pie2":"#5B39F3","pie3":"#A8FDD9","pieStrokeColor":"#111111","pieStrokeWidth":"1px","pieSectionTextColor":"#111111","pieTitleTextSize":"16px"}}}%%
pie showData title Remaining Work by Priority (3.0h)
    "High — PR review & merge" : 0.5
    "Medium — SME sign-off" : 2.0
    "Low — Markdown render check" : 0.5
```

**Integrity check:** "Remaining Work" = **3.0h** in the pie chart equals the Remaining Hours in §1.2 and the Section 2.2 total. "Completed Work" = **27.0h** equals the §1.2 Completed Hours and the Section 2.1 total.

---

## 8. Summary & Recommendations

**Achievements.** The project delivered exactly what the Agent Action Plan requires: one evidence-backed, run-first answer document (`blitzy/documentation/trufflehog_e42153d44a5e.md`, 632 lines) that resolves all six questions about TruffleHog's decoder pipeline, overlap detection, and deduplication — grounded in ~50 verified `file:line` citations and complete, unedited CLI output for six fixtures. The reported nondeterminism was reproduced (not stabilized) across dozens of identical runs, and the key ordering conclusion — **deduplication happens after overlap detection** — was established both from code and observed behavior.

**Remaining gaps.** None in the AAP-specified scope. The only outstanding work is the standard path-to-production for a documentation change: a human PR review and merge, an SME technical sign-off, and a Markdown rendering check — 3.0 hours total.

**Critical path to production.** (1) SME confirms technical accuracy → (2) approve the PR → (3) merge. There are no build, deployment, integration, or configuration steps because no code ships.

**Success metrics.** All six questions answered by name; ~50/50 citations accurate; 7/7 fixtures and 3/3 distributions reproduced; 9 named unit tests passing; read-only guarantee proven (0 source files changed).

**Production readiness assessment.** The deliverable is **production-ready at 90.0% AAP-scoped completion**. The remaining 10% represents the human review-and-merge gate that has not yet occurred; per Blitzy assessment principles, a documentation deliverable is not marked 100% complete before human sign-off. Confidence is **High** — the scope is a single, well-bounded, fully validated document.

| Metric | Value |
|---|---|
| AAP-scoped completion | 90.0% |
| Total / Completed / Remaining hours | 30.0 / 27.0 / 3.0 |
| Unresolved blocking issues | 0 |
| Source files modified | 0 (read-only) |
| Overall risk posture | Low |

---

## 9. Development Guide

This guide explains how to view/verify the deliverable and how to reproduce the investigation. Commands marked *(tested)* were executed in the authoring environment; build/run commands were verified by the autonomous validator inside the canonical container image and are corroborated by the repository's own `Dockerfile` and `Makefile`.

### 9.1 System Prerequisites

- **Git** ≥ 2.x *(tested: git 2.51.0)* — to view the branch and verify the read-only diff.
- **A build/run environment** — either:
  - the canonical container image `ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0` (ships Go 1.24.3), **or**
  - a local **Go** toolchain satisfying `go.mod` (`go 1.23.1`, `toolchain go1.24.2`; Go 1.24.x recommended).
- **Docker** ≥ 20.x *(tested: Docker 28.5.2)* — only if building via the canonical container.
- A Markdown viewer with **Mermaid** support (e.g., GitHub) — to render §7.1's flowchart and this guide's charts.
- OS: Linux/macOS (amd64/arm64). No special hardware required.

> Note: the authoring host does not have Go on `PATH` — as the AAP states, the authoring environment does not itself build/run the scanner. Perform build/run in the canonical image or a Go-equipped host.

### 9.2 View & Verify the Deliverable

```bash
# From the repository root, on branch blitzy-65a86cd4-6510-4d0b-a224-2eb9465e278a

# 1. Confirm the deliverable exists (632 lines)
wc -l blitzy/documentation/trufflehog_e42153d44a5e.md

# 2. Prove read-only compliance: ONLY the document was added (expect a single 'A' line)
git diff e42153d4..HEAD --name-status
#   A   blitzy/documentation/trufflehog_e42153d44a5e.md

# 3. Confirm a clean working tree
git status --porcelain    # (tested: no output = clean)

# 4. Markdown health checks (tested)
grep -c '^```' blitzy/documentation/trufflehog_e42153d44a5e.md   # 74 (even = balanced)
grep -c '```mermaid' blitzy/documentation/trufflehog_e42153d44a5e.md  # 1
grep -cE '^### Q[1-6] ' blitzy/documentation/trufflehog_e42153d44a5e.md  # 6 (Q1..Q6)
grep -c $'\r' blitzy/documentation/trufflehog_e42153d44a5e.md    # 0 (LF endings)
```

### 9.3 Reproduce the Investigation (optional, to independently verify claims)

**Option A — canonical container (recommended):**

```bash
# Build inside the canonical image with the repo mounted READ-ONLY
docker run --rm -v "$PWD":/src:ro -w /src \
  ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0 \
  -c 'CGO_ENABLED=0 go build -o /tmp/trufflehog .'
```

**Option B — local Go toolchain:**

```bash
# From the repository root (requires Go 1.24.x)
CGO_ENABLED=0 go build -o trufflehog .
./trufflehog --version        # expect: trufflehog dev
```

**Create fixtures OUTSIDE the repository tree** (keeps the repo read-only), then run the real entry point:

```bash
mkdir -p /tmp/th/fixtures/a_plaintext /tmp/th/fixtures/b_base64

# (a) plain text
printf 'aws_access_key_id = AKIA2HAFCFGWPBBBW43J aws_secret_access_key = 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\n' \
  > /tmp/th/fixtures/a_plaintext/secrets.txt

# (b) Base64 of that same line
base64 -w0 /tmp/th/fixtures/a_plaintext/secrets.txt > /tmp/th/fixtures/b_base64/secrets.txt

# Run plain output
./trufflehog filesystem /tmp/th/fixtures/a_plaintext \
  --no-verification --results=verified,unverified,unknown

# Run JSON output
./trufflehog filesystem /tmp/th/fixtures/b_base64 --json \
  --no-verification --results=verified,unverified,unknown
```

**Reproduce the nondeterministic collapse** (count always 1; surviving `Decoder Type` flips between `PLAIN` and `BASE64` across runs):

```bash
# Put plain text on line 1 and the Base64 blob on line 2 (fixture d), then loop:
for i in $(seq 1 30); do
  ./trufflehog filesystem /tmp/th/fixtures/d_twoline_plainfirst --json \
    --no-verification --results=verified,unverified,unknown 2>/dev/null \
    | grep -o '"DecoderName":"[A-Z_]*"'
done | sort | uniq -c
```

**Run the unit tests that cover the cited mechanisms** (from the repo root, Go environment):

```bash
go test ./pkg/decoders/... -v
go test ./pkg/engine/ -run TestVerificationOverlap -v
make test        # full unit suite
make test-race   # race detector — corroborates the concurrency claims
```

### 9.4 Verification Steps & Expected Output

- `trufflehog filesystem <dir>` on a single AWS key → **1** result, `Decoder Type: PLAIN` (or `BASE64` for the encoded fixture).
- Two-line fixture with Base64 and plain on **different** lines → **2** results (`PLAIN` + `BASE64`).
- Two-line fixture collapsing to the **same** line metadata → **1** result (dedup collapse).
- Multi-detector fixture without `--allow-verification-overlap` → **2** results, exactly one carrying `Verification issue: More than one detector has found this result…`.
- Same fixture **with** `--allow-verification-overlap` → **2** results, **no** overlap message.

### 9.5 Troubleshooting

- **No results appear.** Unverified keys surface only with `--no-verification` and a `--results` selection that includes `unverified` (`main.go:59`, `main.go:61`).
- **AWS example key yields 0 results.** The AWS-documentation id `AKIAIOSFODNN7EXAMPLE` is dropped as a known false positive ("contains term: example", `pkg/detectors/falsepositives.go`). Use a synthetic `AKIA`-format key (as the document does).
- **Decoder-type split differs from the document (e.g., you see 25/5 not 22/8).** This is expected — the surviving decoder type is an inherent concurrency race. The **count** is stable (1 for the collapse fixture); the reported decoder type varies run-to-run (risk T1).
- **Worker counts differ from the document (128/1024).** Counts scale with `runtime.NumCPU()`, so they depend on the host's CPU count.
- **Build fails on Go version.** Ensure the toolchain satisfies `go.mod` (`go 1.23.1` / `toolchain go1.24.2`); use Go 1.24.x or the canonical image.
- **`git status` shows unexpected files.** The investigation must leave the repo unchanged except for the deliverable; remove any temporary fixtures/scripts (create them under `/tmp`, never in the repo).

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---|---|
| `git diff e42153d4..HEAD --name-status` | Prove read-only: only the deliverable added |
| `git status --porcelain` | Confirm clean working tree |
| `wc -l blitzy/documentation/trufflehog_e42153d44a5e.md` | Confirm 632 lines |
| `CGO_ENABLED=0 go build -o trufflehog .` | Canonical build |
| `./trufflehog --version` | Print version banner (`trufflehog dev`) |
| `./trufflehog filesystem <dir> --no-verification --results=verified,unverified,unknown` | Canonical run |
| `./trufflehog filesystem <dir> ... --json` | Machine-readable output (`DecoderName`) |
| `./trufflehog filesystem <dir> ... --allow-verification-overlap` | Toggle overlap suppression |
| `go test ./pkg/decoders/... ./pkg/engine/...` | Run cited-mechanism unit tests |
| `make test` / `make test-race` / `make lint` | Full unit suite / race detector / linter |

### B. Port Reference

Not applicable — the deliverable is a CLI investigation and a Markdown document. No network ports are opened (all runs use `--no-verification`).

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (only persisted change) |
| `pkg/decoders/decoders.go` | Decoder chain `DefaultDecoders()` (`:8-16`) |
| `pkg/decoders/{utf8,base64,utf16,escaped_unicode}.go` | The four decoders and their `Type()` |
| `pkg/engine/engine.go` | `scannerWorker`, overlap routing (`:796`), `errOverlap` (`:39-42`), dedupe key (`:1216-1221`), notifier |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | `FindDetectorMatches` (detector cardinality) |
| `pkg/pb/detectorspb/detectors.pb.go` | `DecoderType` enum (`:26-30`) |
| `pkg/output/plain.go` | `Detector Type:` / `Decoder Type:` (`:63-64`) |
| `pkg/output/json.go` | `DetectorName` / `DecoderName` (`:63,65`) |
| `main.go` | `filesystem` command (`:143`) and flags (`:55/58/59/61/65`) |
| `README.md` | Canonical output shape + test key `AKIAYVP4CIPPERUVIFXG` |

### D. Technology Versions

| Component | Version |
|---|---|
| Go module target | `go 1.23.1` (`go.mod:3`) |
| Go toolchain (pinned) | `go1.24.2` (`go.mod:5`) |
| Go toolchain (canonical image, observed) | `go1.24.3 linux/amd64` |
| TruffleHog build banner | `trufflehog dev` |
| Canonical container image | `ghcr.io/scaleapi/swe-atlas:swe_atlas_QnA_trufflesecurity_trufflehog_1.0` |
| Git (authoring host) | 2.51.0 |
| Docker (authoring host) | 28.5.2 |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `CGO_ENABLED` | `0` | Canonical static build (matches `Dockerfile`) |

No secrets or credentials are required; all runs use `--no-verification`. The AWS/Postman keys in the document are synthetic and non-verifiable.

### F. Developer Tools Guide

| Tool | Use |
|---|---|
| `go build` / `go test` | Build the scanner and run the cited-mechanism unit tests |
| `make` targets (`test`, `test-race`, `lint`, `run`) | Repository-standard build/test/lint workflow |
| `base64`, `iconv`, `xxd`, `sed` | Construct the Base64 and escaped-Unicode fixtures |
| `--config <yaml>` (CustomRegex) | Add a second detector to force the multi-detector overlap case |
| `grep`/`jq` | Parse `--json` output when tabulating run-to-run distributions |
| Docker | Build/run inside the canonical image with the repo mounted read-only |

### G. Glossary

| Term | Meaning |
|---|---|
| **Decoder** | A transformer applied to each chunk (UTF8/`PLAIN`, Base64, UTF16, EscapedUnicode) that may recover a secret from an encoded form. |
| **Decoder Type** | Which decoder recovered the matched bytes; reported as `Decoder Type:` (plain) / `DecoderName` (JSON). Enum: `PLAIN`, `BASE64`, `UTF16`, `ESCAPED_UNICODE`. |
| **Overlap detection** | Routing that fires when a single decoded chunk is matched by more than one detector; disables verification and emits `errOverlap` unless `--allow-verification-overlap` is set. |
| **Deduplication** | Post-detection step in the notifier that skips a later result sharing an earlier one's key (`DetectorType + Raw + RawV2 + SourceMetadata`) but with a different decoder type. |
| **`errOverlap`** | The verification error "More than one detector has found this result. For your safety, verification has been disabled…" (`engine.go:39-42`). |
| **Dedupe key** | `DetectorType + Raw + RawV2 + SourceMetadata` — excludes decoder type, includes source metadata (`engine.go:1216`). |
| **Unverified result** | A finding emitted without network verification; surfaced via `--no-verification` and `--results` including `unverified`. |
| **AAP** | Agent Action Plan — the governing specification for this task. |