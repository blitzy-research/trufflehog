# Blitzy Project Guide — TruffleHog AWS Credential Detection Investigation

> **Deliverable type:** Documentation-only (investigation & explanation report)
> **Source branch:** `trufflehog_e42153d44a5e` · **Audited commit:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`
> **Repository:** TruffleHog (`github.com/trufflesecurity/trufflehog/v3`)

---

## 1. Executive Summary

### 1.1 Project Overview

This project answers a security engineer's five questions about why TruffleHog's AWS credential scanner detects some credentials but misses or differently reports others that look identical. The deliverable is a single, authoritative markdown report — `blitzy/documentation/trufflehog_e42153d44a5e.md` — that explains the deterministic detection gates (keyword prefilter, regex, Shannon-entropy thresholds, false-positive filters, and the verification-overlap safety mechanism) and the decoder pipeline. Every behavioral claim is grounded in exact source citations ("code as truth") and corroborated by reproducible scan output from a locally built binary. The scope is strictly read-only: zero source files are modified, and all investigation artifacts are ephemeral and out-of-tree.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'18px','pieLegendTextSize':'14px'}}}%%
pie showData
    title Project Completion — 88.9% (32h of 36h)
    "Completed Work" : 32
    "Remaining Work" : 4
```

> **Project Completion: 88.9%** — Completed 32h ÷ Total 36h × 100 = 88.9%

| Metric | Hours |
|---|---|
| **Total Hours** | 36 |
| **Completed Hours (AI + Manual)** | 32 (AI: 32 · Manual: 0) |
| **Remaining Hours** | 4 |
| **Percent Complete** | **88.9%** |

*Color key — Completed Work = Dark Blue `#5B39F3`; Remaining Work = White `#FFFFFF`.*

### 1.3 Key Accomplishments

- ✅ Authored the single required deliverable, `blitzy/documentation/trufflehog_e42153d44a5e.md` (414 lines), named after the source branch and placed in `blitzy/documentation/`.
- ✅ Answered all five questions (Q1 detection variance · Q2 encoding · Q3 test-fixture false positives · Q4 "verification disabled for safety" · Q5 entropy boundaries) with a consistent Mechanism / Rationale / Evidence structure.
- ✅ Grounded every behavioral claim in exact, verified source citations (e.g., `RequiredSecretEntropy = 4.25`, the verbatim `errOverlap` message, the decoder chain ordering).
- ✅ Built the scanner out-of-tree (`CGO_ENABLED=0 go build`) and captured reproducible "detected vs. missed" scan output, including the at-threshold entropy pair (4.1552 below vs. 4.3964 above the 4.25 cutoff).
- ✅ Demonstrated that Base64-encoding does not hide a secret (decoder rewrites the chunk; `Decoder Type: BASE64`).
- ✅ Proved test-fixture credentials are filtered by the `example` term (not entropy) using a `--log-level=4` run.
- ✅ Honored every binding constraint: zero source modifications, no extra code, ephemeral fixtures cleaned up, `git status` clean, `go.mod`/`go.sum` untouched.
- ✅ Included a complete reproduction guide and a mermaid pipeline diagram following repository documentation conventions.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| None — no blocking issues identified | The deliverable is complete; all referenced unit tests pass, the binary builds, every citation and empirical claim was independently reproduced, and the source tree is unmodified. | — | — |

### 1.5 Access Issues

**No access issues identified.** The investigation required only the local Go toolchain (`go1.24.2`) and the repository source; the Go module cache is already populated, so no network or credentialed access is needed. No live AWS verification was performed (all fixtures are non-live; verification is disabled in every run).

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| None | — | No external systems, credentials, or third-party APIs are required for this documentation deliverable | N/A | — |

### 1.6 Recommended Next Steps

1. **[High]** Conduct a human technical review and sign-off of the report, confirming it satisfactorily answers the original five questions and spot-checking a sample of source citations at commit `e42153d4`.
2. **[Medium]** Optionally run the reproducibility steps (build the binary, recreate the five fixtures, re-run the scans) to independently confirm the detected-vs-missed outcomes and entropy values.
3. **[Medium]** Approve and merge the documentation pull request to the target branch.
4. **[Low]** If the report is ever revised against a newer commit, re-validate the line-number citations against that revision (citations are pinned to commit `e42153d4`).

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---|---|
| Build environment & out-of-tree binary | 2 | Configure Go `go1.24.2` toolchain; build `trufflehog` with `CGO_ENABLED=0 go build -mod=readonly` (mirrors `Dockerfile`); confirm version "dev". |
| Source investigation — AWS detection gates (Q1) + entropy boundaries (Q5) | 6 | Read & trace `accesskey.go` (keyword prefilter, `idPat`, entropy gates, hash-skip, `CleanResults`), `sessionkey.go` (`ASIA` + session-token gate), `canary.go`, and `common.go` constants; locate exact line ranges. |
| Source investigation — false-positive subsystem (Q3) | 2.5 | Trace `falsepositives.go` (`DefaultFalsePositives`, `IsKnownFalsePositive`, embedded word lists, `StringShannonEntropy`, filters) and the AWS all-hex guard in `utils.go`. |
| Source investigation — decoder pipeline (Q2) | 1.5 | Trace `decoders.go` chain ordering and `base64.go` decode-and-substitute behavior; confirm `DecoderType` tags. |
| Source investigation — verification-overlap engine (Q4) + CLI flags | 3 | Trace `engine.go` `errOverlap`, `likelyDuplicate` (Levenshtein, 0.9 threshold), `SetVerificationError`, `filterResults`; map governing flags in `main.go`. |
| Fixture engineering + Shannon-entropy boundary computation | 3 | Construct five fixtures; compute Shannon entropy exactly as `StringShannonEntropy` to land secrets at 4.1552 (below) and 4.3964 (above) the 4.25 cutoff; build the Base64 pair. |
| Empirical scan capture & verification | 2 | Run the binary across 5 fixtures + 3 output modes + `--log-level=4`; capture verbatim output, byte counts, decoder types, and the false-positive reason. |
| Report authoring (414-line markdown) | 9 | Write the full report: overview + mermaid pipeline diagram, Q1–Q5 (Mechanism/Rationale/Evidence), cross-cutting flags section, appendix with verbatim output, reproduction guide, and summary. |
| Review-finding remediation | 2 | Address review findings in the second commit (`37c11220`) to refine accuracy and completeness. |
| Cleanup & compliance verification | 1 | Remove ephemeral artifacts; verify `git status` clean, `go.mod`/`go.sum` untouched, and markdown well-formedness (balanced fences, valid mermaid, resolving anchors). |
| **Total Completed** | **32** | |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---|---|
| Human technical review & sign-off of the report (read end-to-end; confirm Q1–Q5 answered; spot-check citations; confirm rationale & mermaid render) | 2.5 | High |
| Reproducibility verification (rebuild binary; recreate 5 fixtures; re-run scans; confirm detected/missed outcomes & entropy values) | 1 | Medium |
| Pull request approval & merge (confirm clean diff = only the doc; approve; merge) | 0.5 | Medium |
| **Total Remaining** | **4** | |

> **Hours reconciliation:** Section 2.1 (32h) + Section 2.2 (4h) = **36h Total** (matches Section 1.2).

### 2.3 Hours Methodology

Hours are AAP-scoped (PA1/PA2): every completed entry traces to an AAP deliverable (the report and its evidence) or a required investigation activity (build, fixtures, empirical capture); every remaining entry is a path-to-production human acceptance step. Completion % = Completed ÷ (Completed + Remaining) × 100 = 32 ÷ 36 × 100 = **88.9%**. No items outside AAP scope or path-to-production are included.

---

## 3. Test Results

All tests below are the repository's existing unit suites for the packages the report cites. They were executed by Blitzy's autonomous validation to (a) confirm the documented behavior matches the code and (b) confirm that the read-only investigation introduced **no regressions** (the source tree is unmodified, so the baseline is preserved). Counts include subtests. Integration tests guarded by `//go:build detectors` (live verification) are excluded by design.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---|---|---|---|---|
| Decoders (`pkg/decoders`) | Go `testing` | 54 | 54 | 0 | 89.5% | Covers UTF8/Base64/UTF16/EscapedUnicode — grounds Q2. |
| AWS access keys (`pkg/detectors/aws/access_keys`) | Go `testing` | 3 | 3 | 0 | 21.5% | Detector regex/entropy/FP paths — grounds Q1/Q3/Q5. Live-verification paths behind excluded build tag. |
| AWS session keys (`pkg/detectors/aws/session_keys`) | Go `testing` | 3 | 3 | 0 | 31.7% | `ASIA` detector + session-token gate — grounds Q1/Q5. |
| Detectors framework + false positives (`pkg/detectors`) | Go `testing` | 36 | 36 | 0 | 56.2% | `IsKnownFalsePositive`, `StringShannonEntropy`, filters — grounds Q3/Q5. |
| Engine overlap/duplicate/verification (`pkg/engine`, filtered) | Go `testing` | 10 | 10 | 0 | — (filtered subset) | `Overlap`/`Duplicate`/`Verification` tests — grounds Q4. |
| **Total** | | **106** | **106** | **0** | | **100% pass rate; 0 failures.** |

**Build & static checks (from autonomous validation logs, independently re-confirmed):** `go build ./...` exit 0; `go vet` on referenced packages exit 0; `go mod verify` → "all modules verified"; `go.mod`/`go.sum` unchanged (`-mod=readonly`).

---

## 4. Runtime Validation & UI Verification

**UI:** Not applicable — TruffleHog is a command-line tool; this deliverable concerns CLI scanning behavior and text/JSON output. There is no user interface to verify.

**Runtime validation (binary built from source, run against purpose-built out-of-tree fixtures):**

- ✅ **Operational** — Build: `CGO_ENABLED=0 go build -mod=readonly -o /tmp/th/trufflehog .` → exit 0; `--version` → `trufflehog dev`.
- ✅ **Operational** — Fixture (c) clean ID + above-threshold secret → **1 finding**, `Detector Type: AWS`, `Decoder Type: PLAIN`, 102 bytes (detected).
- ✅ **Operational** — Fixture (e) Base64 of (c) → **1 finding**, `Decoder Type: BASE64`, 101 bytes (encoding defeated; Q2).
- ✅ **Operational** — Fixture (a) `AKIAIOSFODNN7EXAMPLE` + example secret → **0 findings** (missed; Q3).
- ✅ **Operational** — Fixture (b) clean ID + below-threshold secret (entropy 4.1552 < 4.25) → **0 findings** (missed; Q5).
- ✅ **Operational** — Fixture (d) example ID + high-entropy secret (4.3964) → **0 findings**, and `--log-level=4` reports `reason: contains term: example` (proves term filter, not entropy; Q3).
- ✅ **Operational** — "Reported differently" on the same file (c): default `--results` → 1 finding; `--results=verified` → 0 shown (hidden, not undetected); `--json` → one structured object `{DetectorName: AWS, DecoderName: PLAIN, Verified: false, Redacted: AKIAZXO72LMQ4F8VN3PK}`.
- ✅ **Operational** — Shannon-entropy values reproduced to 4 decimals: `AKIAIOSFODNN7EXAMPLE`=3.6842, clean ID=4.1219, below=4.1552, above=4.3964.
- ✅ **Operational** — Word-list sizes confirmed: `288 / 283 / 2871 / 37`.

**API integration:** No live AWS/STS verification performed or required — all fixtures are non-live and verification is disabled in every run.

---

## 5. Compliance & Quality Review

Cross-mapping of AAP deliverables and binding rules to validation outcomes. Every item passed; fixes applied during autonomous validation are noted.

| Requirement / Benchmark | Source | Status | Progress | Notes |
|---|---|---|---|---|
| Single markdown deliverable, named after source branch | Rule SWE-AtlasQnA-Repo | ✅ Pass | 100% | `blitzy/documentation/trufflehog_e42153d44a5e.md` exists (414 lines). |
| Placed in `blitzy/documentation/` | Rule SWE-AtlasQnA-Repo | ✅ Pass | 100% | Correct path. |
| Q1 — Detection variance answered | AAP Req 1 | ✅ Pass | 100% | Deterministic gates cited + reproduced. |
| Q2 — Encoding effect answered | AAP Req 2 | ✅ Pass | 100% | Decoder chain + Base64 substitution; fixture (e). |
| Q3 — Test-fixture false positives answered | AAP Req 3 | ✅ Pass | 100% | FP subsystem; `--log-level=4` proof. |
| Q4 — "Verification disabled for safety" answered | AAP Req 4 | ✅ Pass | 100% | Verbatim `errOverlap`; overlap routing; override flag. |
| Q5 — Boundaries/thresholds with evidence answered | AAP Req 5 | ✅ Pass | 100% | Entropy pair straddling 4.25. |
| Code-as-truth: exact citations, verified | Rule | ✅ Pass | 100% | All spot-checked citations accurate at commit `e42153d4`. |
| Build & run to validate empirically | Rule | ✅ Pass | 100% | Binary built; all behaviors reproduced. |
| Rationale provided for each answer | Rule | ✅ Pass | 100% | Each question has a Rationale subsection. |
| No source files modified | Prompt + Rule | ✅ Pass | 100% | `git diff` = only the doc (A status). |
| No code added besides the document | Rule | ✅ Pass | 100% | Only markdown committed. |
| Ephemeral fixtures cleaned up; `git status` clean | Prompt | ✅ Pass | 100% | Artifacts out-of-tree and removed; working tree clean. |
| `go.mod` / `go.sum` untouched | AAP constraint | ✅ Pass | 100% | No dependency changes (`-mod=readonly`). |
| Match repo documentation conventions (GFM + mermaid) | Rule | ✅ Pass | 100% | 1 mermaid diagram, balanced fences, anchored TOC, GFM tables. |
| Review findings addressed | Validation | ✅ Pass | 100% | Second commit `37c11220` refined the report. |

---

## 6. Risk Assessment

Overall risk profile is **minimal**: a read-only, documentation-only deliverable with zero behavioral change introduces no runtime, dependency, or CI risk.

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Citation drift — line-number citations could become stale if TruffleHog source changes | Technical | Low | Medium | Report pins the exact commit (`e42153d4`) and branch; cited behaviors are stable design constants. | Mitigated |
| Regression from changes | Technical | Low | Low | Zero source modifications; referenced unit suites pass; baseline preserved. | Closed |
| Credential exposure in the document | Security | Low | Low | All keys/secrets are non-live, agent-constructed fixtures (incl. AWS's public `AKIAIOSFODNN7EXAMPLE`); explicit disclaimer; verification disabled. | Mitigated |
| New attack surface / vulnerable dependency | Security | Low | Low | No code, no dependency, no `go.mod`/`go.sum` change. | Closed |
| Reproducibility prerequisites (Go toolchain + module availability) | Operational | Low | Low–Medium | Report specifies `go1.24.2` + `-mod=readonly`; deps pinned in `go.sum`; module cache present. | Mitigated |
| Monitoring / health / logging gaps | Operational | N/A | N/A | Not applicable to a documentation artifact. | N/A |
| Markdown/mermaid rendering on target platform | Integration | Low | Low | Follows existing repo conventions (`docs/process_flow.md`, `docs/concurrency.md` use the same). | Mitigated |
| Cross-file/dependency integration | Integration | Low | Low | Document introduces no imports, config references, or cross-references; nothing depends on it. | Closed |

---

## 7. Visual Project Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'18px','pieLegendTextSize':'14px'}}}%%
pie showData
    title Project Hours Breakdown (Total 36h)
    "Completed Work" : 32
    "Remaining Work" : 4
```

*Completed Work = Dark Blue `#5B39F3` (32h) · Remaining Work = White `#FFFFFF` (4h).*

**Remaining hours by task (Section 2.2):**

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'xyChartBarColor':'#5B39F3'}}}%%
xychart-beta
    title "Remaining Work by Task (hours)"
    x-axis ["Technical Review", "Reproducibility", "PR Merge"]
    y-axis "Hours" 0 --> 3
    bar [2.5, 1, 0.5]
```

| Priority | Hours | Share of Remaining |
|---|---|---|
| High | 2.5 | 62.5% |
| Medium | 1.5 | 37.5% |
| Low | 0 | 0% |
| **Total Remaining** | **4** | **100%** |

> **Integrity check:** "Remaining Work" = **4h** here = Section 1.2 Remaining Hours = sum of Section 2.2 Hours column. ✓

---

## 8. Summary & Recommendations

**Achievements.** The project is **88.9% complete** (32 of 36 hours). The single required deliverable — a 414-line, code-as-truth investigation report — was authored, fully grounds all five of the user's questions in exact source citations, and corroborates each answer with reproducible scan output. The autonomous work was independently re-validated end-to-end: the binary builds cleanly, all 106 referenced unit tests pass with zero failures, all five empirical fixtures reproduce exactly (including the at-threshold entropy pair and the Base64 decode case), and the four computed Shannon-entropy values match to four decimal places. Every binding constraint was honored — zero source modifications, no extra code, ephemeral artifacts removed, and the working tree clean with `go.mod`/`go.sum` untouched.

**Remaining gaps & critical path to production.** The remaining **4 hours (11.1%)** are exclusively human acceptance activities — there is **no rework, no failing test, and no missing content**. The critical path is: (1) human technical review and sign-off of the report's accuracy and completeness [High, 2.5h]; then (2) optional reproducibility verification [Medium, 1h]; then (3) pull-request approval and merge [Medium, 0.5h].

**Success metrics.** All five questions answered with mechanism + rationale + evidence (5/5); citation accuracy on spot-check (100%); empirical-claim reproduction (100%); referenced unit-test pass rate (106/106 = 100%); scope compliance (0 source files changed).

**Production-readiness assessment.** **Ready for human review and merge.** For a documentation deliverable, "production" is the reviewed, approved, and merged report. The content is complete, accurate, well-formed, and committed; the only gate is human sign-off. **Confidence: High** — the deliverable's scope is well-defined and the autonomous work has been exhaustively verified.

| Metric | Value |
|---|---|
| Completion | 88.9% (32h / 36h) |
| Remaining | 4h (human acceptance only) |
| Referenced unit tests | 106 passed / 0 failed |
| Source files modified | 0 |
| Blocking issues | 0 |
| Overall risk | Minimal (all risks Low) |

---

## 9. Development Guide

How to build the analysis instrument, reproduce the investigation, and verify the repository is unmodified. **Every command below was tested during this assessment.** All investigation artifacts live **outside** the repository so the source tree stays pristine.

### 9.1 System Prerequisites

- **Go** `go1.24.2` (matches the `toolchain` directive in `go.mod`; CI pins go-version `1.24`).
- **Git**.
- **Disk:** ~3 GB for the Go module cache, ~200 MB for the compiled binary.
- **OS:** Linux or macOS (this investigation ran on a Linux container).
- **Network:** only if the Go module cache is cold (dependencies are pinned in `go.sum`).

```bash
# Verify the toolchain (expected: go version go1.24.2 ...)
go version
```

### 9.2 Environment Setup

```bash
# From the repository root. No environment variables are required beyond CGO_ENABLED.
# A scratch directory OUTSIDE the repo holds the binary and fixtures.
mkdir -p /tmp/th/fixtures
```

### 9.3 Build the Analysis Binary

```bash
# Mirrors Dockerfile (CGO_ENABLED=0 go build -o trufflehog .).
# -mod=readonly guarantees go.mod/go.sum are NOT rewritten.
CGO_ENABLED=0 go build -mod=readonly -o /tmp/th/trufflehog .

# Verify (expected: trufflehog dev)
/tmp/th/trufflehog --version
```

### 9.4 Create the Fixtures (outside the repo)

```bash
cd /tmp/th/fixtures
printf 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > a_example.txt
printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=VhFwsGGxGGfGP6o1G8P/fhgGuPIc8qdvhx8dZfZo\n'  > b_below.txt
printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9\n'  > c_above.txt
printf 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9\n'  > d_example_highentropy.txt
printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9' | base64 -w0 > e_base64.txt
```

### 9.5 Run the Scans (example usage)

```bash
# DETECTED (PLAIN) — fixture (c): expect unverified_secrets: 1
/tmp/th/trufflehog filesystem c_above.txt --no-verification --results=verified,unverified,unknown --no-update

# DETECTED (BASE64) — fixture (e): encoding does not hide the secret
/tmp/th/trufflehog filesystem e_base64.txt --no-verification --results=verified,unverified,unknown --no-update

# MISSED — fixtures (a)/(b)/(d): expect unverified_secrets: 0
/tmp/th/trufflehog filesystem a_example.txt --no-verification --results=verified,unverified,unknown --no-update

# FALSE-POSITIVE PROOF — fixture (d) at log level 4: reason "contains term: example"
/tmp/th/trufflehog filesystem d_example_highentropy.txt --no-verification --no-update --log-level=4

# "REPORTED DIFFERENTLY" — same file (c), three views
/tmp/th/trufflehog filesystem c_above.txt --no-verification --results=verified,unverified,unknown --no-update  # 1 finding
/tmp/th/trufflehog filesystem c_above.txt --no-verification --results=verified --no-update                     # 0 shown (hidden)
/tmp/th/trufflehog filesystem c_above.txt --no-verification --no-update --json                                  # 1 structured object
```

### 9.6 Verification Helpers

```bash
# Word-list sizes (expected: 288 / 283 / 2871 / 37)
wc -l pkg/detectors/fp_badlist.txt pkg/detectors/fp_words.txt pkg/detectors/fp_programmingbooks.txt pkg/detectors/fp_uuids.txt

# Recompute Shannon entropy exactly as StringShannonEntropy (H = -sum p*log2 p)
python3 -c "import math;from collections import Counter;H=lambda s:-sum((c/len(s))*math.log2(c/len(s)) for c in Counter(s).values());[print(k, round(H(v),4)) for k,v in {'example_id':'AKIAIOSFODNN7EXAMPLE','below':'VhFwsGGxGGfGP6o1G8P/fhgGuPIc8qdvhx8dZfZo','above':'wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9'}.items()]"

# Run the referenced unit suites (all pass)
go test ./pkg/decoders/ ./pkg/detectors/ ./pkg/detectors/aws/access_keys/ ./pkg/detectors/aws/session_keys/ -count=1
go test ./pkg/engine/ -run 'Overlap|Duplicate|Verification' -count=1

# View the deliverable
sed -n '1,60p' blitzy/documentation/trufflehog_e42153d44a5e.md
```

### 9.7 Cleanup & Scope Verification

```bash
# Remove the out-of-tree binary and fixtures
rm -rf /tmp/th

# Confirm the repository is pristine (only the doc was added; deps untouched)
git status --porcelain                                   # expect: empty (clean)
git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760   # expect: A  blitzy/documentation/trufflehog_e42153d44a5e.md
git diff --stat e42153d44a5e5c37c1bd0c70e074781e9edcb760 -- go.mod go.sum   # expect: empty
```

### 9.8 Troubleshooting

- **`go: command not found`** → Install Go 1.24.x and ensure it is on `PATH`.
- **Build attempts a network download** → Warm the module cache, or ensure `-mod=readonly` and a populated `GOMODCACHE`; dependencies are pinned in `go.sum`.
- **A real-looking key is not detected** → Check the ID for `example`/`sample` substrings, verify the secret's Shannon entropy against the `4.25` cutoff, and rule out the all-hex (`[a-f0-9]{40}`) secret guard.
- **"verification has been disabled for your safety"** → A verification-overlap trip (more than one detector matched the same secret). Re-run with `--allow-verification-overlap` only if you understand the cross-provider safety trade-off.
- **Mermaid diagram does not render** → View the markdown in a GitHub-flavored, mermaid-capable renderer.

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---|---|
| `go version` | Confirm Go `go1.24.2`. |
| `CGO_ENABLED=0 go build -mod=readonly -o /tmp/th/trufflehog .` | Build the analysis binary out-of-tree. |
| `/tmp/th/trufflehog filesystem <file> --no-verification --results=verified,unverified,unknown --no-update` | Scan a fixture for AWS credentials. |
| `--log-level=4` | Surface the false-positive skip reason. |
| `--json` | Emit a structured JSON finding. |
| `wc -l pkg/detectors/fp_*.txt` | Confirm embedded word-list sizes (288/283/2871/37). |
| `go test ./pkg/... -count=1` | Run the referenced unit suites. |
| `git status --porcelain` / `git diff --stat <base>` | Verify the source tree is unmodified. |

### B. Port Reference

Not applicable — the investigation uses local filesystem scanning only; no network services, ports, or listeners are involved.

### C. Key File Locations

| Path | Role |
|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The deliverable** (414 lines). |
| `pkg/detectors/aws/access_keys/accesskey.go` | `AKIA`/`ABIA`/`ACCA` detector — Q1/Q3/Q5. |
| `pkg/detectors/aws/session_keys/sessionkey.go` | `ASIA` session-key detector — Q1/Q5. |
| `pkg/detectors/aws/access_keys/canary.go` | Thinkst canary handling — Q1. |
| `pkg/detectors/aws/common.go` | Entropy constants (`4.25`/`3.0`), `SecretPat` — Q1/Q5. |
| `pkg/detectors/aws/utils.go` | All-hex guard, URL-encoded replacer, `CleanResults` — Q1/Q3. |
| `pkg/detectors/falsepositives.go` | FP terms, word-list matching, `StringShannonEntropy`, filters — Q3/Q5. |
| `pkg/detectors/fp_{badlist,words,programmingbooks,uuids}.txt` | Embedded false-positive word lists — Q3. |
| `pkg/decoders/{decoders,base64,utf8,utf16,escaped_unicode}.go` | Decoder chain — Q2. |
| `pkg/engine/engine.go` | `errOverlap`, overlap routing, `filterResults` — Q4. |
| `main.go` | CLI flags governing verification, results, and filtering. |
| `docs/process_flow.md`, `docs/concurrency.md` | Pipeline/concurrency context. |

### D. Technology Versions

| Component | Version | Source |
|---|---|---|
| Go toolchain | `go1.24.2` | `go.mod` `toolchain` directive |
| Go language target | `1.23.1` | `go.mod` `go` directive |
| Module | `github.com/trufflesecurity/trufflehog/v3` | `go.mod` |
| `github.com/wasilibs/go-re2` | v1.9.0 | RE2 regex (AWS patterns) |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Keyword + word-list prefilter |
| `github.com/adrg/strutil` | v0.3.1 | Levenshtein similarity (overlap) |
| `github.com/aws/aws-sdk-go-v2` | v1.36.3 | AWS SDK core (verification) |
| `github.com/aws/aws-sdk-go-v2/service/sts` | v1.33.19 | STS `GetCallerIdentity` |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `CGO_ENABLED` | `0` | Static build, matching the Dockerfile. |
| `GOFLAGS` (optional) | `-mod=readonly` | Prevent `go.mod`/`go.sum` rewrites during build/test. |

No application runtime environment variables (API keys, DB URLs, service endpoints) are required — verification is disabled and no external services are contacted.

### F. Developer Tools Guide

| Tool | Usage |
|---|---|
| `go build` | Compile the analysis binary (`CGO_ENABLED=0`, `-mod=readonly`). |
| `go test` | Run referenced unit suites; add `-v` for subtests, `-cover` for coverage. |
| `go vet` | Static checks on referenced packages (exit 0). |
| `go mod verify` | Confirm module integrity ("all modules verified"). |
| `trufflehog filesystem` | Scan local files; key flags: `--no-verification`, `--results`, `--json`, `--log-level`, `--allow-verification-overlap`, `--filter-entropy`, `--no-update`. |

### G. Glossary

| Term | Meaning |
|---|---|
| **Aho-Corasick prefilter** | Multi-pattern keyword matcher that routes a chunk to a detector only if a keyword (e.g., `AKIA`) is literally present. |
| **Shannon entropy** | Bits-per-character randomness measure, `H = -sum p*log2 p`; AWS secret gate is `4.25`, ID gate `3.0`. |
| **`errOverlap`** | The engine error that disables verification "for your safety" when more than one detector matches the same secret. |
| **Decoder chain** | Ordered transforms (UTF8 → Base64 → UTF16 → EscapedUnicode) applied before detection; decoded bytes are re-scanned. |
| **`CleanResults`** | Verified-preferred de-duplication yielding one result per access-key ID. |
| **STS `GetCallerIdentity`** | The AWS API call used to verify a live access key (not exercised here; verification disabled). |
| **Verified / Unverified / Unknown** | Result states; `--results` controls which are printed; `errOverlap` yields `unknown`. |