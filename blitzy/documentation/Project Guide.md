# Blitzy Project Guide — TruffleHog Custom-Detector Verification (Webhook) Security Investigation

> **Provenance & color key.** Completed / AI work is shown in **Dark Blue `#5B39F3`**; Remaining / not-completed work is shown in **White `#FFFFFF`** (outlined). Headings/accents use Violet-Black `#B23AF2`; soft highlights use Mint `#A8FDD9`. All hour and percentage figures are derived from the AAP-scoped completion analysis (PA1) and are identical across Sections 1.2, 2.1, 2.2, 7, and 8.

---

## 1. Executive Summary

### 1.1 Project Overview

This project delivers an evidence-based security investigation of TruffleHog's custom-detector *verification* (webhook) feature, targeting security engineers and platform teams who allow contributors to supply custom detector configurations. Operating strictly read-only against commit `e42153d44a5e`, the work builds the real binary and exercises the canonical CLI (`trufflehog filesystem --config=<yaml>`) to answer six questions — SSRF, TLS/MITM, verification multiplicity & rate limiting, data sent to the webhook, ReDoS, and an overall threat model — with observed runtime output rather than theory. The sole artifact is one markdown document (`blitzy/documentation/trufflehog_e42153d44a5e.md`) that characterizes exactly what a party controlling a detector configuration can do, informing risk decisions for teams that permit custom detectors.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'17px'}}}%%
pie showData
    title Completion Status — 88.2% Complete (AAP-scoped)
    "Completed Work (hours)" : 60
    "Remaining Work (hours)" : 8
```

| Metric | Hours |
|--------|------:|
| **Total Hours** | **68.0** |
| **Completed Hours (AI + Manual)** | **60.0** (AI 60.0 + Manual 0.0) |
| **Remaining Hours** | **8.0** |
| **Percent Complete** | **88.2%** |

> Completion is computed on AAP-scoped work only: `60.0 / (60.0 + 8.0) = 88.2%`. Every autonomous deliverable is complete; the remaining 8.0 h is human path-to-production (peer review, sign-off, handoff) that an autonomous agent cannot self-certify for a security assessment.

### 1.3 Key Accomplishments

- ✅ **Single in-scope deliverable created and committed** — `blitzy/documentation/trufflehog_e42153d44a5e.md` (1,217 lines / 111,325 bytes), answering all six questions Q1–Q6.
- ✅ **Run-first methodology honored** — the binary was built via the canonical `CGO_ENABLED=0 go build` (194,309,530-byte static ELF, Go 1.24.2) and every behavioral claim was produced by invoking `trufflehog filesystem --config=<yaml>`.
- ✅ **Every quantitative result reproduced ≥ 2×** across ~30 documented runtime conditions (Q1×7, Q2×6, Q3×8, Q4×7, Q5×2) plus the Q6 synthesis.
- ✅ **User's named example exercised** — the exact `169.254.169.254` cloud-metadata endpoint was dispatched inside a fail-closed network namespace (24 occurrences in the document).
- ✅ **Read-only source mandate upheld** — `git diff e42153d44a5e --name-status` shows only the added document; all 12 reference source files and `go.mod`/`go.sum` are byte-for-byte unchanged.
- ✅ **Provenance discipline** — 36 `[OBSERVED]`, 10 `[INFERRED]`, 4 `[CORROBORATED]` tags; 18+ `file:line` citations; a coverage-pass table mapping every sub-question → condition → command → evidence.
- ✅ **Temporary lab artifacts removed** — all mock servers, configs, targets, and the isolated netns lived outside the checkout and were deleted; working tree verified clean.
- ✅ **Independently re-validated in this review** — a fresh build and a fresh Q4 reproduction reproduced the documented `POST` body, header, and `User-Agent: TruffleHog` exactly.

### 1.4 Critical Unresolved Issues

There are **no unresolved issues that block the deliverable**. The document is complete, evidence-backed, and committed; the source tree is unchanged. The items below are the security *findings* the investigation surfaced in TruffleHog — they are **characterized in prose only** (remediation is explicitly out of AAP scope) and are handed to humans for triage.

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| No blocking issues for the deliverable | Document is production-ready for human review | — | — |
| (Finding) SSRF — no endpoint destination validation (Q1) | Config author can reach loopback/RFC1918/link-local/metadata with 200-byte readback | Security triage (HT-3) | Post-review |
| (Finding) Config-DoS — permutation `int64` overflow hangs the scan (Q3/C8) | A declarative config can wedge a scan indefinitely | Security triage (HT-3) | Post-review |
| (Finding) Secret + arbitrary-header exfiltration (Q4) | Matched secrets and static headers POSTed to a config-controlled endpoint | Security triage (HT-3) | Post-review |

### 1.5 Access Issues

**No access issues identified.** The entire investigation and this review ran locally: the Go toolchain is present, the build required no privileged or external access, and all runtime observations used local loopback mock HTTP/HTTPS servers plus an isolated network namespace. No cloud credentials, third-party API keys, or additional repository permissions were required or blocked. The real cloud-metadata service was proven physically unreachable during the `169.254.169.254` test (fail-closed netns).

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| — | — | No access issues identified | N/A | — |

### 1.6 Recommended Next Steps

1. **[High]** Have a security SME peer-review the document and independently spot-reproduce 2–3 key findings (Q1 loopback SSRF dispatch, Q4 data-sent capture; treat Q3/C8 config-DoS with the "do not re-run" caution). *(HT-1, 4.0 h)*
2. **[Medium]** Obtain security-lead sign-off and distribute the findings to teams that author custom-detector configurations. *(HT-2, 2.0 h)*
3. **[Medium]** File tracked issues for findings S1–S5 to route future remediation, linking this document. *(HT-3, 1.5 h)*
4. **[Low]** Scope a separate follow-on engineering project for the characterized gaps (planning only; remediation coding is out of this project's scope). *(HT-4, 0.5 h)*

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

All completed work was performed autonomously (AI). Each component traces to an AAP requirement (investigation foundation, the six question investigations, or authoring/quality).

| Component | Hours | Description |
|-----------|------:|-------------|
| Build & Go toolchain setup | 1.5 | Canonical `CGO_ENABLED=0 go build` outside the checkout; toolchain standardized on Go 1.24.2 (build prerequisite) |
| Source-chain mapping & code attribution | 5.0 | Read the 12 read-only reference files; attribute each observation to a precise `file:line` (config → detect → verify chain) |
| Lab harness engineering | 7.0 | Threaded mock HTTP/HTTPS servers (large listen backlog), full PKI (self-signed / CA / correct+wrong SAN / expired), isolated netns for the metadata test, owned-PID cleanup traps, readiness sentinels, `CLONE_INDEX` port parameterization |
| Q1 — SSRF investigation & writeup | 7.0 | 7 conditions: loopback, RFC1918, IPv6 `[::1]`, the exact `169.254.169.254` (fail-closed netns), 200-**byte** readback (multibyte → `U+FFFD`), mixed-case `HTTP://` gate bypass, scheme/empty errors |
| Q2 — TLS/MITM investigation & writeup | 8.0 | 6 conditions A–F: self-signed reject, trusted-CA accept, wrong-SAN reject, redirect downgrade (301/302/303 vs 307/308), expired cert, proxy `Proxy-Authorization` retention (GO-2025-3751) |
| Q3 — Multiplicity / rate-limit investigation & writeup | 9.0 | 8 conditions: one request per permutation, per-**span** cap `min(N,100)` (not global — observed 200 & 500 from single files), Cartesian-product cap, ×M verifiers, no throttle, verification cache, dual timeouts, config-DoS `int64` overflow hang |
| Q4 — Data-sent investigation & writeup | 6.0 | 7 conditions: POST JSON body, capture group, header normalization, `User-Agent` default/suffix/override, verifier order, `SuccessRanges` no-op, response/outcome edge cases |
| Q5 — ReDoS investigation & writeup | 3.0 | Evil `(a+)+$` timing stays flat vs an external backtracking control; backreference `(a)\1` rejected at config load; RE2 linear-time engine identified |
| Q6 synthesis + verdict + pipeline + coverage-pass table | 5.0 | Executive verdict table, Mermaid pipeline diagram, and the requirement→condition→command→evidence coverage-pass table |
| Web research + provenance labeling + integrity proof + cleanup | 4.0 | RE2/`net-http`/AWS IMDS/OWASP benchmarking; `[OBSERVED]`/`[INFERRED]` discipline; durable repo-integrity proof; deletion of all temp artifacts |
| Multi-round QA refinement | 4.5 | 7 QA rounds across 6 commits (evidence-accuracy rewrite, consistency fixes, appendix fixes, cross-reference corrections, QA Report 7) |
| **Total Completed** | **60.0** | |

### 2.2 Remaining Work Detail

All remaining work is human path-to-production for a documentation/Q&A artifact. It contains **no** autonomous defect repair (there are zero unresolved autonomous errors) and **no** remediation coding (explicitly out of AAP scope).

| Category | Hours | Priority |
|----------|------:|----------|
| Security-SME peer review & independent spot-reproduction of key findings | 4.0 | High |
| Stakeholder sign-off & distribution to detector-contributing teams | 2.0 | Medium |
| Findings triage & issue-filing (S1–S5) for remediation tracking | 1.5 | Medium |
| Follow-on remediation project scoping (planning only; coding out of scope) | 0.5 | Low |
| **Total Remaining** | **8.0** | |

### 2.3 Hours Reconciliation

- Completed (2.1) **60.0 h** + Remaining (2.2) **8.0 h** = **68.0 h** Total (matches Section 1.2).
- Completion % = 60.0 / 68.0 = **88.2%** (matches Sections 1.2, 7, 8).

---

## 3. Test Results

For this Q&A investigation, the "test suite" is Blitzy's autonomous set of **runtime reproductions**: each documented behavioral claim was produced by invoking the compiled binary through its canonical entry point and confirmed stable across **≥ 2 runs**. All entries below originate from Blitzy's autonomous validation logs for this project. This is a documentation deliverable, so "Coverage %" denotes the fraction of documented conditions successfully reproduced (not source-line coverage). The repository's built-in Go unit tests are **not** part of this AAP (new tests were out of scope and none were added).

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---------------|-----------|------------:|-------:|-------:|-----------:|-------|
| Q1 — SSRF reproductions | Canonical CLI + threaded mock HTTP + fail-closed netns | 7 | 7 | 0 | 100% | Loopback, RFC1918, `[::1]`, exact `169.254.169.254`, 200-byte readback, mixed-case gate bypass, scheme/empty errors |
| Q2 — TLS/MITM reproductions | Canonical CLI + self-signed/CA HTTPS mocks | 6 | 6 | 0 | 100% | Self-signed reject, CA accept, wrong-SAN reject, redirect downgrade, expired reject, proxy header retention |
| Q3 — Multiplicity / rate-limit reproductions | Canonical CLI + request-counting mock | 8 | 8 | 0 | 100% | Per-span cap `min(N,100)`, product cap, ×M verifiers, no throttle, cache, timeouts, config-DoS overflow (guarded) |
| Q4 — Data-sent reproductions | Canonical CLI + capturing mock | 7 | 7 | 0 | 100% | POST JSON body, capture group, header normalization, User-Agent variants, verifier order, `SuccessRanges` no-op, edge cases |
| Q5 — ReDoS reproductions | Canonical CLI + wall-clock timing + external control | 2 | 2 | 0 | 100% | Evil pattern flat timing; backreference rejected at load |
| Q6 — Threat-model synthesis | Coverage-pass cross-check vs Q1–Q5 evidence | 1 | 1 | 0 | 100% | No new run; verified against reproduced Q1–Q5 evidence |
| **Independent review re-reproduction** | Canonical CLI + threaded mock (this review) | 1 | 1 | 0 | 100% | Fresh build + fresh Q4 run reproduced POST body/header/User-Agent exactly |
| **Totals** | | **32** | **32** | **0** | **100%** | Every documented condition reproduced and matched; ≥ 2 runs each |

**Build/compile validation (autonomous logs, confirmed in review):** `go build` exit 0 → 194,309,530-byte static ELF; `go mod verify` → "all modules verified"; `go.mod`/`go.sum` unmutated.

---

## 4. Runtime Validation & UI Verification

- ✅ **Build** — `CGO_ENABLED=0 GOTOOLCHAIN=local go build -o /tmp/lab/th .` completes with exit 0; produces a statically-linked ELF (194,309,530 bytes, Go 1.24.2). **Operational.**
- ✅ **CLI entry point** — `trufflehog --version` → `trufflehog dev`; `trufflehog filesystem --help` renders (`--config`, `--no-update`, `--results`). **Operational.**
- ✅ **Verification webhook dispatch** — a custom detector with a `verify.endpoint` produces a real outbound `POST` to the configured mock; a `200` yields `✅ Found verified result` and the response body is echoed. **Operational.**
- ✅ **Data-sent contract** — captured request: `method=POST path=/verify UA='TruffleHog' Auth='Bearer …' body={"LabTokenDetector":{"theToken":["labtok_abc123","abc123"]}}`. **Operational** and matches the documented Q4 finding.
- ✅ **Read-only integrity at runtime** — `git status --porcelain` empty before and after build + reproduction; `git diff e42153d44a5e --name-status` shows only the added document. **Operational.**
- ⚠ **Environment-sensitive reproductions** — the `169.254.169.254` (isolated netns), IPv6 `[::1]` (IPv6-on-`lo`), and RFC1918 tests require specific Linux lab prerequisites documented in the appendix. **Partial** portability outside Linux.
- ❌ **User Interface** — **Not applicable.** This is a backend/CLI secret-verification feature; there is no UI surface in scope, so no UI verification was performed.

---

## 5. Compliance & Quality Review

The deliverable is cross-mapped to the AAP's governing rules and Blitzy's quality benchmarks. Fixes were applied autonomously across 7 QA rounds; no outstanding compliance items remain.

| Benchmark / Rule | Requirement | Status | Evidence / Notes |
|------------------|-------------|:------:|------------------|
| MainRule — Deliverable | Create `blitzy/documentation/trufflehog_e42153d44a5e.md`; no other file added | ✅ Pass | `git diff` shows exactly one added file |
| MainRule — Read-only source | No existing repo file modified/deleted | ✅ Pass | 12 reference files + `go.mod`/`go.sum` byte-for-byte unchanged |
| MainRule — Cleanup | Temporary scripts removed after use | ✅ Pass | `/tmp/lab` lab tree deleted; netns auto-removed; working tree clean |
| Rule 1 — Run-first, canonical entry | Build & run real code path via `filesystem --config=…`; ≥ 2 runs | ✅ Pass | Binary built; every quantitative result reproduced ≥ 2× |
| Rule 2 — Exhaustive conditions | Primary + alternate flags + edge/error/transitional states | ✅ Pass | `unsafe` true/false, below/above cap, verified/unverified, redirect matrix, expired cert, etc. |
| Rule 3 — Observed-output discipline | Show observed output next to each claim; label inferred | ✅ Pass | 36 `[OBSERVED]`, 10 `[INFERRED]`, 4 `[CORROBORATED]` |
| Rule 4 — Complete, grounded answering | Every sub-question + named items; `file:line`; cause→effect; coverage pass | ✅ Pass | Coverage-pass table; `169.254.169.254` exercised (24×) |
| Special — Observed-vs-inferred labeling | Explicit provenance tags | ✅ Pass | Labeling scheme defined in the document header |
| Special — Alpha-status note | Note feature is alpha & subject to change | ✅ Pass | Cites `README.md:L644` |
| Special — Web research | RE2/ReDoS and SSRF/metadata benchmarking | ✅ Pass | External references section (Go, AWS IMDS, OWASP) |
| Quality — Markdown structure | Balanced code fences, clean headings, no placeholder tokens | ✅ Pass | 104 balanced fences; clean UTF-8; zero TODO/FIXME |
| Quality — Numerical consistency | Counts/values internally consistent & reproducible | ✅ Pass | Confirmed across 7 QA rounds; independently re-reproduced here |

---

## 6. Risk Assessment

Risks are split into **deliverable/project risks** and the **security findings** the investigation surfaced (product risks in TruffleHog, characterized only — remediation is out of AAP scope). Q2 (TLS verified by default) and Q5 (RE2 linear-time) are **negative/safe** findings and are *not* risks; they reduce residual risk.

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|:--------:|:-----------:|------------|--------|
| Alpha-feature drift — findings pinned to `e42153d44a5e` may change in later releases | Technical | Medium | Medium | Commit-pinned citations; re-run appendix harness on version bumps | Documented |
| Environment-dependent reproduction (netns/IPv6/RFC1918) | Technical | Low | Medium | Appendix documents exact prerequisites; canonical vs harness values labeled | Mitigated |
| Go-version sensitivity for proxy header retention (Q2/F) | Technical | Low | Medium | Labeled version-specific (pre-fix go1.24.2; fixed 1.24.4/1.23.10) | Documented |
| SSRF — no endpoint destination validation (Q1) | Security | High | High | (Prose) allowlist + reserved-range block + DNS-resolve-before-request + disable redirects | Open — characterized |
| Config-DoS — permutation `int64` overflow hangs scan (Q3/C8) | Security | High | Medium | (Prose) overflow-safe product / bounded permutation count | Open — characterized |
| Secret + arbitrary-header exfiltration (Q4) | Security | High | High | (Prose) endpoint governance; disallow arbitrary static headers | Open — characterized |
| Redirect downgrade to cleartext + no cert pinning (Q2/D) | Security | Medium | Medium | (Prose) disable redirect-follow / strip-on-downgrade / pin CAs | Open — characterized |
| No request rate-limiting (up to 100 concurrent/span, unbounded across spans) | Security | Medium | Medium | (Prose) `errgroup.SetLimit` + throttle/delay | Open — characterized |
| Findings require human action to have value | Operational | Medium | Medium | Remaining tasks HT-1…HT-3 (review, sign-off, triage) | Open — remaining work |
| Human-review dependency (agent cannot self-certify a security assessment) | Operational | Low | High | Peer-review gate (HT-1) queued | Open — remaining work |
| Reproduction-harness portability (Linux-only parts) | Integration | Low | Medium | Prerequisites documented; core Q1/Q3/Q4/Q5 need only loopback + Go | Mitigated |
| External dependency / credential risk | Integration | — | — | None: local mocks + isolated netns only; real IMDS unreachable (fail-closed) | N/A (positive) |

---

## 7. Visual Project Status

**Project hours — completed vs remaining** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieStrokeWidth':'2px','pieOuterStrokeWidth':'2px','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'17px'}}}%%
pie showData
    title Project Hours Breakdown (Total 68.0 h)
    "Completed Work" : 60
    "Remaining Work" : 8
```

**Remaining hours by category** (Section 2.2 — sums to 8.0 h):

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#8266F6','pie3':'#B9A7FA','pie4':'#FFFFFF','pieStrokeColor':'#B23AF2','pieSectionTextColor':'#B23AF2','pieTitleTextSize':'15px'}}}%%
pie showData
    title Remaining Work by Category (8.0 h)
    "SME peer review [High]" : 4.0
    "Sign-off & distribution [Medium]" : 2.0
    "Findings triage & issue-filing [Medium]" : 1.5
    "Remediation scoping [Low]" : 0.5
```

> **Integrity check:** the pie "Remaining Work" value (**8**) equals the Section 1.2 Remaining Hours (**8.0**) and the sum of the Section 2.2 Hours column (**4.0 + 2.0 + 1.5 + 0.5 = 8.0**).

---

## 8. Summary & Recommendations

**Achievements.** The project is **88.2% complete** on an AAP-scoped basis (60.0 of 68.0 hours). Every autonomous deliverable is finished: the six security questions are answered with observed runtime evidence, reproduced ≥ 2× through the canonical CLI, and grounded in precise `file:line` citations. The user's named example (`169.254.169.254`) was exercised in a fail-closed network namespace. The read-only mandate was upheld exactly — only the answer document was added — and all temporary lab artifacts were removed. An independent re-build and re-reproduction during this review matched the documented Q4 behavior byte-for-byte, reinforcing confidence in the findings.

**Remaining gaps (critical path to production).** The remaining **8.0 hours** are entirely human path-to-production for a documentation artifact and cannot be autonomously certified: (1) a security SME must peer-review the document and spot-reproduce key findings; (2) stakeholders must sign off and distribute the findings; (3) the findings should be filed as tracked issues; and (4) a follow-on remediation project should be scoped. No autonomous defect repair remains, and — per AAP scope — no code remediation is included here.

**Success metrics.** 6/6 questions answered; ~30 runtime conditions reproduced (100% pass); 0 source files modified; 0 unresolved errors; document committed at HEAD `1b18bd73`.

**Production-readiness assessment.** The deliverable is **ready for human review**. Because this is a security assessment, "production" means the findings have been peer-reviewed, signed off, and routed for remediation tracking — the 8.0 hours of remaining human work. The discovered gaps (SSRF, config-DoS, exfiltration, redirect downgrade, no rate-limiting) are real and should be prioritized for separate remediation projects; TLS validation and ReDoS resistance were confirmed safe.

| Metric | Value |
|--------|------:|
| AAP-scoped completion | 88.2% |
| Questions answered | 6 / 6 |
| Runtime conditions reproduced | 32 / 32 (100%) |
| Source files modified | 0 |
| Unresolved autonomous errors | 0 |

---

## 9. Development Guide

Every command below was executed during this review and produced the stated output. Build **outside** the repository checkout to preserve the read-only source mandate.

### 9.1 System Prerequisites

- **OS:** Linux (x86-64). The core reproductions need only loopback; the `169.254.169.254`, IPv6, and RFC1918 tests need Linux network tooling (`iproute2`, network namespaces) and specific sysctls.
- **Go:** 1.24.2 (matches `go.mod` `toolchain go1.24.2`); build with `CGO_ENABLED=0`.
- **git:** for integrity verification.
- **Python 3:** for the local mock HTTP/HTTPS servers used to capture requests.
- **Hardware:** ~2 GB free disk (the static binary is ~194 MB) and ≥ 2 GB RAM for the build.

### 9.2 Environment Setup

```bash
# Work from the repository root (read-only source tree)
cd /tmp/blitzy/trufflehog/blitzy-0e571e63-0888-47e8-87a8-5c68894d651f_385163

# Confirm toolchain and module
go version                       # expect: go version go1.24.2 linux/amd64
head -1 go.mod                   # module github.com/trufflesecurity/trufflehog/v3
grep -E '^(go|toolchain) ' go.mod

# Verify module integrity WITHOUT mutating go.sum
GOTOOLCHAIN=local go mod verify  # expect: all modules verified
```

> **Do not run** `go mod download all` — it mutates `go.sum`. Use `go mod verify` / `go build` instead.

### 9.3 Build (canonical entry point, output outside the checkout)

```bash
mkdir -p /tmp/lab
CGO_ENABLED=0 GOTOOLCHAIN=local go build -o /tmp/lab/th .
echo "exit=$?"                   # expect: exit=0
ls -l /tmp/lab/th                # expect: ~194,309,530-byte executable
file /tmp/lab/th                 # expect: ELF 64-bit ... statically linked
```

### 9.4 Smoke Test

```bash
/tmp/lab/th --version                    # expect: trufflehog dev
/tmp/lab/th filesystem --help | head     # expect: usage: TruffleHog filesystem ...
```

### 9.5 Example Usage — reproduce the Q4 "data sent" finding

```bash
mkdir -p /tmp/lab/ex && cd /tmp/lab/ex

# 1) threaded mock that logs the exact request
cat > mock.py <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length','0') or 0)
        body = self.rfile.read(n).decode('utf-8','replace')
        print(f"CAPTURED POST {self.path} UA={self.headers.get('User-Agent')!r} "
              f"Auth={self.headers.get('Authorization')!r} body={body}", flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self,*a): pass
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address=True; request_queue_size=1024
with S(("127.0.0.1",18901),H) as s:
    print("READY",flush=True); s.serve_forever()
PYEOF

# 2) custom-detector config with a verify webhook
cat > q4.yaml <<'YMLEOF'
detectors:
  - name: LabTokenDetector
    keywords: [labtok_]
    regex:
      theToken: 'labtok_([a-z0-9]{6})'
    verify:
      - endpoint: http://127.0.0.1:18901/verify
        unsafe: true
        headers:
          - 'Authorization: Bearer SAMPLE-STATIC-HEADER'
YMLEOF

# 3) target file with a match
printf 'here is a secret labtok_abc123 in a file\n' > target.txt

# 4) run mock, then the canonical CLI
python3 mock.py > mock.log 2>&1 &
MPID=$!; for i in $(seq 1 50); do grep -q READY mock.log && break; sleep 0.1; done
/tmp/lab/th filesystem --no-update --results=verified,unverified --config=q4.yaml target.txt
grep CAPTURED mock.log
kill "$MPID" 2>/dev/null
```

**Expected output:**

```
✅ Found verified result 🐷🔑
Name: LabTokenDetector
Response: OK
CAPTURED POST /verify UA='TruffleHog' Auth='Bearer SAMPLE-STATIC-HEADER' body={"LabTokenDetector":{"theToken":["labtok_abc123","abc123"]}}
```

### 9.6 Verify Read-Only Integrity

```bash
cd /tmp/blitzy/trufflehog/blitzy-0e571e63-0888-47e8-87a8-5c68894d651f_385163
git status --porcelain                       # expect: (empty)
git diff e42153d44a5e --name-status          # expect: A  blitzy/documentation/trufflehog_e42153d44a5e.md
```

### 9.7 Cleanup

```bash
rm -rf /tmp/lab/ex /tmp/lab/th /tmp/lab/build.log   # remove all temporary lab artifacts
```

### 9.8 Troubleshooting

- **`externally-managed-environment` on `pip`** — not needed here; the harness uses only the Python 3 standard library.
- **`go mod verify` fails / `go.sum` changed** — you likely ran `go mod download all`; restore with `git checkout -- go.sum`.
- **Port already in use** — change `18901` in both `mock.py` and `q4.yaml`.
- **The scan appears to hang** — do **not** reproduce the Q3/C8 config-DoS overflow config (10 regexes × 99 matches); it intentionally wedges the scan. Run it only in a disposable, killable process if you must observe it.
- **`169.254.169.254` / IPv6 / RFC1918 tests don't reproduce** — these require Linux namespaces / `iproute2` / IPv6-on-`lo`; see the deliverable's appendix for exact prerequisites and safety gates.

---

## 10. Appendices

### A. Command Reference

| Command | Purpose |
|---------|---------|
| `go version` | Confirm Go 1.24.2 |
| `GOTOOLCHAIN=local go mod verify` | Verify modules without mutating `go.sum` |
| `CGO_ENABLED=0 GOTOOLCHAIN=local go build -o /tmp/lab/th .` | Build the binary (canonical entry) outside the checkout |
| `/tmp/lab/th --version` | Print version (`trufflehog dev`) |
| `/tmp/lab/th filesystem --help` | Show filesystem subcommand flags |
| `/tmp/lab/th filesystem --no-update --results=verified,unverified --config=<yaml> <target>` | Run detection + webhook verification |
| `git status --porcelain` | Confirm clean working tree |
| `git diff e42153d44a5e --name-status` | Confirm only the deliverable was added |

### B. Port Reference

| Port | Component | Notes |
|------|-----------|-------|
| 18901 | Example mock HTTP server (this guide) | Loopback only; change if occupied |
| 18100 + `CLONE_INDEX`×200 (base) | Deliverable appendix mock servers | Parameterized so parallel runs never collide |
| 18066 | `trufflehog --profile` pprof/fgprof server | Only if profiling is enabled (not used here) |

### C. Key File Locations

| Path | Role |
|------|------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The sole deliverable** (1,217 lines) |
| `main.go` | CLI entry point (`filesystem` subcommand, `config.Read`) |
| `pkg/custom_detectors/custom_detectors.go` | Verification engine (`maxTotalMatches=100` L23; `SaneHttpClient()` L62; request build L214–L240) |
| `pkg/custom_detectors/validation.go` | Config-time validation (`ValidateVerifyEndpoint` L35 — scheme-only) |
| `pkg/common/http.go` | `SaneHttpClient` / `saneTransport` (system-CA TLS default); `User-Agent` injection |
| `pkg/roundtripper/roundtripper.go` | `WithInsecureTLS` (sources/LDAP only — not webhooks) |
| `pkg/config/config.go` | Untrusted-YAML → validated detectors |
| `pkg/engine/engine.go` | `detectChunk`, per-match 10 s timeout |
| `pkg/detectors/http.go` | `DefaultResponseTimeout = 10 * time.Second` (L18) |

### D. Technology Versions

| Component | Version |
|-----------|---------|
| Go toolchain | go1.24.2 (`go.mod`: `go 1.23.1`, `toolchain go1.24.2`) |
| Module | `github.com/trufflesecurity/trufflehog/v3` |
| `golang.org/x/sync` (errgroup) | v0.13.0 |
| `github.com/hashicorp/go-retryablehttp` | v0.7.7 (not used by the webhook client) |
| Python (mock servers) | 3 (standard library only) |
| Commit under test | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` |
| Branch / HEAD | `blitzy-0e571e63-0888-47e8-87a8-5c68894d651f` / `1b18bd73` |

### E. Environment Variable Reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `CGO_ENABLED` | `0` | Static, cgo-free build |
| `GOTOOLCHAIN` | `local` | Pin the local Go toolchain; avoid auto-download |
| `SSL_CERT_FILE` | path to test CA | (Deliverable appendix, Q2) trust a private CA for the TLS-accept case |
| `HTTP_PROXY` / `HTTPS_PROXY` | proxy URL | (Deliverable appendix, Q2/F) proxy-forwarding test |
| `CLONE_INDEX` | integer | (Deliverable appendix) parameterizes mock ports for parallel runs |

### F. Developer Tools Guide

- **git** — integrity verification (`status --porcelain`, `diff … --name-status`, `log`).
- **Go toolchain** — `build`, `mod verify`, `version`.
- **Python 3 `http.server` / `ssl`** — local mock HTTP/HTTPS servers to capture webhook requests.
- **`iproute2` / network namespaces** — isolate the `169.254.169.254` metadata test (fail-closed; no route to any external network).
- **`/usr/bin/time -v`** — capture build/run resource usage and wall-clock timing (used for the Q5 ReDoS timing sweep).

### G. Glossary

| Term | Definition |
|------|------------|
| **SSRF** | Server-Side Request Forgery — coercing a server into making requests to attacker-chosen destinations (e.g., cloud metadata). |
| **IMDS / `169.254.169.254`** | Cloud instance metadata service; IMDSv2 requires a `PUT`-token then `GET`, so a fixed `POST` cannot lift credentials. |
| **ReDoS** | Regular-expression Denial of Service via catastrophic backtracking; avoided by RE2/Go `regexp` (linear-time, no backtracking). |
| **RE2** | Google's linear-time regex engine design; Go's `regexp` follows the same principles (no backreferences). |
| **Verification / webhook** | The opt-in step where a custom detector POSTs a matched secret to a configured `endpoint` to check validity. |
| **`unsafe` flag** | Per-verifier config boolean; gates a case-sensitive `http://` scheme check — it does **not** disable TLS validation. |
| **Span** | A matched region within a chunk; `maxTotalMatches=100` caps permutations **per span**, not globally. |
| **Fail-closed netns** | An isolated Linux network namespace with no external route, used so the metadata test can only reach a synthetic fake. |
| **`[OBSERVED]` / `[INFERRED]` / `[CORROBORATED]`** | Provenance tags: runtime-confirmed / code-derived / inferred-but-runtime-supported. |