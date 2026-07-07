# Blitzy Project Guide — TruffleHog ReDoS / Computational-Complexity DoS Investigation

> **Scope note:** This is a **read-only security investigation**. The Agent Action Plan (AAP) authorizes exactly **one** persistent deliverable — the answer document `blitzy/documentation/trufflehog_e42153d44a5e.md` — and **prohibits any modification to TruffleHog source**. Completion is measured against that AAP scope plus the standard path-to-production activities for a security-finding deliverable.
>
> **Brand color legend:** <span style="color:#5B39F3">■</span> **Completed / AI Work = Dark Blue `#5B39F3`** · <span style="color:#FFFFFF">□</span> **Remaining / Not Completed = White `#FFFFFF`** · Headings/Accents = Violet-Black `#B23AF2` · Highlight = Mint `#A8FDD9`.

---

## 1. Executive Summary

### 1.1 Project Overview

This project answers a security question for teams evaluating TruffleHog in CI: **can an attacker who commits a specially crafted file weaponize TruffleHog's regex-based secret detection into a catastrophic-backtracking (ReDoS) denial-of-service that hangs the pipeline?** Following a strict *run-first, evidence-grounded* methodology, the Blitzy agent built the canonical scanner, drove TruffleHog's own detector patterns through the real `trufflehog filesystem` entry point with paired attack/benign inputs, and captured timing plus pprof/fgprof CPU profiles. The deliverable is a single 686-line analysis proving the vulnerability is **impossible by construction** (linear-time RE2 engine) and quantifying the residual bounded slowdown. Target users are security and platform engineers; the business impact is a defensible go/no-go input for CI tooling selection.

### 1.2 Completion Status

The AAP-scoped completion is **88.6%**, computed from engineering hours: **62 completed hours** of autonomous investigation + authoring against **8 remaining hours** of human path-to-production (review, peer verification, and operational follow-up).

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieSectionTextColor':'#111111','pieStrokeWidth':'2px','pieTitleTextSize':'16px'}}}%%
pie showData
    title AAP-Scoped Completion — 88.6%
    "Completed Work (AI) — Dark Blue" : 62
    "Remaining Work — White" : 8
```

| Metric | Hours |
|--------|-------|
| **Total Project Hours** | **70** |
| Completed Hours (AI + Manual) | 62 |
| — of which AI (autonomous) | 62 |
| — of which Manual (human) | 0 |
| **Remaining Hours** | **8** |
| **Percent Complete** | **88.6%** |

*Formula:* `62 / (62 + 8) = 62 / 70 = 88.6%`.

### 1.3 Key Accomplishments

- ✅ **Direct verdict delivered with runtime proof:** a crafted file **cannot** trigger a catastrophic-backtracking ReDoS — it is impossible by construction because the detector path uses the linear-time RE2 engine, not a backtracking engine.
- ✅ **Regex-engine identity quantified:** 867 detector `.go` files compile with `go-re2` (RE2), 3 use Go's ReDoS-safe stdlib `regexp`, and the backtracking `regexp2` engine appears **0** times on the detector path — all counts independently reproduced.
- ✅ **Equivalent-size impact measured:** an 8 MiB "evil-regex-shaped" attack file is **not slower** than a benign file of identical size (attack:benign ≈ **0.97×**), across 3 stable runs.
- ✅ **CPU-profiling evidence captured:** pprof shows ~85–88% of CPU in the RE2/WASM automaton (`runtime._ExternalCode`), never in exponential backtracking; fgprof corroborates.
- ✅ **KEY nuance verified at runtime:** the per-detector `--detector-timeout` is **soft/non-preemptive** — with `--detector-timeout=1ns` the scan still finds every secret, with 0 watchdog logs and 0 deadline errors.
- ✅ **Edge cases covered:** `--scan-entire-chunk`, base64 decoder amplification, many-match extraction, and 2/4/8/16 MiB linear-scaling all confirmed bounded/linear.
- ✅ **Repository left pristine:** exactly one file added, zero TruffleHog source changes, all temporary artifacts deleted — the read-only constraint fully honored.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|-------|--------|-------|-----|
| Finding awaiting human security-team review & sign-off | Cannot be relied on for the CI go/no-go decision until reviewed | Security Lead | 3h |
| Measurements captured on a single host (NumCPU=128 / 4-CPU cgroup) | Absolute timings host-dependent; qualitative verdict is not | Platform Eng | 3h |

> There are **no** code-level blockers: the codebase builds, runs, and passes all investigation-relevant tests. The items above are standard path-to-production gates for a security deliverable, not defects.

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|-----------------|----------------|-------------------|-------------------|-------|
| `github.com/joeleonjr/leakyAPK` test fixture | Public HTTP fetch during `pkg/handlers` test | Third-party fixture `aws_leak.apk` now returns HTTP 404, failing `TestAPKHandler/apk_with_3_leaked_keys` | Out of scope — external, pre-existing, not a regression; adjacent archive vector only | Upstream / N/A |
| TruffleHog repository (read-only) | Git read/build | None — full read/build/run access confirmed | Resolved | N/A |
| Profiling server port `:18066` | Localhost HTTP | None on this host — pprof & fgprof served HTTP 200 | Resolved | N/A |

> No access issue blocks the in-scope deliverable. The single external fixture 404 affects only an out-of-scope, pre-existing test and is disclosed for completeness.

### 1.6 Recommended Next Steps

1. **[High]** Have the security team read the deliverable (§1–§8) and validate the methodology and verdict. *(2h)*
2. **[High]** Record a formal sign-off / go-no-go decision on adopting TruffleHog in the CI pipeline. *(1h)*
3. **[Medium]** Rebuild the canonical binary on representative CI-runner hardware and reproduce the attack-vs-benign and linear-scaling measurements. *(2h)*
4. **[Medium]** Reproduce the `--detector-timeout=1ns` soft-timeout experiment on CI hardware to confirm host-independence. *(1h)*
5. **[Low]** Evaluate/apply operational hardening (input-size limits & path filtering for throughput; treat `--detector-timeout` as advisory; use `--archive-max-*` for the archive vector). *(2h)*

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

Every completed component traces to a specific AAP requirement (the five investigated questions Q1–Q5, the investigation activities, or the sole deliverable). All items are **fully complete and validated**.

| Component | Hours | Description |
|-----------|-------|-------------|
| Environment setup & canonical binary build | 3 | Go 1.24.2 toolchain, `CGO_ENABLED=0 go build`, verify `filesystem` subcommand + all measurement flags (build exit=0; 194,309,626-byte binary) |
| Regex-engine identity analysis (Q2) | 5 | Established go-re2/RE2 linear-time engine from `go.mod`; produced the 867 / 3 / 0 detector inventory; confirmed `regexp2` indirect/unused |
| Candidate pattern enumeration & per-pattern analysis (Q3) | 6 | Surveyed 845 detectors; analyzed `mongodb.connStrPat`, `common.EmailPattern` (via `alegra`), and `anthropic`; read each `Keywords()` gate |
| Attack/benign/many-match input crafting (Q4) | 4 | Designed the equivalent-size paired-input experiment; crafted 8 MiB evil-shape (`mongodb://`+560×`a`+`!`), benign, and 1216-match files |
| Attack-vs-benign timing measurement (Q4) | 6 | Ran `trufflehog filesystem` with `--no-verification --concurrency=1 --print-avg-detector-time`; 3 runs each; computed ≈0.97× ratio |
| CPU profiling capture & analysis (Q5) | 6 | `--profile` server on `:18066`; captured pprof + fgprof at multiple scales; showed RE2 automaton dominance, no backtracking |
| Six-layer defense-in-depth analysis | 5 | Traced chunker → decoders → Aho-Corasick prefilter → ±512B span → RE2 → soft timeout; authored the mermaid stack diagram |
| Soft-timeout runtime verification (KEY finding) | 4 | Proved via `--detector-timeout=1ns` that the watchdog only logs and never preempts a CPU-bound regex |
| Edge-case coverage | 6 | `--scan-entire-chunk`, base64 amplification, many-match `FindAllStringSubmatch(-1)`, and 2/4/8/16 MiB linear scaling |
| Web research (RE2 guarantee) | 2 | Validated RE2 linear-time / ReDoS-immunity-by-design against authoritative sources |
| Answer-document authoring + QA refinement | 12 | Wrote the 686-line, 35-table, 34-code-block deliverable with embedded unedited output; 4 QA/accuracy refinement cycles |
| Coverage pass & adjacent-vector note | 2 | Mapped all question parts (a–e) + every named flag/mechanism/file/engine; documented the adjacent archive vector |
| Cleanup & repository-unchanged verification | 1 | Deleted all temporary artifacts; verified pristine `git status` and zero source changes |
| **Total Completed** | **62** | |

### 2.2 Remaining Work Detail

Each remaining category is standard path-to-production for a security-finding deliverable. No item is a code defect.

| Category | Hours | Priority |
|----------|-------|----------|
| Security-team review & sign-off of the finding (R1) | 3 | High |
| Independent peer verification of measurements on CI hardware (R2) | 3 | Medium |
| Operational CI hardening recommendations — decision & action (R3) | 2 | Low |
| **Total Remaining** | **8** | |

### 2.3 Hours Reconciliation

| Check | Value | Status |
|-------|-------|--------|
| Section 2.1 Completed total | 62 h | ✅ |
| Section 2.2 Remaining total | 8 h | ✅ |
| 2.1 + 2.2 = Total Project Hours | 62 + 8 = 70 h | ✅ matches §1.2 |
| Remaining hours (§1.2 = §2.2 = §7 pie) | 8 h | ✅ identical |
| Percent complete | 62 / 70 = 88.6% | ✅ |

---

## 3. Test Results

All results below originate from Blitzy's autonomous validation logs (Final Validator gates) and were independently re-run this session. This is a Go project with no bespoke test suite added (read-only scope); the tests are TruffleHog's existing suite plus build/vet/runtime validation gates. Package-level pass/fail is the reporting unit; per-test statement coverage was not the validation objective, so **Coverage %** is marked **N/A** where not measured.

| Test Category | Framework | Total | Passed | Failed | Coverage % | Notes |
|---------------|-----------|-------|--------|--------|-----------|-------|
| Dependency verification | `go mod verify` | 1 | 1 | 0 | N/A | "all modules verified"; no deps added/updated (read-only) |
| Build / Compile | `go build` (Go 1.24.2) | 2 | 2 | 0 | N/A | `CGO_ENABLED=0 go build -o binary .` **and** `go build ./...` both exit=0; binary 194,309,626 B |
| Static analysis | `go vet` | referenced pkgs | pass | 0 | N/A | Clean on all investigation-referenced packages |
| Unit — detector patterns | `go test` | 3 pkgs | 3 | 0 | N/A | `mongodb`, `alegra`, `anthropic` — all `ok` |
| Unit — engine / pipeline | `go test` | 5 pkgs | 5 | 0 | N/A | `common`, `decoders`, `engine/ahocorasick`, `engine/defaults`, `sources/filesystem` — all `ok` |
| Broad community suite | `go test ./...` | 891 pkgs | 890 | 1 \* | N/A | 58 packages have no tests; the single failure is out-of-scope (see \*) |
| Runtime validation | trufflehog CLI | 4 checks | 4 | 0 | N/A | scan `rc=0`; version `dev`; all flags present; pprof + fgprof endpoints HTTP 200 |
| Deliverable claim reproduction | empirical re-run | all claims | all | 0 | N/A | Every `file:line` citation, count, timing, profile, and edge-case reproduces |

**\* The single broad-suite failure** is `pkg/handlers TestAPKHandler/apk_with_3_leaked_keys`. It fails because it performs a **live HTTP fetch** of a third-party GitHub fixture that now returns **HTTP 404** — an external-dependency failure, **not** a code defect. It is **out of AAP scope** (the adjacent archive/decompression-bomb vector), **byte-identical to the base commit** (pre-existing, **not a regression**), and the deliverable makes **no claim** that depends on it. It is disclosed here for full transparency.

> **Investigation-relevant test outcome: 100% pass.** Independently re-run this session with `-p 4` to avoid CPU-oversubscription flakiness: all 8 relevant packages returned `ok` (exit=0).

---

## 4. Runtime Validation & UI Verification

**UI verification: Not Applicable.** TruffleHog is a command-line scanner and the AAP deliverable is a Markdown document — there is no web/graphical UI in scope. Runtime validation therefore centers on CLI health, flag surface, and the profiling server.

**Runtime health:**

- ✅ **Operational** — Canonical build: `CGO_ENABLED=0 go build` completes with exit=0; artifact is a ~194 MB static binary (byte-identical size, 194,309,626 B, across independent rebuilds).
- ✅ **Operational** — Version reporting: `--version` emits `trufflehog dev` (a default/dev build, stated as such, not a release value).
- ✅ **Operational** — Canonical entry point: `trufflehog filesystem <path> --no-verification --concurrency=1 --print-avg-detector-time` returns `rc=0` and logs `finished scanning`.
- ✅ **Operational** — Measurement flags present: `--profile`, `--concurrency`, `--no-verification`, `--print-avg-detector-time`, `--detector-timeout`; the hidden `--scan-entire-chunk` flag is accepted.
- ✅ **Operational** — Profiling server: `--profile` serves pprof at `:18066/debug/pprof/` (HTTP 200) and fgprof at `:18066/debug/fgprof` (HTTP 200).
- ✅ **Operational** — Attack-vs-benign behavior: the evil-shape attack file yields **0 secrets** and is **not slower** than an equivalent-size benign file (no super-linear blow-up).
- ✅ **Operational** — Soft-timeout behavior (KEY): `--detector-timeout=1ns` still finds every secret (independently reproduced: 25,909 matches identical to default), with 0 watchdog logs and 0 deadline errors.

**API integration:** Not exercised — `--no-verification` deliberately isolates CPU-bound pattern matching from the network verification path (per AAP scope).

---

## 5. Compliance & Quality Review

Cross-mapping the AAP's binding rules (§0.7) and requirements to observed evidence. "Fixes applied during validation" = 0 (the deliverable was already accurate; per the *report-exactly-what-is-observed* rule, correct observed values were not overwritten).

| AAP Requirement / Rule | Benchmark | Status | Evidence / Notes |
|------------------------|-----------|--------|------------------|
| Single deliverable, fixed name & location | `blitzy/documentation/trufflehog_e42153d44a5e.md` exists | ✅ Pass | 686 lines; only added path since base |
| Investigate by RUNNING first | Build + run evidence embedded | ✅ Pass | Binary built; scans executed; output embedded |
| Sufficient scale, ≥2 stable runs | State scale; ≥2 runs | ✅ Pass | 8 MiB, 3 runs; 2/4/8/16 MiB scaling |
| Exercise exact canonical code path | Real `trufflehog filesystem` + own patterns | ✅ Pass | No hand-written stand-in regex used |
| Default, canonical build/config | `CGO_ENABLED=0`; dev build stated | ✅ Pass | Version `dev` disclosed as non-release |
| Exercise every condition / edge path | Primary + edge/error paths | ✅ Pass | `--scan-entire-chunk`, base64, many-match, 1ns timeout |
| Actual, complete, unedited output | Real output beside each claim | ✅ Pass | 34 console/code blocks with commands |
| Answer every part + coverage pass | Decompose + final pass | ✅ Pass | §10 maps parts a–e + every named item |
| Exact & grounded (`file:line`) | Cite specific locations | ✅ Pass | All citations pinned to commit `e42153d4`, verified |
| Report exactly what is observed | Lead with plain-reading answer | ✅ Pass | Negative result (≈0.97×) reported as-is |
| Scope is read-only | Zero source modification | ✅ Pass | `git status` pristine; zero `pkg/`/`main.go`/`go.mod` changes |
| Cleanup temporary artifacts | Repo unchanged afterward | ✅ Pass | All `/tmp` inputs, scripts, binary deleted |

**Overall compliance: 12 / 12 rules satisfied.** Quality gates (build, vet, investigation-relevant tests, runtime, deliverable reproduction) all pass. Outstanding items are human review only.

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|------|----------|----------|-------------|------------|--------|
| Measurement host-dependence (NumCPU=128 / 4-CPU cgroup) affects absolute timings | Technical | Low | Medium | Host/scale stated; qualitative conclusions host-independent; peer verification (R2) | Mitigated (documented) |
| Citation drift if TruffleHog source evolves past base commit | Technical | Low | Medium | All citations pinned to `e42153d4`; stable `git diff --name-status <base> HEAD` proof | Mitigated (documented) |
| Linear throughput cost on very large inputs / many legitimate matches | Technical | Low | Low | Framed as throughput (not vulnerability); input-size limits/path filtering (R3) | Open (advisory) |
| Soft `--detector-timeout` does not preempt a CPU-bound detector (KEY §7) | Security | Low | Low | Flagged to operators; harmless under RE2 linear-time; use `--archive-max-*` for archive vector | Mitigated (documented) |
| Verdict scoped to built-in detectors; custom backtracking detectors would differ | Security | Low | Low | Explicitly scoped; `regexp2` proven 0 uses on detector path | Open (scoped caveat) |
| Adjacent archive/decompression-bomb vector not deep-dived | Security | Low | Low | Noted in §9 with bounding flags `--archive-max-size/-max-depth/-timeout` | Out of scope (noted) |
| Finding relied upon before human review/sign-off | Operational | Medium | Medium | Security-team review & sign-off (R1) | Open (needs review) |
| CI lacks resource limits, so large inputs could degrade throughput | Operational | Low | Low | Adopt input-size/path/resource caps (R3) | Open (advisory) |
| Pre-existing external test failure (`TestAPKHandler`, 404 fixture) | Integration | Low | Medium | External, pre-existing, byte-identical to base; out of scope; not a regression | Out of scope (external) |
| Reproduction needs Go 1.24.2 toolchain + `:18066` profiling port | Integration | Low | Low | Exact copy-pasteable commands provided; profiling optional for the verdict | Mitigated (documented) |

**Overall risk posture: LOW.** No High-severity risks. The single **Medium** item is procedural (human review pending), not a code/quality defect.

---

## 7. Visual Project Status

**Project hours breakdown** (Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`):

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieSectionTextColor':'#111111','pieStrokeWidth':'2px','pieTitleTextSize':'16px'}}}%%
pie showData
    title Project Hours — 62 Completed / 8 Remaining
    "Completed Work" : 62
    "Remaining Work" : 8
```

**Remaining work by priority** (8h total):

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#B23AF2','pie2':'#5B39F3','pie3':'#A8FDD9','pieStrokeColor':'#333333','pieSectionTextColor':'#111111','pieStrokeWidth':'2px','pieTitleTextSize':'16px'}}}%%
pie showData
    title Remaining Hours by Priority
    "High" : 3
    "Medium" : 3
    "Low" : 2
```

**Remaining hours per category (Section 2.2):**

| Category | Hours | Priority |
|----------|-------|----------|
| Security-team review & sign-off | 3 | High |
| Peer verification on CI hardware | 3 | Medium |
| Operational hardening recommendations | 2 | Low |
| **Total** | **8** | — |

> **Integrity check:** the pie chart "Remaining Work" = **8**, identical to §1.2 Remaining Hours and the §2.2 Hours sum. "Completed Work" = **62**, identical to §2.1 total.

---

## 8. Summary & Recommendations

**Achievements.** The investigation delivers a definitive, evidence-backed answer to the user's question. The headline finding: **a crafted file cannot weaponize TruffleHog's regex detection into a catastrophic-backtracking ReDoS — it is impossible by construction**, because the detector path uses the linear-time RE2 engine (`go-re2`, 867 files) rather than a backtracking engine (`regexp2`, 0 uses on the path). The worst achievable impact is a **bounded, linear** slowdown; an 8 MiB evil-shape attack file measured **≈0.97×** the time of an equivalent-size benign file. CPU profiling puts ~85–88% of time in the RE2/WASM automaton, never in exponential backtracking. A subtle but important operational nuance was verified at runtime: the per-detector timeout is **soft/advisory** and does not preempt a CPU-bound regex — harmless here because RE2 guarantees linear-time completion.

**Remaining gaps & critical path to production.** The autonomous deliverable is complete and validated; the remaining **8 hours (11.4%)** are entirely human path-to-production: (1) security-team review and sign-off (critical path), (2) optional peer verification of the measurements on representative CI hardware, and (3) a decision on operational hardening recommendations.

**Success metrics.**

| Metric | Result |
|--------|--------|
| AAP-scoped completion | 88.6% (62 / 70 h) |
| AAP questions answered with runtime evidence | 5 / 5 |
| AAP compliance rules satisfied | 12 / 12 |
| Investigation-relevant tests passing | 100% |
| TruffleHog source files modified | 0 (read-only honored) |
| Repository state | Pristine (1 file added) |

**Production readiness assessment.** The in-scope deliverable is **production-ready**. The codebase builds and runs, all investigation-relevant tests pass, the repository is pristine, and every claim in the 686-line document reproduces on independent verification. At **88.6% complete**, the only work between here and "done" is human review and optional environment-specific verification — there are no code defects or unresolved technical blockers.

---

## 9. Development Guide

This guide reproduces the investigation end-to-end. Every command below was executed successfully during validation. Run from the repository root.

### 9.1 System Prerequisites

- **OS:** Linux (x86-64) — validated on Ubuntu; macOS works with the same commands.
- **Go toolchain:** `go1.24.2` (matches `go.mod` `toolchain go1.24.2`). No C compiler needed — `go-re2` runs RE2 as WebAssembly via `wazero`, so builds use `CGO_ENABLED=0`.
- **Git + Git LFS** installed.
- **Disk:** ~1 GB free (the static binary is ~194 MB, plus the Go build cache).
- **Optional:** Python 3 for the timing harness; `curl` for the profiling endpoints.

```bash
go version          # expect: go version go1.24.2 linux/amd64
git --version
```

### 9.2 Read-Only Provenance (prove nothing in source changes)

```bash
# The analyzed source baseline:
git rev-parse e42153d44a5e5c37c1bd0c70e074781e9edcb760
# Exactly one path changed since the baseline (the deliverable):
git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD
# Expected output:
#   A    blitzy/documentation/trufflehog_e42153d44a5e.md
```

### 9.3 Build the Canonical Binary

```bash
CGO_ENABLED=0 go build -o /tmp/trufflehog_bin . ; echo "exit=$?"   # expect exit=0
ls -la /tmp/trufflehog_bin                                          # ~194,309,626 bytes
/tmp/trufflehog_bin --version 2>&1                                  # trufflehog dev
```

### 9.4 Verify the Measurement Flags

```bash
/tmp/trufflehog_bin filesystem --help 2>&1 \
  | grep -E 'no-verification|print-avg-detector-time|profile|detector-timeout|concurrency'
# Shows: --[no-]profile, --concurrency=128, --[no-]no-verification,
#        --[no-]print-avg-detector-time, --detector-timeout
# (--scan-entire-chunk is hidden from --help but accepted.)
```

### 9.5 Reproduce the Attack-vs-Benign Comparison

```bash
mkdir -p /tmp/redos_lab
# Attack file: canonical evil-regex shape (mongodb keyword + long ambiguous run + failing tail)
python3 -c "open('/tmp/redos_lab/attack.bin','wb').write((b'mongodb://'+b'a'*560+b'!\n')*13744)"
# Benign file of equivalent size:
python3 -c "open('/tmp/redos_lab/benign.bin','wb').write(b'the quick brown fox. '*399000)"

/tmp/trufflehog_bin filesystem /tmp/redos_lab/attack.bin --no-verification --concurrency=1 2>&1 | grep 'finished scanning'
/tmp/trufflehog_bin filesystem /tmp/redos_lab/benign.bin --no-verification --concurrency=1 2>&1 | grep 'finished scanning'
# Expect: attack yields 0 secrets and is NOT slower than benign (no super-linear blow-up).
```

### 9.6 Reproduce the KEY Soft-Timeout Finding

```bash
# A file packed with legitimately-matching connection strings:
python3 -c "open('/tmp/redos_lab/manymatch.bin','wb').write(b''.join(b'mongodb://user%d:realpass99@host.example.com:27017/db?tls=true\n'%i for i in range(20000)))"

# Default timeout vs an absurd 1ns timeout — the secret count is identical:
/tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 2>&1 \
  | grep 'finished scanning' | grep -o '"unverified_secrets": [0-9]*'
/tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 --detector-timeout=1ns 2>/tmp/ns.err >/dev/null
grep 'finished scanning' /tmp/ns.err | grep -o '"unverified_secrets": [0-9]*'
grep -c 'ignored the context timeout' /tmp/ns.err   # expect 0 (watchdog only logs; never fired)
grep -c 'context deadline exceeded' /tmp/ns.err      # expect 0 (timeout is non-preemptive)
```

### 9.7 Capture CPU Profiles

```bash
# Start a scan with the profiling server, then pull profiles from :18066
/tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 --profile >/tmp/prof.log 2>&1 &
PROF_PID=$!
sleep 2
curl -s -o /dev/null -w "pprof HTTP %{http_code}\n" http://localhost:18066/debug/pprof/
curl -s -o /dev/null -w "fgprof HTTP %{http_code}\n" "http://localhost:18066/debug/fgprof?seconds=1"
# For an interactive CPU profile: go tool pprof http://localhost:18066/debug/pprof/profile
wait $PROF_PID
```

### 9.8 Run the Investigation-Relevant Tests

```bash
# IMPORTANT: pin -p 4 (or GOMAXPROCS=4) to avoid CPU-oversubscription flakiness in
# pkg/common's short-HTTP-timeout tests when runtime.NumCPU() is large under a small cgroup.
CGO_ENABLED=0 go test -p 4 \
  ./pkg/detectors/mongodb/... ./pkg/detectors/alegra/... ./pkg/detectors/anthropic/... \
  ./pkg/common/... ./pkg/decoders/... ./pkg/engine/ahocorasick/... ./pkg/sources/filesystem/...
# Expect: all packages "ok", exit=0.
```

### 9.9 Cleanup (restore pristine state)

```bash
rm -rf /tmp/redos_lab /tmp/trufflehog_bin /tmp/prof.log /tmp/ns.err
git status --porcelain          # expect empty (pristine)
git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD   # expect the single deliverable path
```

### 9.10 Troubleshooting

- **`pkg/common` tests flake intermittently** → run with `-p 4` or `GOMAXPROCS=4`. Cause: `runtime.NumCPU()` reports 128 while the cgroup grants ~4 CPUs, oversubscribing goroutines and tripping 10 ms HTTP timeouts. Not a code defect.
- **`pkg/handlers/TestAPKHandler/apk_with_3_leaked_keys` fails** → the test fetches an external GitHub fixture that returns HTTP 404. Out of scope (adjacent archive vector), pre-existing, and safe to ignore for this investigation.
- **fgprof endpoint returns a non-200 code** → the scan finished before the fgprof capture window (`?seconds=N`) elapsed. Use a larger input so the scan outlasts the window.
- **`error: externally-managed-environment` from pip** → only relevant to the optional Python harness; use a virtualenv or `pip install --break-system-packages`.
- **Binary size differs by a few bytes** → expected across Go patch releases; `194,309,626 B` is specific to this exact toolchain/host.

---

## 10. Appendices

### Appendix A — Command Reference

| Purpose | Command |
|---------|---------|
| Check Go toolchain | `go version` |
| Canonical build | `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` |
| Print version | `/tmp/trufflehog_bin --version 2>&1` |
| Canonical scan | `/tmp/trufflehog_bin filesystem <path> --no-verification --concurrency=1 --print-avg-detector-time` |
| Worst-case span | add `--scan-entire-chunk` (hidden flag) |
| Soft-timeout probe | add `--detector-timeout=1ns` |
| Profiling server | add `--profile` (serves `:18066`) |
| CPU profile | `go tool pprof http://localhost:18066/debug/pprof/profile` |
| Engine inventory | `grep -rl 'wasilibs/go-re2' pkg/detectors --include='*.go' \| wc -l` |
| Read-only proof | `git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD` |
| Relevant tests | `CGO_ENABLED=0 go test -p 4 ./pkg/detectors/mongodb/... ./pkg/engine/ahocorasick/... ...` |

### Appendix B — Port Reference

| Port | Service | Notes |
|------|---------|-------|
| `18066` | pprof + fgprof profiling server | Enabled only with `--profile`; endpoints `/debug/pprof/` and `/debug/fgprof` |

### Appendix C — Key File Locations

| Path | Role |
|------|------|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | **The sole deliverable** — the answer document |
| `go.mod` | Regex engine + toolchain declaration (`go-re2 v1.9.0` [L100]; toolchain `go1.24.2` [L5]) |
| `main.go` | CLI entry point + all measurement flags (`--profile` [L53], `filesystem` [L143]) |
| `pkg/engine/engine.go` | Detector execution, keyword gate [L795], soft timeout [L1066-L1077] |
| `pkg/engine/ahocorasick/ahocorasickcore.go` | Keyword prefilter + `defaultOffsetRadius=512` [L155] |
| `pkg/sources/chunker.go` | `ChunkSize = 10*1024` [L14] |
| `pkg/decoders/decoders.go` | Default decoder chain (≤4×) [L8-L16] |
| `pkg/detectors/mongodb/mongodb.go` | Primary candidate pattern `connStrPat` [L32] |
| `pkg/common/patterns.go` | `EmailPattern` [L10] |
| `pkg/detectors/http.go` | `DefaultResponseTimeout = 10s` [L18] |

### Appendix D — Technology Versions

| Component | Version |
|-----------|---------|
| Go language | `go 1.23.1` (directive) |
| Go toolchain | `go1.24.2` |
| Module | `github.com/trufflesecurity/trufflehog/v3` |
| Regex engine | `github.com/wasilibs/go-re2 v1.9.0` (RE2, linear-time) |
| WASM runtime | `github.com/tetratelabs/wazero v1.9.0` (indirect) |
| Keyword prefilter | `github.com/BobuSumisu/aho-corasick v1.0.3` |
| Profiler | `github.com/felixge/fgprof v0.9.5` + `net/http/pprof` |
| Backtracking engine (indirect/unused on detector path) | `github.com/dlclark/regexp2 v1.4.0` |
| Binary version | `trufflehog dev` (default/dev build) |

### Appendix E — Environment Variable Reference

| Variable | Value | Purpose |
|----------|-------|---------|
| `CGO_ENABLED` | `0` | Pure-Go build; no C compiler (go-re2 runs as WASM) |
| `GOMAXPROCS` / `go test -p` | `4` | Cap parallelism to avoid CPU-oversubscription test flakiness |
| `GOFLAGS` | (optional) | e.g. `-mod=mod` if the environment requires it |

### Appendix F — Developer Tools Guide

- **pprof** — CPU/heap/goroutine profiling. Confirms ~85–88% of scan CPU is in `runtime._ExternalCode` (RE2/WASM automaton), proving no exponential backtracking.
- **fgprof** — full (on- + off-CPU) profiling. Shows `runtime.gopark` dominance (the scanner waits, it is not CPU-pegged), corroborating the linear-time verdict.
- **`--print-avg-detector-time`** — per-detector average time; result-gated (prints only when a detector returns ≥1 result), e.g. `MongoDB: 29.437232ms`.
- **`go tool pprof`** — interactive analysis of profiles pulled from `:18066`.

### Appendix G — Glossary

| Term | Definition |
|------|------------|
| **ReDoS** | Regular-expression Denial-of-Service — exhausting CPU via catastrophic backtracking in a vulnerable regex engine |
| **Catastrophic backtracking** | Exponential-time regex behavior on adversarial input; requires a backtracking engine |
| **RE2** | Google's finite-automaton regex engine with a linear-time guarantee and no backtracking; designed for untrusted patterns |
| **go-re2** | The Go WASM binding to RE2 used by TruffleHog's detectors |
| **Aho-Corasick prefilter** | Keyword Trie that runs a detector's regex only when one of its keywords appears in the chunk |
| **Span limiting** | Restricting regex input to ±512 bytes around a keyword hit (`defaultOffsetRadius`) |
| **Soft timeout** | An advisory per-detector deadline that logs but does **not** preempt a running CPU-bound regex |
| **Evil-regex shape** | The canonical ReDoS probe input: a keyword + long ambiguous run + failing tail (e.g. `mongodb://` + `a`×560 + `!`) |
| **Many-match input** | A file packed with legitimately-matching secrets, whose cost is linear in match count |

---

*This Blitzy Project Guide reports on a read-only security investigation. AAP-scoped completion: **88.6%** (62 of 70 hours). Remaining 8 hours are human path-to-production (review, verification, operational follow-up). No TruffleHog source was modified; the sole deliverable is `blitzy/documentation/trufflehog_e42153d44a5e.md`.*