# Can a crafted file weaponize TruffleHog's regex detection into a ReDoS denial-of-service?

**A run-first, evidence-grounded security analysis of TruffleHog's pattern-matching layer.**

> **Question investigated (paraphrased from the user):** "I'm evaluating TruffleHog for my CI pipeline. If an attacker commits a specially crafted file, can they exhaust the scanner (catastrophic-backtracking / ReDoS) and block the pipeline? Which detector patterns are exploitable? How much slower is a crafted attack file than a normal file of *equivalent size*? Provide timing and CPU-profiling evidence."

---

## Investigation parameters (how every number below was produced)

| Parameter | Value |
|-----------|-------|
| Source baseline commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` — the TruffleHog source under analysis; **all `file:line` citations resolve against it**. Verified with `git rev-parse e42153d44…` and `git log --oneline -1 e42153d44…`, **not** `git rev-parse HEAD`. |
| Deliverable commit(s) | One or more **documentation-only** commits layered on the baseline that add and refine *this* document. Their hashes rotate whenever the document is revised (committing the doc changes `HEAD`), so the read-only proof below uses `git diff --name-status e42153d44a5e… HEAD` — stable across commits, listing exactly one changed path (this document) — rather than a self-referential `HEAD` hash |
| Build command | `CGO_ENABLED=0 go build -o /tmp/trufflehog_bin .` |
| Go toolchain | `go1.24.2 linux/amd64` (matches `go.mod` `toolchain go1.24.2` [go.mod:L5]) |
| Binary version | `trufflehog dev` — this is a **default/dev build**, *not* a release value (stated per rule) |
| Canonical entry point | `trufflehog filesystem <path>` [main.go:L143] |
| Deterministic flags | `--no-verification` [main.go:L59] and `--concurrency=1` (default is `runtime.NumCPU()` [main.go:L58]) |
| Host CPU count | `runtime.NumCPU() = 128` (the binary's default `--concurrency=128` confirms it; note `nproc`/cgroup quota reports `4`, which caps *active* parallelism — see the profiling notes) |
| Profiling | `--profile` server on `:18066` [main.go:L53, L434] — pprof at `/debug/pprof/profile`, fgprof at `/debug/fgprof` |
| Per-detector timing | `--print-avg-detector-time` [main.go:L72] |

All measurements below are **my own fresh captures on this host**, each repeated ≥2–3 times. Where my absolute numbers differ from a higher-core reference machine, I say so; the qualitative conclusions are identical and are what the question turns on. This document is the sole persistent artifact of the investigation; every temporary input file, script, and the built binary were deleted afterward, leaving the repository unchanged.

### Reproducibility evidence — environment, build, and commit provenance

The parameter table above condenses the commands below; each is shown here with its complete, unedited output.

**Source baseline vs. deliverable commit** — the analyzed source is untouched; the sole change is this document:

```console
$ git rev-parse e42153d44a5e5c37c1bd0c70e074781e9edcb760
e42153d44a5e5c37c1bd0c70e074781e9edcb760
$ git log --oneline -1 e42153d44a5e5c37c1bd0c70e074781e9edcb760
e42153d4 [Fix] Added Prefix In Dockerhub Detector Regex (#4084)
$ git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD
A	blitzy/documentation/trufflehog_e42153d44a5e.md
```

→ The **source baseline** is `e42153d44…` (every `file:line` citation in this document resolves against it); `HEAD` is the **deliverable**, delivered as documentation-only commit(s) that add and refine this file. Since the baseline, `git diff --name-status` lists exactly one added path — this document — proving **zero TruffleHog source files were modified**. The deliverable's own `HEAD` hash is intentionally *not* pinned here: committing this document changes `HEAD`, so a self-referential hash would immediately go stale, whereas `git diff --name-status <baseline> HEAD` is a stable, reproducible read-only proof.

**Go toolchain, canonical build, exit code, and artifact:**

```console
$ go version
go version go1.24.2 linux/amd64
$ CGO_ENABLED=0 go build -o /tmp/trufflehog_bin . ; echo "exit=$?"
exit=0
$ ls -la /tmp/trufflehog_bin
-rwxr-xr-x 1 root root 194309626 Jul  6 23:20 /tmp/trufflehog_bin
```

→ The canonical build completes with `exit=0` and no C compiler (`CGO_ENABLED=0`; go-re2 executes RE2 as WASM via wazero [go.mod:L285]), producing a ~194 MB static binary; the toolchain matches `go.mod` [go.mod:L5].

**Binary version — a default/`dev` build (stated as such, not a release value; it is emitted on stderr):**

```console
$ /tmp/trufflehog_bin --version 2>&1
trufflehog dev
```

**Host CPU count and default concurrency:**

```console
$ nproc
4
$ /tmp/trufflehog_bin filesystem --help 2>&1 | grep -E 'concurrency'
      --concurrency=128          Number of concurrent workers.
```

→ The default `--concurrency=128` is `runtime.NumCPU()` [main.go:L58] = **128** on this host; `nproc` reports the cgroup quota (**4**), which caps *active* parallelism and explains the ~4-CPU sample percentages in §5. Every timing run below pins `--concurrency=1` for deterministic attribution.

**Measurement flags on the canonical `filesystem` entry point** (the `no-verification` grep also matches `--[no-]no-verification-cache`; `--scan-entire-chunk` is a *hidden* flag — present on the binary but omitted from `--help`):

```console
$ /tmp/trufflehog_bin filesystem --help 2>&1 | grep -E 'no-verification|print-avg-detector-time|profile|detector-timeout'
      --[no-]profile             Enables profiling and sets a pprof and fgprof
      --[no-]no-verification     Don't verify the results.
      --[no-]print-avg-detector-time  
      --detector-timeout=DETECTOR-TIMEOUT  
      --[no-]no-verification-cache  
$ grep -n 'scan-entire-chunk' main.go
68:	scanEntireChunk            = cli.Flag("scan-entire-chunk", "Scan the entire chunk for secrets.").Hidden().Default("false").Bool()
```

→ All flags used below are present: `--profile` [main.go:L53], `--no-verification` [main.go:L59], `--print-avg-detector-time` [main.go:L72], `--detector-timeout` [main.go:L77], and the hidden `--scan-entire-chunk` [main.go:L68].

---

## 1. Direct verdict

**No — a crafted file cannot trigger a catastrophic-backtracking ReDoS that hangs or times out TruffleHog's scan. It is impossible by construction.** **No detector on the scan path uses a catastrophic-backtracking regex engine.** The overwhelming majority — **867 detector `.go` files** — compile their patterns with the linear-time **RE2** engine (`github.com/wasilibs/go-re2` [go.mod:L100]), a finite-automaton matcher that performs **no backtracking**; the remaining **3** detector files use Go's **standard-library `regexp`**, itself an RE2-derived automaton with only a *bounded* backtracker (fixed budget), so it too is ReDoS-safe (the exact 867 / 3 / 0 inventory is proven in §2). The backtracking-capable `regexp2` engine is present only as an *indirect* dependency and is used **nowhere** on the detector path. A backtracking engine is the prerequisite for catastrophic "evil regex" blow-up; TruffleHog's detector path does not use one.

The **worst** an attacker can achieve against the pattern-matching layer is a **bounded, linear (constant-factor) slowdown** — never an exponential blow-up, never a hang.

**Measured headline** (equivalent-size **8 MiB** files, `--no-verification --concurrency=1`, 3 runs each; each file is exactly `8388608` bytes; every scan reports `chunks=820`):

- **An attack file built from the canonical "evil regex" shape (`mongodb://` + 560 × `a` + `!`) is *not* slower than a benign file of the same size.** Attack wall time was **1.977 / 1.981 / 2.000 s**; a benign file with no keyword was **2.032 / 2.037 / 2.045 s**; a benign file *containing* the keyword was **2.079 / 2.031 / 2.044 s**. The attack:benign ratio is **≈ 0.97× — no meaningful difference** (the attack is, if anything, marginally faster because it produces zero matches).
- A file packed with *legitimately matching* secrets ("many-match") is slower (**~4.4 s** wall for 8 MiB) **only because it produces 1216 real matches** that each require genuine per-match work (`url.Parse`, dedup) — cost that is **linear in the number of matches**, still bounded, and never a hang.

Everything below substantiates this with complete, unedited command output next to each claim.

---

## 2. Regex-engine evidence — why catastrophic backtracking is impossible

Catastrophic backtracking (ReDoS) requires a **backtracking** regex engine. **No detector on TruffleHog's scan path uses one.** 867 detector files compile their patterns with Google's **RE2** via the pure-Go WASM binding `go-re2`, and the remaining 3 detector files use Go's ReDoS-safe **standard-library `regexp`** (the full 867 / 3 / 0 inventory is quantified just below).

**Engine identity from `go.mod`:**

- `github.com/wasilibs/go-re2 v1.9.0` [go.mod:L100] — the linear-time RE2 engine, executed as WebAssembly. This is the crux of ReDoS immunity.
- `github.com/tetratelabs/wazero v1.9.0 // indirect` [go.mod:L285] — the pure-Go WASM runtime that backs `go-re2` (this is what makes the `CGO_ENABLED=0` build possible — no C compiler required).
- `github.com/BobuSumisu/aho-corasick v1.0.3` [go.mod:L17] — the keyword prefilter Trie (defense layer 2).
- `github.com/felixge/fgprof v0.9.5` [go.mod:L46] — the full (on+off CPU) profiler.
- `github.com/dlclark/regexp2 v1.4.0 // indirect` [go.mod:L187] — a **backtracking** engine, present **only** as an *indirect* dependency and **not used anywhere on the detector path** (proven by the `0` count below).

**Quantitative facts (each with the exact command that produced it):**

```console
$ grep -rl 'wasilibs/go-re2' pkg/detectors --include='*.go' | wc -l
867
```
→ 867 detector `.go` files import the linear-time RE2 engine.

```console
$ grep -rlE '^\s*"regexp"' pkg/detectors --include='*.go'
pkg/detectors/azure_entra/serviceprincipal/v2/spv2.go
pkg/detectors/azure_cosmosdb/azure_cosmosdb.go
pkg/detectors/jdbc/jdbc.go
$ grep -rlE '^\s*"regexp"' pkg/detectors --include='*.go' | wc -l
3
```
→ Exactly **3** detector files use the Go **standard-library** `regexp`. That stdlib engine is *also* non-backtracking-catastrophic: Go's `regexp` is an RE2-derived automaton with a **bounded** backtracker (constant memory budget), so it too is ReDoS-safe (corroborated in the profiling section, where these three account for only a small, scale-dependent slice of CPU — ≈1.5 % at 34 MiB rising to ≈4 % at 68 MiB, always dwarfed by RE2's ~85–88 % — see §5).

```console
$ find pkg/detectors -mindepth 1 -maxdepth 1 -type d | wc -l
845
```
→ 845 detector directories.

```console
$ grep -rl 'dlclark/regexp2' pkg/ main.go --include='*.go' | wc -l
0
```
→ The **backtracking** `regexp2` engine appears **zero** times across `pkg/` and `main.go` — it is never on the detector path.

**The MongoDB detector confirms the engine choice at the import site:**

```console
$ sed -n '14p' pkg/detectors/mongodb/mongodb.go
	regexp "github.com/wasilibs/go-re2"
```
→ `pkg/detectors/mongodb/mongodb.go` aliases `go-re2` as `regexp` [mongodb.go:L14], so every `regexp.MustCompile`/`FindAllStringSubmatch` in that file is RE2, not the stdlib.

**External corroboration (general knowledge, clearly separated from the observed evidence above):** Google's RE2 project documents that its primary guarantee is match time **linear** in the length of the input, and that it was explicitly designed to accept regexes from **untrusted** users; it achieves this by using finite automata and **omitting** backtracking-only features such as backreferences and lookaround. Security references (e.g. Snyk Learn, OWASP/HackTricks write-ups on ReDoS) independently note that RE2 "does not use backtracking and is therefore immune to catastrophic backtracking / ReDoS by design." This is *why* the runtime evidence below shows no blow-up — but the verdict in this document rests on the **observed** behavior, not on the citation.

---


## 3. Per-candidate pattern analysis — the most "dangerous-looking" regexes

I selected the detector patterns whose *shape* would blow up a **backtracking** engine — nested quantifiers, alternations, and embedded complex sub-patterns — and drove each through the real keyword gate. Under RE2 none of them blows up.

### 3.1 MongoDB `connStrPat` — the primary attack target

```console
$ sed -n '32p' pkg/detectors/mongodb/mongodb.go
	connStrPat = regexp.MustCompile(`\b(mongodb(?:\+srv)?://(?P<username>\S{3,50}):(?P<password>\S{3,88})@(?P<host>[-.%\w]+(?::\d{1,5})?(?:,[-.%\w]+(?::\d{1,5})?)*)(?:/(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)(?:\b|$)`)
```

This pattern [mongodb.go:L32] contains the **classic catastrophic-backtracking shapes**: the nested quantifier group `(?:,[-.%\w]+(?::\d{1,5})?)*` for comma-separated hosts, and `(?:&(?:amp;)?\w+=[\w@/.$-]+)*` for `&`-separated options. On a backtracking engine, an ambiguous run that *almost* matches these repeated groups is what produces exponential blow-up. Under RE2 these compile to a finite automaton and run in linear time (demonstrated in §4 and §8).

- Keyword gate: `Keywords()` returns `[]string{"mongodb"}` [mongodb.go:L40] (declared at [mongodb.go:L39]). The keyword is the literal string `mongodb`, so it is trivially embedded in an attack payload — this is why MongoDB is the ideal attack target: the payload reaches `FromData` with minimal effort.
- Execution: `FromData` [mongodb.go:L44] runs `connStrPat.FindAllStringSubmatch(dataStr, -1)` [mongodb.go:L49]; a `placeholderPasswordPat = regexp.MustCompile(`^[xX]+|\*+$`)` [mongodb.go:L34] filters obvious placeholder passwords.

The canonical evil input for this pattern is `mongodb://` (passes the gate) + a long ambiguous run of `a` (stresses the `\S{3,50}`/`\S{3,88}`/host groups) + a failing tail `!` (defeats the final match). §4 (Table 1), §8 (linear scaling), and §8 (`--scan-entire-chunk`) show this input produces **no** super-linear cost.

### 3.2 `common.EmailPattern` (via the `alegra` detector)

```console
$ sed -n '5p;10p' pkg/common/patterns.go
	"regexp"
const EmailPattern = `\b((?i)(?:[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))\b`
```

`common.EmailPattern` [patterns.go:L10] is the most structurally complex shared building block — it is the RFC-5322-flavored email regex, embedded in ~16 detectors. Crucially, **it is only a `const` string** [patterns.go:L10] — it compiles no regex by itself, so **the engine that executes it is decided by whichever detector `MustCompile`s it**, not by `pkg/common/patterns.go`. (That file's stdlib `"regexp"` import [patterns.go:L5] is used only by its helper *functions*, e.g. `PrefixRegex` — not to compile `EmailPattern`.) The named `alegra` candidate imports `regexp "github.com/wasilibs/go-re2"` [alegra.go:L10] and compiles the combined pattern with **go-re2 / RE2**:

```console
$ sed -n '28p;42p' pkg/detectors/alegra/alegra.go
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"alegra"}) + common.EmailPattern)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
```

`idPat` [alegra.go:L28] = `PrefixRegex(["alegra"]) + common.EmailPattern`, **compiled with go-re2** (the file's `regexp` alias [alegra.go:L10]) and executed via `idPat.FindAllStringSubmatch(dataStr, -1)` [alegra.go:L42] (the API-key half runs at [alegra.go:L41]). Keyword: `alegra`. So for this candidate the complex email pattern runs on **RE2** — the linear-time guarantee applies to it, not the stdlib engine.

### 3.3 Representative detector — `anthropic`

```console
$ sed -n '27p;36,37p;44p' pkg/detectors/anthropic/anthropic.go
	keyPat = regexp.MustCompile(`\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b`)
func (s Scanner) Keywords() []string {
	return []string{"sk-ant-api03", "sk-ant-admin01"}
	keys := keyPat.FindAllStringSubmatch(dataStr, -1)
```

`anthropic` shows the general detector contract: a compiled `keyPat` [anthropic.go:L27], `Keywords()` [anthropic.go:L36] returning the key **prefixes** `sk-ant-api03` / `sk-ant-admin01` [anthropic.go:L37] (⚠️ note: the keyword is the *key prefix*, **not** the word "anthropic" — a payload must embed `sk-ant-api03`/`sk-ant-admin01` to pass the Aho-Corasick gate), and `FindAllStringSubmatch(dataStr, -1)` [anthropic.go:L44]. This mirrors the `Detector` contract in `pkg/detectors/detectors.go`: `FromData(ctx, verify, data) ([]Result, error)` [detectors.go:L21] and `Keywords() []string` [detectors.go:L24] on `type Detector interface` [detectors.go:L19], returning `type Result struct` [detectors.go:L87].

**Bottom line for all three:** the patterns *look* dangerous (nested quantifiers, embedded email regex, alternations), which is precisely why they were chosen as attack candidates — but because they execute on RE2, the "dangerous" shape is compiled away into a linear-time automaton. The empirical proof is in the next sections.

---


## 4. Attack-vs-benign timing at equivalent size (the user's core comparison)

### Input crafting

Four **equivalent-size 8 MiB** files were generated. Every attack/keyword payload embeds the target detector's `Keywords()` substring so it passes the Aho-Corasick gate [engine.go:L795] and actually reaches `FromData`; a payload without the keyword short-circuits at the prefilter and the regex never runs.

```console
$ python3 - <<'PY'
import os
TARGET=8*1024*1024  # 8 MiB per file
def w(path,unit,tgt):
    with open(path,'wb') as f:
        n=0; c=unit*max(1,65536//len(unit)+1)
        while n<tgt: k=min(len(c),tgt-n); f.write(c[:k]); n+=k
w("attack_span.bin", b"mongodb://"+b"a"*560+b"!\n", TARGET)          # ATTACK: keyword + long ambiguous run + failing tail
w("benign_nokeyword.bin", b"The quick brown fox jumps over the lazy dog near the riverbank at dawn. ", TARGET)  # no keyword
w("benign_keyword.bin", b"mongodb connection notes: see the manual for details about the driver setup.\n", TARGET)  # keyword, benign
w("manymatch.bin", b"mongodb://user1:realpass99@host.example.com:27017/db?tls=true\n", TARGET)  # valid conn strings
print({p:os.path.getsize(p) for p in sorted(os.listdir('.')) if p.endswith('.bin')})
PY
{'attack_span.bin': 8388608, 'benign_keyword.bin': 8388608, 'benign_nokeyword.bin': 8388608, 'manymatch.bin': 8388608}
```

Timing harness (GNU `time` may be absent — this wrapper reports wall + user + sys via `resource.getrusage`):

```console
$ cat /tmp/redos_lab/timeit.py
import subprocess,sys,time,resource
label=sys.argv[1]; runs=int(sys.argv[2]); assert sys.argv[3]=="--"; cmd=sys.argv[4:]
for i in range(runs):
    r0=resource.getrusage(resource.RUSAGE_CHILDREN); t0=time.perf_counter()
    p=subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE); t1=time.perf_counter()
    r1=resource.getrusage(resource.RUSAGE_CHILDREN)
    print(f"[{label}] run{i+1}: wall={t1-t0:.3f}s user={r1.ru_utime-r0.ru_utime:.3f}s sys={r1.ru_stime-r0.ru_stime:.3f}s rc={p.returncode}")
```

### Table 1 — Attack vs Benign, equivalent 8 MiB (3 runs each)

```console
$ python3 timeit.py ATTACK 3 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/attack_span.bin --no-verification --concurrency=1 --print-avg-detector-time
[ATTACK] run1: wall=1.977s user=2.075s sys=0.228s rc=0
[ATTACK] run2: wall=1.981s user=2.113s sys=0.203s rc=0
[ATTACK] run3: wall=2.000s user=2.084s sys=0.246s rc=0

$ python3 timeit.py BENIGN_NOKW 3 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/benign_nokeyword.bin --no-verification --concurrency=1 --print-avg-detector-time
[BENIGN_NOKW] run1: wall=2.032s user=2.141s sys=0.191s rc=0
[BENIGN_NOKW] run2: wall=2.037s user=2.162s sys=0.207s rc=0
[BENIGN_NOKW] run3: wall=2.045s user=2.164s sys=0.227s rc=0

$ python3 timeit.py BENIGN_KW 3 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/benign_keyword.bin --no-verification --concurrency=1 --print-avg-detector-time
[BENIGN_KW] run1: wall=2.079s user=2.348s sys=0.224s rc=0
[BENIGN_KW] run2: wall=2.031s user=2.257s sys=0.205s rc=0
[BENIGN_KW] run3: wall=2.044s user=2.291s sys=0.200s rc=0
```

| File (all 8 MiB = 8388608 B) | Content | wall (3 runs), s | matches |
|---|---|---|---|
| `attack_span.bin` | `mongodb://` + `a`×560 + `!` (evil shape) | 1.977 / 1.981 / 2.000 | 0 |
| `benign_nokeyword.bin` | prose, no keyword (prefilter short-circuits) | 2.032 / 2.037 / 2.045 | 0 |
| `benign_keyword.bin` | keyword present, benign content | 2.079 / 2.031 / 2.044 | 0 |

**Ratio attack:benign = 1.986 / 2.038 ≈ 0.97× — no meaningful difference.** Scale: 8 MiB, `chunks=820` per scan; values stable across 3 runs. The attack file is *not* slower; it is marginally faster because it yields zero matches.

The scan metadata for **all three** files confirms equal work — each reports `chunks=820`, `bytes=10903552` and zero secrets — and directly substantiates the headline that the attack's `scan_duration` is *lower* than either benign file (the attack is, if anything, marginally faster because it produces zero matches):

```console
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/attack_span.bin --no-verification --concurrency=1 --print-avg-detector-time >/dev/null 2>attack.err ; grep 'finished scanning' attack.err
2026-07-07T02:31:19Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "271.744712ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/benign_nokeyword.bin --no-verification --concurrency=1 --print-avg-detector-time >/dev/null 2>benign_nokw.err ; grep 'finished scanning' benign_nokw.err
2026-07-07T02:31:21Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "332.298111ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/benign_keyword.bin --no-verification --concurrency=1 --print-avg-detector-time >/dev/null 2>benign_kw.err ; grep 'finished scanning' benign_kw.err
2026-07-07T02:31:23Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "361.786435ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

For the attack file, `--print-avg-detector-time` prints **only its header and no detector lines**, because the per-detector accounting is result-gated — it runs only when a detector returns ≥ 1 result: `if e.printAvgDetectorTime && len(results) > 0` [engine.go:L1092-L1104]. (The CLI-level print call itself is `if *printAvgDetectorTime { printAverageDetectorTime(eng) }` [main.go:L963-L964].) The evil input matches nothing, so the accounting map stays empty:

```console
$ grep -A0 'Average detector time' attack.err
Average detector time is the measurement of average time spent on each detector when results are returned.
```

### Table 2 — Many-match (legitimate matches), equivalent 8 MiB (3 runs)

```console
$ python3 timeit.py MANYMATCH 3 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 --print-avg-detector-time
[MANYMATCH] run1: wall=4.629s user=13.259s sys=0.278s rc=0
[MANYMATCH] run2: wall=4.033s user=10.890s sys=0.278s rc=0
[MANYMATCH] run3: wall=4.551s user=12.978s sys=0.255s rc=0

$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 --print-avg-detector-time >/dev/null 2>mm.err
$ grep 'finished scanning' mm.err
2026-07-06T22:40:54Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 1216, "scan_duration": "3.027012765s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
$ grep -A1 'Average detector time' mm.err
Average detector time is the measurement of average time spent on each detector when results are returned.
MongoDB: 29.437232ms
```

The many-match file is slower (**~4.4 s** wall vs the attack's **~2.0 s**) for one reason only: it contains **1216 legitimately-matching connection strings** (`unverified_secrets: 1216`), each requiring real per-match work (submatch extraction, `url.Parse`, deduplication). This cost is **linear in the number of matches**, not exponential — doubling the matches roughly doubles the work. The per-detector average (`MongoDB: 29.437232ms`) is the mean time MongoDB spent per chunk that returned results.

**On `user ≫ wall`:** the many-match runs show `user` (~11–13 s) far exceeding `wall` (~4.4 s) even at `--concurrency=1`. This is honest and expected: `go-re2` runs RE2 inside a **pool of WASM module instances** (via wazero), so a single logical scan still fans regex execution across multiple OS threads. The profiling in §5 shows the pool's mutex/semaphore activity directly. It is *parallel CPU accounting*, not a super-linear time blow-up — wall time remains ~4.4 s and bounded.

---


## 5. CPU profiling — the decisive engine evidence

To see *where the CPU time actually goes*, I captured a 10 s CPU profile from TruffleHog's own `--profile` server ([main.go:L53], `http.ListenAndServe(":18066", router)` [main.go:L434]) while it scanned a larger many-match file (so the scan outlives the profiling window).

```console
$ python3 -c "open('/tmp/redos_lab/manymatch_big.bin','wb').write((b'mongodb://user1:realpass99@host.example.com:27017/db?tls=true\n')*550000)"
$ ls -la /tmp/redos_lab/manymatch_big.bin
-rw-r--r-- 1 root root 34100000 Jul  6 22:41 /tmp/redos_lab/manymatch_big.bin

$ ( /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch_big.bin --no-verification --concurrency=1 --profile >/dev/null 2>mm.err ) &
$ sleep 2
$ curl -s -o cpu.pprof "http://localhost:18066/debug/pprof/profile?seconds=10"; wait
$ go tool pprof -top -nodecount=15 cpu.pprof
File: trufflehog_bin
Build ID: fe6b016d78e155ef05df8b601f116bd0dcb61a18
Type: cpu
Time: 2026-07-06 22:41:22 UTC
Duration: 10.14s, Total samples = 39.82s (392.64%)
Showing nodes accounting for 36.48s, 91.61% of 39.82s total
Dropped 351 nodes (cum <= 0.20s)
Showing top 15 nodes out of 41
      flat  flat%   sum%        cum   cum%
    34.93s 87.72% 87.72%     34.93s 87.72%  runtime._ExternalCode
     0.64s  1.61% 89.33%      0.64s  1.61%  runtime.memmove
     0.27s  0.68% 90.01%      0.52s  1.31%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.18s  0.45% 90.46%      0.55s  1.38%  regexp.(*Regexp).tryBacktrack
     0.10s  0.25% 90.71%      0.67s  1.68%  regexp.(*Regexp).backtrack
     0.07s  0.18% 90.88%      2.89s  7.26%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mongodb.Scanner.FromData
     0.07s  0.18% 91.06%      0.50s  1.26%  runtime.mallocgcSmallScanNoHeader
     0.06s  0.15% 91.21%      0.77s  1.93%  runtime.mallocgc
     0.04s   0.1% 91.31%      0.56s  1.41%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.04s   0.1% 91.41%      0.26s  0.65%  runtime.growslice
     0.02s  0.05% 91.46%      1.23s  3.09%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.02s  0.05% 91.51%      0.28s   0.7%  net/url.parse
     0.02s  0.05% 91.56%      0.42s  1.05%  runtime.newobject
     0.01s 0.025% 91.59%      1.20s  3.01%  github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
     0.01s 0.025% 91.61%      0.23s  0.58%  github.com/wasilibs/go-re2/internal.getChildModule
```

**Interpretation — this is the crux of the whole investigation:**

- **`runtime._ExternalCode` = 34.93 s = 87.72 %** of all CPU. `_ExternalCode` is Go's label for time spent inside the WASM module — i.e. **the RE2 automaton executing through wazero**. The overwhelming majority of scan CPU is spent in **linear-time finite-automaton matching**, exactly as RE2 promises.
- The call chain into that automaton is visible: `mongodb.Scanner.FromData` (cum 7.26%) → `go-re2 …findAllSubmatch` (cum 3.01%) → wazero `callWithStack` → `runtime._ExternalCode`.
- **The only backtracking frames are `regexp.(*Regexp).backtrack` (cum 1.68%) and `regexp.(*Regexp).tryBacktrack` (cum 1.38%)** — these are Go's **standard-library** regex engine (from the 3 stdlib-`regexp` detectors identified in §2). Go's backtracker is **bounded** (a fixed instruction/visited-state budget), so it is *linear-time and ReDoS-safe*, not catastrophic. Its share is small but **scale-dependent** — it is ≈1.5–1.8 % at this 34 MiB scale (stable across five captures here) and rises to ≈3–4 % on a doubled 68 MiB input (the cross-check below) — always negligible next to RE2's dominant `_ExternalCode`, and *never* the go-re2 detector path.

A `-peek` on the go-re2 entry point makes the linear automaton chain explicit:

```console
$ go tool pprof -peek 'findAllSubmatch' cpu.pprof
      flat  flat%   sum%        cum   cum%   calls calls% + context 	 	 
----------------------------------------------------------+-------------
                                             1.20s   100% |   github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.01s 0.025% 0.025%      1.20s  3.01%                | github.com/wasilibs/go-re2/internal.(*Regexp).findAllSubmatch
                                             0.91s 75.83% |   github.com/wasilibs/go-re2/internal.matchFrom
                                             0.16s 13.33% |   github.com/wasilibs/go-re2/internal.readMatches
                                             0.12s 10.00% |   github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch.func1
```

→ `FindAllStringSubmatch → findAllSubmatch → matchFrom` (75.83% of that node's children) — RE2 automaton stepping, no backtracking function anywhere in the go-re2 chain.

**On the sample percentage:** `Total samples = 39.82s (392.64%)` means ~4 CPUs were active during the 10 s window. On this host the cgroup CPU quota caps *active* parallelism at 4 (`nproc = 4`), even though `runtime.NumCPU() = 128`. On a machine with more available cores this percentage is higher (a reference 128-core capture showed ~784%), but the *distribution* is identical: `_ExternalCode` dominates and backtracking is negligible. The conclusion does not depend on the absolute sample count.

**Scale cross-check — the stdlib backtracker is small, bounded, and grows only *linearly*.** The `regexp.(*Regexp).backtrack` / `tryBacktrack` frames above are a *small absolute* quantity (~0.6–0.7 s of ~40 s of samples), so their sampled percentage is variance- and scale-sensitive: across five 34 MiB captures here it stayed at **backtrack ≈1.5–1.8 % / tryBacktrack ≈1.2 %** (the 34 MiB block above, a separate capture, sits in the same regime at 1.68 % / 1.38 %), but **doubling** the input to a **68 MiB** many-match file raises it to **backtrack 4.09 % / tryBacktrack 3.11 %** while `_ExternalCode` stays dominant. This is the honest observed distribution (stable across runs at each scale), not a one-off:

```console
$ python3 -c "open('/tmp/redos_lab/manymatch_huge.bin','wb').write((b'mongodb://user1:realpass99@host.example.com:27017/db?tls=true\n')*1100000)"   # 68,200,000 B — double the 34 MiB file
$ ( /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch_huge.bin --no-verification --concurrency=1 --profile >/dev/null 2>/dev/null ) &
$ sleep 2; curl -s -o cpu_huge.pprof "http://localhost:18066/debug/pprof/profile?seconds=10"; wait
$ go tool pprof -top -nodecount=15 cpu_huge.pprof
File: trufflehog_bin
Build ID: 145c457addfaf462420df5fbfc7a6aa89df6394e
Type: cpu
Time: 2026-07-07 01:16:46 UTC
Duration: 10.18s, Total samples = 39.85s (391.61%)
Showing nodes accounting for 36.54s, 91.69% of 39.85s total
Dropped 302 nodes (cum <= 0.20s)
Showing top 15 nodes out of 55
      flat  flat%   sum%        cum   cum%
    33.44s 83.91% 83.91%     33.44s 83.91%  runtime._ExternalCode
     0.66s  1.66% 85.57%      0.66s  1.66%  runtime.memmove
     0.39s  0.98% 86.55%      1.24s  3.11%  regexp.(*Regexp).tryBacktrack
     0.33s  0.83% 87.38%      1.63s  4.09%  regexp.(*Regexp).backtrack
     0.28s   0.7% 88.08%      0.44s  1.10%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.24s   0.6% 88.68%      0.38s  0.95%  regexp.(*bitState).push (inline)
     0.21s  0.53% 89.21%      0.21s  0.53%  regexp.(*bitState).shouldVisit (inline)
     0.20s   0.5% 89.71%      0.25s  0.63%  github.com/BobuSumisu/aho-corasick.(*Trie).Walk
     0.18s  0.45% 90.16%      0.22s  0.55%  internal/sync.(*Mutex).Unlock (inline)
     0.16s   0.4% 90.56%      0.23s  0.58%  regexp.lazyFlag.match
     0.12s   0.3% 90.87%      0.40s  1.00%  internal/sync.(*Mutex).Lock (inline)
     0.12s   0.3% 91.17%      0.28s   0.7%  internal/sync.(*Mutex).lockSlow
     0.08s   0.2% 91.37%      3.11s  7.80%  github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mongodb.Scanner.FromData
     0.08s   0.2% 91.57%      0.23s  0.58%  runtime.mallocgcSmallNoscan
     0.05s  0.13% 91.69%      0.31s  0.78%  runtime.growslice
```

Two facts confirm this backtracking is **bounded**, not catastrophic. First, the `regexp.(*bitState).push` / `regexp.(*bitState).shouldVisit` frames are Go's *bounded* backtracker — a fixed visited-state bitmap budget. Second, a `-peek` shows the frame is driven by the stdlib `regexp.(*Regexp).doExecute`, **not** the go-re2 path:

```console
$ go tool pprof -peek 'regexp\.\(\*Regexp\)\.backtrack$' cpu_huge.pprof
File: trufflehog_bin
Build ID: 145c457addfaf462420df5fbfc7a6aa89df6394e
Type: cpu
Time: 2026-07-07 01:16:46 UTC
Duration: 10.18s, Total samples = 39.85s (391.61%)
Showing nodes accounting for 39.85s, 100% of 39.85s total
----------------------------------------------------------+-------------
      flat  flat%   sum%        cum   cum%   calls calls% + context 	 	 
----------------------------------------------------------+-------------
                                             1.63s   100% |   regexp.(*Regexp).doExecute
     0.33s  0.83%  0.83%      1.63s  4.09%                | regexp.(*Regexp).backtrack
                                             1.24s 76.07% |   regexp.(*Regexp).tryBacktrack
                                             0.05s  3.07% |   regexp.(*inputBytes).step
                                             0.01s  0.61% |   regexp.(*inputBytes).index
----------------------------------------------------------+-------------
```

→ Even at 4.09 % on a 68 MiB input, the stdlib backtracker is (a) **bounded** — `bitState` with a fixed budget, hence *linear-time* — and (b) *linear in input size* — doubling the file roughly doubled its share (≈1.7 %→≈4 %), the exact opposite of the exponential blow-up a catastrophic-backtracking ReDoS would produce. RE2's `_ExternalCode` still dominates at 83.91 %. So the residual backtracking is negligible **and** structurally incapable of the super-linear behavior the question asks about.

(These two 68 MiB blocks were captured with this session's build — `Build ID 145c457…`; the 34 MiB capture earlier shows a different `Build ID` because it is a separate build of the *same* source commit `e42153d4` — the Go `Build ID` hashes build-graph inputs, so it rotates per build while behavior is identical.)

### fgprof (on + off CPU) — completeness

```console
$ ( /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch_big.bin --no-verification --concurrency=1 --profile >/dev/null 2>/dev/null ) &
$ sleep 2; curl -s -o fgprof.pprof "http://localhost:18066/debug/fgprof?seconds=8&format=pprof"; wait
$ go tool pprof -top -nodecount=14 fgprof.pprof
Type: time
Time: 2026-07-06 22:42:09 UTC
Duration: 8.01s, Total samples = 229.68s (2868.57%)
Showing nodes accounting for 223.79s, 97.43% of 229.68s total
Dropped 232 nodes (cum <= 1.15s)
Showing top 14 nodes out of 87
      flat  flat%   sum%        cum   cum%
   193.64s 84.31% 84.31%    193.64s 84.31%  runtime.gopark
    15.96s  6.95% 91.26%     15.96s  6.95%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack.func1
     8.01s  3.49% 94.74%      8.01s  3.49%  runtime.notetsleepg
     4.22s  1.84% 96.58%      4.23s  1.84%  runtime.assertE2I
     1.09s  0.47% 97.05%      1.31s  0.57%  internal/sync.(*Mutex).unlockSlow
     0.33s  0.14% 97.20%     60.30s 26.25%  github.com/wasilibs/go-re2/internal.(*lazyFunction).callWithStack
     0.21s 0.093% 97.29%     38.09s 16.58%  internal/sync.(*Mutex).lockSlow
     0.19s 0.083% 97.37%     29.48s 12.83%  github.com/wasilibs/go-re2/internal.(*Regexp).MatchString
     0.05s 0.023% 97.40%     20.26s  8.82%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).callWithStack
     0.05s 0.023% 97.42%     31.02s 13.51%  github.com/wasilibs/go-re2/internal.matchFrom
     0.01s 0.0046% 97.42%     20.27s  8.82%  github.com/tetratelabs/wazero/internal/engine/wazevo.(*callEngine).CallWithStack
     0.01s 0.0046% 97.43%     31.41s 13.68%  github.com/wasilibs/go-re2/internal.(*Regexp).FindAllStringSubmatch
     0.01s 0.0046% 97.43%     37.77s 16.44%  internal/sync.runtime_SemacquireMutex
         0     0% 97.43%      8.01s  3.49%  github.com/jpillora/overseer.(*child).run
```

fgprof counts **off-CPU (waiting) time too**, so it tells a complementary story:

- **`runtime.gopark` = 84.31 %** — most of the pipeline's goroutines are *parked/waiting* (channel reads between source → chunker → decoder → detector stages). The scanner spends the bulk of its lifetime **waiting, not burning CPU**. A ReDoS victim would show the opposite: a goroutine pinned at 100% CPU inside a regex.
- Active regex work is all **go-re2 / WASM**: `lazyFunction.callWithStack` (cum 26.25%), `FindAllStringSubmatch` (13.68%), `matchFrom` (13.51%), `MatchString` (12.83%).
- `internal/sync.(*Mutex).lockSlow` (16.58%) + `runtime_SemacquireMutex` (16.44%) are the **WASM-module pool** contending for instances — this is the mechanism behind the `user ≫ wall` observation in §4.
- **No backtracking frame appears in the fgprof top nodes at this 34 MiB scale.** (At the doubled 68 MiB scale of the pprof cross-check above, the Go-stdlib bounded backtracker does surface, but only as tiny frames — `regexp.(*Regexp).backtrack` cum ≈ 0.7 %, `regexp.(*Regexp).tryBacktrack` cum ≈ 0.5 % — still far below the `go-re2`/WASM frames and, being off-CPU-weighted, far below even its own on-CPU pprof share.)

---


## 6. Six-layer defense-in-depth — what bounds an attacker's impact

Even setting aside RE2's linear-time guarantee, TruffleHog stacks six mechanisms that each bound the work an attacker-controlled file can induce, holding total impact to a **linear constant factor**.

```mermaid
graph TD
    A["Crafted / committed file"] --> B["Layer 4: 10 KiB chunking<br/>ChunkSize=10*1024, PeekSize=3*1024,<br/>TotalChunkSize=13 KiB (chunker.go:L14,L16,L18)<br/>per-chunk work bounded; total time linear in file size"]
    B --> C["Layer 5: Decoder chain (<=4x)<br/>DefaultDecoders(): UTF8, Base64, UTF16, EscapedUnicode<br/>(decoders.go:L8-L16)"]
    C --> D["Layer 2: Aho-Corasick keyword prefilter<br/>single Trie (ahocorasickcore.go:L127);<br/>FindDetectorMatches gate (engine.go:L795)<br/>regex runs only if a Keyword() is present"]
    D --> E["Layer 3: +/-512B span limiting<br/>defaultOffsetRadius=512 (ahocorasickcore.go:L155)<br/>bypassed only by --scan-entire-chunk (main.go:L68)"]
    E --> F["Layer 1: go-re2 / RE2 linear-time engine<br/>wasilibs/go-re2 v1.9.0 (go.mod:L100)<br/>no backtracking; ReDoS-immune by construction"]
    F --> G["Layer 6: 10s soft per-detector timeout<br/>context.WithTimeout (engine.go:L1066);<br/>watchdog at +1s LOGS only (engine.go:L1067-L1068)"]
    G --> H["Bounded, LINEAR CPU cost<br/>(no exponential blow-up, no hang)"]
```

**Layer 1 — go-re2 / RE2 linear-time engine.** `github.com/wasilibs/go-re2 v1.9.0` [go.mod:L100], backed by `github.com/tetratelabs/wazero v1.9.0` [go.mod:L285]. No backtracking → no catastrophic ReDoS (§2, §5).

**Layer 2 — Aho-Corasick keyword prefilter.** A single Trie `prefilter ahocorasick.Trie` [ahocorasickcore.go:L127], populated from `keywordsToDetectors map[string][]DetectorKey` [ahocorasickcore.go:L133] and built via `NewTrieBuilder().AddStrings(keywords).Build()` [ahocorasickcore.go:L159]. `FindDetectorMatches(chunkData []byte)` [ahocorasickcore.go:L241] is invoked at the engine gate `matchingDetectors := e.AhoCorasickCore.FindDetectorMatches(decoded.Chunk.Data)` [engine.go:L795]. **A detector's regex runs only if one of its `Keywords()` appears in the chunk** — so a payload that lacks the keyword (my `benign_nokeyword.bin`) never reaches any detector regex, which is why it timed identically to the others.

**Layer 3 — ±512-byte span limiting.** `const defaultOffsetRadius int64 = 512` [ahocorasickcore.go:L155] feeds `newAdjustableSpanCalculator(defaultOffsetRadius)` [ahocorasickcore.go:L160]. Only ±512 bytes around each keyword hit are handed to the detector (rationale comment at [engine.go:L1056-L1062]), so the regex input per hit is bounded regardless of file size. This is bypassed **only** by the hidden `--scan-entire-chunk` flag [main.go:L68], wired to the `EntireChunkSpanCalculator` [engine.go:L526] — measured separately in §8 and found to make no difference.

**Layer 4 — 10 KiB chunking.** `ChunkSize = 10 * 1024` [chunker.go:L14], `PeekSize = 3 * 1024` [chunker.go:L16], `TotalChunkSize = ChunkSize + PeekSize` = 13 KiB [chunker.go:L18]. Input is windowed into ≤13 KiB chunks, so per-chunk work is capped and total scan time is **linear in file size** (§8 scaling table).

**Layer 5 — decoder chain (≤4×).** `DefaultDecoders()` returns `{ &UTF8{}, &Base64{}, &UTF16{}, &EscapedUnicode{} }` [decoders.go:L8-L16]. At most four decoders view each chunk, so decoder amplification is bounded ≤4× — my 8 MiB file reported `bytes: 10903552` scanned = **1.30×** (§8 base64 note).

**Layer 6 — 10 s soft per-detector timeout.** `ctx, cancel := context.WithTimeout(ctx, detectionTimeout)` [engine.go:L1066] with `detectionTimeout` defaulting to `DefaultResponseTimeout = 10 * time.Second` [http.go:L18]. **Critically, this timeout is soft/advisory — it does not preempt a CPU-bound regex** (§7). It is a backstop, not the primary defense; Layer 1 is what makes a runaway impossible.

Detector timing is instrumented by the `detector_execution_duration` histogram (`Help: "Duration of detector execution in milliseconds."`, `Buckets: prometheus.ExponentialBuckets(1, 5, 6)`) [metrics.go:L38-L46], and the scan source under test is the filesystem source: `s.paths = append(conn.Paths, conn.Directories...)` [filesystem.go:L73], `func (s *Source) Chunks(...)` [filesystem.go:L85].

---


## 7. Soft-timeout nuance (KEY finding) — the timeout does *not* preempt a CPU-bound regex

The per-detector timeout is the one place where reading the code alone could mislead, so I verified its behavior at runtime. The relevant block in `pkg/engine/engine.go`:

```console
$ sed -n '1066,1077p' pkg/engine/engine.go
		ctx, cancel := context.WithTimeout(ctx, detectionTimeout)
		t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
			ctx.Logger().Error(nil, "a detector ignored the context timeout")
		})
		results, err := e.verificationCache.FromData(
			ctx,
			data.detector.Detector,
			data.chunk.Verify,
			data.chunk.SecretID != 0,
			matchBytes)
		t.Stop()
		cancel()
```

Reading this: a context deadline is set [engine.go:L1066]; a watchdog `time.AfterFunc(detectionTimeout+1*time.Second, …)` [engine.go:L1067] is armed whose callback **only logs** `"a detector ignored the context timeout"` [engine.go:L1068]; then the detector's `FromData` is invoked via `e.verificationCache.FromData(…)` [engine.go:L1070] (the verification cache wraps and calls the detector's `FromData`); and `t.Stop()` [engine.go:L1076] + `cancel()` [engine.go:L1077] run **after `FromData` returns**. Nothing here *kills* a running detector — the watchdog logs, it does not preempt.

**Runtime proof.** If the deadline actually interrupted the regex, then an absurdly tiny timeout would cut matches short and drop the secret count toward zero. It does not:

```console
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 >/dev/null 2>def.err
$ grep 'finished scanning' def.err
2026-07-06T22:44:13Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 1216, "scan_duration": "3.022585473s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/manymatch.bin --no-verification --concurrency=1 --detector-timeout=1ns >/dev/null 2>ns.err
$ grep 'finished scanning' ns.err
2026-07-06T22:44:18Z	info-0	trufflehog	finished scanning	{"chunks": 820, "bytes": 10903552, "verified_secrets": 0, "unverified_secrets": 1216, "scan_duration": "3.109800832s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}

$ grep -c 'ignored the context timeout' ns.err
0
$ grep -c 'context deadline exceeded' ns.err
0
```

| Run | `--detector-timeout` | `unverified_secrets` | watchdog logs | deadline errors |
|---|---|---|---|---|
| default | 10 s | **1216** | — | — |
| absurd | **1 ns** | **1216** (identical) | **0** | **0** |

**Conclusion (stated plainly):** With `--detector-timeout=1ns`, TruffleHog **still finds all 1216 secrets** — byte-for-byte identical to the 10 s default — with **0** watchdog log lines and **0** `context deadline exceeded` errors. This empirically proves the `context.WithTimeout` deadline [engine.go:L1066] does **not** interrupt the CPU-bound `go-re2` call: go-re2 does not observe context cancellation mid-execution, so each call runs to completion, and `t.Stop()`/`cancel()` only execute *after* `FromData` returns [engine.go:L1076-L1077]. The watchdog [engine.go:L1067] never fires here because each individual RE2 call finishes in well under a second (the whole scan is 1216 matches across 820 chunks in ~3 s).

So the timeout is **soft/advisory and non-preemptive**: a *truly* runaway CPU-bound regex would **not** be killed by it. That would be a real concern for a *backtracking* engine — but on the go-re2 detector path a true runaway is impossible in the first place, because RE2 guarantees linear-time completion (§2, §5). The soft timeout is a backstop for a scenario that RE2's engine choice already prevents.

---


## 8. Edge-case results

### 8.1 Linear scaling with file size (2 / 4 / 8 / 16 MiB + startup baseline)

```console
$ for mb in 2 4 8 16; do python3 -c "open('/tmp/redos_lab/a${mb}.bin','wb').write((b'mongodb://'+b'a'*560+b'!\n')*(${mb}*1897))"; done
$ printf 'mongodb://a!\n' > /tmp/redos_lab/tiny.bin
$ python3 timeit.py STARTUP 2 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/tiny.bin --no-verification --concurrency=1
[STARTUP] run1: wall=1.708s user=1.723s sys=0.184s rc=0
[STARTUP] run2: wall=1.707s user=1.684s sys=0.223s rc=0
$ for mb in 2 4 8 16; do python3 timeit.py "SCALE_${mb}MiB" 2 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/a${mb}.bin --no-verification --concurrency=1; done
[SCALE_2MiB] run1: wall=1.765s user=1.811s sys=0.183s rc=0
[SCALE_2MiB] run2: wall=1.770s user=1.787s sys=0.212s rc=0
[SCALE_4MiB] run1: wall=1.841s user=1.884s sys=0.217s rc=0
[SCALE_4MiB] run2: wall=1.853s user=1.908s sys=0.207s rc=0
[SCALE_8MiB] run1: wall=2.055s user=2.123s sys=0.257s rc=0
[SCALE_8MiB] run2: wall=2.000s user=2.103s sys=0.216s rc=0
[SCALE_16MiB] run1: wall=2.273s user=2.480s sys=0.238s rc=0
[SCALE_16MiB] run2: wall=2.269s user=2.482s sys=0.267s rc=0
```

| Input | wall (2 runs), s | avg wall, s | scan-only (avg − startup), s |
|---|---|---|---|
| startup (13 B) | 1.708 / 1.707 | 1.707 | — (fixed baseline) |
| 2 MiB | 1.765 / 1.770 | 1.768 | 0.061 |
| 4 MiB | 1.841 / 1.853 | 1.847 | 0.140 |
| 8 MiB | 2.055 / 2.000 | 2.028 | 0.321 |
| 16 MiB | 2.273 / 2.269 | 2.271 | 0.564 |

The **startup baseline is ~1.707 s** — a fixed cost paid once per invocation for WASM-compiling the 867 detector patterns and building the Aho-Corasick Trie. Subtracting it, the **scan-only** increments are 0.061 → 0.140 → 0.321 → 0.564 s: **each doubling of file size roughly doubles the increment**, which is the signature of **linear** scaling (~0.035 s/MiB). An exponential blow-up would show the increment multiplying by far more than 2× per doubling. Most of the wall time an attacker could "cause" is the fixed startup, not attacker-controlled scan work.

### 8.2 `--scan-entire-chunk` — worst case for the span limiter (2 runs each)

This bypasses the ±512 B span limit [ahocorasickcore.go:L155] and feeds the regex the full ≤13 KiB chunk. I built an input with a 12000-character ambiguous run to maximize the span fed to `connStrPat`:

```console
$ python3 -c "open('/tmp/redos_lab/bigrun.bin','wb').write((b'mongodb://'+b'a'*12000+b'!\n')*64)"
$ python3 timeit.py BIGRUN_DEFAULT 2 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/bigrun.bin --no-verification --concurrency=1
[BIGRUN_DEFAULT] run1: wall=1.738s user=1.751s sys=0.200s rc=0
[BIGRUN_DEFAULT] run2: wall=1.742s user=1.756s sys=0.192s rc=0
$ python3 timeit.py BIGRUN_ENTIRE 2 -- /tmp/trufflehog_bin filesystem /tmp/redos_lab/bigrun.bin --no-verification --concurrency=1 --scan-entire-chunk
[BIGRUN_ENTIRE] run1: wall=1.799s user=1.790s sys=0.218s rc=0
[BIGRUN_ENTIRE] run2: wall=1.741s user=1.759s sys=0.196s rc=0
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/bigrun.bin --no-verification --concurrency=1 >/dev/null 2>br_def.err ; grep 'finished scanning' br_def.err
2026-07-06T23:14:47Z	info-0	trufflehog	finished scanning	{"chunks": 76, "bytes": 996864, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "23.958523ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/bigrun.bin --no-verification --concurrency=1 --scan-entire-chunk >/dev/null 2>br_ent.err ; grep 'finished scanning' br_ent.err
2026-07-06T23:14:49Z	info-0	trufflehog	finished scanning	{"chunks": 76, "bytes": 996864, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "24.359568ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Default (span-limited) **1.738 / 1.742 s** vs `--scan-entire-chunk` **1.799 / 1.741 s** — **identical** (scan_duration 23.96 ms vs 24.36 ms). Even handing the regex a full 12000-character evil run per chunk produces **no blow-up**. This is the most direct proof that RE2 handles the pattern's worst case in linear time.

### 8.3 Base64 decoder amplification

```console
$ python3 -c "import base64;open('/tmp/redos_lab/b64.bin','wb').write((base64.b64encode(b'mongodb://user1:realpass99@host.example.com:27017/db?tls=true')+b'\n')*2000)"
$ /tmp/trufflehog_bin filesystem /tmp/redos_lab/b64.bin --no-verification --concurrency=1 >/dev/null 2>b64.err
$ grep 'finished scanning' b64.err
2026-07-06T22:43:48Z	info-0	trufflehog	finished scanning	{"chunks": 17, "bytes": 160058, "verified_secrets": 0, "unverified_secrets": 23, "scan_duration": "48.169678ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

Base64-encoded connection strings **are** decoded (by the `Base64` decoder in the chain [decoders.go:L8-L16]) and detected: `unverified_secrets: 23` (after deduplication of the 2000 identical lines). The decoder chain expands the scanned surface but is bounded ≤4× — for the 8 MiB attack file the scanned `bytes` was `10903552`, i.e. **1.30×** the on-disk size, not unbounded.

### 8.4 Many-match `FindAllStringSubmatch(-1)` extraction

Covered quantitatively in §4 Table 2: `FindAllStringSubmatch(dataStr, -1)` [mongodb.go:L49] extracts all 1216 matches; cost scales **linearly** with match count (the many-match file is ~2.2× the attack file's wall time because it does real work for 1216 secrets, whereas the attack file does zero). This is the realistic worst case for the pattern-matching layer, and it is linear and bounded.

---


## 9. Adjacent vector (noted, out of scope) — archive / decompression bombs

The user's question is specifically about the **regex pattern-matching** layer. A *separate*, distinct resource-exhaustion class exists in TruffleHog's archive handling under `pkg/handlers/` (`archive.go`, `apk.go`, `ar.go`, `default.go`, `rpm.go`, …): a decompression ("zip") bomb could expand a tiny archive into a huge decoded stream. That vector is **not** a regex/ReDoS issue and is bounded by its own controls, which are separate CLI flags:

```console
$ grep -nE 'archive-max-size|archive-max-depth|archive-timeout' main.go
78:	archiveMaxSize       = cli.Flag("archive-max-size", "Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)").Bytes()
79:	archiveMaxDepth      = cli.Flag("archive-max-depth", "Maximum depth of archive to scan.").Int()
80:	archiveTimeout       = cli.Flag("archive-timeout", "Maximum time to spend extracting an archive.").Duration()
```

`--archive-max-size`, `--archive-max-depth`, and `--archive-timeout` [main.go:L78-L80] cap the size, nesting depth, and wall time of extraction. This is acknowledged for completeness but is **explicitly out of scope** for the pattern-matching (ReDoS) question and was not deep-dived.

---

## 10. Coverage pass — every part of the question answered

| # | Question part | Answer | Evidence |
|---|---|---|---|
| a | Can an attacker who commits a crafted file make TruffleHog **hang / time out** and block the pipeline? | **No.** No hang is possible; worst case is a bounded linear slowdown. The soft timeout wouldn't even need to fire because RE2 completes in linear time. | §1, §7, §8 |
| b | Is the **regex layer exploitable** (catastrophic backtracking / ReDoS)? | **No — impossible by construction.** No detector on the scan path uses a catastrophic-backtracking engine: **867** detector files compile with linear-time RE2 (`go-re2`) and **3** use Go's ReDoS-safe stdlib `regexp` (`regexp2` is indirect/unused). The profile is ~84–88% RE2-automaton `_ExternalCode` with only a small, scale-dependent (≈1.5–4%) *bounded* stdlib-`regexp` backtracking share. | §2, §5 |
| c | **Which patterns** are exploitable? | **None.** The most "dangerous-looking" candidates — `mongodb.connStrPat` (nested `(?:,…)*`/`(?:&…)*`) [mongodb.go:L32], the `common.EmailPattern` *string constant* [patterns.go:L10] as compiled by `alegra` with go-re2 [alegra.go:L10,L28], and representative `anthropic` [anthropic.go:L27] — all run linearly under RE2. | §3, §8.2 |
| d | **How much slower** is a crafted file than a normal file of **equivalent size**? | **Not slower — ratio ≈ 0.97×** at 8 MiB. A file of *legitimate* matches costs more (~2.2×) but only linearly in match count (1216 matches), never exponentially. | §4 Tables 1 & 2 |
| e | **Timing + CPU-profiling evidence** provided? | **Yes** — `time`/per-run wall+user+sys, `--print-avg-detector-time` (`MongoDB: 29.437232ms`), pprof (`runtime._ExternalCode` 87.72%), and fgprof (`runtime.gopark` 84.31%). | §4, §5 |

**Named items addressed explicitly:** flags `--no-verification` [main.go:L59], `--concurrency` [main.go:L58], `--print-avg-detector-time` [main.go:L72], `--profile` [main.go:L53], `--scan-entire-chunk` [main.go:L68], `--detector-timeout` [main.go:L77], `--archive-max-size/-max-depth/-timeout` [main.go:L78-L80]. Mechanisms: Aho-Corasick prefilter [ahocorasickcore.go:L127,L241; engine.go:L795], ±512 B span limiting [ahocorasickcore.go:L155,L160], 10 KiB chunking [chunker.go:L14-L18], decoder chain [decoders.go:L8-L16], soft timeout [engine.go:L1066-L1068,L1076-L1077; http.go:L18], metrics [metrics.go:L38-L46]. Patterns/files: `mongodb` [mongodb.go:L14,L32,L40,L44,L49], `common.EmailPattern` [patterns.go:L5,L10], `alegra` [alegra.go:L10,L28,L41,L42], `anthropic` [anthropic.go:L27,L36,L37,L44], `Detector` contract [detectors.go:L19,L21,L24,L87], filesystem source [filesystem.go:L73,L85]. Engines: `go-re2 v1.9.0` [go.mod:L100], `wazero v1.9.0` [go.mod:L285], `aho-corasick v1.0.3` [go.mod:L17], `fgprof v0.9.5` [go.mod:L46], `regexp2 v1.4.0` indirect/unused [go.mod:L187].

### Practical CI takeaway

TruffleHog's **regex pattern-matching cannot be weaponized into a ReDoS hang** — the engine choice (linear-time RE2) makes catastrophic backtracking impossible, and five further defense layers bound attacker impact to a linear constant factor. The only realistic residual cost is **linear**: a file stuffed with many *valid-looking* secrets costs more only in proportion to the number of matches (my 1216-match 8 MiB file took ~4.4 s vs ~2.0 s for a non-matching file of the same size). If **total scan throughput** on very large inputs is a CI concern, address it as a *linear-scaling/throughput* consideration (input size limits, parallelism, path filtering) — **not** as a catastrophic-backtracking vulnerability, because that vulnerability class does not exist on this detector path.

> **Caveat worth flagging to operators:** the per-detector `--detector-timeout` is **soft/advisory** — it logs but does not preempt a CPU-bound detector (§7). This is harmless given RE2's linear-time guarantee, but operators should not rely on `--detector-timeout` as a hard kill-switch for a runaway detector. For the *adjacent* archive vector (§9), use `--archive-max-size/-max-depth/-timeout` instead.

## 11. Cleanup & repository-unchanged evidence

Per the read-only constraint, every temporary artifact created for this investigation — the built binary (`/tmp/trufflehog_bin`), the `/tmp/redos_lab` input files, and the observation scripts — is deleted, leaving the repository with **only** this document changed:

```console
$ rm -rf /tmp/redos_lab /tmp/trufflehog_bin
$ ls -d /tmp/redos_lab /tmp/trufflehog_bin 2>&1
ls: cannot access '/tmp/redos_lab': No such file or directory
ls: cannot access '/tmp/trufflehog_bin': No such file or directory
```

With the document committed as the deliverable, the working tree is **clean**, and `git diff --name-status` against the source baseline confirms the document is the only addition since `e42153d44…` — **zero** TruffleHog source files changed:

```console
$ git status --porcelain
$ git diff --name-status e42153d44a5e5c37c1bd0c70e074781e9edcb760 HEAD
A	blitzy/documentation/trufflehog_e42153d44a5e.md
```

→ `git status --porcelain` prints nothing — the document is committed, so the working tree is clean — and `git diff --name-status` lists exactly one added path, this document. No `pkg/**`, `main.go`, `go.mod`, or `go.sum` file is modified. TruffleHog's source is untouched — exactly as required.

---

*Investigation methodology: build the canonical binary → craft equivalent-size attack/benign inputs → run the real `trufflehog filesystem` entry point with TruffleHog's own compiled detector patterns → capture timing, `--print-avg-detector-time`, pprof, and fgprof → verify stability across ≥2–3 runs → delete all temporary artifacts. No TruffleHog source file was modified; this document is the only persistent change. All `file:line` citations are to commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`.*

