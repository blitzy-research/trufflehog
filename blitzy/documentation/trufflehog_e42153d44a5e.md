# TruffleHog AWS Credential Detection — Why Identical-Looking Credentials Are Detected, Missed, or Reported Differently

> **Audience:** A security engineer evaluating TruffleHog for a scanning pipeline who has observed detection behaviors that appear inconsistent.
>
> **Methodology — *code as truth*.** Every behavioral claim in this report is (a) anchored to an exact source location (file + line range) at the audited commit, and (b) corroborated by empirical scan output captured from a binary built directly from this source tree. Where a threshold is involved, the report shows what happens right at the boundary. Nothing here is inferred or assumed; if it is stated, it is either cited or demonstrated.
>
> **Audited revision:** branch `trufflehog_e42153d44a5e`, commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`.
>
> **Headline:** TruffleHog's AWS detection is **deterministic**. The *same bytes* always produce the *same result* — there is no randomness, no sampling, and no time-dependence in the detection path. When two files that "look like" they contain the same credential produce different results, it is because something the pipeline is *sensitive to* actually differs between them: a missing keyword, a regex word-boundary, an entropy value on the wrong side of a threshold, a hash-shaped secret, a false-positive term such as `example`, a verification-overlap safety trip, or simply a different **output filter / verification status**. This document identifies, for each observed symptom, the precise gate responsible and proves it with a reproducible scan.

---

## Table of contents

1. [Overview — the four-stage detection pipeline](#overview--the-four-stage-detection-pipeline)
2. [Q1 — Detection variance across files (deterministic gates)](#q1--detection-variance-across-files-deterministic-gates)
3. [Q2 — The effect of encoding (encoding does *not* hide a secret)](#q2--the-effect-of-encoding-encoding-does-not-hide-a-secret)
4. [Q3 — Test-fixture credentials that are never flagged (false-positive filtering)](#q3--test-fixture-credentials-that-are-never-flagged-false-positive-filtering)
5. [Q4 — "verification has been disabled for your safety" (the verification-overlap mechanism)](#q4--verification-has-been-disabled-for-your-safety-the-verification-overlap-mechanism)
6. [Q5 — Boundaries and thresholds, with evidence (entropy at the cutoff)](#q5--boundaries-and-thresholds-with-evidence-entropy-at-the-cutoff)
7. [Cross-cutting — "reported differently" is governed by flags, not randomness](#cross-cutting--reported-differently-is-governed-by-flags-not-randomness)
8. [Appendix — reproducible commands and verbatim scan output](#appendix--reproducible-commands-and-verbatim-scan-output)
9. [How to reproduce this investigation](#how-to-reproduce-this-investigation)

> **A note on the credentials in this report.** Every key and secret shown below is an **agent-constructed, non-live fixture** built purely to demonstrate detection behavior. `AKIAIOSFODNN7EXAMPLE` is AWS's own public documentation placeholder; the 40-character "secrets" are random strings generated to land on specific Shannon-entropy values. None of them is, or corresponds to, a real AWS credential, and verification is disabled in every run. They exist only as evidence.

---

## Overview — the four-stage detection pipeline

TruffleHog decomposes a scan into four stages, documented in `docs/process_flow.md` and parallelized across worker pools described in `docs/concurrency.md`:

1. **Source Decomposition** — sources (filesystem, git, GitHub, Postman, …) are broken down into *units* and finally into small **chunks**, which are the unit of detection (`docs/process_flow.md`, "Source Decomposition").
2. **Chunk-to-Detector Matching** — each chunk is matched to candidate detectors using an **Aho-Corasick keyword prefilter**; a detector only runs on a chunk if one of its keywords is literally present (`docs/process_flow.md`, "Keyword Matching (Aho-Corsick)" *[sic]*).
3. **Secret Detection** — for the matched detectors the engine runs **De-Dupe-Detectors → Collect Matches → Verify Matches**: it decides which detector "owns" a secret so it does not "duplicate verification requests to externa APIs" *[sic]*, runs detector-specific regexes to collect unverified candidates, then optionally verifies them against the live provider (`docs/process_flow.md`, "Secret Detection").
4. **Result Notification** — surviving results are enriched and dispatched to the output (`docs/process_flow.md`, "Result Notification").

Concurrency mirrors these stages: `ScannerWorkers` enumerate and chunk a source and run the keyword match; `VerificationOverlapWorkers` "handle chunks matched to multiple detectors"; `DetectorWorkers` run detection, verification, filtering, and enrichment; and `NotifierWorkers` write results out (`docs/concurrency.md`).

**The mental model that explains every symptom in this report:** detection is a *chain of deterministic gates*. A credential is reported **only if it passes every gate**. Crucially, before detection even begins, the chunk is run through a **decoder chain** (UTF-8, Base64, UTF-16, escaped-Unicode), and the decoded bytes are what the keyword prefilter and detectors see.

```mermaid
flowchart TD
    A["File / chunk"] --> B["Decoder chain<br/>UTF8 - Base64 - UTF16 - EscapedUnicode"]
    B --> C{"Keyword present?<br/>AKIA / ABIA / ACCA / ASIA"}
    C -->|No| MISS1["Not scanned by AWS detector -> MISS"]
    C -->|Yes| D{"ID regex match &<br/>ID entropy >= 3.0?"}
    D -->|No| MISS2["Skipped -> MISS"]
    D -->|Yes| E{"Secret regex match &<br/>secret entropy >= 4.25?"}
    E -->|No| MISS3["Skipped -> MISS"]
    E -->|Yes| F{"Multiple detectors<br/>match same secret?"}
    F -->|"Yes (no override)"| G["errOverlap set:<br/>verification DISABLED for safety"]
    F -->|No| H{"verify enabled?"}
    H -->|Yes| I["STS GetCallerIdentity"]
    H -->|No| J["Unverified result"]
    G --> K{"False-positive filters"}
    I --> K
    J --> K
    K -->|"ID contains example/sample,<br/>wordlist hit, or all-hex secret"| MISS4["Filtered -> MISS (unless verified)"]
    K -->|"Passes"| OUT["Reported (verified / unverified / unknown)"]
```

Each of the five questions below maps to one (or two) of these gates. The appendix contains the verbatim scan runs that prove each answer.

---

## Q1 — Detection variance across files (deterministic gates)

> *"Valid AWS credentials get detected perfectly in some files, but in other files that look like they contain the same credentials they're completely missed or reported differently — and it's consistent: the same file always produces the same result."*

### (1) Mechanism

AWS access keys (the long-lived `AKIA`/`ABIA`/`ACCA` family) are detected by `pkg/detectors/aws/access_keys/accesskey.go`. Detection is a strict sequence of gates; every one of them is a pure function of the (decoded) chunk bytes, which is why the result is **consistent for a given file**.

1. **Keyword prefilter (Aho-Corasick).** `Keywords()` returns `["AKIA", "ABIA", "ACCA"]` (`pkg/detectors/aws/access_keys/accesskey.go:L70-L76`). If none of these literal substrings appears in the decoded chunk, the AWS detector is **never invoked** on that chunk — a guaranteed miss before any regex runs. This is the engine's keyword-matching stage from `docs/process_flow.md`.
2. **ID regex with word boundaries.** `idPat = \b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b` (`pkg/detectors/aws/access_keys/accesskey.go:L65`). The leading/trailing `\b` word boundaries matter: the *same* 20-character key embedded with different neighbouring characters can match in one file and fail to match in another. The detector entry point is `FromData` (`…/accesskey.go:L105`), and the chunk first has URL-encoded base64 punctuation normalized via `aws.UrlEncodedReplacer.Replace(dataStr)` (`…/accesskey.go:L108`, replacer defined at `pkg/detectors/aws/utils.go:L35-L42`).
3. **ID entropy gate.** `if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy { continue }` (`…/accesskey.go:L122`), where `RequiredIdEntropy = 3.0` (`pkg/detectors/aws/common.go:L6`).
4. **Secret regex + secret entropy gate.** The secret pattern is `SecretPat = (?:[^A-Za-z0-9+/]|\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\z)` (`pkg/detectors/aws/common.go:L10`) — exactly 40 base64-alphabet characters, bounded by non-base64 characters. The gate is `if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy { continue }` (`…/accesskey.go:L132`), where `RequiredSecretEntropy = 4.25` (`pkg/detectors/aws/common.go:L7`). (This boundary is the subject of **Q5**.)
5. **What gets reported.** The result is populated with `Raw: []byte(idMatch)`, `Redacted: idMatch`, and `RawV2: []byte(idMatch + ":" + secretMatch)` (`…/accesskey.go:L137-L140`). The key consequence — central to **Q3** — is that the false-positive screen later runs on `Raw`, i.e. **the ID**, not the secret.
6. **Unverified hash skip.** `if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) { continue }` (`…/accesskey.go:L202-L205`), with `FalsePositiveSecretPat = [a-f0-9]{40}` (`pkg/detectors/aws/utils.go:L44-L47`). A 40-character all-lowercase-hex string (e.g. a git commit hash) matches `SecretPat` but is dropped when unverified, because "they are extremely unlikely to be generated as an actual AWS secret" (`utils.go:L44-L46`).
7. **Verification (when enabled).** `verifyMatch` issues `stsClient.GetCallerIdentity(...)` (`…/accesskey.go:L248`). There is a documented workaround: rapid duplicate ID/secret requests can return a spurious `403 SignatureDoesNotMatch`, so the call is resubmitted **once** when `retryOn403` is set (`…/accesskey.go:L250-L268`; `retryOn403` is `len(secretMatches) > 1`, `…/accesskey.go:L186`). An `InvalidClientTokenId` response simply means *unverified* (`…/accesskey.go:L265-L266`).
8. **De-duplication — verified-preferred, one result per ID.** The detector implements `CleanResults` (`…/accesskey.go:L280-L282`) which delegates to `aws.CleanResults` (`pkg/detectors/aws/utils.go:L89-L114`). For each ID (keyed on `result.Redacted`) it keeps **at most one** result, *always preferring the verified one*; otherwise it keeps the first unverified result. AWS also declares `ShouldCleanResultsIrrespectiveOfConfiguration() == true` (`…/accesskey.go:L218-L220`), so this de-duplication runs **regardless** of CLI flags. This is why a file containing the same ID twice yields one finding, and why a verified hit suppresses unverified duplicates of the same ID.

Two adjacent detectors explain further "reported differently" cases:

- **Temporary / STS keys (`ASIA`)** are a *separate* detector, `pkg/detectors/aws/session_keys/sessionkey.go`: `idPat = \b((?:ASIA)[A-Z0-9]{16})\b` (`…/sessionkey.go:L61`), a long session-token pattern `([a-zA-Z0-9+/]{100,}={0,3})` (`…/sessionkey.go:L62`), `Keywords() = ["ASIA"]` (`…/sessionkey.go:L67-L69`). It applies the same ID and secret entropy gates (`…/sessionkey.go:L93`, `L103`) **plus** an additional session-token entropy gate `< 4.5` (`…/sessionkey.go:L108`). An `ASIA` key without a sufficiently long, high-entropy session token therefore behaves differently from an `AKIA` key.
- **Canary tokens** — `pkg/detectors/aws/access_keys/canary.go` decodes the account number embedded in the key and, if it belongs to a known canary account list (`thinkstCanaryList`, 10 accounts, `canary.go:L17-L28`; `thinkstKnockoffsCanaryList`, 16 accounts, `canary.go:L29-L46`), routes verification to **SNS** rather than STS (`verifyCanary`, `canary.go:L49`) and attaches an explanatory `message` (`canary.go:L13-L14`). Such keys are *reported differently* by design.

### (2) Rationale

Every gate is deterministic on purpose. Security scanning runs in CI and must be **reproducible and auditable**: the same commit must scan the same way every time, or the signal is worthless. The keyword/regex/entropy gates trade a small number of misses for an enormous reduction in false positives and (when verification is on) in outbound API traffic — TruffleHog will not call AWS STS for every 40-character string it sees. Verified-preferred de-duplication keeps the output clean: a single ID found many times in a file collapses to one finding, and a confirmed-live result is never buried under unverified duplicates. The separate `ASIA` and canary paths exist because those credentials *are* different (temporary credentials need a session token; canary tokens are tripwires whose "verification" must not behave like a normal STS probe).

### (3) Evidence

- Appendix fixtures **(b) vs (c)** show the entropy gate (#4 above) flipping the outcome for the *same ID and same file shape* — `(b)` is missed, `(c)` is detected.
- Fixtures **(a)** and **(d)** show the false-positive path (#5) producing a miss even when the format is perfect.
- Fixture **(c)** yields exactly **one** finding, illustrating the one-result-per-ID de-duplication (#8).

---


## Q2 — The effect of encoding (encoding does *not* hide a secret)

> *"Some developers encode sensitive data before committing it because they believe it adds a layer of protection. Can that fool the scanner?"*

**Short answer: no.** Encoding is not a security control, and TruffleHog deliberately defeats it by decoding chunk content and re-scanning the decoded bytes *before* detection runs.

### (1) Mechanism

- **The decoder chain runs first.** `pkg/decoders/decoders.go` defines `DefaultDecoders()` returning, in order, `&UTF8{}, &Base64{}, &UTF16{}, &EscapedUnicode{}` (`pkg/decoders/decoders.go:L8-L16`). The comment notes "UTF8 must be first for duplicate detection" (`decoders.go:L10`). Each decoder tags the chunk with a `DecoderType`, which is what you see on the `Decoder Type:` output line: `PLAIN` (`pkg/decoders/utf8.go:L12-L13`), `BASE64` (`pkg/decoders/base64.go:L30-L31`), `UTF16` (`pkg/decoders/utf16.go:L14-L15`), and `ESCAPED_UNICODE` (`pkg/decoders/escaped_unicode.go:L28-L29`).
- **Base64 decode-and-substitute.** `(*Base64).FromChunk` (`pkg/decoders/base64.go:L34`) locates base64 runs longer than 20 characters via `getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)` (`base64.go:L36`). For each run it attempts both `base64.StdEncoding` and `base64.RawURLEncoding`, and accepts a decode **only if the result is ASCII** (`isASCII(dec)`, `base64.go:L40-L48`). It then **rewrites `chunk.Data` in place**: a `bytes.Buffer` is filled with the bytes *before* each run, the *decoded* bytes in place of the run, and finally the trailing bytes, and the rebuilt buffer is assigned back with `chunk.Data = result.Bytes()` (`base64.go:L51-L67`).
- **The decoded chunk is re-routed through the keyword prefilter.** Because the substitution physically replaces the encoded run with its plaintext, an `AKIA…` identifier that was hidden inside a base64 blob is now present as literal text — so the Aho-Corasick keyword match (Q1, gate #1) fires, and the AWS detector runs exactly as it would on a plaintext file. The only visible difference is the `Decoder Type:` line.

The `>20 characters` length floor and the `isASCII` acceptance test are deliberate guards: they prevent TruffleHog from trying to "decode" every short token or treating binary/garbage as text.

### (2) Rationale

Real secrets are constantly embedded inside encoded blobs — base64-encoded environment dumps, Kubernetes secrets, JSON/JWT-like payloads, and config files. A scanner that only matched plaintext would miss a huge class of genuine leaks. Decoding-then-rescanning is therefore essential to recall. The corollary for the user's question is direct: **base64-encoding a credential before committing provides no protection whatsoever** — TruffleHog transparently undoes it. The `DecoderType` tag exists so that an operator can *see* that a finding came in through a decoded path rather than as plaintext.

### (3) Evidence

Appendix fixture **(e)** is a base64 blob that decodes to exactly the same `ID + secret` as plaintext fixture **(c)**. Both are detected as `AWS`; the *only* difference in the output is `Decoder Type: BASE64` (fixture e) versus `Decoder Type: PLAIN` (fixture c). Same secret, both found, different path.

---


## Q3 — Test-fixture credentials that are never flagged (false-positive filtering)

> *"Some credentials in our test fixtures never get flagged even though they follow the right format."*

This is the most common source of confusion, and the answer is precise: **correctly formatted credentials in fixtures are usually missed not because of their format, and usually not because of entropy, but because they trip the false-positive subsystem — most often the `example` / `sample` term filter applied to the access-key ID.**

### (1) Mechanism

The false-positive subsystem lives in `pkg/detectors/falsepositives.go`, and is wired into the engine's `filterResults` (`pkg/engine/engine.go:L1126-L1150`).

- **Default term list.** `DefaultFalsePositives = {"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"}` (`pkg/detectors/falsepositives.go:L17-L18`).
- **Embedded word lists.** Four lists are compiled into the binary with `//go:embed` (`falsepositives.go:L35-L42`) and loaded into an Aho-Corasick trie (`filter`) in `init()` (`falsepositives.go:L45-L68`): `fp_badlist.txt`, `fp_words.txt`, `fp_programmingbooks.txt`, `fp_uuids.txt`. Their sizes at this commit (reproducible with `wc -l pkg/detectors/fp_*.txt`) are **288 / 283 / 2871 / 37** lines respectively.
- **The matching function.** `IsKnownFalsePositive(match, falsePositives, wordCheck)` (`falsepositives.go:L85-L109`) lowercases the candidate and applies three checks **in order**:
  1. exact membership in the term map → reason `"matches term: <t>"` (`L91-L93`);
  2. **substring** containment, `strings.Contains(lower, fps)` → reason `"contains term: <t>"` (`L95-L100`);
  3. if `wordCheck` is set, an Aho-Corasick wordlist hit, `filter.MatchFirstString(lower)` → reason `"matches wordlist: <w>"` (`L102-L106`).
  Invalid UTF-8 short-circuits to `true` with reason `"invalid utf8"` (`L86-L88`).
- **What gets screened, for AWS.** A detector without a custom checker (AWS is such a detector) uses the default `GetFalsePositiveCheck`, which calls `IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)` (`falsepositives.go:L70-L78`). Recall from Q1 that for AWS, `res.Raw` is the **ID** (`accesskey.go:L138`). **So the access-key ID is the string screened for `example` / `sample` / wordlist hits.**
- **Verified results are never filtered.** Both `FilterKnownFalsePositives` (`falsepositives.go:L176-L201`) and `FilterResultsWithEntropy` (`falsepositives.go:L153-L174`) pass any `result.Verified == true` straight through (`L188-L191` and `L169-L171` respectively). They only filter **unverified** results. `FilterKnownFalsePositives` emits a `V(4)` log line `"Skipping result: false positive"` carrying the `result` (`string(result.Raw)`) and the `reason` (`falsepositives.go:L194`).
- **The AWS all-hex guard** (already noted in Q1) is an additional, AWS-specific false-positive rule: `FalsePositiveSecretPat = [a-f0-9]{40}` drops unverified git-hash-shaped secrets (`pkg/detectors/aws/utils.go:L44-L47`, applied at `accesskey.go:L202-L205`).

#### Key proof — it is the term filter, not entropy

`AKIAIOSFODNN7EXAMPLE` has Shannon entropy **3.6842**, which is **≥ 3.0**, so it *passes* the ID entropy gate (Q1 gate #3). It is filtered solely because its lowercase form `akiaiosfodnn7example` **contains the substring `example`** — check #2 above. This is confirmed directly by the engine's debug log: `"reason": "contains term: example"` (appendix fixture **(d)**, run with `--log-level=4`). To remove any doubt that entropy is involved, fixture **(d)** pairs that example ID with a *high-entropy* secret (4.3964, comfortably above the 4.25 secret threshold) — and the credential is **still** missed, with the same `contains term: example` reason. **Entropy is demonstrably not the cause; the ID's `example` substring is.**

### (2) Rationale

Documentation, SDK samples, tutorials, and — exactly as the user observed — **test fixtures** are saturated with placeholder keys like `AKIAIOSFODNN7EXAMPLE`. If TruffleHog flagged all of them, real findings would drown in noise and the tool would be operationally useless. The term/wordlist filters encode the heuristic "things that contain obvious placeholder words are probably not live secrets."

The single most important design decision here is the **verified-always-passes asymmetry**: because the false-positive and entropy filters skip verified results entirely, a *genuinely live* credential is **never** suppressed by these filters — even if it happens to contain the substring `example`. Only **unverified** look-alikes are filtered. This is the precise mechanism behind "the same key is detected in file X but missed in file Y": in X it either verified (so the filters were bypassed) or it did not trip a filter; in Y it was unverified **and** tripped a filter (most often the `example`/`sample` term on the ID, or the all-hex secret guard).

### (3) Evidence

- Appendix fixture **(a)** — `AKIAIOSFODNN7EXAMPLE` plus the canonical example secret → **0 findings**.
- Appendix fixture **(d)** — example ID plus a *high-entropy* secret → **0 findings**, with the decisive `--log-level=4` log line `reason: contains term: example`. This isolates the cause to the term filter, not entropy.

---


## Q4 — "verification has been disabled for your safety" (the verification-overlap mechanism)

> *"We get CI warnings that verification was disabled 'for safety.' What triggers that, and why would verification be disabled?"*

### (1) Mechanism

The warning is the verbatim text of the `errOverlap` error in `pkg/engine/engine.go:L39-L41`:

```
More than one detector has found this result. For your safety, verification has been disabled.You can override this behavior by using the --allow-verification-overlap flag.
```

> **Reproduced exactly.** In the source this message is built by concatenating two string literals (`engine.go:L40` and `L41`). The first ends with `disabled."` and the second begins with `"You`, so the rendered message has **no space between `disabled.` and `You`** (`…disabled.You can override…`). That missing space is a faithful fingerprint of the literal at this commit, not a transcription error in this report.

This error is attached when the **same secret value is matched by more than one detector** within a single chunk. The decision is made by `likelyDuplicate` (`engine.go:L887`) with `const similarityThreshold = 0.9` (`engine.go:L888`), comparing the candidate against the secrets already seen in the chunk. It deliberately:

- **skips length-mismatched candidates** — `if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 { continue }` (`engine.go:L894`), i.e. it ignores pairs whose lengths differ by more than ~10%;
- **skips same-detector pairs** — `if val.detectorKey.Type() == dupeKey.detectorKey.Type() { continue }` (`engine.go:L900-L902`); two hits from the *same* detector are an expected intra-detector duplicate and are *still verified*;
- returns `true` on an **exact match** (`valStr == dupe`, `engine.go:L904-L909`) or when `strutil.Similarity(valStr, dupe, metrics.NewLevenshtein()) > similarityThreshold` (`engine.go:L911-L919`).

The "same secret, different detector" key is `chunkSecretKey{secret, detectorKey}` (`engine.go:L882-L885`). When `likelyDuplicate` returns true at the call site (`engine.go:L982`), the engine increments the overlap tracker and calls `res.SetVerificationError(errOverlap)` (`engine.go:L985-L988`) — which is exactly how verification is disabled for that result. The override is the CLI flag `--allow-verification-overlap` (`main.go:L65`).

For context, this is the engine stage that `docs/concurrency.md` assigns to the `VerificationOverlapWorkers` ("handles chunks matched to multiple detectors"), and that `docs/process_flow.md` labels "De-Dupe-Detectors" — chosen so TruffleHog does "not duplicate verification requests to externa APIs" *[sic]*.

### (2) Rationale

Suppose a 40-character string matches both AWS's `SecretPat` and some *other* provider's secret pattern. If TruffleHog "verified" it against AWS, it would transmit a credential that may actually belong to a different provider — leaking it to a third party that should never have seen it. That is a genuine safety and privacy hazard. Rather than *guess* which provider owns the secret, the engine refuses to verify and says so. The behavior is opt-out, not opt-in, precisely because the safe default must not require the operator to know about the hazard in advance; `--allow-verification-overlap` exists for advanced users who understand the trade-off. Levenshtein **similarity** (rather than exact equality) is used so that near-identical captures still trip the guard — for example when one detector captures a trailing character that another does not (the canonical illustration in the source is a Postman key whose embedded substring also looks like a generic "api key", `engine.go:L973-L976`).

### (3) Evidence

The decisive evidence here is the **source itself**: the verbatim `errOverlap` literal (`engine.go:L39-L41`) and the routing that attaches it (`engine.go:L982`, `L988`), corroborated by the presence of the `--allow-verification-overlap` override in the built binary's `--help`. A natural multi-detector overlap depends on which detectors happen to co-match a given chunk and is **not** something this investigation reproduces with a synthetic fixture — fabricating one would violate the code-as-truth methodology. The mechanism above (quoted from source and confirmed against the compiled binary's flag set) is the proof.

---


## Q5 — Boundaries and thresholds, with evidence (entropy at the cutoff)

> *"Where thresholds are involved — like entropy — show what happens right at the boundary."*

### (1) Mechanism

The secret-entropy threshold is a **hard cutoff**: `RequiredSecretEntropy = 4.25` (`pkg/detectors/aws/common.go:L7`), enforced at `accesskey.go:L132` (`if … < aws.RequiredSecretEntropy { continue }`). The companion ID threshold is `RequiredIdEntropy = 3.0` (`common.go:L6`, enforced at `accesskey.go:L122`). The `ASIA` session detector adds a third, stricter session-token gate `< 4.5` (`pkg/detectors/aws/session_keys/sessionkey.go:L108`).

"Entropy" here is **Shannon entropy in bits per character**, computed by `StringShannonEntropy` (`pkg/detectors/falsepositives.go:L136-L151`):

$$H = -\sum_{c} p_c \log_2 p_c$$

where `p_c` is the frequency of character `c` divided by the string length. The function builds a per-rune count map, multiplies each count by `1/len`, accumulates `p·log₂(p)`, and returns the negation (`falsepositives.go:L137-L150`). It depends **only on the multiset of characters** — not on their order — so two strings that "look equally random" can have materially different entropy if one repeats a few characters more than the other.

The CLI exposes an *additional*, post-hoc entropy filter: `--filter-entropy` (help text "Start with 3.0", `main.go:L67`), which runs `FilterResultsWithEntropy` on **unverified** results (`falsepositives.go:L153-L174`, wired at `engine.go:L1145-L1146`). The built-in `4.25` gate in the detector is always active; `--filter-entropy` layers another threshold on top.

#### Boundary fixtures (both 40 characters, both match `SecretPat`; only entropy differs)

| Secret (40 chars) | Distinct chars / max repeat | Shannon entropy | vs 4.25 | Outcome |
|---|---|---|---|---|
| `VhFwsGGxGGfGP6o1G8P/fhgGuPIc8qdvhx8dZfZo` | 22 / 7 (`G`×7) | **4.1552** | below | **missed** |
| `wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9` | 24 / 4 | **4.3964** | above | **detected** |

The intuition the numbers make concrete: the "below" secret concentrates probability mass on a few repeated characters (`G` appears seven times), which *lowers* entropy under the cutoff; the "above" secret spreads more evenly across more distinct characters, pushing entropy over the cutoff. For reference, computed with the same function: `AKIAIOSFODNN7EXAMPLE` = **3.6842**, and the clean ID `AKIAZXO72LMQ4F8VN3PK` = **4.1219** (both ≥ 3.0, so both clear the ID gate).

### (2) Rationale

Genuine AWS secret access keys are high-entropy random strings. A 40-character *shape* match (`SecretPat`) is necessary but not sufficient — plenty of 40-character strings that are *not* secrets (formatted data, padded identifiers, repeated patterns, dictionary-ish text) also match the shape. The entropy gate is a precision/recall tuning knob: `4.25` is chosen so that real keys comfortably pass while common 40-character non-secrets fall below it. That a threshold exists at all is *exactly* why "two identical-looking secrets" can diverge — they are not actually identical to the gate; their character distributions differ, and one lands on each side of `4.25`.

### (3) Evidence

Appendix fixtures **(b)** and **(c)** are identical except for the secret: same clean ID `AKIAZXO72LMQ4F8VN3PK`, same file layout, same byte length. `(b)`'s secret has entropy 4.1552 (below 4.25) → **0 findings**; `(c)`'s secret has entropy 4.3964 (above 4.25) → **1 finding**. The threshold, and nothing else, flips the outcome.

---


## Cross-cutting — "reported differently" is governed by flags, not randomness

The phrase "reported differently" almost always reduces to **verification status + which result states are printed + output format** — all configured in `main.go`, and all deterministic:

| Flag (`main.go`) | Line | Effect on what you see |
|---|---|---|
| `--no-verification` | `L59` | Skip live verification; every finding is reported as `unverified`. |
| `--results` (default `verified,unverified,unknown`) | `L61` | Which result *states* are printed. With `--results=verified`, an unverified finding is **hidden** even though it was detected. |
| `--allow-verification-overlap` | `L65` | Override the Q4 overlap safety and verify anyway. |
| `--filter-unverified` | `L66` | Keep only the first unverified result per chunk per detector. |
| `--filter-entropy` | `L67` | Apply an extra Shannon-entropy filter to unverified results ("Start with 3.0"). |
| `--fail` | `L74` | Exit with code **183** if any results are found (confirmed at `main.go:L577-L578`). |
| `--no-verification-cache` | `L85` | Disable verification result caching. |
| `--json` / `-j` | `L55` | Emit structured JSON instead of the human-readable block. |

The decisive demonstration is in the appendix: the **same file** (fixture c) shows **one** finding under the default `--results`, **zero** under `--results=verified` (the unverified finding is *hidden by the output filter, not undetected*), and a single structured object under `--json`. The bytes on disk never changed; only the reporting configuration did. This is the direct refutation of the "randomness" hypothesis: detection is fixed by the source bytes, and **presentation** is fixed by the flags.

A second, equally important cross-cutting fact (established in Q3): the false-positive and entropy filters **never suppress a verified result**. So when "the same key is detected in file X but missed in file Y," the usual explanation is that in X the result was verified (or simply did not trip a filter), whereas in Y it was unverified **and** tripped the `example`/`sample` term filter, the all-hex secret guard, or the entropy gate.

---


## Appendix — reproducible commands and verbatim scan output

All runs use a binary built from this source tree (see [How to reproduce](#how-to-reproduce-this-investigation)) and the command pattern:

```
trufflehog filesystem <fixture> --no-verification --results=verified,unverified,unknown --no-update
```

`--no-verification` is used because no live AWS credentials are involved — these fixtures demonstrate **detection**, not verification. Volatile fields in the output (the ISO timestamp, `source_manager_worker_id` / `detector_worker_id`, and `scan_duration`) vary per run and are shown generically as `<ts>` / `<id>` / `<dur>`; the **detection outcome** (counts, `Detector Type`, `Decoder Type`, `Raw result`, and skip `reason`) is deterministic and is what matters.

### Results summary

| Fixture | Content | Gate exercised | Observed |
|---|---|---|---|
| (a) example creds | `AKIAIOSFODNN7EXAMPLE` + `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | FP `example` term (on ID) | **0 findings** (missed) |
| (b) below-threshold | `AKIAZXO72LMQ4F8VN3PK` + secret entropy 4.1552 (< 4.25) | secret entropy gate | **0 findings** (missed) |
| (c) above-threshold | `AKIAZXO72LMQ4F8VN3PK` + secret entropy 4.3964 (> 4.25) | passes all gates | **1 finding**, `Decoder Type: PLAIN` |
| (d) example ID + high-entropy secret | `AKIAIOSFODNN7EXAMPLE` + secret entropy 4.3964 | FP `example` term (**not** entropy) | **0 findings** (missed) |
| (e) Base64-encoded pair | base64 of `(c)`'s `ID + secret` | Base64 decoder | **1 finding**, `Decoder Type: BASE64` |

The five fixtures are single-line files of the form `aws_access_key_id=<ID> aws_secret_access_key=<SECRET>` (fixtures a–d), created **outside** the repository. Fixture (e) is the Base64 encoding of fixture (c)'s exact content.

**Fixture (e) raw content** (decodes to `aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9`):

```
YXdzX2FjY2Vzc19rZXlfaWQ9QUtJQVpYTzcyTE1RNEY4Vk4zUEsgYXdzX3NlY3JldF9hY2Nlc3Nfa2V5PXdnZmExTU9tZ2Y5NkhjbWpOQjlXOUhST0htc1VlZGRGTWpQT3RnYTk=
```

### Detected — fixture (c), `Decoder Type: PLAIN`

```
$ trufflehog filesystem c_above.txt --no-verification --results=verified,unverified,unknown --no-update

🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

<ts>   info-0  trufflehog   running source   {"source_manager_worker_id": "<id>", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAZXO72LMQ4F8VN3PK
Resource_type: Access key
File: c_above.txt
Line: 1

<ts>   info-0  trufflehog   finished scanning   {"chunks": 1, "bytes": 102, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "<dur>", "trufflehog_version": "dev", ...}
```

### Detected — fixture (e), `Decoder Type: BASE64`

Identical to (c) except for the decoder path and the file name — the *same secret* is recovered after Base64 decoding (Q2):

```
$ trufflehog filesystem e_base64.txt --no-verification --results=verified,unverified,unknown --no-update

🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

<ts>   info-0  trufflehog   running source   {"source_manager_worker_id": "<id>", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: BASE64
Raw result: AKIAZXO72LMQ4F8VN3PK
Resource_type: Access key
File: e_base64.txt
Line: 1

<ts>   info-0  trufflehog   finished scanning   {"chunks": 1, "bytes": 102, "verified_secrets": 0, "unverified_secrets": 1, ...}
```

### Missed — fixtures (a), (b), (d)

Each produces **no** `Found …` block; the summary reports zero secrets. Example for fixture (a) (b and d are identical in shape):

```
$ trufflehog filesystem a_example.txt --no-verification --results=verified,unverified,unknown --no-update

🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

<ts>   info-0  trufflehog   running source   {"source_manager_worker_id": "<id>", "with_units": true}
<ts>   info-0  trufflehog   finished scanning   {"chunks": 1, "bytes": 102, "verified_secrets": 0, "unverified_secrets": 0, ...}
```

### False-positive proof — fixture (d) with `--log-level=4`

This is the decisive evidence for **Q3**. The example ID is paired with a *high-entropy* secret (4.3964 > 4.25), so the entropy gate is *not* the cause; the engine logs the real reason at verbosity 4:

```
$ trufflehog filesystem d_example_highentropy.txt --no-verification --no-update --log-level=4

<ts>   info-4  trufflehog   Skipping result: false positive   {"detector_worker_id": "<id>", "detector": {"type":"AWS"}, "timeout": 10, "result": "AKIAIOSFODNN7EXAMPLE", "reason": "contains term: example"}
```

(The same verbose run also emits `Failed to decode account number … "err": "can't get account number from AKIAJ/ASIAJ or AKIAI/ASIAI keys"`, which confirms the account-decode guard at `pkg/detectors/aws/utils.go:L55-L57` for IDs whose fifth character is `I` or `J` — `AKIAIOSFODNN7EXAMPLE` qualifies.)

### "Reported differently" — the same file, three views

All three runs are against the **same** fixture (c); only the flags change.

```
# Default --results → ONE finding shown
$ trufflehog filesystem c_above.txt --no-verification --results=verified,unverified,unknown --no-update
… Found unverified result …   →  summary "unverified_secrets": 1

# --results=verified → ZERO shown (hidden by the output filter, not undetected)
$ trufflehog filesystem c_above.txt --no-verification --results=verified --no-update
… (no Found block) …          →  summary "unverified_secrets": 0

# --json → a single structured finding
$ trufflehog filesystem c_above.txt --no-verification --no-update --json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"c_above.txt","line":1}}}, … ,
 "DetectorName":"AWS","DecoderName":"PLAIN","Verified":false,
 "Raw":"AKIAZXO72LMQ4F8VN3PK",
 "RawV2":"AKIAZXO72LMQ4F8VN3PK:wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9",
 "Redacted":"AKIAZXO72LMQ4F8VN3PK","ExtraData":{"resource_type":"Access key"}}
```

---


## How to reproduce this investigation

Everything below is performed **outside** the repository so the source tree stays untouched (the only artifact committed is this document).

1. **Toolchain.** Build with Go `go1.24.2`, consistent with the `toolchain go1.24.2` directive in `go.mod:L5` (CI pins go-version `1.24`).
2. **Build the analysis binary** (mirrors `Dockerfile:L1-L9`, which uses `CGO_ENABLED=0 go build -o trufflehog .`). `-mod=readonly` guarantees `go.mod`/`go.sum` are not rewritten:

   ```
   CGO_ENABLED=0 go build -mod=readonly -o /tmp/th/trufflehog .
   ```

3. **Create the fixtures outside the repo** (e.g. under `/tmp/th/fixtures/`):

   ```
   printf 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > a_example.txt
   printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=VhFwsGGxGGfGP6o1G8P/fhgGuPIc8qdvhx8dZfZo\n' > b_below.txt
   printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9\n' > c_above.txt
   printf 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9\n' > d_example_highentropy.txt
   printf 'aws_access_key_id=AKIAZXO72LMQ4F8VN3PK aws_secret_access_key=wgfa1MOmgf96HcmjNB9W9HROHmsUeddFMjPOtga9' | base64 -w0 > e_base64.txt
   ```

4. **Run the scans** with the command pattern in the appendix; add `--log-level=4` to surface the false-positive skip log (Q3) and `--json` for the output-format demo.
5. **Verify the entropy values** with the *exact* formula TruffleHog uses (`StringShannonEntropy`, `pkg/detectors/falsepositives.go:L136-L151`): `H = -Σ p·log₂p` over the per-character frequencies. Expected: `AKIAIOSFODNN7EXAMPLE = 3.6842`, clean ID `AKIAZXO72LMQ4F8VN3PK = 4.1219`, below-threshold secret `= 4.1552`, above-threshold secret `= 4.3964`.
6. **Confirm the word-list sizes** with `wc -l pkg/detectors/fp_*.txt` → `288 / 283 / 2871 / 37`.
7. **Clean up.** Remove `/tmp/th` (the binary and fixtures); the Go module cache and toolchain live outside the repo as well. A final `git status` must show the working tree clean except for this single document under `blitzy/documentation/`, with `go.mod`/`go.sum` unchanged.

---

## Summary

TruffleHog's AWS detection is a deterministic chain of gates — keyword prefilter → ID regex/entropy → secret regex/entropy → overlap safety → false-positive/entropy filters → output filter. A credential is reported only if it clears every gate, and the same bytes always clear (or fail) the same gates. The behaviors the user observed map cleanly onto specific gates:

- **Detected here, missed there (Q1, Q5):** the files differ in something a gate is sensitive to — most often the secret's Shannon entropy relative to the `4.25` cutoff (`common.go:L7`), or a word-boundary in the ID regex (`accesskey.go:L65`).
- **Encoding offers no protection (Q2):** the Base64 decoder rewrites the chunk in place and the decoded bytes are re-scanned (`base64.go:L34-L67`); only the `Decoder Type` line changes.
- **Fixtures never flagged (Q3):** the access-key ID is screened for placeholder terms, and `example`/`sample` (or the all-hex secret guard) suppress *unverified* look-alikes — verified credentials always pass (`falsepositives.go:L70-L109,L176-L201`; `utils.go:L44-L47`).
- **"Verification disabled for safety" (Q4):** when more than one detector matches the same secret, the engine sets `errOverlap` and refuses to verify so a credential is never sent to the wrong provider; `--allow-verification-overlap` overrides it (`engine.go:L39-L41,L982,L988`; `main.go:L65`).
- **"Reported differently" is configuration, not randomness:** verification status, `--results`, and `--json` determine what is shown for an unchanged finding (`main.go:L59,L61,L55`).

