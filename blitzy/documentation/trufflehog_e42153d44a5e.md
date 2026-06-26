# TruffleHog Custom-Detector Webhook Verification — Security Analysis

**Can untrusted teams safely contribute custom detector configurations to TruffleHog?**

This document answers, with evidence, a set of concrete security questions about the **custom
detector webhook verification** path in TruffleHog, framed for an operator who must decide whether
detector YAML configurations supplied by **untrusted teams** can be treated as safe input.

| Property | Value |
|---|---|
| Subject | Security of the custom-detector *webhook verification* path when detector YAML configs are **untrusted input** |
| Pinned commit | `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (branch `trufflehog_e42153d44a5e`) |
| Go toolchain used | `go1.24.2` (the highest explicitly documented toolchain; `go.mod` declares `go 1.23.1` with `toolchain go1.24.2` `[go.mod:L3-L4]`) |
| Module | `github.com/trufflesecurity/trufflehog/v3` `[go.mod:L1]` |
| Methodology | **Evidence over theory** — every answer is backed by *both* (a) an inline source citation `[path:Lxx]` (the code is the source of truth) *and* (b) reproduced runtime output captured by building and running TruffleHog. |

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
It calls, in order, `ValidateKeywords`, `ValidateRegex` `[:L45]`, then for each verify block
`ValidateVerifyEndpoint` `[:L50]` and `ValidateVerifyHeaders` `[:L53]`. Notably, two other validators
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
    A["YAML config loaded<br/>config.Read — config.go:L18"] --> B["NewWebhookCustomRegex<br/>validation wiring<br/>custom_detectors.go:L40-L60"]
    B --> C["ValidateVerifyEndpoint<br/>validation.go:L35-L44<br/>NON-EMPTY + http-scheme check ONLY"]
    C --> D["Scan chunk -> regex matches + filters<br/>entropy / exclude-words / exclude-regexes<br/>custom_detectors.go:L117-L153"]
    D --> E["Permute matches<br/>cap maxTotalMatches = 100<br/>custom_detectors.go:L23,L295-L297"]
    E --> F["errgroup dispatch — one g.Go per match<br/>NO SetLimit (unbounded concurrency)<br/>custom_detectors.go:L112,L155-L157"]
    F --> G["createResults: build JSON body<br/>{Name:{group:[match]}}<br/>custom_detectors.go:L214-L216"]
    G --> H["POST via SaneHttpClient<br/>to RAW user endpoint<br/>custom_detectors.go:L228"]
    H --> I{"HTTP 200?"}
    I -->|"yes"| J["result.Verified = true; break<br/>custom_detectors.go:L249,L251,L268"]
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
		return fmt.Errorf("no endpoint")                       // (a) non-empty           [validation.go:L36-L38]
	}
	if strings.HasPrefix(endpoint, "http://") && !unsafe {
		return fmt.Errorf("http endpoint must have unsafe=true") // (b) http:// needs unsafe [validation.go:L40-L42]
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

*Q1a — internal/loopback target with a cloud-metadata-style path.* Config
(`config_q1a_loopback.yaml`):

```yaml
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      hogID: 'HOG[A-Z0-9]{17}'
    verify:
      - endpoint: http://127.0.0.1:18099/latest/meta-data/iam/security-credentials/
        unsafe: true
```

```bash
# Terminal 1: a listener that logs each request and returns HTTP 200
python3 listener_http.py 18099
# Terminal 2:
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/config_q1a_loopback.yaml --custom-verifiers-only --no-update
```

*Q1b — the AWS metadata IP `169.254.169.254`.* Config (`config_q1b_metadata.yaml`) uses
`endpoint: https://169.254.169.254/latest/meta-data/iam/security-credentials/` (no `unsafe` needed
because the scheme is `https`):

```bash
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/config_q1b_metadata.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

*Q1a* — TruffleHog verified the match by POSTing to the loopback metadata-style path; the listener
received the request:

```text
✅ Found verified result 🐷🔑
Detector Type: CustomRegex
Raw result: HOGCCCCCCCCCCCCCCCCC
Response: {"status":"ok"}
Name: HogTokenDetector
File: /tmp/th_harness/target_single.txt
...
finished scanning  {"chunks": 1, "bytes": 50, "verified_secrets": 1, "unverified_secrets": 0, ...}
```

```text
==== REQUEST @ 21:31:41.605306 ====
REQUEST-LINE: POST /latest/meta-data/iam/security-credentials/ HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
==== END @ 21:31:41.605306 ====
```

*Q1b* — the `169.254.169.254` configuration was **accepted with no validation error**, and the
request was *attempted* (it returns unverified only because the metadata IP is unreachable in the
sandbox, not because of any guard):

```text
Found unverified result 🐷🔑❓
Raw result: HOGCCCCCCCCCCCCCCCCC
...
finished scanning  {"chunks": 1, "bytes": 50, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "14.595266ms", ...}
```

```text
# grep for a config-load validation error on the 169.254.169.254 config:
NO config validation error (config accepted)
```

**(e) Reasoning.**

The endpoint is attacker-influenced input that reaches an outbound `POST` with no destination
validation: `ValidateVerifyEndpoint` enforces only "non-empty" and "http scheme ⇒ `unsafe=true`"
`[pkg/custom_detectors/validation.go:L35-L44]`, and the request targets `GetEndpoint()` directly
`[pkg/custom_detectors/custom_detectors.go:L228]` over a client with no IP-block hook and default
redirect-following `[pkg/common/http.go:L211-L228]`. The Q1a evidence shows the scanner can be made
to issue a request to a loopback metadata-style path; the Q1b evidence shows the metadata IP itself
is accepted unchallenged. This is the canonical webhook-SSRF "confused deputy": the trust and
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
	httpClient.Timeout = DefaultResponseTimeout            // 5s  [http.go:L209,L225]
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

Generate a self-signed (untrusted) certificate, serve HTTPS with it, and point a detector at it:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost"
python3 listener_https.py 18443 cert.pem key.pem        # wraps the socket with ssl
# Config endpoint: https://127.0.0.1:18443/
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/config_q2_selfsigned.yaml --custom-verifiers-only --no-update
```

Also demonstrate the load-time scheme gate (an `http://` endpoint without `unsafe: true`):

```bash
# config_q2_http_no_unsafe.yaml uses endpoint: http://127.0.0.1:18099/  (no unsafe)
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/config_q2_http_no_unsafe.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

First, proof the certificate is genuinely untrusted (so a default client *should* reject it) yet the
server is up:

```text
$ curl -sS https://127.0.0.1:18443/
curl: (60) SSL certificate problem: self-signed certificate
$ curl -skS https://127.0.0.1:18443/      # -k bypasses verification -> server is reachable
<!DOCTYPE HTML> ...
```

TruffleHog against that endpoint returns **unverified**, and — decisively — the HTTPS listener
received **no request at all** (the handshake was rejected before any body was sent):

```text
Found unverified result 🐷🔑❓
Raw result: HOGCCCCCCCCCCCCCCCCC
...
finished scanning  {"chunks": 1, "bytes": 50, "verified_secrets": 0, "unverified_secrets": 1, ...}
```

```text
# Full contents of the HTTPS listener log after the scan:
HTTPS listener on 127.0.0.1:18443 (self-signed cert)
[end of listener log]   <-- no "REQUEST" line was ever logged
```

The `http://`-without-`unsafe` configuration is rejected at **load time**:

```text
error parsing the provided configuration file  {"error": "http endpoint must have unsafe=true"}
# process exits non-zero (183/1); no scan occurs
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
if count > maxTotalMatches {        // [custom_detectors.go:L295-L297]
	count = maxTotalMatches
}
```

The results channel is buffered to the same bound `[pkg/custom_detectors/custom_detectors.go:L115]`.
Dispatch, however, is where the amplification lives. An `errgroup.Group` is created with **no
concurrency limit** — there is no `g.SetLimit(...)` call anywhere
`[pkg/custom_detectors/custom_detectors.go:L112]` — and one goroutine is launched per surviving match:

```go
g := new(errgroup.Group)            // [custom_detectors.go:L112]  (no SetLimit)
...
g.Go(func() error {                 // [custom_detectors.go:L155-L157]  one per match
	return c.createResults(ctx, match, verify, resultsCh)
})
```

Each `createResults` call then issues **one POST per configured verify endpoint per match**: it
loops over `c.GetVerify()` `[pkg/custom_detectors/custom_detectors.go:L223]`, builds a request
`[:L228]`, and on the first HTTP 200 sets `result.Verified = true` `[:L251]` and `break`s `[:L268]`.
So the outbound request count for one qualifying chunk is approximately
**min(matches, 100) × N endpoints**, dispatched concurrently with no ceiling.

**(c) Reproducible commands.**

A single fixture (`target_multi.txt`) with three matching tokens in one chunk, and a verify endpoint
that returns HTTP 200:

```text
hog tokens for amplification test
HOGAAAAAAAAAAAAAAAAA
HOGBBBBBBBBBBBBBBBBB
HOGCCCCCCCCCCCCCCCCC
```

```bash
python3 listener_http.py 18099          # threaded; logs each request with a microsecond timestamp
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_multi.txt \
  --config=/tmp/th_harness/config_q3_multi.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

TruffleHog reports three verified secrets from the one chunk:

```text
finished scanning  {"chunks": 1, "bytes": 97, "verified_secrets": 3, "unverified_secrets": 0, "scan_duration": "7.025478ms", ...}
```

The threaded listener received **three** separate `POST /verify` requests with near-simultaneous
microsecond timestamps, and its per-thread log lines are **interleaved** — direct evidence of
concurrent dispatch:

```text
==== REQUEST @ 21:32:50.097056 ====
==== REQUEST @ 21:32:50.097443 ====
==== REQUEST @ 21:32:50.097788 ====
...
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
BODY: {"HogTokenDetector":{"hogID":["HOGBBBBBBBBBBBBBBBBB"]}}
BODY: {"HogTokenDetector":{"hogID":["HOGAAAAAAAAAAAAAAAAA"]}}
# POST count: 3 ; timestamp span ~ 0.73 ms
```

**(e) Reasoning.**

Three matches produced three POSTs, confirming the relationship is one outbound request per match
(per endpoint), not a single per-detector call. The match count is bounded — `maxTotalMatches = 100`
caps permutations `[pkg/custom_detectors/custom_detectors.go:L23,L295-L297]` and the results channel
is sized to match `[:L115]` — but the *concurrency* of those requests is **not** bounded, because the
`errgroup` is created without `SetLimit` `[:L112]`. The ~0.73 ms spread across three requests and the
interleaved listener output show the requests fire effectively in parallel. Scaling this up: a single
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
	req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))   // [custom_detectors.go:L232-L239]
}
```

Finally, `CustomTransport.RoundTrip` adds a `User-Agent: TruffleHog` header
`[pkg/common/http.go:L99-L102]` (the value from `UserAgent()` `[pkg/common/http.go:L96-L97]`). The
documented body shape and the "respond 200 ⇒ verified" contract match the sample verification
servers in `pkg/custom_detectors/CUSTOM_DETECTORS.md` `[pkg/custom_detectors/CUSTOM_DETECTORS.md:L100-L209]`.

**(c) Reproducible commands.**

Add two operator headers to the verify block (placeholder values shown — never put a real secret in a
config you don't fully control), and capture what arrives:

```yaml
    verify:
      - endpoint: http://127.0.0.1:18099/verify
        unsafe: true
        headers:
          - "Authorization: Bearer demo-not-a-real-secret-PLACEHOLDER"
          - "X-Custom-Token: static-token-PLACEHOLDER-value"
```

```bash
python3 listener_http.py 18099
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_single.txt \
  --config=/tmp/th_harness/config_q4_headers.yaml --custom-verifiers-only --no-update
```

**(d) Captured runtime output.**

The listener captured the full request — method, path, the `User-Agent: TruffleHog` header, **both
operator headers verbatim**, and a body containing the **candidate secret value**:

```text
==== REQUEST @ 21:31:25.408326 ====
REQUEST-LINE: POST /verify HTTP/1.1
HEADER: Host: 127.0.0.1:18099
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 55
HEADER: Authorization: Bearer demo-not-a-real-secret-PLACEHOLDER
HEADER: X-Custom-Token: static-token-PLACEHOLDER-value
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"hogID":["HOGCCCCCCCCCCCCCCCCC"]}}
==== END @ 21:31:25.408326 ====
```

```text
✅ Found verified result 🐷🔑
...
finished scanning  {"chunks": 1, "bytes": 50, "verified_secrets": 1, "unverified_secrets": 0, ...}
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
	if _, err := regexp.Compile(reg); err != nil {        // [validation.go:L28]
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

Two further bounds apply. Input size is bounded by the chunker
`[pkg/sources/chunker.go:L13-L18]` — `ChunkSize = 10 * 1024`, `PeekSize = 3 * 1024`,
`TotalChunkSize = ChunkSize + PeekSize` — so each regex execution sees a bounded slice. There is also
a per-detector timeout, but it is **observational only**: `detectionTimeout` defaults to
`detectors.DefaultResponseTimeout` `[pkg/engine/engine.go:L37]` (`10 * time.Second`
`[pkg/detectors/http.go:L18]`, overridable via `SetDetectorTimeout` `[pkg/engine/engine.go:L331]`),
and each detector call is wrapped in `context.WithTimeout` `[pkg/engine/engine.go:L1066]` with a
`time.AfterFunc` watchdog that merely **logs** when the deadline passes:

```go
ctx, cancel := context.WithTimeout(ctx, detectionTimeout)             // [engine.go:L1066]
t := time.AfterFunc(detectionTimeout+1*time.Second, func() {
	ctx.Logger().Error(nil, "a detector ignored the context timeout")  // [engine.go:L1067-L1068]
})
```

Go's `regexp` does not honor context cancellation, so this watchdog cannot *interrupt* a running
match — it only records that one outran the deadline. RE2's linear-time guarantee, not the timeout, is
the real safeguard.

**(c) Reproducible commands.**

A pathological nested-quantifier pattern (`(a+)+$`) against the classic catastrophic-backtracking
input (a long run of `a` followed by a non-matching character):

```yaml
detectors:
  - name: RedosDetector
    keywords: [hog]
    regex:
      redos: '(a+)+$'
```

```bash
# adversarial fixture: 'hog\n' + ('a' * 10000) + '!'
/tmp/th_harness/trufflehog filesystem /tmp/th_harness/target_redos.txt \
  --config=/tmp/th_harness/config_q5_redos.yaml --custom-verifiers-only --no-update
```

For contrast, the *same* pattern in a backtracking engine (Python `re`) versus Go's RE2:

```bash
# Python (backtracking): each n capped at 5 seconds with `timeout`
for n in 20 24 28; do timeout 5 python3 -c "import re; re.compile(r'(a+)+\$').search('a'*$n+'!')"; done
# Go RE2 (stdlib regexp): same pattern, n up to 100000
```

**(d) Captured runtime output.**

TruffleHog (Go RE2) scanned the 10,000-`a` adversarial input in **single-digit milliseconds** with no
CPU blow-up:

```text
finished scanning  {"chunks": 1, "bytes": 10006, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.648572ms", ...}
```

The contrast is decisive. A backtracking engine (Python `re`) on the same pattern explodes
exponentially, while Go's RE2 stays linear even at 100,000 characters:

```text
# Python re (backtracking):
  n=20  ->  0.0903 s
  n=24  ->  1.3067 s
  n=28  ->  TIMED OUT (>5.000 s, catastrophic backtracking)

# Go RE2 (stdlib regexp — TruffleHog's engine):
  n=    20  ->  34.988µs
  n=  1000  ->  79.358µs
  n= 10000  ->  1.098283ms
  n=100000  ->  4.666914ms
```

**(e) Reasoning.**

The same pattern (`(a+)+$`) that drives a backtracking engine to a timeout at n = 28 is handled by
TruffleHog in ~4.6 ms at n = 10,000, and the standalone RE2 measurements grow linearly (20 → 100,000
characters scales roughly with input length, not exponentially). This is the empirical signature of
RE2's linear-time guarantee `[pkg/custom_detectors/custom_detectors.go:L9]`. Compile-time validation
`[pkg/custom_detectors/validation.go:L23-L33]` plus the bounded chunk size
`[pkg/sources/chunker.go:L13-L18]` further constrain cost. The per-detector timeout
`[pkg/engine/engine.go:L1066-L1068]` is a logging watchdog rather than a hard kill, but with RE2 it is
not needed to prevent ReDoS — the engine choice already does that.

**(f) Verdict.** **Catastrophic-backtracking ReDoS is not feasible.** Custom patterns run on RE2
(linear time); the detector timeout is observational only, but RE2 plus the bounded chunk size keep
regex execution cost bounded regardless.

---

## Section 3 — Consolidated Threat-Model Verdict

**Answering the operator's overarching question** — *"whether someone with control over a detector
configuration could abuse the verification system in ways we haven't anticipated"* — the answer is
**yes, in specific and significant ways.** If detector YAML is untrusted, then the `endpoint`,
`headers`, and `regex` fields are attacker-influenced, and the verification subsystem will act on
them with the scanner's identity and network position.

| # | Exposure | Status | One-line basis |
|---|----------|--------|----------------|
| Q1 | **SSRF** (internal / metadata destinations) | **REAL — confirmed** | No destination validation; raw endpoint POSTed; redirects followed `[validation.go:L35-L44]`, `[custom_detectors.go:L228]`, `[common/http.go:L211-L228]` |
| Q2 | **TLS interception / MITM** | **MITIGATED** (fails closed) | Default Go TLS; no `InsecureSkipVerify`; untrusted cert → no request sent `[common/http.go:L211-L228]` |
| Q3 | **Request amplification / fan-out** | **REAL — partially bounded** | Per-match verification; 100-match cap but **no concurrency limit** `[custom_detectors.go:L23,L112,L155-L157]` |
| Q4 | **Sensitive-data egress** | **REAL — by design** | Candidate secret + operator headers POSTed verbatim to the named endpoint `[custom_detectors.go:L214-L216,L232-L239]` |
| Q5 | **ReDoS** (catastrophic backtracking) | **MITIGATED** (structurally) | RE2 linear-time engine; backtracking `regexp2` unused on this path `[custom_detectors.go:L9]`, `[go.mod:L187]` |

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

### 5.2 Harness (created outside the repo, then deleted)

All scaffolding lived under `/tmp/th_harness/` and was removed after evidence capture:

- a **threaded HTTP listener** (`listener_http.py`, Python stdlib `http.server.ThreadingHTTPServer`)
  that logs each request's method, path, headers, and body with a microsecond timestamp and returns
  HTTP 200;
- a **threaded HTTPS listener** (`listener_https.py`) wrapping the socket with `ssl` and serving a
  **self-signed** certificate generated with
  `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost"`;
- per-question **YAML configurations** and **target fixtures** (single-token, three-token, and the
  `(a+)+$` adversarial input);
- a throwaway Go file used only for the RE2 vs. backtracking timing comparison.

The `HogTokenDetector` configuration shape (detector `name`, `keywords: [hog]`, a named `regex`
group, and a `verify.endpoint`) is modeled on the official example in
`pkg/custom_detectors/CUSTOM_DETECTORS.md` `[pkg/custom_detectors/CUSTOM_DETECTORS.md:L17-L31]`. Any
credential-looking values placed in `headers` during the Q4 demonstration were obvious non-secret
placeholders.

### 5.3 Integrity verification

- **No source modification.** `git status --porcelain` was verified clean before, during, and after
  the investigation; `go.mod` and `go.sum` are unchanged (the build used `-mod=readonly`).
- **No extra code added to the repository.** The only persisted artifact is this document,
  `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- **Scaffolding deleted.** The entire `/tmp/th_harness/` directory (binary, listeners,
  certificate/key, configs, fixtures) and all listener processes were removed/stopped after capture.
- **Pinned context.** Commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760`; Go `go1.24.2`.

### 5.4 Reproducibility note

Each question above includes the exact configuration, the exact `trufflehog filesystem … --config=…
--custom-verifiers-only` command, and the verbatim captured output (listener request logs and the
`"finished scanning"` counters `[main.go:L566-L574]`). An operator can recreate the harness from the
descriptions in 5.1–5.2 and re-run every demonstration to independently confirm these findings.











