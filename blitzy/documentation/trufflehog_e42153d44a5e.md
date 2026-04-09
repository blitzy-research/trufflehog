# TruffleHog Custom Detector Verification: Security Analysis

| Field          | Value                                                                     |
|----------------|---------------------------------------------------------------------------|
| **Date**       | 2026-04-09                                                                |
| **Scope**      | Branch reference `e42153d44a5e`; TruffleHog open-source codebase (Go 1.23.1, toolchain go1.24.2) |
| **Audience**   | Security engineers, platform teams, and operators evaluating TruffleHog deployment for multi-team environments with custom detector contributions |
| **Methodology**| Static code analysis — all findings are derived from source code inspection, not runtime testing |

---

## Introduction

This document provides an evidence-based security analysis of TruffleHog's **custom detector verification system**. It is intended for organizations evaluating the safety of deploying TruffleHog in environments where multiple teams contribute custom detector YAML configurations that include webhook verification endpoints.

Custom detectors allow operators to define regex-based secret patterns and optional webhook endpoints for verification. When verification is enabled, TruffleHog sends HTTP POST requests to the configured endpoints containing matched secret data. The security properties of this verification pipeline — including network boundary enforcement, TLS behavior, request volume, and payload content — are critical to understand before deployment.

**Baseline context:** The existing custom detector documentation at `pkg/custom_detectors/CUSTOM_DETECTORS.md` covers YAML configuration syntax and verification server examples but does not address security boundaries. This analysis fills that gap.

### Questions Answered

This document answers six specific security questions:

1. **SSRF / Network Boundary Controls** — What validation prevents verification requests from targeting private, loopback, link-local, and cloud metadata addresses?
2. **TLS Certificate Validation** — Does the HTTP client enforce certificate chain verification for HTTPS verification endpoints?
3. **Multi-Match Verification Behavior** — When multiple regex matches occur in a single chunk, how many verification requests are sent, and what bounds exist?
4. **Verification Request Payload** — What data is included in the HTTP POST body sent to the verification endpoint?
5. **Regex Safety (ReDoS)** — What safeguards exist against Regular Expression Denial of Service from malicious custom detector patterns?
6. **Abuse Surface Summary** — Can a malicious actor with control over a detector YAML configuration abuse the verification system?

---

## 1. SSRF / Network Boundary Analysis

**Question:** When a custom detector specifies a webhook verification endpoint URL, what validation prevents Server-Side Request Forgery (SSRF) — specifically requests to RFC 1918 private addresses, loopback addresses, link-local addresses (including cloud metadata at `169.254.169.254`), and other non-routable addresses?

### 1.1 Built-in Detector SSRF Protections

TruffleHog's **built-in detectors** use an HTTP client with explicit SSRF protections. This serves as the reference for what protections exist in the codebase and what the custom detector path is missing.

**Evidence:** The built-in detector HTTP client is initialized at `pkg/detectors/http.go:33-38`:

```go
DetectorHttpClientWithNoLocalAddresses = NewDetectorHttpClient(
    WithTransport(NewDetectorTransport(nil)),
    WithTimeout(DefaultResponseTimeout),
    WithNoFollowRedirects(),
    WithNoLocalIP(),
)
```

The `isLocalIP` function at `pkg/detectors/http.go:96-102` defines what constitutes a "local" IP:

```go
func isLocalIP(ip net.IP) bool {
    if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
        return true
    }
    return false
}
```

**Analysis:** This function blocks:
- **Loopback addresses:** `127.0.0.0/8`, `::1` (via `ip.IsLoopback()`)
- **Link-local unicast:** `169.254.0.0/16`, `fe80::/10` (via `ip.IsLinkLocalUnicast()`) — this includes the AWS/GCP/Azure cloud metadata endpoint at `169.254.169.254`
- **Link-local multicast:** `224.0.0.0/24`, `ff02::/16` (via `ip.IsLinkLocalMulticast()`)
- **Private addresses:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (via `ip.IsPrivate()`)

The `WithNoLocalIP()` function at `pkg/detectors/http.go:106-151` wraps the transport's `DialContext` to perform DNS resolution **before** connecting, then checks all resolved IPs against `isLocalIP()`. This prevents DNS rebinding bypasses where a hostname resolves to a local address.

**Test confirmation:** Unit tests at `pkg/detectors/http_test.go:74-93` confirm that `127.0.0.1` (loopback), `::1` (IPv6 loopback), `192.168.1.1` (private), and `fd00::1` (private IPv6) are all correctly identified as local, while `8.8.8.8` and `2001:4860:4860::8888` are allowed.

### 1.2 Custom Detector HTTP Client

**Evidence:** The custom detector HTTP client is initialized at `pkg/custom_detectors/custom_detectors.go:62`:

```go
var httpClient = common.SaneHttpClient()
```

The `SaneHttpClient()` function is defined at `pkg/common/http.go:223-228`:

```go
func SaneHttpClient() *http.Client {
    httpClient := &http.Client{}
    httpClient.Timeout = DefaultResponseTimeout
    httpClient.Transport = NewCustomTransport(saneTransport)
    return httpClient
}
```

The `saneTransport` at `pkg/common/http.go:211-221` is a plain `*http.Transport`:

```go
var saneTransport = &http.Transport{
    Proxy: http.ProxyFromEnvironment,
    DialContext: (&net.Dialer{
        Timeout:   2 * time.Second,
        KeepAlive: 5 * time.Second,
    }).DialContext,
    MaxIdleConns:          5,
    IdleConnTimeout:       5 * time.Second,
    TLSHandshakeTimeout:   3 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
}
```

`NewCustomTransport` at `pkg/common/http.go:104-109` simply wraps the transport to add a User-Agent header — it adds no security filtering.

### 1.3 Finding: No Local IP Blocking for Custom Detectors

**Finding:** The custom detector HTTP client (`SaneHttpClient()`) does **not** use `WithNoLocalIP()`. The `saneTransport` uses a standard `net.Dialer` with no IP-level filtering. There is no dial guard that checks resolved IP addresses against `isLocalIP()`.

**Security implication:** A custom detector YAML configuration can specify a verification endpoint targeting any IP address, including:
- `https://127.0.0.1:8080/api/internal` (loopback)
- `https://10.0.0.5:9200/` (private network / Elasticsearch)
- `https://169.254.169.254/latest/meta-data/` (cloud metadata)
- `https://192.168.1.1/admin` (private network)

All of these will be connected to by the custom detector HTTP client without restriction.

### 1.4 Finding: Custom Detectors Follow Redirects

**Evidence:** The built-in detector client uses `WithNoFollowRedirects()` at `pkg/detectors/http.go:59-64`:

```go
func WithNoFollowRedirects() ClientOption {
    return func(c *http.Client) {
        c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        }
    }
}
```

The `SaneHttpClient()` at `pkg/common/http.go:223-228` does **not** set `CheckRedirect`. In Go's `net/http` package, the default behavior is to follow up to 10 redirects automatically.

**Security implication:** Even if a custom detector endpoint URL initially points to an external host, a redirect response (HTTP 301/302/307/308) could redirect the request to a local or private address. Since there is no local IP check on the redirect target either (no custom `DialContext`), redirect-based SSRF is possible. For example, an attacker-controlled external server could respond with a redirect to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

### 1.5 Finding: Cloud Metadata Endpoint Exposure

**Finding:** The cloud metadata endpoint at `169.254.169.254` is a link-local unicast address. The built-in detector client blocks it via `isLocalIP()` → `ip.IsLinkLocalUnicast()`. The custom detector client has no such protection.

**Security implication:** In cloud environments (AWS, GCP, Azure), the instance metadata service at `169.254.169.254` exposes sensitive information including IAM credentials, API tokens, and instance configuration. A malicious custom detector configuration could target this endpoint directly or via redirect.

### 1.6 Endpoint Validation Scope

**Evidence:** The endpoint validation function at `pkg/custom_detectors/validation.go:35-43`:

```go
func ValidateVerifyEndpoint(endpoint string, unsafe bool) error {
    if len(endpoint) == 0 {
        return fmt.Errorf("no endpoint")
    }
    if strings.HasPrefix(endpoint, "http://") && !unsafe {
        return fmt.Errorf("http endpoint must have unsafe=true")
    }
    return nil
}
```

**Analysis:** This function performs **only** two checks:
1. The endpoint is not empty.
2. If the endpoint uses `http://` (not HTTPS), the `unsafe` flag must be `true`.

There is **no** URL parsing, **no** hostname validation, **no** IP address filtering. An endpoint of `https://169.254.169.254/latest/meta-data/` passes validation without any flags set.

**Contrast with built-in detector overrides:** The `ParseVerifierEndpoints` function at `pkg/config/detectors.go:97-117` enforces that built-in detector endpoint overrides must use HTTPS and performs actual URL parsing. Custom detector endpoint validation is significantly weaker.

### 1.7 Comparison: Built-in vs. Custom Detector HTTP Clients

| Property                        | Built-in Detector Client                                      | Custom Detector Client                     |
|---------------------------------|---------------------------------------------------------------|--------------------------------------------|
| **Client constructor**          | `NewDetectorHttpClient()` (`pkg/detectors/http.go:167-177`)  | `SaneHttpClient()` (`pkg/common/http.go:223-228`) |
| **Local IP blocking (SSRF)**    | ✅ `WithNoLocalIP()` — dial guard checks all resolved IPs     | ❌ None — standard `net.Dialer`            |
| **Redirect suppression**        | ✅ `WithNoFollowRedirects()` — returns last response          | ❌ None — follows up to 10 redirects (Go default) |
| **Timeout**                     | 10 seconds (`DefaultResponseTimeout` at `pkg/detectors/http.go:18`) | 5 seconds (`DefaultResponseTimeout` at `pkg/common/http.go:209`) |
| **User-Agent header**           | `"TruffleHog"` via `detectorTransport`                        | `"TruffleHog"` via `CustomTransport`       |
| **DNS rebinding protection**    | ✅ IP check occurs after DNS resolution, before connection     | ❌ None                                    |
| **Cloud metadata protection**   | ✅ `169.254.x.x` blocked by `IsLinkLocalUnicast()`            | ❌ None — directly reachable               |
| **Endpoint scheme enforcement** | HTTPS required (`pkg/config/detectors.go:110-111`)            | HTTP allowed with `unsafe: true` flag      |

---

## 2. TLS Certificate Validation Analysis

**Question:** When verification HTTP requests are made over HTTPS, does the HTTP client enforce certificate chain verification, or could a man-in-the-middle attacker intercept verification traffic?

### 2.1 Transport Configuration

**Evidence:** The `saneTransport` used by the custom detector HTTP client is defined at `pkg/common/http.go:211-221`:

```go
var saneTransport = &http.Transport{
    Proxy: http.ProxyFromEnvironment,
    DialContext: (&net.Dialer{
        Timeout:   2 * time.Second,
        KeepAlive: 5 * time.Second,
    }).DialContext,
    MaxIdleConns:          5,
    IdleConnTimeout:       5 * time.Second,
    TLSHandshakeTimeout:   3 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
}
```

**Analysis:** The `TLSClientConfig` field is **not set** on this transport. In Go's `net/http` package, when `TLSClientConfig` is `nil`, the transport uses Go's default TLS configuration, which:
- Uses the system's CA certificate pool for certificate chain verification
- Sets `InsecureSkipVerify` to `false` (the default)
- Enforces certificate hostname matching

### 2.2 Finding: System CA Verification is Enforced

**Finding:** The custom detector HTTP client enforces TLS certificate chain verification using the system's CA certificate pool. Certificate validation is **not** bypassed.

**Security implication:** A man-in-the-middle attacker on the network path cannot intercept HTTPS verification traffic without presenting a certificate signed by a CA trusted by the system's certificate store. This is the correct, secure default behavior.

### 2.3 PinnedCertPool vs. System Defaults

**Evidence:** A `PinnedCertPool()` function exists at `pkg/common/http.go:72-78` that creates a certificate pool containing ISRG Root X1 and X2 (Let's Encrypt) certificates. This pinned pool is used by `PinnedRetryableHttpClient()` at `pkg/common/http.go:159-178`:

```go
func PinnedRetryableHttpClient() *http.Client {
    httpClient := retryablehttp.NewClient()
    httpClient.HTTPClient.Transport = NewCustomTransport(&http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: PinnedCertPool(),
        },
        // ... other settings
    })
    return httpClient.StandardClient()
}
```

**Finding:** The `PinnedRetryableHttpClient` is **not** used by the custom detector verification path. Custom detectors use `SaneHttpClient()`, which trusts the full system CA pool rather than a pinned subset. This means custom detector verification requests trust any CA in the system store, not just Let's Encrypt.

### 2.4 WithInsecureTLS Availability

**Evidence:** The `WithInsecureTLS()` option exists at `pkg/roundtripper/roundtripper.go:122-129`:

```go
func WithInsecureTLS() func(*RoundTripper) {
    return func(r *RoundTripper) {
        r.original = common.NewCustomTransport(&http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        })
    }
}
```

**Finding:** This option exists in the codebase but is **not** applied to the custom detector HTTP client path. There is no mechanism in the custom detector configuration schema (see `proto/custom_detectors.proto:26-31`) that would allow a YAML configuration to disable TLS verification.

**Conclusion:** TLS certificate validation is enforced by default for custom detector verification requests. MITM attacks against HTTPS verification endpoints are mitigated by Go's standard TLS behavior. The `unsafe` flag in the YAML configuration only controls HTTP vs. HTTPS scheme acceptance — it does **not** disable certificate verification.

---

## 3. Multi-Match Verification Behavior

**Question:** When a custom detector regex produces multiple matches within a single scanned chunk, does TruffleHog send one verification request or multiple? What is the combinatorial behavior, and is there an upper bound?

### 3.1 Match Permutation Algorithm

**Evidence:** The `permutateMatches` function at `pkg/custom_detectors/custom_detectors.go:317-343` converts all regex match groups into a Cartesian product of permutations. For example, if a detector defines two regex patterns — `"foo"` matching `[matchA, matchB]` and `"bar"` matching `[matchC]` — the permutations are:

```
[{"foo": matchA, "bar": matchC}, {"foo": matchB, "bar": matchC}]
```

The Cartesian product is computed by `productIndices` at `pkg/custom_detectors/custom_detectors.go:287-310`:

```go
func productIndices(lengths ...int) [][]int {
    count := 1
    for _, l := range lengths {
        count *= l
    }
    if count == 0 {
        return nil
    }
    if count > maxTotalMatches {
        count = maxTotalMatches
    }
    // ... build index permutations
}
```

### 3.2 Upper Bound: maxTotalMatches = 100

**Evidence:** The constant at `pkg/custom_detectors/custom_detectors.go:23`:

```go
const maxTotalMatches = 100
```

The `productIndices` function caps the total number of permutations at `maxTotalMatches` (lines 295-297). This means regardless of how many regex matches are found in a chunk, at most **100 permutations** are generated.

**Test confirmation:** The test `TestProductIndicesMax` at `pkg/custom_detectors/custom_detectors_test.go:167-171` confirms this behavior:

```go
func TestProductIndicesMax(t *testing.T) {
    got := productIndices(2, 3, 4, 5, 6)
    assert.GreaterOrEqual(t, 2*3*4*5*6, maxTotalMatches)
    assert.Equal(t, maxTotalMatches, len(got))
}
```

This test verifies that even when the true Cartesian product size (`2*3*4*5*6 = 720`) exceeds `maxTotalMatches`, only 100 permutations are returned.

### 3.3 Concurrent Verification Dispatch

**Evidence:** In the `FromData` method at `pkg/custom_detectors/custom_detectors.go:110-161`:

1. Line 110: `matches := permutateMatches(regexMatches)` — generates up to 100 permutations
2. Line 112: `g := new(errgroup.Group)` — creates a concurrency group
3. Line 115: `resultsCh := make(chan detectors.Result, maxTotalMatches)` — buffered channel
4. Lines 155-157: Each permutation match (that passes entropy, exclude word, and exclude regex filters) launches a **concurrent goroutine**:

```go
g.Go(func() error {
    return c.createResults(ctx, match, verify, resultsCh)
})
```

Inside `createResults` at lines 223-270, for each match, TruffleHog iterates over all configured `VerifierConfig` entries and sends an HTTP POST to each endpoint until one succeeds (returns `200 OK`).

### 3.4 Volume Estimation

**Analysis — Worst-case scenario for a single chunk:**

- **Maximum permutations per chunk:** 100 (bounded by `maxTotalMatches`)
- **Verification requests per permutation:** One HTTP POST per `VerifierConfig` entry, iterated until the first `200 OK` response. In the worst case (all endpoints fail), every configured endpoint is tried.
- **Concurrent dispatch:** All 100 permutations are dispatched as concurrent goroutines via `errgroup.Group.Go()`
- **Detection timeout:** Each detector invocation is bounded by `detectionTimeout` = `detectors.DefaultResponseTimeout` = 10 seconds (`pkg/engine/engine.go:37`, `pkg/detectors/http.go:18`). The context wrapping at `pkg/engine/engine.go:1066-1077` ensures all verification for a single chunk is cancelled after 10 seconds.

**System-wide concurrency:**
- Default `detectorWorkerMultiplier = 8` (`pkg/engine/engine.go:343-345`)
- Default `concurrency = runtime.NumCPU()` (`pkg/engine/engine.go:337-340`)
- Total detector workers = `concurrency × detectorWorkerMultiplier`. On an 8-core machine: `8 × 8 = 64` workers (`pkg/engine/engine.go:675-676`)
- Each worker processes chunks independently, so up to 64 chunks could be verified concurrently, each producing up to 100 verification requests.

**There is no per-endpoint rate limiting.** The only bounds are:
1. `maxTotalMatches = 100` per chunk
2. `detectionTimeout` = 10 seconds per chunk
3. `httpClient.Timeout` = 5 seconds per individual HTTP request (`pkg/common/http.go:209`)

### 3.5 Verification Flow Diagram

```mermaid
flowchart TD
    A[Scanned Chunk] --> B[Regex Matching]
    B --> C["regexMatches: map of pattern name → [][]string"]
    C --> D["permutateMatches()"]
    D --> E["productIndices() — capped at maxTotalMatches=100"]
    E --> F["Up to 100 match permutations"]
    F --> G{For each permutation}
    G --> H["Filter: entropy check"]
    H --> I["Filter: exclude words"]
    I --> J["Filter: exclude regexes"]
    J --> K["errgroup.Go() — concurrent goroutine"]
    K --> L["createResults()"]
    L --> M{For each VerifierConfig}
    M --> N["JSON marshal match data"]
    N --> O["HTTP POST to endpoint"]
    O --> P{Response 200 OK?}
    P -->|Yes| Q["Mark result as Verified, break"]
    P -->|No| R["Try next VerifierConfig"]
    R --> M
    Q --> S["Send result to resultsCh"]
```

---

## 4. Verification Request Payload Analysis

**Question:** What data is included in the HTTP POST body sent to the verification webhook endpoint? What information does the endpoint operator receive?

### 4.1 JSON Payload Structure

**Evidence:** The JSON payload is constructed at `pkg/custom_detectors/custom_detectors.go:214-221`:

```go
jsonBody, err := json.Marshal(map[string]map[string][]string{
    c.GetName(): match,
})
```

The `match` variable is of type `map[string][]string`, where:
- Keys are the regex pattern names defined in the YAML `regex:` block
- Values are string slices where index 0 is the full regex match and subsequent indices are capture group matches

The outer map uses the detector name (from the YAML `name:` field) as the key.

**Example payload:** Given a detector YAML configuration:

```yaml
name: "my-api-detector"
regex:
  api_key: "(AKIA[A-Z0-9]{16})"
  secret_key: "([a-zA-Z0-9/+=]{40})"
```

If the regex matches produce `api_key = ["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"]` and `secret_key = ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]`, the POST body would be:

```json
{
  "my-api-detector": {
    "api_key": ["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
    "secret_key": ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
  }
}
```

### 4.2 Data Included

The HTTP request to the verification endpoint includes:

1. **POST body:** JSON object containing the detector name and all regex capture group matches (as described above)
2. **Custom headers:** Any headers configured in the `headers:` field of the `VerifierConfig`. These are added at `pkg/custom_detectors/custom_detectors.go:232-238`:
   ```go
   for _, header := range verifyConfig.GetHeaders() {
       key, value, found := strings.Cut(header, ":")
       if !found {
           continue
       }
       req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))
   }
   ```
3. **User-Agent:** `"TruffleHog"` (or with a suffix if `feature.UserAgentSuffix` is set), added by `CustomTransport.RoundTrip` at `pkg/common/http.go:99-101`
4. **HTTP method:** POST (`pkg/custom_detectors/custom_detectors.go:228`)

### 4.3 Data Excluded

The following data is **not** included in the verification POST body:
- Source metadata (file path, repository URL, commit hash, branch name)
- The raw scanned chunk data (only the regex-matched portions are sent)
- Information about other detectors or other matches
- TruffleHog configuration details

### 4.4 Response Handling

**Evidence:** Response processing at `pkg/custom_detectors/custom_detectors.go:249-266`:

- **Success criteria:** Line 249: `resp.StatusCode == http.StatusOK` — **only** HTTP 200 is treated as a successful verification. This is hardcoded and does **not** use the `successRanges` configuration (see Section 6.2).
- **Response body handling:** Lines 253-263: The response body is read, converted to a string, and truncated to 200 characters:
  ```go
  responseStr := string(body)
  if len(responseStr) > 200 {
      responseStr = responseStr[:200]
  }
  result.ExtraData["response"] = responseStr
  ```
- **Result storage:** The truncated response is stored in `result.ExtraData["response"]` and is available in TruffleHog's output.

---

## 5. Regex Safety (ReDoS) Analysis

**Question:** What safeguards exist against Regular Expression Denial of Service when a custom detector specifies a computationally expensive regex pattern?

### 5.1 Regex Engine Selection

**Evidence:** The custom detector implementation imports Go's standard library `regexp` package at `pkg/custom_detectors/custom_detectors.go:9`:

```go
import "regexp"
```

Regex compilation and matching occur at `pkg/custom_detectors/custom_detectors.go:92-97`:

```go
regex, err := regexp.Compile(regex)
if err != nil {
    return nil, err
}
regexMatches[name] = regex.FindAllStringSubmatch(dataStr, -1)
```

### 5.2 RE2 Linear-Time Guarantees

**Analysis:** Go's standard `regexp` package implements the RE2 algorithm, which guarantees **linear-time** matching with respect to input size. RE2 achieves this by:
- Using a non-backtracking NFA (Nondeterministic Finite Automaton) simulation
- Rejecting features that require backtracking (e.g., backreferences, lookaheads)
- Ensuring that the time complexity is `O(n × m)` where `n` is the input length and `m` is the pattern complexity

**Security implication:** ReDoS attacks exploit backtracking regex engines where specially crafted patterns cause exponential execution time. Since Go's `regexp` uses RE2 semantics, **ReDoS is not a practical risk** for custom detector patterns. A pattern that would cause catastrophic backtracking in PCRE or Java regex engines will either be rejected at compile time (if it uses unsupported features) or execute in linear time.

### 5.3 Compile-Time Validation

**Evidence:** The `ValidateRegex` function at `pkg/custom_detectors/validation.go:23-33`:

```go
func ValidateRegex(regex map[string]string) error {
    if len(regex) == 0 {
        return fmt.Errorf("no regex")
    }
    for name, reg := range regex {
        if _, err := regexp.Compile(reg); err != nil {
            return fmt.Errorf("regex '%s': %w", name, err)
        }
    }
    return nil
}
```

**Analysis:** All regex patterns are compiled at configuration load time (called from `NewWebhookCustomRegex` at `pkg/custom_detectors/custom_detectors.go:45-46`). Invalid patterns are rejected before scanning begins. This ensures that only syntactically valid RE2 patterns are accepted.

### 5.4 Comparison with Built-in Detectors

**Evidence:** Built-in detectors use `github.com/wasilibs/go-re2` (version v1.9.0, from `go.mod`), which is a CGo wrapper around Google's RE2 C++ library. Custom detectors use Go's standard `regexp` package.

**Analysis:** Both engines implement RE2 semantics and provide the same linear-time safety guarantees. The `go-re2` library may offer different performance characteristics (particularly for large inputs or complex patterns) but does not provide fundamentally different safety properties. The choice of standard `regexp` for custom detectors does **not** introduce ReDoS risk.

**Conclusion:** ReDoS is not a practical risk for custom detector regex patterns due to RE2 linear-time guarantees enforced by Go's standard `regexp` package.

---

## 6. Configuration Validation Analysis

This section documents additional findings about configuration validation gaps discovered during the security analysis.

### 6.1 Endpoint Validation Scope

**Evidence:** As documented in Section 1.6, the `ValidateVerifyEndpoint` function at `pkg/custom_detectors/validation.go:35-43` performs only a scheme check (HTTP requires `unsafe: true`; HTTPS is always accepted; no hostname or IP validation).

**Analysis:** The validation does not parse the URL to extract the hostname or IP address. It uses `strings.HasPrefix(endpoint, "http://")` — a string prefix check rather than URL parsing. This means:
- No hostname validation (arbitrary hostnames accepted)
- No IP address filtering (private, loopback, link-local IPs accepted)
- No port validation (any port accepted)
- No path validation (any path accepted)
- The protobuf `validate.rules` annotation (`string.uri_ref = true` at `proto/custom_detectors.proto:27`) provides structural URI validation but does not enforce security properties.

### 6.2 Finding: successRanges Defined But Not Implemented

**Evidence chain:**

1. **Schema definition:** The `VerifierConfig` message at `proto/custom_detectors.proto:30` defines:
   ```protobuf
   repeated string successRanges = 4;
   ```

2. **Validation function exists:** `ValidateVerifyRanges` at `pkg/custom_detectors/validation.go:55-97` validates that the ranges are well-formed HTTP status code ranges (e.g., `"200-250"`, `"288"`).

3. **Validation function is NOT called:** The `NewWebhookCustomRegex` constructor at `pkg/custom_detectors/custom_detectors.go:40-59` calls `ValidateKeywords`, `ValidateRegex`, `ValidateVerifyEndpoint`, and `ValidateVerifyHeaders` — but does **not** call `ValidateVerifyRanges`.

4. **Runtime ignores successRanges:** The verification success check at `pkg/custom_detectors/custom_detectors.go:249` is hardcoded:
   ```go
   if resp.StatusCode == http.StatusOK {
   ```
   The `successRanges` field from the `VerifierConfig` is never referenced in the `createResults` method.

**Finding:** The `successRanges` configuration field can be specified in YAML, is defined in the protobuf schema, and has a validation function — but the validation function is never called, and the field is completely ignored at runtime. Only HTTP 200 is treated as a successful verification, regardless of any `successRanges` configuration.

**Test evidence:** The test at `pkg/custom_detectors/custom_detectors_test.go:13-43` shows a YAML configuration with `successRanges: ["200-250", "288"]` being parsed correctly into the protobuf struct, confirming the field is preserved in the data but never used.

### 6.3 Finding: unsafe Flag Limited Scope

**Evidence:** The `unsafe` field is defined at `proto/custom_detectors.proto:28`:

```protobuf
bool unsafe = 2;
```

Its only effect is in `ValidateVerifyEndpoint` at `pkg/custom_detectors/validation.go:35-43`, where it gates acceptance of `http://` endpoints.

**Finding:** The `unsafe` flag:
- ✅ Controls whether `http://` (non-TLS) endpoints are accepted
- ❌ Does **not** enable or disable SSRF protection (none exists regardless)
- ❌ Does **not** enable or disable TLS certificate verification
- ❌ Does **not** enable or disable redirect following
- ❌ Does **not** enable or disable rate limiting

The name `unsafe` is misleading because it suggests a broader security scope than its actual effect. Setting `unsafe: false` (the default) only ensures HTTPS is required — it does not make the verification process "safe" from SSRF or other network-level attacks.

---

## 7. Abuse Surface Summary

**Question:** Can a malicious or careless actor with control over a detector YAML configuration abuse the verification system as an SSRF proxy, credential exfiltration channel, or denial-of-service vector?

### 7.1 SSRF Proxy Risk — HIGH

A malicious detector YAML configuration can target internal services through the verification endpoint. Based on the evidence in Section 1:

- **No local IP blocking:** The custom detector HTTP client (`SaneHttpClient()` at `pkg/common/http.go:223-228`) does not use `WithNoLocalIP()` (contrast with `pkg/detectors/http.go:33-38`). Private, loopback, and link-local addresses are reachable.
- **No redirect protection:** The client follows up to 10 redirects (Go default), enabling redirect-based SSRF even from initially external endpoints.
- **Cloud metadata exposure:** `169.254.169.254` is reachable, potentially exposing IAM credentials and instance metadata.
- **No URL-level validation:** `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go:35-43`) only checks the URL scheme, not the hostname or IP address.

**Attack vector:** An attacker with write access to the detector YAML configuration can set `verify.endpoint` to target any internal service, cloud metadata endpoint, or private network address. The POST body contains matched regex data, and custom headers can be configured to include authentication tokens.

### 7.2 Credential Exfiltration Risk — MEDIUM

The verification webhook sends matched secret values to the configured endpoint. Based on the evidence in Section 4:

- The POST body (`pkg/custom_detectors/custom_detectors.go:214-221`) contains all regex capture group matches, which are typically the secret values the detector is designed to find.
- Custom headers (`pkg/custom_detectors/custom_detectors.go:232-238`) can be configured to include any header values.
- A malicious actor could configure an endpoint they control to receive all secrets found by the detector.

**Attack vector:** An attacker creates a detector YAML with a broad regex pattern and a verification endpoint pointing to their own server. Every matched secret is automatically exfiltrated via the POST body. The `name` field in the JSON payload also identifies which detector found the secret.

**Mitigating factor:** The attacker must have the ability to configure custom detectors (write access to the YAML configuration). The detector must match data in the scanned sources for any exfiltration to occur.

### 7.3 Denial-of-Service Risk — MEDIUM

Based on the evidence in Section 3:

- **Up to 100 concurrent verification requests per chunk** (`maxTotalMatches = 100` at `pkg/custom_detectors/custom_detectors.go:23`).
- **64 detector workers by default** on an 8-core machine (`detectorWorkerMultiplier = 8` at `pkg/engine/engine.go:343-345`, `numWorkers = concurrency × detectorWorkerMultiplier` at `pkg/engine/engine.go:675-676`).
- **No per-endpoint rate limiting** exists in the codebase.
- **Bounded by detection timeout:** 10-second context timeout per chunk (`pkg/engine/engine.go:37`, `pkg/engine/engine.go:1066-1077`).

**Attack vector:** A malicious detector configuration with a very broad regex (many matches per chunk) could generate substantial request volume against a target endpoint. With multiple workers processing chunks in parallel, the aggregate request rate could be significant.

**Mitigating factors:** The `maxTotalMatches = 100` cap limits per-chunk volume. The 5-second HTTP client timeout (`pkg/common/http.go:209`) and 10-second detection timeout provide outer bounds. The detector must match data in scanned sources.

### 7.4 Security Boundary Diagram

```mermaid
flowchart LR
    subgraph Config_Load_Time["Config Load Time — Validation Present"]
        V1["ValidateKeywords()"]
        V2["ValidateRegex() — compile check"]
        V3["ValidateVerifyEndpoint() — scheme check only"]
        V4["ValidateVerifyHeaders() — colon check"]
    end

    subgraph Config_Load_Time_Unused["Config Load Time — Validation Exists But NOT Called"]
        V5["ValidateVerifyRanges() — never invoked"]
    end

    subgraph Runtime_Missing["Runtime — Protections ABSENT"]
        R1["❌ No SSRF / local IP blocking"]
        R2["❌ No redirect suppression"]
        R3["❌ No per-endpoint rate limiting"]
        R4["❌ No URL hostname/IP validation"]
        R5["❌ successRanges ignored — hardcoded 200 OK"]
    end

    subgraph Runtime_Present["Runtime — Protections Present"]
        R6["✅ TLS certificate verification (Go default)"]
        R7["✅ RE2 regex engine (linear-time)"]
        R8["✅ maxTotalMatches = 100 per chunk"]
        R9["✅ Detection timeout = 10s per chunk"]
        R10["✅ HTTP client timeout = 5s per request"]
    end

    YAML["Detector YAML Config"] --> Config_Load_Time
    Config_Load_Time --> Runtime_Missing
    Config_Load_Time --> Runtime_Present
    YAML -.-> Config_Load_Time_Unused
```

---

## References

### Custom Detector Implementation

| File | Role in Analysis |
|------|------------------|
| `pkg/custom_detectors/custom_detectors.go` | Primary analysis target — HTTP client selection (line 62), verification request construction (lines 184-278), match permutation (lines 287-343), concurrent dispatch (lines 155-157) |
| `pkg/custom_detectors/validation.go` | Endpoint validation (lines 35-43), regex validation (lines 23-33), range validation (lines 55-97, defined but not called) |
| `pkg/custom_detectors/validation_test.go` | Test cases confirming validation accepts `http://localhost:8000/` with `unsafe: true` and rejects without it |
| `pkg/custom_detectors/custom_detectors_test.go` | Test cases for permutation behavior, `maxTotalMatches` bound (line 167-171), YAML parsing with `successRanges` (lines 13-43) |
| `pkg/custom_detectors/regex_varstring.go` | Placeholder variable parsing for verification URL templates |

### HTTP Client Infrastructure

| File | Role in Analysis |
|------|------------------|
| `pkg/detectors/http.go` | Built-in detector SSRF-protected client (lines 33-38), `isLocalIP()` (lines 96-102), `WithNoLocalIP()` dial guard (lines 106-151), `WithNoFollowRedirects()` (lines 59-64) |
| `pkg/detectors/http_test.go` | Tests confirming local IP blocking for `127.0.0.1`, `::1`, `192.168.1.1`, `fd00::1` (lines 74-93) |
| `pkg/common/http.go` | `SaneHttpClient()` used by custom detectors (lines 223-228), `saneTransport` with no SSRF protection (lines 211-221), `PinnedCertPool()` (lines 72-78), `NewCustomTransport()` User-Agent wrapper (lines 104-109) |
| `pkg/roundtripper/roundtripper.go` | `WithInsecureTLS()` option (lines 122-129) — exists but not used by custom detectors |

### Configuration and Schema

| File | Role in Analysis |
|------|------------------|
| `proto/custom_detectors.proto` | `VerifierConfig` schema defining `endpoint`, `unsafe`, `headers`, `successRanges` fields (lines 26-31) |
| `pkg/config/config.go` | YAML → protobuf → `NewWebhookCustomRegex` loading pipeline (lines 27-45) |
| `pkg/config/detectors.go` | `ParseVerifierEndpoints` enforcing HTTPS for built-in detector overrides (lines 97-117) — contrast with custom detector validation |

### Engine Orchestration

| File | Role in Analysis |
|------|------------------|
| `pkg/engine/engine.go` | Detection timeout (line 37), concurrency defaults (lines 336-346), detector worker spawning (lines 675-688), context timeout wrapping (lines 1066-1077) |
| `pkg/feature/feature.go` | Feature flags inventory — no verification-specific flags exist (lines 1-35) |

### Existing Documentation

| File | Role in Analysis |
|------|------------------|
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` | Existing custom detector setup guide — covers configuration syntax, does not address security boundaries |
| `docs/concurrency.md` | Worker pipeline architecture — provides context for understanding verification concurrency |
| `docs/process_flow.md` | End-to-end scanning data flow — documents pipeline stages including verification step |

### Configuration Examples

| File | Role in Analysis |
|------|------------------|
| `examples/generic.yml` | Sample generic API key detector without verification |
| `examples/generic_with_filters.yml` | Advanced detector config with entropy and exclusion filters |

### Project Configuration

| File | Role in Analysis |
|------|------------------|
| `go.mod` | Go version (1.23.1), toolchain (go1.24.2), `go-re2` dependency (v1.9.0) |
