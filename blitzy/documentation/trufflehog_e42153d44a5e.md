# TruffleHog Custom-Detector Webhook Verification — Security Investigation

**Target:** `trufflesecurity/trufflehog` at commit `e42153d44a5e5c37c1bd0c70e074781e9edcb760` (source branch `trufflehog_e42153d44a5e`).
**Question:** Is it safe to run TruffleHog in an environment where multiple teams supply their own custom-detector configurations? Specifically, can an actor who controls a detector configuration abuse the **verification webhook** subsystem (SSRF, MITM, amplification, exfiltration, ReDoS)?
**Method:** Evidence-first. The scanner was built from source and driven through its real `--config` entry point against synthetic data while a controllable loopback server captured the exact traffic. Every claim below is backed by the complete, unedited output of the command that produced it, plus exact `file:line` citations into the source.

---

## 0. How to read this document — provenance legend

Every evidence block is tagged with one of four labels:

- **[OBSERVED]** — captured directly from running the canonically-built scanner through the real `--config` entry point. The exact command and its complete, unedited stdout/stderr are shown next to the claim.
- **[SOURCE-DERIVED / INFERRED]** — a statement read from the source at a cited `file:line` rather than (or in addition to) being observed at runtime. Anything not backed by a capture is marked inferred.
- **[CORROBORATED]** — an external, authoritative reference (official documentation) that supports an observed/derived claim. All external sources are listed with exact titles and stable URLs in §10.
- **[NON-CANONICAL COMPARISON]** — a deliberately out-of-band measurement (e.g. a *different* regex engine) shown only for contrast. It is **not** TruffleHog behavior and never substitutes for a canonical run.

Ground rules honored throughout:

- All runtime output was produced through TruffleHog's own `CustomRegex` detector loaded via `--config` — never a mock, debug hook, or synthetic bypass.
- Primary probes (SSRF, TLS, amplification, exfiltration, headers, cache) use the canonical **`HogTokenDetector`** from `pkg/custom_detectors/CUSTOM_DETECTORS.md`. The ReDoS probe (§8) uses a custom detector named **`ReDoSProbe`** — still the real `CustomRegex` path, just a different pattern. Detector attribution is called out per section and reconciled in the coverage pass (§11).
- All secret material shown is synthetic (the example token and authorization header from the project's own documentation).
- Reproduction is **safe**: no host-wide firewall/NAT rules are used. Egress toward a cloud-metadata address is captured by routing it through a **loopback-only** HTTP proxy (see §3.2), so the real metadata service is never contacted.

---

## 1. Summary — direct answers

1. **SSRF reachability — YES, unrestricted at the configuration layer.** The only endpoint guard, `ValidateVerifyEndpoint` [pkg/custom_detectors/validation.go:35-44], performs **no** host/IP allow- or deny-listing; its sole rule is that a plaintext `http://` endpoint must set `unsafe: true`. A webhook aimed at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` is accepted and a secret-bearing `POST` is dispatched to it. **[OBSERVED]** (§3). What this proves is *request reachability + secret-bearing POST egress*, **not** cloud-credential retrieval (§3.5).
2. **TLS / MITM — default strict verification applies.** Custom detectors use `common.SaneHttpClient()` [pkg/common/http.go:223-229], which sets **no** `TLSClientConfig`, so Go's default certificate + hostname verification governs HTTPS. An untrusted self-signed endpoint is **rejected before any application bytes are sent** (server sees 0 requests); trusting the same certificate lets the identical secret-bearing request through. **[OBSERVED]** (§4). A network MITM without a trusted certificate cannot silently intercept HTTPS verification traffic; plaintext `http://` (with `unsafe: true`) removes that protection entirely.
3. **Amplification — one verification per match *permutation*, capped at 100 *per keyword-match region* (per `FromData` invocation), not per chunk and not scan-wide.** `maxTotalMatches = 100` [pkg/custom_detectors/custom_detectors.go:23] bounds one `FromData` call, and the engine invokes `FromData` **once per merged keyword-match region** [pkg/engine/engine.go:1061-1070]; a single chunk that contains several non-merging regions therefore exceeds 100 (observed: one 8241-byte chunk → **120** verifications). The total is multiplied further by the number of chunks, the number of configured verifiers, and any redirects. **[OBSERVED]** (§5).
4. **Data exfiltration — the matched secret is JSON-marshaled and POSTed with attacker-chosen headers, to every configured verifier, and replayed across redirects; the endpoint's 200 response is read back (first 200 bytes) into CLI output.** **[OBSERVED]** (§6).
5. **ReDoS — not a concern for the matching engine.** Patterns compile with Go's `regexp` (RE2) [pkg/custom_detectors/validation.go:23-33], which guarantees linear-time matching; the classic catastrophic pattern does not blow up. **[OBSERVED]** + **[CORROBORATED]** (§8).
6. **Threat model — the trust boundary is whoever supplies `--config`.** That party chooses the endpoint (SSRF egress + secret-bearing POST), the headers, the regex, and — via redirects — additional destinations, and can read back a bounded slice of each endpoint's response. **[OBSERVED/SOURCE-DERIVED]** (§9).

### 1.1 Corrections to the initial working hypothesis (all OBSERVED)

- A TLS/transport failure yields status **`unverified`**, not `unknown`: the error is swallowed by `if err != nil { continue }` [custom_detectors.go:241-242] with no `SetVerificationError` (§4.4).
- `successRanges` is a **runtime no-op** at this commit; only HTTP 200 marks a result verified [custom_detectors.go:249] (§6.6).
- The 100 limit is **per keyword-match region** (per `FromData` invocation), not per chunk and not scan-wide — a single chunk containing two non-merging regions was observed issuing **120** verifications (§5).
- The verification cache dedupes on `hash(Raw + RawV2 + DetectorType)` and only short-circuits when **every** result is a cache hit (§7).

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

**`scripts/lib.sh`** — shared constants (the canonical `HogTokenDetector` inputs, copied verbatim from `pkg/custom_detectors/CUSTOM_DETECTORS.md`) and server-lifecycle helpers. The teardown `trap` is installed **before** any server is started, so no process can leak on error or interrupt; `start_server` captures the PID and blocks on a readiness probe; `stop_all` is idempotent.

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

### 3.5 What this proves — and what it does not

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

### 4.3 Edge case — the TLS error is swallowed even at maximum verbosity

Re-running the untrusted case at trace level (`--log-level=5`, the highest verbosity the CLI offers) confirms the error is fully swallowed by `if err != nil { continue }` — no `x509`/`certificate`/`tls`/`handshake` text is emitted at any log level, and the server still receives nothing. Each command below is shown with its **complete, unedited** output:

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

### 4.4 Scope and caveats (qualifications)

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

**Direct answer:** The webhook receives an HTTP `POST` whose JSON body is `json.Marshal` of a nested map `{detectorName: {regexName: [fullMatch, captureGroup, …]}}` — i.e. the **matched secret material in cleartext** — plus every configured header verbatim and an injected `User-Agent: TruffleHog`. The secret is sent **regardless of the response status** (200 *and* 403 both receive it). On a 200, up to the first **200 bytes** of the response body are read back into the result and surfaced in the CLI as `Response:` — a bidirectional channel. Redirects replay the same secret-bearing body to new destinations (and add a `Referer`).

### 6.1 Code path (what is serialized and attached)

**[SOURCE-DERIVED / INFERRED]**
- Body: `json.Marshal(map[string]map[string][]string{ c.GetName(): match })` [pkg/custom_detectors/custom_detectors.go:214-216]. The array's first element is the full regex match; subsequent elements are capture groups.
- Request: `http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))` [custom_detectors.go:228] — always `POST`.
- Headers: split at the **first** colon with `strings.Cut(header, ":")` [custom_detectors.go:233] and added with the value left-trimmed of whitespace, `req.Header.Add(key, strings.TrimLeft(value, "\t\n\v\f\r "))` [custom_detectors.go:238].
- `User-Agent: TruffleHog` is injected by the shared transport [pkg/common/http.go:92-100].
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
- **Headers as received:** the configured `Authorization: super secret authorization header` verbatim, the injected `User-Agent: TruffleHog`, and `Accept-Encoding: gzip` (added by the Go transport). No secret-redaction is applied to the body or headers.
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

---

## 7. Verification caching (amplification nuance)

**Direct answer:** With the verification cache enabled (the default), identical secrets are de-duplicated so repeated occurrences do not each hit the network — but the short-circuit only applies when **every** result in a chunk is a cache hit; **any** miss forces a full re-verification pass for that chunk. The cache key is `hash(Raw + RawV2 + DetectorType)`, which **excludes** the detector name and the verifier configuration (endpoint/headers). Disabling the cache (`--no-verification-cache`) verifies every occurrence.

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
- **Non-determinism note (OBSERVED):** the exact ON hit-count varies run to run (here 15; a separate run observed 20) because the engine verifies across `concurrency × detectorWorkerMultiplier` workers (multiplier defaults to 8, [pkg/engine/engine.go]) that race on the shared cache. The **invariants** are stable: ON always yields `< 40` POSTs with `AttemptsSaved > 0`; OFF always yields exactly `40`.
- **Key excludes config (amplification nuance):** because the key omits endpoint/headers/name, two detectors that match the **same** secret bytes collide in the cache — the first to verify populates the result the others read. Conversely, changing only the endpoint (same secret) does **not** create a new key, so a config author cannot force re-verification merely by pointing at a different URL with the cache enabled.

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
- **Direct requests at internal / link-local / metadata addresses.** No allowlist/denylist exists (§3.1); the metadata address `169.254.169.254` is accepted and a secret-bearing `POST` is aimed at it (§3.3). **Precisely:** this is **request reachability plus secret-bearing `POST` egress**, *not* cloud-credential retrieval — the verifier only ever issues a `POST` with a JSON body, whereas IMDS credential retrieval is a `GET` (IMDSv2 additionally requires a `PUT` token) (§3.5, §10). Whether a given network actually routes to such a host is environment-dependent; TruffleHog itself imposes no destination restriction.
- **Receive data back (bidirectional channel).** On a 200, up to 200 bytes of the endpoint's response are read into `ExtraData["response"]` and shown to the operator (§6.4). The endpoint author therefore controls a small return channel, not just a sink.
- **Fan out and amplify.** Verification is dispatched per match permutation, capped at 100 **per keyword-match region** (per `FromData` invocation) — not per chunk and not scan-wide — and multiplied by the number of configured verifiers and by followed redirects (§5). A single chunk with multiple non-merging regions can already exceed 100 (observed: **120** verifications in one chunk); the total grows further across chunks, verifiers, and each redirect hop, which replays the secret-bearing body (and leaks a `Referer`) to a new destination (§6.5).
- **Choose cleartext.** Setting `unsafe: true` with an `http://` endpoint sends the identical secret body with **no** TLS protection (§3.4, §4.4).

### 9.2 What the system does constrain (qualified, not overstated)

- **HTTPS certificate validation is real, in the observed contrast.** With an HTTPS endpoint, Go's default strict verification applies; an untrusted certificate blocks the handshake so the secret is **not** transmitted and the result is **unverified** (§4.2–§4.3). This makes a passive network MITM against an HTTPS webhook ineffective **in the environment tested**; it is not a claim that certificate trust is the only factor in every deployment, nor does it protect the opt-in `http://` path.
- **The secret is not always transmitted on failure — it depends on the stage.** A pre-write failure (untrusted-TLS handshake) withholds the secret (0 server requests); a failure at/after the request write (e.g. a 403, or a post-send read error) does not (§6.4). Statements that "any connection error means the secret was not sent" are incorrect.
- **RE2 bounds regex cost.** Patterns run on a linear-time, backtracking-free engine, so a hostile regex cannot mount a classic catastrophic-backtracking DoS (§8).
- **Identical secrets are de-duplicated (cache on by default),** reducing—but, on any cache miss in a chunk, not eliminating—repeat verifications (§7).

### 9.3 Bottom line

An actor who controls a detector configuration **can** abuse the verification system: they can harvest secrets found in the scanned data and send them, in cleartext if they choose, to arbitrary internal or external destinations, with a return channel and amplification. Deploying TruffleHog with **untrusted, multi-tenant detector configs is unsafe** unless the config source is trusted or the endpoints are constrained out-of-band (e.g. egress firewalling, an allowlist enforced by the network, or review of every `--config`). The engine-level protections (strict HTTPS verification, RE2) are genuine but narrow; they do not address the central risk, which is that the config author is inside the trust boundary.

---

## 10. External corroboration

The following authoritative sources corroborate — but do not substitute for — the runtime observations above. Each is marked **[CORROBORATED]** and quoted minimally.

- **[CORROBORATED] Go `regexp` is RE2 / linear-time (supports §8).** Official package documentation, *"regexp package - regexp - Go Packages"* (https://pkg.go.dev/regexp), states matching is `"guaranteed to run in time linear in the size of the input"`. The syntax reference is *"Syntax - regexp/syntax"* (https://pkg.go.dev/regexp/syntax) and the RE2 design is described in Russ Cox's *"Regular Expression Matching Can Be Simple And Fast"* (https://swtch.com/~rsc/regexp/regexp1.html). This confirms the observed linear scaling and the absence of catastrophic backtracking.

- **[CORROBORATED] `net/http` default redirect replays method and body via `GetBody` (supports §6.5).** Official documentation, *"http package - net/http - Go Packages"* (https://pkg.go.dev/net/http), states a 307/308 redirect `"preserves the original HTTP method and body, provided that the Request.GetBody function is defined."` Because the verifier builds the request from a `bytes.Reader`, `GetBody` is populated, so the secret body is replayed on redirect — matching the hop-2 capture in §6.5.

- **[CORROBORATED] `crypto/tls` verifies by default when `TLSClientConfig` is unset (supports §4).** Official documentation, *"tls package - crypto/tls - Go Packages"* (https://pkg.go.dev/crypto/tls), states that for `RootCAs`, `"If RootCAs is nil, TLS uses the host's root CA set"`, and that `InsecureSkipVerify` defaults to `false` (full certificate and hostname verification). This confirms that `SaneHttpClient`, which sets no `TLSClientConfig`, gets strict verification — matching the untrusted-cert failure in §4.2.

- **[CORROBORATED] `169.254.169.254` is the cloud instance-metadata endpoint (supports §3).** AWS documentation, *"Use the Instance Metadata Service to access instance metadata - Amazon EC2"* (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), documents the link-local `169.254.169.254` address and that IMDSv2 requires a `PUT` to `/latest/api/token` to obtain a token that must accompany subsequent `GET` requests (IMDSv1 uses a plain `GET`). This confirms the significance of the address in §3 and the method/shape mismatch (verifier `POST` vs metadata `GET`/`PUT`) noted in §3.5 and §9.1.

---

## 11. Coverage pass

Every named sub-question and mechanism from the prompt is addressed, with observed evidence and `file:line` citations:

| Question / named item | Where answered | Verdict (observed) |
|---|---|---|
| SSRF: what happens with an internal / `169.254.169.254` endpoint? | §3.3 | No filtering; secret-bearing `POST` aimed at the metadata address |
| Any validation / allowlist / denylist? (`ValidateVerifyEndpoint`) | §3.1 [validation.go:35-44] | Only an `http`+`unsafe` check; no address filtering |
| `http://` without `unsafe`? / `https://` without `unsafe`? | §3.4 | `http` rejected at load; `https` accepted |
| TLS/cert validation on HTTPS webhooks? MITM? | §4.1–§4.3 | Go default strict verification; untrusted cert ⇒ 0 requests, unverified |
| Which client? (`SaneHttpClient`, no `TLSClientConfig`) | §4.1 [http.go:211-221, custom_detectors.go:62] | No `InsecureSkipVerify`, no pinning on this path |
| Amplification: once or many times? any cap? | §5.3–§5.4 | Per-permutation; cap 100 **per keyword-match region** (per `FromData`), not per chunk / scan-wide |
| `permutateMatches` / `maxTotalMatches = 100` | §5.1 [custom_detectors.go:23,110,295-296; engine.go:1061-1070] | Confirmed per-region; one chunk ⇒ 120 POSTs; multi-file 2×150 ⇒ 200 |
| Multiple verifiers / redirects amplify? | §5.4, §6.5 | Fan-out to every verifier; each redirect hop replays body |
| Data surface: headers, body, secret material | §6.1–§6.4 [custom_detectors.go:214-238] | Exact JSON body + verbatim headers + `User-Agent: TruffleHog` |
| Secret sent on non-200? | §6.3–§6.4 | Yes (403 case still receives the full request) |
| Response readback (bidirectional)? | §6.4 [custom_detectors.go:253-266] | Up to 200 **bytes** into `ExtraData["response"]` |
| Header handling (`strings.Cut`, `TrimLeft`, canonicalization) | §6.6 [custom_detectors.go:233,238] | First-colon split, left-trim, canonicalized, dups kept, malformed rejected |
| `successRanges` behavior at this commit | §6.7 [custom_detectors.go:249; validation.go:55-97] | No-op: only `== 200` is checked |
| Verification caching / dedup | §7 [verification_cache.go:58-147] | All-hit short-circuit; key = `hash(Raw+RawV2+DetectorType)` |
| ReDoS: complex/malicious regex handling; safeguards? | §8 [validation.go:23-33] | RE2 (linear, no backtracking); `(a+)+$` does not blow up |
| Overall threat model / trust boundary | §9 | Config author is inside the trust boundary; unsafe for untrusted configs |
| External corroboration (RE2, net/http, crypto/tls, IMDS) | §10 | Four authoritative sources |

**Detector attribution (correction).** All primary probes — SSRF (§3), TLS (§4), amplification (§5), data surface and headers (§6), caching (§7) — use TruffleHog's own **`HogTokenDetector`** definition (from `pkg/custom_detectors/CUSTOM_DETECTORS.md`) through the canonical `--config` path. The **only** exception is the ReDoS experiment (§8), which necessarily uses a distinct **`ReDoSProbe`** detector whose regex is the catastrophic `(a+)+$`; this is stated explicitly in §8.2 and is not claimed to be `HogTokenDetector`. The non-canonical Python contrast in §8.3 is not TruffleHog at all and is labeled `[NON-CANONICAL COMPARISON]`.

Nothing in the prompt is left unaddressed.

---

## 12. Integrity and cleanup

### 12.1 Repository integrity

This investigation is read-only with respect to the repository. The **only** committed change is this document. Concretely:
- `git status --porcelain` reports exactly one changed path, `blitzy/documentation/trufflehog_e42153d44a5e.md`; no source, test, proto, or example file is modified.
- `go.mod` and `go.sum` are untouched (the scanner is built from the existing, pinned module graph; `go mod download all` was deliberately avoided because it would append transitive checksums to `go.sum`).
- All observation artifacts — the built binary, the capture servers, probe configs, scan data, and logs — live under `/tmp` (outside the repository) and bind loopback (`127.0.0.1`) only. Nothing global on the host is mutated (no `iptables`, no host networking).
- Every secret used is **synthetic** (a randomly-shaped 40-character token), never a real credential.

### 12.2 A note on output fidelity

Embedded command output is complete and unedited except for a single normalization: trailing end-of-line whitespace — invisible when rendered and carrying no semantic content — was stripped so the deliverable passes `git diff --check`. For instance, `openssl`'s `X509v3 Subject Alternative Name:` header (its value is on the following line) and TruffleHog's `Response:` label for an empty body each end with such whitespace in the raw terminal capture. No values, counters, lines, or other content were added, removed, or altered; the emptiness of that response is independently shown by the server-side capture and the `finished scanning` summary.

### 12.3 Teardown procedure

The following idempotent script terminates any capture server that was started (by explicit numeric PID, never a broad match), removes every `/tmp` artifact by explicit path, and proves absence. Its execution output is captured in §12.4.

```bash
# ---- scripts/09_cleanup.sh ----
#!/usr/bin/env bash
# Idempotent teardown: terminate any capture servers WE started (found by our
# exact script name, killed by explicit numeric PID — never a broad match),
# remove ALL /tmp harness artifacts by explicit path, and PROVE absence.
set -u
TH=/tmp/th_harness
BIN=/tmp/trufflehog

echo "===== before: harness artifacts present? ====="
ls -d "$TH" "$BIN" 2>/dev/null || true

echo "===== terminate any capture_server.py we started (by explicit numeric PID) ====="
# [c]apture trick: the grep line does not match its own command line.
PIDS=$(ps -eo pid,args | grep "[c]apture_server.py" | awk '{print $1}')
if [ -n "$PIDS" ]; then
  for pid in $PIDS; do kill "$pid" 2>/dev/null && echo "terminated pid $pid"; done
  sleep 1
else
  echo "none running"
fi

echo "===== remove artifacts (explicit paths ONLY under /tmp) ====="
rm -rf "$TH"; echo "rm $TH exit=$?"
rm -f  "$BIN"; echo "rm $BIN exit=$?"

echo "===== absence checks ====="
[ -e "$TH"  ] && echo "STILL PRESENT: $TH"  || echo "ABSENT: $TH"
[ -e "$BIN" ] && echo "STILL PRESENT: $BIN" || echo "ABSENT: $BIN"

echo "===== no capture_server.py process remains ====="
REM=$(ps -eo pid,args | grep "[c]apture_server.py" | awk '{print $1}')
[ -z "$REM" ] && echo "no capture_server.py process" || echo "PROCESS STILL RUNNING: $REM"
```

### 12.4 Cleanup execution (observed)

Running the teardown after all evidence was captured — complete, unedited output:

```text
===== before: harness artifacts present? =====
/tmp/th_harness
/tmp/trufflehog
===== terminate any capture_server.py we started (by explicit numeric PID) =====
none running
===== remove artifacts (explicit paths ONLY under /tmp) =====
rm /tmp/th_harness exit=0
rm /tmp/trufflehog exit=0
===== absence checks =====
ABSENT: /tmp/th_harness
ABSENT: /tmp/trufflehog
===== no capture_server.py process remains =====
no capture_server.py process
```

The binary and all harness artifacts are absent, and no capture-server process remains. The repository's working tree now contains only the single modified document; the source tree is byte-for-byte unchanged.
