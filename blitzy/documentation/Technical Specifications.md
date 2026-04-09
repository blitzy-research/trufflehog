# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **create new security analysis documentation** that comprehensively investigates and answers specific security questions about TruffleHog's custom detector verification system. The user is evaluating the safety of deploying TruffleHog in an environment where teams contribute custom detector configurations, and needs evidence-based answers grounded in actual codebase behavior — not theoretical descriptions.

- **Documentation Category:** Create new documentation
- **Documentation Type:** Security analysis and investigative technical documentation
- **Target Audience:** Security engineers, platform teams, and operators evaluating TruffleHog deployment for multi-team environments with custom detector contributions
- **Output File:** `blitzy/documentation/trufflehog_e42153d44a5e.md` (per the `SWE-AtlasQnA-Repo` rule, named after the source branch)

The user's core questions, restated with technical precision, are:

- **SSRF / Network Boundary Controls:** When a custom detector configuration specifies a webhook verification endpoint URL, what validation is performed to prevent Server-Side Request Forgery (SSRF) — specifically requests to RFC 1918 private addresses (e.g., `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback addresses (`127.0.0.0/8`, `::1`), link-local addresses (`169.254.0.0/16`, including cloud metadata endpoints such as `169.254.169.254`), and other non-routable addresses?
- **TLS Certificate Validation:** When verification HTTP requests are made over HTTPS, what certificate validation is performed? Does the HTTP client enforce certificate chain verification, or can a man-in-the-middle (MITM) attacker on the network path intercept verification traffic?
- **Multi-Match Verification Behavior:** When a custom detector regex produces multiple matches within a single scanned chunk, does TruffleHog send one verification request or multiple? What is the combinatorial behavior, and is there an upper bound?
- **Verification Request Payload:** What data is included in the HTTP POST body sent to the verification webhook endpoint? What information does the endpoint operator receive?
- **Regex Safety (ReDoS):** What safeguards exist against Regular Expression Denial of Service when a custom detector specifies a computationally expensive regex pattern? Does TruffleHog use backtracking-vulnerable regex engines?
- **Abuse Surface Summary:** Can a malicious or careless actor with control over a detector YAML configuration abuse the verification system as an SSRF proxy, credential exfiltration channel, or denial-of-service vector?

### 0.1.2 Special Instructions and Constraints

- **CRITICAL — Read-only mandate:** The user has explicitly stated: *"Don't modify any source files in the repository."* No source code files may be modified. Test scripts may be created to observe behavior but must be cleaned up when finished.
- **CRITICAL — Evidence-based answers only:** The user requires answers derived from actual code inspection and observed behavior, not theoretical or aspirational statements.
- **Implementation Rule — `SWE-AtlasQnA-Repo`:** The output is a new markdown document named `trufflehog_e42153d44a5e.md` placed in the `blitzy/documentation` directory. No existing files may be modified. The document must provide thinking/rationale and base answers on the code as truth.

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- To **document SSRF protections**, we will analyze the HTTP client initialization in `pkg/custom_detectors/custom_detectors.go` (line 62: `var httpClient = common.SaneHttpClient()`) and contrast it with the SSRF-protected client in `pkg/detectors/http.go` (lines 33-38: `DetectorHttpClientWithNoLocalAddresses` which uses `WithNoLocalIP()`). We will document the explicit absence of the `WithNoLocalIP()` dial guard in the custom detector HTTP path.
- To **document TLS certificate behavior**, we will analyze the `saneTransport` in `pkg/common/http.go` (lines 211-221) and determine whether it specifies a custom `TLSClientConfig`. We will document that Go's default transport enforces system CA certificate verification.
- To **document multi-match verification behavior**, we will trace the `permutateMatches` function in `pkg/custom_detectors/custom_detectors.go` (lines 317-343) and the `productIndices` function (lines 287-310) that generates combinatorial match permutations, bounded by `maxTotalMatches = 100` (line 23). Each permutation triggers a concurrent verification request via `errgroup.Group.Go()`.
- To **document verification payload content**, we will extract the JSON serialization in `createResults` (lines 214-221) which sends `map[string]map[string][]string{c.GetName(): match}` as the POST body.
- To **document regex safety**, we will confirm that `pkg/custom_detectors/custom_detectors.go` imports the standard `"regexp"` package (Go RE2 semantics, linear-time guarantees), and note that built-in detectors use `github.com/wasilibs/go-re2` for enhanced safety.
- To **document the overall abuse surface**, we will create a consolidated security assessment section synthesizing all findings.

### 0.1.4 Inferred Documentation Needs

Based on code analysis, the following implicit documentation needs have been identified:

- **Gap: `successRanges` configuration is defined but not implemented.** The `VerifierConfig` protobuf schema (`proto/custom_detectors.proto`, line 30) and validation logic (`pkg/custom_detectors/validation.go`, lines 55-97) support `successRanges`, but the actual verification in `createResults` (`pkg/custom_detectors/custom_detectors.go`, line 249) hardcodes `resp.StatusCode == http.StatusOK`. This discrepancy should be documented.
- **Gap: Custom detectors use `common.SaneHttpClient()` which lacks the `WithNoLocalIP()` SSRF protection** that the built-in detector client (`DetectorHttpClientWithNoLocalAddresses`) applies. This is a critical security finding that the document must address.
- **Gap: `common.SaneHttpClient()` does not suppress redirects,** unlike the built-in detector HTTP client which uses `WithNoFollowRedirects()`. This means redirect-based SSRF may be possible.
- **Gap: No URL-level validation against internal addresses exists** in `ValidateVerifyEndpoint` (`pkg/custom_detectors/validation.go`, lines 35-43); only HTTP vs. HTTPS scheme checking is performed.
- **Gap: Verification requests are dispatched concurrently** with no per-endpoint rate limiting, only bounded by `maxTotalMatches = 100` permutations and the engine's `detectionTimeout` context.

## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals a minimal documentation structure with two architecture-focused markdown files and scattered package-level documentation. No documentation generator framework (mkdocs, Sphinx, Docusaurus, etc.) is detected.

**Documentation files discovered:**

| File Path | Type | Coverage Status |
|---|---|---|
| `README.md` | Project overview, installation, usage examples | Comprehensive for general usage; no custom detector security analysis |
| `SECURITY.md` | Security reporting policy | Single-line email contact (`security@trufflesec.com`) — no security architecture docs |
| `CONTRIBUTING.md` | Contribution guidelines | Standard contribution workflow |
| `CODE_OF_CONDUCT.md` | Community conduct policy | Standard governance |
| `PreCommit.md` | Pre-commit hook setup | Focused on hook installation |
| `docs/concurrency.md` | Concurrency architecture with Mermaid diagrams | Documents worker pipeline, not verification security |
| `docs/process_flow.md` | End-to-end scanning data flow | Documents pipeline stages; brief mention of verification step |
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` | Custom detector setup guide | Covers YAML configuration, keywords, regex, basic verification server examples; **does not address security boundaries** |
| `examples/README.md` | Example custom detector usage | Explains how to run with `--config` flag; notes that generic detection is not default |
| `examples/generic.yml` | Sample generic API key detector | No verification configured |
| `examples/generic_with_filters.yml` | Advanced generic detector with exclusion filters | No verification configured |

**Key finding:** No existing documentation covers the security properties of the custom detector verification system. The `CUSTOM_DETECTORS.md` guide explains _how_ to configure verification webhooks but does not document what security boundaries, SSRF protections, TLS behavior, or rate limits exist.

### 0.2.2 Repository Code Analysis for Documentation

The following source code files were analyzed to derive the security documentation:

**Primary security-relevant files:**

| Source File | Relevance |
|---|---|
| `pkg/custom_detectors/custom_detectors.go` | Main custom detector implementation: HTTP client selection, verification request construction, match permutation, response handling |
| `pkg/custom_detectors/validation.go` | Input validation: endpoint scheme check, regex compilation, header format, range validation |
| `pkg/custom_detectors/validation_test.go` | Test coverage for validation logic — reveals accepted/rejected inputs |
| `pkg/custom_detectors/custom_detectors_test.go` | Test coverage for detector behavior, permutation, parsing |
| `pkg/detectors/http.go` | Built-in detector HTTP client with SSRF protection (`WithNoLocalIP()`), redirect suppression, timeout |
| `pkg/detectors/http_test.go` | Tests confirming local IP blocking behavior |
| `pkg/common/http.go` | `SaneHttpClient()` and `saneTransport` used by custom detectors — lacks SSRF protections |
| `pkg/roundtripper/roundtripper.go` | Transport layer with `WithInsecureTLS()` option (not used by custom detectors) |
| `proto/custom_detectors.proto` | Protobuf schema defining `VerifierConfig` with `endpoint`, `unsafe`, `headers`, `successRanges` |
| `pkg/config/config.go` | YAML config loading pipeline: file → protobuf → `NewWebhookCustomRegex` |
| `pkg/config/detectors.go` | `ParseVerifierEndpoints` enforcing HTTPS for built-in detector overrides (not for custom detectors) |
| `pkg/engine/engine.go` | Engine orchestration: worker counts, detection timeout, context management |
| `pkg/feature/feature.go` | Feature flags (no verification-specific flags found) |

**Search patterns used:**
- Searched for SSRF-related patterns (`WithNoLocalIP`, `isLocalIP`, `169.254`, `metadata`) across all Go files
- Searched for TLS-related patterns (`InsecureSkipVerify`, `TLSClientConfig`, `RootCAs`) across all Go files
- Searched for regex engine usage (`go-re2`, `wasilibs`, standard `regexp`) across custom detector and common packages
- Searched for rate limiting, timeout, and concurrency controls in engine and custom detector code

### 0.2.3 Web Search Research Conducted

No external web searches were required for this analysis. All findings are derived directly from codebase inspection, which aligns with the user's explicit requirement for evidence-based answers grounded in the actual code.

## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

The documentation to be produced is a security analysis answering the user's specific questions. The following modules require documentation coverage, mapped to the specific security questions:

**Module: `pkg/custom_detectors/` — Custom Detector Verification System**
- Public APIs: `NewWebhookCustomRegex()`, `FromData()`, `createResults()`, `permutateMatches()`, `productIndices()`
- Validation APIs: `ValidateKeywords()`, `ValidateRegex()`, `ValidateVerifyEndpoint()`, `ValidateVerifyHeaders()`, `ValidateVerifyRanges()`
- Current documentation: `CUSTOM_DETECTORS.md` covers configuration syntax only — no security analysis
- Documentation needed: SSRF exposure analysis, verification payload documentation, match permutation behavior, rate/volume limits

**Module: `pkg/detectors/http.go` — Detector HTTP Infrastructure**
- Public APIs: `WithNoLocalIP()`, `isLocalIP()`, `NewDetectorHttpClient()`, `NewDetectorTransport()`
- Current documentation: None
- Documentation needed: Contrast between SSRF-protected built-in client and unprotected custom detector client

**Module: `pkg/common/http.go` — Common HTTP Client**
- Public APIs: `SaneHttpClient()`, `NewCustomTransport()`, `PinnedCertPool()`, `PinnedRetryableHttpClient()`
- Current documentation: None
- Documentation needed: TLS certificate validation behavior, transport configuration, absence of local-IP and redirect controls

**Module: `proto/custom_detectors.proto` — Configuration Schema**
- Messages: `CustomRegex`, `VerifierConfig`
- Current documentation: Inline proto comments only
- Documentation needed: Document the `successRanges` field that is defined but not implemented in runtime

**Module: `pkg/engine/engine.go` — Engine Orchestration**
- APIs: `startDetectorWorkers()`, `setDefaults()`, detection timeout context
- Current documentation: `docs/concurrency.md` covers worker architecture
- Documentation needed: Concurrency multiplier defaults, detection timeout, and their impact on verification request volume

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, documentation gaps include:

- **No SSRF security analysis exists anywhere in the repository.** The `isLocalIP()` function and `WithNoLocalIP()` option exist but are not documented, and their absence from the custom detector HTTP path is not noted.
- **No TLS validation documentation exists.** The `PinnedCertPool()` function and `saneTransport` behavior are undocumented.
- **No documentation of verification request payload format.** The JSON structure sent to webhook endpoints is only visible in source code.
- **No documentation of match permutation combinatorics.** The `maxTotalMatches = 100` bound and the `productIndices` algorithm are test-covered but undocumented for operators.
- **No documentation of the `successRanges` configuration gap.** The field is present in the proto schema and validated during config loading but ignored during actual verification execution.
- **No documentation of regex engine safety characteristics.** The standard library `regexp` (RE2 semantics) is used by custom detectors while built-in detectors use `go-re2`, but neither choice is documented for security assessment purposes.
- **No documentation of the `unsafe` flag's actual scope.** The `unsafe: true` flag only gates HTTP vs. HTTPS endpoint acceptance — it does not enable or disable any other safety mechanism.

## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

The output document will be placed at `blitzy/documentation/trufflehog_e42153d44a5e.md` and structured as a comprehensive security analysis document:

```
blitzy/
└── documentation/
    └── trufflehog_e42153d44a5e.md
        ├── Introduction (context and purpose)
        ├── SSRF / Network Boundary Analysis
        │   ├── Built-in detector SSRF protections (evidence)
        │   ├── Custom detector HTTP client (evidence)
        │   ├── Absence of local IP blocking (finding)
        │   ├── Redirect-following behavior (finding)
        │   └── Cloud metadata endpoint exposure (finding)
        ├── TLS Certificate Validation Analysis
        │   ├── Transport configuration (evidence)
        │   ├── Certificate verification behavior (finding)
        │   └── PinnedCertPool vs. system defaults (comparison)
        ├── Multi-Match Verification Behavior
        │   ├── Match permutation algorithm (evidence)
        │   ├── maxTotalMatches bound (evidence)
        │   ├── Concurrent dispatch (evidence)
        │   └── Volume estimation (analysis)
        ├── Verification Request Payload Analysis
        │   ├── JSON payload structure (evidence)
        │   ├── Data included and excluded (finding)
        │   └── Response handling and truncation (evidence)
        ├── Regex Safety Analysis
        │   ├── Regex engine selection (evidence)
        │   ├── RE2 linear-time guarantees (analysis)
        │   └── Compile-time validation (evidence)
        ├── Configuration Validation Analysis
        │   ├── Endpoint validation scope (evidence)
        │   ├── successRanges gap (finding)
        │   └── unsafe flag scope (finding)
        ├── Abuse Surface Summary
        │   ├── SSRF proxy risk (assessment)
        │   ├── Credential exfiltration risk (assessment)
        │   ├── Denial-of-service risk (assessment)
        │   └── Recommendations (if appropriate within scope)
        └── References (source files cited)
```

### 0.4.2 Content Generation Strategy

**Information Extraction Approach:**
- Extract HTTP client initialization from `pkg/custom_detectors/custom_detectors.go:62` and `pkg/common/http.go:223-228`
- Extract SSRF protection logic from `pkg/detectors/http.go:96-151`
- Extract verification payload construction from `pkg/custom_detectors/custom_detectors.go:214-221`
- Extract permutation logic from `pkg/custom_detectors/custom_detectors.go:287-343`
- Extract validation logic from `pkg/custom_detectors/validation.go:35-43`
- Extract TLS configuration from `pkg/common/http.go:211-221` and `pkg/common/http.go:159-178`
- Extract worker concurrency from `pkg/engine/engine.go:336-354` and `pkg/engine/engine.go:675-688`

**Documentation Standards:**
- Every finding must cite specific file paths and line numbers
- Code snippets will be short (2-3 lines) and focused on the security-relevant logic
- Mermaid diagrams will be used for the HTTP client comparison and verification flow
- Tables will be used for comparing built-in vs. custom detector HTTP behaviors
- All answers will distinguish between "the code does X" (evidence) and "this means Y" (analysis)

### 0.4.3 Diagram and Visual Strategy

The document will include:
- **Comparison table:** Built-in detector HTTP client vs. custom detector HTTP client — listing SSRF protection, redirect behavior, timeout, TLS configuration side by side
- **Flow diagram:** How a single chunk with multiple regex matches triggers verification requests through the permutation → errgroup → HTTP POST pipeline
- **Security boundary diagram:** Showing where validation occurs (config load time vs. runtime) and where it is absent

## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

| Target Documentation File | Transformation | Source Code/Docs | Content/Changes |
|---|---|---|---|
| `blitzy/documentation/trufflehog_e42153d44a5e.md` | CREATE | `pkg/custom_detectors/custom_detectors.go`, `pkg/custom_detectors/validation.go`, `pkg/detectors/http.go`, `pkg/common/http.go`, `proto/custom_detectors.proto`, `pkg/engine/engine.go`, `pkg/config/config.go`, `pkg/config/detectors.go`, `pkg/roundtripper/roundtripper.go`, `pkg/feature/feature.go` | Complete security analysis document answering all six user questions about custom detector verification security boundaries |

No existing files are updated or deleted. This is a single-file CREATE operation per the `SWE-AtlasQnA-Repo` implementation rule.

### 0.5.2 New Documentation File Detail

```
File: blitzy/documentation/trufflehog_e42153d44a5e.md
Type: Security Analysis / Investigative Technical Documentation
Source Code:
    - pkg/custom_detectors/custom_detectors.go (primary)
    - pkg/custom_detectors/validation.go (primary)
    - pkg/detectors/http.go (primary)
    - pkg/common/http.go (primary)
    - proto/custom_detectors.proto (schema reference)
    - pkg/engine/engine.go (concurrency/timeout context)
    - pkg/config/config.go (config loading pipeline)
    - pkg/config/detectors.go (ParseVerifierEndpoints for comparison)
    - pkg/roundtripper/roundtripper.go (TLS options reference)
    - pkg/feature/feature.go (feature flag inventory)
    - pkg/custom_detectors/CUSTOM_DETECTORS.md (existing doc reference)
    - examples/generic.yml (configuration example reference)
    - examples/generic_with_filters.yml (advanced config reference)
Sections:
    - Introduction and scope
    - Q1: SSRF / Network boundary analysis (evidence from http.go, custom_detectors.go, common/http.go)
    - Q2: TLS certificate validation (evidence from common/http.go saneTransport)
    - Q3: Multi-match verification behavior (evidence from permutateMatches, productIndices, errgroup)
    - Q4: Verification request payload (evidence from createResults JSON marshaling)
    - Q5: Regex safety / ReDoS (evidence from regexp import, validation.go compile checks)
    - Q6: Abuse surface summary (synthesized from all findings)
    - Configuration validation analysis (bonus: successRanges gap, unsafe flag scope)
    - References and source citations
Key Citations:
    - pkg/custom_detectors/custom_detectors.go:62 (SaneHttpClient usage)
    - pkg/detectors/http.go:33-38 (SSRF-protected client for contrast)
    - pkg/detectors/http.go:96-151 (isLocalIP and WithNoLocalIP)
    - pkg/common/http.go:211-228 (saneTransport and SaneHttpClient)
    - pkg/custom_detectors/custom_detectors.go:214-270 (createResults verification flow)
    - pkg/custom_detectors/custom_detectors.go:287-310 (productIndices with maxTotalMatches=100)
    - pkg/custom_detectors/validation.go:35-43 (ValidateVerifyEndpoint)
    - proto/custom_detectors.proto:26-31 (VerifierConfig schema)
    - pkg/engine/engine.go:338-346 (concurrency defaults)
```

### 0.5.3 Documentation Configuration Updates

No documentation generator configuration files exist in this repository (no `mkdocs.yml`, `docusaurus.config.js`, `.readthedocs.yml`, or `sphinx/conf.py`). The `blitzy/documentation/` directory will be created as a new directory if it does not exist.

### 0.5.4 Cross-Documentation Dependencies

- The new document references findings from `pkg/custom_detectors/CUSTOM_DETECTORS.md` for baseline context on how custom detectors are configured
- The document references `docs/concurrency.md` for the worker pipeline architecture that contextualizes verification concurrency
- No navigation links, table of contents updates, or index changes are required since no documentation framework is in use

## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

This documentation task does not require any additional documentation tools or packages to be installed. The output is a standalone Markdown file. The following are the project's existing dependencies relevant to the security analysis being documented:

| Registry | Package Name | Version | Purpose (in security analysis context) |
|---|---|---|---|
| Go module | `github.com/trufflesecurity/trufflehog/v3` | v3 (Go 1.23.1 / toolchain go1.24.2) | Root module; defines all detector and verification behavior |
| Go stdlib | `regexp` | Go 1.23.1 stdlib | Used by custom detectors for pattern matching — RE2 semantics (linear-time) |
| Go module | `github.com/wasilibs/go-re2` | v1.9.0 | Used by built-in detectors as a RE2-compatible regexp replacement |
| Go module | `github.com/hashicorp/go-retryablehttp` | (per go.mod) | Used by `common.RetryableHTTPClient()` and `PinnedRetryableHttpClient()` — NOT used by custom detector verification |
| Go module | `golang.org/x/sync/errgroup` | (per go.mod) | Used by custom detector `FromData()` for concurrent verification dispatch |
| Protobuf | `validate/validate.proto` | (buf/protoc-gen-validate) | Provides `uri_ref` validation on `VerifierConfig.endpoint` field |
| Go module | `google.golang.org/protobuf` | (per go.mod) | Protobuf runtime for `custom_detectorspb.CustomRegex` message handling |

### 0.6.2 Documentation Reference Updates

No documentation link updates are required. This is a greenfield documentation file creation with no existing cross-references to modify.

## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current coverage analysis (pre-documentation):**
- Custom detector security properties documented: 0/6 questions (0%)
- SSRF behavior documented: 0% — `WithNoLocalIP()` exists but its non-application to custom detectors is nowhere noted
- TLS verification behavior documented: 0% — no documentation on `saneTransport` or `PinnedCertPool()` TLS settings
- Verification payload format documented: 0% — only visible in source code
- Match permutation behavior documented: 0% — `maxTotalMatches` only appears in code and unit tests
- Regex safety documented: 0% — no documentation on regex engine choice or ReDoS protections
- `successRanges` implementation gap documented: 0% — not noted anywhere

**Target coverage after documentation:**
- All 6 user questions answered with code-level evidence: 100%
- Every security-relevant code path cited with file:line references
- Every finding accompanied by rationale explaining why the behavior matters

### 0.7.2 Documentation Quality Criteria

**Completeness requirements:**
- Each of the user's 6 questions receives a dedicated section with evidence and analysis
- All relevant source files are cited with exact line numbers
- The `successRanges` implementation gap is documented as a bonus finding
- The `unsafe` flag's limited scope is documented
- The comparison between built-in and custom detector HTTP clients is made explicit

**Accuracy validation:**
- All code citations must reference the correct file path and line numbers (verified via `read_file`)
- No claims are made about behavior that cannot be traced to specific source code
- The document must distinguish between "the code does X" and "this implies Y"
- Any limitations in the analysis (e.g., runtime behavior not tested) must be noted

**Clarity standards:**
- Each section opens with a clear statement of the question being answered
- Evidence is presented before analysis
- Short code snippets (2-3 lines) illustrate key points
- Tables are used for structured comparisons
- Mermaid diagrams visualize complex flows

**Maintainability:**
- All source citations include file paths so future readers can verify against the codebase
- The document is self-contained — no external links required to understand the findings

### 0.7.3 Example and Diagram Requirements

- Minimum 1 comparison table (built-in vs. custom detector HTTP clients)
- Minimum 1 flow diagram (verification request pipeline from match to HTTP POST)
- Short code snippets for each critical finding (HTTP client initialization, `isLocalIP`, JSON payload, `productIndices` bound)
- No screenshots required (CLI-only project)

## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

**New documentation files:**
- `blitzy/documentation/trufflehog_e42153d44a5e.md` — the sole deliverable

**Source files analyzed for documentation content (read-only):**
- `pkg/custom_detectors/custom_detectors.go` — verification HTTP client, request construction, match permutation, response handling
- `pkg/custom_detectors/validation.go` — endpoint validation, regex validation, header validation, range validation
- `pkg/custom_detectors/validation_test.go` — test cases revealing validation boundaries
- `pkg/custom_detectors/custom_detectors_test.go` — test cases for permutation and parsing behavior
- `pkg/custom_detectors/regex_varstring.go` — placeholder variable parsing
- `pkg/custom_detectors/CUSTOM_DETECTORS.md` — existing user guide for reference
- `pkg/detectors/http.go` — `WithNoLocalIP()`, `isLocalIP()`, SSRF protection, detector transport
- `pkg/detectors/http_test.go` — tests confirming local IP blocking behavior
- `pkg/common/http.go` — `SaneHttpClient()`, `saneTransport`, `PinnedCertPool()`, `NewCustomTransport()`
- `pkg/roundtripper/roundtripper.go` — `WithInsecureTLS()` option (for reference/contrast)
- `proto/custom_detectors.proto` — `VerifierConfig` schema with `successRanges`
- `pkg/config/config.go` — YAML → protobuf → detector construction pipeline
- `pkg/config/detectors.go` — `ParseVerifierEndpoints()` HTTPS enforcement for built-in detectors
- `pkg/engine/engine.go` — concurrency defaults, detection timeout, worker orchestration
- `pkg/feature/feature.go` — feature flags inventory
- `go.mod` — Go version, `go-re2` dependency, module path
- `examples/generic.yml` — sample detector config without verification
- `examples/generic_with_filters.yml` — advanced detector config with exclusions

**Security topics in scope:**
- SSRF / network boundary analysis for custom detector verification webhooks
- TLS certificate validation behavior of the custom detector HTTP client
- Multi-match verification behavior (permutation, concurrency, bounds)
- Verification request payload content analysis
- Regex engine safety (ReDoS) for custom detector patterns
- Configuration validation completeness (`successRanges` gap, `unsafe` flag scope)
- Overall abuse surface assessment for malicious detector configurations

### 0.8.2 Explicitly Out of Scope

- **Source code modifications** — the user has explicitly prohibited modifying any source files
- **Built-in detector security analysis** — the user's questions are specific to custom detectors with webhook verification
- **Enterprise TruffleHog features** — only the open-source codebase is analyzed
- **Performance benchmarking** — verification throughput testing is not requested
- **Remediation implementation** — the document identifies findings but does not implement fixes
- **Test file modifications** — no test files are modified
- **Any changes to `pkg/`, `proto/`, `examples/`, `docs/`, or any other existing directory** — per the `SWE-AtlasQnA-Repo` rule
- **Generic/non-custom detector security** — only the `pkg/custom_detectors/` verification path is in scope
- **Source scanning security** (git, filesystem, S3, etc.) — not relevant to the user's questions

## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

- **Documentation build command:** Not applicable — the output is a standalone Markdown file with no build step
- **Documentation preview command:** Standard Markdown viewer or `cat blitzy/documentation/trufflehog_e42153d44a5e.md`
- **Diagram generation command:** Mermaid diagrams are embedded inline in the Markdown using fenced code blocks; rendering is delegated to the Markdown viewer
- **Documentation deployment command:** Not applicable — the file is committed to the `blitzy/documentation/` directory in the destination repository
- **Default format:** Markdown with Mermaid diagrams
- **Citation requirement:** Every section must reference source files with `file_path:line_number` format
- **Style guide:** Evidence-first structure — present the code evidence, then the analysis/finding, then the security implication
- **Documentation validation:** Manual review of file:line citations against codebase; no automated linting pipeline

### 0.9.2 File Creation Strategy

The document creation follows a straightforward single-file approach:

- Create directory `blitzy/documentation/` if it does not exist
- Create `blitzy/documentation/trufflehog_e42153d44a5e.md` with the complete security analysis
- The document must be self-contained and not depend on external resources
- All Mermaid diagrams must be embedded as fenced code blocks within the Markdown
- Code snippets must use Go syntax highlighting (`go` language tag)
- The document must open with a clear statement of purpose and the questions being answered
- Each section must be independently readable while contributing to the whole

## 0.10 Rules for Documentation

The following documentation rules apply, derived from the user's explicit instructions and the `SWE-AtlasQnA-Repo` implementation rule:

- **Do not modify any existing files in the source repository.** The only file created is `blitzy/documentation/trufflehog_e42153d44a5e.md`.
- **Do not make assumptions — base all answers on the code as the truth.** Every claim must be traceable to a specific file and line number in the codebase.
- **Provide thinking and rationale behind the answers.** The document must explain not just what the code does, but why it matters from a security perspective.
- **Create the document in the `blitzy/documentation` directory** in the destination repository, named `trufflehog_e42153d44a5e.md` (matching the source branch name).
- **Evidence over theory.** The user explicitly stated: *"I don't want theoretical explanations of what the code should do. I want to see actual evidence of how the system behaves in practice."* All findings must be anchored in source code inspection.
- **Clean up any test scripts.** If test scripts are created to observe behavior, they must be removed when finished. The final state of the repository must contain only the documentation file as a new artifact.
- **No source file modifications under any circumstances.** This is a documentation-only exercise.
- **Distinguish between configuration-time and runtime behavior.** Where validation exists at config parsing time but not at runtime (e.g., `successRanges`), both facts must be documented.
- **Cite all source files comprehensively.** Include a references section listing every file examined and its role in the analysis.

## 0.11 References

### 0.11.1 Files and Folders Searched

The following files and folders were retrieved and analyzed during context gathering:

**Root-level files:**
| File | Purpose in Analysis |
|---|---|
| `go.mod` (lines 1-20) | Go version (1.23.1), toolchain (go1.24.2), `go-re2` dependency (v1.9.0), module path |
| `README.md` (lines 1-50) | Project overview, capabilities summary, custom detector alpha status |
| `SECURITY.md` | Security reporting policy (single-line email contact) |
| `Makefile` | Build commands reference |

**Custom detector implementation (primary analysis target):**
| File | Purpose in Analysis |
|---|---|
| `pkg/custom_detectors/custom_detectors.go` (full file, 357 lines) | HTTP client selection (`SaneHttpClient` at line 62), verification request construction (`createResults` at lines 184-278), match permutation (`permutateMatches` at lines 317-343, `productIndices` at lines 287-310), `maxTotalMatches = 100` (line 23), response truncation (lines 260-263) |
| `pkg/custom_detectors/validation.go` (full file, 109 lines) | `ValidateVerifyEndpoint` (lines 35-43) — HTTP vs. HTTPS check only; `ValidateRegex` (lines 23-33) — compile-time check; `ValidateVerifyRanges` (lines 55-97) — validates ranges but not used at runtime |
| `pkg/custom_detectors/validation_test.go` (full file, 234 lines) | Test cases confirming validation accepts `http://localhost:8000/` with `unsafe: true`, confirms HTTP rejected without `unsafe` flag |
| `pkg/custom_detectors/custom_detectors_test.go` (full file, 216 lines) | Tests for permutation behavior, `maxTotalMatches` bound, YAML parsing |
| `pkg/custom_detectors/regex_varstring.go` | Placeholder parser for verification URL templates |
| `pkg/custom_detectors/CUSTOM_DETECTORS.md` (full file) | Existing custom detector setup guide; verification server examples in Python and Go |

**HTTP client and network security:**
| File | Purpose in Analysis |
|---|---|
| `pkg/detectors/http.go` (full file, 178 lines) | `isLocalIP` (lines 96-102) — checks loopback, link-local, private; `WithNoLocalIP` (lines 106-151) — dial guard blocking local addresses; `DetectorHttpClientWithNoLocalAddresses` (lines 33-38) — the SSRF-protected client used by built-in detectors |
| `pkg/detectors/http_test.go` (full file, 94 lines) | Tests confirming `127.0.0.1` blocked, `192.168.1.1` blocked, `::1` blocked, `8.8.8.8` allowed |
| `pkg/common/http.go` (full file, 237 lines) | `SaneHttpClient()` (lines 223-228) — the client used by custom detectors, **lacks `WithNoLocalIP()` and redirect suppression**; `saneTransport` (lines 211-221) — no custom `TLSClientConfig` (uses Go default TLS); `PinnedCertPool()` (lines 72-78) — ISRG Root X1/X2 cert pool for pinned clients, **not used by SaneHttpClient** |
| `pkg/roundtripper/roundtripper.go` (lines 1-140) | `WithInsecureTLS()` (lines 122-129) — available but not used by custom detectors |

**Configuration and schema:**
| File | Purpose in Analysis |
|---|---|
| `proto/custom_detectors.proto` (full file, 31 lines) | `VerifierConfig` message with `endpoint`, `unsafe`, `headers`, `successRanges` fields; `validate.rules` URI-ref annotation on endpoint |
| `pkg/config/config.go` (full file, 45 lines) | Config loading: YAML → `protoyaml.UnmarshalStrict` → `NewWebhookCustomRegex` pipeline |
| `pkg/config/detectors.go` (full file, 232 lines) | `ParseVerifierEndpoints` (lines 97-117) — enforces HTTPS for built-in detector endpoint overrides (contrast with custom detectors) |

**Engine and concurrency:**
| File | Purpose in Analysis |
|---|---|
| `pkg/engine/engine.go` (selected ranges) | `setDefaults` (lines 336-354) — `detectorWorkerMultiplier = 8`, concurrency defaults to `runtime.NumCPU()`; detection timeout (line 37, lines 1066-1077) — context-based timeout wrapping detector execution; worker spawning (lines 675-688) |
| `pkg/feature/feature.go` (full file, 35 lines) | Feature flag inventory — no verification-specific flags exist |

**Existing documentation and examples:**
| File | Purpose in Analysis |
|---|---|
| `docs/concurrency.md` (full file) | Worker pipeline architecture; Mermaid sequence diagram |
| `docs/process_flow.md` | End-to-end scanning data flow reference |
| `examples/generic.yml` (full file) | Sample detector config without verification |
| `examples/generic_with_filters.yml` (lines 1-50) | Advanced detector config with entropy and exclusion filters |
| `examples/README.md` | Example usage instructions |

**Folders explored:**
| Folder | Depth | Purpose |
|---|---|---|
| Root (`""`) | Level 0 | Repository structure discovery |
| `pkg/` | Level 1 | Core package inventory |
| `pkg/custom_detectors/` | Level 2 | Primary analysis target |
| `pkg/detectors/` | Level 2 | HTTP client and SSRF protection |
| `pkg/common/` | Level 2 | Shared HTTP utilities |
| `pkg/config/` | Level 2 | Configuration loading and validation |
| `pkg/roundtripper/` | Level 2 | Transport layer options |
| `pkg/engine/` | Level 2 | Engine orchestration and concurrency |
| `docs/` | Level 1 | Existing documentation |
| `examples/` | Level 1 | Configuration examples |
| `proto/` | Level 1 | Protobuf schema definitions |

### 0.11.2 Attachments

No attachments were provided by the user. No Figma screens were referenced.

