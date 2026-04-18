# Jenkins Secret Guard Plugin Implementation Guide

## Purpose

This document explains how the current implementation works, how the main classes collaborate, and where to add future functionality safely.

## Package Layout

The Java sources are organized under `io.jenkins.plugins.secretguard`:

- `action`
  - Jenkins UI actions for Job, Run, and global reports
- `config`
  - global plugin configuration
- `listener`
  - save-time, item, and build-time entry points
- `model`
  - immutable scan and finding objects
- `monitor`
  - `AdministrativeMonitor` integration
- `rules`
  - detection rule interface and built-in rules
- `scan`
  - content scanners for XML and Pipeline text
- `service`
  - orchestration, whitelist/exemption logic, and result storage
- `util`
  - helper utilities such as masking

## End-to-End Flow

### Save-time flow

1. Jenkins saves a `Job`
2. `SecretGuardJobConfigFilter` wraps Job create and update HTTP requests before the response is committed
3. `ConfigXmlScanner` extracts candidate values from the candidate `config.xml`
4. `BuiltInSecretRuleSet` emits findings
5. `SecretScanService` applies whitelist and exemption policy
6. If mode is `BLOCK` and threshold is hit, the filter restores the previous `config.xml` or deletes the newly created Job, then returns an error response
7. `SecretGuardSaveableListener` and `SecretGuardItemListener` refresh the persisted latest result for reporting, remove stale entries for deleted Jobs, and refresh persisted keys when Jobs are renamed or moved

### Build-time flow

1. Jenkins starts a build
2. `SecretGuardRunListener` asks `PipelineDefinitionExtractor` for Pipeline text
3. Inline Pipeline scripts are read from the job definition; Pipeline-from-SCM and multibranch Jenkinsfiles are read with lightweight `SCMFileSystem` access
4. `PipelineScriptScanner` scans the script text
5. `SecretScanService` post-processes the findings
6. `SecretGuardRunAction` is attached to the build
7. Depending on mode:
   - `AUDIT`: log/report only
   - `WARN`: mark build `UNSTABLE`
   - `BLOCK`: interrupt build with `FAILURE`

If SCM Jenkinsfile content cannot be read through lightweight access, the build-time scan is skipped for that Jenkinsfile and the build is not failed by the read failure. Secret Guard records a scan note so the build report explains why the Jenkinsfile was skipped.

### Manual Job scan flow

1. User opens a Job's `Secret Guard` page
2. User clicks `Scan Now`
3. `SecretGuardJobAction#doScanNow` checks `Item.CONFIGURE`
4. `ManualJobScanService` reads the current `config.xml`
5. `ConfigXmlScanner` scans XML content and inline Pipeline script content
6. `PipelineDefinitionExtractor` tries to read Pipeline-from-SCM or multibranch Jenkinsfile content through `SCMFileSystem`
7. `PipelineScriptScanner` scans the SCM Jenkinsfile as `JENKINSFILE` when it is available
8. `SecretScanService` applies whitelist, exemptions, deduplication, scan notes, and latest-result persistence
9. User is redirected back to the Job report page with the refreshed latest result

Manual scan always runs in report-only mode. It refreshes findings but does not block save operations and does not change build results.
If a Pipeline-from-SCM or multibranch Jenkinsfile cannot be read through lightweight access, the Job report and system report show a scan note instead of silently skipping that Jenkinsfile.

### Save-time flow for Pipeline-from-SCM

Save-time enforcement continues to scan the submitted Job `config.xml`.
It does not perform SCM network reads in the blocking save path.
Pipeline-from-SCM Jenkinsfiles are scanned during manual scans and build-time scans when lightweight SCM access is available.

## Main Classes

### Configuration

- `SecretGuardGlobalConfiguration`
  - exposes Jenkins global form fields
  - parses multi-line whitelist entries
  - parses multi-line exemption entries
  - safely returns `null` when accessed outside a Jenkins runtime, which keeps unit tests simple

### Model

- `SecretFinding`
  - immutable finding payload
  - supports `withExemption(reason)` to preserve original finding content while marking policy state
  - can carry an optional analysis note that explains why a finding was downgraded or why generic sibling findings were suppressed
- `SecretScanResult`
  - holds findings, scan notes, highest severity, blocked flag, and scan timestamp
- `ScanContext`
  - carries source metadata and enforcement inputs into scanners and rules

### Rules

- `SecretRule`
  - common detection contract
- `BuiltInSecretRuleSet`
  - builds the rule registry once
  - contains:
    - `SensitiveFieldRule`
    - regex-driven `PatternSecretRule`
    - entropy-based `HighEntropyRule`
  - downgrades strongly placeholder-like sensitive-field values to `LOW` instead of treating them as plaintext secrets

When adding a new rule:

1. implement `SecretRule`
2. register it in `BuiltInSecretRuleSet`
3. add unit tests for positive and negative cases

### Scanners

#### `ConfigXmlScanner`

- uses secure XML parser settings
- traverses attributes and element text
- maps XML paths to:
  - `CONFIG_XML`
  - `PARAMETER_DEFAULT`
  - `ENVIRONMENT`
- detects inline Pipeline `<script>` elements and sends the complete script text to `PipelineScriptScanner`
- runs plugin-specific `ConfigXmlScanAdapter` implementations before generic XML value scanning so high-confidence plugin semantics can skip or replace generic traversal
- records deduplicated `Adapter:` decision notes when plugin-specific semantics skip or replace generic traversal; notes name the adapter decision but never include raw field values
- recognizes `HTTP Request`-style `config.xml` sections so credentials-backed `authentication` references and `customHeaders` values can be interpreted with plugin-specific semantics
- recognizes Git SCM metadata such as branch specs, refspecs, and remote names so readable repository metadata does not trigger generic secret heuristics
- recognizes Kubernetes secret-backed environment variables as references while still scanning plaintext key/value environment variables
- recognizes common publisher/build-wrapper reference fields such as external `secretName` and credential names when values look like readable references rather than high-confidence secret literals
- avoids scanning recognized Pipeline `<script>` text as ordinary XML text to reduce duplicate fallback findings
- calculates approximate line numbers by locating the matched text in the source XML
- falls back to raw line scanning if XML parsing fails

#### `PipelineScriptScanner`

- scans line by line
- ignores obvious comment-only lines
- tracks `environment {}` nesting
- classifies:
  - environment assignments
  - command steps
  - HTTP-style authorization lines
- parses literal `httpRequest customHeaders` lists into per-header entries before scanning
- detects hardcoded custom header literals and separately reports `maskValue: false`
- detects hardcoded secrets embedded in URL query parameters such as `?key=...` and `?token=...`
- supports mixed single-line and multi-line header layouts, multiple headers in one request, and nested Groovy expressions inside header values
- passes header names into generic rules only for parsed header `value:` entries, so later non-header lines in the same `httpRequest` block do not inherit the header context
- treats runtime header references such as `"$TOKEN"`, `"${TOKEN}"`, `env.TOKEN`, `params.TOKEN`, `env['TOKEN']`, simple GString/concatenation forms, and common `withCredentials`-bound variable combinations as non-plaintext values through shared `NonSecretHeuristics` helpers
- treats obvious redaction placeholders in headers as non-hardcoded header secrets while still allowing generic low-severity sensitive-field reporting
- passes header names into generic rules so benign tracking headers do not trigger high-entropy false positives
- keeps implementation text-based so it does not require Pipeline AST integration

#### `PipelineDefinitionExtractor`

- detects inline Pipeline definitions through `getDefinition().getScript()`
- detects ordinary Pipeline-from-SCM definitions through `getDefinition().getScm()` and `getDefinition().getScriptPath()`
- resolves multibranch branch jobs through `BranchJobProperty`, `SCMSourceOwner`, branch head metadata, and lightweight SCM reads
- keeps production code decoupled from concrete workflow classes by using reflection
- returns a `PipelineSourceResolution` with either a `PipelineScriptSource` or scan notes explaining unavailable SCM reads

#### `ScmJenkinsfileReader`

- reads configured Jenkinsfile paths with Jenkins `SCMFileSystem`
- defaults blank script paths to `Jenkinsfile`
- reports SCM Jenkinsfile findings with `FindingLocationType.JENKINSFILE`
- returns an unavailable-read scan note when lightweight access is unsupported, the file is missing, empty, or reading fails
- never performs a workspace checkout fallback in the blocking or build-start scan path

#### `MultibranchContextResolver`

- resolves branch jobs created by multibranch Pipeline
- looks up `BranchJobProperty` reflectively so the plugin still starts without a hard runtime dependency on `workflow-multibranch`
- extracts branch `SCMHead`, source ID, optional revision, and multibranch `scriptPath`
- falls back safely when source or revision metadata is unavailable

#### `MultibranchJenkinsfileReader`

- reads branch-specific Jenkinsfiles with `SCMFileSystem.of(SCMSource, SCMHead, SCMRevision)`
- uses the run revision when available so build-time scans align with the exact branch revision Jenkins is building
- reports multibranch findings as `JENKINSFILE` with source names like `Jenkinsfile from Multibranch SCM: ci/Jenkinsfile`
- returns an unavailable-read scan note when the branch Jenkinsfile cannot be read through lightweight access

#### Operational logging

- configure Jenkins system log logger `io.jenkins.plugins.secretguard`
- log messages use fixed prefixes so troubleshooting can be filtered quickly
- `[Secret Guard][Manual Scan]` covers page-triggered rescans
- `[Secret Guard][Build Scan]` covers build-start scanning and enforcement
- `[Secret Guard][Pipeline Source]` covers inline, SCM, and multibranch source resolution
- `[Secret Guard][Multibranch]` covers branch metadata, source, revision, and script path resolution
- `[Secret Guard][SCM Read]` and `[Secret Guard][SCM Read][Multibranch]` cover lightweight Jenkinsfile reads
- `[Secret Guard][Save Scan]` covers save-time config scanning failures
- `[Secret Guard][Item Sync]` covers item create/update/copy synchronization failures
- `[Secret Guard][ClassLoader]` covers optional plugin class resolution
- `[Secret Guard][Persistence]` covers latest-result disk persistence and restore failures
- `[Secret Guard][Heuristics]` at debug/FINE level explains why high-entropy candidates were treated as non-secret values

#### `NonSecretHeuristics`

- centralizes false-positive suppression for common non-secret values
- skips credential ID fields such as `credentialsId` and `credentialId`
- exposes shared runtime-reference detection for values such as `$TOKEN`, `${TOKEN}`, `env.TOKEN`, `params.TOKEN`, `env['TOKEN']`, and `credentials(...)`
- recognizes strongly placeholder-like literals such as redacted/masked/hidden markers and repeated mask characters, including simple assignments and XML text nodes
- skips paths, repository addresses such as `http(s)://`, `ftp://`, `sftp://`, short-host/IP `host:port/path`, scp-style `user@host:path`, network-share paths, storage URI paths such as `hdfs:///...`, Docker image references, Jenkinsfile/script paths, hash/checksum/digest/commit contexts, public certificates, and trace/request ID headers
- suppresses sensitive-file-name false positives when the value is a readable local file reference such as a relative path or filename
- suppresses high-entropy false positives for generated parameter identifiers such as Uno-Choice `randomName` values and parameter-separator generated names
- suppresses high-entropy false positives for readable JDBC connection options embedded in JDBC URLs
- suppresses high-entropy false positives for readable non-secret HTTP URLs unless the authority looks credentialed or the query/fragment still looks secret-bearing
- exposes structured reason text for ignored high-entropy candidates so UI notes and debug logs can explain the suppression
- exposes a shared entropy helper for rules and Pipeline header analysis

### Services

#### `SecretScanService`

This is the only place that should decide whether a result blocks:

- scanners detect
- services decide policy
- listeners enforce runtime consequences

Responsibilities:

- short-circuit when plugin is disabled
- apply whitelist first
- apply exemptions second
- apply priority-based deduplication after whitelist and exemption processing
- compute blocked state using mode and threshold
- write result into `ScanResultStore`

Priority-based deduplication suppresses generic rules, such as `high-entropy-string` and `sensitive-field-name`, when a more specific rule reports the same source name, line, field, and masked snippet.

#### `GlobalJobScanService`

- owns the background `Scan All Jobs` task
- allows only one global scan at a time
- updates `GlobalJobScanStatus` with total jobs, completed jobs, current job, findings counters, failures, and terminal state
- supports cooperative cancellation between jobs so large Jenkins instances do not block the UI behind a synchronous request

#### `WhitelistService`

Supports matching by:

- rule ID
- job full name
- field name

Whitelisted findings are converted to exempted findings with a generated reason so they still appear in reports.

#### `ExemptionService`

Parses entries in:

```text
jobFullName|ruleId|reason
```

If an entry matches the finding, the finding is re-emitted as exempted.

#### `ScanResultStore`

- singleton latest-result store
- keeps latest results in memory for fast reads
- writes masked latest-result XML files under `$JENKINS_HOME/secret-guard/results/`
- lazy-loads a target result from disk when it is missing from memory
- loads all result files for global reports and administrative monitor counts
- removes stale persisted results when a Job is renamed or deleted
- powers Job page, root page, and administrative monitor

Persisted results contain only report data such as rule IDs, severity, source location, masked snippets, recommendations, and exemption state. Raw scanned text and raw secret values are not persisted.

### Jenkins UI and Monitoring

- `SecretGuardJobAction`
  - shows latest findings for a job
  - exposes the `Scan Now` POST endpoint for on-demand re-scan
- `SecretGuardRunAction`
  - shows findings for a build
- `SecretGuardRootAction`
  - shows global summary
  - exposes the `Scan All Jobs` POST endpoint for manage users
  - runs `Scan All Jobs` asynchronously and shows a status badge, short summary, expandable details, failure list, cancellation controls, and a dismiss action for finished scan status
  - shows summary cards for unexempted high findings, blocked jobs, jobs with findings, total findings, and scanned jobs
  - sorts latest results by risk so blocked and actionable `HIGH` rows stay near the top
  - provides quick filters for `All`, `High`, `Blocked`, `With Findings`, `With Exemptions`, and `With Notes`
  - links each listed job to its job-level Secret Guard report
  - adds a `View report` action per row and compacts long target IDs while preserving the full value in the tooltip
  - shows exempted finding counts as compact badges in the `Findings` column without rendering exemption reasons
  - highlights blocked rows and uses blocked/allowed badges to make enforcement state easier to scan
  - renders severity values as colored badges so `LOW`, `MEDIUM`, and `HIGH` are easier to distinguish
- `SecretGuardAdministrativeMonitor`
  - activates when unexempted high-severity findings exist
  - uses the Jenkins native warning alert on `/manage/` and links directly to the Secret Guard system page

Jelly resources live under:

- `src/main/resources/io/jenkins/plugins/secretguard/action/...`
- `src/main/resources/io/jenkins/plugins/secretguard/config/...`
- `src/main/resources/io/jenkins/plugins/secretguard/monitor/...`

## Data and State Model

### What is persisted

- global configuration values through Jenkins `GlobalConfiguration`
- latest masked scan result per target under `$JENKINS_HOME/secret-guard/results/`
- whitelist text areas accept newline or comma separated entries, while exemptions accept one `jobFullName|ruleId|reason` entry per line with UI validation

### What is not persisted

- scan result history
- blocked event history
- raw scanned content
- raw secret values

This means the current UI can restore the latest report after restart, and restart coverage now verifies both Job and system report recovery, but it does not provide trends or historical snapshots.

## Testing Strategy

Current test coverage is intentionally focused on the deterministic core:

- `BuiltInSecretRuleSetTest`
  - high-confidence patterns
  - entropy findings
  - common false-positive guard for UUID
  - false-positive guards for credential IDs, hashes, public certificates, paths, and Docker images
  - URL query secret detection for webhook-style URLs
- `ConfigXmlScannerTest`
  - parameter default detection
  - sensitive config fields
  - whole inline Pipeline script scanning from `config.xml`
  - fixture-based false-positive coverage for stored artifact metadata, request headers, and public certificates
- `PipelineScriptScannerTest`
  - environment block detection
  - command step detection
  - hardcoded `httpRequest customHeaders` detection
  - webhook URL query secret detection
  - benign tracking header false-positive guards
  - fixture-based false-positive coverage for artifact publishing Pipelines
  - `withCredentials` examples for string, username/password, file, SSH private key, Git username/password, and username-colon-password bindings do not escalate to `HIGH`
- `SecretScanServiceTest`
  - block decision
  - whitelist effect
  - warn-mode handling
  - priority-based duplicate suppression
- `SecretGuardEnforcementIntegrationTest`
  - save/create/copy blocking
  - manual scan endpoint persistence
  - build-time RunAction serialization
  - Pipeline-from-SCM manual and build-time scanning through lightweight SCM access
- `ScanResultStoreTest`
  - latest result persistence and lazy reload
  - exemption state restoration
  - persisted result cleanup
  - persisted XML safety checks for raw scanned content and raw secret values
  - malformed and legacy persisted file tolerance
- `SecretMaskerTest`
  - JWT, URL credential, and PEM masking

Recommended next layer:

- UI smoke tests for Job and root actions
- multibranch-specific Jenkinsfile coverage
- SCM read failure reporting tests

## Safe Change Guidelines

### Adding a new rule

- prefer adding a new `SecretRule`
- keep remediation text explicit and actionable
- avoid broad regexes without negative tests

### Adding a new scanner

- keep extraction logic in the scanner
- keep blocking logic in `SecretScanService`
- keep Jenkins lifecycle decisions in listeners

### Changing enforcement behavior

- update `SecretScanService` first
- then verify listener behavior
- then add tests for all three modes

### Persisting results in the future

- treat `ScanResultStore` as the abstraction boundary
- keep `Action` classes read-only
- avoid pushing persistence logic into listeners directly
- extend the current latest-result files or add a separate history store if long-term retention is required

## Known Gaps

- Pipeline-from-SCM and multibranch support depend on SCM plugins exposing lightweight `SCMFileSystem` access
- save/create blocking intentionally does not perform SCM Jenkinsfile reads
- multibranch-specific indexing integration is not implemented
- no trend/history view exists

## Current Hardening Backlog

1. Expand runtime-expression regression coverage for forms such as `params['X'] ?: ''`, ternary expressions, safe-navigation calls, and additional method-chain transforms
2. Build a realistic Jenkinsfile false-positive corpus so common in-house Pipeline patterns stay covered by regression tests
3. Continue hardening `httpRequest customHeaders` parsing for more nested map/list layouts and mixed call styles

Completed hardening:

- Added `withCredentials` regression coverage for `file`, `sshUserPrivateKey`, `gitUsernamePassword`, and `usernameColonPassword`
- Treated `env.get('X')`, `params.get('X')`, and uppercase runtime variable method chains such as encoded username/password combinations as runtime references

## Suggested Next Steps

1. Add multibranch-specific Jenkinsfile coverage
2. Add optional Pipeline step support
3. Persist report history if auditability becomes a requirement
4. Expand plugin-specific adapters for common credential-bearing publishers and builders
