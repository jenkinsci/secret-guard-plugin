# Jenkins Secret Guard Plugin Implementation Guide

## Purpose

This document explains how the current MVP is implemented, how the main classes collaborate, and where to add future functionality safely.

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
7. `SecretGuardSaveableListener` and `SecretGuardItemListener` refresh the persisted latest result for reporting

### Build-time flow

1. Jenkins starts a build
2. `SecretGuardRunListener` tries to extract inline Pipeline script from the job definition
3. `PipelineScriptScanner` scans the script text
4. `SecretScanService` post-processes the findings
5. `SecretGuardRunAction` is attached to the build
6. Depending on mode:
   - `AUDIT`: log/report only
   - `WARN`: mark build `UNSTABLE`
   - `BLOCK`: interrupt build with `FAILURE`

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
- `SecretScanResult`
  - holds findings, highest severity, blocked flag, and scan timestamp
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
- tracks multi-line `httpRequest customHeaders` blocks
- detects hardcoded custom header literals and separately reports `maskValue: false`
- detects hardcoded secrets embedded in URL query parameters such as `?key=...` and `?token=...`
- passes header names into generic rules so benign tracking headers do not trigger high-entropy false positives
- keeps implementation text-based so it does not require Pipeline AST integration

#### `NonSecretHeuristics`

- centralizes false-positive suppression for common non-secret values
- skips credential ID fields such as `credentialsId` and `credentialId`
- skips paths, Docker image references, hash/checksum/digest/commit contexts, public certificates, and trace/request ID headers
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
- `SecretGuardRunAction`
  - shows findings for a build
- `SecretGuardRootAction`
  - shows global summary
  - links each listed job to its job-level Secret Guard report
  - renders severity values as colored badges so `LOW`, `MEDIUM`, and `HIGH` are easier to distinguish
- `SecretGuardAdministrativeMonitor`
  - activates when unexempted high-severity findings exist

Jelly resources live under:

- `src/main/resources/io/jenkins/plugins/secretguard/action/...`
- `src/main/resources/io/jenkins/plugins/secretguard/config/...`
- `src/main/resources/io/jenkins/plugins/secretguard/monitor/...`

## Data and State Model

### What is persisted

- global configuration values through Jenkins `GlobalConfiguration`
- latest masked scan result per target under `$JENKINS_HOME/secret-guard/results/`

### What is not persisted

- scan result history
- blocked event history
- raw scanned content
- raw secret values

This means the current UI can restore the latest report after restart, but it does not provide trends or historical snapshots.

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
- `PipelineScriptScannerTest`
  - environment block detection
  - command step detection
  - hardcoded `httpRequest customHeaders` detection
  - webhook URL query secret detection
  - benign tracking header false-positive guards
  - `withCredentials` example does not escalate to `HIGH`
- `SecretScanServiceTest`
  - block decision
  - whitelist effect
  - warn-mode handling
  - priority-based duplicate suppression
- `ScanResultStoreTest`
  - latest result persistence and lazy reload
  - exemption state restoration
  - persisted result cleanup
- `SecretMaskerTest`
  - JWT, URL credential, and PEM masking

Recommended next layer:

- JenkinsRule integration tests for save blocking
- JenkinsRule integration tests for build `UNSTABLE` and `FAILURE`
- UI smoke tests for Job and root actions

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

- build-time scanning only covers inline Pipeline scripts exposed by `getDefinition().getScript()`
- external SCM `Jenkinsfile` retrieval is not implemented
- save/create blocking still needs deeper JenkinsRule coverage for UI and XML API flows
- report storage is volatile
- no trend/history view exists

## Suggested Next Steps

1. Add JenkinsRule tests for save/build enforcement
2. Support Pipeline-from-SCM / multibranch `Jenkinsfile`
3. Add optional manual re-scan action
4. Persist report history if auditability becomes a requirement
5. Expand plugin-specific adapters for common credential-bearing publishers and builders
