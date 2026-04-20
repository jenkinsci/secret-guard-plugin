# Jenkins Secret Guard Plugin Architecture

## Overview

Jenkins Secret Guard is a focused Jenkins plugin for detecting and preventing secret leakage in:

- Job `config.xml`
- Pipeline inline scripts
- Pipeline-from-SCM Jenkinsfiles when lightweight SCM access is available
- Multibranch Pipeline Jenkinsfiles when lightweight SCM access is available
- Build parameter default values
- Environment variable definitions
- Command steps such as `sh`, `bat`, and `powershell`

The implementation is intentionally deterministic:

- no AI
- no generic code-quality rules
- no broad governance workflows

## Why this plugin exists

The plugin scope comes from recurring, publicly documented Jenkins leakage shapes rather than hypothetical secret hunting.
Across Jenkinsfiles, Job XML, and plugin configuration examples, the same families keep appearing:

- credentials copied directly into Job fields such as `token`, `password`, `secret`, or `apiKey`
- parameter defaults or environment definitions that persist plaintext secrets in `config.xml`
- inline Pipeline header literals such as `Authorization: Bearer ...`
- notifier or webhook URLs whose query string carries a secret like `token`, `key`, `signature`, or similar variants
- integration endpoints that look like normal URLs but embed a token directly in the path

That history explains the architecture choices:

- text and XML scanning are enough for the highest-value cases
- deterministic rules are preferred over broad inference
- URL, header, and sensitive-field handling are first-class because those are common leak carriers
- false-positive reduction matters because many Jenkins jobs also store readable endpoints, identifiers, and references that are not secrets

The core flow is:

```mermaid
flowchart LR
    A["Jenkins Save / Build Event"] --> B["Filter / Listener Entry Point"]
    B --> C["ScanContext"]
    C --> D["SecretScanner"]
    D --> E["BuiltInSecretRuleSet"]
    E --> F["SecretFinding[]"]
    F --> G["AllowListService / ExemptionService"]
    G --> H["SecretScanService"]
    H --> I["ScanResultStore"]
    H --> J["Mode Decision (Audit/Warn/Block)"]
    I --> K["Job / Run / Root Actions"]
    I --> L["AdministrativeMonitor"]
```

## Design Goals

- Detect plaintext secrets with high-confidence rules first
- Block only actionable `HIGH` findings in `BLOCK` mode
- Keep reporting and enforcement consistent across save-time and build-time scans
- Make findings human-readable with masking and fixed remediation guidance
- Keep configuration simple enough for Jenkins administrators to adopt quickly

## Subsystems

### 1. Configuration

`SecretGuardGlobalConfiguration` is the single source of truth for runtime behavior:

- plugin enabled flag
- enforcement mode: `AUDIT`, `WARN`, `BLOCK`
- block threshold, default `HIGH`
- rule ID allow list
- job allow list
- field name allow list
- exemptions in `jobFullName|ruleId|reason` format

The configuration is stored using Jenkins `GlobalConfiguration`, so no external storage is required for policy settings.

### 2. Domain Model

The model layer standardizes scanning and reporting:

- `Severity`: `LOW`, `MEDIUM`, `HIGH`
- `EnforcementMode`: `AUDIT`, `WARN`, `BLOCK`
- `FindingLocationType`: location classification for XML, Pipeline, environment, parameter default, and command steps
- `ScanPhase`: `SAVE`, `BUILD`, `MANUAL`
- `ScanContext`: immutable scan metadata
- `SecretFinding`: one rule hit with masked snippet and remediation text
- `SecretScanResult`: scan summary with findings, scan notes, highest severity, and blocked flag

This model keeps scanners, listeners, and UI layers loosely coupled.

### 3. Rule Engine

`BuiltInSecretRuleSet` registers all built-in deterministic rules. Rules implement `SecretRule` and produce findings from:

- field names
- raw values
- context
- source location

Built-in rules cover:

- sensitive field names such as `token`, `password`, `secret`, `apikey`, `accessKey`, `clientSecret`
- JWTs
- GitHub tokens
- AWS access keys and common secret key patterns
- bearer tokens
- PEM private keys
- credentials embedded in URLs
- secret-bearing URL query parameters such as webhook `?key=` and `?token=`
- hardcoded `httpRequest customHeaders` values, including `maskValue: false`
- high-entropy candidate strings

High-confidence contextual rules take priority over generic fallback rules. For example, when an `httpRequest customHeaders` value is detected, the generic `high-entropy-string` finding for the same line, field, and masked snippet is suppressed.

### 4. Scanners

Two scanners implement `SecretScanner`:

- `ConfigXmlScanner`
  - parses Job `config.xml`
  - walks XML elements and attributes
  - classifies parameter defaults and environment-related nodes
  - extracts inline Pipeline `<script>` contents from Job XML and re-scans the entire script with `PipelineScriptScanner`
  - falls back to raw line scanning when XML parsing fails
- `PipelineScriptScanner`
  - scans Pipeline text line by line
  - tracks `environment {}` scope
  - classifies command steps and HTTP-style secret usage
  - parses literal `httpRequest customHeaders` lists into per-header entries so `name`, `value`, and `maskValue` are evaluated together across single-line and multi-line layouts
  - detects URL query secrets in shell commands and other script strings, such as webhook URLs with hardcoded `key` or `token` parameters
  - avoids heavy Groovy parsing by design

Pipeline definitions are extracted through `PipelineDefinitionExtractor`:

- inline Pipeline definitions are read from `getDefinition().getScript()`
- Pipeline-from-SCM definitions are read from the configured `scriptPath`, defaulting to `Jenkinsfile`
- multibranch branch jobs are resolved from branch metadata, `SCMSourceOwner`, and `scriptPath`
- SCM Jenkinsfile content is retrieved through Jenkins `SCMFileSystem` lightweight access
- unsupported SCMs or unreadable Jenkinsfiles are skipped without failing saves or builds, and the skipped read is surfaced as a scan note

The scanner layer is responsible for extracting candidate values and location metadata, not for enforcement.

### 5. Orchestration and Policy

`SecretScanService` is the central coordinator:

- executes the scanner
- applies allow lists
- applies exemptions
- suppresses lower-priority duplicate findings when a more specific rule matches the same source location
- computes whether the result should block
- persists the latest result into `ScanResultStore`

Policy behavior:

- `AUDIT`: record only
- `WARN`: record and allow continuation; build listeners may mark `UNSTABLE`
- `BLOCK`: block only when an unexempted finding is at or above the threshold

### 6. Jenkins Integration

The plugin integrates across save-time, build-time, manual-scan, and reporting entry points:

- `SecretGuardJobConfigFilter`
  - intercepts Job create and config update HTTP requests
  - runs the save-time scan for filter-managed create and update requests
  - restores the prior `config.xml` or deletes a newly created Job when `BLOCK` mode rejects the change
  - restores the previous persisted latest result when a blocked save is rolled back
- `SecretGuardItemListener`
  - refreshes scan results for non-filter item lifecycle updates
  - blocks copying a risky Job before the copy is created in `BLOCK` mode
  - removes persisted latest results for deleted Jobs
  - removes the old persisted key and re-scans when a Job location changes
  - complements filter-managed save-time enforcement for copy, delete, rename, move, and fallback synchronization paths
- `SecretGuardRunListener`
  - scans inline Pipeline scripts and lightweight Pipeline-from-SCM Jenkinsfiles at build start
  - adds a run action report
  - marks builds `UNSTABLE` in `WARN`
  - interrupts builds in `BLOCK`
- `GlobalJobScanService`
  - runs `Scan All Jobs` as a background task
  - tracks progress, current job, summary counters, and cancellation state for the system page

### 7. Reporting

Results are exposed through:

- `SecretGuardJobAction`
- `SecretGuardRunAction`
- `SecretGuardRootAction`
- `GlobalJobScanStatus`
- `SecretGuardAdministrativeMonitor`

Job-level reports are available on each Job page so users can run `Scan Now` even before a previous scan result exists.

`ScanResultStore` keeps the latest result in memory and persists one masked latest-result XML file per target under `$JENKINS_HOME/secret-guard/results/`. Reports can be restored lazily after a controller restart without storing raw secret values, and restart coverage verifies Job and root report recovery.
Persisted latest results include scan notes, so Job and system reports keep SCM-read diagnostics after a controller restart.

## Current Boundaries

The current implementation deliberately does not include:

- SCM checkout fallback when lightweight `SCMFileSystem` access is unavailable
- multibranch-specific branch indexing integration
- Groovy AST or taint analysis
- plugin-specific deep adapters for every Jenkins plugin
- history trends or long-term scan retention
- approval workflows for exemptions
- AI explanation or remediation generation

## Extension Points

Recommended evolution path:

1. Add more `SecretRule` implementations without changing listener code
2. Expand plugin-specific configuration adapters
3. Add historical result retention if trend or audit reporting becomes required
4. Add Pipeline step support for explicit in-pipeline scans
5. Add SCM fallback strategies where lightweight Jenkinsfile reads are unavailable

## Key Tradeoffs

- **Text scanning over AST parsing**
  - faster to implement
  - easier to reason about
  - may miss deeper semantic misuse
- **Latest-result persistence**
  - keeps restart behavior predictable for latest reports
  - stores only masked snippets, not raw secret values
  - does not provide historical trends
- **Global configuration only**
  - easy to administer
  - less granular than per-job policy

## Operational Notes

- Use `WARN` first in production rollout to measure noise
- Tighten to `BLOCK` only after tuning allow lists and exemptions
- Review global high-severity findings through the root action and administrative monitor
- Keep exemption reasons specific so future audits remain understandable
