# Jenkins Secret Guard Plugin Development Plan

## Purpose

This document turns the current MVP into an executable backlog. It separates immediate hardening work from feature expansion so the plugin can move from proof-of-MVP to production-ready releases without losing its focused boundary: detecting and preventing Jenkins secret leakage.

## Current Baseline

The current implementation includes:

- global configuration for enablement, mode, threshold, whitelist, and exemptions
- deterministic built-in secret rules
- `config.xml` scanner
- save-time extraction and scanning of inline Pipeline `<script>` content from Job XML
- inline Pipeline script scanner
- hardcoded `httpRequest customHeaders` detection, including `maskValue: false`
- URL query secret detection for webhook-style `?key=` / `?token=` patterns
- false-positive heuristics for credential IDs, hashes, public certificates, tracking headers, paths, and Docker images
- priority-based duplicate suppression for generic fallback rules
- save-time listener
- build-time listener for inline Pipeline jobs and lightweight Pipeline-from-SCM Jenkinsfiles
- manual Job `Scan Now` action
- Pipeline-from-SCM Jenkinsfile retrieval through `SCMFileSystem`
- disk-backed latest-result store under `$JENKINS_HOME/secret-guard/results/`
- Job, Run, root, and administrative report surfaces
- unit and JenkinsRule tests for rules, scanners, masking, service policy, save blocking, build scanning, manual scanning, and Pipeline-from-SCM coverage

Known limitations:

- Pipeline-from-SCM support depends on lightweight `SCMFileSystem` access
- multibranch-specific indexing integration is not implemented
- scan history is not retained beyond the latest result
- no export, trend, or history view exists
- no dedicated adapters for common plugin-specific credential fields

## Release Strategy

### MVP Hardening

Goal: make the current implementation safe enough for dogfooding in `AUDIT` or `WARN` mode.

Expected outcome:

- JenkinsRule tests cover lifecycle behavior
- core UI pages are smoke-tested
- known false positives are reduced
- save/build enforcement behavior is verified in real Jenkins test harness

### V1

Goal: make the plugin viable for production rollout in controlled environments.

Expected outcome:

- global scan-all action
- multibranch-specific Jenkinsfile support
- clearer admin UX
- better exemption validation

### V2

Goal: expand coverage and governance without turning the plugin into broad security tooling.

Expected outcome:

- historical reporting
- export support
- plugin-specific adapters
- optional AI-assisted explanations
- better policy granularity

## MVP Hardening Backlog

### 1. Add JenkinsRule lifecycle tests

Priority: `P0`

Status: save-time blocking, manual scan, Pipeline-from-SCM, multibranch, `AUDIT`/`WARN` save-flow, `WARN` build-result, and dedicated `BLOCK` build-failure flows are covered with JenkinsRule tests.

Tasks:

- add a save-time integration test for a Job containing plaintext `password` in config
- [x] verify `AUDIT` does not block
- [x] verify `WARN` does not block
- [x] verify `BLOCK` blocks unexempted `HIGH`
- add a Pipeline build test for inline script with bearer token
- [x] verify `WARN` marks the build `UNSTABLE`
- [x] verify `BLOCK` interrupts/fails the build

Acceptance criteria:

- tests fail if listeners stop firing
- tests fail if `BLOCK` no longer blocks actionable `HIGH`
- tests fail if `WARN` no longer marks build `UNSTABLE`

Implementation notes:

- use Jenkins test harness
- avoid relying only on unit tests for listener behavior
- keep test fixtures minimal and inline

### 2. Harden save-time blocking behavior

Priority: `P0`

Status: a dedicated `SecretGuardJobConfigFilter` now wraps Job create and update HTTP requests, restores the previous `config.xml` for blocked updates, deletes blocked newly created jobs, and returns a user-visible masked error response. `SecretGuardSaveableListener` remains in place for reporting-oriented scanning rather than primary save rejection.

Tasks:

- [x] verify whether `SaveableListener.onChange` exception propagation reliably rejects Job save in Jenkins UI and API flows
- [x] if unreliable, introduce a safer interception point for Job config submissions
- [x] ensure error message is user-visible and includes a short summary
- [x] avoid printing raw secret values in errors
- [ ] add broader regression coverage for additional config submission paths if new Jenkins UI/API entry points are introduced

Acceptance criteria:

- `BLOCK` mode reliably prevents saving a Job with unexempted `HIGH`
- saved config on disk remains unchanged after blocked save
- user-facing message contains rule ID and masked snippet only

Implementation notes:

- this is the most important production-hardening item
- keep `SaveableListener` for reporting once a safer interception point becomes primary

### 3. Expand false-positive regression corpus

Priority: `P1`

Status: regression coverage now includes placeholders plus anonymized Jenkinsfile and `config.xml` fixtures for public certificates, artifact metadata, and tracking-header cases, but the broader curated corpus is still incomplete.

Tasks:

- [x] add anonymized fixtures for common Jenkinsfiles and Job XML shapes
- [x] add regression cases for placeholder/mock/test values
- [x] add regression cases for public certificates and artifact metadata
- [x] add regression cases for common request/trace/correlation headers

Acceptance criteria:

- new false-positive fixes always include a fixture
- fixtures never contain real domains, tokens, host names, or internal paths
- high-confidence rules still detect real hardcoded secret shapes

### 4. Validate global configuration inputs

Priority: `P1`

Tasks:

- add form validation for exemption lines
- reject exemption entries without `jobFullName|ruleId|reason`
- warn on empty reason
- [x] document accepted whitelist separators

Acceptance criteria:

- invalid exemption syntax is visible in global config UI
- existing valid entries continue to load

### 5. Add UI smoke tests

Priority: `P2`

Status: action registration and administrative monitor activation are covered, but exempted-monitor suppression still needs a dedicated smoke test.

Tasks:

- [x] verify Job action is available
- [x] verify root action is available
- [x] verify administrative monitor activates when unexempted `HIGH` exists
- verify exempted findings do not activate the monitor

Acceptance criteria:

- tests catch missing Jelly resources or broken action registration

## V1 Backlog

### 1. Manual re-scan action

Priority: `P0`

Status: Job-level manual re-scan, latest-result refresh, and admin-only global re-scan are implemented.

Tasks:

- [x] add a Job-level “Scan now” action
- [x] scan current `config.xml`
- [x] store and display latest result
- [x] add global “scan all jobs” administrative action for admins
- [x] protect actions with appropriate Jenkins permissions

Acceptance criteria:

- admins can re-scan without saving a Job
- reports update immediately after manual scan
- [x] non-admin users cannot trigger global scans

### 2. Pipeline-from-SCM and multibranch support

Priority: `P0`

Status: ordinary Pipeline-from-SCM jobs and multibranch-specific Jenkinsfile reads are implemented through lightweight `SCMFileSystem`, and unavailable lightweight reads are surfaced as scan notes in Job, Run, and system reports.

Tasks:

- [x] detect Pipeline definitions that reference SCM
- [x] retrieve Jenkinsfile content through lightweight SCM access where safe and available
- [x] scan retrieved Jenkinsfile as `JENKINSFILE`
- [x] report source name as Jenkinsfile path
- [x] handle unavailable Jenkinsfile without failing the build
- [x] add multibranch-specific coverage
- [x] add explicit UI reporting for unavailable Jenkinsfile reads

Acceptance criteria:

- inline Pipeline behavior remains unchanged
- Pipeline-from-SCM jobs get scanned when Jenkinsfile content is available
- unavailable SCM content results in a clear audit message, not a hard failure

### 3. Latest-result persistence hardening

Priority: `P1`

Status: storage location and masked-only persistence behavior are now documented in `README.md`; deleted and renamed Job cleanup behavior is now verified; restart coverage, persisted-file safety checks, and malformed/legacy file tolerance checks are now in place.

Tasks:

- [x] add JenkinsRule restart coverage for latest-result reload
- [x] verify persisted files never include raw scanned content or raw secret values
- [x] validate cleanup behavior for deleted and renamed Jobs
- [x] document storage location and retention behavior in README

Acceptance criteria:

- Job and root reports survive controller restart
- storage never includes raw secret values
- deleted Jobs do not leave stale active report entries

### 4. Better report UX

Priority: `P1`

Status: the system page now shows summary counts, root-to-job links, blocked highlighting, quick filters for severity/findings/notes, relative scan times, and per-row report actions; detailed job reports are grouped by severity.

Tasks:

- [x] group findings by severity
- [x] show summary counts
- [x] link root report entries to Job report pages
- [x] highlight blocked findings separately
- [x] add concise remediation copy per rule

Acceptance criteria:

- admins can quickly identify unexempted `HIGH` findings
- report remains readable for jobs with many findings

### 5. Exemption management UX

Priority: `P2`

Status: not started.

Tasks:

- add structured exemption entries instead of plain text only
- include created by and created at metadata
- keep reason mandatory
- optionally support expiry date

Acceptance criteria:

- exemptions are auditable
- existing text format is migrated or still accepted

## V2 Backlog

Status: not started; current implementation remains focused on MVP hardening and V1 usability.

### 1. Plugin-specific configuration adapters

Priority: `P0`

Targets:

- HTTP Request plugin
- Git plugin credential-adjacent fields
- Kubernetes plugin environment fields
- common publisher/build-wrapper fields that persist strings

Tasks:

- identify plugin XML node patterns
- add adapter-style scanners or path classifiers
- provide plugin-specific remediation messages

Acceptance criteria:

- findings show meaningful plugin-specific locations
- adapters do not require all target plugins to be installed at compile time unless explicitly added as optional dependencies

### 2. Historical reporting and export

Priority: `P1`

Status: not started.

Tasks:

- store scan history with bounded retention
- add CSV or JSON export
- include scan time, target, rule ID, severity, masked snippet, and exemption state
- never export raw secret values

Acceptance criteria:

- administrators can export audit evidence
- retention limits prevent unbounded disk growth

### 3. Policy granularity

Priority: `P1`

Status: not started.

Tasks:

- add per-folder or per-job policy overrides
- support rule-level enforcement thresholds
- provide inheritance from global defaults

Acceptance criteria:

- global policy remains the default
- overrides are explicit and visible
- `BLOCK` behavior is deterministic after inheritance

### 4. Optional Pipeline step

Priority: `P2`

Status: not started.

Tasks:

- add a `secretGuard` Pipeline step
- allow teams to explicitly scan workspace files
- support fail/warn/audit behavior based on global or step-level options

Acceptance criteria:

- teams can scan checked-out Jenkinsfiles or generated scripts
- step output reuses the same finding model and reporting

### 5. AI-assisted explanations

Priority: `P2`

Status: not started.

Tasks:

- keep AI optional and disabled by default
- send only masked findings and surrounding non-secret metadata
- generate human-readable risk explanation
- generate safe remediation examples

Acceptance criteria:

- no raw secret is sent to an AI provider
- deterministic findings remain the source of truth
- AI output never changes enforcement decisions

## Test Matrix

| Area | MVP Hardening | V1 | V2 |
| --- | --- | --- | --- |
| Rules | unit tests for each rule and false positives | regression suite for custom additions | large corpus tests |
| XML scanning | parameter/env/plugin field tests | plugin adapter fixtures | compatibility fixtures |
| Pipeline scanning | inline Pipeline tests | SCM Jenkinsfile tests | Pipeline step tests |
| Enforcement | JenkinsRule save/build tests | manual scan tests | policy inheritance tests |
| UI | action and monitor smoke tests | report UX tests | export/history tests |
| Persistence | latest-result unit tests | restart survival tests | migration tests |

## Release Checklist

Before each release:

- run `mvn test`
- verify no raw secret values appear in logs, reports, or exported data
- verify default mode is safe for new installs
- verify README and docs match actual behavior
- verify all new rules include false-positive tests
- verify user-visible blocking messages are masked

## Current Hardening Backlog

1. `withCredentials` regression coverage for `file`, `sshUserPrivateKey`, `gitUsernamePassword`, and `usernameColonPassword`
2. runtime-expression regression coverage for `env.get('X')`, `params['X'] ?: ''`, ternary expressions, safe-navigation calls, and method chains
3. realistic Jenkinsfile false-positive corpus for common internal Pipeline patterns
4. `httpRequest customHeaders` edge-case parsing for deeper nesting and mixed single-line/multi-line call layouts

## Recommended Next Sprint

The next sprint should focus only on hardening:

1. `withCredentials` regression coverage for `file`, `sshUserPrivateKey`, `gitUsernamePassword`, and `usernameColonPassword`
2. runtime-expression regression coverage for `env.get('X')`, `params['X'] ?: ''`, ternary expressions, safe-navigation calls, and method chains
3. realistic Jenkinsfile false-positive corpus for common internal Pipeline patterns
4. `httpRequest customHeaders` edge-case parsing for deeper nesting and mixed single-line/multi-line call layouts
5. JenkinsRule lifecycle tests
6. save-time blocking reliability
7. config validation for exemptions
8. UI smoke tests

This keeps the MVP stable while continuing to reduce false positives before expanding coverage to multibranch-specific Jenkinsfile handling or historical reporting.
