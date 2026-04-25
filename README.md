# Jenkins Secret Guard Plugin

[![GitHub release](https://img.shields.io/github/v/release/jenkinsci/secret-guard-plugin?sort=semver)](https://github.com/jenkinsci/secret-guard-plugin/releases)
[![Jenkins Plugin Site](https://img.shields.io/badge/Jenkins-Plugin%20Site-D24939?logo=jenkins&logoColor=white)](https://plugins.jenkins.io/secret-guard)
[![Jenkins Security Scan](https://github.com/jenkinsci/secret-guard-plugin/actions/workflows/jenkins-security-scan.yml/badge.svg)](https://github.com/jenkinsci/secret-guard-plugin/actions/workflows/jenkins-security-scan.yml)
[![codecov](https://codecov.io/github/jenkinsci/secret-guard-plugin/graph/badge.svg)](https://app.codecov.io/github/jenkinsci/secret-guard-plugin)
[![License](https://img.shields.io/github/license/jenkinsci/secret-guard-plugin)](LICENSE.md)

![Jenkins Secret Guard cover](docs/assets/secret-guard-cover-jenkins-shield.svg)

## Introduction

Jenkins Secret Guard detects hardcoded secret leakage risks in Jenkins jobs and Pipeline definitions.
It focuses only on high-risk secret exposure patterns, not general code style or broad security governance.

Key capabilities:

- save-time enforcement
- build-time scanning
- Job-level `Scan Now`
- global `Scan All Jobs`
- lightweight Pipeline-from-SCM and multibranch Jenkinsfile reads
- masked latest-result persistence
- plugin-aware false-positive reduction for common Jenkins patterns

## Why this plugin exists

Secret Guard is built around leakage patterns that repeatedly show up in Jenkins and Jenkins-plugin usage:

- plaintext tokens, passwords, or API keys placed directly in Job `config.xml`
- parameter defaults or environment values that persist secrets in Job configuration
- inline Pipeline literals such as `Authorization: Bearer ...`
- webhook or notifier URLs that carry secrets in query parameters or path segments

This plugin intentionally focuses on those deterministic, repeatedly observed shapes.
It does not try to infer arbitrary intent from general Groovy or XML content.

## Getting started

Configure the plugin from **Manage Jenkins → Jenkins Secret Guard**.

Supported scan targets:

- Job `config.xml`
- Pipeline inline scripts
- Pipeline-from-SCM Jenkinsfiles when lightweight `SCMFileSystem` access is available
- Multibranch Pipeline Jenkinsfiles when lightweight `SCMFileSystem` access is available
- Build parameter default values
- Environment variable definitions
- `sh`, `bat`, `powershell`, and HTTP request style command content

Enforcement modes:

- `AUDIT`: records findings and never blocks.
- `WARN`: allows saves and marks builds `UNSTABLE` when findings are present.
- `BLOCK`: blocks unexempted findings at or above the configured threshold, defaulting to `HIGH`.

Example risky Pipeline:

```groovy
pipeline {
  agent any
  environment {
    API_TOKEN = 'ghp_012345678901234567890123456789012345'
  }
  stages {
    stage('call api') {
      steps {
        sh "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc123456789.def123456789' https://example.invalid"
      }
    }
  }
}
```

Safer pattern:

```groovy
pipeline {
  agent any
  stages {
    stage('call api') {
      steps {
        withCredentials([string(credentialsId: 'api-token', variable: 'API_TOKEN')]) {
          sh 'curl -H "Authorization: Bearer $API_TOKEN" https://example.invalid'
        }
      }
    }
  }
}
```

Allow list entries are newline or comma separated. Exemptions use one entry per line:

```text
jobFullName|ruleId|reason
```

The global configuration page validates exemption lines and warns when the reason is empty.

Typical remediation guidance:

- Move plaintext secrets to Jenkins Credentials.
- Use `withCredentials` to inject them at runtime.
- Avoid storing secrets in parameter defaults, Job configuration, URLs, or command lines.

## Scanning

- **Job scan**
  - Entry: each Job page has a `Secret Guard` side-panel entry with `Scan Now`.
  - Scope: re-checks the current Job configuration, including inline Pipeline content and Pipeline-from-SCM Jenkinsfile content when lightweight SCM access is available.
  - Effect: refreshes the latest report for that Job only.
  - Behavior: report-only; it does not block the scan action or change build results, but the report still shows whether findings would be blocked by current policy.

![Secret Guard Job Action Page](docs/assets/secret-guard-job-action-page-screenshot.png)

- **Global scan**
  - Entry: users with `Manage Jenkins` permission can open the global `Secret Guard` page and click `Scan All Jobs`.
  - Scope: re-scans all Jenkins jobs in report-only mode using the same latest-result refresh flow.
  - Effect: refreshes the latest persisted result for each scanned job.
  - Behavior: does not block saves or change build results; the page still records whether current policy would classify findings as blocked.
  - UI: shows summary cards, filterable results, exempted-count badges, blocked-row highlighting, and links to each Job report.
  - Storage: only masked latest-result data is persisted under `$JENKINS_HOME/secret-guard/results/`; raw scanned content and raw secret values are not stored.

![Secret Guard Root Action Page](docs/assets/secret-guard-root-action-page-screenshot.png)

## Troubleshooting

For Jenkins system log troubleshooting, enable the logger `io.jenkins.plugins.secretguard`.

Common log areas:

- scan flow: `[Manual Scan]`, `[Build Scan]`, `[Global Scan]`
- Pipeline source: `[Pipeline Source]`, `[Multibranch]`, `[SCM Read]`
- infrastructure: `[Item Sync]`, `[ClassLoader]`, `[Persistence]`, `[Heuristics]`

## Documentation

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Detection coverage: [`docs/detection-coverage.md`](docs/detection-coverage.md)
- Implementation guide: [`docs/implementation.md`](docs/implementation.md)
- Development plan: [`docs/development-plan.md`](docs/development-plan.md)

## GitHub Issues

Report issues and enhancements in [GitHub issues](https://github.com/jenkinsci/secret-guard-plugin/issues).

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)
