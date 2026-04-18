# Jenkins Secret Guard Plugin

![Jenkins Secret Guard cover](docs/assets/secret-guard-cover-jenkins-shield.svg)

## Introduction

Jenkins Secret Guard detects hardcoded secret leakage risks in Jenkins jobs and Pipeline definitions.
It focuses only on high-risk secret exposure patterns, not general code style or broad security governance.

Current capabilities:

- save-time enforcement
- build-time scanning
- manual Job scans
- global `Scan All Jobs` reporting
- lightweight Pipeline-from-SCM and multibranch Jenkinsfile reads
- masked latest-result persistence
- plugin-aware false-positive reduction for common Jenkins patterns

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
- Manual `Scan Now` action on each Job page

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
        sh "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc123456789.def123456789'"
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

Whitelist entries are newline or comma separated. Exemptions use one entry per line:

```text
jobFullName|ruleId|reason
```

The global configuration page validates exemption lines and warns when the reason is empty.

Typical remediation guidance:

- Move plaintext tokens, passwords, and keys to Jenkins Credentials.
- Use `withCredentials` to inject secrets at runtime.
- Do not use secrets as build parameter default values.
- Do not persist secrets in Job configuration.
- Do not embed secrets in URLs or command-line arguments.

## Manual Scan

- Entry: each Job page has a `Secret Guard` side-panel entry with `Scan Now`.
- Scope: re-checks the current Job configuration, including inline Pipeline script content stored in `config.xml`, and Pipeline-from-SCM Jenkinsfile content when lightweight SCM access is available.
- Effect: refreshes the latest report for that Job only.
- Does not do: does not block the manual-scan action, does not block later saves, and does not change build results.
- Blocked field: the refreshed report still shows whether the current enforcement policy would classify the findings as blocked.

## Global Scan

- Entry: users with `Manage Jenkins` permission can open the global `Secret Guard` page and click `Scan All Jobs`.
- Scope: re-scans all Jenkins jobs in report-only mode, using the same latest-result refresh flow as Job-level manual scans.
- Effect: refreshes the latest persisted result for each scanned job.
- Does not do: does not block saves and does not change build results.
- Blocked field: each refreshed result still records whether the current enforcement policy would classify it as blocked.
- Page summary: shows cards for unexempted high findings, blocked jobs, jobs with findings, total findings, and scanned jobs.
- Result list: sorts by risk, supports `All`, `High`, `Blocked`, `With Findings`, `With Exemptions`, and `With Notes` filters, shows exempted-count badges, highlights blocked rows, and links to each job-level `Secret Guard` report.
- Storage: only masked latest-result data is persisted under `$JENKINS_HOME/secret-guard/results/`; raw scanned content and raw secret values are not stored.

## Troubleshooting

For Jenkins system log troubleshooting, enable the logger `io.jenkins.plugins.secretguard`.

Common log areas:

- scan flow: `[Manual Scan]`, `[Build Scan]`, `[Global Scan]`, `[Save Scan]`
- Pipeline source: `[Pipeline Source]`, `[Multibranch]`, `[SCM Read]`
- infrastructure: `[Item Sync]`, `[ClassLoader]`, `[Persistence]`, `[Heuristics]`

## Documentation

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Implementation guide: [`docs/implementation.md`](docs/implementation.md)
- Development plan: [`docs/development-plan.md`](docs/development-plan.md)

## Issues

Report issues and enhancements in the [Jenkins issue tracker](https://issues.jenkins.io/).

## Contributing

Refer to our [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)
