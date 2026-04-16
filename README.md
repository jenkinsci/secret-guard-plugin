# Jenkins Secret Guard Plugin

## Introduction

Jenkins Secret Guard detects hardcoded secret leakage risks in Jenkins jobs and Pipeline definitions.
It focuses only on high-risk secret exposure patterns, not general code style or broad security governance.

## Getting started

Configure the plugin from **Manage Jenkins → Jenkins Secret Guard**.

Supported MVP scan targets:

- Job `config.xml`
- Pipeline inline scripts
- Pipeline-from-SCM Jenkinsfiles when lightweight `SCMFileSystem` access is available
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

Typical remediation guidance:

- Move plaintext tokens, passwords, and keys to Jenkins Credentials.
- Use `withCredentials` to inject secrets at runtime.
- Do not use secrets as build parameter default values.
- Do not persist secrets in Job configuration.
- Do not embed secrets in URLs or command-line arguments.

## Manual Scan

Each Job page exposes a `Scan Now` action through the `Secret Guard` side-panel entry.
The manual scan re-checks the current Job `config.xml`, inline Pipeline script content, and Pipeline-from-SCM Jenkinsfile content when lightweight SCM access is available, then refreshes the latest report for that Job.
Manual scan only updates the report and does not block saves or change build results.

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
