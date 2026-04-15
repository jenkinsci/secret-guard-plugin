# AGENTS.md

This file applies to the entire repository.

## Project summary

- This repository contains the Jenkins plugin `secret-guard`.
- The plugin detects hardcoded secret leakage in Jenkins job configuration and inline Pipeline definitions.
- The MVP is intentionally deterministic: no AI, no broad governance workflows, and no generic code-quality analysis.

## Tech stack

- Build tool: Maven (`pom.xml`)
- Packaging: Jenkins plugin (`hpi`)
- Language: Java
- Java / JDK: 17+
- Maven: 3.9.6+
- Test framework: JUnit 5
- UI layer: Jelly views under `src/main/resources`

## Repository map

- `src/main/java/io/jenkins/plugins/secretguard/action`: Jenkins actions for job, run, and root views
- `src/main/java/io/jenkins/plugins/secretguard/config`: global plugin configuration
- `src/main/java/io/jenkins/plugins/secretguard/listener`: save/build/item listeners
- `src/main/java/io/jenkins/plugins/secretguard/model`: domain model and enums
- `src/main/java/io/jenkins/plugins/secretguard/monitor`: administrative monitor
- `src/main/java/io/jenkins/plugins/secretguard/rules`: deterministic secret-detection rules
- `src/main/java/io/jenkins/plugins/secretguard/scan`: scanners for XML and Pipeline content
- `src/main/java/io/jenkins/plugins/secretguard/service`: orchestration, persistence, whitelist, and exemptions
- `src/main/java/io/jenkins/plugins/secretguard/util`: masking and heuristic helpers
- `src/test/java/io/jenkins/plugins/secretguard`: package-aligned unit tests
- `docs/`: architecture, implementation notes, and development plan

## Working rules

- Preserve the plugin's deterministic scope. Do not add AI-based detection or unrelated governance features unless explicitly requested.
- Favor high-confidence secret detection over aggressive heuristics that increase false positives.
- Never persist or expose raw secret values. Use masked snippets only.
- Keep enforcement policy centralized in `SecretScanService`; scanners should extract candidates and locations, not make block/warn decisions.
- Keep global runtime behavior in `SecretGuardGlobalConfiguration` rather than scattering policy flags across listeners or views.
- Put new detection logic in `rules/` or `scan/` based on responsibility:
  - use `rules/` for matching/classification logic
  - use `scan/` for extracting candidate values from XML or Pipeline text
- Keep UI/reporting code in actions, monitor, and Jelly files presentation-only.
- Follow existing code style: small focused classes, descriptive names, and minimal inline comments.

## Testing expectations

- After every code change, run `mvn spotless:apply` before finishing the task.
- Add or update focused unit tests for behavior changes in the corresponding `src/test/java` package.
- Prefer synthetic sample secrets in tests; never use real credentials or realistic live secrets.
- When practical, validate with the smallest relevant command first, for example:
  - `mvn -Dtest=SecretScanServiceTest test`
  - `mvn -Dtest=ConfigXmlScannerTest test`
- Use `mvn test` for broader verification when changes affect multiple areas.

## Change guidance

- For new detection rules, document the intended severity, scope, and false-positive tradeoff in code and tests.
- For new persisted data, ensure restart behavior is safe and stored content remains masked.
- For Jenkins UI/config changes, keep wording concise and administrator-focused.
- When changing `pom.xml` or dependencies, prefer staying aligned with the Jenkins plugin parent and BOM already declared in `pom.xml`.
- Keep docs in `README.md` or `docs/` in sync when behavior, configuration, or architecture meaningfully changes.
