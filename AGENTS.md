# AGENTS.md

This file applies to the entire repository.

## Project summary

- This repository contains the Jenkins plugin `secret-guard`.
- The plugin detects hardcoded secret leakage in Jenkins job configuration and inline Pipeline definitions.
- The plugin is intentionally deterministic: no AI, no broad governance workflows, and no generic code-quality analysis.

## Tech stack

- Java / JDK: 17+
- Maven: 3.9.6+ with Jenkins plugin packaging (`hpi`)
- Test framework: JUnit 5; UI layer: Jelly views under `src/main/resources`

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
- Never persist or expose raw secret values; use masked snippets only.
- Sanitize user-provided or internal-looking identifiers in code, tests, and docs. Prefer neutral placeholders such as `example.invalid`, `repo-host`, `build-tools`, and `SERVICE_TOKEN`.
- Keep enforcement policy centralized in `SecretScanService`, global runtime behavior in `SecretGuardGlobalConfiguration`, and extraction/detection responsibilities split between `scan/` and `rules/`.
- Keep UI/reporting code presentation-only and Jenkins-native, with concise administrator-facing wording and minimal Jelly/HTML structure.
- Follow existing code style: small focused classes, descriptive names, and minimal inline comments.

## Testing expectations

- After every code change, run `mvn spotless:apply` before finishing the task.
- Add or update focused tests for behavior changes in the corresponding `src/test/java` package.
- Prefer synthetic sample secrets and sanitized generic fixtures; never use real credentials or internal-looking domains, paths, or naming patterns.
- When practical, validate with the smallest relevant command first, for example:
  - `mvn -Dtest=SecretScanServiceTest test`
  - `mvn -Dtest=ConfigXmlScannerTest test`
- Use `mvn test` for broader verification when changes affect multiple areas.

## Change guidance

- For detection changes, document the intended severity, scope, and false-positive tradeoff in code and tests, and prefer heuristics/rules plus regression coverage over unrealistic fake examples.
- For new persisted data, ensure restart behavior is safe and stored content remains masked.
- When changing `pom.xml` or dependencies, prefer staying aligned with the Jenkins plugin parent and BOM already declared in `pom.xml`.

## Documentation rules

- Avoid MVP-stage wording in docs. Prefer `current implementation`, `core hardening`, `V1`, or `V2` depending on context.
- Keep `README.md` administrator-facing and concise: current capabilities, configuration entry points, scan actions, storage behavior, and troubleshooting.
- Keep `docs/architecture.md` focused on design goals, subsystem boundaries, tradeoffs, current boundaries, and extension points.
- Keep `docs/implementation.md` focused on package layout, class collaboration, implementation details, data/state behavior, testing strategy, and safe change guidance.
- Keep backlog, future work, status, stories, tasks, and acceptance criteria in `docs/development-plan.md`; do not duplicate backlog sections in README or implementation docs.
- Keep implementation details out of plan status paragraphs when a checklist is clearer; put scanner, adapter, heuristic, and persistence details in `docs/implementation.md`.
- Keep status text consistent with checklists: if a status says incomplete, include at least one unchecked task; if all tasks are checked, mark the story completed or implemented.
- Avoid conflicting parent/child status. For example, if any V2 story is started, do not describe the whole V2 backlog as not started.
- After documentation changes, search for stale wording such as `MVP`, `Current Hardening Backlog`, `Suggested Next Steps`, `Recommended next layer`, and `three levels`.
