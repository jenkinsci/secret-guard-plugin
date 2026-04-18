# AGENTS.md

This file applies to the entire repository.

## Project summary

- This repository contains the Jenkins plugin `secret-guard`.
- The plugin detects hardcoded secret leakage in Jenkins job configuration and inline Pipeline definitions.
- The plugin is intentionally deterministic: no AI, no broad governance workflows, and no generic code-quality analysis.

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
- Do not copy user-provided real-looking variable names, header names, URLs, repository paths, host names, or other internal identifiers directly into source, tests, or docs; always sanitize them to neutral, readable placeholders.
- When creating examples, fixtures, or regression cases, prefer neutral names such as `example.invalid`, `repo-host`, `build-tools`, `SERVICE_TOKEN`, and similar generic placeholders over internal naming patterns.
- Keep enforcement policy centralized in `SecretScanService`; scanners should extract candidates and locations, not make block/warn decisions.
- Keep global runtime behavior in `SecretGuardGlobalConfiguration` rather than scattering policy flags across listeners or views.
- Put new detection logic in `rules/` or `scan/` based on responsibility:
  - use `rules/` for matching/classification logic
  - use `scan/` for extracting candidate values from XML or Pipeline text
- Keep UI/reporting code in actions, monitor, and Jelly files presentation-only.
- Prefer Jenkins-native UI patterns and behaviors for Jelly/admin pages, including warning styles, dismiss actions, button placement, and concise administrator-facing wording.
- Keep Jelly/HTML structure minimal and avoid unnecessary wrapper elements when existing layout already provides them.
- Follow existing code style: small focused classes, descriptive names, and minimal inline comments.

## Testing expectations

- After every code change, run `mvn spotless:apply` before finishing the task.
- Add or update focused unit tests for behavior changes in the corresponding `src/test/java` package.
- Prefer synthetic sample secrets in tests; never use real credentials or realistic live secrets.
- Do not reuse internal-looking domains, API paths, repository addresses, or naming conventions in tests; sanitize all fixtures to generic examples.
- When practical, validate with the smallest relevant command first, for example:
  - `mvn -Dtest=SecretScanServiceTest test`
  - `mvn -Dtest=ConfigXmlScannerTest test`
- Use `mvn test` for broader verification when changes affect multiple areas.

## Change guidance

- For new detection rules, document the intended severity, scope, and false-positive tradeoff in code and tests.
- For new persisted data, ensure restart behavior is safe and stored content remains masked.
- For Jenkins UI/config changes, keep wording concise and administrator-focused.
- For false-positive fixes, prefer improving heuristics/rules and adding regression coverage instead of changing examples into unrealistic fake configurations merely to silence detection.
- When changing `pom.xml` or dependencies, prefer staying aligned with the Jenkins plugin parent and BOM already declared in `pom.xml`.
- Keep docs in `README.md` or `docs/` in sync when behavior, configuration, or architecture meaningfully changes.

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
