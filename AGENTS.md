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
- `src/main/java/io/jenkins/plugins/secretguard/listener`: build and item listeners plus job config interception
- `src/main/java/io/jenkins/plugins/secretguard/model`: domain model and enums
- `src/main/java/io/jenkins/plugins/secretguard/monitor`: administrative monitor
- `src/main/java/io/jenkins/plugins/secretguard/rules`: deterministic secret-detection rules
- `src/main/java/io/jenkins/plugins/secretguard/scan`: scanners for XML and Pipeline content
- `src/main/java/io/jenkins/plugins/secretguard/service`: orchestration, persistence, allow-list handling, and exemptions
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
- Keep UI markup CSP-friendly: no inline `<script>` or `<style>` tags, inline event handlers, or `style=` attributes; prefer external static assets under `src/main/webapp`.
- Prefer Jenkins-native UI building blocks over custom markup when available, for example `f:entry description`, `<f:enum>` for simple enum selectors, `jenkins-hidden` for toggled visibility, `t:progressBar` for progress display, and minimal Jelly forms that do not restate defaults such as `checkMethod="post"`.
- When presentation varies by state, return stable CSS class names from Java, prefer Jenkins semantic design tokens over hard-coded colors, apply table row highlighting to `td` cells, and snapshot mutable runtime values with `<j:set>` before branching.
- Follow existing code style: small focused classes, descriptive names, and minimal inline comments.

## Testing expectations

- After every code change, run `mvn spotless:apply` before finishing the task; documentation-only changes do not require it.
- Add or update focused tests for behavior changes in the corresponding `src/test/java` package.
- Prefer synthetic sample secrets and sanitized generic fixtures; never use real credentials or internal-looking domains, paths, or naming patterns.
- For CSP- or UI-related changes, add focused regression coverage that verifies external asset references, required render markers, and absence of inline `style=` usage where applicable.
- When practical, validate with the smallest relevant command first, for example:
  - `mvn -Dtest=SecretScanServiceTest test`
  - `mvn -Dtest=ConfigXmlScannerTest test`
- Use `mvn test` for broader verification when changes affect multiple areas.
- When touching Jelly views or Java-generated HTML, also consider a quick repository scan for inline markup patterns, for example `grep -RInE 'style=|<style|<script|\\son[a-zA-Z]+=' src/main/resources src/main/java src/main/webapp`.

## Change guidance

- For detection changes, document the intended severity, scope, and false-positive tradeoff in code and tests, and prefer heuristics/rules plus regression coverage over unrealistic fake examples.
- For new persisted data, ensure restart behavior is safe and stored content remains masked.
- When changing `pom.xml` or dependencies, stay aligned with the Jenkins plugin parent and BOM already declared in `pom.xml`, and declare cross-plugin UI/API dependencies explicitly rather than relying on transitive availability.
- For job save/config enforcement, keep HTTP save/create interception centralized in the servlet filter path, use listeners only for non-HTTP or fallback synchronization paths to avoid duplicate scans, and restore the previous persisted scan result when a blocked operation rolls configuration back.

## Documentation rules

- Avoid MVP-stage wording in docs. Prefer `current implementation`, `core hardening`, `V1`, or `V2` depending on context.
- Keep doc responsibilities separate: `README.md` stays administrator-facing and concise, `docs/architecture.md` covers design boundaries and tradeoffs, `docs/implementation.md` covers implementation details and safe change guidance, and `docs/development-plan.md` holds backlog, future work, status, stories, tasks, and acceptance criteria.
- Keep status text consistent with checklists and parent/child state, prefer checklists over long status paragraphs for implementation details, and after doc changes search for stale wording such as `MVP`, `Current Hardening Backlog`, `Suggested Next Steps`, `Recommended next layer`, and `three levels`.
