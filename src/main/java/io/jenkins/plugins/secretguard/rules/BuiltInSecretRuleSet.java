package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BuiltInSecretRuleSet {
    private static final Logger LOGGER = Logger.getLogger(BuiltInSecretRuleSet.class.getName());
    private static final Pattern SENSITIVE_FIELD = Pattern.compile(
            "(?i)(token|password|passphrase|secret|api[_-]?key|apikey|access[_-]?key|accessKey|clientSecret)");
    private static final Pattern SIMPLE_ASSIGNMENT_LITERAL =
            Pattern.compile("\\b([A-Za-z_]\\w*)\\s*=\\s*(['\"])([^'\"]+)\\2");

    private final List<SecretRule> rules;

    public BuiltInSecretRuleSet() {
        List<SecretRule> builtIns = new ArrayList<>();
        builtIns.add(new SensitiveFieldRule());
        builtIns.add(new PatternSecretRule(
                "jwt-token",
                "JWT token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "github-token",
                "GitHub token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{60,255})\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "aws-access-key",
                "AWS access key is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "aws-secret-key",
                "AWS secret key pattern is hardcoded",
                Severity.HIGH,
                Pattern.compile(
                        "(?i)(?:aws(.{0,20})?)?(?:secret|secretAccessKey|secret_access_key)['\"\\s:=]+([A-Za-z0-9/+=]{40})"),
                Recommendations.CREDENTIALS,
                2));
        builtIns.add(new PatternSecretRule(
                "bearer-token",
                "Bearer token is hardcoded",
                Severity.HIGH,
                Pattern.compile("(?i)\\bBearer\\s+([A-Za-z0-9._~+/=-]{12,})"),
                Recommendations.NO_COMMAND_LINE_SECRET,
                1));
        builtIns.add(new PatternSecretRule(
                "slack-bot-token",
                "Slack bot token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\bxoxb-[0-9]{8,}(?:-[0-9]{8,})?-[A-Za-z0-9-]{20,}\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "pypi-api-token",
                "PyPI API token is hardcoded",
                Severity.HIGH,
                Pattern.compile("\\bpypi-[A-Za-z0-9_-]{60,}\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "gitlab-token",
                "GitLab token is hardcoded",
                Severity.HIGH,
                Pattern.compile(
                        "\\b(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_-]{20,}\\b"),
                Recommendations.CREDENTIALS));
        builtIns.add(new BasicAuthHeaderRule());
        builtIns.add(new NpmAuthTokenContextRule());
        builtIns.add(new NpmLegacyAuthContextRule());
        builtIns.add(new JfrogAccessTokenContextRule());
        builtIns.add(new CommandUserPasswordContextRule());
        builtIns.add(new DockerPasswordStdinContextRule());
        builtIns.add(new PyPiPasswordContextRule());
        builtIns.add(new KubernetesSecretLiteralContextRule());
        builtIns.add(new PatternSecretRule(
                "pem-private-key",
                "PEM private key is hardcoded",
                Severity.HIGH,
                Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
                Recommendations.CREDENTIALS));
        builtIns.add(new PatternSecretRule(
                "url-embedded-secret",
                "Credential is embedded in a URL",
                Severity.HIGH,
                Pattern.compile("(?i)https?://[^\\s:/@'\"<>]+:[^\\s/@'\"<>]{6,}@[^\\s'\"<>]+"),
                Recommendations.NO_URL_SECRET));
        builtIns.add(new DatabaseConnectionStringRule(
                "mysql-connection-url",
                "MySQL connection string contains a hardcoded password",
                Pattern.compile("(?i)\\b(?:jdbc:)?mysql://[^\\s'\"<>]+")));
        builtIns.add(new DatabaseConnectionStringRule(
                "postgres-connection-string",
                "PostgreSQL connection string contains a hardcoded password",
                Pattern.compile("(?i)\\b(?:jdbc:)?postgres(?:ql)?://[^\\s'\"<>]+")));
        builtIns.add(new ProviderWebhookUrlRule(
                "slack-webhook-url",
                "Slack webhook URL is hardcoded",
                Pattern.compile("https://hooks\\.slack\\.com/services/[^\\s'\"<>]{40,}", Pattern.CASE_INSENSITIVE)));
        builtIns.add(new ProviderWebhookUrlRule(
                "teams-webhook-url",
                "Microsoft Teams webhook URL is hardcoded",
                Pattern.compile(
                        "https://(?:[^/]+\\.)?(?:webhook\\.office\\.com|outlook\\.office(?:365)?\\.com)/(?:webhook|webhookb2)/[^\\s'\"<>]*/IncomingWebhook/[^\\s'\"<>]{12,}",
                        Pattern.CASE_INSENSITIVE)));
        builtIns.add(new ProviderWebhookUrlRule(
                "zapier-webhook-url",
                "Zapier webhook URL is hardcoded",
                Pattern.compile(
                        "https://hooks\\.zapier\\.com/hooks/catch/\\d+/[A-Za-z0-9]{6,}(?:/[^\\s'\"<>]*)?",
                        Pattern.CASE_INSENSITIVE)));
        builtIns.add(new UrlQuerySecretRule());
        builtIns.add(new NotifierUrlSecretRule());
        builtIns.add(new HighEntropyRule());
        this.rules = Collections.unmodifiableList(builtIns);
    }

    public List<SecretRule> getRules() {
        return rules;
    }

    private static boolean isSensitiveField(String fieldName) {
        return fieldName != null && SENSITIVE_FIELD.matcher(fieldName).find();
    }

    private static boolean looksLikeSafeReference(String value) {
        return NonSecretHeuristics.looksLikeSafeReference(value);
    }

    private static String normalizeAssignedLiteralValue(String fieldName, String value) {
        if (fieldName == null || fieldName.isBlank() || value == null || value.isBlank()) {
            return value;
        }
        Matcher matcher = SIMPLE_ASSIGNMENT_LITERAL.matcher(value);
        if (matcher.find() && fieldName.equals(matcher.group(1))) {
            return matcher.group(3);
        }
        return value;
    }

    private static SecretFinding finding(
            String ruleId,
            String title,
            Severity severity,
            ScanContext context,
            String sourceName,
            int lineNumber,
            String fieldName,
            String matchedValue,
            String recommendation) {
        return finding(
                ruleId, title, severity, context, sourceName, lineNumber, fieldName, matchedValue, recommendation, "");
    }

    private static SecretFinding finding(
            String ruleId,
            String title,
            Severity severity,
            ScanContext context,
            String sourceName,
            int lineNumber,
            String fieldName,
            String matchedValue,
            String recommendation,
            String analysisNote) {
        return new SecretFinding(
                        ruleId,
                        title,
                        severity,
                        context.getLocationType(),
                        context.getJobFullName(),
                        sourceName,
                        lineNumber,
                        fieldName,
                        SecretMasker.mask(matchedValue),
                        recommendation,
                        analysisNote)
                .withEvidenceKeyFromValue(matchedValue);
    }

    private static final class SensitiveFieldRule implements SecretRule {
        @Override
        public String getId() {
            return "sensitive-field-name";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            String normalizedValue = normalizeAssignedLiteralValue(fieldName, value);
            if (!isSensitiveField(fieldName) || NonSecretHeuristics.isCredentialIdField(fieldName)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikeCredentialBindingVariableReference(fieldName, normalizedValue)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikeSensitiveFileReference(fieldName, normalizedValue)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikeReadableEndpointUrl(normalizedValue)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikePlaceholderValue(normalizedValue)) {
                return List.of(finding(
                        getId(),
                        "Sensitive field contains a placeholder-like value",
                        Severity.LOW,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        normalizedValue,
                        Recommendations.PLACEHOLDER,
                        "Downgraded because the value looks like a redaction placeholder instead of a real secret."));
            }
            if (looksLikeSafeReference(normalizedValue)) {
                return Collections.emptyList();
            }
            Severity severity = normalizedValue.trim().length() >= 8 ? Severity.HIGH : Severity.LOW;
            String recommendation = context.getLocationType().name().contains("CONFIG")
                    ? Recommendations.NO_CONFIG_SECRET
                    : Recommendations.CREDENTIALS;
            return List.of(finding(
                    getId(),
                    "Sensitive field contains a plaintext value",
                    severity,
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    normalizedValue,
                    recommendation));
        }
    }

    private static final class PatternSecretRule implements SecretRule {
        private final String id;
        private final String title;
        private final Severity severity;
        private final Pattern pattern;
        private final String recommendation;
        private final int matchingGroup;

        private PatternSecretRule(String id, String title, Severity severity, Pattern pattern, String recommendation) {
            this(id, title, severity, pattern, recommendation, 0);
        }

        private PatternSecretRule(
                String id, String title, Severity severity, Pattern pattern, String recommendation, int matchingGroup) {
            this.id = id;
            this.title = title;
            this.severity = severity;
            this.pattern = pattern;
            this.recommendation = recommendation;
            this.matchingGroup = matchingGroup;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null
                    || value.isBlank()
                    || NonSecretHeuristics.isCredentialIdField(fieldName)
                    || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String matched = matcher.group(matchingGroup);
                findings.add(finding(
                        id, title, severity, context, sourceName, lineNumber, fieldName, matched, recommendation));
            }
            return findings;
        }
    }

    private static final class BasicAuthHeaderRule implements SecretRule {
        private static final Pattern BASIC_AUTH_LITERAL = Pattern.compile("(?i)\\bBasic\\s+([A-Za-z0-9+/=]{8,})");

        @Override
        public String getId() {
            return "basic-auth-header";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null
                    || value.isBlank()
                    || NonSecretHeuristics.isCredentialIdField(fieldName)
                    || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = BASIC_AUTH_LITERAL.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String token = matcher.group(1);
                if (!looksLikeBasicAuthCredential(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "HTTP Basic authentication credential is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        token,
                        Recommendations.NO_COMMAND_LINE_SECRET));
            }
            return findings;
        }

        private boolean looksLikeBasicAuthCredential(String token) {
            try {
                String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
                int separator = decoded.indexOf(':');
                return separator > 0 && separator < decoded.length();
            } catch (IllegalArgumentException ignored) {
                return false;
            }
        }
    }

    private static final class NpmAuthTokenContextRule implements SecretRule {
        private static final Pattern ASSIGNED_AUTH_TOKEN = Pattern.compile(
                "(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_authToken|_authToken)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern CONFIG_SET_AUTH_TOKEN =
                Pattern.compile("(?i)\\bnpm\\s+config\\s+set\\s+//[^\\s]+/:_authToken\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "npm-auth-token-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectContextFindings(context, sourceName, lineNumber, fieldName, value, ASSIGNED_AUTH_TOKEN, findings);
            collectContextFindings(context, sourceName, lineNumber, fieldName, value, CONFIG_SET_AUTH_TOKEN, findings);
            return findings;
        }

        private void collectContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "npm registry auth token is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "_authToken" : fieldName,
                        token,
                        Recommendations.CREDENTIALS));
            }
        }
    }

    private static final class JfrogAccessTokenContextRule implements SecretRule {
        private static final Pattern CLI_ACCESS_TOKEN_ARGUMENT =
                Pattern.compile("(?i)--access-token(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern JFROG_CLI_ACCESS_TOKEN_ASSIGNMENT =
                Pattern.compile("(?i)\\bJFROG_CLI_ACCESS_TOKEN\\s*[=:]\\s*(['\"]?)([^\\s'\";]+)\\1");
        private static final Pattern JFROG_API_KEY_HEADER =
                Pattern.compile("(?i)X-JFrog-Art-Api\\s*[:=]\\s*(['\"]?)([^\\s'\";]+)\\1");

        @Override
        public String getId() {
            return "jfrog-access-token-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    JFROG_CLI_ACCESS_TOKEN_ASSIGNMENT,
                    findings,
                    "JFROG_CLI_ACCESS_TOKEN");
            collectContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    JFROG_API_KEY_HEADER,
                    findings,
                    "X-JFrog-Art-Api");
            if (looksLikeJfrogCommandContext(value)) {
                collectContextFindings(
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        value,
                        CLI_ACCESS_TOKEN_ARGUMENT,
                        findings,
                        fieldName);
            }
            return findings;
        }

        private void collectContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings,
                String fallbackFieldName) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "JFrog access token or API key is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? fallbackFieldName : fieldName,
                        token,
                        Recommendations.CREDENTIALS));
            }
        }

        private boolean looksLikeJfrogCommandContext(String value) {
            String lower = value.toLowerCase(Locale.ENGLISH);
            return lower.contains("jf ")
                    || lower.contains("jfrog ")
                    || lower.contains("artifactory")
                    || lower.contains("jf c ")
                    || lower.contains("jf rt ");
        }
    }

    private static final class NpmLegacyAuthContextRule implements SecretRule {
        private static final Pattern ASSIGNED_AUTH =
                Pattern.compile("(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_auth|_auth)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern ASSIGNED_PASSWORD = Pattern.compile(
                "(?i)(?:^|\\s)(?:(?://[^\\s'\"=]+/)?:_password|_password)\\s*[=:]\\s*(['\"]?)([^\\s'\"}]+)\\1");
        private static final Pattern CONFIG_SET_AUTH =
                Pattern.compile("(?i)\\bnpm\\s+config\\s+set\\s+(?://[^\\s]+/:)?_auth\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern CONFIG_SET_PASSWORD = Pattern.compile(
                "(?i)\\bnpm\\s+config\\s+set\\s+(?://[^\\s]+/:)?_password\\s+(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "npm-legacy-auth-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectContextFindings(context, sourceName, lineNumber, fieldName, value, ASSIGNED_AUTH, findings, "_auth");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, ASSIGNED_PASSWORD, findings, "_password");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, CONFIG_SET_AUTH, findings, "_auth");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, CONFIG_SET_PASSWORD, findings, "_password");
            return findings;
        }

        private void collectContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings,
                String fallbackFieldName) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "npm legacy auth credential is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? fallbackFieldName : fieldName,
                        token,
                        Recommendations.CREDENTIALS));
            }
        }
    }

    private static final class CommandUserPasswordContextRule implements SecretRule {
        private static final Pattern CURL_USER_ARGUMENT =
                Pattern.compile("(?i)\\bcurl\\b[^\\r\\n]*?(?:\\s-u|\\s--user)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern DOCKER_PASSWORD_ARGUMENT = Pattern.compile(
                "(?i)\\bdocker\\b[^\\r\\n]*?\\blogin\\b[^\\r\\n]*?(?:\\s-p|\\s--password)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern SSHPASS_PASSWORD_ARGUMENT =
                Pattern.compile("(?i)\\bsshpass\\b[^\\r\\n]*?\\s-p(?:\\s+)?(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern WGET_PASSWORD_ARGUMENT =
                Pattern.compile("(?i)\\bwget\\b[^\\r\\n]*?\\s--password(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");

        @Override
        public String getId() {
            return "command-user-password-argument";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectCurlFindings(context, sourceName, lineNumber, fieldName, value, findings);
            collectContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    DOCKER_PASSWORD_ARGUMENT,
                    findings,
                    "--password");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, SSHPASS_PASSWORD_ARGUMENT, findings, "-p");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, WGET_PASSWORD_ARGUMENT, findings, "--password");
            return findings;
        }

        private void collectCurlFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                List<SecretFinding> findings) {
            Matcher matcher = CURL_USER_ARGUMENT.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token) || !token.contains(":")) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "Command line basic authentication credential is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "--user" : fieldName,
                        token,
                        Recommendations.NO_COMMAND_LINE_SECRET));
            }
        }

        private void collectContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings,
                String fallbackFieldName) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "Command line password argument is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? fallbackFieldName : fieldName,
                        token,
                        Recommendations.NO_COMMAND_LINE_SECRET));
            }
        }
    }

    private static final class DockerPasswordStdinContextRule implements SecretRule {
        private static final Pattern ECHO_PASSWORD_STDIN = Pattern.compile(
                "(?i)\\becho\\b\\s+(['\"]?)([^\\s'\"\\\\|]+)\\1\\s*\\|\\s*docker\\b[^\\r\\n]*?\\blogin\\b[^\\r\\n]*?\\s--password-stdin(?:\\s|$)");

        @Override
        public String getId() {
            return "docker-password-stdin-secret";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            Matcher matcher = ECHO_PASSWORD_STDIN.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "docker login password-stdin secret is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "--password-stdin" : fieldName,
                        token,
                        Recommendations.NO_COMMAND_LINE_SECRET));
            }
            return findings;
        }
    }

    private static final class PyPiPasswordContextRule implements SecretRule {
        private static final Pattern TWINE_PASSWORD_ASSIGNMENT =
                Pattern.compile("(?i)\\bTWINE_PASSWORD\\s*[=:]\\s*(['\"]?)([^\\s'\";]+)\\1");
        private static final Pattern TWINE_PASSWORD_ARGUMENT = Pattern.compile(
                "(?i)\\btwine\\s+upload\\b[^\\r\\n]*?(?:\\s-p|\\s--password)(?:=|\\s+)(['\"]?)([^\\s'\"\\\\]+)\\1");
        private static final Pattern PYPIRC_PASSWORD_LINE =
                Pattern.compile("(?im)^\\s*password\\s*=\\s*(['\"]?)([^\\s'\"#;]+)\\1");

        @Override
        public String getId() {
            return "pypi-password-context";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            List<SecretFinding> findings = new ArrayList<>();
            collectContextFindings(
                    context,
                    sourceName,
                    lineNumber,
                    fieldName,
                    value,
                    TWINE_PASSWORD_ASSIGNMENT,
                    findings,
                    "TWINE_PASSWORD");
            collectContextFindings(
                    context, sourceName, lineNumber, fieldName, value, TWINE_PASSWORD_ARGUMENT, findings, "--password");
            if (looksLikePypircContext(fieldName, value)) {
                collectContextFindings(
                        context, sourceName, lineNumber, fieldName, value, PYPIRC_PASSWORD_LINE, findings, "password");
            }
            return findings;
        }

        private void collectContextFindings(
                ScanContext context,
                String sourceName,
                int lineNumber,
                String fieldName,
                String value,
                Pattern pattern,
                List<SecretFinding> findings,
                String fallbackFieldName) {
            Matcher matcher = pattern.matcher(value);
            while (matcher.find()) {
                String token = matcher.group(2);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "PyPI or Twine password is hardcoded",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? fallbackFieldName : fieldName,
                        token,
                        Recommendations.CREDENTIALS));
            }
        }

        private boolean looksLikePypircContext(String fieldName, String value) {
            String lowerFieldName = nullToEmpty(fieldName).toLowerCase(Locale.ENGLISH);
            String lowerValue = nullToEmpty(value).toLowerCase(Locale.ENGLISH);
            return lowerFieldName.contains("pypirc")
                    || lowerValue.contains("[distutils]")
                    || lowerValue.contains("index-servers")
                    || lowerValue.contains("[pypi]")
                    || lowerValue.contains("repository:");
        }
    }

    private static final class KubernetesSecretLiteralContextRule implements SecretRule {
        private static final Pattern SECRET_FROM_LITERAL = Pattern.compile(
                "(?i)\\b(?:kubectl|oc)\\b[^\\r\\n]*?\\bcreate\\s+secret\\b[^\\r\\n]*?--from-literal(?:=|\\s+)([A-Za-z0-9_.-]+)=(['\"]?)([^\\s'\"\\\\]+)\\2");

        @Override
        public String getId() {
            return "kubernetes-secret-from-literal";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank()) {
                return Collections.emptyList();
            }
            Matcher matcher = SECRET_FROM_LITERAL.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String literalFieldName = matcher.group(1);
                String token = matcher.group(3);
                if (shouldSkipContextLiteral(token)) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "Kubernetes secret literal is hardcoded on the command line",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        literalFieldName,
                        token,
                        Recommendations.NO_COMMAND_LINE_SECRET));
            }
            return findings;
        }
    }

    private static final class ProviderWebhookUrlRule implements SecretRule {
        private final String id;
        private final String title;
        private final Pattern pattern;

        private ProviderWebhookUrlRule(String id, String title, Pattern pattern) {
            this.id = id;
            this.title = title;
            this.pattern = pattern;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank() || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                findings.add(finding(
                        id,
                        title,
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        matcher.group(),
                        Recommendations.NO_NOTIFIER_URL_SECRET));
            }
            return findings;
        }
    }

    private static final class DatabaseConnectionStringRule implements SecretRule {
        private final String id;
        private final String title;
        private final Pattern pattern;

        private DatabaseConnectionStringRule(String id, String title, Pattern pattern) {
            this.id = id;
            this.title = title;
            this.pattern = pattern;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank() || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String connectionString = stripTrailingConnectionPunctuation(matcher.group());
                String password = extractPassword(connectionString);
                if (password.isEmpty()) {
                    continue;
                }
                findings.add(finding(
                        id,
                        title,
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "password" : fieldName,
                        password,
                        Recommendations.NO_URL_SECRET));
            }
            return findings;
        }

        private String extractPassword(String connectionString) {
            String authorityPassword = extractAuthorityPassword(connectionString);
            if (!authorityPassword.isEmpty()) {
                return authorityPassword;
            }
            return extractQueryPassword(connectionString);
        }

        private String extractAuthorityPassword(String connectionString) {
            int schemeIndex = connectionString.indexOf("://");
            if (schemeIndex < 0) {
                return "";
            }
            int authorityStart = schemeIndex + 3;
            int authorityEnd = firstDelimiterIndex(connectionString, authorityStart, '/', '?', '#');
            String authority = authorityEnd >= 0
                    ? connectionString.substring(authorityStart, authorityEnd)
                    : connectionString.substring(authorityStart);
            int atIndex = authority.lastIndexOf('@');
            if (atIndex < 0) {
                return "";
            }
            String userInfo = authority.substring(0, atIndex);
            int separator = userInfo.indexOf(':');
            if (separator <= 0 || separator == userInfo.length() - 1) {
                return "";
            }
            String password = decodeComponent(userInfo.substring(separator + 1));
            return shouldSkipContextLiteral(password) ? "" : password;
        }

        private String extractQueryPassword(String connectionString) {
            int queryIndex = connectionString.indexOf('?');
            if (queryIndex < 0 || queryIndex == connectionString.length() - 1) {
                return "";
            }
            int fragmentIndex = connectionString.indexOf('#', queryIndex + 1);
            String query = fragmentIndex >= 0
                    ? connectionString.substring(queryIndex + 1, fragmentIndex)
                    : connectionString.substring(queryIndex + 1);
            boolean hasUser = false;
            String password = "";
            for (String parameter : query.split("[&;]")) {
                if (parameter.isBlank()) {
                    continue;
                }
                int separator = parameter.indexOf('=');
                if (separator <= 0 || separator == parameter.length() - 1) {
                    continue;
                }
                String key = decodeComponent(parameter.substring(0, separator)).toLowerCase(Locale.ENGLISH);
                String value = decodeComponent(parameter.substring(separator + 1));
                if ((key.equals("user") || key.equals("username")) && !value.isBlank()) {
                    hasUser = true;
                }
                if (key.equals("password")) {
                    password = value;
                }
            }
            if (!hasUser || shouldSkipContextLiteral(password)) {
                return "";
            }
            return password;
        }

        private int firstDelimiterIndex(String value, int start, char... delimiters) {
            int index = -1;
            for (char delimiter : delimiters) {
                int candidate = value.indexOf(delimiter, start);
                if (candidate >= 0 && (index < 0 || candidate < index)) {
                    index = candidate;
                }
            }
            return index;
        }

        private String stripTrailingConnectionPunctuation(String value) {
            int end = value.length();
            while (end > 0) {
                char current = value.charAt(end - 1);
                if (current == '.' || current == ',' || current == ';' || current == ')' || current == ']') {
                    end--;
                    continue;
                }
                break;
            }
            return value.substring(0, end);
        }

        private String decodeComponent(String value) {
            try {
                return URLDecoder.decode(value, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException ignored) {
                return value;
            }
        }
    }

    private static final class HighEntropyRule implements SecretRule {
        private static final Pattern CANDIDATE = Pattern.compile("\\b[A-Za-z0-9+/=_-]{32,}\\b");

        @Override
        public String getId() {
            return "high-entropy-string";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank() || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = CANDIDATE.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String candidate = matcher.group();
                String suppressionReason =
                        NonSecretHeuristics.nonSecretHighEntropyReason(sourceName, value, fieldName, candidate);
                if (!suppressionReason.isEmpty() || NonSecretHeuristics.entropy(candidate) < 4.0) {
                    if (!suppressionReason.isEmpty() && LOGGER.isLoggable(Level.FINE)) {
                        LOGGER.fine("[Secret Guard][Heuristics] " + suppressionReason + " Source=" + sourceName
                                + ", field=" + fieldName + ", line=" + lineNumber + ".");
                    }
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "High entropy string may be a secret",
                        Severity.MEDIUM,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        candidate,
                        Recommendations.CREDENTIALS));
            }
            return findings;
        }
    }

    private static final class UrlQuerySecretRule implements SecretRule {
        private static final Pattern URL = Pattern.compile("https?://[^\\s'\"<>\\\\]+");
        private static final Pattern SECRET_QUERY_PARAMETER = Pattern.compile(
                "(?i)(?:^|[?&])(key|token|secret|password|access[_-]?token|access[_-]?key|api[_-]?key|auth(?:[_-]?token)?|webhook|client[_-]?secret|secret[_-]?key|signature|sig)=([^&#\\s'\"<>\\\\]+)");

        @Override
        public String getId() {
            return "url-query-secret";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank() || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher urlMatcher = URL.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (urlMatcher.find()) {
                String url = urlMatcher.group();
                Matcher queryMatcher = SECRET_QUERY_PARAMETER.matcher(url);
                while (queryMatcher.find()) {
                    String parameterName = queryMatcher.group(1);
                    String parameterValue = queryMatcher.group(2);
                    if (parameterValue.contains("$") || parameterValue.length() < 8) {
                        continue;
                    }
                    findings.add(finding(
                            getId(),
                            "Secret is embedded in a URL query parameter",
                            Severity.HIGH,
                            context,
                            sourceName,
                            lineNumber,
                            parameterName,
                            parameterValue,
                            Recommendations.NO_URL_QUERY_SECRET));
                }
            }
            return findings;
        }
    }

    private static final class NotifierUrlSecretRule implements SecretRule {
        private static final Pattern URL = Pattern.compile("https?://[^\\s'\"<>\\\\]+");
        private static final Pattern UUID =
                Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
        private static final Pattern HEX_TOKEN = Pattern.compile("(?i)[a-f0-9]{24,}");
        private static final Pattern UPPER_TOKEN = Pattern.compile("[A-Z0-9_-]{24,}");
        private static final Pattern GENERIC_TOKEN = Pattern.compile("[A-Za-z0-9._@=-]{20,}");

        @Override
        public String getId() {
            return "notifier-url-secret";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null || value.isBlank() || looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher urlMatcher = URL.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (urlMatcher.find()) {
                String url = urlMatcher.group();
                String matchedSegment = findEmbeddedNotifierSecret(url);
                if (matchedSegment.isEmpty()) {
                    continue;
                }
                findings.add(finding(
                        getId(),
                        "Notifier or webhook URL contains an embedded secret in its path",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        matchedSegment,
                        Recommendations.NO_NOTIFIER_URL_SECRET));
            }
            return findings;
        }

        private String findEmbeddedNotifierSecret(String url) {
            if (looksLikeKnownProviderWebhookUrl(url)) {
                return "";
            }
            URI uri;
            try {
                uri = URI.create(url);
            } catch (IllegalArgumentException ignored) {
                return "";
            }
            String host = nullToEmpty(uri.getHost()).toLowerCase(Locale.ENGLISH);
            String path = nullToEmpty(uri.getPath());
            if (path.isBlank()) {
                return "";
            }
            String[] rawSegments = path.split("/+");
            List<String> segments = new ArrayList<>();
            for (String rawSegment : rawSegments) {
                if (!rawSegment.isBlank()) {
                    segments.add(rawSegment);
                }
            }
            if (segments.isEmpty()) {
                return "";
            }

            boolean hostLooksNotifier = containsNotifierIndicator(host);
            int indicatorIndex = firstNotifierIndicatorIndex(segments);
            if (!hostLooksNotifier && indicatorIndex < 0) {
                return "";
            }

            int startIndex = indicatorIndex >= 0 ? indicatorIndex + 1 : Math.max(0, segments.size() - 3);
            for (int index = segments.size() - 1; index >= startIndex; index--) {
                String segment = segments.get(index);
                String previousSegment = index > 0 ? segments.get(index - 1) : "";
                if (looksLikeEmbeddedNotifierSecret(segment, previousSegment)) {
                    return segment;
                }
            }
            return "";
        }

        private int firstNotifierIndicatorIndex(List<String> segments) {
            for (int index = 0; index < segments.size(); index++) {
                if (containsNotifierIndicator(segments.get(index))) {
                    return index;
                }
            }
            return -1;
        }

        private boolean containsNotifierIndicator(String value) {
            String normalized = normalize(value);
            return normalized.contains("webhook")
                    || normalized.contains("hook")
                    || normalized.contains("notify")
                    || normalized.contains("notifier")
                    || normalized.contains("incoming")
                    || normalized.contains("callback")
                    || normalized.contains("trigger");
        }

        private boolean looksLikeEmbeddedNotifierSecret(String segment, String previousSegment) {
            String candidate = segment.trim();
            if (candidate.length() < 12 || containsNotifierIndicator(candidate) || candidate.matches("(?i)v\\d+")) {
                return false;
            }
            if (UUID.matcher(candidate).matches()) {
                return normalize(previousSegment).contains("hook");
            }
            if (HEX_TOKEN.matcher(candidate).matches()) {
                return true;
            }
            if (UPPER_TOKEN.matcher(candidate).matches()) {
                return true;
            }
            if (!GENERIC_TOKEN.matcher(candidate).matches()) {
                return false;
            }
            boolean hasUpper = candidate.chars().anyMatch(Character::isUpperCase);
            boolean hasLower = candidate.chars().anyMatch(Character::isLowerCase);
            boolean hasDigit = candidate.chars().anyMatch(Character::isDigit);
            if (!hasDigit) {
                return false;
            }
            if (candidate.contains("@") && NonSecretHeuristics.entropy(candidate) >= 3.4) {
                return true;
            }
            if (hasUpper && hasLower && candidate.length() >= 20 && NonSecretHeuristics.entropy(candidate) >= 3.4) {
                return true;
            }
            return !candidate.contains("-")
                    && candidate.length() >= 24
                    && NonSecretHeuristics.entropy(candidate) >= 3.6;
        }

        private String normalize(String value) {
            return nullToEmpty(value).toLowerCase(Locale.ENGLISH).replaceAll("[^a-z0-9]", "");
        }

        private String nullToEmpty(String value) {
            return value == null ? "" : value;
        }
    }

    private static boolean looksLikeKnownProviderWebhookUrl(String url) {
        String candidate = nullToEmpty(url);
        return candidate.matches("(?i)https://hooks\\.slack\\.com/services/[^\\s'\"<>]{40,}")
                || candidate.matches(
                        "(?i)https://(?:[^/]+\\.)?(?:webhook\\.office\\.com|outlook\\.office(?:365)?\\.com)/(?:webhook|webhookb2)/[^\\s'\"<>]*/IncomingWebhook/[^\\s'\"<>]{12,}")
                || candidate.matches(
                        "(?i)https://hooks\\.zapier\\.com/hooks/catch/\\d+/[A-Za-z0-9]{6,}(?:/[^\\s'\"<>]*)?");
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static boolean shouldSkipContextLiteral(String token) {
        if (token == null) {
            return true;
        }
        String trimmed = token.trim();
        return trimmed.isEmpty()
                || trimmed.length() < 8
                || trimmed.contains("$")
                || trimmed.contains("credentials(")
                || NonSecretHeuristics.isRuntimeSecretReference(trimmed)
                || NonSecretHeuristics.looksLikePlaceholderValue(trimmed);
    }

    private static final class Recommendations {
        private static final String CREDENTIALS =
                "Move the plaintext secret to Jenkins Credentials and inject it only at runtime.";
        private static final String NO_CONFIG_SECRET =
                "Do not persist secrets in Job configuration; move the value to Jenkins Credentials.";
        private static final String NO_COMMAND_LINE_SECRET =
                "Use withCredentials and avoid placing secrets directly in command-line arguments or headers.";
        private static final String NO_URL_SECRET =
                "Do not embed secrets in URLs; use Jenkins Credentials and safe request configuration.";
        private static final String NO_URL_QUERY_SECRET =
                "Move URL query secrets such as webhook keys to Jenkins Credentials and inject them at runtime.";
        private static final String NO_NOTIFIER_URL_SECRET =
                "Treat notifier or webhook URLs with embedded tokens as secrets; store them in Jenkins Credentials.";
        private static final String PLACEHOLDER =
                "Verify this placeholder is not used as a real secret; store real values in Jenkins Credentials.";
    }
}
