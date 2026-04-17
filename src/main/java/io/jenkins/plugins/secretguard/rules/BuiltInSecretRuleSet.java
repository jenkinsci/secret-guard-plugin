package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BuiltInSecretRuleSet {
    private static final Logger LOGGER = Logger.getLogger(BuiltInSecretRuleSet.class.getName());
    private static final Pattern SENSITIVE_FIELD =
            Pattern.compile("(?i)(token|password|secret|api[_-]?key|apikey|access[_-]?key|accessKey|clientSecret)");

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
        builtIns.add(new UrlQuerySecretRule());
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
                analysisNote);
    }

    private static final class SensitiveFieldRule implements SecretRule {
        @Override
        public String getId() {
            return "sensitive-field-name";
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (!isSensitiveField(fieldName) || NonSecretHeuristics.isCredentialIdField(fieldName)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikePlaceholderValue(value)) {
                return List.of(finding(
                        getId(),
                        "Sensitive field contains a placeholder-like value",
                        Severity.LOW,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        value,
                        Recommendations.PLACEHOLDER,
                        "Downgraded because the value looks like a redaction placeholder instead of a real secret."));
            }
            if (looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Severity severity = value.trim().length() >= 8 ? Severity.HIGH : Severity.LOW;
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
                    value,
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
                String suppressionReason = NonSecretHeuristics.nonSecretHighEntropyReason(value, fieldName, candidate);
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
                "(?i)(?:^|[?&])(key|token|secret|password|access_token|api[_-]?key|auth|webhook)=([^&#\\s'\"<>\\\\]+)");

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
        private static final String PLACEHOLDER =
                "Verify this placeholder is not used as a real secret; store real values in Jenkins Credentials.";
    }
}
