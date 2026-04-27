package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.net.URI;
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
        builtIns.add(new BasicAuthHeaderRule());
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
            if (NonSecretHeuristics.looksLikeSensitiveFileReference(fieldName, value)) {
                return Collections.emptyList();
            }
            if (NonSecretHeuristics.looksLikeReadableEndpointUrl(value)) {
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
