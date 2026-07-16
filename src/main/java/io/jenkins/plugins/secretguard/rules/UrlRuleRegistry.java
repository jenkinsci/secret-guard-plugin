package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class UrlRuleRegistry {
    private UrlRuleRegistry() {}

    static void addRules(List<SecretRule> rules) {
        rules.add(new GenericSecretRules.PatternSecretRule(
                "url-embedded-secret",
                "Credential is embedded in a URL",
                Severity.HIGH,
                Pattern.compile("(?i)https?://[^\\s:/@'\"<>]+:[^\\s/@'\"<>]{6,}@[^\\s'\"<>]+"),
                SecretRuleSupport.Recommendations.NO_URL_SECRET));
        rules.add(new GenericSecretRules.DatabaseConnectionStringRule(
                "mysql-connection-url",
                "MySQL connection string contains a hardcoded password",
                Pattern.compile("(?i)\\b(?:jdbc:)?mysql://[^\\s'\"<>]+")));
        rules.add(new GenericSecretRules.DatabaseConnectionStringRule(
                "postgres-connection-string",
                "PostgreSQL connection string contains a hardcoded password",
                Pattern.compile("(?i)\\b(?:jdbc:)?postgres(?:ql)?://[^\\s'\"<>]+")));
        rules.add(new GenericSecretRules.ProviderWebhookUrlRule(
                "slack-webhook-url",
                "Slack webhook URL is hardcoded",
                Pattern.compile("https://hooks\\.slack\\.com/services/[^\\s'\"<>]{40,}", Pattern.CASE_INSENSITIVE)));
        rules.add(new GenericSecretRules.ProviderWebhookUrlRule(
                "teams-webhook-url",
                "Microsoft Teams webhook URL is hardcoded",
                Pattern.compile(
                        "https://(?:[^/]+\\.)?(?:webhook\\.office\\.com|outlook\\.office(?:365)?\\.com)/(?:webhook|webhookb2)/[^\\s'\"<>]*/IncomingWebhook/[^\\s'\"<>]{12,}",
                        Pattern.CASE_INSENSITIVE)));
        rules.add(new GenericSecretRules.ProviderWebhookUrlRule(
                "zapier-webhook-url",
                "Zapier webhook URL is hardcoded",
                Pattern.compile(
                        "https://hooks\\.zapier\\.com/hooks/catch/\\d+/[A-Za-z0-9]{6,}(?:/[^\\s'\"<>]*)?",
                        Pattern.CASE_INSENSITIVE)));
        rules.add(new UrlQuerySecretRule());
        rules.add(new NotifierUrlSecretRule());
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
            if (value == null || value.isBlank() || SecretRuleSupport.looksLikeSafeReference(value)) {
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
                    findings.add(SecretRuleSupport.finding(
                            getId(),
                            "Secret is embedded in a URL query parameter",
                            Severity.HIGH,
                            context,
                            sourceName,
                            lineNumber,
                            parameterName,
                            parameterValue,
                            SecretRuleSupport.Recommendations.NO_URL_QUERY_SECRET));
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
            if (value == null || value.isBlank() || SecretRuleSupport.looksLikeSafeReference(value)) {
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
                findings.add(SecretRuleSupport.finding(
                        getId(),
                        "Notifier or webhook URL contains an embedded secret in its path",
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        matchedSegment,
                        SecretRuleSupport.Recommendations.NO_NOTIFIER_URL_SECRET));
            }
            return findings;
        }

        private String findEmbeddedNotifierSecret(String url) {
            if (SecretRuleSupport.looksLikeKnownProviderWebhookUrl(url)) {
                return "";
            }
            URI uri;
            try {
                uri = URI.create(url);
            } catch (IllegalArgumentException ignored) {
                return "";
            }
            String host = SecretRuleSupport.nullToEmpty(uri.getHost()).toLowerCase(Locale.ENGLISH);
            String path = SecretRuleSupport.nullToEmpty(uri.getPath());
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
            if (candidate.contains("@")
                    && io.jenkins.plugins.secretguard.util.NonSecretHeuristics.entropy(candidate) >= 3.4) {
                return true;
            }
            if (hasUpper
                    && hasLower
                    && candidate.length() >= 20
                    && io.jenkins.plugins.secretguard.util.NonSecretHeuristics.entropy(candidate) >= 3.4) {
                return true;
            }
            return !candidate.contains("-")
                    && candidate.length() >= 24
                    && io.jenkins.plugins.secretguard.util.NonSecretHeuristics.entropy(candidate) >= 3.6;
        }

        private String normalize(String value) {
            return SecretRuleSupport.nullToEmpty(value)
                    .toLowerCase(Locale.ENGLISH)
                    .replaceAll("[^a-z0-9]", "");
        }
    }
}
