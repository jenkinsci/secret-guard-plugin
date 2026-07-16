package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SecretRuleSupport {
    private static final Pattern SENSITIVE_FIELD = Pattern.compile(
            "(?i)(token|password|passphrase|secret|api[_-]?key|apikey|access[_-]?key|accessKey|clientSecret)");
    private static final Pattern SIMPLE_ASSIGNMENT_LITERAL =
            Pattern.compile("\\b([A-Za-z_]\\w*)\\s*=\\s*(['\"])([^'\"]+)\\2");

    private SecretRuleSupport() {}

    static boolean isSensitiveField(String fieldName) {
        return fieldName != null && SENSITIVE_FIELD.matcher(fieldName).find();
    }

    static boolean looksLikeSafeReference(String value) {
        return NonSecretHeuristics.looksLikeSafeReference(value);
    }

    static String normalizeAssignedLiteralValue(String fieldName, String value) {
        if (fieldName == null || fieldName.isBlank() || value == null || value.isBlank()) {
            return value;
        }
        Matcher matcher = SIMPLE_ASSIGNMENT_LITERAL.matcher(value);
        if (matcher.find() && fieldName.equals(matcher.group(1))) {
            return matcher.group(3);
        }
        return value;
    }

    static SecretFinding finding(
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

    static SecretFinding finding(
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

    static boolean shouldSkipContextLiteral(String token) {
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

    static boolean looksLikeKnownProviderWebhookUrl(String url) {
        String candidate = nullToEmpty(url);
        return candidate.matches("(?i)https://hooks\\.slack\\.com/services/[^\\s'\"<>]{40,}")
                || candidate.matches(
                        "(?i)https://(?:[^/]+\\.)?(?:webhook\\.office\\.com|outlook\\.office(?:365)?\\.com)/(?:webhook|webhookb2)/[^\\s'\"<>]*/IncomingWebhook/[^\\s'\"<>]{12,}")
                || candidate.matches(
                        "(?i)https://hooks\\.zapier\\.com/hooks/catch/\\d+/[A-Za-z0-9]{6,}(?:/[^\\s'\"<>]*)?");
    }

    static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    static final class Recommendations {
        static final String CREDENTIALS =
                "Move the plaintext secret to Jenkins Credentials and inject it only at runtime.";
        static final String NO_CONFIG_SECRET =
                "Do not persist secrets in Job configuration; move the value to Jenkins Credentials.";
        static final String NO_COMMAND_LINE_SECRET =
                "Use withCredentials and avoid placing secrets directly in command-line arguments or headers.";
        static final String NO_URL_SECRET =
                "Do not embed secrets in URLs; use Jenkins Credentials and safe request configuration.";
        static final String NO_URL_QUERY_SECRET =
                "Move URL query secrets such as webhook keys to Jenkins Credentials and inject them at runtime.";
        static final String NO_NOTIFIER_URL_SECRET =
                "Treat notifier or webhook URLs with embedded tokens as secrets; store them in Jenkins Credentials.";
        static final String PLACEHOLDER =
                "Verify this placeholder is not used as a real secret; store real values in Jenkins Credentials.";

        private Recommendations() {}
    }
}
