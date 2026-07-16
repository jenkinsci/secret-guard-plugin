package io.jenkins.plugins.secretguard.rules;

import io.jenkins.plugins.secretguard.config.CustomPatternRuleEntry;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class GenericSecretRules {
    private GenericSecretRules() {}

    static final class PatternSecretRule implements SecretRule {
        private final String id;
        private final String title;
        private final Severity severity;
        private final Pattern pattern;
        private final String recommendation;
        private final int matchingGroup;

        PatternSecretRule(String id, String title, Severity severity, Pattern pattern, String recommendation) {
            this(id, title, severity, pattern, recommendation, 0);
        }

        PatternSecretRule(
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
                    || SecretRuleSupport.looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String matched = matcher.group(matchingGroup);
                findings.add(SecretRuleSupport.finding(
                        id, title, severity, context, sourceName, lineNumber, fieldName, matched, recommendation));
            }
            return findings;
        }
    }

    static final class CustomPatternSecretRule implements SecretRule {
        private final CustomPatternRuleEntry entry;
        private final Pattern pattern;

        CustomPatternSecretRule(CustomPatternRuleEntry entry) {
            this.entry = entry;
            this.pattern = entry.compilePattern();
        }

        @Override
        public String getId() {
            return entry.getRuleId();
        }

        @Override
        public List<SecretFinding> scan(
                ScanContext context, String sourceName, int lineNumber, String fieldName, String value) {
            if (value == null
                    || value.isBlank()
                    || NonSecretHeuristics.isCredentialIdField(fieldName)
                    || SecretRuleSupport.looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                String matched = matcher.group(entry.getMatchingGroup());
                findings.add(SecretRuleSupport.finding(
                        entry.getRuleId(),
                        entry.getTitle(),
                        entry.getSeverity(),
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        matched,
                        SecretRuleSupport.Recommendations.CREDENTIALS));
            }
            return findings;
        }
    }

    static final class ProviderWebhookUrlRule implements SecretRule {
        private final String id;
        private final String title;
        private final Pattern pattern;

        ProviderWebhookUrlRule(String id, String title, Pattern pattern) {
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
            if (value == null || value.isBlank() || SecretRuleSupport.looksLikeSafeReference(value)) {
                return Collections.emptyList();
            }
            Matcher matcher = pattern.matcher(value);
            List<SecretFinding> findings = new ArrayList<>();
            while (matcher.find()) {
                findings.add(SecretRuleSupport.finding(
                        id,
                        title,
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName,
                        matcher.group(),
                        SecretRuleSupport.Recommendations.NO_NOTIFIER_URL_SECRET));
            }
            return findings;
        }
    }

    static final class DatabaseConnectionStringRule implements SecretRule {
        private final String id;
        private final String title;
        private final Pattern pattern;

        DatabaseConnectionStringRule(String id, String title, Pattern pattern) {
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
            if (value == null || value.isBlank() || SecretRuleSupport.looksLikeSafeReference(value)) {
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
                findings.add(SecretRuleSupport.finding(
                        id,
                        title,
                        Severity.HIGH,
                        context,
                        sourceName,
                        lineNumber,
                        fieldName.isBlank() ? "password" : fieldName,
                        password,
                        SecretRuleSupport.Recommendations.NO_URL_SECRET));
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
            return SecretRuleSupport.shouldSkipContextLiteral(password) ? "" : password;
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
            if (!hasUser || SecretRuleSupport.shouldSkipContextLiteral(password)) {
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
}
