package io.jenkins.plugins.secretguard.util;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NonSecretHeuristics {
    private static final Pattern FILE_EXTENSION =
            Pattern.compile("(?i).+\\.(py|sh|bash|groovy|jar|war|zip|tar|tgz|gz|json|yaml|yml|xml|txt|log|md)$");
    private static final Pattern DOCKER_IMAGE_REFERENCE =
            Pattern.compile("(?i)(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)+(?::[a-z0-9._-]+)?");
    private static final Pattern UUID =
            Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern HEADER_NAME_IN_LINE = Pattern.compile("\\bname\\s*:\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern DIRECT_RUNTIME_REFERENCE = Pattern.compile("\\$[A-Za-z_][A-Za-z0-9_]*"
            + "|(?:env|params)\\.[A-Za-z_][A-Za-z0-9_]*"
            + "|(?:env|params)\\[['\"][A-Za-z_][A-Za-z0-9_.-]*['\"]\\]"
            + "|credentials\\([^\\r\\n]+\\)");
    private static final Pattern ASSIGNED_QUOTED_LITERAL =
            Pattern.compile("(?s).*\\b[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(['\"])(.*?)\\1\\s*,?\\s*");
    private static final Pattern XML_TEXT_LITERAL = Pattern.compile("(?s)\\s*<[^>/][^>]*>\\s*([^<]+?)\\s*</[^>]+>\\s*");
    private static final Pattern BEARER_LITERAL = Pattern.compile("(?i)Bearer\\s+(.+)");
    private static final Pattern MASKED_PLACEHOLDER = Pattern.compile("[*xX•]{4,}");

    private NonSecretHeuristics() {}

    public static boolean isRuntimeSecretReference(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = stripBalancedParens(value.trim());
        return !trimmed.isEmpty()
                && (trimmed.contains("${")
                        || looksLikeInterpolatedString(trimmed)
                        || DIRECT_RUNTIME_REFERENCE.matcher(trimmed).matches()
                        || looksLikeRuntimeConcatenation(trimmed));
    }

    public static boolean looksLikeSafeReference(String value) {
        if (value == null) {
            return true;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty()
                || isRuntimeSecretReference(trimmed)
                || looksLikePlaceholderValue(trimmed)
                || trimmed.contains("credentialsId")
                || trimmed.equals("****")
                || trimmed.matches("\\{[A-Za-z0-9+/=]{16,}}");
    }

    public static boolean looksLikePlaceholderValue(String value) {
        if (value == null) {
            return false;
        }
        String candidate = extractLikelyLiteralValue(value.trim());
        if (candidate.isEmpty()) {
            return false;
        }
        String unquoted = unquote(candidate).trim();
        if (MASKED_PLACEHOLDER.matcher(unquoted).matches()) {
            return true;
        }
        String normalized = unquoted.toLowerCase(Locale.ENGLISH).replaceAll("^[^a-z0-9]+|[^a-z0-9]+$", "");
        return normalized.equals("redacted")
                || normalized.equals("masked")
                || normalized.equals("hidden")
                || normalized.equals("placeholder");
    }

    public static boolean isCredentialIdField(String fieldName) {
        String normalized = normalize(fieldName);
        return normalized.contains("credentialid") || normalized.contains("credentialsid");
    }

    public static boolean isHashOrDigestContext(String fieldName, String value) {
        String context = (nullToEmpty(fieldName) + " " + nullToEmpty(value)).toLowerCase(Locale.ENGLISH);
        return context.contains("sha256:")
                || context.contains("@sha256:")
                || context.contains("sha1:")
                || context.contains("md5:")
                || context.contains("checksum")
                || context.contains("digest")
                || context.contains("commit")
                || context.contains("revision");
    }

    public static boolean isPublicCertificateContext(String value) {
        String upper = nullToEmpty(value).toUpperCase(Locale.ENGLISH);
        return !upper.contains("PRIVATE KEY")
                && (upper.contains("-----BEGIN CERTIFICATE-----") || upper.contains("-----BEGIN PUBLIC KEY-----"));
    }

    public static boolean isBenignTrackingHeaderName(String headerName) {
        String normalized = normalize(headerName);
        return normalized.equals("xrequestid")
                || normalized.equals("requestid")
                || normalized.equals("xcorrelationid")
                || normalized.equals("correlationid")
                || normalized.equals("xtraceid")
                || normalized.equals("traceid")
                || normalized.equals("xspanid")
                || normalized.equals("spanid")
                || normalized.equals("xamzntraceid")
                || normalized.equals("xb3traceid")
                || normalized.equals("xb3spanid")
                || normalized.equals("xdatadogtraceid")
                || normalized.equals("xdatadogparentid");
    }

    public static boolean isBenignTrackingHeaderContext(String fieldName, String value) {
        if (isBenignTrackingHeaderName(fieldName)) {
            return true;
        }
        Matcher matcher = HEADER_NAME_IN_LINE.matcher(nullToEmpty(value));
        return matcher.find() && isBenignTrackingHeaderName(matcher.group(1));
    }

    public static boolean looksLikeNonSecretHighEntropyToken(String originalValue, String fieldName, String candidate) {
        return !nonSecretHighEntropyReason(originalValue, fieldName, candidate).isEmpty();
    }

    public static String nonSecretHighEntropyReason(String originalValue, String fieldName, String candidate) {
        if (isCredentialIdField(fieldName)) {
            return "Skipped high-entropy candidate because the field looks like a credentials ID.";
        }
        if (isHashOrDigestContext(fieldName, originalValue)) {
            return "Skipped high-entropy candidate because the surrounding context looks like a hash or digest.";
        }
        if (isPublicCertificateContext(originalValue)) {
            return "Skipped high-entropy candidate because the value looks like a public certificate.";
        }
        if (isBenignTrackingHeaderContext(fieldName, originalValue)) {
            return "Skipped high-entropy candidate because the header looks like a trace or request identifier.";
        }
        if (looksLikeIdentifier(candidate)) {
            return "Skipped high-entropy candidate because it looks like a readable identifier.";
        }
        if (looksLikePathOrImage(originalValue, candidate)) {
            return "Skipped high-entropy candidate because it looks like a repository address, path, or image reference.";
        }
        if (looksLikeHumanReadableIdentifier(candidate)) {
            return "Skipped high-entropy candidate because it looks like a human-readable identifier.";
        }
        return "";
    }

    public static double entropy(String value) {
        if (value == null || value.isEmpty()) {
            return 0.0;
        }
        int[] counts = new int[128];
        for (char c : value.toCharArray()) {
            if (c < counts.length) {
                counts[c]++;
            }
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) {
                continue;
            }
            double probability = (double) count / value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    private static boolean looksLikeIdentifier(String value) {
        String lower = nullToEmpty(value).toLowerCase(Locale.ENGLISH);
        return lower.startsWith("jenkins")
                || lower.startsWith("http")
                || lower.contains("example")
                || UUID.matcher(lower).matches();
    }

    private static boolean looksLikeInterpolatedString(String value) {
        return value.length() >= 2
                && value.startsWith("\"")
                && value.endsWith("\"")
                && (value.contains("${") || value.matches(".*\\$[A-Za-z_][A-Za-z0-9_]*.*"));
    }

    private static boolean looksLikeRuntimeConcatenation(String value) {
        if (!value.contains("+")) {
            return false;
        }
        boolean hasRuntimeReference = false;
        for (String segment : value.split("\\+")) {
            String token = stripBalancedParens(segment.trim());
            if (token.isEmpty()) {
                return false;
            }
            if (DIRECT_RUNTIME_REFERENCE.matcher(token).matches() || looksLikeInterpolatedString(token)) {
                hasRuntimeReference = true;
                continue;
            }
            if (isQuotedString(token)) {
                continue;
            }
            return false;
        }
        return hasRuntimeReference;
    }

    private static boolean isQuotedString(String value) {
        return value.length() >= 2
                && ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'")));
    }

    private static String extractLikelyLiteralValue(String value) {
        String trimmed = stripBalancedParens(value.trim());
        if (isQuotedString(trimmed)) {
            trimmed = unquote(trimmed);
        }
        Matcher assignmentMatcher = ASSIGNED_QUOTED_LITERAL.matcher(trimmed);
        if (assignmentMatcher.matches()) {
            return assignmentMatcher.group(2);
        }
        Matcher xmlMatcher = XML_TEXT_LITERAL.matcher(trimmed);
        if (xmlMatcher.matches()) {
            return xmlMatcher.group(1);
        }
        Matcher bearerMatcher = BEARER_LITERAL.matcher(trimmed);
        if (bearerMatcher.matches()) {
            return bearerMatcher.group(1);
        }
        return trimmed;
    }

    private static String unquote(String value) {
        String trimmed = value.trim();
        if (isQuotedString(trimmed)) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String stripBalancedParens(String value) {
        String result = value;
        while (result.length() >= 2 && result.startsWith("(") && result.endsWith(")")) {
            result = result.substring(1, result.length() - 1).trim();
        }
        return result;
    }

    private static boolean looksLikePathOrImage(String originalValue, String candidate) {
        String token = expandToken(originalValue, candidate);
        String lowerToken = token.toLowerCase(Locale.ENGLISH);
        return lowerToken.startsWith("/")
                || lowerToken.startsWith("./")
                || lowerToken.startsWith("../")
                || looksLikeRepositoryAddress(lowerToken)
                || lowerToken.contains("/opt/")
                || lowerToken.contains("/usr/")
                || lowerToken.contains("/var/")
                || lowerToken.contains("/bin/")
                || lowerToken.contains("docker.sock")
                || lowerToken.contains(".cn/")
                || lowerToken.contains(".com/")
                || lowerToken.contains(".net/")
                || lowerToken.contains(".org/")
                || FILE_EXTENSION.matcher(lowerToken).matches()
                || looksLikeRepositoryPath(lowerToken)
                || DOCKER_IMAGE_REFERENCE.matcher(lowerToken).matches();
    }

    private static String expandToken(String originalValue, String candidate) {
        if (originalValue == null || candidate == null) {
            return candidate == null ? "" : candidate;
        }
        int start = originalValue.indexOf(candidate);
        if (start < 0) {
            return candidate;
        }
        int tokenStart = start;
        int tokenEnd = start + candidate.length();
        while (tokenStart > 0 && isPathLikeChar(originalValue.charAt(tokenStart - 1))) {
            tokenStart--;
        }
        while (tokenEnd < originalValue.length() && isPathLikeChar(originalValue.charAt(tokenEnd))) {
            tokenEnd++;
        }
        return originalValue.substring(tokenStart, tokenEnd);
    }

    private static boolean isPathLikeChar(char c) {
        return Character.isLetterOrDigit(c)
                || c == '/'
                || c == '.'
                || c == '_'
                || c == '-'
                || c == ':'
                || c == '@'
                || c == '%'
                || c == '~';
    }

    private static boolean looksLikeHumanReadableIdentifier(String value) {
        String normalized = nullToEmpty(value).trim();
        if (normalized.isEmpty()) {
            return false;
        }
        String[] parts;
        String lower = normalized.toLowerCase(Locale.ENGLISH);
        if (lower.contains("_") || lower.contains("-")) {
            parts = lower.split("[_-]+");
        } else if (looksLikeCamelCaseIdentifier(normalized)) {
            parts = normalized.split("(?<=[a-z0-9])(?=[A-Z])");
        } else {
            return false;
        }
        int wordLikeParts = 0;
        for (String part : parts) {
            if (part.length() >= 2 && part.toLowerCase(Locale.ENGLISH).matches("[a-z][a-z0-9]*")) {
                wordLikeParts++;
            }
        }
        return wordLikeParts >= 3;
    }

    private static boolean looksLikeCamelCaseIdentifier(String value) {
        return value.matches("[a-z][A-Za-z0-9]*") && value.matches(".*[A-Z].*") && value.matches(".*[a-z][A-Z].*");
    }

    private static boolean looksLikeRepositoryPath(String value) {
        if (value == null || !value.contains("/")) {
            return false;
        }
        String[] segments = value.split("/+");
        int readableSegments = 0;
        for (String segment : segments) {
            if (segment.isBlank()) {
                continue;
            }
            if (!looksLikeReadablePathSegment(segment)) {
                return false;
            }
            readableSegments++;
        }
        return readableSegments >= 3;
    }

    private static boolean looksLikeReadablePathSegment(String segment) {
        if (segment.length() > 24 || !segment.matches("[a-z0-9._-]+") || !segment.matches(".*[a-z].*")) {
            return false;
        }
        return looksLikeHumanReadableIdentifier(segment)
                || segment.matches("[a-z0-9]+")
                || segment.contains("_")
                || segment.contains("-");
    }

    private static boolean looksLikeRepositoryAddress(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value;
        int schemeIndex = normalized.indexOf("://");
        if (schemeIndex >= 0) {
            normalized = normalized.substring(schemeIndex + 3);
        } else if (normalized.startsWith("//")) {
            normalized = normalized.substring(2);
        }

        int scpSeparator = findScpSeparator(normalized);
        if (scpSeparator > 0) {
            String host = normalized.substring(0, scpSeparator);
            String path = normalized.substring(scpSeparator + 1);
            int userSeparator = host.lastIndexOf('@');
            if (userSeparator >= 0) {
                host = host.substring(userSeparator + 1);
            }
            return looksLikeHost(host) && looksLikeRepositoryPath(path);
        }

        int slashIndex = normalized.indexOf('/');
        if (slashIndex <= 0) {
            return false;
        }
        String hostPort = normalized.substring(0, slashIndex);
        String path = normalized.substring(slashIndex + 1);
        return looksLikeHostPort(hostPort) && looksLikeRepositoryPath(path);
    }

    private static int findScpSeparator(String value) {
        int colonIndex = value.indexOf(':');
        int slashIndex = value.indexOf('/');
        if (colonIndex <= 0 || slashIndex < 0 || colonIndex > slashIndex) {
            return -1;
        }
        String colonValue = value.substring(colonIndex + 1, slashIndex);
        if (colonValue.matches("\\d{2,5}")) {
            return -1;
        }
        if (value.substring(0, colonIndex).contains("/")) {
            return -1;
        }
        return colonIndex;
    }

    private static boolean looksLikeHostPort(String value) {
        int colonIndex = value.lastIndexOf(':');
        if (colonIndex > 0
                && value.indexOf(':') == colonIndex
                && value.substring(colonIndex + 1).matches("\\d{2,5}")) {
            return looksLikeHost(value.substring(0, colonIndex));
        }
        return looksLikeHost(value);
    }

    private static boolean looksLikeHost(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String host = value.toLowerCase(Locale.ENGLISH);
        if (host.equals("localhost")) {
            return true;
        }
        if (host.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) {
            return true;
        }
        if (!host.matches("[a-z0-9.-]+") || host.startsWith(".") || host.endsWith(".")) {
            return false;
        }
        for (String label : host.split("\\.")) {
            if (label.isBlank() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
        }
        return true;
    }

    private static String normalize(String value) {
        return nullToEmpty(value).toLowerCase(Locale.ENGLISH).replaceAll("[^a-z0-9]", "");
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
