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

    private NonSecretHeuristics() {}

    public static boolean looksLikeSafeReference(String value) {
        if (value == null) {
            return true;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty()
                || trimmed.contains("${")
                || trimmed.contains("credentials(")
                || trimmed.contains("credentialsId")
                || trimmed.equals("****")
                || trimmed.matches("\\{[A-Za-z0-9+/=]{16,}}");
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
        return isCredentialIdField(fieldName)
                || isHashOrDigestContext(fieldName, originalValue)
                || isPublicCertificateContext(originalValue)
                || isBenignTrackingHeaderContext(fieldName, originalValue)
                || looksLikeIdentifier(candidate)
                || looksLikePathOrImage(originalValue, candidate)
                || looksLikeHumanReadableIdentifier(candidate);
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

    private static boolean looksLikePathOrImage(String originalValue, String candidate) {
        String token = expandToken(originalValue, candidate);
        String lowerToken = token.toLowerCase(Locale.ENGLISH);
        return lowerToken.startsWith("/")
                || lowerToken.startsWith("./")
                || lowerToken.startsWith("../")
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
        return Character.isLetterOrDigit(c) || c == '/' || c == '.' || c == '_' || c == '-' || c == ':';
    }

    private static boolean looksLikeHumanReadableIdentifier(String value) {
        String lower = nullToEmpty(value).toLowerCase(Locale.ENGLISH);
        if (!lower.contains("_") && !lower.contains("-")) {
            return false;
        }
        String[] parts = lower.split("[_-]+");
        int wordLikeParts = 0;
        for (String part : parts) {
            if (part.length() >= 3 && part.matches("[a-z][a-z0-9]*")) {
                wordLikeParts++;
            }
        }
        return wordLikeParts >= 3;
    }

    private static String normalize(String value) {
        return nullToEmpty(value).toLowerCase(Locale.ENGLISH).replaceAll("[^a-z0-9]", "");
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
