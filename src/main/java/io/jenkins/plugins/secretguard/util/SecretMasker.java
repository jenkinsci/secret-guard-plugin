package io.jenkins.plugins.secretguard.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SecretMasker {
    private static final Pattern URL_USERINFO = Pattern.compile("(?i)(https?://)([^/@\\s]+)@([^\\s\"'<>]+)");
    private static final Pattern JWT = Pattern.compile("([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)");

    private SecretMasker() {
    }

    public static String mask(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.contains("-----BEGIN") && trimmed.contains("PRIVATE KEY-----")) {
            return "-----BEGIN PRIVATE KEY-----…-----END PRIVATE KEY-----";
        }
        Matcher urlMatcher = URL_USERINFO.matcher(trimmed);
        if (urlMatcher.find()) {
            return urlMatcher.replaceAll("$1***:***@$3");
        }
        Matcher jwtMatcher = JWT.matcher(trimmed);
        if (jwtMatcher.matches()) {
            return trim(jwtMatcher.group(1), 6) + ".***." + tail(jwtMatcher.group(3), 6);
        }
        if (trimmed.length() <= 8) {
            return "***";
        }
        int keep = trimmed.length() > 24 ? 4 : 3;
        return trimmed.substring(0, keep) + "…" + trimmed.substring(trimmed.length() - keep);
    }

    public static String maskSnippet(String value) {
        if (value == null) {
            return "";
        }
        String collapsed = value.replaceAll("\\s+", " ").trim();
        if (collapsed.length() > 160) {
            collapsed = collapsed.substring(0, 160) + "…";
        }
        return mask(collapsed);
    }

    private static String trim(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static String tail(String value, int max) {
        return value.length() <= max ? value : value.substring(value.length() - max);
    }
}
