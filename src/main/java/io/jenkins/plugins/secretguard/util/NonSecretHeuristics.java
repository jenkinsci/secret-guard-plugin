package io.jenkins.plugins.secretguard.util;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NonSecretHeuristics {
    private static final Pattern FILE_EXTENSION = Pattern.compile(
            "(?i).+\\.(py|sh|bash|groovy|jar|war|zip|tar|tgz|gz|json|yaml|yml|xml|txt|log|md|jenkinsfile)$");
    private static final Pattern STORAGE_URI_SCHEME =
            Pattern.compile("(?i)(hdfs|viewfs|file|s3|s3a|gs|gcs|oss|cosn|obs|bos|tos|wasb|wasbs|abfs|abfss|adl)://.+");
    private static final Pattern DOCKER_IMAGE_REFERENCE =
            Pattern.compile("(?i)(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)+(?::[a-z0-9._-]+)?");
    private static final Pattern UUID =
            Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern HEADER_NAME_IN_LINE = Pattern.compile("\\bname\\s*:\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern DIRECT_RUNTIME_REFERENCE = Pattern.compile("\\$[A-Za-z_][A-Za-z0-9_]*"
            + "|(?:env|params)(?:\\?)?\\.[A-Za-z_][A-Za-z0-9_]*(?:(?:\\?)?\\.[A-Za-z_][A-Za-z0-9_]*(?:\\([^\\r\\n]*\\))?)*"
            + "|(?:env|params)\\[['\"][A-Za-z_][A-Za-z0-9_.-]*['\"]\\](?:(?:\\?)?\\.[A-Za-z_][A-Za-z0-9_]*(?:\\([^\\r\\n]*\\))?)*"
            + "|(?:env|params)(?:\\?)?\\.get\\(\\s*['\"][A-Za-z_][A-Za-z0-9_.-]*['\"]\\s*\\)(?:(?:\\?)?\\.[A-Za-z_][A-Za-z0-9_]*(?:\\([^\\r\\n]*\\))?)*"
            + "|[A-Z][A-Z0-9_]*(?:\\??\\.[A-Za-z_][A-Za-z0-9_]*(?:\\([^\\r\\n]*\\))?)+"
            + "|credentials\\([^\\r\\n]+\\)");
    private static final Pattern ASSIGNED_QUOTED_LITERAL =
            Pattern.compile("(?s).*\\b[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(['\"])(.*?)\\1\\s*,?\\s*");
    private static final Pattern XML_TEXT_LITERAL = Pattern.compile("(?s)\\s*<[^>/][^>]*>\\s*([^<]+?)\\s*</[^>]+>\\s*");
    private static final Pattern BEARER_LITERAL = Pattern.compile("(?i)Bearer\\s+(.+)");
    private static final Pattern MASKED_PLACEHOLDER = Pattern.compile("[*xX•]{4,}");
    private static final Pattern JDBC_URL = Pattern.compile("(?i)\\bjdbc:[a-z0-9][a-z0-9:._-]*://[^\\s'\"<>]+");
    private static final Pattern SENSITIVE_PARAMETER_NAME = Pattern.compile(
            "(?i).*(password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|accesskey|client[_-]?secret|credential|auth|webhook).*");
    private static final Pattern HTTP_URL = Pattern.compile("(?i)\\bhttps?://[^\\s'\"<>]+");
    private static final Pattern SENSITIVE_URL_NAME = Pattern.compile(
            "(?i).*(password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|accesskey|client[_-]?secret|credential|auth|webhook|signature|sig).*");

    private NonSecretHeuristics() {}

    public static boolean isRuntimeSecretReference(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = stripBalancedParens(value.trim());
        if (trimmed.isEmpty()) {
            return false;
        }
        return trimmed.contains("${")
                || looksLikeInterpolatedString(trimmed)
                || DIRECT_RUNTIME_REFERENCE.matcher(trimmed).matches()
                || looksLikeRuntimeConcatenation(trimmed)
                || looksLikeRuntimeFallbackExpression(trimmed)
                || looksLikeRuntimeConditionalExpression(trimmed);
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

    public static boolean looksLikeSensitiveFileReference(String fieldName, String value) {
        if (!isSensitiveFileReferenceField(fieldName) || value == null || value.isBlank()) {
            return false;
        }
        String candidate = extractLikelyLiteralValue(value.trim());
        if (candidate.isEmpty() || isRuntimeSecretReference(candidate) || looksLikePlaceholderValue(candidate)) {
            return false;
        }
        return looksLikeLocalFileReference(candidate);
    }

    public static boolean looksLikeNonSecretUrl(String originalValue, String candidate) {
        String url = findContainingHttpUrl(originalValue, candidate);
        if (url.isEmpty() || candidate == null || !candidate.contains("/")) {
            return false;
        }
        if (urlAuthorityLooksCredentialed(url) || urlContainsSensitiveQueryOrFragment(url)) {
            return false;
        }
        String path = urlPath(url);
        return looksLikeReadableUrlPath(path) && !urlPathLooksSensitive(path);
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

    public static boolean looksLikeNonSecretHighEntropyToken(
            String sourceName, String originalValue, String fieldName, String candidate) {
        return !nonSecretHighEntropyReason(sourceName, originalValue, fieldName, candidate)
                .isEmpty();
    }

    public static boolean looksLikeNonSecretHighEntropyToken(String originalValue, String fieldName, String candidate) {
        return looksLikeNonSecretHighEntropyToken("", originalValue, fieldName, candidate);
    }

    public static String nonSecretHighEntropyReason(
            String sourceName, String originalValue, String fieldName, String candidate) {
        if (isScriptPathField(fieldName)) {
            return "Skipped high-entropy candidate because the field is a Pipeline script path.";
        }
        if (isCredentialIdField(fieldName)) {
            return "Skipped high-entropy candidate because the field looks like a credentials ID.";
        }
        if (looksLikeJenkinsfilePath(originalValue, candidate)) {
            return "Skipped high-entropy candidate because it looks like a Jenkinsfile path.";
        }
        if (looksLikeStorageUriPath(originalValue, candidate)) {
            return "Skipped high-entropy candidate because it looks like a storage URI path.";
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
        if (looksLikeGeneratedParameterSeparatorName(sourceName, fieldName, candidate)) {
            return "Skipped high-entropy candidate because it looks like a generated separator parameter name.";
        }
        if (looksLikeGeneratedRandomName(fieldName, candidate)) {
            return "Skipped high-entropy candidate because it looks like a generated parameter identifier.";
        }
        if (looksLikeBenignDatabaseConnectionParameter(originalValue, candidate)) {
            return "Skipped high-entropy candidate because it looks like a database connection option.";
        }
        if (looksLikeNonSecretUrl(originalValue, candidate)) {
            return "Skipped high-entropy candidate because it looks like a non-secret URL.";
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

    public static String nonSecretHighEntropyReason(String originalValue, String fieldName, String candidate) {
        return nonSecretHighEntropyReason("", originalValue, fieldName, candidate);
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

    private static boolean isScriptPathField(String fieldName) {
        String normalized = normalize(fieldName);
        return normalized.equals("scriptpath") || normalized.equals("jenkinsfilepath");
    }

    private static boolean isSensitiveFileReferenceField(String fieldName) {
        String normalized = normalize(fieldName);
        boolean containsSensitiveTerm = normalized.contains("password")
                || normalized.contains("token")
                || normalized.contains("secret")
                || normalized.contains("apikey")
                || normalized.contains("accesskey")
                || normalized.contains("clientsecret");
        boolean containsFileIndicator = normalized.contains("file")
                || normalized.contains("path")
                || normalized.contains("filename")
                || normalized.contains("filepath");
        return containsSensitiveTerm && containsFileIndicator;
    }

    private static boolean isRandomNameField(String fieldName) {
        return normalize(fieldName).equals("randomname");
    }

    private static boolean isNameField(String fieldName) {
        return normalize(fieldName).equals("name");
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
            if (DIRECT_RUNTIME_REFERENCE.matcher(token).matches()
                    || looksLikeInterpolatedString(token)
                    || looksLikeRuntimeFallbackExpression(token)
                    || looksLikeRuntimeConditionalExpression(token)) {
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

    private static boolean looksLikeRuntimeFallbackExpression(String value) {
        int fallbackIndex = findTopLevelOperator(value, "?:");
        if (fallbackIndex < 0) {
            return false;
        }
        String left = stripBalancedParens(value.substring(0, fallbackIndex).trim());
        String right = stripBalancedParens(value.substring(fallbackIndex + 2).trim());
        return !left.isEmpty() && !right.isEmpty() && isRuntimeExpressionToken(left) && isSafeFallbackLiteral(right);
    }

    private static boolean looksLikeRuntimeConditionalExpression(String value) {
        int questionIndex = findTopLevelConditionalQuestion(value);
        if (questionIndex < 0) {
            return false;
        }
        int colonIndex = findTopLevelMatchingColon(value, questionIndex + 1);
        if (colonIndex < 0) {
            return false;
        }
        String condition = stripBalancedParens(value.substring(0, questionIndex).trim());
        String whenTrue = stripBalancedParens(
                value.substring(questionIndex + 1, colonIndex).trim());
        String whenFalse = stripBalancedParens(value.substring(colonIndex + 1).trim());
        return !condition.isEmpty()
                && !whenTrue.isEmpty()
                && !whenFalse.isEmpty()
                && containsRuntimeReference(condition)
                && isSafeConditionalBranch(whenTrue)
                && isSafeConditionalBranch(whenFalse);
    }

    private static boolean isRuntimeExpressionToken(String value) {
        String trimmed = stripBalancedParens(value.trim());
        return !trimmed.isEmpty()
                && (DIRECT_RUNTIME_REFERENCE.matcher(trimmed).matches()
                        || looksLikeInterpolatedString(trimmed)
                        || looksLikeRuntimeConcatenation(trimmed));
    }

    private static boolean containsRuntimeReference(String value) {
        String trimmed = stripBalancedParens(nullToEmpty(value).trim());
        if (trimmed.isEmpty()) {
            return false;
        }
        if (isRuntimeExpressionToken(trimmed)) {
            return true;
        }
        if (trimmed.contains("${")) {
            return true;
        }
        return DIRECT_RUNTIME_REFERENCE.matcher(trimmed).find();
    }

    private static boolean isSafeConditionalBranch(String value) {
        return isRuntimeExpressionToken(value) || isSafeFallbackLiteral(value);
    }

    private static boolean isSafeFallbackLiteral(String value) {
        String trimmed = stripBalancedParens(value.trim());
        return trimmed.equals("''")
                || trimmed.equals("\"\"")
                || trimmed.equals("null")
                || trimmed.equals("true")
                || trimmed.equals("false")
                || trimmed.matches("-?[0-9]+(?:\\.[0-9]+)?");
    }

    private static int findTopLevelConditionalQuestion(String value) {
        int parenthesisDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (escaping) {
                escaping = false;
                continue;
            }
            if ((inSingleQuote || inDoubleQuote) && c == '\\') {
                escaping = true;
                continue;
            }
            if (inSingleQuote) {
                if (c == '\'') {
                    inSingleQuote = false;
                }
                continue;
            }
            if (inDoubleQuote) {
                if (c == '"') {
                    inDoubleQuote = false;
                }
                continue;
            }
            if (c == '\'') {
                inSingleQuote = true;
                continue;
            }
            if (c == '"') {
                inDoubleQuote = true;
                continue;
            }
            if (c == '(') {
                parenthesisDepth++;
                continue;
            }
            if (c == ')' && parenthesisDepth > 0) {
                parenthesisDepth--;
                continue;
            }
            if (c == '[') {
                bracketDepth++;
                continue;
            }
            if (c == ']' && bracketDepth > 0) {
                bracketDepth--;
                continue;
            }
            if (c == '{') {
                braceDepth++;
                continue;
            }
            if (c == '}' && braceDepth > 0) {
                braceDepth--;
                continue;
            }
            if (parenthesisDepth == 0
                    && bracketDepth == 0
                    && braceDepth == 0
                    && c == '?'
                    && (index + 1 >= value.length() || value.charAt(index + 1) != ':')
                    && (index == 0 || value.charAt(index - 1) != '.')) {
                return index;
            }
        }
        return -1;
    }

    private static int findTopLevelMatchingColon(String value, int startIndex) {
        int parenthesisDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        for (int index = startIndex; index < value.length(); index++) {
            char c = value.charAt(index);
            if (escaping) {
                escaping = false;
                continue;
            }
            if ((inSingleQuote || inDoubleQuote) && c == '\\') {
                escaping = true;
                continue;
            }
            if (inSingleQuote) {
                if (c == '\'') {
                    inSingleQuote = false;
                }
                continue;
            }
            if (inDoubleQuote) {
                if (c == '"') {
                    inDoubleQuote = false;
                }
                continue;
            }
            if (c == '\'') {
                inSingleQuote = true;
                continue;
            }
            if (c == '"') {
                inDoubleQuote = true;
                continue;
            }
            if (c == '(') {
                parenthesisDepth++;
                continue;
            }
            if (c == ')' && parenthesisDepth > 0) {
                parenthesisDepth--;
                continue;
            }
            if (c == '[') {
                bracketDepth++;
                continue;
            }
            if (c == ']' && bracketDepth > 0) {
                bracketDepth--;
                continue;
            }
            if (c == '{') {
                braceDepth++;
                continue;
            }
            if (c == '}' && braceDepth > 0) {
                braceDepth--;
                continue;
            }
            if (parenthesisDepth == 0 && bracketDepth == 0 && braceDepth == 0 && c == ':') {
                return index;
            }
        }
        return -1;
    }

    private static int findTopLevelOperator(String value, String operator) {
        int parenthesisDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        for (int index = 0; index <= value.length() - operator.length(); index++) {
            char c = value.charAt(index);
            if (escaping) {
                escaping = false;
                continue;
            }
            if ((inSingleQuote || inDoubleQuote) && c == '\\') {
                escaping = true;
                continue;
            }
            if (inSingleQuote) {
                if (c == '\'') {
                    inSingleQuote = false;
                }
                continue;
            }
            if (inDoubleQuote) {
                if (c == '"') {
                    inDoubleQuote = false;
                }
                continue;
            }
            if (c == '\'') {
                inSingleQuote = true;
                continue;
            }
            if (c == '"') {
                inDoubleQuote = true;
                continue;
            }
            if (c == '(') {
                parenthesisDepth++;
                continue;
            }
            if (c == ')' && parenthesisDepth > 0) {
                parenthesisDepth--;
                continue;
            }
            if (c == '[') {
                bracketDepth++;
                continue;
            }
            if (c == ']' && bracketDepth > 0) {
                bracketDepth--;
                continue;
            }
            if (c == '{') {
                braceDepth++;
                continue;
            }
            if (c == '}' && braceDepth > 0) {
                braceDepth--;
                continue;
            }
            if (parenthesisDepth == 0 && bracketDepth == 0 && braceDepth == 0 && value.startsWith(operator, index)) {
                return index;
            }
        }
        return -1;
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
        if (looksLikeEncodedHighEntropyToken(normalized)) {
            return false;
        }
        String[] parts;
        String lower = normalized.toLowerCase(Locale.ENGLISH);
        if (lower.contains("_") || lower.contains("-")) {
            parts = lower.split("[_-]+");
        } else if (looksLikeCamelOrPascalIdentifier(normalized)) {
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

    private static boolean looksLikeGeneratedRandomName(String fieldName, String value) {
        if (!isRandomNameField(fieldName)) {
            return false;
        }
        String normalized = nullToEmpty(value).trim();
        if (normalized.isEmpty()) {
            return false;
        }
        return normalized.matches("[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z][A-Za-z0-9]*)+-\\d{6,}");
    }

    private static boolean looksLikeGeneratedParameterSeparatorName(String sourceName, String fieldName, String value) {
        if (!isNameField(fieldName)) {
            return false;
        }
        String normalizedSource = nullToEmpty(sourceName).replace('\\', '/');
        if (!normalizedSource.contains("/jenkins.plugins.parameter__separator.ParameterSeparatorDefinition/name")) {
            return false;
        }
        String normalizedValue = nullToEmpty(value).trim();
        return normalizedValue.matches(
                "[A-Za-z][A-Za-z0-9]*(?:-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    }

    private static boolean looksLikeLocalFileReference(String value) {
        String trimmed = nullToEmpty(value).trim();
        if (trimmed.isEmpty() || trimmed.contains("://")) {
            return false;
        }
        if (trimmed.matches("[A-Za-z]:\\\\[^\\s]+") || trimmed.matches("(?:/|\\./|\\.\\./|~/)[^\\s]+")) {
            return true;
        }
        if ((trimmed.contains("/") || trimmed.contains("\\")) && trimmed.matches("[A-Za-z0-9._/\\\\@%+=:-]+")) {
            return true;
        }
        return trimmed.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,120}\\.[A-Za-z0-9]{1,10}");
    }

    private static String findContainingHttpUrl(String originalValue, String candidate) {
        if (originalValue == null || candidate == null || candidate.isBlank()) {
            return "";
        }
        Matcher matcher = HTTP_URL.matcher(originalValue);
        while (matcher.find()) {
            String url = stripTrailingUrlPunctuation(matcher.group());
            if (url.contains(candidate)) {
                return url;
            }
        }
        return "";
    }

    private static String stripTrailingUrlPunctuation(String value) {
        String trimmed = nullToEmpty(value).trim();
        while (!trimmed.isEmpty()) {
            char last = trimmed.charAt(trimmed.length() - 1);
            if (".,;!?)]}）】，。；！？".indexOf(last) < 0) {
                break;
            }
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static boolean urlAuthorityLooksCredentialed(String url) {
        int authorityStart = url.indexOf("://");
        if (authorityStart < 0) {
            return false;
        }
        authorityStart += 3;
        int authorityEnd = url.length();
        for (char delimiter : new char[] {'/', '?', '#'}) {
            int delimiterIndex = url.indexOf(delimiter, authorityStart);
            if (delimiterIndex >= 0) {
                authorityEnd = Math.min(authorityEnd, delimiterIndex);
            }
        }
        String authority = url.substring(authorityStart, authorityEnd);
        int userInfoEnd = authority.lastIndexOf('@');
        return userInfoEnd > 0 && authority.substring(0, userInfoEnd).contains(":");
    }

    private static boolean urlContainsSensitiveQueryOrFragment(String url) {
        String query = urlQuery(url);
        if (!query.isBlank()) {
            for (String parameter : query.split("[&;]")) {
                int separator = parameter.indexOf('=');
                String name = separator >= 0 ? parameter.substring(0, separator) : parameter;
                String value = separator >= 0 ? parameter.substring(separator + 1) : "";
                if (SENSITIVE_URL_NAME.matcher(name).matches()
                        || (!value.isBlank() && value.length() >= 16 && entropy(value) >= 4.0)) {
                    return true;
                }
            }
        }
        String fragment = urlFragment(url);
        return !fragment.isBlank()
                && (SENSITIVE_URL_NAME.matcher(fragment).matches()
                        || (fragment.length() >= 16 && entropy(fragment) >= 4.0));
    }

    private static String urlPath(String url) {
        int authorityStart = url.indexOf("://");
        if (authorityStart < 0) {
            return "";
        }
        authorityStart += 3;
        int pathStart = url.indexOf('/', authorityStart);
        if (pathStart < 0) {
            return "";
        }
        int pathEnd = url.length();
        for (char delimiter : new char[] {'?', '#'}) {
            int delimiterIndex = url.indexOf(delimiter, pathStart);
            if (delimiterIndex >= 0) {
                pathEnd = Math.min(pathEnd, delimiterIndex);
            }
        }
        return url.substring(pathStart, pathEnd);
    }

    private static String urlQuery(String url) {
        int queryStart = url.indexOf('?');
        if (queryStart < 0) {
            return "";
        }
        int fragmentStart = url.indexOf('#', queryStart + 1);
        return fragmentStart >= 0 ? url.substring(queryStart + 1, fragmentStart) : url.substring(queryStart + 1);
    }

    private static String urlFragment(String url) {
        int fragmentStart = url.indexOf('#');
        return fragmentStart >= 0 && fragmentStart + 1 < url.length() ? url.substring(fragmentStart + 1) : "";
    }

    private static boolean looksLikeReadableUrlPath(String path) {
        String[] segments = nullToEmpty(path).split("/+");
        int readableSegments = 0;
        for (String segment : segments) {
            if (segment.isBlank()) {
                continue;
            }
            if (segment.length() > 80 || !segment.matches("[A-Za-z0-9._~%+=:-]+")) {
                return false;
            }
            if (segment.length() >= 24
                    && entropy(segment) >= 4.0
                    && !UUID.matcher(segment).matches()) {
                return false;
            }
            if (segment.matches(".*[A-Za-z].*")) {
                readableSegments++;
            }
        }
        return readableSegments >= 2;
    }

    private static boolean urlPathLooksSensitive(String path) {
        for (String segment : nullToEmpty(path).split("/+")) {
            if (SENSITIVE_URL_NAME.matcher(segment).matches()) {
                return true;
            }
        }
        return false;
    }

    private static boolean looksLikeEncodedHighEntropyToken(String value) {
        return value.length() >= 32 && value.length() % 4 == 0 && value.matches("[A-Za-z0-9+/]+={0,2}");
    }

    private static boolean looksLikeCamelOrPascalIdentifier(String value) {
        return value.matches("[A-Za-z][A-Za-z0-9]*") && value.matches(".*[A-Z].*") && value.matches(".*[a-z][A-Z].*");
    }

    private static boolean looksLikeJenkinsfilePath(String originalValue, String candidate) {
        String token = expandToken(originalValue, candidate).trim();
        if (token.isEmpty()) {
            return false;
        }
        String lower = token.toLowerCase(Locale.ENGLISH);
        return lower.equals("jenkinsfile")
                || lower.endsWith("/jenkinsfile")
                || lower.endsWith(".jenkinsfile")
                || lower.contains("/jenkinsfile.")
                || lower.contains(".jenkinsfile/");
    }

    private static boolean looksLikeStorageUriPath(String originalValue, String candidate) {
        String token = expandToken(originalValue, candidate).trim();
        if (!STORAGE_URI_SCHEME.matcher(token).matches() || token.contains("?") || token.contains("#")) {
            return false;
        }
        int schemeSeparator = token.indexOf("://");
        if (schemeSeparator < 0 || schemeSeparator + 3 >= token.length()) {
            return false;
        }
        String remainder = token.substring(schemeSeparator + 3);
        int firstSlash = remainder.indexOf('/');
        String authority = firstSlash >= 0 ? remainder.substring(0, firstSlash) : remainder;
        String path = firstSlash >= 0 ? remainder.substring(firstSlash) : "";
        if (path.isBlank() || !path.startsWith("/") || authorityLooksLikeCredentialUserInfo(authority)) {
            return false;
        }
        if (!authority.isBlank() && !looksLikeStorageAuthority(authority)) {
            return false;
        }
        return looksLikeReadableStoragePath(path);
    }

    private static boolean looksLikeBenignDatabaseConnectionParameter(String originalValue, String candidate) {
        if (!isInsideJdbcQuery(originalValue, candidate)) {
            return false;
        }
        String token = expandToken(originalValue, candidate).trim();
        int separator = token.indexOf('=');
        if (separator <= 0 || separator == token.length() - 1) {
            return false;
        }
        String parameterName = token.substring(0, separator);
        if (!looksLikeReadableParameterName(parameterName)
                || SENSITIVE_PARAMETER_NAME.matcher(token).matches()) {
            return false;
        }
        String parameterValue = token.substring(separator + 1);
        return looksLikeReadableConnectionParameterValue(parameterValue);
    }

    private static boolean isInsideJdbcQuery(String originalValue, String candidate) {
        String original = nullToEmpty(originalValue);
        if (original.isBlank() || candidate == null || candidate.isBlank()) {
            return false;
        }
        Matcher matcher = JDBC_URL.matcher(original);
        while (matcher.find()) {
            String url = matcher.group();
            int queryIndex = url.indexOf('?');
            int candidateIndex = url.indexOf(candidate);
            if (queryIndex >= 0 && candidateIndex > queryIndex && !databaseAuthorityLooksCredentialed(url)) {
                return true;
            }
        }
        return false;
    }

    private static boolean databaseAuthorityLooksCredentialed(String url) {
        int schemeSeparator = url.indexOf("://");
        if (schemeSeparator < 0) {
            return false;
        }
        int authorityStart = schemeSeparator + 3;
        int authorityEnd = url.length();
        for (char delimiter : new char[] {'/', '?', '#'}) {
            int delimiterIndex = url.indexOf(delimiter, authorityStart);
            if (delimiterIndex >= 0) {
                authorityEnd = Math.min(authorityEnd, delimiterIndex);
            }
        }
        String authority = url.substring(authorityStart, authorityEnd);
        int userInfoEnd = authority.lastIndexOf('@');
        return userInfoEnd > 0 && authority.substring(0, userInfoEnd).contains(":");
    }

    private static boolean looksLikeReadableParameterName(String value) {
        return value != null && value.matches("[A-Za-z][A-Za-z0-9_.-]{1,80}");
    }

    private static boolean looksLikeReadableConnectionParameterValue(String value) {
        String trimmed = nullToEmpty(value).trim();
        if (trimmed.isEmpty() || trimmed.length() > 160 || !trimmed.matches("[A-Za-z0-9_.,:=+-]+")) {
            return false;
        }
        String normalized = trimmed.replaceAll("[.,:=+-]+", "_");
        return looksLikeHumanReadableIdentifier(normalized);
    }

    private static boolean authorityLooksLikeCredentialUserInfo(String authority) {
        if (authority == null || authority.isBlank()) {
            return false;
        }
        int atIndex = authority.indexOf('@');
        if (atIndex < 0) {
            return false;
        }
        int dotIndex = authority.indexOf('.');
        return dotIndex < 0 || atIndex < dotIndex;
    }

    private static boolean looksLikeStorageAuthority(String authority) {
        return looksLikeHostPort(authority) || looksLikeReadableStorageSegment(authority);
    }

    private static boolean looksLikeReadableStoragePath(String path) {
        String[] segments = path.split("/+");
        int readableSegments = 0;
        for (String segment : segments) {
            if (segment.isBlank()) {
                continue;
            }
            if (!looksLikeReadableStorageSegment(segment)) {
                return false;
            }
            readableSegments++;
        }
        return readableSegments >= 2;
    }

    private static boolean looksLikeReadableStorageSegment(String segment) {
        if (segment.isBlank() || segment.length() > 80 || !segment.matches("[A-Za-z0-9._=:-]+")) {
            return false;
        }
        return segment.matches(".*[A-Za-z].*") || segment.matches(".*[0-9].*");
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
