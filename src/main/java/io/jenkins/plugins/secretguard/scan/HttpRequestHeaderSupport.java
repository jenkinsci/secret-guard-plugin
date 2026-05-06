package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

final class HttpRequestHeaderSupport {
    private static final Pattern HEADER_SENSITIVE_NAME =
            Pattern.compile("(?i)(authorization|token|secret|api[_-]?key|apikey|auth|credential)");
    private static final String HTTP_HEADER_RULE_ID = "http-request-hardcoded-header-secret";
    private static final String HTTP_HEADER_UNMASKED_RULE_ID = "http-request-unmasked-header-secret";
    private static final String HTTP_HEADER_REMEDIATION =
            "Use withCredentials or a credentials-backed variable for custom headers instead of hardcoded literals.";

    private HttpRequestHeaderSupport() {}

    static List<SecretFinding> scanHardcodedCustomHeader(
            ScanContext context,
            int lineNumber,
            String headerName,
            String headerValueExpression,
            boolean maskValueFalse) {
        if (headerValueExpression.isBlank()
                || looksLikeGroovyVariableReference(headerValueExpression)
                || NonSecretHeuristics.isRuntimeSecretReference(headerValueExpression)) {
            return List.of();
        }
        String headerValue = unquote(headerValueExpression);
        if (!looksLikeHardcodedSecretHeaderValue(headerName, headerValue)) {
            return List.of();
        }
        List<SecretFinding> findings = new ArrayList<>();
        findings.add(new SecretFinding(
                        HTTP_HEADER_RULE_ID,
                        "Hardcoded custom header secret in httpRequest",
                        Severity.HIGH,
                        context.getLocationType(),
                        context.getJobFullName(),
                        context.getSourceName(),
                        lineNumber,
                        headerName.isBlank() ? "customHeader" : headerName,
                        SecretMasker.mask(headerValue),
                        HTTP_HEADER_REMEDIATION)
                .withEvidenceKeyFromValue(headerValue));
        if (maskValueFalse) {
            findings.add(new SecretFinding(
                            HTTP_HEADER_UNMASKED_RULE_ID,
                            "Custom header secret is configured with maskValue: false",
                            Severity.HIGH,
                            context.getLocationType(),
                            context.getJobFullName(),
                            context.getSourceName(),
                            lineNumber,
                            headerName.isBlank() ? "customHeader" : headerName,
                            SecretMasker.mask(headerValue),
                            "Set maskValue to true and keep the header value in Jenkins Credentials.")
                    .withEvidenceKeyFromValue(headerValue));
        }
        return findings;
    }

    static boolean looksLikeGroovyVariableReference(String value) {
        String trimmed = value.trim();
        return trimmed.matches("[A-Za-z_][A-Za-z0-9_]*");
    }

    static List<ParsedCustomHeader> parseHeaderExpression(String expression, int baseLineNumber) {
        String trimmed = normalizeHeaderExpression(expression);
        if (trimmed.length() < 2 || !trimmed.startsWith("[") || !trimmed.endsWith("]")) {
            return List.of();
        }
        String listBody = trimmed.substring(1, trimmed.length() - 1);
        List<ParsedCustomHeader> headers = new ArrayList<>();
        for (Segment item : splitTopLevelSegments(listBody)) {
            String itemText = stripBalancedParens(item.text().trim());
            if (itemText.length() < 2 || !itemText.startsWith("[") || !itemText.endsWith("]")) {
                continue;
            }
            String mapBody = itemText.substring(1, itemText.length() - 1);
            String headerName = "";
            String headerValueExpression = "";
            boolean maskValueFalse = false;
            int lineNumber = baseLineNumber + countNewlines(listBody, item.startOffset());
            for (Segment property : splitTopLevelSegments(mapBody)) {
                String propertyText = property.text().trim();
                int colonIndex = propertyText.indexOf(':');
                if (colonIndex < 0) {
                    continue;
                }
                String propertyName = normalizeMapKey(propertyText.substring(0, colonIndex));
                String propertyValue = stripBalancedParens(
                        propertyText.substring(colonIndex + 1).trim());
                if ("name".equals(propertyName)) {
                    headerName = unquote(propertyValue);
                } else if ("value".equals(propertyName)) {
                    headerValueExpression = propertyValue;
                    lineNumber = baseLineNumber + countNewlines(listBody, item.startOffset() + property.startOffset());
                } else if ("maskvalue".equals(propertyName)) {
                    maskValueFalse = "false".equalsIgnoreCase(unquote(propertyValue));
                }
            }
            if (!headerValueExpression.isBlank()) {
                headers.add(new ParsedCustomHeader(headerName, headerValueExpression, maskValueFalse, lineNumber));
            }
        }
        return headers;
    }

    static ExtractedExpression extractBracketedExpression(String[] lines, int startLineIndex, int startColumn) {
        BracketStart bracketStart = findBracketStart(lines, startLineIndex, startColumn);
        if (bracketStart == null) {
            return ExtractedExpression.empty(startLineIndex);
        }
        StringBuilder expression = new StringBuilder();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        int bracketDepth = 0;
        for (int currentLine = bracketStart.lineIndex(); currentLine < lines.length; currentLine++) {
            String line = lines[currentLine];
            int start = currentLine == bracketStart.lineIndex() ? bracketStart.columnIndex() : 0;
            for (int index = start; index < line.length(); index++) {
                char c = line.charAt(index);
                expression.append(c);
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
                } else if (c == '"') {
                    inDoubleQuote = true;
                } else if (c == '[') {
                    bracketDepth++;
                } else if (c == ']') {
                    bracketDepth--;
                    if (bracketDepth == 0) {
                        return new ExtractedExpression(expression.toString(), currentLine, index);
                    }
                }
            }
            if (currentLine + 1 < lines.length) {
                expression.append('\n');
            }
        }
        return ExtractedExpression.empty(startLineIndex);
    }

    private static BracketStart findBracketStart(String[] lines, int startLineIndex, int startColumn) {
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        for (int lineIndex = startLineIndex; lineIndex < lines.length; lineIndex++) {
            String line = lines[lineIndex];
            int column = lineIndex == startLineIndex ? startColumn : 0;
            for (int index = column; index < line.length(); index++) {
                char c = line.charAt(index);
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
                if (c == '[') {
                    return new BracketStart(lineIndex, index);
                }
            }
        }
        return null;
    }

    private static String normalizeHeaderExpression(String expression) {
        String trimmed = stripBalancedParens(expression == null ? "" : expression.trim());
        int castIndex = indexOfTopLevelAsKeyword(trimmed);
        if (castIndex >= 0) {
            trimmed = trimmed.substring(0, castIndex).trim();
        }
        return stripBalancedParens(trimmed);
    }

    private static String normalizeMapKey(String value) {
        return unquote(stripBalancedParens(value == null ? "" : value.trim())).toLowerCase(Locale.ENGLISH);
    }

    private static String stripBalancedParens(String value) {
        String result = value == null ? "" : value.trim();
        while (result.length() >= 2 && result.startsWith("(") && result.endsWith(")")) {
            int depth = 0;
            boolean balanced = true;
            for (int index = 0; index < result.length(); index++) {
                char c = result.charAt(index);
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth == 0 && index < result.length() - 1) {
                        balanced = false;
                        break;
                    }
                }
                if (depth < 0) {
                    balanced = false;
                    break;
                }
            }
            if (!balanced || depth != 0) {
                break;
            }
            result = result.substring(1, result.length() - 1).trim();
        }
        return result;
    }

    private static int indexOfTopLevelAsKeyword(String value) {
        int parenthesisDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean escaping = false;
        for (int index = 0; index < value.length() - 1; index++) {
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
            if (parenthesisDepth == 0 && bracketDepth == 0 && braceDepth == 0 && startsWithAsKeyword(value, index)) {
                return index;
            }
        }
        return -1;
    }

    private static boolean startsWithAsKeyword(String value, int index) {
        if (!value.regionMatches(true, index, "as", 0, 2)) {
            return false;
        }
        boolean leftBoundary = index == 0 || Character.isWhitespace(value.charAt(index - 1));
        boolean rightBoundary = index + 2 >= value.length() || Character.isWhitespace(value.charAt(index + 2));
        return leftBoundary && rightBoundary;
    }

    private static List<Segment> splitTopLevelSegments(String value) {
        List<Segment> segments = new ArrayList<>();
        if (value == null || value.isEmpty()) {
            return segments;
        }
        int segmentStart = 0;
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
            } else if (c == '"') {
                inDoubleQuote = true;
            } else if (c == '(') {
                parenthesisDepth++;
            } else if (c == ')' && parenthesisDepth > 0) {
                parenthesisDepth--;
            } else if (c == '[') {
                bracketDepth++;
            } else if (c == ']' && bracketDepth > 0) {
                bracketDepth--;
            } else if (c == '{') {
                braceDepth++;
            } else if (c == '}' && braceDepth > 0) {
                braceDepth--;
            } else if (c == ',' && parenthesisDepth == 0 && bracketDepth == 0 && braceDepth == 0) {
                addSegment(segments, value, segmentStart, index);
                segmentStart = index + 1;
            }
        }
        addSegment(segments, value, segmentStart, value.length());
        return segments;
    }

    private static void addSegment(List<Segment> segments, String source, int start, int end) {
        int trimmedStart = start;
        int trimmedEnd = end;
        while (trimmedStart < trimmedEnd && Character.isWhitespace(source.charAt(trimmedStart))) {
            trimmedStart++;
        }
        while (trimmedEnd > trimmedStart && Character.isWhitespace(source.charAt(trimmedEnd - 1))) {
            trimmedEnd--;
        }
        if (trimmedStart < trimmedEnd) {
            segments.add(new Segment(source.substring(trimmedStart, trimmedEnd), trimmedStart));
        }
    }

    private static int countNewlines(String value, int endExclusive) {
        int limit = Math.max(0, Math.min(endExclusive, value.length()));
        int count = 0;
        for (int index = 0; index < limit; index++) {
            if (value.charAt(index) == '\n') {
                count++;
            }
        }
        return count;
    }

    private static String unquote(String value) {
        String trimmed = value.trim();
        if (trimmed.length() >= 2
                && ((trimmed.startsWith("\"") && trimmed.endsWith("\""))
                        || (trimmed.startsWith("'") && trimmed.endsWith("'")))) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static boolean looksLikeHardcodedSecretHeaderValue(String headerName, String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return false;
        }
        if (NonSecretHeuristics.isBenignTrackingHeaderName(headerName)) {
            return false;
        }
        String trimmed = headerValue.trim();
        if (NonSecretHeuristics.isRuntimeSecretReference(trimmed)
                || NonSecretHeuristics.looksLikePlaceholderValue(trimmed)) {
            return false;
        }
        if (HEADER_SENSITIVE_NAME.matcher(headerName == null ? "" : headerName).find()) {
            return true;
        }
        if (trimmed.matches("(?i)Bearer\\s+[A-Za-z0-9._~+/=-]{12,}")) {
            return true;
        }
        if (!trimmed.matches("[A-Za-z0-9+/=_-]{20,}")) {
            return false;
        }
        return NonSecretHeuristics.entropy(trimmed) >= 4.0;
    }

    record ParsedCustomHeader(String name, String valueExpression, boolean maskValueFalse, int lineNumber) {}

    record ExtractedExpression(String value, int endLineIndex, int endColumnIndex) {
        private static ExtractedExpression empty(int lineIndex) {
            return new ExtractedExpression("", lineIndex, -1);
        }
    }

    private record BracketStart(int lineIndex, int columnIndex) {}

    private record Segment(String text, int startOffset) {}
}
