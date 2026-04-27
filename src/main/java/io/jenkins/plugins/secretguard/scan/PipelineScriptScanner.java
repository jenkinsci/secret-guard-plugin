package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.rules.BuiltInSecretRuleSet;
import io.jenkins.plugins.secretguard.rules.SecretRule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PipelineScriptScanner implements SecretScanner {
    private static final Pattern ASSIGNMENT = Pattern.compile("\\b([A-Za-z_]\\w*)\\s*=\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern COMMAND_STEP = Pattern.compile("\\b(sh|bat|powershell)\\s*[('\"]");
    private static final Pattern HTTP_REQUEST = Pattern.compile("\\bhttpRequest\\b");
    private static final Pattern CUSTOM_HEADERS = Pattern.compile("\\bcustomHeaders\\s*:");

    private final BuiltInSecretRuleSet ruleSet;

    public PipelineScriptScanner() {
        this(new BuiltInSecretRuleSet());
    }

    PipelineScriptScanner(BuiltInSecretRuleSet ruleSet) {
        this.ruleSet = ruleSet;
    }

    @Override
    public SecretScanResult scan(ScanContext context, String content) {
        if (content == null || content.isBlank()) {
            return SecretScanResult.empty(context.getJobFullName(), context.getTargetType());
        }
        List<SecretFinding> findings = new ArrayList<>();
        String[] lines = content.split("\\R", -1);
        Map<Integer, List<HttpRequestHeaderSupport.ParsedCustomHeader>> customHeadersByLine =
                parseCustomHeadersByLine(lines);
        int environmentDepth = 0;
        for (int index = 0; index < lines.length; index++) {
            environmentDepth =
                    scanLine(context, findings, customHeadersByLine, lines[index], index + 1, environmentDepth);
        }
        return new SecretScanResult(context.getJobFullName(), context.getTargetType(), findings, false);
    }

    private int scanLine(
            ScanContext context,
            List<SecretFinding> findings,
            Map<Integer, List<HttpRequestHeaderSupport.ParsedCustomHeader>> customHeadersByLine,
            String line,
            int lineNumber,
            int environmentDepth) {
        String trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
            return environmentDepth;
        }
        boolean opensEnvironment = trimmed.matches(".*\\benvironment\\s*\\{.*");
        int scopedEnvironmentDepth = opensEnvironment && environmentDepth == 0 ? 1 : environmentDepth;
        ScanContext locationContext =
                context.withLocationType(classifyLine(trimmed, scopedEnvironmentDepth > 0, context.getLocationType()));
        List<HttpRequestHeaderSupport.ParsedCustomHeader> parsedHeaders = customHeadersByLine.get(lineNumber);
        scanParsedHeaders(context, findings, parsedHeaders);
        scanGenericRules(context, locationContext, findings, lineNumber, trimmed, parsedHeaders);
        return updateEnvironmentDepth(trimmed, scopedEnvironmentDepth, opensEnvironment);
    }

    private void scanParsedHeaders(
            ScanContext context,
            List<SecretFinding> findings,
            List<HttpRequestHeaderSupport.ParsedCustomHeader> parsedHeaders) {
        if (parsedHeaders == null || parsedHeaders.isEmpty()) {
            return;
        }
        ScanContext headerContext = context.withLocationType(FindingLocationType.COMMAND_STEP);
        for (HttpRequestHeaderSupport.ParsedCustomHeader parsedHeader : parsedHeaders) {
            scanHeaderWithGenericRules(context, headerContext, findings, parsedHeader);
            findings.addAll(HttpRequestHeaderSupport.scanHardcodedCustomHeader(
                    headerContext,
                    parsedHeader.lineNumber(),
                    parsedHeader.name(),
                    parsedHeader.valueExpression(),
                    parsedHeader.maskValueFalse()));
        }
    }

    private void scanHeaderWithGenericRules(
            ScanContext context,
            ScanContext headerContext,
            List<SecretFinding> findings,
            HttpRequestHeaderSupport.ParsedCustomHeader parsedHeader) {
        if (!shouldScanWithGenericRules(parsedHeader)) {
            return;
        }
        for (SecretRule rule : ruleSet.getRules()) {
            findings.addAll(rule.scan(
                    headerContext,
                    context.getSourceName(),
                    parsedHeader.lineNumber(),
                    parsedHeader.name(),
                    parsedHeader.valueExpression()));
        }
    }

    private void scanGenericRules(
            ScanContext context,
            ScanContext locationContext,
            List<SecretFinding> findings,
            int lineNumber,
            String trimmed,
            List<HttpRequestHeaderSupport.ParsedCustomHeader> parsedHeaders) {
        String genericLine = genericLine(trimmed, parsedHeaders);
        if (genericLine == null) {
            return;
        }
        String fieldName = extractFieldName(genericLine);
        for (SecretRule rule : ruleSet.getRules()) {
            findings.addAll(rule.scan(locationContext, context.getSourceName(), lineNumber, fieldName, genericLine));
        }
    }

    private String genericLine(String trimmed, List<HttpRequestHeaderSupport.ParsedCustomHeader> parsedHeaders) {
        return trimToNull(
                parsedHeaders == null || parsedHeaders.isEmpty()
                        ? trimmed
                        : sanitizeLineForGenericRuleScan(trimmed, parsedHeaders));
    }

    private boolean shouldScanWithGenericRules(HttpRequestHeaderSupport.ParsedCustomHeader header) {
        return !header.name().isBlank()
                && !header.valueExpression().isBlank()
                && !HttpRequestHeaderSupport.looksLikeGroovyVariableReference(header.valueExpression());
    }

    private String sanitizeLineForGenericRuleScan(
            String line, List<HttpRequestHeaderSupport.ParsedCustomHeader> parsedHeaders) {
        String sanitized = line;
        for (HttpRequestHeaderSupport.ParsedCustomHeader parsedHeader : parsedHeaders) {
            String valueExpression = parsedHeader.valueExpression();
            int matchIndex = sanitized.indexOf(valueExpression);
            if (matchIndex >= 0) {
                sanitized = sanitized.substring(0, matchIndex) + "SG_HEADER_VALUE"
                        + sanitized.substring(matchIndex + valueExpression.length());
            }
        }
        return sanitized;
    }

    private Map<Integer, List<HttpRequestHeaderSupport.ParsedCustomHeader>> parseCustomHeadersByLine(String[] lines) {
        Map<Integer, List<HttpRequestHeaderSupport.ParsedCustomHeader>> headersByLine = new HashMap<>();
        int httpRequestWindow = 0;
        for (int index = 0; index < lines.length; index++) {
            String trimmed = lines[index].trim();
            if (HTTP_REQUEST.matcher(trimmed).find()) {
                httpRequestWindow = 16;
            } else if (httpRequestWindow > 0) {
                httpRequestWindow--;
            }
            if (httpRequestWindow <= 0 || !CUSTOM_HEADERS.matcher(trimmed).find()) {
                continue;
            }
            ParsedCustomHeaders parsedHeaders = parseCustomHeaders(lines, index);
            for (HttpRequestHeaderSupport.ParsedCustomHeader header : parsedHeaders.headers()) {
                headersByLine
                        .computeIfAbsent(header.lineNumber(), ignored -> new ArrayList<>())
                        .add(header);
            }
        }
        return headersByLine;
    }

    private ParsedCustomHeaders parseCustomHeaders(String[] lines, int startLineIndex) {
        Matcher matcher = CUSTOM_HEADERS.matcher(lines[startLineIndex]);
        if (!matcher.find()) {
            return ParsedCustomHeaders.empty(startLineIndex);
        }
        HttpRequestHeaderSupport.ExtractedExpression expression =
                HttpRequestHeaderSupport.extractBracketedExpression(lines, startLineIndex, matcher.end());
        if (expression.value().isBlank()) {
            return ParsedCustomHeaders.empty(startLineIndex);
        }
        return new ParsedCustomHeaders(
                HttpRequestHeaderSupport.parseHeaderExpression(expression.value(), startLineIndex + 1),
                expression.endLineIndex());
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private FindingLocationType classifyLine(
            String line, boolean inEnvironmentBlock, FindingLocationType defaultLocationType) {
        String lower = line.toLowerCase(Locale.ENGLISH);
        if (inEnvironmentBlock || lower.contains("environment {")) {
            return FindingLocationType.ENVIRONMENT;
        }
        if (COMMAND_STEP.matcher(line).find()) {
            return FindingLocationType.COMMAND_STEP;
        }
        if (lower.contains("httprequest") || lower.contains("authorization: bearer")) {
            return FindingLocationType.COMMAND_STEP;
        }
        return defaultLocationType;
    }

    private String extractFieldName(String line) {
        Matcher matcher = ASSIGNMENT.matcher(line);
        if (matcher.find()) {
            return matcher.group(1);
        }
        if (line.toLowerCase(Locale.ENGLISH).contains("authorization: bearer")) {
            return "Authorization";
        }
        return "";
    }

    private int updateEnvironmentDepth(String line, int currentDepth, boolean opensEnvironment) {
        if (currentDepth <= 0) {
            return 0;
        }
        int depth = currentDepth;
        boolean environmentBraceConsumed = !opensEnvironment;
        for (int index = 0; index < line.length(); index++) {
            char c = line.charAt(index);
            if (c == '{') {
                if (environmentBraceConsumed) {
                    depth++;
                } else {
                    environmentBraceConsumed = true;
                }
            } else if (c == '}') {
                depth--;
            }
        }
        return Math.max(0, depth);
    }

    private record ParsedCustomHeaders(List<HttpRequestHeaderSupport.ParsedCustomHeader> headers, int endLineIndex) {
        private static ParsedCustomHeaders empty(int lineIndex) {
            return new ParsedCustomHeaders(List.of(), lineIndex);
        }
    }
}
