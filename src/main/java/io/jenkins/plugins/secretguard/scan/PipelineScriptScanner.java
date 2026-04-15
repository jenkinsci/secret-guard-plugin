package io.jenkins.plugins.secretguard.scan;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.rules.BuiltInSecretRuleSet;
import io.jenkins.plugins.secretguard.rules.SecretRule;
import io.jenkins.plugins.secretguard.util.NonSecretHeuristics;
import io.jenkins.plugins.secretguard.util.SecretMasker;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PipelineScriptScanner implements SecretScanner {
    private static final Pattern ASSIGNMENT =
            Pattern.compile("\\b([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern COMMAND_STEP = Pattern.compile("\\b(sh|bat|powershell)\\s*(?:\\(|['\"])");
    private static final Pattern HTTP_REQUEST = Pattern.compile("\\bhttpRequest\\b");
    private static final Pattern CUSTOM_HEADERS = Pattern.compile("\\bcustomHeaders\\s*:");
    private static final Pattern HEADER_NAME = Pattern.compile("\\bname\\s*:\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern HEADER_VALUE = Pattern.compile("\\bvalue\\s*:\\s*(['\"])([^'\"]{8,})\\1");
    private static final Pattern MASK_VALUE_FALSE = Pattern.compile("\\bmaskValue\\s*:\\s*false\\b");
    private static final Pattern HEADER_SENSITIVE_NAME =
            Pattern.compile("(?i)(authorization|token|secret|api[_-]?key|apikey|auth|credential)");
    private static final String HTTP_HEADER_RULE_ID = "http-request-hardcoded-header-secret";
    private static final String HTTP_HEADER_UNMASKED_RULE_ID = "http-request-unmasked-header-secret";
    private static final String HTTP_HEADER_REMEDIATION =
            "Use withCredentials or a credentials-backed variable for custom headers instead of hardcoded literals.";

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
        int environmentDepth = 0;
        int httpRequestWindow = 0;
        int customHeadersWindow = 0;
        String currentHeaderName = "";
        boolean currentHeaderMaskFalse = false;
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index];
            String trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
                continue;
            }
            if (HTTP_REQUEST.matcher(trimmed).find()) {
                httpRequestWindow = 12;
            } else if (httpRequestWindow > 0) {
                httpRequestWindow--;
            }
            if (httpRequestWindow > 0 && CUSTOM_HEADERS.matcher(trimmed).find()) {
                customHeadersWindow = 12;
                currentHeaderName = "";
                currentHeaderMaskFalse = false;
            } else if (customHeadersWindow > 0) {
                customHeadersWindow--;
            }
            if (customHeadersWindow > 0) {
                Matcher headerNameMatcher = HEADER_NAME.matcher(trimmed);
                if (headerNameMatcher.find()) {
                    currentHeaderName = headerNameMatcher.group(1);
                }
                if (MASK_VALUE_FALSE.matcher(trimmed).find()) {
                    currentHeaderMaskFalse = true;
                }
            }
            boolean opensEnvironment = trimmed.matches(".*\\benvironment\\s*\\{.*");
            if (opensEnvironment && environmentDepth == 0) {
                environmentDepth = 1;
            }
            FindingLocationType locationType = classifyLine(trimmed, environmentDepth > 0, context.getLocationType());
            ScanContext locationContext = context.withLocationType(locationType);
            String fieldName = extractFieldName(trimmed);
            String effectiveFieldName =
                    customHeadersWindow > 0 && fieldName.isBlank() && !currentHeaderName.isBlank()
                            ? currentHeaderName
                            : fieldName;
            for (SecretRule rule : ruleSet.getRules()) {
                findings.addAll(rule.scan(
                        locationContext, context.getSourceName(), index + 1, effectiveFieldName, trimmed));
            }
            if (customHeadersWindow > 0) {
                findings.addAll(scanHardcodedCustomHeader(locationContext, index + 1, trimmed, currentHeaderName, currentHeaderMaskFalse));
                if (trimmed.contains("]")) {
                    currentHeaderMaskFalse = false;
                }
            }
            environmentDepth = updateEnvironmentDepth(trimmed, environmentDepth, opensEnvironment);
        }
        return new SecretScanResult(context.getJobFullName(), context.getTargetType(), findings, false);
    }

    private List<SecretFinding> scanHardcodedCustomHeader(
            ScanContext context, int lineNumber, String line, String headerName, boolean maskValueFalse) {
        Matcher matcher = HEADER_VALUE.matcher(line);
        if (!matcher.find()) {
            return List.of();
        }
        String headerValue = matcher.group(2);
        if (!looksLikeHardcodedSecretHeaderValue(headerName, headerValue)) {
            return List.of();
        }
        List<SecretFinding> findings = new ArrayList<>();
        findings.add(new SecretFinding(
                HTTP_HEADER_RULE_ID,
                "Hardcoded custom header secret in httpRequest",
                Severity.HIGH,
                FindingLocationType.COMMAND_STEP,
                context.getJobFullName(),
                context.getSourceName(),
                lineNumber,
                headerName.isBlank() ? "customHeader" : headerName,
                SecretMasker.mask(headerValue),
                HTTP_HEADER_REMEDIATION));
        if (maskValueFalse) {
            findings.add(new SecretFinding(
                    HTTP_HEADER_UNMASKED_RULE_ID,
                    "Custom header secret is configured with maskValue: false",
                    Severity.HIGH,
                    FindingLocationType.COMMAND_STEP,
                    context.getJobFullName(),
                    context.getSourceName(),
                    lineNumber,
                    headerName.isBlank() ? "customHeader" : headerName,
                    SecretMasker.mask(headerValue),
                    "Set maskValue to true and keep the header value in Jenkins Credentials."));
        }
        return findings;
    }

    private boolean looksLikeHardcodedSecretHeaderValue(String headerName, String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return false;
        }
        if (NonSecretHeuristics.isBenignTrackingHeaderName(headerName)) {
            return false;
        }
        String trimmed = headerValue.trim();
        if (trimmed.contains("${") || trimmed.startsWith("$") || trimmed.contains("credentials(") || trimmed.contains("env.")) {
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
}
