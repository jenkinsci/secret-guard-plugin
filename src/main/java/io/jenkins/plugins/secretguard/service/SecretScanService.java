package io.jenkins.plugins.secretguard.service;

import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.SecretScanner;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class SecretScanService {
    private static final String HIGH_ENTROPY_RULE = "high-entropy-string";
    private static final String SENSITIVE_FIELD_RULE = "sensitive-field-name";
    private static final Set<String> SPECIFIC_SECRET_RULES = Set.of(
            "jwt-token",
            "github-token",
            "aws-access-key",
            "aws-secret-key",
            "bearer-token",
            "pem-private-key",
            "url-embedded-secret",
            "url-query-secret",
            "http-request-hardcoded-header-secret",
            "http-request-unmasked-header-secret");

    private final WhitelistService whitelistService;
    private final ExemptionService exemptionService;

    public SecretScanService() {
        this(new WhitelistService(), new ExemptionService());
    }

    SecretScanService(WhitelistService whitelistService, ExemptionService exemptionService) {
        this.whitelistService = whitelistService;
        this.exemptionService = exemptionService;
    }

    public SecretScanResult scan(SecretScanner scanner, ScanContext context, String content) {
        SecretScanResult rawResult = scanner.scan(context, content);
        return process(context, rawResult.getFindings());
    }

    public SecretScanResult process(ScanContext context, List<SecretFinding> rawFindings) {
        return process(context, rawFindings, List.of());
    }

    public SecretScanResult process(ScanContext context, List<SecretFinding> rawFindings, List<String> notes) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        if (configuration != null && !configuration.isEnabled()) {
            return SecretScanResult.empty(context.getJobFullName(), context.getTargetType(), notes);
        }
        List<SecretFinding> processedFindings = new ArrayList<>();
        for (SecretFinding finding : rawFindings) {
            SecretFinding processed = whitelistService.isWhitelisted(finding)
                    ? finding.withExemption("Whitelisted by global Secret Guard configuration")
                    : exemptionService.applyExemption(finding);
            processedFindings.add(processed);
        }
        processedFindings = dedupeByRulePriority(processedFindings);
        boolean blocked = shouldBlock(context, processedFindings);
        SecretScanResult result = new SecretScanResult(
                context.getJobFullName(), context.getTargetType(), processedFindings, blocked, notes);
        ScanResultStore.get().put(result);
        return result;
    }

    public boolean shouldWarn(ScanContext context, SecretScanResult result) {
        return context.getEnforcementMode() == EnforcementMode.WARN && result.hasFindings();
    }

    private boolean shouldBlock(ScanContext context, List<SecretFinding> findings) {
        if (context.getEnforcementMode() != EnforcementMode.BLOCK) {
            return false;
        }
        Severity threshold = context.getBlockThreshold();
        return findings.stream()
                .anyMatch(finding ->
                        finding.isActionable() && finding.getSeverity().isAtLeast(threshold));
    }

    private List<SecretFinding> dedupeByRulePriority(List<SecretFinding> findings) {
        List<SecretFinding> deduped = new ArrayList<>();
        for (SecretFinding candidate : findings) {
            if (isSuppressed(candidate, findings)) {
                continue;
            }
            List<SecretFinding> suppressedFindings = suppressedByCandidate(candidate, findings);
            deduped.add(
                    suppressedFindings.isEmpty()
                            ? candidate
                            : candidate.withAnalysisNote(buildSuppressionNote(suppressedFindings)));
        }
        return deduped;
    }

    private boolean isSuppressed(SecretFinding candidate, List<SecretFinding> findings) {
        for (SecretFinding other : findings) {
            if (candidate == other || !sameFindingScope(candidate, other)) {
                continue;
            }
            if (suppresses(other.getRuleId(), candidate.getRuleId())) {
                return true;
            }
        }
        return false;
    }

    private List<SecretFinding> suppressedByCandidate(SecretFinding candidate, List<SecretFinding> findings) {
        List<SecretFinding> suppressed = new ArrayList<>();
        for (SecretFinding other : findings) {
            if (candidate == other || !sameFindingScope(candidate, other)) {
                continue;
            }
            if (suppresses(candidate.getRuleId(), other.getRuleId())) {
                suppressed.add(other);
            }
        }
        return suppressed;
    }

    private boolean sameFindingScope(SecretFinding left, SecretFinding right) {
        return left.getLineNumber() == right.getLineNumber()
                && left.getFieldName().equals(right.getFieldName())
                && left.getMaskedSnippet().equals(right.getMaskedSnippet())
                && left.getSourceName().equals(right.getSourceName());
    }

    private boolean suppresses(String strongerRuleId, String weakerRuleId) {
        if (SPECIFIC_SECRET_RULES.contains(strongerRuleId) && HIGH_ENTROPY_RULE.equals(weakerRuleId)) {
            return true;
        }
        return SPECIFIC_SECRET_RULES.contains(strongerRuleId) && SENSITIVE_FIELD_RULE.equals(weakerRuleId);
    }

    private String buildSuppressionNote(List<SecretFinding> suppressedFindings) {
        if (suppressedFindings.isEmpty()) {
            return "";
        }
        Set<String> suppressedRuleIds = suppressedFindings.stream()
                .map(SecretFinding::getRuleId)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        return "Suppressed generic finding(s) for the same value: " + String.join(", ", suppressedRuleIds) + ".";
    }
}
