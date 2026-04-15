package io.jenkins.plugins.secretguard.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SecretScanResult {
    private final String targetId;
    private final String targetType;
    private final List<SecretFinding> findings;
    private final Severity highestSeverity;
    private final boolean blocked;
    private final Instant scannedAt;

    public SecretScanResult(String targetId, String targetType, List<SecretFinding> findings, boolean blocked) {
        this(targetId, targetType, findings, blocked, Instant.now());
    }

    public SecretScanResult(
            String targetId, String targetType, List<SecretFinding> findings, boolean blocked, Instant scannedAt) {
        this.targetId = targetId == null ? "" : targetId;
        this.targetType = targetType == null ? "" : targetType;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.highestSeverity = calculateHighestSeverity(findings);
        this.blocked = blocked;
        this.scannedAt = scannedAt == null ? Instant.now() : scannedAt;
    }

    public static SecretScanResult empty(String targetId, String targetType) {
        return new SecretScanResult(targetId, targetType, Collections.emptyList(), false);
    }

    public String getTargetId() {
        return targetId;
    }

    public String getTargetType() {
        return targetType;
    }

    public List<SecretFinding> getFindings() {
        return findings;
    }

    public Severity getHighestSeverity() {
        return highestSeverity;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    public boolean hasActionableFindingsAtOrAbove(Severity severity) {
        return findings.stream()
                .anyMatch(finding ->
                        finding.isActionable() && finding.getSeverity().isAtLeast(severity));
    }

    public long getUnexemptedHighCount() {
        return findings.stream()
                .filter(finding -> finding.isActionable() && finding.getSeverity() == Severity.HIGH)
                .count();
    }

    private static Severity calculateHighestSeverity(List<SecretFinding> findings) {
        Severity highest = Severity.LOW;
        for (SecretFinding finding : findings) {
            if (finding.getSeverity().ordinal() > highest.ordinal()) {
                highest = finding.getSeverity();
            }
        }
        return highest;
    }
}
