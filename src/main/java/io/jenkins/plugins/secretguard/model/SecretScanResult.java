package io.jenkins.plugins.secretguard.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SecretScanResult {
    private final String targetId;
    private final String targetType;
    private final List<SecretFinding> findings;
    private final List<String> notes;
    private final Severity highestSeverity;
    private final boolean blocked;
    private final long scannedAtEpochMillis;

    public SecretScanResult(String targetId, String targetType, List<SecretFinding> findings, boolean blocked) {
        this(targetId, targetType, findings, blocked, Collections.emptyList(), Instant.now());
    }

    public SecretScanResult(
            String targetId, String targetType, List<SecretFinding> findings, boolean blocked, Instant scannedAt) {
        this(targetId, targetType, findings, blocked, Collections.emptyList(), scannedAt);
    }

    public SecretScanResult(
            String targetId, String targetType, List<SecretFinding> findings, boolean blocked, List<String> notes) {
        this(targetId, targetType, findings, blocked, notes, Instant.now());
    }

    public SecretScanResult(
            String targetId,
            String targetType,
            List<SecretFinding> findings,
            boolean blocked,
            List<String> notes,
            Instant scannedAt) {
        this.targetId = targetId == null ? "" : targetId;
        this.targetType = targetType == null ? "" : targetType;
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        this.notes = Collections.unmodifiableList(sanitizeNotes(notes));
        this.highestSeverity = calculateHighestSeverity(findings);
        this.blocked = blocked;
        this.scannedAtEpochMillis = (scannedAt == null ? Instant.now() : scannedAt).toEpochMilli();
    }

    public static SecretScanResult empty(String targetId, String targetType) {
        return new SecretScanResult(targetId, targetType, Collections.emptyList(), false);
    }

    public static SecretScanResult empty(String targetId, String targetType, List<String> notes) {
        return new SecretScanResult(targetId, targetType, Collections.emptyList(), false, notes);
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

    public List<String> getNotes() {
        return notes;
    }

    public Severity getHighestSeverity() {
        return highestSeverity;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public Instant getScannedAt() {
        return Instant.ofEpochMilli(scannedAtEpochMillis);
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    public boolean hasNotes() {
        return !notes.isEmpty();
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

    public long getExemptedFindingsCount() {
        return findings.stream().filter(SecretFinding::isExempted).count();
    }

    public boolean hasExemptedFindings() {
        return getExemptedFindingsCount() > 0;
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

    private static List<String> sanitizeNotes(List<String> notes) {
        if (notes == null || notes.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> sanitized = new ArrayList<>();
        for (String note : notes) {
            if (note != null && !note.isBlank()) {
                sanitized.add(note);
            }
        }
        return sanitized;
    }
}
