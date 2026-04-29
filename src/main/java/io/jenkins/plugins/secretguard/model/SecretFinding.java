package io.jenkins.plugins.secretguard.model;

import java.util.Objects;

public class SecretFinding {
    private final String ruleId;
    private final String title;
    private final Severity severity;
    private final FindingLocationType locationType;
    private final String jobFullName;
    private final String sourceName;
    private final int lineNumber;
    private final String fieldName;
    private final String maskedSnippet;
    private final String recommendation;
    private final String analysisNote;
    private final boolean exempted;
    private final String exemptionReason;
    private final transient String evidenceKey;

    public SecretFinding(
            String ruleId,
            String title,
            Severity severity,
            FindingLocationType locationType,
            String jobFullName,
            String sourceName,
            int lineNumber,
            String fieldName,
            String maskedSnippet,
            String recommendation) {
        this(
                ruleId,
                title,
                severity,
                locationType,
                jobFullName,
                sourceName,
                lineNumber,
                fieldName,
                maskedSnippet,
                recommendation,
                "",
                false,
                "",
                "");
    }

    public SecretFinding(
            String ruleId,
            String title,
            Severity severity,
            FindingLocationType locationType,
            String jobFullName,
            String sourceName,
            int lineNumber,
            String fieldName,
            String maskedSnippet,
            String recommendation,
            String analysisNote) {
        this(
                ruleId,
                title,
                severity,
                locationType,
                jobFullName,
                sourceName,
                lineNumber,
                fieldName,
                maskedSnippet,
                recommendation,
                analysisNote,
                false,
                "",
                "");
    }

    private SecretFinding(
            String ruleId,
            String title,
            Severity severity,
            FindingLocationType locationType,
            String jobFullName,
            String sourceName,
            int lineNumber,
            String fieldName,
            String maskedSnippet,
            String recommendation,
            String analysisNote,
            boolean exempted,
            String exemptionReason,
            String evidenceKey) {
        this.ruleId = Objects.requireNonNull(ruleId);
        this.title = Objects.requireNonNull(title);
        this.severity = Objects.requireNonNull(severity);
        this.locationType = Objects.requireNonNull(locationType);
        this.jobFullName = nullToEmpty(jobFullName);
        this.sourceName = nullToEmpty(sourceName);
        this.lineNumber = lineNumber;
        this.fieldName = nullToEmpty(fieldName);
        this.maskedSnippet = nullToEmpty(maskedSnippet);
        this.recommendation = nullToEmpty(recommendation);
        this.analysisNote = nullToEmpty(analysisNote);
        this.exempted = exempted;
        this.exemptionReason = nullToEmpty(exemptionReason);
        this.evidenceKey = nullToEmpty(evidenceKey);
    }

    public SecretFinding withExemption(String reason) {
        return new SecretFinding(
                ruleId,
                title,
                severity,
                locationType,
                jobFullName,
                sourceName,
                lineNumber,
                fieldName,
                maskedSnippet,
                recommendation,
                analysisNote,
                true,
                reason,
                evidenceKey);
    }

    public SecretFinding withAnalysisNote(String note) {
        return new SecretFinding(
                ruleId,
                title,
                severity,
                locationType,
                jobFullName,
                sourceName,
                lineNumber,
                fieldName,
                maskedSnippet,
                recommendation,
                appendNote(analysisNote, note),
                exempted,
                exemptionReason,
                evidenceKey);
    }

    public SecretFinding withEvidenceKeyFromValue(String rawValue) {
        return withEvidenceKey(normalizeEvidenceKey(rawValue));
    }

    public SecretFinding withEvidenceKey(String key) {
        String normalizedKey = nullToEmpty(key);
        if (evidenceKey.equals(normalizedKey)) {
            return this;
        }
        return new SecretFinding(
                ruleId,
                title,
                severity,
                locationType,
                jobFullName,
                sourceName,
                lineNumber,
                fieldName,
                maskedSnippet,
                recommendation,
                analysisNote,
                exempted,
                exemptionReason,
                normalizedKey);
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTitle() {
        return title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public FindingLocationType getLocationType() {
        return locationType;
    }

    public String getJobFullName() {
        return jobFullName;
    }

    public String getSourceName() {
        return sourceName;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public String getFieldName() {
        return fieldName;
    }

    public String getMaskedSnippet() {
        return maskedSnippet;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public String getAnalysisNote() {
        return analysisNote;
    }

    public boolean isExempted() {
        return exempted;
    }

    public String getExemptionReason() {
        return exemptionReason;
    }

    public String getEvidenceKey() {
        return evidenceKey;
    }

    public boolean isActionable() {
        return !exempted;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String appendNote(String existing, String additional) {
        String normalizedExisting = nullToEmpty(existing).trim();
        String normalizedAdditional = nullToEmpty(additional).trim();
        if (normalizedAdditional.isEmpty()) {
            return normalizedExisting;
        }
        if (normalizedExisting.isEmpty()) {
            return normalizedAdditional;
        }
        if (normalizedExisting.contains(normalizedAdditional)) {
            return normalizedExisting;
        }
        return normalizedExisting + " " + normalizedAdditional;
    }

    private static String normalizeEvidenceKey(String value) {
        String trimmed = nullToEmpty(value).trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        java.util.regex.Matcher bearerMatcher = java.util.regex.Pattern.compile(
                        "(?i)^Bearer\\s+([A-Za-z0-9._~+/=-]{12,})$")
                .matcher(trimmed);
        if (bearerMatcher.matches()) {
            return bearerMatcher.group(1);
        }
        java.util.regex.Matcher queryMatcher = java.util.regex.Pattern.compile(
                        "(?i)^(?:key|token|secret|password|access[_-]?token|access[_-]?key|api[_-]?key|auth(?:[_-]?token)?|webhook|client[_-]?secret|secret[_-]?key|signature|sig)=([^&#\\s'\"<>\\\\]+)$")
                .matcher(trimmed);
        if (queryMatcher.matches()) {
            return queryMatcher.group(1);
        }
        return trimmed;
    }
}
