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
    private final boolean exempted;
    private final String exemptionReason;

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
                false,
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
            boolean exempted,
            String exemptionReason) {
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
        this.exempted = exempted;
        this.exemptionReason = nullToEmpty(exemptionReason);
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
                true,
                reason);
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

    public boolean isExempted() {
        return exempted;
    }

    public String getExemptionReason() {
        return exemptionReason;
    }

    public boolean isActionable() {
        return !exempted;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
