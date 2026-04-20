package io.jenkins.plugins.secretguard.action;

import io.jenkins.plugins.secretguard.model.SecretFinding;

public interface FindingExplanationSupport {
    default String getWhyFlagged(SecretFinding finding) {
        return finding == null ? "" : finding.getTitle();
    }

    default boolean hasWhyAdjusted(SecretFinding finding) {
        return finding != null && !finding.getAnalysisNote().isBlank();
    }

    default String getWhyAdjustedLabel(SecretFinding finding) {
        if (finding == null) {
            return "Why adjusted";
        }
        String note = finding.getAnalysisNote();
        if (note.startsWith("Suppressed ")) {
            return "Why suppressed";
        }
        return "Why adjusted";
    }

    default String getWhyAdjusted(SecretFinding finding) {
        return finding == null ? "" : finding.getAnalysisNote();
    }
}
