package io.jenkins.plugins.secretguard.action;

import io.jenkins.plugins.secretguard.model.Severity;

public interface SeverityBadgeSupport {
    default String getSeverityBadgeClass(Severity severity) {
        if (severity == Severity.HIGH) {
            return "secret-guard-badge secret-guard-badge--high";
        }
        if (severity == Severity.MEDIUM) {
            return "secret-guard-badge secret-guard-badge--medium";
        }
        if (severity == Severity.LOW) {
            return "secret-guard-badge secret-guard-badge--low";
        }
        return "secret-guard-badge secret-guard-badge--unknown";
    }

    default String getSeverityBadgeLabel(Severity severity) {
        return severity == null ? "UNKNOWN" : severity.name();
    }
}
