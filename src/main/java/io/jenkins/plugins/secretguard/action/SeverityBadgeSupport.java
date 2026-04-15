package io.jenkins.plugins.secretguard.action;

import io.jenkins.plugins.secretguard.model.Severity;

public interface SeverityBadgeSupport {
    default String getSeverityBadgeStyle(Severity severity) {
        return "display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;"
                + "font-weight:700;line-height:1.5;border:1px solid "
                + getSeverityBadgeBorderColor(severity)
                + ";background:"
                + getSeverityBadgeBackgroundColor(severity)
                + ";color:"
                + getSeverityBadgeTextColor(severity)
                + ";";
    }

    default String getSeverityBadgeLabel(Severity severity) {
        return severity == null ? "UNKNOWN" : severity.name();
    }

    private String getSeverityBadgeBackgroundColor(Severity severity) {
        if (severity == Severity.HIGH) {
            return "#fff1f0";
        }
        if (severity == Severity.MEDIUM) {
            return "#fff7ed";
        }
        return "#eff6ff";
    }

    private String getSeverityBadgeBorderColor(Severity severity) {
        if (severity == Severity.HIGH) {
            return "#f5c2c0";
        }
        if (severity == Severity.MEDIUM) {
            return "#f7c9a1";
        }
        return "#b6d4fe";
    }

    private String getSeverityBadgeTextColor(Severity severity) {
        if (severity == Severity.HIGH) {
            return "#b42318";
        }
        if (severity == Severity.MEDIUM) {
            return "#b54708";
        }
        return "#175cd3";
    }
}
