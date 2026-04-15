package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.Severity;
import org.junit.jupiter.api.Test;

class SeverityBadgeSupportTest {
    private final SeverityBadgeSupport support = new SeverityBadgeSupport() {};

    @Test
    void returnsDistinctStylesPerSeverity() {
        assertTrue(support.getSeverityBadgeStyle(Severity.HIGH).contains("#fff1f0"));
        assertTrue(support.getSeverityBadgeStyle(Severity.MEDIUM).contains("#fff7ed"));
        assertTrue(support.getSeverityBadgeStyle(Severity.LOW).contains("#eff6ff"));
    }

    @Test
    void returnsFallbackLabelForNullSeverity() {
        assertEquals("UNKNOWN", support.getSeverityBadgeLabel(null));
    }
}
