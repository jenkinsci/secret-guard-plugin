package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.Severity;
import org.junit.jupiter.api.Test;

class SeverityBadgeSupportTest {
    private final SeverityBadgeSupport support = new SeverityBadgeSupport() {};

    @Test
    void returnsDistinctClassesPerSeverity() {
        assertTrue(support.getSeverityBadgeClass(Severity.HIGH).contains("secret-guard-badge--high"));
        assertTrue(support.getSeverityBadgeClass(Severity.MEDIUM).contains("secret-guard-badge--medium"));
        assertTrue(support.getSeverityBadgeClass(Severity.LOW).contains("secret-guard-badge--low"));
    }

    @Test
    void returnsFallbackLabelForNullSeverity() {
        assertEquals("UNKNOWN", support.getSeverityBadgeLabel(null));
    }
}
