package io.jenkins.plugins.secretguard.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretScanResultTest {
    @Test
    void reportsActionableAndExemptedFindingCountsSeparately() {
        SecretFinding actionableHigh = finding("synthetic-high", Severity.HIGH);
        SecretFinding exemptedMedium =
                finding("synthetic-medium", Severity.MEDIUM).withExemption("approved");

        SecretScanResult result =
                new SecretScanResult("example-job", "WorkflowJob", List.of(actionableHigh, exemptedMedium), false);

        assertTrue(result.hasFindings());
        assertTrue(result.hasActionableFindings());
        assertTrue(result.hasExemptedFindings());
        assertEquals(1, result.getActionableFindingsCount());
        assertEquals(1, result.getExemptedFindingsCount());
        assertEquals(1, result.getUnexemptedHighCount());
    }

    @Test
    void reportsNoActionableFindingsWhenAllFindingsAreExempted() {
        SecretScanResult result = new SecretScanResult(
                "example-job",
                "WorkflowJob",
                List.of(finding("synthetic-medium", Severity.MEDIUM).withExemption("approved")),
                false);

        assertTrue(result.hasFindings());
        assertFalse(result.hasActionableFindings());
        assertEquals(0, result.getActionableFindingsCount());
        assertEquals(1, result.getExemptedFindingsCount());
        assertEquals(0, result.getUnexemptedHighCount());
    }

    private static SecretFinding finding(String ruleId, Severity severity) {
        return new SecretFinding(
                ruleId,
                "Synthetic finding",
                severity,
                FindingLocationType.PIPELINE_SCRIPT,
                "example-job",
                "Pipeline script",
                1,
                "field",
                "****",
                "Review the value.");
    }
}
