package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class GlobalJobScanStatusTest {
    @Test
    void exposesProgressAndSummary() {
        GlobalJobScanStatus status = new GlobalJobScanStatus(
                GlobalJobScanStatus.State.RUNNING,
                8,
                3,
                2,
                1,
                1,
                "folder/example",
                "Scanning folder/example",
                Instant.now(),
                null,
                List.of("folder/failed-job"));

        assertEquals(37, status.getProgressPercentage());
        assertEquals(8, status.getProgressMax());
        assertEquals(3, status.getSummary().getJobsScanned());
        assertEquals(2, status.getSummary().getJobsWithFindings());
        assertEquals(1, status.getSummary().getJobsWithHighSeverity());
        assertEquals(1, status.getSummary().getJobsFailed());
        assertEquals(1, status.getFailedJobFullNames().size());
        assertTrue(status.isRunning());
    }

    @Test
    void defaultsNullStateAndScopeToSafeValues() {
        GlobalJobScanStatus status = new GlobalJobScanStatus(null, 1, 2, 0, 0, 0, null, null, null, null, null, null);

        assertEquals(GlobalJobScanStatus.State.IDLE, status.getState());
        assertEquals("", status.getScanScopeDescription());
        assertEquals(List.of(), status.getFailedJobFullNames());
        assertFalse(status.hasFailedJobs());
        assertFalse(status.isTerminal());
        assertEquals(100, status.getProgressPercentage());
    }
}
