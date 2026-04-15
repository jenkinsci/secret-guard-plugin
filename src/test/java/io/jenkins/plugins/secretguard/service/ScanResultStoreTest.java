package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import java.io.File;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScanResultStoreTest {
    @TempDir
    private File temporaryDirectory;

    @Test
    void persistsAndReloadsLatestScanResult() {
        ScanResultStore writer = ScanResultStore.inDirectory(temporaryDirectory);
        Instant scannedAt = Instant.parse("2026-04-15T12:00:00Z");
        SecretScanResult result =
                new SecretScanResult("folder/job", "WorkflowJob", List.of(finding(false)), true, scannedAt);

        writer.put(result);

        ScanResultStore reader = ScanResultStore.inDirectory(temporaryDirectory);
        SecretScanResult loaded = reader.get("folder/job").orElseThrow();
        assertEquals("folder/job", loaded.getTargetId());
        assertEquals("WorkflowJob", loaded.getTargetType());
        assertEquals(scannedAt.toEpochMilli(), loaded.getScannedAt().toEpochMilli());
        assertTrue(loaded.isBlocked());
        assertEquals(1, loaded.getFindings().size());
        assertEquals("Exa…DEF", loaded.getFindings().get(0).getMaskedSnippet());
        assertEquals(1, reader.getAll().size());
    }

    @Test
    void persistsExemptionStateAndCanRemoveResult() {
        ScanResultStore store = ScanResultStore.inDirectory(temporaryDirectory);
        store.put(new SecretScanResult(
                "folder/job", "WorkflowJob", List.of(finding(true)), false, Instant.parse("2026-04-15T12:00:00Z")));

        ScanResultStore reader = ScanResultStore.inDirectory(temporaryDirectory);
        SecretFinding loadedFinding =
                reader.get("folder/job").orElseThrow().getFindings().get(0);
        assertTrue(loadedFinding.isExempted());
        assertEquals("approved test exemption", loadedFinding.getExemptionReason());

        reader.remove("folder/job");
        assertFalse(reader.get("folder/job").isPresent());
        assertEquals(0, reader.getAll().size());
    }

    private SecretFinding finding(boolean exempted) {
        SecretFinding finding = new SecretFinding(
                "url-query-secret",
                "Secret is embedded in a URL query parameter",
                Severity.HIGH,
                FindingLocationType.COMMAND_STEP,
                "folder/job",
                "Pipeline script",
                12,
                "key",
                "Exa…DEF",
                "Move URL query secrets such as webhook keys to Jenkins Credentials and inject them at runtime.");
        return exempted ? finding.withExemption("approved test exemption") : finding;
    }
}
