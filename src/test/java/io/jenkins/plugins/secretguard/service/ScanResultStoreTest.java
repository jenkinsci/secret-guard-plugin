package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.XmlFile;
import hudson.util.XStream2;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import java.io.File;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
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
        SecretScanResult result = new SecretScanResult(
                "folder/job",
                "WorkflowJob",
                List.of(finding(false)),
                true,
                List.of("Secret Guard skipped one SCM-backed Jenkinsfile because lightweight access was unavailable."),
                scannedAt);

        writer.put(result);

        ScanResultStore reader = ScanResultStore.inDirectory(temporaryDirectory);
        SecretScanResult loaded = reader.get("folder/job").orElseThrow();
        assertEquals("folder/job", loaded.getTargetId());
        assertEquals("WorkflowJob", loaded.getTargetType());
        assertEquals(scannedAt.toEpochMilli(), loaded.getScannedAt().toEpochMilli());
        assertTrue(loaded.isBlocked());
        assertEquals(1, loaded.getFindings().size());
        assertEquals(1, loaded.getNotes().size());
        assertEquals(
                "Secret Guard skipped one SCM-backed Jenkinsfile because lightweight access was unavailable.",
                loaded.getNotes().get(0));
        assertEquals("Exa…DEF", loaded.getFindings().get(0).getMaskedSnippet());
        assertEquals(
                "Suppressed generic finding(s) for the same value: high-entropy-string.",
                loaded.getFindings().get(0).getAnalysisNote());
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

    @Test
    void persistedXmlNeverIncludesRawScannedContentOrRawSecretValues() throws Exception {
        String rawSecretValue = "ghp_012345678901234567890123456789012345";
        String rawPipelineContent =
                "pipeline { agent any stages { stage('ship') { steps { echo 'shipping release' } } } }";
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[%s
                    def token = '%s'
                    ]]></script>
                  </definition>
                </flow-definition>
                """.formatted(rawPipelineContent, rawSecretValue);

        ScanResultStore store = ScanResultStore.inDirectory(temporaryDirectory);
        SecretScanResult scanned = new ConfigXmlScanner().scan(context(), xml);
        assertFalse(scanned.getFindings().isEmpty());

        store.put(scanned);

        File[] persistedFiles = temporaryDirectory.listFiles((dir, name) -> name.endsWith(".xml"));
        assertEquals(1, persistedFiles == null ? 0 : persistedFiles.length);
        String persistedXml = Files.readString(persistedFiles[0].toPath());

        assertTrue(persistedXml.contains("folder/job"));
        assertTrue(persistedXml.contains("WorkflowJob"));
        assertFalse(persistedXml.contains(rawSecretValue));
        assertFalse(persistedXml.contains(rawPipelineContent));
        assertFalse(persistedXml.contains("shipping release"));
    }

    @Test
    void ignoresMalformedPersistedFilesWhileLoadingHealthyResults() throws Exception {
        ScanResultStore writer = ScanResultStore.inDirectory(temporaryDirectory);
        writer.put(new SecretScanResult(
                "healthy/job", "WorkflowJob", List.of(finding(false)), false, Instant.parse("2026-04-15T12:00:00Z")));
        Files.writeString(new File(temporaryDirectory, "broken.xml").toPath(), "<broken");

        ScanResultStore reader = ScanResultStore.inDirectory(temporaryDirectory);
        List<SecretScanResult> loaded = reader.getAll();

        assertEquals(1, loaded.size());
        assertEquals("healthy/job", loaded.get(0).getTargetId());
    }

    @Test
    void toleratesLegacyPersistedFilesWithMissingOrInvalidOptionalFields() throws Exception {
        ScanResultStore.PersistedScanResult legacy = new ScanResultStore.PersistedScanResult();
        legacy.targetId = "legacy/job";
        legacy.targetType = null;
        legacy.blocked = false;
        legacy.scannedAtEpochMillis = 0L;
        legacy.notes = null;

        ScanResultStore.PersistedFinding legacyFinding = new ScanResultStore.PersistedFinding();
        legacyFinding.ruleId = null;
        legacyFinding.title = null;
        legacyFinding.severity = "NOT_A_REAL_SEVERITY";
        legacyFinding.locationType = "NOT_A_REAL_LOCATION";
        legacyFinding.jobFullName = "legacy/job";
        legacyFinding.sourceName = "config.xml";
        legacyFinding.lineNumber = 7;
        legacyFinding.fieldName = "field";
        legacyFinding.maskedSnippet = "abc…xyz";
        legacyFinding.recommendation = "Rotate the secret.";
        legacyFinding.analysisNote = null;
        legacyFinding.exempted = false;
        legacyFinding.exemptionReason = null;
        legacy.findings = new ArrayList<>(List.of(legacyFinding));

        new XmlFile(new XStream2(), new File(temporaryDirectory, "legacy%2Fjob.xml")).write(legacy);

        ScanResultStore reader = ScanResultStore.inDirectory(temporaryDirectory);
        SecretScanResult loaded = reader.get("legacy/job").orElseThrow();

        assertEquals("legacy/job", loaded.getTargetId());
        assertEquals("", loaded.getTargetType());
        assertEquals(1, loaded.getFindings().size());
        assertEquals("unknown", loaded.getFindings().get(0).getRuleId());
        assertEquals(Severity.LOW, loaded.getFindings().get(0).getSeverity());
        assertEquals(FindingLocationType.CONFIG_XML, loaded.getFindings().get(0).getLocationType());
        assertFalse(loaded.hasNotes());
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
                "Move URL query secrets such as webhook keys to Jenkins Credentials and inject them at runtime.",
                "Suppressed generic finding(s) for the same value: high-entropy-string.");
        return exempted ? finding.withExemption("approved test exemption") : finding;
    }

    private ScanContext context() {
        return new ScanContext(
                "folder/job",
                "config.xml",
                "WorkflowJob",
                FindingLocationType.CONFIG_XML,
                ScanPhase.SAVE,
                EnforcementMode.AUDIT,
                Severity.HIGH);
    }
}
