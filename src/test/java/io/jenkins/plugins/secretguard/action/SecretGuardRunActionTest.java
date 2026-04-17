package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.XStream2;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecretGuardRunActionTest {
    @Test
    void showsRunActionWhenScanHasNotesWithoutFindings() {
        SecretGuardRunAction action = new SecretGuardRunAction(new SecretScanResult(
                "folder/job",
                "WorkflowJob",
                List.of(),
                false,
                List.of("Secret Guard skipped an SCM Jenkinsfile because lightweight access was unavailable.")));

        assertTrue(action.hasNotes());
        assertTrue(action.getFindings().isEmpty());
        assertTrue(action.getIconFileName() != null);
        assertTrue(action.getDisplayName() != null);
        assertTrue(action.getUrlName() != null);
    }

    @Test
    void canMarshalRunActionWithoutJavaTimeBlacklistFailure() {
        SecretGuardRunAction action = new SecretGuardRunAction(new SecretScanResult(
                "folder/job",
                "WorkflowJob",
                List.of(
                        new SecretFinding(
                                "url-query-secret",
                                "Secret is embedded in a URL query parameter",
                                Severity.HIGH,
                                FindingLocationType.COMMAND_STEP,
                                "folder/job",
                                "Pipeline script",
                                12,
                                "key",
                                "Exa…DEF",
                                "Move URL query secrets such as webhook keys to Jenkins Credentials and inject them at runtime.")),
                true,
                Instant.parse("2026-04-16T00:00:00Z")));

        String xml = new XStream2().toXML(action);

        assertTrue(xml.contains("<scannedAtEpochMillis>"));
        assertTrue(!xml.contains("java.time.Instant"));
    }
}
