package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.List;
import org.htmlunit.Page;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardJobActionTest {
    private final SecretGuardJobAction action = new SecretGuardJobAction(null);

    @Test
    void keepsShortLocationUnchanged() {
        SecretFinding finding = finding("Jenkinsfile");

        assertEquals("Jenkinsfile", action.getDisplayLocation(finding));
    }

    @Test
    void compactsLongPathToUsefulTailSegments() {
        SecretFinding finding = finding("/flow-definition/properties/hudson.model.ParametersDefinitionProperty/"
                + "parameterDefinitions/hudson.model.StringParameterDefinition/description");

        assertEquals(
                "\u2026/parameterDefinitions/hudson.model.StringParameterDefinition/description",
                action.getDisplayLocation(finding));
    }

    @Test
    void middleEllipsizesLongNonPathLocation() {
        SecretFinding finding = finding("pipeline-step-" + "a".repeat(120) + "-environment-value");

        String displayLocation = action.getDisplayLocation(finding);

        assertTrue(displayLocation.length() <= 96);
        assertTrue(displayLocation.startsWith("pipeline-step-"));
        assertTrue(displayLocation.contains("\u2026"));
        assertTrue(displayLocation.endsWith("-environment-value"));
    }

    @Test
    void groupsFindingsBySeverityInHighToLowOrder() {
        SecretFinding lowFinding = finding("low-source", Severity.LOW);
        SecretFinding highFindingOne = finding("high-source-one", Severity.HIGH);
        SecretFinding mediumFinding = finding("medium-source", Severity.MEDIUM);
        SecretFinding highFindingTwo = finding("high-source-two", Severity.HIGH);

        List<SecretGuardJobAction.SeverityGroup> groups = SecretGuardJobAction.groupFindingsBySeverity(
                List.of(lowFinding, highFindingOne, mediumFinding, highFindingTwo));

        assertEquals(
                List.of(Severity.HIGH, Severity.MEDIUM, Severity.LOW),
                groups.stream()
                        .map(SecretGuardJobAction.SeverityGroup::getSeverity)
                        .toList());
        assertEquals(List.of(highFindingOne, highFindingTwo), groups.get(0).getFindings());
        assertEquals(2, groups.get(0).getCount());
        assertEquals(List.of(mediumFinding), groups.get(1).getFindings());
        assertEquals(List.of(lowFinding), groups.get(2).getFindings());
    }

    @Test
    void omitsEmptySeverityGroups() {
        List<SecretGuardJobAction.SeverityGroup> groups =
                SecretGuardJobAction.groupFindingsBySeverity(List.of(finding("medium-only", Severity.MEDIUM)));

        assertEquals(1, groups.size());
        assertEquals(Severity.MEDIUM, groups.get(0).getSeverity());
        assertFalse(groups.stream().anyMatch(group -> group.getSeverity() == Severity.HIGH));
        assertFalse(groups.stream().anyMatch(group -> group.getSeverity() == Severity.LOW));
    }

    @Test
    void labelsSuppressionNotesAsWhySuppressed() {
        SecretFinding finding = finding("example-source", Severity.MEDIUM)
                .withAnalysisNote("Suppressed generic finding(s) for the same value: high-entropy-string.");

        assertEquals("Synthetic finding", action.getWhyFlagged(finding));
        assertTrue(action.hasWhyAdjusted(finding));
        assertEquals("Why suppressed", action.getWhyAdjustedLabel(finding));
    }

    @Test
    void labelsNonSuppressionNotesAsWhyAdjusted() {
        SecretFinding finding = finding("example-source", Severity.LOW)
                .withAnalysisNote(
                        "Downgraded because the value looks like a redaction placeholder instead of a real secret.");

        assertEquals("Why adjusted", action.getWhyAdjustedLabel(finding));
    }

    @Test
    @WithJenkins
    void rendersFindingsGroupedBySeverityOnJobPage(JenkinsRule jenkinsRule) throws Exception {
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("example-job");
        ScanResultStore.get()
                .put(new SecretScanResult(
                        project.getFullName(),
                        project.getClass().getSimpleName(),
                        List.of(
                                finding("low-source", Severity.LOW),
                                finding("high-source", Severity.HIGH)
                                        .withAnalysisNote(
                                                "Suppressed generic finding(s) for the same value: high-entropy-string."),
                                finding("medium-source", Severity.MEDIUM)),
                        false));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        Page page = webClient.goTo(project.getUrl() + "secret-guard");
        String content = page.getWebResponse().getContentAsString();

        assertTrue(content.contains("HIGH"));
        assertTrue(content.contains("MEDIUM"));
        assertTrue(content.contains("LOW"));
        assertFalse(content.contains("Scan notes"));
        assertTrue(content.contains("1 finding(s)"));
        assertTrue(content.contains("Why flagged:"));
        assertTrue(content.contains("Why suppressed:"));
        assertTrue(content.indexOf("high-source") < content.indexOf("medium-source"));
        assertTrue(content.indexOf("medium-source") < content.indexOf("low-source"));
    }

    private static SecretFinding finding(String sourceName) {
        return finding(sourceName, Severity.MEDIUM);
    }

    private static SecretFinding finding(String sourceName, Severity severity) {
        return new SecretFinding(
                "synthetic-rule",
                "Synthetic finding",
                severity,
                FindingLocationType.CONFIG_XML,
                "example-job",
                sourceName,
                -1,
                "field",
                "****",
                "Review the value.");
    }
}
