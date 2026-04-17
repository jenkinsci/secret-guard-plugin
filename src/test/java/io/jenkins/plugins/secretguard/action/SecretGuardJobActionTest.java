package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import org.junit.jupiter.api.Test;

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

    private static SecretFinding finding(String sourceName) {
        return new SecretFinding(
                "synthetic-rule",
                "Synthetic finding",
                Severity.MEDIUM,
                FindingLocationType.CONFIG_XML,
                "example-job",
                sourceName,
                -1,
                "field",
                "****",
                "Review the value.");
    }
}
