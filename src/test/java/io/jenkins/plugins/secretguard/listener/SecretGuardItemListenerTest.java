package io.jenkins.plugins.secretguard.listener;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.io.StringReader;
import javax.xml.transform.stream.StreamSource;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardItemListenerTest {
    @Test
    @WithJenkins
    void removesLatestResultWhenJobIsDeleted(JenkinsRule jenkinsRule) throws Exception {
        configureAuditMode();
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("delete-me");
        project.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(project.getConfigFile().asString()))));

        assertTrue(ScanResultStore.get().get(project.getFullName()).isPresent());

        project.delete();

        assertTrue(ScanResultStore.get().get(project.getFullName()).isEmpty());
    }

    @Test
    @WithJenkins
    void removesOldLatestResultAndRefreshesNewOneWhenJobIsRenamed(JenkinsRule jenkinsRule) throws Exception {
        configureAuditMode();
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("before-rename");
        project.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(project.getConfigFile().asString()))));

        assertTrue(ScanResultStore.get().get("before-rename").isPresent());

        project.renameTo("after-rename");

        assertTrue(ScanResultStore.get().get("before-rename").isEmpty());
        assertTrue(ScanResultStore.get().get("after-rename").isPresent());
        assertTrue(ScanResultStore.get().get("after-rename").orElseThrow().hasFindings());
        assertFalse(ScanResultStore.get().get("after-rename").orElseThrow().isBlocked());
    }

    @Test
    @WithJenkins
    void skipsUpdateScanWhenFilterManagesSaveRequest(JenkinsRule jenkinsRule) throws Exception {
        configureAuditMode();
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("filter-managed-save");
        ScanResultStore.get().remove(project.getFullName());

        try (JobConfigSaveScanGuard.Scope ignored = JobConfigSaveScanGuard.filterManagedSave()) {
            project.updateByXml(new StreamSource(
                    new StringReader(withRiskyParameter(project.getConfigFile().asString()))));
        }

        assertTrue(ScanResultStore.get().get(project.getFullName()).isEmpty());
    }

    private void configureAuditMode() {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(true);
        configuration.setEnforcementMode(EnforcementMode.AUDIT);
        configuration.setBlockThreshold(Severity.HIGH);
    }

    private String withRiskyParameter(String xml) {
        String property = """
                <properties>
                  <hudson.model.ParametersDefinitionProperty>
                    <parameterDefinitions>
                      <hudson.model.StringParameterDefinition>
                        <name>API_TOKEN</name>
                        <defaultValue>ghp_012345678901234567890123456789012345</defaultValue>
                        <trim>false</trim>
                      </hudson.model.StringParameterDefinition>
                    </parameterDefinitions>
                  </hudson.model.ParametersDefinitionProperty>
                </properties>
                """;
        if (xml.contains("<properties/>")) {
            return xml.replace("<properties/>", property);
        }
        return xml.replace("<properties></properties>", property);
    }
}
