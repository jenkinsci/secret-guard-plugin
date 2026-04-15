package io.jenkins.plugins.secretguard.listener;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.Failure;
import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import java.io.StringReader;
import javax.xml.transform.stream.StreamSource;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardEnforcementIntegrationTest {
    @Test
    @WithJenkins
    void blocksConfigXmlModificationInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        FreeStyleProject project = jenkinsRule.createFreeStyleProject("guarded");
        String originalXml = project.getConfigFile().asString();
        String riskyXml = withRiskyParameter(originalXml);

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl(project.getUrl() + "config.xml"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertEquals(409, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Secret Guard blocked saving"));
        String restoredXml = jenkinsRule
                .jenkins
                .getItemByFullName(project.getFullName(), FreeStyleProject.class)
                .getConfigFile()
                .asString();
        assertFalse(restoredXml.contains("API_TOKEN"));
        assertFalse(restoredXml.contains("ghp_012345678901234567890123456789012345"));
        assertTrue(restoredXml.contains("<properties/>") || restoredXml.contains("<properties></properties>"));
    }

    @Test
    @WithJenkins
    void blocksCreatingJobFromXmlInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.BLOCK);
        FreeStyleProject template = jenkinsRule.createFreeStyleProject("template");
        String riskyXml = withRiskyParameter(template.getConfigFile().asString());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        WebRequest request =
                new WebRequest(webClient.createCrumbedUrl("createItem?name=blocked-created-job"), HttpMethod.POST);
        request.setAdditionalHeader("Content-Type", "application/xml");
        request.setRequestBody(riskyXml);

        Page page = webClient.getPage(request);

        assertEquals(409, page.getWebResponse().getStatusCode());
        assertTrue(page.getWebResponse().getContentAsString().contains("Secret Guard blocked creating"));
        assertNull(jenkinsRule.jenkins.getItem("blocked-created-job"));
    }

    @Test
    @WithJenkins
    void blocksCopyingRiskyJobInBlockMode(JenkinsRule jenkinsRule) throws Exception {
        configure(EnforcementMode.AUDIT);
        FreeStyleProject source = jenkinsRule.createFreeStyleProject("copy-source");
        source.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(source.getConfigFile().asString()))));

        configure(EnforcementMode.BLOCK);

        Failure failure = assertThrows(
                Failure.class,
                () -> jenkinsRule.jenkins.copy((hudson.model.AbstractProject<?, ?>) source, "copy-target"));

        assertTrue(failure.getMessage().contains("Secret Guard blocked copying"));
        assertFalse(jenkinsRule.jenkins.getAllItems(FreeStyleProject.class).stream()
                .anyMatch(project -> project.getName().equals("copy-target")));
    }

    private void configure(EnforcementMode mode) {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(true);
        configuration.setEnforcementMode(mode);
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
