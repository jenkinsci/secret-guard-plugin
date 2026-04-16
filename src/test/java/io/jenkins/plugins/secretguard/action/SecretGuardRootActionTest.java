package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.config.SecretGuardGlobalConfiguration;
import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.io.StringReader;
import javax.xml.transform.stream.StreamSource;
import jenkins.model.Jenkins;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardRootActionTest {
    @Test
    void buildsJobSecretGuardPathForNestedJob() {
        assertEquals(
                "job/folder/job/sub%20job/secret-guard", SecretGuardRootAction.toJobSecretGuardPath("folder/sub job"));
    }

    @Test
    void returnsNullWhenTargetIdIsBlank() {
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(" "));
        assertNull(SecretGuardRootAction.toJobSecretGuardPath(null));
    }

    @Test
    @WithJenkins
    void globalPageRequiresManagePermission(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ)
                .everywhere()
                .to("alice")
                .grant(Jenkins.READ, Jenkins.MANAGE)
                .everywhere()
                .to("bob"));

        JenkinsRule.WebClient deniedClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        deniedClient.login("alice");
        Page deniedPage = deniedClient.goTo("secret-guard");
        assertEquals(403, deniedPage.getWebResponse().getStatusCode());

        JenkinsRule.WebClient allowedClient =
                jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        allowedClient.login("bob");
        Page allowedPage = allowedClient.goTo("secret-guard");
        assertEquals(200, allowedPage.getWebResponse().getStatusCode());
        assertTrue(allowedPage.getWebResponse().getContentAsString().contains("Jenkins Secret Guard"));
    }

    @Test
    @WithJenkins
    void manageUserCanScanAllJobsFromRootPage(JenkinsRule jenkinsRule) throws Exception {
        SecretGuardGlobalConfiguration configuration = SecretGuardGlobalConfiguration.get();
        configuration.setEnabled(false);

        FreeStyleProject project = jenkinsRule.createFreeStyleProject("scan-all-target");
        project.updateByXml(new StreamSource(
                new StringReader(withRiskyParameter(project.getConfigFile().asString()))));
        assertTrue(ScanResultStore.get().get(project.getFullName()).isEmpty());

        configuration.setEnabled(true);
        configuration.setEnforcementMode(EnforcementMode.AUDIT);
        configuration.setBlockThreshold(Severity.HIGH);

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin")
                .grant(Jenkins.READ, Jenkins.MANAGE)
                .everywhere()
                .to("bob"));

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("bob");

        Page page = webClient.goTo("secret-guard");
        assertTrue(page.getWebResponse().getContentAsString().contains("Scan All Jobs"));

        WebRequest request = new WebRequest(webClient.createCrumbedUrl("secret-guard/scanAll"), HttpMethod.POST);
        Page postResult = webClient.getPage(request);

        assertEquals(200, postResult.getWebResponse().getStatusCode());
        SecretGuardRootAction rootAction = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardRootAction.class)
                .get(0);
        waitForGlobalScanToFinish(rootAction);

        Page completedPage = webClient.goTo("secret-guard");

        assertTrue(completedPage.getWebResponse().getContentAsString().contains("COMPLETED"));
        assertTrue(completedPage.getWebResponse().getContentAsString().contains("Scanned 1 of 1 jobs"));
        assertTrue(completedPage.getWebResponse().getContentAsString().contains("Hide Scan Status"));
        assertFalse(rootAction.canCancelScanAll());
        assertTrue(rootAction.canDismissScanAllStatus());
        assertTrue(ScanResultStore.get().get(project.getFullName()).isPresent());
        assertTrue(
                ScanResultStore.get().get(project.getFullName()).orElseThrow().hasFindings());

        WebRequest dismissRequest =
                new WebRequest(webClient.createCrumbedUrl("secret-guard/dismissScanAllStatus"), HttpMethod.POST);
        Page dismissedPage = webClient.getPage(dismissRequest);

        assertEquals(200, dismissedPage.getWebResponse().getStatusCode());
        assertFalse(dismissedPage.getWebResponse().getContentAsString().contains("Hide Scan Status"));
        assertFalse(rootAction.canDismissScanAllStatus());
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

    private void waitForGlobalScanToFinish(SecretGuardRootAction rootAction) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10000;
        while (rootAction.getScanAllStatus().isRunning() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        assertFalse(rootAction.getScanAllStatus().isRunning());
    }
}
