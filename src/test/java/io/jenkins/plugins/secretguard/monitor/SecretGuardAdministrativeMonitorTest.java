package io.jenkins.plugins.secretguard.monitor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.util.List;
import jenkins.model.Jenkins;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardAdministrativeMonitorTest {
    @Test
    @WithJenkins
    void managePageShowsDismissAndCanDisableMonitor(JenkinsRule jenkinsRule) throws Exception {
        String targetId = "monitor-test/job";
        ScanResultStore.get()
                .put(new SecretScanResult(
                        targetId,
                        "FreeStyleProject",
                        List.of(new SecretFinding(
                                "test-rule",
                                "Plain secret",
                                Severity.HIGH,
                                FindingLocationType.CONFIG_XML,
                                targetId,
                                "config.xml",
                                12,
                                "password",
                                "sup…ord",
                                "Move the plaintext secret to Jenkins Credentials.")),
                        false));

        jenkinsRule.jenkins.setSecurityRealm(jenkinsRule.createDummySecurityRealm());
        jenkinsRule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));

        SecretGuardAdministrativeMonitor monitor = jenkinsRule
                .jenkins
                .getExtensionList(SecretGuardAdministrativeMonitor.class)
                .get(0);
        assertTrue(monitor.isActivated());
        assertTrue(monitor.isEnabled());

        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        webClient.login("admin");

        Page managePage = webClient.goTo("manage");
        String initialContent = managePage.getWebResponse().getContentAsString();
        assertTrue(initialContent.contains("Jenkins Secret Guard"));
        assertTrue(initialContent.contains("Dismiss"));

        WebRequest dismissRequest =
                new WebRequest(webClient.createCrumbedUrl(monitor.getUrl() + "/disable"), HttpMethod.POST);
        Page dismissedPage = webClient.getPage(dismissRequest);

        assertEquals(200, dismissedPage.getWebResponse().getStatusCode());
        assertFalse(monitor.isEnabled());

        Page manageAfterDismiss = webClient.goTo("manage");
        assertFalse(manageAfterDismiss.getWebResponse().getContentAsString().contains("Jenkins Secret Guard"));

        ScanResultStore.get().remove(targetId);
    }
}
