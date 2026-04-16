package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jenkins.model.Jenkins;
import org.htmlunit.Page;
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
}
