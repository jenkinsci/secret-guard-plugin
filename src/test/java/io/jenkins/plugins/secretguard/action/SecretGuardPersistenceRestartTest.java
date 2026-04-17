package io.jenkins.plugins.secretguard.action;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.FreeStyleProject;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.service.ScanResultStore;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import org.htmlunit.Page;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.fixtures.JenkinsSessionFixture;

class SecretGuardPersistenceRestartTest {
    @Test
    void restoresJobAndRootReportsAfterControllerRestart() throws Throwable {
        JenkinsSessionFixture sessions = new JenkinsSessionFixture();
        sessions.setUp(getClass().getName(), "restoresJobAndRootReportsAfterControllerRestart");
        try {
            sessions.then(jenkinsRule -> {
                FreeStyleProject project = jenkinsRule.createFreeStyleProject("restart-survival");
                ScanResultStore.get()
                        .put(new SecretScanResult(
                                project.getFullName(),
                                project.getClass().getSimpleName(),
                                List.of(finding(project.getFullName())),
                                false,
                                List.of(
                                        "Secret Guard skipped one SCM-backed Jenkinsfile because lightweight access was unavailable."),
                                Instant.parse("2026-04-17T12:00:00Z")));
            });

            sessions.then(jenkinsRule -> {
                clearInMemoryStoreCache();

                JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
                Page jobPage = webClient.goTo("job/restart-survival/secret-guard");
                String jobContent = jobPage.getWebResponse().getContentAsString();

                assertTrue(jobContent.contains("Scan notes"));
                assertTrue(jobContent.contains("Secret Guard skipped one SCM-backed Jenkinsfile"));
                assertTrue(jobContent.contains("synthetic-rule"));

                Page rootPage = webClient.goTo("secret-guard");
                String rootContent = rootPage.getWebResponse().getContentAsString();

                assertTrue(rootContent.contains("restart-survival"));
                assertTrue(rootContent.contains(">Yes<"));
                assertFalse(rootContent.contains("Secret Guard skipped one SCM-backed Jenkinsfile"));
            });
        } finally {
            sessions.tearDown();
        }
    }

    private static void clearInMemoryStoreCache() throws Exception {
        Field resultsField = ScanResultStore.class.getDeclaredField("results");
        resultsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentMap<String, SecretScanResult> results =
                (ConcurrentMap<String, SecretScanResult>) resultsField.get(ScanResultStore.get());
        results.clear();
        assertTrue(results.isEmpty());
    }

    private static SecretFinding finding(String jobFullName) {
        return new SecretFinding(
                "synthetic-rule",
                "Synthetic secret finding",
                Severity.HIGH,
                FindingLocationType.CONFIG_XML,
                jobFullName,
                "config.xml",
                12,
                "field",
                "tok…123",
                "Move the plaintext secret to Jenkins Credentials and inject it only at runtime.");
    }
}
