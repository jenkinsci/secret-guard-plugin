package io.jenkins.plugins.secretguard.listener;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecretGuardJobConfigFilterTest {
    @Test
    void rendersStructuredBlockedHtmlForModalDialog() {
        SecretScanResult result = new SecretScanResult(
                "folder/job",
                "FreeStyleProject",
                List.of(new SecretFinding(
                        "github-token",
                        "GitHub token is hardcoded",
                        Severity.HIGH,
                        FindingLocationType.CONFIG_XML,
                        "folder/job",
                        "config.xml",
                        12,
                        "API_TOKEN",
                        "ghp_?2345",
                        "Move plaintext secrets to Jenkins Credentials.")),
                true);
        String html = SecretGuardJobConfigFilter.buildBlockedHtml(null, result, "Blocked <message>", "/jenkins");

        assertTrue(html.contains("id=\"error-description\""));
        assertTrue(html.contains("role=\"alert\""));
        assertTrue(html.contains(">Error<"));
        assertTrue(html.contains("Secret Guard blocked the change"));
        assertTrue(html.contains("Blocked &lt;message&gt;"));
        assertTrue(html.contains("href=\"/jenkins/plugin/secret-guard/styles/secret-guard.css\""));
        assertTrue(html.contains("class=\"secret-guard-blocked-card\""));
        assertTrue(html.contains(">Rule</div><div><code>github-token</code></div>"));
        assertTrue(html.contains(">Masked snippet</div><div><code>ghp_?2345</code></div>"));
        assertTrue(html.contains("Move plaintext secrets to Jenkins Credentials."));
        assertFalse(html.contains("style="));
    }
}
