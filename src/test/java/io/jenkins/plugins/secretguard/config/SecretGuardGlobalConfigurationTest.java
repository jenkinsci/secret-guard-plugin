package io.jenkins.plugins.secretguard.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.FormValidation;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.List;
import java.util.Set;
import org.htmlunit.Page;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

class SecretGuardGlobalConfigurationTest {
    @Test
    void splitsAllowListEntriesByCommaOrNewline() {
        assertEquals(
                List.of("github-token", "url-query-secret", "high-entropy-string"),
                SecretGuardGlobalConfiguration.splitAllowListEntries(
                        "github-token,\nurl-query-secret\r\nhigh-entropy-string"));
    }

    @Test
    void keepsExemptionReasonsOnSingleLineEvenWhenTheyContainCommas() {
        assertEquals(
                List.of(
                        "team/service/release|github-token|approved for demo, rotate in staging",
                        "team/service/release|url-query-secret|accepted webhook sample"),
                SecretGuardGlobalConfiguration.splitExemptionEntries(
                        "team/service/release|github-token|approved for demo, rotate in staging\n"
                                + "team/service/release|url-query-secret|accepted webhook sample"));
    }

    @Test
    void rejectsMalformedExemptionLines() {
        FormValidation validation =
                SecretGuardGlobalConfiguration.validateExemptions("team/service/release|github-token");

        assertEquals(FormValidation.Kind.ERROR, validation.kind);
        assertTrue(validation.renderHtml().contains("jobFullName|ruleId|reason"));
    }

    @Test
    void warnsWhenExemptionReasonIsEmpty() {
        FormValidation validation =
                SecretGuardGlobalConfiguration.validateExemptions("team/service/release|github-token|   ");

        assertEquals(FormValidation.Kind.WARNING, validation.kind);
        assertTrue(validation.renderHtml().contains("empty reason"));
    }

    @Test
    void acceptsValidExemptionLines() {
        FormValidation validation =
                SecretGuardGlobalConfiguration.validateExemptions("team/service/release|github-token|approved sample\n"
                        + "team/service/release|url-query-secret|documented webhook example");

        assertEquals(FormValidation.Kind.OK, validation.kind);
    }

    @Test
    void parsesCustomPatternRules() {
        List<CustomPatternRuleEntry> entries = CustomPatternRuleEntry.parseStrict(
                "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|(?i)jdbc:oracle:[^\\s]+password=([^;\\s]+)|1\n"
                        + "service-token|Service token is hardcoded|MEDIUM|svc\\|token=([A-Za-z0-9_-]{12,})|1");

        assertEquals(2, entries.size());
        assertEquals("oracle-connection-url", entries.get(0).getRuleId());
        assertEquals(Severity.HIGH, entries.get(0).getSeverity());
        assertEquals(1, entries.get(0).getMatchingGroup());
        assertEquals("svc|token=([A-Za-z0-9_-]{12,})", entries.get(1).getPattern());
    }

    @Test
    void rejectsMalformedCustomPatternRuleLines() {
        FormValidation validation = SecretGuardGlobalConfiguration.validateCustomPatternRules(
                "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH");

        assertEquals(FormValidation.Kind.ERROR, validation.kind);
        assertTrue(validation.renderHtml().contains("ruleId|title|severity|pattern"));
    }

    @Test
    void rejectsInvalidCustomPatternRuleMatchingGroup() {
        FormValidation validation = SecretGuardGlobalConfiguration.validateCustomPatternRules(
                "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|(?i)password=([^;\\s]+)|2");

        assertEquals(FormValidation.Kind.ERROR, validation.kind);
        assertTrue(validation.renderHtml().contains("matchingGroup 2 exceeds"));
    }

    @Test
    void acceptsBlankCustomPatternRuleConfiguration() {
        FormValidation validation = SecretGuardGlobalConfiguration.validateCustomPatternRules(" \n ");

        assertEquals(FormValidation.Kind.OK, validation.kind);
    }

    @Test
    void configurationReturnsParsedCustomRuleEntriesAndIds() {
        TestSecretGuardGlobalConfiguration configuration = new TestSecretGuardGlobalConfiguration();
        configuration.setCustomPatternRules(
                "oracle-connection-url|Oracle connection string contains a hardcoded password|HIGH|password=([^;\\s]+)|1\n"
                        + "service-token|Service token is hardcoded|MEDIUM|svc\\|token=([A-Za-z0-9_-]{12,})|1");

        List<CustomPatternRuleEntry> entries = configuration.getCustomPatternRuleEntries();
        Set<String> ruleIds = configuration.getCustomPatternRuleIds();

        assertEquals(2, entries.size());
        assertEquals(Set.of("oracle-connection-url", "service-token"), ruleIds);
    }

    @Test
    void configurationReturnsEmptyCustomRuleEntriesForBlankText() {
        TestSecretGuardGlobalConfiguration configuration = new TestSecretGuardGlobalConfiguration();

        assertTrue(configuration.getCustomPatternRuleEntries().isEmpty());
        assertTrue(configuration.getCustomPatternRuleIds().isEmpty());
    }

    @Test
    @WithJenkins
    void systemConfigPutsAllowListsAndExemptionsInAdvancedSection(JenkinsRule jenkinsRule) throws Exception {
        Page page = jenkinsRule.createWebClient().goTo("configure");
        String content = page.getWebResponse().getContentAsString();

        int sectionIndex = content.indexOf("Jenkins Secret Guard");
        int advancedButtonIndex = content.indexOf("advanced-button", sectionIndex);
        int advancedBodyIndex = content.indexOf("advancedBody", advancedButtonIndex);

        assertTrue(sectionIndex >= 0);
        assertTrue(advancedButtonIndex > sectionIndex);
        assertTrue(advancedBodyIndex > advancedButtonIndex);
        assertTrue(content.indexOf("Rule ID allow list", advancedBodyIndex) > advancedBodyIndex);
        assertTrue(content.indexOf("Job allow list", advancedBodyIndex) > advancedBodyIndex);
        assertTrue(content.indexOf("Field name allow list", advancedBodyIndex) > advancedBodyIndex);
        assertTrue(content.indexOf("Exemptions", advancedBodyIndex) > advancedBodyIndex);
        assertTrue(content.indexOf("Custom pattern rules", advancedBodyIndex) > advancedBodyIndex);
    }

    private static class TestSecretGuardGlobalConfiguration extends SecretGuardGlobalConfiguration {
        @Override
        public synchronized void load() {
            // no-op for unit testing outside a Jenkins runtime
        }

        @Override
        public synchronized void save() {
            // no-op for unit testing outside a Jenkins runtime
        }
    }
}
