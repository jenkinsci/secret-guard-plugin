package io.jenkins.plugins.secretguard.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.FormValidation;
import java.util.List;
import org.junit.jupiter.api.Test;

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
}
