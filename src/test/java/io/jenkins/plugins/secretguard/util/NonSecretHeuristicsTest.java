package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NonSecretHeuristicsTest {
    @Test
    void detectsRuntimeSecretReferencesConsistently() {
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("$SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("${SERVICE_API_TOKEN}"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("env.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("params.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("env['SERVICE_API_TOKEN']"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("params[\"SERVICE_API_TOKEN\"]"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("credentials('service-api-token')"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + env.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + params.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("('Bearer ' + env.SERVICE_API_TOKEN)"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("\"Bearer ${env.SERVICE_API_TOKEN}\""));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference(
                "\"${SERVICE_USER}:${SERVICE_PASS}\".bytes.encodeBase64().toString()"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("ExampleHeaderSecretValue0123456789ABCDEF"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + 'literal-token'"));
    }

    @Test
    void detectsStrongPlaceholderValues() {
        assertTrue(NonSecretHeuristics.looksLikePlaceholderValue("__REDACTED__"));
        assertTrue(NonSecretHeuristics.looksLikePlaceholderValue("SERVICE_SECRET = '__MASKED__'"));
        assertTrue(NonSecretHeuristics.looksLikePlaceholderValue("<apiToken>****</apiToken>"));
        assertTrue(NonSecretHeuristics.looksLikePlaceholderValue("Bearer __HIDDEN__"));
        assertFalse(NonSecretHeuristics.looksLikePlaceholderValue("ExamplePlaintextSecret12345"));
        assertFalse(NonSecretHeuristics.looksLikePlaceholderValue("change-me-later"));
    }

    @Test
    void reportsWhyHighEntropyCandidatesAreIgnored() {
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "https://artifacts.example.invalid:443/repository/build-tools/bootstrap_bundle/",
                        "",
                        "artifacts.example.invalid:443/repository/build-tools/bootstrap_bundle/"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "jfrog-cred-default", "registryCredentialsId", "jfrog-cred-default"));
    }
}
