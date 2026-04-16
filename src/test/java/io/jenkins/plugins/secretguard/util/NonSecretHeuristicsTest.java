package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("ExampleHeaderSecretValue0123456789ABCDEF"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + 'literal-token'"));
    }
}
