package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
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
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "ExamplePipelineScript.Jenkinsfile", "scriptPath", "ExamplePipelineScript"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "ci/ExamplePipelineScript.Jenkinsfile", "", "ExamplePipelineScript"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "hdfs:///example/runtime/sample_dataset/record_01",
                        "json_data_path",
                        "example/runtime/sample_dataset/record_01"));
        for (String value : List.of(
                "s3://example-bucket/runtime/sample_dataset/record_01",
                "s3a://example-bucket/runtime/sample_dataset/record_01",
                "gs://example-bucket/runtime/sample_dataset/record_01",
                "gcs://example-bucket/runtime/sample_dataset/record_01",
                "oss://example-bucket/runtime/sample_dataset/record_01",
                "cosn://example-bucket/runtime/sample_dataset/record_01",
                "obs://example-bucket/runtime/sample_dataset/record_01",
                "bos://example-bucket/runtime/sample_dataset/record_01",
                "tos://example-bucket/runtime/sample_dataset/record_01",
                "wasb://example-bucket/runtime/sample_dataset/record_01",
                "wasbs://example-bucket/runtime/sample_dataset/record_01",
                "abfs://example-bucket/runtime/sample_dataset/record_01",
                "abfss://example-bucket/runtime/sample_dataset/record_01",
                "adl://example-bucket/runtime/sample_dataset/record_01")) {
            assertNotEquals(
                    "",
                    NonSecretHeuristics.nonSecretHighEntropyReason(
                            value, "json_data_path", "example-bucket/runtime/sample_dataset/record_01"));
        }
    }
}
