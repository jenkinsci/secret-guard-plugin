package io.jenkins.plugins.secretguard.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("env.get('SERVICE_API_TOKEN')"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("params.get(\"SERVICE_API_TOKEN\")"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("credentials('service-api-token')"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("SERVICE_LOGIN.bytes.encodeBase64().toString()"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + env.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + params.SERVICE_API_TOKEN"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("('Bearer ' + env.SERVICE_API_TOKEN)"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("\"Bearer ${env.SERVICE_API_TOKEN}\""));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("params['SERVICE_API_TOKEN'] ?: ''"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("env?.SERVICE_API_TOKEN?.trim()"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("params?.get('SERVICE_API_TOKEN')?.trim()"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("helper(env?.SERVICE_API_TOKEN?.trim())"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference(
                "helper([token: env?.SERVICE_API_TOKEN?.trim(), meta: [source: 'jenkins']])"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference(
                "params.SERVICE_API_TOKEN ? params.SERVICE_API_TOKEN : ''"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + (params['SERVICE_API_TOKEN'] ?: '')"));
        assertTrue(NonSecretHeuristics.isRuntimeSecretReference(
                "\"${SERVICE_USER}:${SERVICE_PASS}\".bytes.encodeBase64().toString()"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("ExampleHeaderSecretValue0123456789ABCDEF"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference("'Bearer ' + 'literal-token'"));
        assertFalse(NonSecretHeuristics.isRuntimeSecretReference(
                "params.SERVICE_API_TOKEN ? 'literal-token' : 'other-literal'"));
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
    void detectsSensitiveFileReferencesWithoutHidingPlaintextSecrets() {
        assertTrue(NonSecretHeuristics.looksLikeSensitiveFileReference("PASSWORD_FILE", "PASSWORD_FILE = 'pwd.txt'"));
        assertTrue(NonSecretHeuristics.looksLikeSensitiveFileReference(
                "SERVICE_TOKEN_PATH", "SERVICE_TOKEN_PATH = '/run/secrets/service_token'"));
        assertFalse(NonSecretHeuristics.looksLikeSensitiveFileReference("PASSWORD_FILE", "PASSWORD_FILE = 'hunter2'"));
    }

    @Test
    void detectsCredentialBindingVariableReferencesWithoutHidingPlaintextValues() {
        assertTrue(NonSecretHeuristics.looksLikeCredentialBindingVariableReference(
                "passphraseVariable", "SSH_PASSPHRASE"));
        assertTrue(NonSecretHeuristics.looksLikeCredentialBindingVariableReference(
                "privateKeyPassphraseVariable", "DEPLOY_KEY_PASSPHRASE"));
        assertFalse(
                NonSecretHeuristics.looksLikeCredentialBindingVariableReference("passphraseVariable", "PlainSecret42"));
        assertFalse(NonSecretHeuristics.looksLikeCredentialBindingVariableReference("passphrase", "SSH_PASSPHRASE"));
    }

    @Test
    void detectsNonSecretUrlsWithoutHidingUrlSecrets() {
        assertTrue(NonSecretHeuristics.looksLikeNonSecretUrl(
                "Example: http://jenkins.example.invalid:8080/job/example-service/job/build-test/80",
                "8080/job/example-service/job/build-test/80"));
        assertFalse(NonSecretHeuristics.looksLikeNonSecretUrl(
                "https://user:password@example.invalid/job/example-service/job/build-test/80",
                "example.invalid/job/example-service/job/build-test/80"));
        assertFalse(NonSecretHeuristics.looksLikeNonSecretUrl(
                "https://example.invalid/webhook?token=QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l",
                "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l"));
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
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "jdbc:mysql://db.example.invalid:3306/example_metadata?sessionVariables=sql_mode=STRICT_TRANS_TABLES&useMysqlMetadata=true",
                        "defaultValue",
                        "sessionVariables=sql_mode=STRICT_TRANS_TABLES"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "choice-parameter-108997464504044", "randomName", "choice-parameter-108997464504044"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "/flow-definition/properties/hudson.model.ParametersDefinitionProperty/parameterDefinitions/jenkins.plugins.parameter__separator.ParameterSeparatorDefinition/name",
                        "separator-d45a9f41-b001-4c08-80ab-a23bdc5ccb96",
                        "name",
                        "separator-d45a9f41-b001-4c08-80ab-a23bdc5ccb96"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "Example: http://jenkins.example.invalid:8080/job/example-service/job/build-test/80",
                        "description",
                        "8080/job/example-service/job/build-test/80"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "httpRequest customHeaders: [[\"name\": \"X-Correlation-ID\", \"value\": \"QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l\", \"maskValue\": false]]",
                        "",
                        "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l"));
        assertNotEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "/project/properties/hudson.model.ParametersDefinitionProperty/parameterDefinitions/hudson.model.StringParameterDefinition/description",
                        "Run svcOnlineRestoreSvcFromReplicaDataBackup before retrying the workflow.",
                        "description",
                        "svcOnlineRestoreSvcFromReplicaDataBackup"));
        assertEquals(
                "",
                NonSecretHeuristics.nonSecretHighEntropyReason(
                        "/project/properties/hudson.model.ParametersDefinitionProperty/parameterDefinitions/hudson.model.StringParameterDefinition/description",
                        "Example token: QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l",
                        "description",
                        "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l"));
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
