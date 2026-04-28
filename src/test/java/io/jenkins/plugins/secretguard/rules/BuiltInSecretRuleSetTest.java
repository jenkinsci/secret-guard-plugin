package io.jenkins.plugins.secretguard.rules;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.Severity;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class BuiltInSecretRuleSetTest {
    private final BuiltInSecretRuleSet ruleSet = new BuiltInSecretRuleSet();

    @Test
    void detectsHighConfidenceSecrets() {
        List<SecretFinding> findings = scan("token", "ghp_012345678901234567890123456789012345");
        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("github-token")));
        assertTrue(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void detectsHardcodedBasicAuthHeader() {
        List<SecretFinding> findings = scan("Authorization", "Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("basic-auth-header")));
        assertTrue(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void detectsCommonCicdProviderTokens() {
        assertTrue(scan("slackToken", slackBotToken()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("slack-bot-token")));
        assertTrue(scan("pypiToken", pypiApiToken()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-api-token")));
        assertTrue(scan("gitlabToken", gitlabToken()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("gitlab-token")));
    }

    @Test
    void detectsNpmAndJfrogSecretsFromOperationalContexts() {
        assertTrue(scan("", npmAuthTokenConfig()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-auth-token-context")));
        assertTrue(scan("", "//registry.npmjs.org/:_auth=QWxhZGRpbjpPcGVuU2VzYW1l").stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-legacy-auth-context")));
        assertTrue(scan("", "npm config set _password QWxhZGRpbjpPcGVuU2VzYW1l").stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-legacy-auth-context")));
        assertTrue(scan("", jfrogCliCommand()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("jfrog-access-token-context")));
        assertTrue(scan("", jfrogApiHeader()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("jfrog-access-token-context")));
        assertTrue(scan("", "TWINE_PASSWORD=PlainSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-password-context")));
        assertTrue(scan("", "twine upload -u build-user -p PlainSecret42 dist/*").stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-password-context")));
        assertTrue(scan("pypirc", """
                        [distutils]
                        index-servers = pypi

                        [pypi]
                        username = build-user
                        password = PlainSecret42
                        """).stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-password-context")));
        assertTrue(scan("", "curl --user build-user:PlainSecret42 https://example.invalid").stream()
                .anyMatch(finding -> finding.getRuleId().equals("command-user-password-argument")));
        assertTrue(
                scan("", "wget --user build-user --password PlainSecret42 https://example.invalid/archive.tgz").stream()
                        .anyMatch(finding -> finding.getRuleId().equals("command-user-password-argument")));
        assertTrue(
                scan("", "docker login --username build-user --password PlainSecret42 registry.example.invalid")
                        .stream()
                        .anyMatch(finding -> finding.getRuleId().equals("command-user-password-argument")));
        assertTrue(scan(
                        "",
                        "echo PlainSecret42 | docker login --username build-user --password-stdin registry.example.invalid")
                .stream()
                .anyMatch(finding -> finding.getRuleId().equals("docker-password-stdin-secret")));
        assertTrue(scan("", "sshpass -p PlainSecret42 ssh build-user@example.invalid true").stream()
                .anyMatch(finding -> finding.getRuleId().equals("command-user-password-argument")));
        assertTrue(scan("", "kubectl create secret generic example-secret --from-literal=token=PlainSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("kubernetes-secret-from-literal")));
        assertTrue(scan("", "oc create secret generic example-secret --from-literal password=PlainSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("kubernetes-secret-from-literal")));
    }

    @Test
    void doesNotFlagRuntimeReferencesInNpmAndJfrogContexts() {
        assertTrue(scan("", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}").isEmpty());
        assertTrue(scan("", "_auth=${NPM_BASIC_AUTH}").isEmpty());
        assertTrue(scan("", "npm config set _password \"$NPM_PASSWORD\"").isEmpty());
        assertTrue(scan("", "npm config set //registry.npmjs.org/:_authToken \"$NPM_TOKEN\"")
                .isEmpty());
        assertTrue(scan("", "JFROG_CLI_ACCESS_TOKEN = credentials('jfrog-cli-token')")
                .isEmpty());
        assertTrue(scan("", "jf c add example --access-token $JFROG_CLI_ACCESS_TOKEN")
                .isEmpty());
        assertTrue(scan("", "TWINE_PASSWORD=${TWINE_PASSWORD}").isEmpty());
        assertTrue(scan("", "twine upload -u build-user -p \"$TWINE_PASSWORD\" dist/*")
                .isEmpty());
        assertTrue(scan("pypirc", """
                        [distutils]
                        index-servers = pypi

                        [pypi]
                        username = build-user
                        password = ${TWINE_PASSWORD}
                        """).isEmpty());
        assertTrue(scan("", "curl -u \"$SERVICE_USER:$SERVICE_PASS\" https://example.invalid")
                .isEmpty());
        assertTrue(scan("", "wget --user \"$SERVICE_USER\" --password \"$SERVICE_PASS\" https://example.invalid")
                .isEmpty());
        assertTrue(scan(
                        "",
                        "docker login --username \"$REGISTRY_USER\" --password \"$REGISTRY_PASSWORD\" registry.example.invalid")
                .isEmpty());
        assertTrue(scan(
                        "",
                        "echo \"$REGISTRY_PASSWORD\" | docker login --username build-user --password-stdin registry.example.invalid")
                .isEmpty());
        assertTrue(scan("", "sshpass -p \"$SSH_PASSWORD\" ssh build-user@example.invalid true")
                .isEmpty());
        assertTrue(scan("", "kubectl create secret generic example-secret --from-literal=token=$SERVICE_TOKEN")
                .isEmpty());
        assertTrue(scan("", "oc create secret generic example-secret --from-literal password=${SERVICE_PASSWORD}")
                .isEmpty());
    }

    @Test
    void detectsHighEntropyStringsButNotAsHigh() {
        List<SecretFinding> findings = scan("", "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l");
        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
        assertFalse(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotTreatUuidAsHighRiskSecret() {
        List<SecretFinding> findings = scan("", "123e4567-e89b-12d3-a456-426614174000");
        assertTrue(findings.isEmpty());
    }

    @Test
    void doesNotTreatPathsOrDockerImagesAsHighEntropySecrets() {
        assertTrue(scan("", "registry.example.invalid/team/tooling/cicd/example_runner:0.2")
                .isEmpty());
        assertTrue(scan("", "/opt/example-tools/run-task-reporter.py").isEmpty());
        assertTrue(scan("", "https://artifacts.example.invalid:443/repository/build-tools/bootstrap_bundle/")
                .isEmpty());
        assertTrue(scan("", "ftp://artifacts.example.invalid:21/repository/build-tools/bootstrap_bundle/")
                .isEmpty());
        assertTrue(scan("", "sftp://10.1.2.3:22/repository/build-tools/bootstrap_bundle/")
                .isEmpty());
        assertTrue(scan("", "http://artifactory:8081/repository/build-tools/bootstrap_bundle/")
                .isEmpty());
        assertTrue(scan("", "10.1.2.3:8081/repository/build-tools/bootstrap_bundle/")
                .isEmpty());
        assertTrue(scan("", "git@repo-host:platform/build-tools/bootstrap_bundle_release.git")
                .isEmpty());
        assertTrue(scan("", "//repo-host/shared/build-tools/bootstrap_bundle_release")
                .isEmpty());
        assertTrue(scan("", "/var/run/docker.sock:/var/run/docker.sock").isEmpty());
        assertTrue(scan("", "publishAllPublicationsToMavenRepository").isEmpty());
        assertTrue(
                scan("", "artifact-internal/inf/tool/tool_prebuild_binary/test").isEmpty());
    }

    @Test
    void doesNotTreatReadableJdbcOptionsAsHighEntropySecrets() {
        assertTrue(scan(
                        "defaultValue",
                        "jdbc:mysql://db.example.invalid:3306/example_metadata?sessionVariables=sql_mode=STRICT_TRANS_TABLES&useMysqlMetadata=true")
                .isEmpty());
    }

    @Test
    void doesNotTreatGeneratedRandomNamesAsHighEntropySecrets() {
        assertTrue(scan("randomName", "choice-parameter-108997464504044").isEmpty());
    }

    @Test
    void doesNotTreatParameterSeparatorNamesAsHighEntropySecrets() {
        assertTrue(scan(
                        "/flow-definition/properties/hudson.model.ParametersDefinitionProperty/parameterDefinitions/jenkins.plugins.parameter__separator.ParameterSeparatorDefinition/name",
                        "name",
                        "separator-d45a9f41-b001-4c08-80ab-a23bdc5ccb96")
                .isEmpty());
    }

    @Test
    void doesNotTreatNonSecretUrlsAsHighEntropySecrets() {
        assertTrue(scan(
                        "description",
                        "Example: http://jenkins.example.invalid:8080/job/example-service/job/build-test/80")
                .isEmpty());
    }

    @Test
    void stillDetectsSensitiveJdbcParametersAsHighEntropySecrets() {
        List<SecretFinding> findings = scan(
                "defaultValue",
                "jdbc:mysql://db.example.invalid:3306/example_metadata?password=QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotTreatCredentialIdsAsSecrets() {
        assertTrue(scan("registryCredentialsId", "jfrog-cred-default").isEmpty());
        assertTrue(scan("tokenCredentialId", "ghp_012345678901234567890123456789012345")
                .isEmpty());
    }

    @Test
    void detectsPassphraseFieldsWithoutFlaggingBindingVariableNames() {
        assertTrue(scan("passphrase", "PlainSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertTrue(scan("privateKeyPassphrase", "AnotherSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertTrue(scan("keyPassphrase", "ThirdSecret42").stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertTrue(scan("passphraseVariable", "SSH_PASSPHRASE").isEmpty());
        assertTrue(scan("privateKeyPassphraseVariable", "DEPLOY_KEY_PASSPHRASE").isEmpty());
    }

    @Test
    void downgradesSensitivePlaceholderValues() {
        List<SecretFinding> findings = scan("serviceApiToken", "__REDACTED__");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
        assertEquals(Severity.LOW, findings.get(0).getSeverity());
    }

    @Test
    void doesNotTreatSensitiveFileReferencesAsSecrets() {
        assertTrue(scan("PASSWORD_FILE", "PASSWORD_FILE = 'pwd.txt'").isEmpty());
        assertTrue(scan("SERVICE_TOKEN_PATH", "SERVICE_TOKEN_PATH = '/run/secrets/service_token'")
                .isEmpty());
    }

    @Test
    void doesNotTreatReadableUrlsOnSensitiveNamedFieldsAsSecrets() {
        assertTrue(scan("getPasswordUrl", "http://service.example.invalid/auth").isEmpty());
        assertTrue(scan("tokenEndpoint", "https://service.example.invalid/oauth/token")
                .isEmpty());
        assertTrue(scan("secretServiceUrl", "https://service.example.invalid/runtime/check")
                .isEmpty());
        assertTrue(scan("secretUploadUrl", "sftp://files.example.invalid:22/runtime/upload")
                .isEmpty());
        assertTrue(scan("passwordServiceEndpoint", "service.example.invalid:8443/auth")
                .isEmpty());
        assertTrue(scan("tokenWebhookUrl", "hooks.example.invalid/services/runtime")
                .isEmpty());
    }

    @Test
    void stillFlagsCredentialedOrSecretBearingUrlsOnSensitiveNamedFields() {
        assertTrue(scan("getPasswordUrl", "https://user:password123@example.invalid/auth").stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertTrue(
                scan("tokenEndpoint", "https://service.example.invalid/auth?token=123e4567-e89b-12d3-a456-426614174999")
                        .stream()
                        .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
        assertTrue(scan(
                        "passwordServiceEndpoint",
                        "service.example.invalid:8443/auth?token=123e4567-e89b-12d3-a456-426614174999")
                .stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertTrue(scan("secretUploadUrl", "sftp://user:password123@files.example.invalid/runtime/upload").stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void stillFlagsPlaintextValuesOnSensitiveFileFields() {
        List<SecretFinding> findings = scan("PASSWORD_FILE", "PASSWORD_FILE = 'hunter2'");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotTreatHashesOrDigestsAsHighEntropySecrets() {
        assertTrue(scan("checksum", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .isEmpty());
        assertTrue(scan("commit", "0123456789abcdef0123456789abcdef01234567").isEmpty());
        assertTrue(scan(
                        "imageDigest",
                        "repo/image@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
                .isEmpty());
    }

    @Test
    void doesNotTreatPublicCertificatesAsSecrets() {
        String certificate = """
                -----BEGIN CERTIFICATE-----
                QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l
                -----END CERTIFICATE-----
                """;
        assertTrue(scan("certificate", certificate).isEmpty());
    }

    @Test
    void detectsSecretInUrlQueryParameter() {
        List<SecretFinding> findings =
                scan("", "https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999");
        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
        assertTrue(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void detectsSecretInNotifierUrlQueryVariants() {
        List<SecretFinding> findings =
                scan("", "https://notify.example.invalid/api/webhook/deliver?signature=Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
    }

    @Test
    void detectsSecretEmbeddedInNotifierUrlPath() {
        List<SecretFinding> findings =
                scan("webhookUrl", "https://hooks.example.invalid/services/TEAM01/ROOM01/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
        assertTrue(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void detectsProviderSpecificWebhookUrls() {
        assertTrue(scan("webhookUrl", slackWebhookUrl()).stream()
                .anyMatch(finding -> finding.getRuleId().equals("slack-webhook-url")));
        assertTrue(scan(
                        "webhookUrl",
                        "https://outlook.office.com/webhook/11111111-2222-3333-4444-555555555555@66666666-7777-8888-9999-aaaaaaaaaaaa/IncomingWebhook/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua/bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
                .stream()
                .anyMatch(finding -> finding.getRuleId().equals("teams-webhook-url")));
        assertTrue(scan("webhookUrl", "https://hooks.zapier.com/hooks/catch/123456/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua/").stream()
                .anyMatch(finding -> finding.getRuleId().equals("zapier-webhook-url")));
    }

    @Test
    void doesNotDoubleReportKnownProviderWebhookUrlsAsGenericNotifierUrls() {
        List<SecretFinding> findings = scan("webhookUrl", slackWebhookUrl());

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("slack-webhook-url")));
        assertFalse(findings.stream().anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
    }

    @Test
    void doesNotTreatReadableNotifierUrlsAsSecrets() {
        assertTrue(scan("webhookUrl", "https://hooks.example.invalid/services/release-events/build-status")
                .isEmpty());
        assertTrue(scan("notifyUrl", "https://notify.example.invalid/api/callback/release-created")
                .isEmpty());
        assertTrue(scan("chatWebhookDocs", "https://hooks.slack.com/services/T00000000/B00000000")
                .isEmpty());
    }

    private List<SecretFinding> scan(String fieldName, String value) {
        return scan("Pipeline script", fieldName, value);
    }

    private List<SecretFinding> scan(String sourceName, String fieldName, String value) {
        ScanContext context = new ScanContext(
                "folder/job",
                "Pipeline script",
                "WorkflowJob",
                FindingLocationType.PIPELINE_SCRIPT,
                ScanPhase.BUILD,
                EnforcementMode.BLOCK,
                Severity.HIGH);
        List<SecretFinding> findings = new ArrayList<>();
        for (SecretRule rule : ruleSet.getRules()) {
            findings.addAll(rule.scan(context, sourceName, 1, fieldName, value));
        }
        return findings;
    }

    private String slackWebhookUrl() {
        return "https://hooks.slack.com"
                + "/services/"
                + "T00000000"
                + "/"
                + "B00000000"
                + "/"
                + "Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua";
    }

    private String slackBotToken() {
        return "xoxb-" + "123456789012" + "-" + "123456789013" + "-" + "abcdefghijklmnopqrstuvwxyz123456";
    }

    private String pypiApiToken() {
        return "pypi-" + "AgENdGVzdC5weXBpLm9yZwIkMDAwMDAwMDA"
                + "tMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwAA"
                + "IzWmFrZVB5cGlUb2tlblZhbHVlMDEyMzQ1Njc4OTA";
    }

    private String gitlabToken() {
        return "glpat-" + "abcdefghijklmnopqrstuvwxyz012345";
    }

    private String npmAuthTokenConfig() {
        return "//registry.npmjs.org/:_authToken=" + "0123456789abcdef0123456789abcdef";
    }

    private String jfrogCliCommand() {
        return "jf c add build-tools --access-token " + "cmVmLXRva2VuLTAxMjM0NTY3ODlhYmNkZWY";
    }

    private String jfrogApiHeader() {
        return "X-JFrog-Art-Api: " + "AKCpExampleJfrogApiToken0123456789";
    }
}
