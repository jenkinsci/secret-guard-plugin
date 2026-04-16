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
        assertTrue(scan("", "/var/run/docker.sock:/var/run/docker.sock").isEmpty());
        assertTrue(scan("", "publishAllPublicationsToMavenRepository").isEmpty());
        assertTrue(
                scan("", "artifact-internal/inf/tool/tool_prebuild_binary/test").isEmpty());
    }

    @Test
    void doesNotTreatCredentialIdsAsSecrets() {
        assertTrue(scan("registryCredentialsId", "jfrog-cred-default").isEmpty());
        assertTrue(scan("tokenCredentialId", "ghp_012345678901234567890123456789012345")
                .isEmpty());
    }

    @Test
    void downgradesSensitivePlaceholderValues() {
        List<SecretFinding> findings = scan("serviceApiToken", "__REDACTED__");

        assertTrue(findings.stream().anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(findings.stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
        assertEquals(Severity.LOW, findings.get(0).getSeverity());
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

    private List<SecretFinding> scan(String fieldName, String value) {
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
            findings.addAll(rule.scan(context, context.getSourceName(), 1, fieldName, value));
        }
        return findings;
    }
}
