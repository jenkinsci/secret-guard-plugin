package io.jenkins.plugins.secretguard.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.scan.ConfigXmlScanner;
import io.jenkins.plugins.secretguard.scan.SecretScanner;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecretScanServiceTest {
    @Test
    void blocksOnActionableHighFindings() {
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        SecretScanResult result =
                service.scan(scannerWith(singleFinding(false)), context(EnforcementMode.BLOCK), "ignored");
        assertTrue(result.isBlocked());
    }

    @Test
    void allowListedFindingsDoNotBlock() {
        SecretScanService service = new SecretScanService(
                new AllowListService() {
                    @Override
                    public boolean isAllowListed(SecretFinding finding) {
                        return true;
                    }
                },
                new ExemptionService());
        SecretScanResult result =
                service.scan(scannerWith(singleFinding(false)), context(EnforcementMode.BLOCK), "ignored");
        assertFalse(result.isBlocked());
        assertTrue(result.getFindings().get(0).isExempted());
    }

    @Test
    void warnModeIsReportedSeparately() {
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        SecretScanResult result =
                service.scan(scannerWith(singleFinding(false)), context(EnforcementMode.WARN), "ignored");
        assertFalse(result.isBlocked());
        assertTrue(service.shouldWarn(context(EnforcementMode.WARN), result));
    }

    @Test
    void preservesScannerNotesDuringPolicyProcessing() {
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        SecretScanResult result = service.scan(
                (context, content) -> new SecretScanResult(
                        context.getJobFullName(),
                        context.getTargetType(),
                        List.of(),
                        false,
                        List.of("Config adapter skipped test reference.")),
                context(EnforcementMode.AUDIT),
                "ignored");

        assertTrue(result.hasNotes());
        assertTrue(result.getNotes().contains("Config adapter skipped test reference."));
    }

    @Test
    void normalizesAndDeduplicatesScannerNotesDuringPolicyProcessing() {
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        SecretScanResult result = service.scan(
                (context, content) -> new SecretScanResult(
                        context.getJobFullName(),
                        context.getTargetType(),
                        List.of(),
                        false,
                        List.of(
                                " Adapter: skipped Git branch metadata. ",
                                "Adapter:   skipped Git branch metadata.",
                                "",
                                "Adapter: skipped Git refspec metadata.")),
                context(EnforcementMode.AUDIT),
                "ignored");

        assertEquals(2, result.getNotes().size());
        assertTrue(result.getNotes().contains("Adapter: skipped Git branch metadata."));
        assertTrue(result.getNotes().contains("Adapter: skipped Git refspec metadata."));
    }

    @Test
    void suppressesHighEntropyWhenSpecificRuleHitsSameFinding() {
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        List<SecretFinding> findings = new ArrayList<>();
        findings.add(finding("high-entropy-string", Severity.MEDIUM, "x-example-auth", "Exa…DEF"));
        findings.add(finding("http-request-hardcoded-header-secret", Severity.HIGH, "x-example-auth", "Exa…DEF"));
        findings.add(finding("http-request-unmasked-header-secret", Severity.HIGH, "x-example-auth", "Exa…DEF"));

        SecretScanResult result = service.scan(
                (context, content) ->
                        new SecretScanResult(context.getJobFullName(), context.getTargetType(), findings, false),
                context(EnforcementMode.BLOCK),
                "ignored");

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertTrue(result.getFindings().stream()
                .filter(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret"))
                .map(SecretFinding::getAnalysisNote)
                .anyMatch(note -> note.contains("Suppressed generic finding(s)")));
    }

    @Test
    void suppressesHighEntropyForInlinePipelineHttpHeaderFromConfigXml() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def helper(){
                    httpRequest customHeaders: [[maskValue: false, name: 'x-example-auth',
                                value: 'ExampleHeaderSecretValue0123456789ABCDEF']],
                                url: "https://example.invalid"
                }
                pipeline {
                    agent any
                    stages {
                        stage('sync') {
                            steps {
                                script {
                                    helper()
                                }
                            }
                        }
                    }
                }
                    ]]></script>
                  </definition>
                </flow-definition>
                """;
        SecretScanService service = new SecretScanService(new AllowListService(), new ExemptionService());
        SecretScanResult result = service.scan(new ConfigXmlScanner(), context(EnforcementMode.BLOCK), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
    }

    private SecretScanner scannerWith(SecretFinding finding) {
        return (context, content) ->
                new SecretScanResult(context.getJobFullName(), context.getTargetType(), List.of(finding), false);
    }

    private SecretFinding singleFinding(boolean exempted) {
        SecretFinding finding = finding("rule-1", Severity.HIGH, "password", "sup…ord");
        return exempted ? finding.withExemption("already exempted") : finding;
    }

    private SecretFinding finding(String ruleId, Severity severity, String fieldName, String maskedSnippet) {
        return new SecretFinding(
                ruleId,
                "Plain secret",
                severity,
                FindingLocationType.CONFIG_XML,
                "folder/job",
                "/project/password",
                12,
                fieldName,
                maskedSnippet,
                "Move the plaintext secret to Jenkins Credentials.");
    }

    private ScanContext context(EnforcementMode mode) {
        return new ScanContext(
                "folder/job",
                "config.xml",
                "WorkflowJob",
                FindingLocationType.CONFIG_XML,
                ScanPhase.SAVE,
                mode,
                Severity.HIGH);
    }
}
