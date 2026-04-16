package io.jenkins.plugins.secretguard.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import org.junit.jupiter.api.Test;

class ConfigXmlScannerTest {
    @Test
    void detectsParameterDefaultsAndSensitiveConfigFields() {
        String xml = """
                <project>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <hudson.model.StringParameterDefinition>
                          <name>API_TOKEN</name>
                          <defaultValue>ghp_012345678901234567890123456789012345</defaultValue>
                        </hudson.model.StringParameterDefinition>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                  <publishers>
                    <somePublisher>
                      <password>super-secret-password</password>
                    </somePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        ScanContext context = new ScanContext(
                "folder/job",
                "config.xml",
                "FreeStyleProject",
                FindingLocationType.CONFIG_XML,
                ScanPhase.SAVE,
                EnforcementMode.BLOCK,
                Severity.HIGH);
        SecretScanResult result = scanner.scan(context, xml);
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getLocationType() == FindingLocationType.PARAMETER_DEFAULT));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getFieldName().equals("password")));
        assertEquals("folder/job", result.getTargetId());
    }

    @Test
    void scansWholeInlinePipelineScriptFromConfigXml() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def intiWiritePasswordToFile(fileName){
                    def sonarServer = "http://security.example.invalid/qa_auth"
                    result = httpRequest customHeaders: [[maskValue: false, name: 'x-example-auth',
                                value: 'ExampleHeaderSecretValue0123456789ABCDEF']],
                                url: "${sonarServer}",
                                quiet: true,
                                wrapAsMultipart: false
                }

                pipeline {
                    agent any
                    stages {
                        stage('sync') {
                            steps {
                                script {
                                    intiWiritePasswordToFile("${PWD_FILE}")
                                }
                            }
                        }
                    }
                }
                    ]]></script>
                    <sandbox>true</sandbox>
                  </definition>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
    }

    @Test
    void doesNotFlagRuntimeReferencesFromConfigXmlOrInlinePipeline() {
        String xml = """
                <flow-definition>
                  <properties>
                    <somePublisher>
                      <password>$SERVICE_API_TOKEN</password>
                    </somePublisher>
                    <otherPublisher>
                      <token>params.SERVICE_API_TOKEN</token>
                    </otherPublisher>
                    <thirdPublisher>
                      <secret>env['SERVICE_API_TOKEN']</secret>
                    </thirdPublisher>
                  </properties>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def response = httpRequest(
                    httpMode: "POST",
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: "${SERVICE_API_TOKEN}", maskValue: true]]
                )
                def alternate = httpRequest(
                    httpMode: "POST",
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "Authorization", value: 'Bearer ' + params.SERVICE_API_TOKEN, maskValue: true]]
                )
                    ]]></script>
                    <sandbox>true</sandbox>
                  </definition>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertFalse(result.hasFindings());
    }

    @Test
    void downgradesPlaceholderValuesFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <somePublisher>
                      <apiToken>__REDACTED__</apiToken>
                      <clientSecret>****</clientSecret>
                    </somePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void parsesMixedCustomHeadersFromInlinePipelineScript() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def response = httpRequest(
                    httpMode: "POST",
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [
                        [name: "x-safe-token", value: params.SERVICE_API_TOKEN, maskValue: true],
                        [
                            name: "Authorization",
                            value: "Bearer hardcodedHeaderValue0123456789ABCDEF",
                            maskValue: false
                        ]
                    ]
                )
                    ]]></script>
                    <sandbox>true</sandbox>
                  </definition>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .filter(finding -> finding.getRuleId().startsWith("http-request-"))
                .anyMatch(finding -> finding.getFieldName().equals("x-safe-token")));
    }

    @Test
    void doesNotFlagWithCredentialsBindingsFromInlinePipelineScript() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                withCredentials([
                  string(credentialsId: 'service-api-token', variable: 'SERVICE_TOKEN'),
                  usernamePassword(credentialsId: 'service-user-pass', usernameVariable: 'SERVICE_USER', passwordVariable: 'SERVICE_PASS')
                ]) {
                  httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [
                      [name: "Authorization", value: "Bearer ${SERVICE_TOKEN}", maskValue: true],
                      [name: "x-service-basic", value: "${SERVICE_USER}:${SERVICE_PASS}".bytes.encodeBase64().toString(), maskValue: true]
                    ]
                  )
                }
                    ]]></script>
                    <sandbox>true</sandbox>
                  </definition>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertFalse(result.hasFindings());
    }

    private ScanContext context(String targetType) {
        return new ScanContext(
                "folder/job",
                "config.xml",
                targetType,
                FindingLocationType.CONFIG_XML,
                ScanPhase.SAVE,
                EnforcementMode.BLOCK,
                Severity.HIGH);
    }
}
