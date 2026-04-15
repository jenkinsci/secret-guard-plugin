package io.jenkins.plugins.secretguard.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        assertTrue(result.getFindings().stream().anyMatch(finding -> finding.getFieldName().equals("password")));
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
