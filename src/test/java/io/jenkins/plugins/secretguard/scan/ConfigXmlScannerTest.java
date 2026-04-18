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
import io.jenkins.plugins.secretguard.testutil.TestResourceLoader;
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
    void doesNotFlagSensitiveEnvironmentFileReferencesFromInlinePipelineScript() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                pipeline {
                  agent any
                  environment {
                    PASSWORD_FILE = 'pwd.txt'
                  }
                  stages {
                    stage('noop') {
                      steps {
                        echo 'using file-backed secret reference'
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

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotFlagGeneratedParameterSeparatorNamesAsHighEntropySecrets() {
        String xml = """
                <flow-definition>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <jenkins.plugins.parameter__separator.ParameterSeparatorDefinition plugin="parameter-separator@1.3">
                          <name>separator-d45a9f41-b001-4c08-80ab-a23bdc5ccb96</name>
                        </jenkins.plugins.parameter__separator.ParameterSeparatorDefinition>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagNonSecretUrlDescriptionsAsHighEntropySecrets() {
        String xml = """
                <flow-definition>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <hudson.model.StringParameterDefinition>
                          <name>EXAMPLE_BUILD_URL</name>
                          <description>Example: http://jenkins.example.invalid:8080/job/example-service/job/build-test/80</description>
                        </hudson.model.StringParameterDefinition>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
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
    void detectsStructuredHttpRequestPluginCustomHeadersFromConfigXml() {
        String xml = """
                <project>
                  <builders>
                    <jenkins.plugins.http__request.HttpRequest plugin="http_request@1.20">
                      <url>https://api.example.invalid/v1/request-check</url>
                      <authentication>service-http-request-credential</authentication>
                      <customHeaders>
                        <jenkins.plugins.http__request.util.HttpRequestNameValuePair>
                          <name>Authorization</name>
                          <value>Bearer hardcodedHeaderValue0123456789ABCDEF</value>
                          <maskValue>false</maskValue>
                        </jenkins.plugins.http__request.util.HttpRequestNameValuePair>
                        <jenkins.plugins.http__request.util.HttpRequestNameValuePair>
                          <name>X-Request-ID</name>
                          <value>0af7651916cd43dd8448eb211c80319c</value>
                          <maskValue>false</maskValue>
                        </jenkins.plugins.http__request.util.HttpRequestNameValuePair>
                      </customHeaders>
                    </jenkins.plugins.http__request.HttpRequest>
                  </builders>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")
                        && finding.getFieldName().equals("authentication")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getFieldName().equals("X-Request-ID")));
    }

    @Test
    void doesNotFlagSerializedHttpRequestPluginCustomHeadersWithRuntimeReference() {
        String xml = """
                <project>
                  <builders>
                    <jenkins.plugins.http__request.HttpRequest plugin="http_request@1.20">
                      <url>https://api.example.invalid/v1/request-check</url>
                      <authentication>service-http-request-credential</authentication>
                      <customHeaders>[[name: 'x-service-token', value: "${SERVICE_TOKEN}", maskValue: true], [name: 'Authorization', value: 'Bearer ' + params.SERVICE_TOKEN, maskValue: true]]</customHeaders>
                    </jenkins.plugins.http__request.HttpRequest>
                  </builders>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.hasFindings());
    }

    @Test
    void doesNotFlagGitPluginBranchAndRefspecMetadataAsSecrets() {
        String xml = """
                <project>
                  <scm class="hudson.plugins.git.GitSCM" plugin="git@5.2.1">
                    <userRemoteConfigs>
                      <hudson.plugins.git.UserRemoteConfig>
                        <url>git@example.invalid:platform/backend-service.git</url>
                        <credentialsId>git-reader-main</credentialsId>
                        <name>origin-enterprise</name>
                        <refspec>+refs/heads/release/0123456789abcdef0123456789abcdef:refs/remotes/origin/release/0123456789abcdef0123456789abcdef</refspec>
                      </hudson.plugins.git.UserRemoteConfig>
                    </userRemoteConfigs>
                    <branches>
                      <hudson.plugins.git.BranchSpec>
                        <name>refs/heads/release/0123456789abcdef0123456789abcdef</name>
                      </hudson.plugins.git.BranchSpec>
                    </branches>
                  </scm>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.hasFindings());
    }

    @Test
    void stillFlagsGitPluginRemoteUrlQuerySecrets() {
        String xml = """
                <project>
                  <scm class="hudson.plugins.git.GitSCM" plugin="git@5.2.1">
                    <userRemoteConfigs>
                      <hudson.plugins.git.UserRemoteConfig>
                        <url>https://git.example.invalid/platform/backend-service.git?access_token=ghp_012345678901234567890123456789012345</url>
                        <credentialsId>git-reader-main</credentialsId>
                      </hudson.plugins.git.UserRemoteConfig>
                    </userRemoteConfigs>
                  </scm>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
    }

    @Test
    void doesNotFlagKubernetesSecretEnvVarReferencesAsPlaintextSecrets() {
        String xml = """
                <project>
                  <properties>
                    <org.csanchez.jenkins.plugins.kubernetes.KubernetesPodTemplateProperty>
                      <templates>
                        <org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                          <containers>
                            <org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                              <envVars>
                                <org.csanchez.jenkins.plugins.kubernetes.model.SecretEnvVar>
                                  <key>SERVICE_API_TOKEN</key>
                                  <secretName>service-api-token-prod</secretName>
                                  <secretKey>token</secretKey>
                                </org.csanchez.jenkins.plugins.kubernetes.model.SecretEnvVar>
                              </envVars>
                            </org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                          </containers>
                        </org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                      </templates>
                    </org.csanchez.jenkins.plugins.kubernetes.KubernetesPodTemplateProperty>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.hasFindings());
    }

    @Test
    void stillFlagsKubernetesPlaintextKeyValueEnvVarSecrets() {
        String xml = """
                <project>
                  <properties>
                    <org.csanchez.jenkins.plugins.kubernetes.KubernetesPodTemplateProperty>
                      <templates>
                        <org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                          <containers>
                            <org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                              <envVars>
                                <org.csanchez.jenkins.plugins.kubernetes.model.KeyValueEnvVar>
                                  <key>SERVICE_API_TOKEN</key>
                                  <value>ghp_012345678901234567890123456789012345</value>
                                </org.csanchez.jenkins.plugins.kubernetes.model.KeyValueEnvVar>
                              </envVars>
                            </org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                          </containers>
                        </org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                      </templates>
                    </org.csanchez.jenkins.plugins.kubernetes.KubernetesPodTemplateProperty>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("github-token")));
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

    @Test
    void doesNotFlagScriptPathJenkinsfileNamesAsHighEntropySecrets() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition">
                    <scriptPath>ExamplePipelineScript.Jenkinsfile</scriptPath>
                  </definition>
                </flow-definition>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("WorkflowJob"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagReadableJdbcDefaultValueOptionsAsHighEntropySecrets() {
        String xml = """
                <project>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <hudson.model.StringParameterDefinition>
                          <name>EXAMPLE_DATABASE_URL</name>
                          <defaultValue>jdbc:mysql://db.example.invalid:3306/example_metadata?sessionVariables=sql_mode=STRICT_TRANS_TABLES&amp;permitMysqlScheme&amp;useMysqlMetadata=true</defaultValue>
                        </hudson.model.StringParameterDefinition>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagGeneratedParameterRandomNamesAsHighEntropySecrets() {
        String xml = """
                <project>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <org.biouno.unochoice.DynamicReferenceParameter plugin="uno-choice@2.8.3">
                          <name>EXAMPLE_MEMORY_MB</name>
                          <randomName>choice-parameter-108997464504044</randomName>
                        </org.biouno.unochoice.DynamicReferenceParameter>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagCuratedArtifactMetadataFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-artifact-job-config.xml"));

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
