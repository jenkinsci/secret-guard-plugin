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
    void detectsBasicAuthAndProviderWebhookSecretsFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <notificationEndpoint>https://hooks.zapier.com/hooks/catch/123456/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua/</notificationEndpoint>
                    <customHeaders>
                      <header>Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l</header>
                    </customHeaders>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("basic-auth-header")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("zapier-webhook-url")));
    }

    @Test
    void detectsCommonCicdProviderTokensAndAuthContextsFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <slackToken>%s</slackToken>
                    <pypiToken>%s</pypiToken>
                    <gitlabToken>%s</gitlabToken>
                    <npmConfig>//registry.npmjs.org/:_authToken=%s</npmConfig>
                    <npmLegacyAuth>//registry.npmjs.org/:_auth=QWxhZGRpbjpPcGVuU2VzYW1l</npmLegacyAuth>
                    <npmLegacyPassword>npm config set _password QWxhZGRpbjpPcGVuU2VzYW1l</npmLegacyPassword>
                    <jfrogCli>jf c add build-tools --access-token %s</jfrogCli>
                    <twineCommand>TWINE_PASSWORD=PlainSecret42 twine upload -u build-user -p PlainSecret42 dist/*</twineCommand>
                    <pypirc>[distutils]
index-servers = pypi

[pypi]
username = build-user
password = PlainSecret42
                    </pypirc>
                    <dockerCommand>echo PlainSecret42 | docker login --username build-user --password-stdin registry.example.invalid</dockerCommand>
                  </publishers>
                </project>
                """.formatted(slackBotToken(), pypiApiToken(), gitlabToken(), npmAuthToken(), jfrogAccessToken());
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("slack-bot-token")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-api-token")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("gitlab-token")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-auth-token-context")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-legacy-auth-context")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("jfrog-access-token-context")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-password-context")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("docker-password-stdin-secret")));
    }

    @Test
    void doesNotFlagRuntimeNpmAndJfrogContextsFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <npmConfig>//registry.npmjs.org/:_authToken=${NPM_TOKEN}</npmConfig>
                    <npmLegacyAuth>//registry.npmjs.org/:_auth=${NPM_BASIC_AUTH}</npmLegacyAuth>
                    <npmLegacyPassword>npm config set _password ${NPM_PASSWORD}</npmLegacyPassword>
                    <jfrogCli>jf c add build-tools --access-token ${JFROG_CLI_ACCESS_TOKEN}</jfrogCli>
                    <twineCommand>TWINE_PASSWORD=${TWINE_PASSWORD} twine upload -u build-user -p ${TWINE_PASSWORD} dist/*</twineCommand>
                    <pypirc>[distutils]
index-servers = pypi

[pypi]
username = build-user
password = ${TWINE_PASSWORD}
                    </pypirc>
                    <dockerCommand>echo ${REGISTRY_PASSWORD} | docker login --username build-user --password-stdin registry.example.invalid</dockerCommand>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-auth-token-context")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("npm-legacy-auth-context")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("jfrog-access-token-context")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("pypi-password-context")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("docker-password-stdin-secret")));
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
                    <fourthPublisher>
                      <secret>params['SERVICE_API_TOKEN'] ?: ''</secret>
                    </fourthPublisher>
                    <fifthPublisher>
                      <secret>env?.SERVICE_API_TOKEN?.trim()</secret>
                    </fifthPublisher>
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
                def fallback = httpRequest(
                    httpMode: "POST",
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: params['SERVICE_API_TOKEN'] ?: '', maskValue: true]]
                )
                def conditional = httpRequest(
                    httpMode: "POST",
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "Authorization", value: params.SERVICE_API_TOKEN ? "Bearer ${params.SERVICE_API_TOKEN}" : '', maskValue: true]]
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
    void detectsPassphraseFieldsWithoutFlaggingVariableDeclarationsFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <somePublisher>
                      <deployPassphrase>PlainSecret42</deployPassphrase>
                      <passphraseVariable>SSH_PASSPHRASE</passphraseVariable>
                      <privateKeyPassphraseVariable>DEPLOY_KEY_PASSPHRASE</privateKeyPassphraseVariable>
                    </somePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(
                result.getFindings().stream().anyMatch(finding -> "passphraseVariable".equals(finding.getFieldName())));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> "privateKeyPassphraseVariable".equals(finding.getFieldName())));
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
    void doesNotFlagReadableUrlsOnSensitiveNamedConfigFields() {
        String xml = """
                <project>
                  <properties>
                    <integration>
                      <getPasswordUrl>http://service.example.invalid/auth</getPasswordUrl>
                      <tokenEndpoint>https://service.example.invalid/oauth/token</tokenEndpoint>
                    </integration>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotFlagReadableUrlsAssignedToSensitiveNamedInlinePipelineVariables() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def getPasswordUrl = "http://service.example.invalid/auth"
                def tokenEndpoint = "https://service.example.invalid/oauth/token"
                def secretUploadUrl = "sftp://files.example.invalid:22/runtime/upload"
                def passwordServiceEndpoint = "service.example.invalid:8443/auth"
                def tokenWebhookUrl = "hooks.example.invalid/services/runtime"
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
    void doesNotFlagReadableDescriptionIdentifiersAsHighEntropySecrets() {
        String xml = """
                <project>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <hudson.model.StringParameterDefinition>
                          <name>EXAMPLE_OPERATION_NOTE</name>
                          <description>Run svcOnlineRestoreSvcFromReplicaDataBackup before retrying the workflow.</description>
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
    void stillFlagsEncodedDescriptionTokensAsHighEntropySecrets() {
        String xml = """
                <project>
                  <properties>
                    <hudson.model.ParametersDefinitionProperty>
                      <parameterDefinitions>
                        <hudson.model.StringParameterDefinition>
                          <name>EXAMPLE_OPERATION_NOTE</name>
                          <description>Token sample: QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l</description>
                        </hudson.model.StringParameterDefinition>
                      </parameterDefinitions>
                    </hudson.model.ParametersDefinitionProperty>
                  </properties>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
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
    void parsesParenthesizedAndCastCustomHeadersFromInlinePipelineScript() {
        String xml = """
                <flow-definition>
                  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
                    <script><![CDATA[
                def response = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: (
                        [
                            (["name": "x-service-token", "value": env.SERVICE_API_TOKEN, "maskValue": true]),
                            ([name: "Authorization", value: "Bearer hardcodedHeaderValue0123456789ABCDEF", maskValue: false])
                        ] as List<Map<String, Object>>
                    )
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
                .anyMatch(finding -> finding.getFieldName().equals("x-service-token")));
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
    void doesNotFlagReadableNotifierUrlsInConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <io.example.ChatNotifierPublisher>
                      <webhookUrl>https://hooks.example.invalid/services/release-events/build-status</webhookUrl>
                      <callbackUrl>https://notify.example.invalid/api/callback/release-created</callbackUrl>
                    </io.example.ChatNotifierPublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void detectsSecretsEmbeddedInNotifierUrlsFromConfigXml() {
        String xml = """
                <project>
                  <publishers>
                    <io.example.ChatNotifierPublisher>
                      <webhookUrl>https://hooks.example.invalid/services/TEAM01/ROOM01/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua</webhookUrl>
                      <notifyUrl>https://notify.example.invalid/api/webhook/deliver?signature=Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua</notifyUrl>
                    </io.example.ChatNotifierPublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
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
    void doesNotFlagCommonPublisherSecretReferenceFieldsAsPlaintextSecrets() {
        String xml = """
                <project>
                  <publishers>
                    <io.example.SecretAwarePublisher>
                      <secretName>artifact-service-token-prod</secretName>
                      <secretKey>token</secretKey>
                      <credentialsName>artifact-deploy-reader</credentialsName>
                    </io.example.SecretAwarePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertFalse(result.hasFindings());
        assertTrue(result.hasNotes());
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped common plugin")));
        assertFalse(result.getNotes().stream().anyMatch(note -> note.contains("artifact-service-token-prod")));
    }

    @Test
    void deduplicatesRepeatedAdapterDecisionNotes() {
        String xml = """
                <project>
                  <publishers>
                    <io.example.SecretAwarePublisher>
                      <secretName>artifact-service-token-prod</secretName>
                      <secretKey>token</secretKey>
                      <credentialsName>artifact-deploy-reader</credentialsName>
                      <credential>artifact-runtime-reader</credential>
                    </io.example.SecretAwarePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertEquals(
                1,
                result.getNotes().stream()
                        .filter(note -> note.contains("Adapter: skipped common plugin"))
                        .count());
    }

    @Test
    void stillFlagsCommonPublisherHighConfidenceSecretLiterals() {
        String xml = """
                <project>
                  <publishers>
                    <io.example.SecretAwarePublisher>
                      <secretName>ghp_012345678901234567890123456789012345</secretName>
                      <secretKey>token</secretKey>
                    </io.example.SecretAwarePublisher>
                  </publishers>
                </project>
                """;
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(context("FreeStyleProject"), xml);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("github-token")));
        assertFalse(
                result.getNotes().stream().anyMatch(note -> note.contains("ghp_012345678901234567890123456789012345")));
    }

    @Test
    void recordsAdapterDecisionNotesWithoutRawValues() {
        String xml = """
                <project>
                  <scm class="hudson.plugins.git.GitSCM" plugin="git@5.2.1">
                    <userRemoteConfigs>
                      <hudson.plugins.git.UserRemoteConfig>
                        <name>origin-sensitive-reference</name>
                        <refspec>+refs/heads/release/0123456789abcdef0123456789abcdef:refs/remotes/origin/release/0123456789abcdef0123456789abcdef</refspec>
                      </hudson.plugins.git.UserRemoteConfig>
                    </userRemoteConfigs>
                    <branches>
                      <hudson.plugins.git.BranchSpec>
                        <name>refs/heads/release/0123456789abcdef0123456789abcdef</name>
                      </hudson.plugins.git.BranchSpec>
                    </branches>
                  </scm>
                  <properties>
                    <org.csanchez.jenkins.plugins.kubernetes.KubernetesPodTemplateProperty>
                      <templates>
                        <org.csanchez.jenkins.plugins.kubernetes.PodTemplate>
                          <containers>
                            <org.csanchez.jenkins.plugins.kubernetes.ContainerTemplate>
                              <envVars>
                                <org.csanchez.jenkins.plugins.kubernetes.model.SecretEnvVar>
                                  <key>SERVICE_API_TOKEN</key>
                                  <secretName>k8s-service-token-prod</secretName>
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

        assertTrue(result.hasNotes());
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped Git branch metadata")));
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped Git refspec metadata")));
        assertTrue(result.getNotes().stream()
                .anyMatch(note -> note.contains("Adapter: skipped Kubernetes secret-backed")));
        assertFalse(result.getNotes().stream().anyMatch(note -> note.contains("origin-sensitive-reference")));
        assertFalse(result.getNotes().stream().anyMatch(note -> note.contains("0123456789abcdef")));
        assertFalse(result.getNotes().stream().anyMatch(note -> note.contains("k8s-service-token-prod")));
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

    @Test
    void doesNotFlagCuratedParameterMetadataFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-parameter-metadata-config.xml"));

        assertFalse(result.hasFindings());
    }

    @Test
    void doesNotFlagCuratedPluginReferenceFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-plugin-reference-config.xml"));

        assertFalse(result.hasFindings());
        assertTrue(result.hasNotes());
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped Git branch metadata")));
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped Git refspec metadata")));
        assertTrue(result.getNotes().stream()
                .anyMatch(note -> note.contains("Adapter: skipped Kubernetes secret-backed")));
        assertTrue(result.getNotes().stream().anyMatch(note -> note.contains("Adapter: skipped common plugin")));
    }

    @Test
    void detectsCuratedPluginSecretConfigFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/true-positives/common-plugin-secret-job-config.xml"));

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("github-token")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")
                        && finding.getFieldName().equals("password")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getFieldName().equals("X-Request-ID")));
    }

    @Test
    void doesNotFlagCuratedGenericPluginHeadersFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-generic-plugin-headers-config.xml"));

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
        assertTrue(result.getNotes().stream()
                .anyMatch(note -> note.contains("Adapter: parsed generic plugin header configuration")));
    }

    @Test
    void detectsCuratedGenericPluginHeaderSecretFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/true-positives/common-generic-plugin-header-secret-config.xml"));

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getFieldName().equals("X-Request-ID")));
    }

    @Test
    void doesNotFlagCuratedNotifierUrlFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-notifier-urls-config.xml"));

        assertFalse(result.hasFindings());
    }

    @Test
    void detectsCuratedNotifierSecretFixture() {
        ConfigXmlScanner scanner = new ConfigXmlScanner();
        SecretScanResult result = scanner.scan(
                context("FreeStyleProject"),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/true-positives/common-notifier-secret-job-config.xml"));

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
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

    private String npmAuthToken() {
        return "0123456789abcdef0123456789abcdef";
    }

    private String jfrogAccessToken() {
        return "cmVmLXRva2VuLTAxMjM0NTY3ODlhYmNkZWY";
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
