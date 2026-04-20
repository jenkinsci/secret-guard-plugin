package io.jenkins.plugins.secretguard.scan;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
import io.jenkins.plugins.secretguard.model.SecretFinding;
import io.jenkins.plugins.secretguard.model.SecretScanResult;
import io.jenkins.plugins.secretguard.model.Severity;
import io.jenkins.plugins.secretguard.testutil.TestResourceLoader;
import org.junit.jupiter.api.Test;

class PipelineScriptScannerTest {
    private final PipelineScriptScanner scanner = new PipelineScriptScanner();

    @Test
    void detectsEnvironmentAndCommandSecrets() {
        String script = """
                pipeline {
                  agent any
                  environment {
                    API_TOKEN = 'ghp_012345678901234567890123456789012345'
                  }
                  stages {
                    stage('Call API') {
                      steps {
                        sh "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature' https://example.invalid"
                      }
                    }
                  }
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getLocationType() == FindingLocationType.ENVIRONMENT));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getLocationType() == FindingLocationType.COMMAND_STEP));
    }

    @Test
    void doesNotFlagWithCredentialsExampleAsHighRisk() {
        String script = """
                pipeline {
                  agent any
                  stages {
                    stage('Call API') {
                      steps {
                        withCredentials([string(credentialsId: 'api-token', variable: 'API_TOKEN')]) {
                          sh 'curl -H "Authorization: Bearer $API_TOKEN" https://example.invalid'
                        }
                      }
                    }
                  }
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void downgradesPlaceholderEnvironmentValues() {
        String script = """
                pipeline {
                  agent any
                  environment {
                    SERVICE_API_TOKEN = '__REDACTED__'
                    SERVICE_API_SECRET = '****'
                  }
                  stages {
                    stage('noop') {
                      steps {
                        echo 'placeholder values are configured elsewhere'
                      }
                    }
                  }
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotFlagSensitiveEnvironmentFileReferences() {
        String script = """
                pipeline {
                  agent any
                  environment {
                    PASSWORD_FILE = 'pwd.txt'
                    SERVICE_TOKEN_PATH = '/run/secrets/service_token'
                  }
                  stages {
                    stage('noop') {
                      steps {
                        echo 'using file-backed secrets'
                      }
                    }
                  }
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void detectsHardcodedHttpRequestCustomHeaderSecret() {
        String script = """
                def sonarServer = "http://security.example.invalid/qa_auth"
                result = httpRequest customHeaders: [[maskValue: false, name: 'x-example-auth',
                            value: 'ExampleHeaderSecretValue0123456789ABCDEF']],
                            url: "${sonarServer}",
                            quiet: true
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
    }

    @Test
    void doesNotFlagCredentialBackedHttpRequestHeader() {
        String script = """
                withCredentials([string(credentialsId: 'qa-tools-header', variable: 'QA_TOOLS_HEADER')]) {
                  httpRequest customHeaders: [[maskValue: true, name: 'x-example-auth', value: QA_TOOLS_HEADER]],
                              url: "https://example.invalid"
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
    }

    @Test
    void doesNotTreatPlaceholderHttpRequestHeaderAsHardcodedSecret() {
        String script = """
                httpRequest customHeaders: [[maskValue: false, name: 'x-example-token',
                            value: 'Bearer __MASKED__']],
                            url: "https://example.invalid"
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotFlagWithCredentialsUsernamePasswordAndStringCombinations() {
        String script = """
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
                  sh 'curl -u "$SERVICE_USER:$SERVICE_PASS" https://example.invalid'
                  sh "curl -H \\"Authorization: Bearer $SERVICE_TOKEN\\" https://example.invalid"
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotFlagAdditionalWithCredentialsBindingTypes() {
        String script = """
                withCredentials([
                  file(credentialsId: 'deploy-secret-file', variable: 'SECRET_FILE'),
                  sshUserPrivateKey(credentialsId: 'deploy-ssh-key', keyFileVariable: 'SSH_KEY_FILE', usernameVariable: 'SSH_USER', passphraseVariable: 'SSH_PASSPHRASE'),
                  usernameColonPassword(credentialsId: 'repository-login', variable: 'REPOSITORY_LOGIN'),
                  gitUsernamePassword(credentialsId: 'git-http-login', gitToolName: 'Default')
                ]) {
                  sh 'cat "$SECRET_FILE" >/dev/null'
                  sh 'ssh -i "$SSH_KEY_FILE" -l "$SSH_USER" example.invalid true'
                  sh 'curl -u "$REPOSITORY_LOGIN" https://example.invalid/repository/index'
                  sh 'git ls-remote https://example.invalid/platform/example.git'
                  httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [
                      [name: "Authorization", value: REPOSITORY_LOGIN.bytes.encodeBase64().toString(), maskValue: true],
                      [name: "x-service-passphrase", value: env.get('SSH_PASSPHRASE'), maskValue: true]
                    ]
                  )
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(result.getFindings().stream().anyMatch(finding -> finding.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotCarryHeaderNameAcrossFollowingLinesWhenHeaderUsesRuntimeVariable() {
        String script = """
                def response = httpRequest \\
                    httpMode: "POST",
                    contentType: 'APPLICATION_JSON',
                    requestBody: groovy.json.JsonOutput.toJson(request_body),
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: "$SERVICE_API_TOKEN", maskValue: true]]
                def response_content = readJSON text: response.content
                def response_code = response_content['code']
                if (response_code != 0) {
                  error("failed")
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
        assertFalse(
                result.getFindings().stream().map(SecretFinding::getFieldName).anyMatch("x-service-token"::equals));
    }

    @Test
    void doesNotFlagAdditionalRuntimeHeaderReferenceForms() {
        String script = """
                def first = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: params.SERVICE_API_TOKEN, maskValue: true]]
                )
                def second = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: env['SERVICE_API_TOKEN'], maskValue: true]]
                )
                def third = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "Authorization", value: "Bearer ${env.SERVICE_API_TOKEN}", maskValue: true]]
                )
                def fourth = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "Authorization", value: 'Bearer ' + params.SERVICE_API_TOKEN, maskValue: true]]
                )
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotFlagRuntimeHeaderReferencesWithFallbacksOrConditionals() {
        String script = """
                def first = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: params['SERVICE_API_TOKEN'] ?: '', maskValue: true]]
                )
                def second = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "x-service-token", value: env?.SERVICE_API_TOKEN?.trim(), maskValue: true]]
                )
                def third = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[name: "Authorization", value: params.SERVICE_API_TOKEN ? "Bearer ${params.SERVICE_API_TOKEN}" : '', maskValue: true]]
                )
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotFlagReadableUrlsAssignedToSensitiveNamedVariables() {
        String script = """
                def getPasswordUrl = "http://service.example.invalid/auth"
                def tokenEndpoint = "https://service.example.invalid/oauth/token"
                def secretUploadUrl = "sftp://files.example.invalid:22/runtime/upload"
                def passwordServiceEndpoint = "service.example.invalid:8443/auth"
                def tokenWebhookUrl = "hooks.example.invalid/services/runtime"
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void parsesMultipleCustomHeadersAcrossMixedLayouts() {
        String script = """
                def response = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [
                        [
                            name: "x-safe-token",
                            value: env['SERVICE_API_TOKEN'],
                            maskValue: true
                        ],
                        [name: "Authorization", value: "Bearer hardcodedHeaderValue0123456789ABCDEF", maskValue: false]],
                    quiet: true
                )
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .filter(finding -> finding.getRuleId().startsWith("http-request-"))
                .anyMatch(finding -> finding.getFieldName().equals("x-safe-token")));
    }

    @Test
    void parsesNestedHeaderValueExpressionsWithoutCarryingWrongContext() {
        String script = """
                def response = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: [[
                        name: "Authorization",
                        value: "Bearer ${helper([token: env.SERVICE_API_TOKEN, meta: [source: 'jenkins']])}",
                        maskValue: true
                    ]]
                )
                def response_content = readJSON text: response.content
                def response_code = response_content['code']
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void parsesParenthesizedAndCastCustomHeadersLayouts() {
        String script = """
                def response = httpRequest(
                    url: "https://api.example.invalid/v1/request-check",
                    customHeaders: (
                        [
                            (["name": "x-service-token", "value": env.SERVICE_API_TOKEN, "maskValue": true]),
                            ([name: "Authorization", value: "Bearer hardcodedHeaderValue0123456789ABCDEF", maskValue: false])
                        ] as List<Map<String, Object>>
                    ),
                    quiet: true
                )
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .filter(finding -> finding.getRuleId().startsWith("http-request-"))
                .anyMatch(finding -> finding.getFieldName().equals("x-service-token")));
    }

    @Test
    void stillScansOtherArgumentsOnSameLineAsCustomHeaders() {
        String script = """
                def response = httpRequest(customHeaders: [[name: "Authorization", value: "Bearer hardcodedHeaderValue0123456789ABCDEF", maskValue: false]], url: "https://chat.example.invalid/cgi-bin/webhook/send?token=123e4567-e89b-12d3-a456-426614174999")
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
    }

    @Test
    void doesNotFlagHumanReadableGradleTaskNamesAsHighEntropySecrets() {
        String script = """
                sh './gradlew --info --refresh-dependencies -Prelease -PskipAndroid=true -PskipCodegen=true build publishAllPublicationsToMavenRepository -x test -x check -PmavenUser=$USER -PmavenPassword=$PASSWORD'
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagHumanReadableArtifactRepositoryPathsAsHighEntropySecrets() {
        String script = """
                sh 'jfrog rt u /opt/tool/tool-$ARCH-$TIMESTAMP.tar artifact-internal/inf/tool/tool_prebuild_binary/test/$DATE/tool-$ARCH-$TIMESTAMP.tar'
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagUrlHostPortRepositoryPathsAsHighEntropySecrets() {
        String script = """
                def buildType = sh(script: 'wget https://artifacts.example.invalid:443/repository/build-tools/bootstrap_bundle/ && python3 resolve_build_type.py', returnStdout: true).trim()
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagAdditionalRepositoryAddressFamiliesAsHighEntropySecrets() {
        String script = """
                sh 'curl ftp://artifacts.example.invalid:21/repository/build-tools/bootstrap_bundle/'
                sh 'curl sftp://10.1.2.3:22/repository/build-tools/bootstrap_bundle/'
                sh 'wget http://artifactory:8081/repository/build-tools/bootstrap_bundle/'
                sh 'wget 10.1.2.3:8081/repository/build-tools/bootstrap_bundle/'
                sh 'git clone git@repo-host:platform/build-tools/bootstrap_bundle_release.git'
                sh 'cp //repo-host/shared/build-tools/bootstrap_bundle_release /tmp/bootstrap_bundle_release'
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagDockerImageOrScriptPathAsHighEntropySecret() {
        String script = """
                pipeline {
                    agent {
                        docker {
                            alwaysPull true
                            image 'registry.example.invalid/team/tooling/cicd/example_runner:0.2'
                            registryUrl 'http://registry.example.invalid'
                            registryCredentialsId 'jfrog-cred-default'
                            args  '-v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/usr/bin/docker -u root:root -e TZ=Asia/Shanghai'
                            label 'nsgx'
                        }
                    }

                    stages {
                        stage('sync') {
                            steps {
                                sh 'python3 /opt/example-tools/run-task-reporter.py'
                            }
                        }
                    }
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagJenkinsfilePathLiteralsAsHighEntropySecrets() {
        String script = """
                def pipelineScript = load 'ci/ExamplePipelineScript.Jenkinsfile'
                pipelineScript.run()
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagStorageUriPathsAsHighEntropySecrets() {
        String script = """
                properties([
                    parameters([
                        string(name: 'json_data_path', value: 'hdfs:///example/runtime/sample_dataset/record_01')
                    ])
                ])
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void doesNotFlagTrackingHeadersAsSecrets() {
        String script = """
                httpRequest customHeaders: [[maskValue: false, name: 'X-Request-ID',
                            value: '0af7651916cd43dd8448eb211c80319c']],
                            url: "https://example.invalid"
                httpRequest customHeaders: [[maskValue: false, name: 'X-Correlation-ID',
                            value: 'QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l']],
                            url: "https://example.invalid"
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
    }

    @Test
    void detectsWebhookKeyEmbeddedInUrl() {
        String script = """
                def sendMessage(){
                    sh '''
                        curl "https://chat.example.invalid/cgi-bin/webhook/send?key=123e4567-e89b-12d3-a456-426614174999" \\
                           -H "Content-Type: application/json" \\
                           -d '{"msgtype":"text","text":{"content":"weekly update"}}'
                    '''
                }
                """;
        SecretScanResult result = scanner.scan(context(), script);
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("url-query-secret")));
    }

    @Test
    void detectsNotifierSecretsEmbeddedInWebhookUrlPaths() {
        String script = """
                def webhookUrl = "https://hooks.example.invalid/services/TEAM01/ROOM01/Nr8YkL2Pm5Qx7Vd1Hs4Jt6Ua"
                sh "curl -X POST '${webhookUrl}'"
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
    }

    @Test
    void doesNotFlagReadableNotifierUrlsInPipelineScripts() {
        String script = """
                def webhookUrl = "https://hooks.example.invalid/services/release-events/build-status"
                def callbackUrl = "https://notify.example.invalid/api/callback/release-created"
                sh "echo ready"
                """;
        SecretScanResult result = scanner.scan(context(), script);

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("notifier-url-secret")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void doesNotFlagCuratedPublishPipelineFixture() {
        SecretScanResult result = scanner.scan(
                context(),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-publish.Jenkinsfile"));

        assertFalse(result.hasFindings());
    }

    @Test
    void doesNotFlagCuratedRuntimePatternsFixture() {
        SecretScanResult result = scanner.scan(
                context(),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-runtime-patterns.Jenkinsfile"));

        assertFalse(result.hasFindings());
    }

    @Test
    void doesNotFlagCuratedHttpRequestCustomHeadersFixture() {
        SecretScanResult result = scanner.scan(
                context(),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/false-positives/common-http-request-custom-headers.Jenkinsfile"));

        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().startsWith("http-request-")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("high-entropy-string")));
        assertFalse(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("sensitive-field-name")));
    }

    @Test
    void detectsCuratedHardcodedHttpRequestCustomHeadersFixture() {
        SecretScanResult result = scanner.scan(
                context(),
                TestResourceLoader.load(
                        "/io/jenkins/plugins/secretguard/fixtures/true-positives/hardcoded-http-request-custom-headers.Jenkinsfile"));

        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-hardcoded-header-secret")));
        assertTrue(result.getFindings().stream()
                .anyMatch(finding -> finding.getRuleId().equals("http-request-unmasked-header-secret")));
        assertFalse(result.getFindings().stream()
                .filter(finding -> finding.getRuleId().startsWith("http-request-"))
                .anyMatch(finding -> finding.getFieldName().equals("x-safe-token")));
    }

    private ScanContext context() {
        return new ScanContext(
                "folder/job",
                "Pipeline script",
                "WorkflowJob",
                FindingLocationType.PIPELINE_SCRIPT,
                ScanPhase.BUILD,
                EnforcementMode.BLOCK,
                Severity.HIGH);
    }
}
