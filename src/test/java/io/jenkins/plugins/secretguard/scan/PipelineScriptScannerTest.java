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
