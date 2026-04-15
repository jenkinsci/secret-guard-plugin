package io.jenkins.plugins.secretguard.scan;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jenkins.plugins.secretguard.model.EnforcementMode;
import io.jenkins.plugins.secretguard.model.FindingLocationType;
import io.jenkins.plugins.secretguard.model.ScanContext;
import io.jenkins.plugins.secretguard.model.ScanPhase;
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
