@Library('build-tools@release') _

pipeline {
  agent { label 'linux && docker' }

  options {
    timeout(time: 30, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '20'))
  }

  environment {
    RELEASE_MANIFEST_URL = 'https://repo-host.example.invalid/repository/manifests/example-service/latest.json'
    DEPLOY_CONFIG_PATH = 'ci/release/deploy-values.yaml'
  }

  stages {
    stage('Prepare') {
      steps {
        script {
          def repoRef = 'refs/tags/release-2026.05'
          def callbackUrl = 'https://notify.example.invalid/api/callback/release-created'
          def metadataUrl = 'jdbc:mysql://db.example.invalid:3306/release_metadata?sessionVariables=sql_mode=STRICT_TRANS_TABLES&permitMysqlScheme&useMysqlMetadata=true'

          echo "ref=${repoRef}"
          echo "callback=${callbackUrl}"
          echo "metadata=${metadataUrl}"
          echo "deployConfig=${DEPLOY_CONFIG_PATH}"
        }
      }
    }

    stage('Publish') {
      steps {
        withCredentials([
          string(credentialsId: 'release-service-token', variable: 'SERVICE_API_TOKEN'),
          usernamePassword(credentialsId: 'release-user-pass', usernameVariable: 'SERVICE_USER', passwordVariable: 'SERVICE_PASS'),
          file(credentialsId: 'release-token-file', variable: 'TOKEN_FILE')
        ]) {
          withEnv([
            "JFROG_CLI_BUILD_NAME=${env.JOB_NAME}",
            "SERVICE_TOKEN_FILE=${TOKEN_FILE}"
          ]) {
            retry(2) {
              httpRequest(
                url: "https://api.example.invalid/v2/release/status",
                customHeaders: sanitizeHeaders(
                  "release",
                  [source: "jenkins", trace: [requestId: "0af7651916cd43dd8448eb211c80319c"]],
                  [
                    [name: "Authorization", value: "Bearer ${params.SERVICE_API_TOKEN ?: env.SERVICE_API_TOKEN ?: ''}", maskValue: true],
                    [name: "x-service-basic", value: "${SERVICE_USER}:${SERVICE_PASS}".bytes.encodeBase64().toString(), maskValue: true],
                    [name: "X-Request-ID", value: "0af7651916cd43dd8448eb211c80319c", maskValue: false]
                  ] as List<Map<String, Object>>
                ),
                validResponseCodes: "100:599",
                quiet: true
              )
              sh 'curl -u "$SERVICE_USER:$SERVICE_PASS" https://repo-host.example.invalid/repository/index'
              sh 'cat "$TOKEN_FILE" >/dev/null'
            }
          }
        }
      }
    }
  }
}
