pipeline {
  agent any

  environment {
    BUILD_REPORT_URL = 'https://ci.example.invalid/job/example-service/job/build-and-publish/80'
    SERVICE_PASSWORD_FILE = 'pwd.txt'
  }

  stages {
    stage('Resolve metadata') {
      steps {
        script {
          def restoreTask = '@svcOnlineRestoreFromReplicaDataBackup'
          def buildScriptPath = 'ci/ExampleReleasePipeline.Jenkinsfile'
          def artifactPath = 's3://example-bucket/runtime/sample_dataset/record_01'
          def metadataUrl = 'jdbc:mysql://db.example.invalid:3306/example_metadata?sessionVariables=sql_mode=STRICT_TRANS_TABLES&permitMysqlScheme&useMysqlMetadata=true'

          echo "task=${restoreTask}"
          echo "script=${buildScriptPath}"
          echo "artifact=${artifactPath}"
          echo "metadata=${metadataUrl}"
        }
      }
    }

    stage('Publish') {
      steps {
        withCredentials([
          string(credentialsId: 'artifact-service-token', variable: 'SERVICE_TOKEN'),
          usernamePassword(credentialsId: 'repository-user-pass', usernameVariable: 'SERVICE_USER', passwordVariable: 'SERVICE_PASS'),
          file(credentialsId: 'deploy-secret-file', variable: 'SECRET_FILE')
        ]) {
          sh '''
            ./gradlew --info --refresh-dependencies build publishAllPublicationsToMavenRepository -x test -x check
            jfrog rt u build/output/tool-$BUILD_TAG.tgz artifact-internal/team/tool/releases/$BUILD_TAG/tool-$BUILD_TAG.tgz
            cat "$SECRET_FILE" >/dev/null
          '''
          sh 'curl -u "$SERVICE_USER:$SERVICE_PASS" https://repo.example.invalid/repository/index'
          sh "curl -H \\"Authorization: Bearer $SERVICE_TOKEN\\" https://api.example.invalid/v1/request-check"
        }
      }
    }
  }
}
