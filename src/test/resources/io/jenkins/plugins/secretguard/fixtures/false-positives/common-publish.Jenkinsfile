pipeline {
  agent any
  stages {
    stage('Publish artifacts') {
      steps {
        withCredentials([string(credentialsId: 'artifact-service-token', variable: 'SERVICE_TOKEN')]) {
          httpRequest(
            url: "https://artifacts.example.invalid:443/repository/build-tools/bootstrap_bundle/",
            customHeaders: [
              [name: 'X-Request-ID', value: '0af7651916cd43dd8448eb211c80319c', maskValue: false],
              [name: 'X-Correlation-ID', value: 'QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l', maskValue: false],
              [name: 'Authorization', value: "Bearer ${SERVICE_TOKEN}", maskValue: true]
            ]
          )
          sh './gradlew --info --refresh-dependencies build publishAllPublicationsToMavenRepository -x test -x check -PmavenUser=$USER -PmavenPassword=$PASSWORD'
          sh 'jfrog rt u build/output/tool-$BUILD_TAG.tgz artifact-internal/team/tool/releases/$BUILD_TAG/tool-$BUILD_TAG.tgz'
          sh 'wget ftp://artifacts.example.invalid:21/repository/build-tools/bootstrap_bundle/'
        }
      }
    }
  }
}
