pipeline {
    agent any

    stages {
        stage('Release') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'service-token', variable: 'SERVICE_TOKEN')
                    ]) {

                        def requestHeaders = [[
                            name: 'Authorization',
                            value: "Bearer ${SERVICE_TOKEN}",
                            maskValue: true
                        ]]

                        httpRequest(
                            url: "https://api.example.invalid/v1/request-check",
                            customHeaders: requestHeaders,
                            validResponseCodes: "100:599",
                            quiet: true
                        )
                    }
                }
            }
        }
    }
}