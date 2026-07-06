pipeline {
    agent any

    stages {
        stage('Release') {
            steps {
                script {
                    withEnv([
                        "SERVICE_TOKEN=${params.SERVICE_API_TOKEN ?: env.get('SERVICE_API_TOKEN') ?: ''}"
                    ]) {

                        def requestHeaders = [[
                            name: "Authorization",
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