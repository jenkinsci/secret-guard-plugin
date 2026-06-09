pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
        success {
            junit '**/target/surefire-reports/*.xml'
        }
        failure {
            mail to: 'team@example.com',
                 subject: "Pipeline failed: ${env.JOB_NAME}",
                 body: "Something went wrong."
        }
        unstable {
            echo 'Build is unstable'
        }
    }
}