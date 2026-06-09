pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                withCredentials([string(credentialsId: 'my-secret', variable: 'SECRET')]) {
                    sh 'echo $SECRET'
                }
            }
        }
    }
}