@Library('my-shared-library@1.0') _

pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    def result = myLibrary.someMethod()
                    echo "Result: ${result}"
                }
            }
        }
    }
}