def response = httpRequest(
  httpMode: "POST",
  validResponseCodes: "100:599",
  contentType: "APPLICATION_JSON",
  acceptType: "APPLICATION_JSON",
  timeout: 60,
  consoleLogResponseBody: false,
  quiet: true,
  wrapAsMultipart: false,
  ignoreSslErrors: false,
  responseHandle: "STRING",
  multipartName: "payload",
  outputFile: "build/secret-guard-response.json",
  proxyAuthentication: "proxy-readonly",
  authentication: "service-http-credential",
  requestBody: groovy.json.JsonOutput.toJson([
    jobName: env.JOB_NAME,
    buildNumber: env.BUILD_NUMBER,
    branchName: env.BRANCH_NAME
  ]),
  customHeaders: [
    [
      name: "X-Correlation-ID",
      value: "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l",
      maskValue: false
    ],
    [
      name: "Authorization",
      value: "Bearer ${params.SERVICE_API_TOKEN ?: ''}",
      maskValue: true
    ],
    [
      name: "x-runtime-token",
      value: helper([
        token: env?.SERVICE_API_TOKEN?.trim(),
        meta: [source: "jenkins", branch: env.BRANCH_NAME]
      ]),
      maskValue: true
    ]
  ],
  url: "https://api.example.invalid/v1/request-check"
)
