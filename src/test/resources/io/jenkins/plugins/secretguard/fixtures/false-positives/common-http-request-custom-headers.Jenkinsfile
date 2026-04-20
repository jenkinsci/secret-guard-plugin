def response = httpRequest(
  url: "https://api.example.invalid/v1/request-check",
  customHeaders: (
    [
      (["name": "X-Request-ID", "value": "0af7651916cd43dd8448eb211c80319c", "maskValue": false]),
      (["name": "X-Correlation-ID", "value": "QWxhZGRpbjpPcGVuU2VzYW1lQWxhZGRpbjpPcGVuU2VzYW1l", "maskValue": false]),
      ([
        "name": "Authorization",
        "value": "Bearer ${params.SERVICE_API_TOKEN ?: ''}",
        "maskValue": true
      ]),
      ([
        name: "x-service-basic",
        value: "${SERVICE_USER}:${SERVICE_PASS}".bytes.encodeBase64().toString(),
        maskValue: true
      ]),
      ([
        name: "x-runtime-token",
        value: helper([
          token: env?.SERVICE_API_TOKEN?.trim(),
          meta: [source: 'jenkins']
        ]),
        maskValue: true
      ])
    ] as List<Map<String, Object>>
  ),
  quiet: true
)

def retryResponse = httpRequest(
  url: "https://api.example.invalid/v1/request-check",
  customHeaders: [[
    name: "x-service-token",
    value: env.get('SERVICE_API_TOKEN'),
    maskValue: true
  ], [
    name: "Authorization",
    value: 'Bearer ' + params.SERVICE_API_TOKEN,
    maskValue: true
  ]]
)
