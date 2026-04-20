def response = httpRequest(
  url: "https://api.example.invalid/v1/request-check",
  customHeaders: (
    [
      (["name": "x-safe-token", "value": env.SERVICE_API_TOKEN, "maskValue": true]),
      ([
        "name": "Authorization",
        "value": "Bearer hardcodedHeaderValue0123456789ABCDEF",
        "maskValue": false
      ])
    ] as List<Map<String, Object>>
  ),
  quiet: true
)
