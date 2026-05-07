httpRequest(
  url: "https://api.example.invalid/v2/release/status",
  customHeaders: sanitizeHeaders("runtime", [
    [
      name: "Authorization",
      value: "Bearer ${params.SERVICE_API_TOKEN ?: env.get('SERVICE_API_TOKEN') ?: ''}",
      maskValue: true
    ],
    [
      name: "x-service-basic",
      value: "${SERVICE_USER}:${SERVICE_PASS}".bytes.encodeBase64().toString(),
      maskValue: true
    ],
    [
      name: "X-Request-ID",
      value: "0af7651916cd43dd8448eb211c80319c",
      maskValue: false
    ]
  ] as List<Map<String, Object>>),
  validResponseCodes: "100:599",
  quiet: true
)
