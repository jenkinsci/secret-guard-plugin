httpRequest(
  url: "https://chat.example.invalid/cgi-bin/webhook/send",
  customHeaders: sanitizeHeaders(
    "release",
    [source: "jenkins", channel: "alerts"],
    [
      [
        name: "Authorization",
        value: "Bearer hardcodedHeaderValue0123456789ABCDEF",
        maskValue: false
      ],
      [
        name: "x-safe-token",
        value: env.get("SAFE_RUNTIME_TOKEN"),
        maskValue: true
      ]
    ] as List<Map<String, Object>>
  ),
  quiet: true
)
