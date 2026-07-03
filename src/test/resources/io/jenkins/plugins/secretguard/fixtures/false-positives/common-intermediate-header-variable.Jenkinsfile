def authHeaders = [
    [
        name: "Authorization",
        value: "Bearer ${params.SERVICE_API_TOKEN ?: ''}",
        maskValue: true
    ]
]

httpRequest(
    url: "https://api.example.invalid/v1/request-check",
    customHeaders: authHeaders + [[
                       name: "X-Request-ID",
                       value: "0af7651916cd43dd8448eb211c80319c",
                       maskValue: false
                   ]],
    quiet: true
)