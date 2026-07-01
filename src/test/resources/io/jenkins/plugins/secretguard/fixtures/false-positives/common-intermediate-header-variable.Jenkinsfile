def authHeaders = [
    [
        name: "Authorization",
        value: "Bearer ${params.SERVICE_API_TOKEN ?: ''}",
        maskValue: true
    ]
]

def requestHeaders = authHeaders + [[
    name: "X-Request-ID",
    value: "0af7651916cd43dd8448eb211c80319c",
    maskValue: false
]]

httpRequest(
    url: "https://api.example.invalid/v1/request-check",
    customHeaders: requestHeaders,
    quiet: true
)