from fastapi import Request

async def extract_payload(request: Request) -> dict:
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="replace")

    # Combine ALL injectable surfaces into one analysis string
    full_payload = " ".join([
        str(request.url.path),
        str(request.url.query),
        body,
        request.headers.get("user-agent", ""),
        request.headers.get("referer", ""),
    ])

    return {
        "method":       request.method,
        "url":          str(request.url),
        "path":         request.url.path,
        "query":        str(request.url.query),
        "body":         body,
        "client_ip":    request.client.host,
        "user_agent":   request.headers.get("user-agent", ""),
        "full_payload": full_payload,
    }