"""HTML error redirect middleware with API-safe pass-through behavior."""

from __future__ import annotations

import secrets
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse


def _is_api_request(request: Request) -> bool:
    path = request.url.path
    # Health probes must always see the real status code, never an error-page redirect.
    if path in {"/health", "/ready"}:
        return True
    # Private OpenAI routes and the public API must remain machine-readable.
    if path == "/v1" or path.startswith("/v1/"):
        return True
    if path == "/api/public" or path.startswith("/api/public/"):
        return True
    if path == "/api" or path.startswith("/api/"):
        return True
    if "application/json" in request.headers.get("accept", "").lower():
        return True
    # A non-GET/HEAD action is an API-style mutation in this app.  Redirecting
    # its 403/500 into an HTML error site hides the actual JSON status from
    # clients and breaks form/API callers alike.
    return request.method.upper() not in {"GET", "HEAD"}


def _api_exception(request: Request, status_code: int = 500) -> JSONResponse:
    request_id = request.headers.get("x-request-id", "").strip()
    if not request_id or len(request_id) > 128 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in request_id):
        request_id = secrets.token_hex(16)
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": "Internal server error.", "type": "server_error", "code": "gateway_error"}},
        headers={"X-Request-ID": request_id},
    )


async def error_redirect_middleware(request: Request, call_next):
    redirect_codes = {403, 404, 500, 502, 503, 504}
    try:
        response = await call_next(request)
        if _is_api_request(request):
            return response
        if response.status_code in redirect_codes:
            source = request.headers.get("host", "-")
            path = quote(request.url.path, safe="/")
            ip = request.client.host if request.client else "-"
            ray = request.headers.get("cf-ray", "-")
            url = f"https://error.luomo.moe/{response.status_code}?status={response.status_code}&source={quote(source, safe='')}&path={path}&ip={quote(ip, safe='')}&ray={quote(ray, safe='')}"
            return RedirectResponse(url=url, status_code=302)
        return response
    except Exception:
        if _is_api_request(request):
            return _api_exception(request)
        source = quote(request.headers.get("host", "-"), safe="")
        path = quote(request.url.path, safe="/")
        ip = quote(request.client.host if request.client else "-", safe="")
        url = f"https://error.luomo.moe/500?status=500&source={source}&path={path}&ip={ip}&ray=app-exception"
        return RedirectResponse(url=url, status_code=302)
