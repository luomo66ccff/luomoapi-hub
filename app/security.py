from fastapi import Request
from fastapi.responses import JSONResponse
from urllib.parse import urlsplit
from app.config import settings


async def security_headers(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"} and request.cookies.get("luomoapi_session") and not request.url.path.startswith(("/v1/", "/api/public/v1/")):
        source = request.headers.get("origin") or request.headers.get("referer", "")
        parsed = urlsplit(source)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        allowed = {settings.app_base_url.rstrip("/"), f"{request.url.scheme}://{request.url.netloc}"}
        if origin not in allowed or request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "页面来源校验失败，请返回本站页面重试。"}, status_code=403)
    response = await call_next(request)
    private_page = request.url.path.startswith(("/developer", "/admin", "/api/developer"))
    if private_page or (request.cookies.get("luomoapi_session") and not request.url.path.startswith("/static/")):
        response.headers["Cache-Control"] = "no-store"
    if request.url.path == "/verify-email":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Preserve a same-origin form's Origin/Referer for CSRF validation while
    # withholding referrers from links to other origins.
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    public_info = request.url.path in {"/", "/docs", "/models", "/pricing", "/status"}
    scripts = "'self' https://static.cloudflareinsights.com" if public_info else "'self'"
    connections = "'self' https://cloudflareinsights.com" if public_info else "'self'"
    response.headers["Content-Security-Policy"] = f"default-src 'self'; script-src {scripts}; style-src 'self'; img-src 'self' data:; connect-src {connections}; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    return response
