import hashlib
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.api_client import validate_url
from app.db import connect
from app.keyring import verify_api_key
from app.utils.redact import preview, redact_obj, redact_url
from app.utils.timefmt import now_iso


router = APIRouter()
RATE_CACHE: dict[int, list[float]] = {}


def json_error(error: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": error, "message": message}, status_code=status_code)


def extract_api_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.headers.get("x-api-key", "").strip()


def scopes_include(scopes: str | None, required: str | None) -> bool:
    if not required:
        return True
    values = {item.strip() for item in (scopes or "").split(",") if item.strip()}
    return required in values or "*" in values


def check_rate_limit(key_row) -> tuple[bool, str]:
    now_ts = time.time()
    key_id = key_row["id"]
    window = [ts for ts in RATE_CACHE.get(key_id, []) if now_ts - ts < 60]
    if len(window) >= int(key_row["rate_limit_per_minute"] or 60):
        RATE_CACHE[key_id] = window
        return False, "API key rate limit exceeded."
    RATE_CACHE[key_id] = [*window, now_ts]
    day = datetime.now(timezone.utc).date().isoformat()
    with connect() as conn:
        used_today = conn.execute(
            "SELECT COUNT(*) AS c FROM api_usage_logs WHERE api_key_id = ? AND created_at LIKE ?",
            (key_id, f"{day}%"),
        ).fetchone()["c"]
    if used_today >= int(key_row["daily_quota"] or 1000):
        return False, "API key daily quota exceeded."
    return True, ""


def lookup_key(raw_key: str, route):
    if not raw_key:
        return None, None
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT api_keys.*, users.status AS user_status, users.role AS user_role, users.id AS owner_id
            FROM api_keys JOIN users ON users.id = api_keys.user_id
            WHERE api_keys.status = 'active'
            """
        ).fetchall()
    for row in rows:
        if verify_api_key(raw_key, row["key_hash"]):
            if row["user_status"] != "active":
                return None, "API key owner is not active."
            if row["expires_at"] and row["expires_at"] < now_iso():
                return None, "API key expired."
            if not scopes_include(row["scopes"], route["required_scope"]):
                return None, "API key scope is not allowed for this route."
            ok, message = check_rate_limit(row)
            if not ok:
                return None, message
            return row, None
    return None, "Invalid or missing API key."


def log_usage(route, key_row, method: str, target_url: str, status_code: int | None, elapsed_ms: int | None,
              success: bool, request: Request, error: str | None, request_preview: str, response_preview: str) -> None:
    client = request.client.host if request.client else ""
    ip_hash = hashlib.sha256(client.encode("utf-8")).hexdigest() if client else ""
    user_agent = (request.headers.get("user-agent") or "")[:240]
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO api_usage_logs(created_at, user_id, api_key_id, route_id, method, public_path,
            target_url_masked, status_code, response_time_ms, success, client_ip_hash, user_agent_preview,
            error_summary, request_preview, response_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                key_row["owner_id"] if key_row else None,
                key_row["id"] if key_row else None,
                route["id"] if route else None,
                method,
                route["public_path"] if route else "",
                redact_url(target_url) if target_url else "",
                status_code,
                elapsed_ms,
                1 if success else 0,
                ip_hash,
                preview(user_agent, 240),
                preview(error, 500) if error else None,
                request_preview,
                response_preview,
            ),
        )
        if key_row:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now_iso(), key_row["id"]))
        conn.commit()


@router.api_route("/api/public/v1/{route_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def public_gateway(route_path: str, request: Request):
    with connect() as conn:
        route = conn.execute(
            """
            SELECT public_gateway_routes.*, apis.base_url, apis.auth_type, apis.secret_ref
            FROM public_gateway_routes JOIN apis ON apis.id = public_gateway_routes.target_api_id
            WHERE public_gateway_routes.public_path = ?
            """,
            (route_path.strip("/"),),
        ).fetchone()
    if not route or not route["enabled"]:
        return json_error("not_found", "Public API route not found.", 404)
    key_row = None
    auth_error = None
    if not route["allow_anonymous"]:
        key_row, auth_error = lookup_key(extract_api_key(request), route)
        if auth_error:
            log_usage(route, None, request.method, "", None, None, False, request, auth_error, "", "")
            status_code = 429 if "limit" in auth_error.lower() or "quota" in auth_error.lower() else 401
            error = "rate_limited" if status_code == 429 else "unauthorized"
            return json_error(error, auth_error, status_code)
    if request.method != route["target_method"]:
        return json_error("method_not_allowed", "This route does not allow the requested method.", 405)

    target_url = urljoin(route["base_url"].rstrip("/") + "/", route["target_path"].lstrip("/"))
    try:
        validate_url(target_url)
    except Exception as exc:
        return json_error("blocked_target", str(exc), 400)

    headers = {}
    if route["auth_type"] == "bearer" and route["secret_ref"]:
        secret = os.getenv(route["secret_ref"]) or ""
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
    body = await request.body()
    if len(body) > 1024 * 1024:
        return json_error("request_too_large", "Request body is too large.", 413)
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.request(request.method, target_url, headers=headers, content=body or None, params=dict(request.query_params))
        elapsed = int((time.perf_counter() - start) * 1000)
        try:
            payload = redact_obj(response.json())
            content = payload
        except ValueError:
            content = {"text": preview(response.text)}
        response_preview = preview(content)
        log_usage(route, key_row, request.method, str(response.url), response.status_code, elapsed, response.status_code < 400,
                  request, None if response.status_code < 400 else f"HTTP {response.status_code}", preview({"query": dict(request.query_params)}), response_preview)
        return JSONResponse(content, status_code=response.status_code)
    except Exception as exc:
        elapsed = int((time.perf_counter() - start) * 1000)
        error = str(exc)
        log_usage(route, key_row, request.method, target_url, None, elapsed, False, request, error, "", "")
        return json_error("upstream_error", "Upstream request failed.", 502)
