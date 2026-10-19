"""Security helpers and the general public API proxy.

The private CodexProxy routes share the key, model, quota, and logging helpers
from this module.  This module keeps the older public route contract intact
while making its database lifetime explicit: all SQLite work finishes before
the upstream request starts.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from starlette.concurrency import run_in_threadpool

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.ai_usage import (
    QuotaRejection,
    UsageReservation,
    complete_usage,
    get_key_models,
    insert_usage,
    model_allowed,
    quota_rejection,
    reserve_usage,
)
from app.upstream_security import PinnedTarget, resolve_and_pin_target
from app.http_clients import public_upstream_client


router = APIRouter()
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_BYTES = 100 * 1024 * 1024


class ResponseTooLarge(Exception):
    pass

SENSITIVE_WORDS = [
    "token",
    "password",
    "secret",
    "key",
    "cookie",
    "authorization",
    "credential",
    "api_key",
    "access_token",
    "refresh_token",
    "bearer",
]

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

# Only headers needed for an OpenAI-compatible request are forwarded.  In
# particular this intentionally excludes Cookie, all X-Forwarded variants,
# Host, and client supplied credentials.
REQUEST_HEADER_ALLOWLIST = {
    "accept",
    "accept-encoding",
    "cache-control",
    "content-type",
    "user-agent",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_path() -> str:
    return os.getenv("DATABASE_PATH", "/app/data/luomoapi.db")


def connect() -> sqlite3.Connection:
    db_path = get_db_path()
    if not Path(db_path).exists():
        raise RuntimeError(f"Database not found: {db_path}")
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _row_value(row: Any, name: str, default: Any = None) -> Any:
    if row is None:
        return default
    try:
        return row[name]
    except (KeyError, IndexError, TypeError):
        return default


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def key_expired(key_row: Any, at: datetime | None = None) -> bool:
    raw_expires_at = _row_value(key_row, "expires_at")
    expires_at = _parse_datetime(raw_expires_at)
    if raw_expires_at and expires_at is None:
        return True
    return expires_at is not None and expires_at <= (at or datetime.now(timezone.utc))


def redact_text(value: Any, limit: int = 1000) -> str:
    if value is None:
        return ""
    text = str(value)
    if any(word in text.lower() for word in SENSITIVE_WORDS):
        return "********"
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def redact_json_like(value: Any, limit: int = 1000) -> str:
    try:
        if isinstance(value, (dict, list)):
            def scrub(obj: Any) -> Any:
                if isinstance(obj, dict):
                    out: dict[Any, Any] = {}
                    for key, child in obj.items():
                        if any(word in str(key).lower() for word in SENSITIVE_WORDS):
                            out[key] = "********"
                        else:
                            out[key] = scrub(child)
                    return out
                if isinstance(obj, list):
                    return [scrub(item) for item in obj[:20]]
                if isinstance(obj, str):
                    return redact_text(obj, limit=300)
                return obj

            text = json.dumps(scrub(value), ensure_ascii=False)
        else:
            text = str(value)
        return text if len(text) <= limit else text[:limit] + "...[truncated]"
    except Exception:
        return "[unserializable]"


def request_id_for(request: Request) -> str:
    value = request.headers.get("x-request-id", "").strip()
    # Keep a caller supplied ID useful for tracing but prevent header injection
    # and unbounded log values.
    if value and len(value) <= 128 and all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value):
        return value
    return secrets.token_hex(16)


def json_error(
    status_code: int,
    error: str,
    message: str,
    *,
    request_id: str | None = None,
) -> JSONResponse:
    headers = {"X-Request-ID": request_id} if request_id else None
    return JSONResponse(status_code=status_code, content={"error": error, "message": message}, headers=headers)


def extract_api_key(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    x_api_key = (request.headers.get("x-api-key") or "").strip()
    if bearer and x_api_key and not secrets.compare_digest(bearer, x_api_key):
        return None
    return bearer or x_api_key or None


def verify_pbkdf2(raw_key: str, stored_hash: str) -> bool:
    try:
        separator = "$" if "$" in stored_hash else ":"
        algo, iterations, salt_b64, hash_b64 = stored_hash.split(separator, 3)
        if algo != "pbkdf2_sha256":
            return False
        if separator == "$":
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
            expected = base64.urlsafe_b64decode(hash_b64.encode("ascii"))
        else:
            salt = salt_b64.encode("utf-8")
            expected = base64.b64decode(hash_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", raw_key.encode("utf-8"), salt, int(iterations))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def _key_prefix(raw_key: str) -> str:
    # keyring.generate_api_key stores raw_key[:14] + "...".
    return raw_key[:14] + "..."


def verify_api_key(conn: sqlite3.Connection, raw_key: str) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    """Verify a key using the indexed prefix before doing PBKDF2 work."""

    if not raw_key:
        return None, None
    prefix = _key_prefix(raw_key)
    rows = conn.execute(
        """
        SELECT k.*, u.username, u.role, u.status AS user_status
        FROM api_keys k JOIN users u ON u.id=k.user_id
        WHERE k.status='active' AND k.key_prefix=?
        """,
        (prefix,),
    ).fetchall()
    # Imported legacy keys can have no usable prefix.  This fallback is only
    # reached when the indexed lookup found nothing and keeps old deployments
    # compatible without making normal requests scan every PBKDF2 hash.
    if not rows:
        rows = conn.execute(
            """
            SELECT k.*, u.username, u.role, u.status AS user_status
            FROM api_keys k JOIN users u ON u.id=k.user_id
            WHERE k.status='active' AND (k.key_prefix IS NULL OR k.key_prefix='')
            """
        ).fetchall()

    for row in rows:
        stored_hash = row["key_hash"]
        if not stored_hash:
            continue
        if stored_hash.startswith("pbkdf2_sha256"):
            ok = verify_pbkdf2(raw_key, stored_hash)
        else:
            ok = secrets.compare_digest(hashlib.sha256(raw_key.encode("utf-8")).hexdigest(), stored_hash)
        if ok:
            user = conn.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
            return row, user
    return None, None


def _parse_scopes(raw: Any) -> set[str]:
    return {part.strip() for part in str(raw or "").replace(",", " ").split() if part.strip()}


def has_scope(key_row: Any, required_scope: str | None) -> bool:
    if not required_scope:
        return True
    scopes = _parse_scopes(_row_value(key_row, "scopes"))
    return required_scope in scopes or "*" in scopes


def has_exact_scope(key_row: Any, required_scope: str) -> bool:
    """Check a new private endpoint scope without wildcard expansion."""

    return required_scope in _parse_scopes(_row_value(key_row, "scopes"))


def _quota_error(rejection: QuotaRejection, request_id: str | None = None) -> JSONResponse:
    return json_error(rejection.status_code, rejection.code, rejection.message, request_id=request_id)


def check_quota(conn: sqlite3.Connection, key_row: Any, *, request_id: str | None = None) -> JSONResponse | None:
    rejection = quota_rejection(conn, key_row)
    return _quota_error(rejection, request_id) if rejection else None


def hash_ip(ip: str | None) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:24] if ip else ""


def mask_url(url: str | None) -> str:
    """Remove query, fragment, credentials, and control characters from logs."""

    if not url:
        return ""
    try:
        parsed = urlsplit(str(url))
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:2000]
    except (TypeError, ValueError):
        return "[invalid-url]"


def log_usage(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    api_key_id: int | None,
    route_id: int | None,
    method: str,
    public_path: str,
    target_url_masked: str | None,
    status_code: int | None,
    response_time_ms: int | None,
    success: bool,
    client_ip: str | None,
    user_agent: str | None,
    error_summary: str | None,
    request_preview: str | None,
    response_preview: str | None,
    request_id: str | None = None,
    protocol: str | None = None,
    model: str | None = None,
    streamed: bool = False,
    outcome: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    first_byte_ms: int | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    total_tokens: int | None = None,
    usage_reported: bool = False,
) -> int | None:
    """Compatibility wrapper for callers that already own a DB connection."""

    return insert_usage(
        conn,
        user_id=user_id,
        api_key_id=api_key_id,
        route_id=route_id,
        method=method,
        public_path=public_path,
        target_url_masked=mask_url(target_url_masked),
        status_code=status_code,
        response_time_ms=response_time_ms,
        success=success,
        client_ip_hash=hash_ip(client_ip),
        user_agent_preview=redact_text(user_agent or "", 300),
        error_summary=redact_text(error_summary or "", 500),
        request_id=request_id,
        protocol=protocol,
        model=model,
        streamed=streamed,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        first_byte_ms=first_byte_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        usage_reported=usage_reported,
        request_preview=redact_text(request_preview or "", 1000),
        response_preview=redact_text(response_preview or "", 1000),
    )


def get_route(conn: sqlite3.Connection, route_path: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT r.*, a.base_url, a.auth_type, a.secret_ref
        FROM public_gateway_routes r JOIN apis a ON a.id=r.target_api_id
        WHERE TRIM(r.public_path, '/')=? LIMIT 1
        """,
        (route_path.strip("/"),),
    ).fetchone()


def build_target_url(base_url: str, target_path: str) -> str:
    return base_url.rstrip("/") + "/" + target_path.lstrip("/")


def validate_target_url(url: str) -> PinnedTarget:
    return resolve_and_pin_target(url)


async def read_bounded_response(upstream: httpx.Response, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:
    content_length = upstream.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > max_bytes:
                raise ResponseTooLarge
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    async for chunk in upstream.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def get_upstream_secret(secret_ref: str | None) -> str | None:
    return os.getenv(secret_ref) if secret_ref else None


def make_upstream_headers(route: Any) -> dict[str, str]:
    headers = {"user-agent": "LuomoAPI-Hub-Gateway/1.0"}
    auth_type = str(_row_value(route, "auth_type", "none") or "none").lower()
    secret_ref = _row_value(route, "secret_ref")
    secret = get_upstream_secret(secret_ref)
    if auth_type == "bearer" and secret:
        headers["authorization"] = f"Bearer {secret}"
        if secret_ref in {"ASTRBOT_API_KEY", "ASTRBOT_BRIDGE_TOKEN"}:
            headers["x-bridge-token"] = secret
    return headers


def allowed_request_headers(request: Request, upstream_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        name.lower(): value
        for name, value in request.headers.items()
        if name.lower() in REQUEST_HEADER_ALLOWLIST
    }
    if upstream_headers:
        headers.update({name.lower(): value for name, value in upstream_headers.items()})
    return headers


def response_headers(upstream: httpx.Response, *, request_id: str | None = None,
                     preserve_content_encoding: bool = False) -> dict[str, str]:
    headers = {
        name: value
        for name, value in upstream.headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS | {"content-length", "set-cookie", "x-request-id"}
        and (preserve_content_encoding or name.lower() != "content-encoding")
    }
    if request_id:
        headers["X-Request-ID"] = request_id
    return headers


async def read_bounded_body(request: Request, max_bytes: int = MAX_REQUEST_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("request_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _finalize_or_insert(
    reservation: UsageReservation | None,
    *,
    key_row: Any,
    route: Any,
    request: Request,
    request_id: str,
    status_code: int | None,
    response_time_ms: int | None,
    first_byte_ms: int | None,
    success: bool,
    outcome: str,
    error_summary: str | None = None,
    response_preview: str | None = None,
) -> None:
    try:
        with connect() as conn:
            if reservation:
                complete_usage(
                    conn,
                    reservation,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    first_byte_ms=first_byte_ms,
                    success=success,
                    outcome=outcome,
                    error_summary=redact_text(error_summary or "", 500),
                    response_preview=redact_text(response_preview or "", 1000),
                )
            else:
                log_usage(
                    conn,
                    user_id=_row_value(key_row, "user_id"),
                    api_key_id=_row_value(key_row, "id"),
                    route_id=_row_value(route, "id"),
                    method=request.method,
                    public_path=str(_row_value(route, "public_path", "")),
                    target_url_masked=None,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    success=success,
                    client_ip=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    error_summary=error_summary,
                    request_preview="",
                    response_preview=response_preview,
                    request_id=request_id,
                    outcome=outcome,
                )
            if key_row is not None:
                conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now_iso(), _row_value(key_row, "id")))
                conn.commit()
    except Exception:
        # Observability must not turn a completed upstream response into a 500.
        pass


def _load_public_route(route_path: str, method: str, raw_key: str | None):
    from app.auth import api_user_eligible
    from app.credit_pricing import protected_ai_target
    with connect() as conn:
        route_row = get_route(conn, route_path)
        route = dict(route_row) if route_row else None
        if not route:
            return None, None, (404, "not_found", "Public route not found.")
        if not int(route.get("enabled") or 0):
            return None, None, (404, "route_disabled", "This route is documented but not currently enabled.")
        if protected_ai_target(str(route.get("base_url") or ""), str(route.get("target_path") or "")):
            return None, None, (403, "credit_gateway_required", "AI generation must use the credit-billed /v1 endpoints.")
        expected_method = str(route.get("target_method") or "GET").upper()
        if method.upper() != expected_method:
            return None, None, (405, "method_not_allowed", f"This route only allows {expected_method}.")
        if int(route.get("allow_anonymous") or 0):
            return route, None, None
        if not raw_key:
            return None, None, (401, "unauthorized", "Invalid or missing API key.")
        key, user = verify_api_key(conn, raw_key)
        if not key or not user:
            return None, None, (401, "unauthorized", "Invalid or missing API key.")
        key_row = dict(key)
        if not api_user_eligible(user["status"]):
            return None, None, (403, "forbidden", "User is not active.")
        if key["status"] != "active":
            return None, None, (403, "forbidden", "API key is not active.")
        if key_expired(key):
            return None, None, (403, "key_expired", "API key has expired.")
        if not has_scope(key, route.get("required_scope")):
            return None, None, (403, "forbidden", "API key does not have the required scope.")
        return route, key_row, None


def _reserve_public_usage(route: Any, key_row: Any, request_id: str, method: str,
                          route_path: str, client_ip: str | None, user_agent: str | None):
    with connect() as conn:
        return reserve_usage(
            conn,
            key_row,
            request_id=request_id,
            protocol="public",
            model=None,
            streamed=False,
            method=method,
            public_path=route_path,
            route_id=route.get("id"),
            target_url_masked=mask_url(build_target_url(str(route["base_url"]), str(route["target_path"]))),
            client_ip_hash=hash_ip(client_ip),
            user_agent_preview=redact_text(user_agent or "", 300),
        )


@router.api_route(
    "/api/public/v1/{route_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def public_gateway(route_path: str, request: Request):
    request_id = request_id_for(request)
    started = time.monotonic()
    reservation: UsageReservation | None = None
    key_row: Any = None
    route: Any = None

    try:
        route, key_row, load_error = await run_in_threadpool(
            _load_public_route, route_path, request.method, extract_api_key(request)
        )
        if load_error:
            status_code, error, message = load_error
            return json_error(status_code, error, message, request_id=request_id)

        try:
            body = await read_bounded_body(request)
        except ValueError as exc:
            if str(exc) == "request_too_large":
                return json_error(413, "request_too_large", "Request body is too large.", request_id=request_id)
            raise

        target_url = build_target_url(str(route["base_url"]), str(route["target_path"]))
        try:
            pinned = await asyncio.wait_for(asyncio.to_thread(validate_target_url, target_url), timeout=5.0)
        except asyncio.TimeoutError:
            return json_error(503, "upstream_dns_timeout", "Upstream hostname resolution timed out.", request_id=request_id)
        except ValueError as exc:
            return json_error(400, "blocked_target", str(exc), request_id=request_id)

        if key_row is not None:
            reservation, rejection = await run_in_threadpool(
                _reserve_public_usage,
                route,
                key_row,
                request_id,
                request.method,
                route_path,
                request.client.host if request.client else None,
                request.headers.get("user-agent"),
            )
            if rejection:
                return _quota_error(rejection, request_id)

        upstream_headers = allowed_request_headers(request, make_upstream_headers(route))
        try:
            original_host = urlsplit(target_url).hostname or ""
            async with public_upstream_client(request.app, original_host) as client:
                upstream_request = client.build_request(
                    method=request.method.upper(),
                    url=pinned.url,
                    headers=upstream_headers,
                    params=dict(request.query_params),
                    content=body or None,
                )
                if pinned.host_header:
                    upstream_request.headers["host"] = pinned.host_header
                if pinned.sni_hostname:
                    upstream_request.extensions["sni_hostname"] = pinned.sni_hostname
                upstream = await client.send(upstream_request, stream=True)
                try:
                    response_body = await read_bounded_response(upstream)
                finally:
                    await upstream.aclose()
                status_code = upstream.status_code
                headers = response_headers(upstream, request_id=request_id)
        except ResponseTooLarge:
            elapsed = int((time.monotonic() - started) * 1000)
            await run_in_threadpool(
                _finalize_or_insert,
                reservation,
                key_row=key_row,
                route=route,
                request=request,
                request_id=request_id,
                status_code=502,
                response_time_ms=elapsed,
                first_byte_ms=elapsed,
                success=False,
                outcome="response_too_large",
                error_summary=f"upstream response exceeded {MAX_RESPONSE_BYTES} bytes",
            )
            return json_error(502, "response_too_large", "Upstream response exceeded the configured size limit.", request_id=request_id)
        except httpx.RequestError as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            await run_in_threadpool(
                _finalize_or_insert,
                reservation,
                key_row=key_row,
                route=route,
                request=request,
                request_id=request_id,
                status_code=502,
                response_time_ms=elapsed,
                first_byte_ms=None,
                success=False,
                outcome="upstream_error",
                error_summary=type(exc).__name__,
            )
            return json_error(502, "upstream_error", "Upstream API request failed.", request_id=request_id)

        elapsed = int((time.monotonic() - started) * 1000)
        success = 200 <= status_code < 400
        await run_in_threadpool(
            _finalize_or_insert,
            reservation,
            key_row=key_row,
            route=route,
            request=request,
            request_id=request_id,
            status_code=status_code,
            response_time_ms=elapsed,
            first_byte_ms=elapsed,
            success=success,
            outcome="succeeded" if success else "failed",
            error_summary=None if success else f"upstream status {status_code}",
            response_preview="[response body not retained]",
        )
        headers["X-Request-ID"] = request_id
        return Response(content=response_body, status_code=status_code, headers=headers)
    except Exception:
        elapsed = int((time.monotonic() - started) * 1000)
        if reservation:
            await run_in_threadpool(
                _finalize_or_insert,
                reservation,
                key_row=key_row,
                route=route or {},
                request=request,
                request_id=request_id,
                status_code=500,
                response_time_ms=elapsed,
                first_byte_ms=None,
                success=False,
                outcome="gateway_error",
                error_summary="Gateway failed to process the request.",
            )
        return json_error(500, "gateway_error", "Gateway failed to process the request.", request_id=request_id)


__all__ = [
    "MAX_REQUEST_BYTES",
    "allowed_request_headers",
    "build_target_url",
    "check_quota",
    "connect",
    "extract_api_key",
    "get_key_models",
    "has_exact_scope",
    "has_scope",
    "json_error",
    "key_expired",
    "log_usage",
    "mask_url",
    "model_allowed",
    "now_iso",
    "request_id_for",
    "reserve_usage",
    "response_headers",
    "verify_api_key",
]
