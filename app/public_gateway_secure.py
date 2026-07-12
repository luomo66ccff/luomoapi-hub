import base64
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import socket
import time
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response


router = APIRouter()


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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_path() -> str:
    return os.getenv("DATABASE_PATH", "/app/data/luomoapi.db")


def connect() -> sqlite3.Connection:
    db_path = get_db_path()
    if not Path(db_path).exists():
        raise RuntimeError(f"Database not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def redact_text(value: Any, limit: int = 1000) -> str:
    if value is None:
        return ""

    text = str(value)
    lowered = text.lower()

    if any(word in lowered for word in SENSITIVE_WORDS):
        return "********"

    if len(text) > limit:
        return text[:limit] + "...[truncated]"

    return text


def redact_json_like(value: Any, limit: int = 1000) -> str:
    try:
        if isinstance(value, (dict, list)):
            def scrub(obj):
                if isinstance(obj, dict):
                    out = {}
                    for k, v in obj.items():
                        if any(word in str(k).lower() for word in SENSITIVE_WORDS):
                            out[k] = "********"
                        else:
                            out[k] = scrub(v)
                    return out
                if isinstance(obj, list):
                    return [scrub(x) for x in obj[:20]]
                if isinstance(obj, str):
                    return redact_text(obj, limit=300)
                return obj

            text = json.dumps(scrub(value), ensure_ascii=False)
        else:
            text = str(value)

        if len(text) > limit:
            return text[:limit] + "...[truncated]"
        return text
    except Exception:
        return "[unserializable]"


def json_error(status_code: int, error: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": error,
            "message": message,
        },
    )


def extract_api_key(request: Request) -> str | None:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    x_api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if x_api_key:
        return x_api_key.strip()

    return None


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

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            raw_key.encode("utf-8"),
            salt,
            int(iterations),
        )

        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def verify_api_key(conn: sqlite3.Connection, raw_key: str) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
    rows = conn.execute(
        """
        SELECT
            k.*,
            u.username,
            u.role,
            u.status AS user_status
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        WHERE k.status = 'active'
        """
    ).fetchall()

    for row in rows:
        stored_hash = row["key_hash"]

        ok = False

        if stored_hash and stored_hash.startswith("pbkdf2_sha256"):
            ok = verify_pbkdf2(raw_key, stored_hash)

        # Optional compatibility with plain sha256 legacy hashes.
        elif stored_hash:
            sha256_hex = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
            ok = secrets.compare_digest(sha256_hex, stored_hash)

        if ok:
            user = conn.execute(
                "SELECT * FROM users WHERE id=?",
                (row["user_id"],),
            ).fetchone()
            return row, user

    return None, None


def has_scope(key_row: sqlite3.Row, required_scope: str | None) -> bool:
    if not required_scope:
        return True

    scopes_raw = key_row["scopes"] or ""
    scopes = {
        s.strip()
        for part in scopes_raw.replace(",", " ").split()
        for s in [part.strip()]
        if s.strip()
    }

    return required_scope in scopes or "*" in scopes


def check_quota(conn: sqlite3.Connection, key_row: sqlite3.Row) -> JSONResponse | None:
    key_id = key_row["id"]

    now = datetime.now(timezone.utc)
    one_minute_ago = (now - timedelta(seconds=60)).isoformat()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    per_minute = int(key_row["rate_limit_per_minute"] or 60)
    daily_quota = int(key_row["daily_quota"] or 1000)

    recent_count = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM api_usage_logs
        WHERE api_key_id=? AND created_at>=?
        """,
        (key_id, one_minute_ago),
    ).fetchone()["c"]

    if recent_count >= per_minute:
        return json_error(
            429,
            "rate_limited",
            "API key rate limit exceeded.",
        )

    daily_count = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM api_usage_logs
        WHERE api_key_id=? AND created_at>=?
        """,
        (key_id, today_start),
    ).fetchone()["c"]

    if daily_count >= daily_quota:
        return json_error(
            429,
            "quota_exceeded",
            "API key daily quota exceeded.",
        )

    return None


def hash_ip(ip: str | None) -> str:
    if not ip:
        return ""
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:24]


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
):
    try:
        conn.execute(
            """
            INSERT INTO api_usage_logs (
                created_at,
                user_id,
                api_key_id,
                route_id,
                method,
                public_path,
                target_url_masked,
                status_code,
                response_time_ms,
                success,
                client_ip_hash,
                user_agent_preview,
                error_summary,
                request_preview,
                response_preview
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                user_id,
                api_key_id,
                route_id,
                method,
                public_path,
                target_url_masked,
                status_code,
                response_time_ms,
                1 if success else 0,
                hash_ip(client_ip),
                redact_text(user_agent or "", 300),
                redact_text(error_summary or "", 500),
                redact_text(request_preview or "", 1000),
                redact_text(response_preview or "", 1000),
            ),
        )
        conn.commit()
    except Exception:
        # Logging must never break gateway calls.
        pass


def get_route(conn: sqlite3.Connection, route_path: str) -> sqlite3.Row | None:
    normalized = route_path.strip("/")

    return conn.execute(
        """
        SELECT
            r.*,
            a.base_url,
            a.auth_type,
            a.secret_ref
        FROM public_gateway_routes r
        JOIN apis a ON a.id = r.target_api_id
        WHERE TRIM(r.public_path, '/') = ?
        LIMIT 1
        """,
        (normalized,),
    ).fetchone()


def build_target_url(base_url: str, target_path: str) -> str:
    return base_url.rstrip("/") + "/" + target_path.lstrip("/")


def _validate_public_ip(value: str) -> None:
    address = ip_address(value)
    if not address.is_global:
        raise ValueError("Upstream resolves to a non-public IP address.")


async def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS upstream targets are allowed.")
    if parsed.username or parsed.password:
        raise ValueError("Upstream URL credentials are not allowed.")
    host = parsed.hostname
    if not host:
        raise ValueError("Upstream URL host is missing.")
    try:
        ip = ip_address(host)
        _validate_public_ip(str(ip))
    except ValueError as exc:
        if "non-public IP" in str(exc):
            raise

    try:
        answers = await asyncio.to_thread(
            socket.getaddrinfo,
            host,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError("Upstream host could not be resolved.") from exc

    if not answers:
        raise ValueError("Upstream host did not resolve to an address.")
    for answer in answers:
        _validate_public_ip(answer[4][0])


def get_upstream_secret(secret_ref: str | None) -> str | None:
    if not secret_ref:
        return None
    return os.getenv(secret_ref)


def make_upstream_headers(route: sqlite3.Row) -> dict[str, str]:
    headers = {
        "user-agent": "LuomoAPI-Hub-Gateway/1.0",
    }

    auth_type = (route["auth_type"] or "none").lower()
    secret_ref = route["secret_ref"]
    secret = get_upstream_secret(secret_ref)

    if auth_type == "bearer" and secret:
        headers["authorization"] = f"Bearer {secret}"
        if secret_ref in {"ASTRBOT_API_KEY", "ASTRBOT_BRIDGE_TOKEN"}:
            headers["x-bridge-token"] = secret

    return headers


@router.api_route(
    "/api/public/v1/{route_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def public_gateway(route_path: str, request: Request):
    started = time.monotonic()
    conn = None

    try:
        conn = connect()
        route = get_route(conn, route_path)

        if not route:
            return json_error(
                404,
                "not_found",
                "Public route not found.",
            )

        if not int(route["enabled"] or 0):
            return json_error(
                404,
                "route_disabled",
                "This route is documented but not currently enabled.",
            )

        expected_method = (route["target_method"] or "GET").upper()
        if request.method.upper() != expected_method:
            return json_error(
                405,
                "method_not_allowed",
                f"This route only allows {expected_method}.",
            )

        raw_key = extract_api_key(request)

        key_row = None
        user_row = None

        if not int(route["allow_anonymous"] or 0):
            if not raw_key:
                return json_error(
                    401,
                    "unauthorized",
                    "Invalid or missing API key.",
                )

            key_row, user_row = verify_api_key(conn, raw_key)
            if not key_row or not user_row:
                return json_error(
                    401,
                    "unauthorized",
                    "Invalid or missing API key.",
                )

            if user_row["status"] != "active":
                return json_error(
                    403,
                    "forbidden",
                    "User is not active.",
                )

            if key_row["status"] != "active":
                return json_error(
                    403,
                    "forbidden",
                    "API key is not active.",
                )

            if not has_scope(key_row, route["required_scope"]):
                return json_error(
                    403,
                    "forbidden",
                    "API key does not have the required scope.",
                )

            quota_error = check_quota(conn, key_row)
            if quota_error:
                return quota_error

        body = await request.body()
        target_url = build_target_url(route["base_url"], route["target_path"])
        try:
            await validate_target_url(target_url)
        except ValueError as exc:
            return json_error(
                400,
                "blocked_target",
                str(exc),
            )
        upstream_headers = make_upstream_headers(route)

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            upstream = await client.request(
                method=request.method.upper(),
                url=target_url,
                headers=upstream_headers,
                params=dict(request.query_params),
                content=body if body else None,
            )

        elapsed_ms = int((time.monotonic() - started) * 1000)
        content_type = upstream.headers.get("content-type", "application/json")

        response_preview = ""
        try:
            if "application/json" in content_type:
                response_preview = redact_json_like(upstream.json(), 1000)
            else:
                response_preview = redact_text(upstream.text, 1000)
        except Exception:
            response_preview = "[binary or unreadable response]"

        if key_row:
            try:
                conn.execute(
                    "UPDATE api_keys SET last_used_at=? WHERE id=?",
                    (now_iso(), key_row["id"]),
                )
                conn.commit()
            except Exception:
                pass

        log_usage(
            conn,
            user_id=key_row["user_id"] if key_row else None,
            api_key_id=key_row["id"] if key_row else None,
            route_id=route["id"],
            method=request.method.upper(),
            public_path=route_path,
            target_url_masked=target_url,
            status_code=upstream.status_code,
            response_time_ms=elapsed_ms,
            success=200 <= upstream.status_code < 400,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            error_summary=None if upstream.status_code < 400 else f"upstream status {upstream.status_code}",
            request_preview=redact_text(body.decode("utf-8", errors="ignore"), 1000) if body else "",
            response_preview=response_preview,
        )

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=content_type.split(";")[0],
        )

    except httpx.RequestError as e:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if conn:
            log_usage(
                conn,
                user_id=None,
                api_key_id=None,
                route_id=None,
                method=request.method.upper(),
                public_path=route_path,
                target_url_masked=None,
                status_code=502,
                response_time_ms=elapsed_ms,
                success=False,
                client_ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                error_summary=redact_text(str(e), 300),
                request_preview="",
                response_preview="",
            )

        return json_error(
            502,
            "upstream_error",
            "Upstream API request failed.",
        )

    except Exception as e:
        return json_error(
            500,
            "gateway_error",
            "Gateway failed to process the request.",
        )

    finally:
        if conn:
            conn.close()
