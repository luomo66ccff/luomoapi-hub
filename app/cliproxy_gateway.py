"""Private OpenAI-compatible CodexProxy gateway.

Only the three text endpoints are exposed.  Authentication and quota
reservation happen in short SQLite transactions; upstream network I/O always
runs after those connections have been closed.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
import logging
from contextlib import closing
from collections.abc import AsyncIterator
from typing import Any

import httpx
import anyio
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from app.auth import api_user_eligible
from app.admin_key_policy import AdminKeyPolicyError, admin_unmetered
from app.credit_pricing import PricingError, billing_details, billing_receipt_present, prepare_billable_request
from app.credit_ledger import mark_credit_dispatched

from app.ai_usage import (
    SSEUsageParser,
    UsageReservation,
    complete_usage,
    extract_json_usage,
    get_key_models,
    model_allowed,
    reserve_usage,
)
from app.public_gateway_secure import (
    MAX_RESPONSE_BYTES,
    MAX_REQUEST_BYTES,
    ResponseTooLarge,
    allowed_request_headers,
    connect,
    extract_api_key,
    has_exact_scope,
    key_expired,
    mask_url,
    now_iso,
    request_id_for,
    response_headers,
    read_bounded_response,
    verify_api_key,
)


router = APIRouter()

REQUIRED_SCOPE = "codexproxy:use"
REQUIRED_ROUTE = "codexproxy/*"
NEW_SCOPES = {
    "/v1/models": "models:read",
    "/v1/chat/completions": "chat:completions",
    "/v1/responses": "responses:create",
}
ENDPOINT_PROTOCOLS = {
    "/v1/models": "models",
    "/v1/chat/completions": "chat.completions",
    "/v1/responses": "responses",
}
ENDPOINT_METHODS = {
    "/v1/models": "GET",
    "/v1/chat/completions": "POST",
    "/v1/responses": "POST",
}
ALLOWED_GATEWAY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
STREAM_USAGE_GRACE_SECONDS = 5.0
STREAM_USAGE_GRACE_BYTES = 1024 * 1024


class MeteredStreamingResponse(StreamingResponse):
    """Own the iterator even when sending to a disconnected client fails."""

    def __init__(self, content, *args, on_unstarted_disconnect=None, **kwargs):
        super().__init__(content, *args, **kwargs)
        self.on_unstarted_disconnect = on_unstarted_disconnect

    async def stream_response(self, send) -> None:
        headers_sent = False
        async def tracked_send(message):
            nonlocal headers_sent
            await send(message)
            if message["type"] == "http.response.start":
                headers_sent = True
        try:
            await super().stream_response(tracked_send)
        finally:
            closer = getattr(self.body_iterator, "aclose", None)
            if closer is not None:
                with anyio.CancelScope(shield=True):
                    await closer()
            if not headers_sent and self.on_unstarted_disconnect is not None:
                with anyio.CancelScope(shield=True):
                    await self.on_unstarted_disconnect()


def _explicit_generation_rejection(payload: Any, status_code: int, protocol: str) -> bool:
    """Only specific, structured pre-generation errors can release a hold."""
    allowed = {400: {"context_length_exceeded"}, 401: {"invalid_api_key"},
               403: {"model_access_denied"}, 404: {"model_not_found"}}
    if not isinstance(payload, dict) or billing_receipt_present(payload, protocol=protocol):
        return False
    if any(payload.get(key) for key in ("choices", "output", "response", "content")):
        return False
    error = payload.get("error")
    return (isinstance(error, dict) and isinstance(error.get("code"), str)
            and error["code"] in allowed.get(status_code, set()))


def _request_id(request: Request) -> str:
    return request_id_for(request)


def json_error(
    status_code: int,
    error: str,
    message: str,
    *,
    request_id: str | None = None,
    param: str | None = None,
    code: str | None = None,
) -> JSONResponse:
    """Return an OpenAI-shaped error with a stable trace header."""

    request_id = request_id or secrets.token_hex(16)
    payload: dict[str, Any] = {"message": message, "type": error}
    if param is not None:
        payload["param"] = param
    if code is not None:
        payload["code"] = code
    return JSONResponse(
        status_code=status_code,
        content={"error": payload},
        headers={"X-Request-ID": request_id},
    )


def route_is_authorized(key_row: Any) -> bool:
    """Legacy private grant: both exact scope and exact route are required."""

    scopes = {
        part.strip()
        for part in str(key_row["scopes"] or "").replace(",", " ").split()
        if part.strip()
    }
    routes = {
        part.strip()
        for part in str(key_row["allowed_routes"] or "").replace(",", " ").split()
        if part.strip()
    }
    return REQUIRED_SCOPE in scopes and REQUIRED_ROUTE in routes


def endpoint_is_authorized(key_row: Any, path: str) -> bool:
    # Wildcard scopes intentionally do not grant this private API.  New keys
    # receive one precise scope per endpoint and need no legacy route entry.
    return route_is_authorized(key_row) or has_exact_scope(key_row, NEW_SCOPES[path])


def _load_authorization(raw_key: str, endpoint: str) -> tuple[dict[str, Any] | None, set[str] | None, tuple[int, str, str | None] | None]:
    """Synchronous DB/PBKDF2 portion run off the async event loop."""

    with closing(connect()) as conn:
        key, user = verify_api_key(conn, raw_key)
        if not key or not user:
            return None, None, (401, "Invalid or missing API key.", None)
        # PBKDF2 can be slow: re-read key and owner state together afterwards.
        key = conn.execute("""SELECT k.*, u.role AS user_role, u.status AS user_status
                              FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.id=?""", (key["id"],)).fetchone()
        if not key or not api_user_eligible(key["user_status"]) or key["status"] != "active":
            return None, None, (403, "User or API key is not active.", None)
        try:
            exempt = admin_unmetered(key, owner_role=key["user_role"], owner_status=key["user_status"])
        except AdminKeyPolicyError as exc:
            return None, None, (403, str(exc), None)
        if key_expired(key):
            return None, None, (403, "API key has expired.", "key_expired")
        if not endpoint_is_authorized(key, endpoint):
            return None, None, (403, "API key is not authorized for this endpoint.", None)
        allowed_ids = None
        if endpoint == "/v1/models" and str(key["model_policy"] or "all").strip().lower() != "all":
            allowed_ids = set(get_key_models(conn, key["id"]))
        return {**dict(key), "admin_unmetered": exempt}, allowed_ids, None


def _revalidate_model(key_id: int, endpoint: str, model: str) -> tuple[dict[str, Any] | None, tuple[int, str, str | None] | None]:
    with closing(connect()) as conn:
        current = conn.execute("""SELECT k.*, u.role AS user_role, u.status AS user_status
                                  FROM api_keys k JOIN users u ON u.id=k.user_id
                                  WHERE k.id=? AND k.status='active'""", (key_id,)).fetchone()
        if not current or not api_user_eligible(current["user_status"]) or key_expired(current):
            return None, (403, "API key is no longer active.", "key_expired")
        try:
            exempt = admin_unmetered(current, owner_role=current["user_role"], owner_status=current["user_status"])
        except AdminKeyPolicyError as exc:
            return None, (403, str(exc), None)
        if not endpoint_is_authorized(current, endpoint):
            return None, (403, "API key is not authorized for this endpoint.", None)
        if not model_allowed(conn, current, model):
            return None, (403, "API key is not authorized for this model.", "model_not_allowed")
        return {**dict(current), "admin_unmetered": exempt}, None


def _reserve_gateway_usage(key_row: dict[str, Any], **kwargs):
    with closing(connect()) as conn:
        return reserve_usage(conn, key_row, **kwargs)


def _mark_dispatch(reservation: UsageReservation):
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM credit_holds WHERE usage_id=?", (reservation.id,)).fetchone():
            mark_credit_dispatched(conn, reservation.id)
        conn.commit()


def _response_declares_oversize(upstream: httpx.Response) -> bool:
    try:
        return int(upstream.headers.get("content-length", "0")) > MAX_RESPONSE_BYTES
    except ValueError:
        return False


def request_headers(request: Request, upstream_key: str) -> dict[str, str]:
    headers = allowed_request_headers(request)
    headers["authorization"] = f"Bearer {upstream_key}"
    headers["accept-encoding"] = "identity"
    return headers


async def read_bounded_body(request: Request, max_bytes: int = MAX_REQUEST_BYTES) -> bytes:
    length = request.headers.get("content-length")
    try:
        if length is not None and int(length) > max_bytes:
            raise ValueError("request_too_large")
    except ValueError as exc:
        if str(exc) == "request_too_large":
            raise
        # An invalid Content-Length is rejected as malformed input below.
        raise ValueError("invalid_content_length") from exc

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("request_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_json_body(body: bytes) -> dict[str, Any]:
    if not body:
        raise ValueError("Request body must be a JSON object with a string model.")

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    try:
        payload = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Request body must contain valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("Request body must include a non-empty string model.")
    if len(model) > 256:
        raise ValueError("model is too long.")
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise ValueError("stream must be a boolean when provided.")
    payload["model"] = model
    return payload


def _upstream_base() -> str:
    return os.getenv("CODEXPROXY_BASE_URL", "http://codex-proxy:8317").rstrip("/")


def _upstream_key() -> str:
    return os.getenv("CODEXPROXY_API_KEY", "")


def _upstream_url(path: str) -> str:
    return f"{_upstream_base()}{path}"


def _is_stream_request(payload: dict[str, Any] | None, upstream: httpx.Response) -> bool:
    content_type = upstream.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        return True
    # An upstream JSON error must be buffered and returned as-is even when a
    # client requested stream=true.  Unknown content types on successful
    # responses are still relayed as raw streams for compatible proxies.
    return bool(payload and payload.get("stream") is True and upstream.status_code < 400 and not content_type.startswith("application/json"))


def _filter_models(body: bytes, allowed_ids: set[str] | None) -> bytes:
    if allowed_ids is None:
        return body
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        payload["data"] = [
            item for item in payload["data"]
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] in allowed_ids
        ]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(payload, list):
        payload = [
            item for item in payload
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] in allowed_ids
        ]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return body


def _classify_json_response(body: bytes, protocol: str, status_code: int) -> tuple[bool, str]:
    """Classify an OpenAI-compatible JSON response without changing it."""

    success = 200 <= status_code < 400
    outcome = "succeeded" if success else "failed"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return success, outcome
    if not isinstance(payload, dict):
        return success, outcome
    if isinstance(payload.get("error"), dict):
        return False, "upstream_error"
    if protocol == "responses":
        status = str(payload.get("status", "")).lower()
        if not status and isinstance(payload.get("response"), dict):
            status = str(payload["response"].get("status", "")).lower()
        if status in {"failed", "incomplete", "error", "cancelled", "canceled"}:
            return False, "failed"
    return success, outcome


def _finish(
    reservation: UsageReservation | None,
    *,
    key_row: Any,
    request_id: str,
    status_code: int | None,
    response_time_ms: int | None,
    first_byte_ms: int | None,
    outcome: str,
    success: bool,
    error_summary: str | None = None,
    usage: tuple[int | None, int | None, int | None, bool] = (None, None, None, False),
    response_preview: str | None = None,
    billing_usage: dict | None = None,
    billing_release: bool = False,
    billing_receipt_seen: bool = False,
) -> None:
    """Finalize accounting through a fresh connection, outside network I/O."""

    if not reservation:
        return
    input_tokens, output_tokens, total_tokens, usage_reported = usage
    try:
        with closing(connect()) as conn:
            recorded = complete_usage(
                conn,
                reservation,
                status_code=status_code,
                response_time_ms=response_time_ms,
                first_byte_ms=first_byte_ms,
                outcome=outcome,
                success=success,
                error_summary=error_summary,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                usage_reported=usage_reported,
                response_preview=response_preview,
                billing_usage=billing_usage,
                billing_release=billing_release and billing_usage is None and not usage_reported and not billing_receipt_seen,
            )
            if not recorded:
                raise RuntimeError("Usage settlement could not be committed")
            conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now_iso(), key_row["id"]))
            conn.commit()
    except Exception:
        logging.getLogger("luomoapi.credits").exception("credit_finalization_failed usage_id=%s", reservation.id)
        raise


async def _finish_async(reservation: UsageReservation | None, **kwargs) -> None:
    await run_in_threadpool(_finish, reservation, **kwargs)


async def stream_body(upstream: httpx.Response) -> AsyncIterator[bytes]:
    """Compatibility raw relay helper; it never decodes or rewrites chunks."""

    async for chunk in upstream.aiter_raw():
        yield chunk


async def _relay_stream(
    upstream: httpx.Response,
    client: httpx.AsyncClient,
    *,
    reservation: UsageReservation,
    key_row: Any,
    request_id: str,
    protocol: str,
    started: float,
    payload: dict[str, Any] | None,
    sse_expected: bool,
) -> AsyncIterator[bytes]:
    parser = SSEUsageParser(protocol=protocol, require_billing_details=not getattr(reservation, "admin_unmetered", False))
    first_byte_ms: int | None = None
    success = 200 <= upstream.status_code < 400
    outcome = "succeeded" if success else "failed"
    error_summary: str | None = None
    total_bytes = 0
    iterator = upstream.aiter_bytes().__aiter__()
    pending: asyncio.Task | None = None

    async def read_next():
        # The upstream read survives cancellation of the downstream relay.
        with anyio.CancelScope(shield=True):
            return await anext(iterator)

    try:
        while True:
            pending = asyncio.create_task(read_next())
            try:
                chunk = await asyncio.shield(pending)
            except StopAsyncIteration:
                pending = None
                break
            pending = None
            total_bytes += len(chunk)
            if total_bytes > MAX_RESPONSE_BYTES:
                outcome = "response_too_large"
                success = False
                error_summary = f"upstream stream exceeded {MAX_RESPONSE_BYTES} bytes"
                break
            if chunk and first_byte_ms is None:
                first_byte_ms = int((time.monotonic() - started) * 1000)
            parser.feed(chunk)
            yield chunk
    except asyncio.CancelledError:
        outcome = "client_disconnect"
        success = False
        error_summary = "downstream client disconnected"
        raise
    except GeneratorExit:
        outcome = "client_disconnect"
        success = False
        error_summary = "downstream client disconnected"
        raise
    except Exception as exc:
        outcome = "streamerror"
        success = False
        error_summary = str(exc)[:500]
        raise
    finally:
        with anyio.CancelScope(shield=True):
            if outcome == "client_disconnect" and sse_expected and not parser.stream_complete and parser.billing_usage is None:
                drained_bytes = 0
                with anyio.move_on_after(STREAM_USAGE_GRACE_SECONDS, shield=True) as grace:
                    try:
                        while not parser.stream_complete and parser.billing_usage is None:
                            if pending is None:
                                pending = asyncio.create_task(read_next())
                            try:
                                chunk = await asyncio.shield(pending)
                            except StopAsyncIteration:
                                pending = None
                                break
                            pending = None
                            drained_bytes += len(chunk)
                            total_bytes += len(chunk)
                            if drained_bytes > STREAM_USAGE_GRACE_BYTES or total_bytes > MAX_RESPONSE_BYTES:
                                parser.usage_unknown = True
                                error_summary += "; receipt recovery byte limit reached"
                                break
                            parser.feed(chunk)
                    except Exception:
                        error_summary += "; upstream receipt recovery failed"
                if grace.cancel_called:
                    error_summary += "; receipt recovery deadline reached"
            if pending is not None:
                pending.cancel()
                try:
                    await pending
                except BaseException:
                    pass
            try:
                parser.finish()
            except Exception:
                parser.usage_unknown = True
        # A normal EOF without a terminal SSE event is an incomplete stream.
        # For an opaque successful stream (no SSE content type), EOF is enough.
        if sse_expected and not parser.terminal and success:
            outcome = "stream_incomplete"
            success = False
            error_summary = "upstream SSE stream ended without a terminal event"
        if parser.error and outcome not in {"response_too_large", "client_disconnect"}:
            outcome = "streamerror"
            success = False
            error_summary = error_summary or "upstream SSE reported an error"

        did_finish = False
        try:
            # AnyIO cancellation scopes shield the close and synchronous DB
            # update from the cancellation that caused a downstream disconnect.
            with anyio.CancelScope(shield=True):
                try:
                    await upstream.aclose()
                except Exception:
                    pass
                await run_in_threadpool(
                    _finish,
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=upstream.status_code,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=first_byte_ms,
                    outcome=outcome if not success else "succeeded",
                    success=success,
                    error_summary=error_summary,
                    usage=parser.usage,
                    billing_usage=None if parser.usage_unknown else parser.billing_usage,
                    billing_receipt_seen=parser.billing_receipt_seen or parser.usage_unknown,
                    response_preview="[streamed response not retained]",
                )
                did_finish = True
        except BaseException:
            # If cancellation interrupted the shield itself, make one last
            # synchronous best-effort update so no in-flight row remains.
            if not did_finish:
                await _finish_async(
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=upstream.status_code,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=first_byte_ms,
                    outcome=outcome if not success else "succeeded",
                    success=success,
                    error_summary=error_summary,
                    usage=parser.usage,
                    billing_usage=None if parser.usage_unknown else parser.billing_usage,
                    billing_receipt_seen=parser.billing_receipt_seen or parser.usage_unknown,
                    response_preview="[streamed response not retained]",
                )


async def _close_client(upstream: httpx.Response | None, client: httpx.AsyncClient) -> None:
    if upstream is not None:
        try:
            await upstream.aclose()
        except Exception:
            pass


@router.api_route(f"/v1/{{proxy_path:path}}", methods=ALLOWED_GATEWAY_METHODS)
async def cliproxy_gateway(proxy_path: str, request: Request):
    request_id = _request_id(request)
    path = "/v1/" + proxy_path
    endpoint = path if path in NEW_SCOPES else None
    if endpoint is None:
        return json_error(404, "invalid_request_error", "Unknown or disabled endpoint.", request_id=request_id, code="endpoint_not_found")
    expected_method = ENDPOINT_METHODS[endpoint]
    if request.method.upper() != expected_method:
        return json_error(405, "invalid_request_error", f"This endpoint only allows {expected_method}.", request_id=request_id, code="method_not_allowed")

    raw_key = extract_api_key(request)
    if not raw_key:
        return json_error(401, "authentication_error", "Invalid or missing API key.", request_id=request_id)

    key_row: dict[str, Any] | None = None
    user_row: Any = None
    allowed_ids: set[str] | None = None
    payload: dict[str, Any] | None = None
    reservation: UsageReservation | None = None
    billing_quote = None
    dispatched = False
    try:
        # Authentication/model reads happen before the reservation and the
        # connection is closed before request streaming or upstream I/O.
        key_row, allowed_ids, auth_failure = await run_in_threadpool(_load_authorization, raw_key, endpoint)
        if auth_failure:
            status_code, message, failure_code = auth_failure
            return json_error(status_code, "authentication_error" if status_code == 401 else "permission_error", message, request_id=request_id, code=failure_code)
        expected_admin_unmetered = key_row["admin_unmetered"]

        if endpoint != "/v1/models":
            content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type and content_type != "application/json":
                return json_error(415, "invalid_request_error", "Content-Type must be application/json.", request_id=request_id, param="content-type", code="unsupported_media_type")
            try:
                body = await read_bounded_body(request)
            except ValueError as exc:
                if str(exc) == "request_too_large":
                    return json_error(413, "invalid_request_error", "Request body is too large.", request_id=request_id, code="request_too_large")
                return json_error(400, "invalid_request_error", "Request body must contain valid JSON.", request_id=request_id)
            try:
                payload = parse_json_body(body)
            except ValueError as exc:
                return json_error(400, "invalid_request_error", str(exc), request_id=request_id, param="body")
            model = payload["model"]
            key_row, model_failure = await run_in_threadpool(_revalidate_model, key_row["id"], endpoint, model)
            if model_failure:
                status_code, message, failure_code = model_failure
                return json_error(status_code, "permission_error", message, request_id=request_id, param="model" if failure_code == "model_not_allowed" else None, code=failure_code)
            if key_row["admin_unmetered"] != expected_admin_unmetered:
                return json_error(403, "permission_error", "API key authorization changed; retry the request.", request_id=request_id, code="authorization_changed")
            try:
                if not expected_admin_unmetered:
                    payload, billing_quote = prepare_billable_request(payload, protocol=ENDPOINT_PROTOCOLS[endpoint])
                elif endpoint == "/v1/chat/completions" and payload.get("stream") is True:
                    options = payload.get("stream_options")
                    if options is None or isinstance(options, dict):
                        payload["stream_options"] = {**(options or {}), "include_usage": True}
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            except PricingError as exc:
                return json_error(400, "invalid_request_error", exc.message, request_id=request_id, code=exc.code)
        upstream_key = _upstream_key()
        if not upstream_key:
            return json_error(503, "server_error", "CodexProxy upstream is not configured.", request_id=request_id, code="upstream_unconfigured")

        protocol = ENDPOINT_PROTOCOLS[endpoint]
        streamed_request = bool(payload and payload.get("stream") is True)
        target_url = _upstream_url(endpoint)
        reservation, rejection = await run_in_threadpool(
            _reserve_gateway_usage,
            key_row,
            request_id=request_id,
            protocol=protocol,
            model=payload.get("model") if payload else None,
            streamed=streamed_request,
            method=expected_method,
            public_path=endpoint.lstrip("/"),
            target_url_masked=mask_url(target_url),
            client_ip_hash=None,
            user_agent_preview=None,
            enforce_quota=endpoint != "/v1/models",
            private_scope=NEW_SCOPES[endpoint],
            require_private_grant=True,
            model_id=payload.get("model") if payload else None,
            billing_quote=billing_quote,
            expected_admin_unmetered=expected_admin_unmetered,
        )
        if rejection:
            return json_error(rejection.status_code, "rate_limit_error" if rejection.code == "rate_limited" else rejection.code, rejection.message, request_id=request_id, code=rejection.code)
        if reservation is None:
            return json_error(503, "server_error", "Usage reservation failed.", request_id=request_id, code="usage_reservation_failed")
        # The reservation re-read policy and the exact model rows while it
        # held BEGIN IMMEDIATE.  Use that snapshot for the model response so
        # a concurrent console edit cannot make this response stale.
        if endpoint == "/v1/models":
            allowed_ids = set(reservation.model_ids) if reservation.model_ids is not None else None

        client = request.app.state.codex_http_client
        upstream: httpx.Response | None = None
        started = time.monotonic()
        try:
            upstream_request = client.build_request(
                expected_method,
                target_url,
                headers=request_headers(request, upstream_key),
                content=body if endpoint != "/v1/models" else None,
                timeout=httpx.Timeout(connect=15.0, read=120.0, write=60.0, pool=15.0),
            )
            await run_in_threadpool(_mark_dispatch, reservation)
            dispatched = True
            upstream = await client.send(upstream_request, stream=True)
        except httpx.TimeoutException as exc:
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=504,
                response_time_ms=int((time.monotonic() - started) * 1000),
                first_byte_ms=None,
                outcome="upstream_timeout",
                success=False,
                error_summary=type(exc).__name__,
            )
            return json_error(504, "upstream_timeout", "CodexProxy upstream request timed out.", request_id=request_id)
        except httpx.RequestError as exc:
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=502,
                response_time_ms=int((time.monotonic() - started) * 1000),
                first_byte_ms=None,
                outcome="upstream_error",
                success=False,
                error_summary=type(exc).__name__,
            )
            return json_error(502, "upstream_error", "CodexProxy upstream request failed.", request_id=request_id)

        header_elapsed = int((time.monotonic() - started) * 1000)
        stream_response = _is_stream_request(payload, upstream)
        headers = response_headers(upstream, request_id=request_id, preserve_content_encoding=False)
        if _response_declares_oversize(upstream):
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=502,
                response_time_ms=header_elapsed,
                first_byte_ms=header_elapsed,
                outcome="response_too_large",
                success=False,
                error_summary=f"upstream response exceeded {MAX_RESPONSE_BYTES} bytes",
            )
            return json_error(502, "response_too_large", "CodexProxy upstream response exceeded the configured size limit.", request_id=request_id)
        if endpoint == "/v1/models":
            try:
                response_body = await read_bounded_response(upstream)
                await _close_client(upstream, client)
                response_body = _filter_models(response_body, allowed_ids)
                success = 200 <= upstream.status_code < 400
                await _finish_async(
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=upstream.status_code,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=header_elapsed,
                    outcome="succeeded" if success else "failed",
                    success=success,
                    error_summary=None if success else f"upstream status {upstream.status_code}",
                    response_preview="[model list not retained]",
                )
                return Response(content=response_body, status_code=upstream.status_code, headers=headers)
            except ResponseTooLarge:
                await _close_client(upstream, client)
                await _finish_async(
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=502,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=header_elapsed,
                    outcome="response_too_large",
                    success=False,
                    error_summary=f"upstream response exceeded {MAX_RESPONSE_BYTES} bytes",
                )
                return json_error(502, "response_too_large", "CodexProxy model list exceeded the configured size limit.", request_id=request_id)
            except httpx.TimeoutException as exc:
                await _close_client(upstream, client)
                await _finish_async(
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=504,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=header_elapsed,
                    outcome="upstream_timeout",
                    success=False,
                    error_summary=type(exc).__name__,
                )
                return json_error(504, "upstream_timeout", "CodexProxy upstream response timed out.", request_id=request_id)
            except Exception as exc:
                await _close_client(upstream, client)
                await _finish_async(
                    reservation,
                    key_row=key_row,
                    request_id=request_id,
                    status_code=502,
                    response_time_ms=int((time.monotonic() - started) * 1000),
                    first_byte_ms=header_elapsed,
                    outcome="gateway_error",
                    success=False,
                    error_summary=type(exc).__name__,
                )
                return json_error(502, "upstream_error", "CodexProxy model list response failed.", request_id=request_id)

        if _is_stream_request(payload, upstream):
            async def abandoned_before_stream():
                # Closing an async generator before its first iteration does
                # not enter its finally block. Own that admission explicitly.
                await _close_client(upstream, client)
                await _finish_async(reservation, key_row=key_row, request_id=request_id,
                                    status_code=upstream.status_code,
                                    response_time_ms=int((time.monotonic()-started)*1000),
                                    first_byte_ms=header_elapsed, outcome="client_disconnect", success=False,
                                    error_summary="Downstream disconnected before response headers were sent.")
            return MeteredStreamingResponse(
                _relay_stream(
                    upstream,
                    client,
                    reservation=reservation,
                    key_row=key_row,
                    request_id=request_id,
                    protocol=protocol,
                    started=started,
                    payload=payload,
                    sse_expected="text/event-stream" in upstream.headers.get("content-type", "").lower(),
                ),
                status_code=upstream.status_code,
                headers=headers,
                on_unstarted_disconnect=abandoned_before_stream,
            )

        try:
            response_body = await read_bounded_response(upstream)
        except ResponseTooLarge:
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=502,
                response_time_ms=int((time.monotonic() - started) * 1000),
                first_byte_ms=header_elapsed,
                outcome="response_too_large",
                success=False,
                error_summary=f"upstream response exceeded {MAX_RESPONSE_BYTES} bytes",
            )
            return json_error(502, "response_too_large", "CodexProxy upstream response exceeded the configured size limit.", request_id=request_id)
        except httpx.TimeoutException as exc:
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=504,
                response_time_ms=int((time.monotonic() - started) * 1000),
                first_byte_ms=header_elapsed,
                outcome="upstream_timeout",
                success=False,
                error_summary=type(exc).__name__,
            )
            return json_error(504, "upstream_timeout", "CodexProxy upstream response timed out.", request_id=request_id)
        except httpx.RequestError as exc:
            await _close_client(upstream, client)
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=502,
                response_time_ms=int((time.monotonic() - started) * 1000),
                first_byte_ms=header_elapsed,
                outcome="upstream_error",
                success=False,
                error_summary=type(exc).__name__,
            )
            return json_error(502, "upstream_error", "CodexProxy upstream response failed.", request_id=request_id)
        await _close_client(upstream, client)
        usage = extract_json_usage(response_body, protocol=protocol)
        try:
            receipt_payload = json.loads(response_body)
        except (ValueError, UnicodeDecodeError):
            receipt_payload = None
        success, outcome = _classify_json_response(response_body, protocol, upstream.status_code)
        await _finish_async(
            reservation,
            key_row=key_row,
            request_id=request_id,
            status_code=upstream.status_code,
            response_time_ms=int((time.monotonic() - started) * 1000),
            first_byte_ms=header_elapsed,
            outcome=outcome,
            success=success,
            error_summary=None if success else f"upstream status {upstream.status_code}",
            usage=usage,
            billing_usage=billing_details(receipt_payload, protocol=protocol),
            billing_receipt_seen=billing_receipt_present(receipt_payload, protocol=protocol),
            billing_release=_explicit_generation_rejection(receipt_payload, upstream.status_code, protocol),
            response_preview="[response body not retained]",
        )
        return Response(content=response_body, status_code=upstream.status_code, headers=headers)
    except asyncio.CancelledError:
        with anyio.CancelScope(shield=True):
            if "upstream" in locals() and upstream is not None:
                await _close_client(upstream, client)
            if reservation is not None:
                await _finish_async(reservation, key_row=key_row, request_id=request_id, status_code=None,
                                    response_time_ms=None, first_byte_ms=None, outcome="client_disconnect", success=False,
                                    error_summary="Request cancelled before final usage was received.", billing_release=not dispatched)
        raise
    except Exception as exc:
        # A reservation can exist only after key_row is populated.  Close any
        # partially opened client and complete it so a failed setup cannot
        # leave a permanent in-flight quota row.
        try:
            if "client" in locals() and client is not None:
                await _close_client(upstream if "upstream" in locals() else None, client)
        except Exception:
            pass
        if reservation is not None:
            await _finish_async(
                reservation,
                key_row=key_row,
                request_id=request_id,
                status_code=500,
                response_time_ms=int((time.monotonic() - started) * 1000) if "started" in locals() else None,
                first_byte_ms=None,
                outcome="gateway_error",
                success=False,
                error_summary="Gateway failed to process the request.",
                billing_release=not dispatched,
            )
        return json_error(500, "server_error", "Gateway failed to process the request.", request_id=request_id, code="gateway_error")


__all__ = [
    "ALLOWED_GATEWAY_METHODS",
    "ENDPOINT_METHODS",
    "ENDPOINT_PROTOCOLS",
    "NEW_SCOPES",
    "REQUIRED_ROUTE",
    "REQUIRED_SCOPE",
    "cliproxy_gateway",
    "endpoint_is_authorized",
    "json_error",
    "model_allowed",
    "request_headers",
    "route_is_authorized",
    "stream_body",
]
