"""Usage accounting, model grants, and bounded upstream usage extraction.

The gateway deliberately records a request before it leaves the process.  The
reservation is committed in a short ``BEGIN IMMEDIATE`` transaction so that
rate and quota checks include concurrent in-flight requests.  Callers must
close their database connection before doing network I/O and later call
``complete_usage`` from a fresh connection.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
import logging
from app.auth import api_user_eligible
from app.admin_key_policy import ADMIN_EXEMPT_REASON, AdminKeyPolicyError, admin_unmetered
from app.credit_ledger import CreditError, reserve_credit, settle_credit
from app.credit_pricing import BillingQuote, PricingError, billing_details, billing_receipt_present, calculate_charge


UTC = timezone.utc
MAX_SUMMARY_DAYS = 366


@dataclass(frozen=True)
class QuotaRejection:
    code: str
    message: str
    status_code: int = 429


@dataclass(frozen=True)
class UsageReservation:
    id: int
    request_id: str
    started_at: str
    # ``None`` means policy=all; an empty tuple means an explicit empty
    # allowlist.  Captured under the same reservation lock for /v1/models.
    model_ids: tuple[str, ...] | None = None
    admin_unmetered: bool = False


def _row_value(row: Any, name: str, default: Any = None) -> Any:
    """Read a value from sqlite rows and ordinary mappings safely."""

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
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def iso_now() -> str:
    return datetime.now(UTC).isoformat()


def get_key_models(conn: sqlite3.Connection, key_id: int) -> list[str]:
    """Return the exact model IDs assigned to an API key.

    An old database may be inspected before the migration has run.  Returning
    an empty list in that case keeps the console and key inspection pages
    readable while ``model_policy=all`` continues to preserve old keys.
    """

    try:
        rows = conn.execute(
            "SELECT model_id FROM api_key_models WHERE api_key_id=? ORDER BY model_id",
            (int(key_id),),
        ).fetchall()
    except (sqlite3.DatabaseError, TypeError, ValueError):
        return []
    return [str(row["model_id"] if isinstance(row, sqlite3.Row) else row[0]) for row in rows]


def model_allowed(conn: sqlite3.Connection, key_row: Any, model_id: str) -> bool:
    """Check one exact model grant, preserving the legacy ``all`` policy."""

    if not isinstance(model_id, str) or not model_id:
        return False
    policy = str(_row_value(key_row, "model_policy", "all") or "all").strip().lower()
    if policy == "all":
        return True
    if policy not in {"allowlist", "exact", "restricted"}:
        return False
    key_id = _row_value(key_row, "id")
    if key_id is None:
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM api_key_models WHERE api_key_id=? AND model_id=? LIMIT 1",
            (int(key_id), model_id),
        ).fetchone()
    except (sqlite3.DatabaseError, TypeError, ValueError):
        return False
    return row is not None


def _quota_limits(key_row: Any) -> tuple[int | None, int | None, int | None]:
    def value(name: str) -> int | None:
        raw = _row_value(key_row, name)
        if raw is None or raw == "":
            return None
        try:
            parsed = int(raw)
            # The console policy form defines zero as unlimited.  Negative
            # values are treated as absent here; policy validation rejects
            # them before a key is issued.
            return parsed if parsed > 0 else None
        except (TypeError, ValueError):
            return None

    # None means no configured limit.  Existing schema defaults are supplied
    # by SQLite and therefore arrive here as integers for normal keys.
    return value("rate_limit_per_minute"), value("daily_quota"), value("monthly_quota")


def _key_expired(key_row: Any, now: datetime) -> bool:
    raw_expires_at = _row_value(key_row, "expires_at")
    expires_at = _parse_datetime(raw_expires_at)
    if raw_expires_at and expires_at is None:
        return True
    return expires_at is not None and expires_at <= now


def _usage_count(conn: sqlite3.Connection, key_id: int, since: datetime) -> int:
    # COALESCE keeps old rows (which predate started_at) in quota accounting.
    row = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM api_usage_logs
        WHERE api_key_id=? AND COALESCE(started_at, created_at)>=?
          AND COALESCE(protocol, '') <> 'models'
          AND public_path NOT IN ('v1/models', '/v1/models')
        """,
        (key_id, since.isoformat()),
    ).fetchone()
    return int(row["c"] if isinstance(row, sqlite3.Row) else row[0])


def quota_rejection(conn: sqlite3.Connection, key_row: Any, now: datetime | None = None) -> QuotaRejection | None:
    """Check expiry, minute, daily, and monthly request limits.

    This function intentionally does not begin a transaction.  Use
    ``reserve_usage`` for the atomic check-and-insert needed by request paths.
    """

    now = (now or datetime.now(UTC)).astimezone(UTC)
    if _key_expired(key_row, now):
        return QuotaRejection("key_expired", "API key has expired.", 403)
    key_id = _row_value(key_row, "id")
    if key_id is None:
        return QuotaRejection("quota_error", "API key quota could not be checked.", 503)
    try:
        key_id = int(key_id)
    except (TypeError, ValueError):
        return QuotaRejection("quota_error", "API key quota could not be checked.", 503)

    per_minute, daily, monthly = _quota_limits(key_row)
    if per_minute is not None and _usage_count(conn, key_id, now - timedelta(seconds=60)) >= per_minute:
        return QuotaRejection("rate_limited", "API key rate limit exceeded.")

    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if daily is not None and _usage_count(conn, key_id, day_start) >= daily:
        return QuotaRejection("quota_exceeded", "API key daily quota exceeded.")

    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if monthly is not None and _usage_count(conn, key_id, month_start) >= monthly:
        return QuotaRejection("monthly_quota_exceeded", "API key monthly quota exceeded.")
    return None


def reserve_usage(
    conn: sqlite3.Connection,
    key_row: Any,
    *,
    request_id: str,
    protocol: str,
    model: str | None,
    streamed: bool,
    method: str,
    public_path: str,
    route_id: int | None = None,
    target_url_masked: str | None = None,
    client_ip_hash: str | None = None,
    user_agent_preview: str | None = None,
    enforce_quota: bool = True,
    private_scope: str | None = None,
    require_private_grant: bool = False,
    model_id: str | None = None,
    billing_quote: BillingQuote | None = None,
    expected_admin_unmetered: bool | None = None,
) -> tuple[UsageReservation | None, QuotaRejection | None]:
    """Atomically check quotas and insert an in-flight usage reservation."""

    key_id = _row_value(key_row, "id")
    if key_id is None:
        return None, QuotaRejection("quota_error", "API key quota could not be checked.", 503)
    started_at = iso_now()
    try:
        # BEGIN IMMEDIATE serializes the check and reservation.  No caller may
        # perform HTTP work while this transaction or connection is retained.
        conn.execute("BEGIN IMMEDIATE")
        # Re-read mutable admission state after acquiring the write lock.  A
        # concurrent revoke, suspension, expiry, scope, or model-policy edit
        # therefore takes effect before this request leaves the process.
        current = conn.execute(
            """
            SELECT k.*, u.role AS user_role, u.status AS user_status
            FROM api_keys k JOIN users u ON u.id=k.user_id
            WHERE k.id=?
            """,
            (int(key_id),),
        ).fetchone()
        if not current or current["status"] != "active" or not api_user_eligible(current["user_status"]):
            conn.rollback()
            return None, QuotaRejection("permission_error", "User or API key is not active.", 403)
        # The models endpoint deliberately skips request-count quota checks,
        # but expiry remains an admission rule and must be checked again under
        # this transaction after the mutable row has been re-read.
        if _key_expired(current, datetime.now(UTC)):
            conn.rollback()
            return None, QuotaRejection("key_expired", "API key has expired.", 403)
        try:
            exempt = admin_unmetered(current, owner_role=current["user_role"], owner_status=current["user_status"])
        except AdminKeyPolicyError as exc:
            conn.rollback()
            return None, QuotaRejection("permission_error", str(exc), 403)
        # Old callers are ordinary, never implicitly exempt. Refuse both
        # directions of a policy change after request shaping/authentication.
        if exempt != (expected_admin_unmetered is True):
            conn.rollback()
            return None, QuotaRejection("authorization_changed", "API key authorization changed; retry the request.", 403)
        if require_private_grant:
            scopes = {part.strip() for part in str(current["scopes"] or "").replace(",", " ").split() if part.strip()}
            routes = {part.strip() for part in str(current["allowed_routes"] or "").replace(",", " ").split() if part.strip()}
            legacy_ok = "codexproxy:use" in scopes and "codexproxy/*" in routes
            new_ok = private_scope is not None and private_scope in scopes
            if not (legacy_ok or new_ok):
                conn.rollback()
                return None, QuotaRejection("permission_error", "API key is not authorized for this endpoint.", 403)
        if model_id is not None and not model_allowed(conn, current, model_id):
            conn.rollback()
            return None, QuotaRejection("model_not_allowed", "API key is not authorized for this model.", 403)
        rejection = quota_rejection(conn, current) if enforce_quota else None
        if rejection:
            conn.rollback()
            return None, rejection
        if protocol in {"chat.completions", "responses"} and billing_quote is None and not exempt:
            conn.rollback()
            return None, QuotaRejection("billing_quote_missing", "A credit reservation is required for generation.", 503)
        current_model_ids: tuple[str, ...] | None = None
        if str(current["model_policy"] or "all").strip().lower() != "all" and protocol == "models":
            current_model_ids = tuple(get_key_models(conn, int(key_id)))
        cursor = conn.execute(
            """
            INSERT INTO api_usage_logs(
                created_at, user_id, api_key_id, route_id, method, public_path,
                target_url_masked, status_code, response_time_ms, success,
                client_ip_hash, user_agent_preview, error_summary,
                request_preview, response_preview, request_id, protocol, model,
                streamed, outcome, started_at, completed_at, first_byte_ms,
                input_tokens, output_tokens, total_tokens, usage_reported,
                credit_status, credit_reserved_units, credit_charged_units, credit_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL, NULL,
                      ?, ?, ?, ?, 'in_flight', ?, NULL, NULL, NULL, NULL, NULL, 0,
                      ?, 0, 0, ?)
            """,
            (
                started_at,
                current["user_id"],
                int(key_id),
                route_id,
                method.upper(),
                public_path,
                target_url_masked,
                client_ip_hash,
                user_agent_preview,
                request_id,
                protocol,
                model,
                1 if streamed else 0,
                started_at,
                "admin_exempt" if exempt else "legacy_unbilled",
                ADMIN_EXEMPT_REASON if exempt else None,
            ),
        )
        if billing_quote is not None and not exempt:
            reserve_credit(conn, int(cursor.lastrowid), int(current["user_id"]), billing_quote.amount_units, billing_quote.snapshot)
        conn.commit()
        return UsageReservation(int(cursor.lastrowid), request_id, started_at, current_model_ids, exempt), None
    except CreditError as exc:
        conn.rollback()
        return None, QuotaRejection(exc.code, exc.message, exc.status)
    except sqlite3.OperationalError as exc:
        try:
            conn.rollback()
        except sqlite3.DatabaseError:
            pass
        if "locked" in str(exc).lower() or "busy" in str(exc).lower():
            return None, QuotaRejection("quota_busy", "API key quota is temporarily busy.", 503)
        return None, QuotaRejection("quota_error", "API key quota could not be recorded.", 503)
    except sqlite3.DatabaseError:
        try:
            conn.rollback()
        except sqlite3.DatabaseError:
            pass
        return None, QuotaRejection("quota_error", "API key quota could not be recorded.", 503)


def _normalise_outcome(outcome: str | None, status_code: int | None, success: bool | None) -> str:
    if outcome:
        return str(outcome)[:64]
    if success is True or (success is None and status_code is not None and 200 <= status_code < 400):
        return "succeeded"
    return "failed"


def complete_usage(
    conn: sqlite3.Connection,
    reservation: UsageReservation | int,
    *,
    status_code: int | None,
    response_time_ms: int | None,
    first_byte_ms: int | None,
    outcome: str | None = None,
    success: bool | None = None,
    error_summary: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    total_tokens: int | None = None,
    usage_reported: bool = False,
    response_preview: str | None = None,
    completed_at: str | None = None,
    billing_usage: dict | None = None,
    billing_release: bool = False,
) -> bool:
    """Finalize a reservation from a fresh connection after network I/O."""

    row_id = reservation.id if isinstance(reservation, UsageReservation) else int(reservation)
    final_outcome = _normalise_outcome(outcome, status_code, success)
    if success is None:
        success = final_outcome in {"succeeded", "completed"} or (
            status_code is not None and 200 <= status_code < 400 and final_outcome not in {"streamerror", "client_disconnect", "upstream_error"}
        )
    if not usage_reported:
        input_tokens = output_tokens = total_tokens = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        hold = conn.execute("SELECT * FROM credit_holds WHERE usage_id=?", (row_id,)).fetchone()
        accepted_billing = False
        if hold:
            actual = None
            reason = "Upstream usage was unavailable; frozen funds require reconciliation."
            if billing_usage is not None:
                try:
                    actual = calculate_charge(hold["pricing_snapshot"], billing_usage)
                    reason = "Settled from authoritative upstream token usage."
                except PricingError as exc:
                    reason = exc.message
            elif billing_release:
                actual = 0
                reason = "Request was not dispatched or was explicitly rejected before generation."
            result = settle_credit(conn, row_id, actual, reason=reason, usage_json=json.dumps(billing_usage, separators=(",", ":"), sort_keys=True) if billing_usage else None)
            stored_receipt = conn.execute("SELECT usage_json FROM credit_holds WHERE usage_id=?", (row_id,)).fetchone()[0]
            try:
                stored_details = json.loads(stored_receipt) if stored_receipt is not None else None
            except (ValueError, TypeError):
                stored_details = None
            accepted_billing = (hold["status"] not in {"settled", "released"} and actual is not None
                                and billing_usage is not None and result["actual_units"] == actual
                                and stored_details == billing_usage)
            if accepted_billing:
                input_tokens, output_tokens = billing_usage["input_tokens"], billing_usage["output_tokens"]
                total_tokens, usage_reported = input_tokens + output_tokens, True
        conn.execute(
            """
            UPDATE api_usage_logs
            SET status_code=?, response_time_ms=?, success=?, error_summary=?,
                response_preview=?, outcome=?, completed_at=?, first_byte_ms=?,
                input_tokens=?, output_tokens=?, total_tokens=?, usage_reported=?
            WHERE id=? AND completed_at IS NULL
            """,
            (
                status_code,
                response_time_ms,
                1 if success else 0,
                error_summary,
                response_preview,
                final_outcome,
                completed_at or iso_now(),
                first_byte_ms,
                input_tokens,
                output_tokens,
                total_tokens,
                1 if usage_reported else 0,
                row_id,
            ),
        )
        if accepted_billing:
            # A late receipt completes billing statistics without rewriting the
            # original transport outcome, completion time, or response metadata.
            conn.execute("UPDATE api_usage_logs SET input_tokens=?,output_tokens=?,total_tokens=?,usage_reported=1 WHERE id=?",
                         (input_tokens, output_tokens, total_tokens, row_id))
        # Exemption affects money, not usage evidence. Keep the parsed receipt
        # even though no credit hold (and therefore no settlement) exists.
        receipt = billing_usage
        if receipt is None and usage_reported:
            receipt = {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}
        if receipt is not None:
            conn.execute("""UPDATE api_usage_logs SET credit_usage_json=?
                            WHERE id=? AND credit_status='admin_exempt' AND credit_usage_json IS NULL""",
                         (json.dumps(receipt, separators=(",", ":"), sort_keys=True), row_id))
        conn.commit()
        return conn.execute("SELECT 1 FROM api_usage_logs WHERE id=?", (row_id,)).fetchone() is not None
    except (sqlite3.DatabaseError, CreditError):
        try:
            conn.rollback()
        except sqlite3.DatabaseError:
            pass
        logging.getLogger("luomoapi.credits").exception("usage_settlement_failed usage_id=%s", row_id)
        return False


def insert_usage(
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
    client_ip_hash: str | None,
    user_agent_preview: str | None,
    error_summary: str | None,
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
    request_preview: str | None = None,
    response_preview: str | None = None,
) -> int | None:
    """Insert a completed non-reserved usage row for legacy callers."""

    started_at = started_at or iso_now()
    completed_at = completed_at or started_at
    if not usage_reported:
        input_tokens = output_tokens = total_tokens = None
    try:
        cur = conn.execute(
            """
            INSERT INTO api_usage_logs(
                created_at, user_id, api_key_id, route_id, method, public_path,
                target_url_masked, status_code, response_time_ms, success,
                client_ip_hash, user_agent_preview, error_summary,
                request_preview, response_preview, request_id, protocol, model,
                streamed, outcome, started_at, completed_at, first_byte_ms,
                input_tokens, output_tokens, total_tokens, usage_reported
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                started_at,
                user_id,
                api_key_id,
                route_id,
                method.upper(),
                public_path,
                target_url_masked,
                status_code,
                response_time_ms,
                1 if success else 0,
                client_ip_hash,
                user_agent_preview,
                error_summary,
                request_preview,
                response_preview,
                request_id,
                protocol,
                model,
                1 if streamed else 0,
                _normalise_outcome(outcome, status_code, success),
                started_at,
                completed_at,
                first_byte_ms,
                input_tokens,
                output_tokens,
                total_tokens,
                1 if usage_reported else 0,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    except sqlite3.DatabaseError:
        try:
            conn.rollback()
        except sqlite3.DatabaseError:
            pass
        return None


def _int_usage(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _usage_from_mapping(value: Any) -> tuple[int | None, int | None, int | None, bool]:
    if not isinstance(value, dict):
        return None, None, None, False
    # OpenAI Chat uses prompt/completion tokens; Responses uses input/output.
    input_tokens = _int_usage(value.get("input_tokens", value.get("prompt_tokens")))
    output_tokens = _int_usage(value.get("output_tokens", value.get("completion_tokens")))
    total_tokens = _int_usage(value.get("total_tokens"))
    reported = any(item is not None for item in (input_tokens, output_tokens, total_tokens))
    return input_tokens, output_tokens, total_tokens, reported


def extract_usage(payload: Any, *, protocol: str, completed_only: bool = False) -> tuple[int | None, int | None, int | None, bool]:
    """Extract usage from documented OpenAI response locations only.

    Chat Completions reports ``usage`` at the response/chunk top level.
    Responses reports it at the top level for JSON responses and under
    ``response.usage`` for completion events.  Deliberately avoiding a
    recursive walk prevents a tool result or arbitrary content object with a
    field named ``usage`` from being counted as billing metadata.
    """

    if not isinstance(payload, dict):
        return None, None, None, False
    protocol = (protocol or "").lower()
    completed_types = {"response.completed", "response.done", "response.complete", "completed", "done", "response.incomplete", "response.failed"}
    event_type = str(payload.get("type", "")).lower()
    if completed_only and event_type not in completed_types:
        return None, None, None, False

    candidate = _usage_from_mapping(payload.get("usage"))
    if candidate[3]:
        return candidate
    if protocol.startswith("response"):
        response = payload.get("response")
        if isinstance(response, dict):
            candidate = _usage_from_mapping(response.get("usage"))
            if candidate[3]:
                return candidate
    return None, None, None, False


def extract_json_usage(body: bytes, *, protocol: str) -> tuple[int | None, int | None, int | None, bool]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None, None, False
    return extract_usage(payload, protocol=protocol, completed_only=False)


MAX_SSE_EVENT_BYTES = 1024 * 1024


def _sse_separator(value: bytes) -> tuple[int, int] | None:
    """Return the earliest supported SSE event separator and its byte size."""

    candidates = [(value.find(b"\n\n"), 2), (value.find(b"\r\n\r\n"), 4)]
    candidates = [(index, size) for index, size in candidates if index >= 0]
    return min(candidates, key=lambda item: item[0]) if candidates else None


class SSEUsageParser:
    """Incrementally inspect SSE events without changing their raw bytes."""

    def __init__(self, *, protocol: str, require_billing_details: bool = True):
        self.protocol = protocol
        self.require_billing_details = require_billing_details
        self._buffer = b""
        self._usage: tuple[int | None, int | None, int | None, bool] = (None, None, None, False)
        self.terminal = False
        self.stream_complete = False
        self.error = False
        self.saw_event = False
        self.usage_unknown = False
        self._discarding_oversize_event = False
        self.billing_usage: dict | None = None
        self.billing_receipt_seen = False
        self.response_model: str | None = None
        self._receipt_locked = False

    def _accept_receipt(self, candidate, details) -> None:
        if details is None and self.require_billing_details:
            self.usage_unknown = True
            return
        receipt_changed = self.billing_usage != details
        if not self.require_billing_details:
            receipt_changed = self._usage != candidate or (
                self.billing_usage is not None and details is not None and self.billing_usage != details)
        if self._receipt_locked and receipt_changed:
            self.usage_unknown = True
            return
        self._usage = candidate
        if details is not None:
            self.billing_usage = details
        self._receipt_locked = True

    @property
    def usage(self) -> tuple[int | None, int | None, int | None, bool]:
        # A discarded event may have contained the authoritative usage
        # object.  Do not expose an earlier partial value as if it were final.
        return (None, None, None, False) if self.usage_unknown else self._usage

    def _consume_event(self, event: bytes) -> None:
        data_lines: list[bytes] = []
        event_type = ""
        for line in event.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n"):
            if line.startswith(b"data:"):
                data_lines.append(line[5:].lstrip(b" "))
            elif line.startswith(b"event:"):
                try:
                    event_type = line[6:].strip().decode("utf-8", "ignore").lower()
                except Exception:
                    event_type = ""
        if not data_lines:
            return
        raw = b"\n".join(data_lines).strip()
        if not raw:
            return
        if raw == b"[DONE]":
            self.terminal = True
            self.stream_complete = True
            self.saw_event = True
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        self.saw_event = True
        if billing_receipt_present(payload, protocol=self.protocol):
            self.billing_receipt_seen = True
        lowered_type = event_type or (str(payload.get("type", "")).lower() if isinstance(payload, dict) else "")
        if isinstance(payload, dict):
            obj = payload.get("response") if isinstance(payload.get("response"), dict) else payload
            if isinstance(obj.get("model"), str):
                self.response_model = obj["model"]
        if self.protocol.lower().startswith("response"):
            if lowered_type in {"response.completed", "response.done", "response.complete", "completed", "done"}:
                self.terminal = True
                self.stream_complete = True
            elif lowered_type in {"response.failed", "response.incomplete", "response.error", "error", "failed", "incomplete"}:
                self.terminal = True
                self.stream_complete = True
                self.error = True
        elif isinstance(payload, dict):
            if lowered_type in {"error", "response.error"} or isinstance(payload.get("error"), dict):
                self.terminal = True
                self.stream_complete = True
                self.error = True
            choices = payload.get("choices")
            if isinstance(choices, list) and any(isinstance(item, dict) and item.get("finish_reason") is not None for item in choices):
                self.terminal = True
        if self.protocol.lower().startswith("response"):
            # Some servers expose the event type only as an SSE field while
            # others put it in data.type; make the latter explicit for the
            # completed-only traversal.
            if isinstance(payload, dict) and event_type and "type" not in payload:
                payload = {"type": event_type, **payload}
            candidate = extract_usage(payload, protocol=self.protocol, completed_only=True)
        else:
            candidate = extract_usage(payload, protocol=self.protocol, completed_only=False)
        choices = payload.get("choices") if isinstance(payload, dict) else None
        final_chat_receipt = isinstance(choices, list) and (not choices or all(
            isinstance(item, dict) and item.get("finish_reason") is not None for item in choices))
        final_chat_receipt = final_chat_receipt or (choices is None and self.terminal)
        if candidate[3]:
            details = billing_details(payload, protocol=self.protocol)
            if details is not None and details.get("model") is None:
                details["model"] = self.response_model
            if self.protocol.lower().startswith("response") or final_chat_receipt or self._receipt_locked:
                self._accept_receipt(candidate, details)
        elif (self.stream_complete or (not self.protocol.lower().startswith("response") and final_chat_receipt)) and billing_receipt_present(payload, protocol=self.protocol):
            # An incomplete final receipt must not expose an earlier statistic.
            self.usage_unknown = True

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, (bytes, bytearray)):
            return
        self._buffer += bytes(chunk)
        # SSE event separators are blank lines.  Retain an incomplete event
        # so arbitrary upstream chunk boundaries never lose usage metadata.
        while True:
            separator = _sse_separator(self._buffer)
            if separator is None:
                if len(self._buffer) > MAX_SSE_EVENT_BYTES:
                    # Keep only enough tail bytes to recognize a separator
                    # split across chunks.  Raw relay remains untouched.
                    self.usage_unknown = True
                    self._discarding_oversize_event = True
                    self._buffer = self._buffer[-3:]
                break
            index, separator_len = separator
            event = self._buffer[:index]
            self._buffer = self._buffer[index + separator_len :]
            if self._discarding_oversize_event or len(event) > MAX_SSE_EVENT_BYTES:
                self.usage_unknown = True
                self._discarding_oversize_event = False
                continue
            if not event:
                continue
            self._consume_event(event)

    def finish(self) -> None:
        if self._buffer.strip() and not self._discarding_oversize_event and len(self._buffer) <= MAX_SSE_EVENT_BYTES:
            self._consume_event(self._buffer)
        elif self._buffer.strip() or self._discarding_oversize_event:
            self.usage_unknown = True
        self._buffer = b""
        self._discarding_oversize_event = False


def _summary_cutoff(days: int) -> datetime:
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 7
    days = min(MAX_SUMMARY_DAYS, max(1, days))
    return datetime.now(UTC) - timedelta(days=days)


def read_usage_summary(user_id: int | None, days: int = 7) -> dict[str, Any]:
    """Return dashboard-safe usage aggregates and at most 100 recent rows."""

    from app.db import connect  # local import avoids importing app config here

    cutoff = _summary_cutoff(days).isoformat()
    # Models/list and the older public gateway have separate accounting; this
    # dashboard is specifically for the two text generation protocols.
    where = "protocol IN ('chat.completions', 'responses') AND COALESCE(started_at, created_at)>=?"
    args: list[Any] = [cutoff]
    if user_id is not None:
        where += " AND user_id=?"
        args.append(int(user_id))

    summary: dict[str, Any] = {
        "requests": 0,
        "completed": 0,
        "succeeded": 0,
        "failed": 0,
        "in_flight": 0,
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "usage_reported_requests": 0,
        "avg_latency_ms": None,
    }
    by_model: list[dict[str, Any]] = []
    daily: list[dict[str, Any]] = []
    recent: list[dict[str, Any]] = []
    with connect() as conn:
        row = conn.execute(
            f"""
            SELECT COUNT(*) AS requests,
                   SUM(CASE WHEN completed_at IS NOT NULL OR (outcome IS NOT NULL AND outcome!='in_flight') THEN 1 ELSE 0 END) AS completed,
                   SUM(CASE WHEN outcome IN ('succeeded','completed') OR success=1 THEN 1 ELSE 0 END) AS succeeded,
                   SUM(CASE WHEN (completed_at IS NOT NULL OR (outcome IS NOT NULL AND outcome!='in_flight')) AND COALESCE(success,0)=0 THEN 1 ELSE 0 END) AS failed,
                   SUM(CASE WHEN outcome='in_flight' AND completed_at IS NULL THEN 1 ELSE 0 END) AS in_flight,
                   SUM(CASE WHEN usage_reported=1 THEN input_tokens ELSE NULL END) AS input_tokens,
                   SUM(CASE WHEN usage_reported=1 THEN output_tokens ELSE NULL END) AS output_tokens,
                   SUM(CASE WHEN usage_reported=1 THEN total_tokens ELSE NULL END) AS total_tokens,
                   SUM(CASE WHEN usage_reported=1 THEN 1 ELSE 0 END) AS usage_reported_requests,
                   AVG(CASE WHEN completed_at IS NOT NULL THEN response_time_ms END) AS avg_latency_ms
            FROM api_usage_logs WHERE {where}
            """,
            args,
        ).fetchone()
        if row:
            for key in summary:
                value = row[key]
                if key in {"completed", "succeeded", "failed", "in_flight", "usage_reported_requests"}:
                    summary[key] = int(value or 0)
                elif key in {"input_tokens", "output_tokens", "total_tokens"}:
                    summary[key] = int(value) if value is not None else None
                elif key == "avg_latency_ms":
                    summary[key] = round(float(value), 2) if value is not None else None
                elif key == "requests":
                    summary[key] = int(value or 0)

        try:
            rows = conn.execute(
                f"""
                SELECT COALESCE(model, '') AS model, COUNT(*) AS requests,
                       SUM(CASE WHEN outcome IN ('succeeded','completed') OR success=1 THEN 1 ELSE 0 END) AS succeeded,
                       SUM(CASE WHEN (completed_at IS NOT NULL OR (outcome IS NOT NULL AND outcome!='in_flight')) AND COALESCE(success,0)=0 THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN usage_reported=1 THEN total_tokens ELSE NULL END) AS total_tokens
                FROM api_usage_logs WHERE {where}
                GROUP BY COALESCE(model, '') ORDER BY requests DESC, model
                """,
                args,
            ).fetchall()
            by_model = [
                {"model": row["model"] or None, "requests": int(row["requests"] or 0), "succeeded": int(row["succeeded"] or 0), "failed": int(row["failed"] or 0), "total_tokens": int(row["total_tokens"]) if row["total_tokens"] is not None else None}
                for row in rows
            ]
            rows = conn.execute(
                f"""
                SELECT substr(COALESCE(started_at, created_at), 1, 10) AS day,
                       COUNT(*) AS requests,
                       SUM(CASE WHEN outcome IN ('succeeded','completed') OR success=1 THEN 1 ELSE 0 END) AS succeeded,
                       SUM(CASE WHEN (completed_at IS NOT NULL OR (outcome IS NOT NULL AND outcome!='in_flight')) AND COALESCE(success,0)=0 THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN usage_reported=1 THEN total_tokens ELSE NULL END) AS total_tokens
                FROM api_usage_logs WHERE {where}
                GROUP BY day ORDER BY day
                """,
                args,
            ).fetchall()
            daily = [
                {"day": row["day"], "requests": int(row["requests"] or 0), "succeeded": int(row["succeeded"] or 0), "failed": int(row["failed"] or 0), "total_tokens": int(row["total_tokens"]) if row["total_tokens"] is not None else None}
                for row in rows
            ]
            rows = conn.execute(
                f"""
                SELECT id, created_at, request_id, protocol, model, streamed,
                       outcome, status_code, response_time_ms, first_byte_ms,
                       input_tokens, output_tokens, total_tokens, usage_reported,
                       credit_status, credit_charged_units
                FROM api_usage_logs WHERE {where}
                ORDER BY COALESCE(started_at, created_at) DESC, id DESC LIMIT 100
                """,
                args,
            ).fetchall()
            recent = [dict(row) for row in rows]
            from app.credit_ledger import units_to_credits
            for item in recent:
                item["charged_credits"] = units_to_credits(item["credit_charged_units"] or 0)
        except sqlite3.DatabaseError:
            # An old read-only database can still serve the zero summary while
            # it is awaiting startup migration.
            pass
    return {"summary": summary, "by_model": by_model, "daily": daily, "recent": recent}


__all__ = [
    "QuotaRejection",
    "UsageReservation",
    "SSEUsageParser",
    "complete_usage",
    "extract_json_usage",
    "extract_usage",
    "get_key_models",
    "insert_usage",
    "model_allowed",
    "quota_rejection",
    "read_usage_summary",
    "reserve_usage",
]
