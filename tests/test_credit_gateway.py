"""Real application routes with temporary SQLite and mocked upstream HTTP.

Run with unittest discovery. No production database, email, DNS, account or
network is used; all issued credentials and response bodies are test fixtures.
"""
from __future__ import annotations

import asyncio
import atexit
import gc
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

# These must precede app imports, including when this module runs by itself.
_import_directory = tempfile.TemporaryDirectory(prefix="credit-gateway-import-")
def _cleanup_import_fixture():
    # SQLite cursors/connections can form cycles. Collect them before Windows
    # removes the import fixture shared by discovery of the older test module.
    gc.collect()
    _import_directory.cleanup()
atexit.register(_cleanup_import_fixture)
os.environ.update(
    DATABASE_PATH=str(Path(_import_directory.name) / "import.sqlite"),
    APP_ENV="test",
    APP_BASE_URL="https://api.example.test",
    SESSION_SECRET="credit-gateway-fixture-session-secret-more-than-32-characters",
    SMTP_HOST="",
    SMTP_USERNAME="",
    SMTP_PASSWORD="",
    ADMIN_PASSWORD_HASH="",
    CODEXPROXY_BASE_URL="https://upstream.example.test",
    CODEXPROXY_API_KEY="mock-upstream-key-never-used-on-a-network",
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from fastapi.testclient import TestClient

from app import config, db, main
from app.ai_usage import complete_usage
from app.credit_ledger import add_credit, resolve_credit_hold, wallet_snapshot
from app.credit_payments import claim_order, topup_nonce
from app.credit_pricing import billing_details, calculate_charge, prepare_billable_request
from app.http_clients import create_http_client
from app.self_service_keys import SELF_SCOPES

BASE_URL = "https://api.example.test"
MODEL = "gpt-6.1-sol"
FUND_UNITS = 20_000_000
# Official fixture card: 70 ordinary*2 + 20 cached*0.1 + 10 writes*2.5
# + 5 output*10 = 217 USD/million-token weighted units; times 720 = 156240.
EXPECTED_CHARGE_UNITS = 156_240
PASSWORD = "isolated-gateway-test-password"


class FixtureStream(httpx.AsyncByteStream):
    """Split SSE across arbitrary byte boundaries, including inside JSON."""
    def __init__(self, body: bytes):
        self.body = body

    async def __aiter__(self):
        for offset in range(0, len(self.body), 23):
            yield self.body[offset:offset + 23]
            await asyncio.sleep(0)


def chat_usage(*, alias=False):
    return {
        "prompt_tokens": 100,
        "completion_tokens": 5,
        "total_tokens": 105,
        "prompt_tokens_details": {
            "cached_tokens": 20,
            "cached_creation_tokens" if alias else "cache_write_tokens": 10,
        },
    }


def responses_usage():
    return {
        "input_tokens": 100,
        "output_tokens": 5,
        "total_tokens": 105,
        "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 10},
    }


def chat_response(*, alias=False):
    return {
        "id": "chatcmpl_fixture",
        "object": "chat.completion",
        "model": MODEL,
        "service_tier": "default",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture reply"}, "finish_reason": "stop"}],
        "usage": chat_usage(alias=alias),
    }


def responses_response():
    return {
        "id": "resp_fixture",
        "object": "response",
        "status": "completed",
        "model": MODEL,
        "service_tier": "default",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "fixture reply"}]}],
        "usage": responses_usage(),
    }


def sse_event(payload, event=None):
    prefix = f"event: {event}\n" if event else ""
    value = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    return (prefix + "data: " + value + "\n\n").encode()


class CreditGatewayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="credit-gateway-test-")
        self.path = Path(self.directory.name) / "gateway.sqlite"
        self.stack = ExitStack()
        self.connections = []
        self.client_context = None
        self.addCleanup(self.cleanup)
        self.calls = []
        self.calls_lock = threading.Lock()
        self.outbound_started = threading.Event()
        self.allow_completion = threading.Event()
        self.pause_outbound = False
        self.response_status = 200
        self.response_json = chat_response()
        self.response_sse = None

        original_settings = config.settings
        original_connect = db.connect
        isolated_settings = replace(original_settings, database_path=self.path,
                                    app_env="test", app_base_url=BASE_URL,
                                    session_secret=os.environ["SESSION_SECRET"],
                                    smtp_host="", smtp_username="", smtp_password="",
                                    admin_password_hash="")
        # Imported aliases must all point at this test's SQLite database. This
        # also lets the suite coexist with other test modules imported first.
        for module in list(sys.modules.values()):
            name = getattr(module, "__name__", "")
            if not name.startswith(("app.", "scripts.")):
                continue
            if getattr(module, "settings", None) is original_settings:
                self.stack.enter_context(patch.object(module, "settings", isolated_settings))
            if getattr(module, "connect", None) is original_connect:
                self.stack.enter_context(patch.object(module, "connect", self.open_database))
        self.stack.enter_context(patch.dict(os.environ, {
            "DATABASE_PATH": str(self.path), "APP_BASE_URL": BASE_URL,
            "SESSION_SECRET": isolated_settings.session_secret,
            "CODEXPROXY_BASE_URL": "https://upstream.example.test",
            "CODEXPROXY_API_KEY": "mock-upstream-key-never-used-on-a-network",
            "SMTP_HOST": "", "SMTP_USERNAME": "", "SMTP_PASSWORD": "",
        }))
        self.stack.enter_context(patch.object(main, "seed", return_value=None))
        self.stack.enter_context(patch.object(main, "send_verification_email", return_value=None))
        self.stack.enter_context(patch.object(main, "create_http_client",
            side_effect=lambda timeout: create_http_client(timeout, transport=httpx.MockTransport(self.upstream))))
        self.client_context = TestClient(main.app, base_url=BASE_URL, follow_redirects=False)
        self.client = self.client_context.__enter__()
        self.register_and_login()
        self.key, self.key_id, _, _ = self.issue_key("fixture-key")

    def cleanup(self):
        self.allow_completion.set()
        try:
            if self.client_context is not None:
                self.client_context.__exit__(None, None, None)
        finally:
            self.stack.close()
            # Some existing main routes use connection contexts without closing
            # their handles. Only fixture-owned handles are reclaimed here.
            for conn in self.connections:
                conn.close()
            self.directory.cleanup()

    def open_database(self):
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        self.connections.append(conn)
        return conn

    async def upstream(self, request):
        self.assertEqual(request.url.host, "upstream.example.test")
        self.assertEqual(request.headers["authorization"], "Bearer mock-upstream-key-never-used-on-a-network")
        with self.calls_lock:
            self.calls.append({"path": request.url.path, "body": json.loads(request.content)})
        self.outbound_started.set()
        if self.pause_outbound:
            released = await asyncio.to_thread(self.allow_completion.wait, 10)
            if not released:
                raise AssertionError("Timed out waiting for concurrent test completion")
        if self.response_sse is not None:
            return httpx.Response(self.response_status, headers={"content-type": "text/event-stream"},
                                  stream=FixtureStream(self.response_sse), request=request)
        return httpx.Response(self.response_status, json=self.response_json, request=request)

    def register_and_login(self):
        response = self.client.post("/register", data={
            "username": "gateway_developer", "email": "gateway@example.test",
            "password": PASSWORD, "confirm_password": PASSWORD, "usage_reason": "isolated test",
        })
        self.assertEqual(response.status_code, 200, response.text[:200])
        with closing(self.open_database()) as conn:
            user = conn.execute("SELECT * FROM users WHERE username='gateway_developer'").fetchone()
        self.assertIsNotNone(user)
        self.assertEqual((user["role"], user["status"], user["email_verified"]), ("developer", "active", 0))
        self.user_id = user["id"]
        response = self.client.post("/login", data={"username": "gateway_developer", "password": PASSWORD},
                                    headers={"Origin": BASE_URL})
        self.assertEqual(response.status_code, 303)

    def issue_key(self, name):
        page = self.client.get("/developer/keys")
        self.assertEqual(page.status_code, 200)
        match = re.search(r'name="key_nonce"\s+value="([^"]+)"', page.text)
        self.assertIsNotNone(match)
        nonce = match.group(1)
        fields = {"name": name, "key_nonce": nonce}
        response = self.client.post("/developer/keys/request", data=fields, headers={"Origin": BASE_URL})
        self.assertEqual(response.status_code, 200, response.text[:200])
        raw = re.search(r"lapi_[A-Za-z0-9_-]{43}", response.text)
        self.assertIsNotNone(raw)
        with closing(self.open_database()) as conn:
            key_id = conn.execute("SELECT MAX(id) FROM api_keys WHERE user_id=?", (self.user_id,)).fetchone()[0]
        return raw.group(), key_id, fields, response

    def fund(self, amount=FUND_UNITS):
        with closing(self.open_database()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            add_credit(conn, self.user_id, amount, reference="gateway-fixture-funding",
                       actor_id=None, kind="test_funding", note="Isolated gateway fixture")

    def request_payload(self, protocol="chat", *, stream=False):
        if protocol == "chat":
            payload = {"model": MODEL, "messages": [{"role": "user", "content": "fixture input"}],
                       "max_completion_tokens": 8}
        else:
            payload = {"model": MODEL, "input": "fixture input", "max_output_tokens": 8}
        if stream:
            payload["stream"] = True
        return payload

    def generate(self, protocol="chat", *, stream=False, key=None):
        path = "/v1/chat/completions" if protocol == "chat" else "/v1/responses"
        return self.client.post(path, json=self.request_payload(protocol, stream=stream),
                                headers={"Authorization": "Bearer " + (key or self.key)})

    def accounting(self):
        with closing(self.open_database()) as conn:
            usage = conn.execute("SELECT * FROM api_usage_logs WHERE user_id=? ORDER BY id DESC LIMIT 1", (self.user_id,)).fetchone()
            hold = conn.execute("SELECT * FROM credit_holds WHERE user_id=? ORDER BY usage_id DESC LIMIT 1", (self.user_id,)).fetchone()
            wallet = wallet_snapshot(conn, self.user_id)
            ledger = [dict(row) for row in conn.execute("SELECT * FROM credit_ledger WHERE user_id=? ORDER BY id", (self.user_id,))]
        return dict(usage) if usage else None, dict(hold) if hold else None, wallet, ledger

    def assert_settled(self, charged=EXPECTED_CHARGE_UNITS, fund=FUND_UNITS):
        usage, hold, wallet, ledger = self.accounting()
        self.assertIsNotNone(usage["completed_at"])
        self.assertEqual(usage["credit_status"], "settled")
        self.assertEqual(usage["credit_charged_units"], charged)
        self.assertEqual((hold["status"], hold["actual_units"], hold["dispatch_state"]), ("settled", charged, "dispatched"))
        self.assertEqual((wallet["balance_units"], wallet["reserved_units"], wallet["available_units"]), (fund - charged, 0, fund - charged))
        self.assertEqual(len([entry for entry in ledger if entry["kind"] == "usage_charge"]), 1)
        self.assertEqual(sum(entry["delta_units"] for entry in ledger), fund - charged)
        self.assertEqual(sum(entry["delta_reserved_units"] for entry in ledger), 0)

    def assert_pending(self):
        usage, hold, wallet, ledger = self.accounting()
        self.assertIsNotNone(usage["completed_at"])
        self.assertEqual((usage["credit_status"], usage["credit_charged_units"]), ("reconciliation_required", 0))
        self.assertEqual((hold["status"], hold["dispatch_state"]), ("reconciliation_required", "dispatched"))
        self.assertEqual(wallet["balance_units"], FUND_UNITS)
        self.assertGreater(wallet["reserved_units"], 0)
        self.assertEqual(wallet["reserved_units"], hold["amount_units"])
        self.assertEqual(wallet["available_units"], FUND_UNITS - hold["amount_units"])
        self.assertFalse(any(entry["kind"] in {"usage_charge", "credit_release"} for entry in ledger))

    def error_receipt(self, usage, *, protocol="chat", nested=False):
        self.fund()
        self.response_status = 400
        self.response_json = {"error": {"type": "invalid_request_error", "message": "fixture rejection"}}
        if nested:
            self.response_json["response"] = {"usage": usage, "model": MODEL}
        else:
            self.response_json["usage"] = usage
        response = self.generate(protocol)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), self.response_json)
        self.assert_pending()

    def test_active_registration_key_is_active_and_nonce_is_idempotent(self):
        raw, key_id, fields, response = self.issue_key("second-key")
        self.assertIn(raw, response.text)
        replay = self.client.post("/developer/keys/request", data=fields, headers={"Origin": BASE_URL})
        self.assertEqual(replay.status_code, 200)
        self.assertNotIn(raw, replay.text)
        self.assertNotIn(raw, self.client.get("/developer/keys").text)
        with closing(self.open_database()) as conn:
            user = conn.execute("SELECT status,email_verified FROM users WHERE id=?", (self.user_id,)).fetchone()
            key = conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
            count = conn.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=?", (self.user_id,)).fetchone()[0]
            grants = {row[0] for row in conn.execute("SELECT model_id FROM api_key_models WHERE api_key_id=?", (key_id,))}
            self.assertNotIn(raw, json.dumps(dict(key)))
        self.assertEqual((user["status"], user["email_verified"]), ("active", 0))
        self.assertEqual((key["status"], key["model_policy"], key["scopes"]), ("active", "allowlist", SELF_SCOPES))
        self.assertIn(MODEL, grants)
        self.assertEqual(count, 2)
        self.assertEqual(replay.headers["cache-control"], "no-store")
        self.assertEqual(self.calls, [])

    def test_legacy_pending_user_can_issue_key_and_generate_without_email_verification(self):
        with closing(self.open_database()) as conn, conn:
            conn.execute("UPDATE users SET status='pending' WHERE id=?", (self.user_id,))
        self.issue_key("legacy-pending-key")
        page = self.client.get("/developer")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("账户等待审核", page.text)
        self.assertIn("可以正常领取密钥和使用 API", page.text)
        self.fund()
        self.assertEqual(self.generate().status_code, 200)
        self.assert_settled()

    def test_insufficient_balance_402_never_reaches_upstream(self):
        response = self.generate()
        self.assertEqual(response.status_code, 402)
        self.assertEqual(response.json()["error"]["code"], "insufficient_credits")
        self.assertEqual(self.calls, [])
        usage, hold, wallet, ledger = self.accounting()
        self.assertIsNone(usage)
        self.assertIsNone(hold)
        self.assertEqual(wallet["balance_units"], 0)
        self.assertEqual(ledger, [])

    def test_successful_chat_json_charges_exact_token_breakdown(self):
        self.fund()
        response = self.generate()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self.response_json)
        self.assert_settled()
        self.assertEqual(self.calls[0]["body"]["service_tier"], "default")

    def test_successful_chat_json_cache_creation_alias_is_not_double_counted(self):
        self.fund()
        self.response_json = chat_response(alias=True)
        # Both equal aliases also represent one write count, rather than two.
        self.response_json["usage"]["prompt_tokens_details"]["cache_write_tokens"] = 10
        response = self.generate()
        self.assertEqual(response.status_code, 200)
        self.assert_settled()

    def test_successful_responses_json_charges_and_disables_storage(self):
        self.fund()
        self.response_json = responses_response()
        response = self.generate("responses")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self.response_json)
        self.assert_settled()
        self.assertIs(self.calls[0]["body"]["store"], False)

    def test_chat_sse_relay_and_final_usage_settlement(self):
        self.fund()
        self.response_sse = (
            sse_event({"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "model": MODEL,
                       "choices": [{"index": 0, "delta": {"content": "fixture reply"}, "finish_reason": None}], "usage": None})
            + sse_event({"model": MODEL, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            + sse_event({"model": MODEL, "choices": [], "usage": chat_usage(alias=True)})
            + sse_event("[DONE]")
        )
        response = self.generate(stream=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.response_sse)
        self.assert_settled()
        self.assertIs(self.calls[0]["body"]["stream_options"]["include_usage"], True)

    def test_responses_sse_relay_and_completed_usage_settlement(self):
        self.fund()
        self.response_sse = (
            sse_event({"type": "response.created", "response": {"id": "resp_fixture", "model": MODEL, "status": "in_progress"}}, "response.created")
            + sse_event({"type": "response.output_text.delta", "delta": "fixture reply"}, "response.output_text.delta")
            + sse_event({"response": responses_response()}, "response.completed")
        )
        response = self.generate("responses", stream=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.response_sse)
        self.assert_settled()

    def test_http400_partial_chat_usage_remains_frozen_and_allows_remaining_balance(self):
        self.error_receipt({"prompt_tokens": 100})
        pending_id=self.accounting()[0]["id"]
        held_amount=self.accounting()[1]["amount_units"]
        self.response_status=200
        self.response_json=chat_response()
        response = self.generate()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.calls), 2)
        with closing(self.open_database()) as conn:
            pending=conn.execute("SELECT * FROM credit_holds WHERE usage_id=?",(pending_id,)).fetchone()
            wallet=wallet_snapshot(conn,self.user_id)
        self.assertEqual((pending["status"],pending["actual_units"]),("reconciliation_required",None))
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"],wallet["available_units"]),
                         (FUND_UNITS-EXPECTED_CHARGE_UNITS,held_amount,FUND_UNITS-EXPECTED_CHARGE_UNITS-held_amount))

    def test_http400_partial_nested_responses_usage_remains_pending(self):
        self.error_receipt({"input_tokens": 100}, protocol="responses", nested=True)

    def test_http400_empty_usage_object_remains_pending(self):
        self.error_receipt({})

    def test_http400_invalid_negative_usage_remains_pending(self):
        invalid = chat_usage()
        invalid["prompt_tokens"] = -1
        self.error_receipt(invalid)

    def test_http400_invalid_usage_type_remains_pending(self):
        self.error_receipt("invalid-usage-fixture")

    def test_http400_conflicting_cache_write_aliases_remain_pending(self):
        invalid = chat_usage()
        invalid["prompt_tokens_details"]["cached_creation_tokens"] = 11
        self.error_receipt(invalid)

    def test_http400_missing_cache_breakdown_remains_pending(self):
        self.error_receipt({"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105})

    def test_http400_without_any_usage_or_rejection_code_retains_freeze(self):
        self.fund()
        self.response_status = 400
        self.response_json = {"error": {"message": "fixture upstream error with unknown billing"}}
        response = self.generate()
        self.assertEqual(response.status_code, 400)
        self.assert_pending()

    def test_explicit_model_not_found_rejection_releases_freeze(self):
        self.fund()
        self.response_status = 404
        self.response_json = {"error": {"code":"model_not_found","message": "fixture model unavailable before generation"}}
        response = self.generate()
        self.assertEqual(response.status_code, 404)
        usage, hold, wallet, ledger = self.accounting()
        self.assertEqual((usage["credit_status"], usage["credit_charged_units"]), ("released", 0))
        self.assertEqual((hold["status"], hold["actual_units"]), ("released", 0))
        self.assertEqual((wallet["balance_units"], wallet["reserved_units"]), (FUND_UNITS, 0))
        self.assertEqual(len([row for row in ledger if row["kind"] == "credit_release"]), 1)
        self.assertFalse(any(row["kind"] == "usage_charge" for row in ledger))

    def test_http400_with_valid_usage_charges_reported_generation(self):
        self.fund()
        self.response_status = 400
        self.response_json = {"error": {"message": "fixture generation ended with an error"}, "model": MODEL, "usage": chat_usage()}
        response = self.generate()
        self.assertEqual(response.status_code, 400)
        self.assert_settled()
        self.assertEqual(self.accounting()[0]["success"], 0)

    def test_http400_sse_with_empty_usage_remains_pending(self):
        self.fund()
        self.response_status = 400
        self.response_sse = sse_event({"error": {"message": "fixture stream error"}, "usage": {}}) + sse_event("[DONE]")
        response = self.generate(stream=True)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, self.response_sse)
        self.assert_pending()

    def test_success_without_usage_retains_freeze(self):
        self.fund()
        self.response_json = {"model": MODEL, "choices": [{"message": {"content": "no usage fixture"}, "finish_reason": "stop"}]}
        self.assertEqual(self.generate().status_code, 200)
        self.assert_pending()

    def test_unknown_freeze_exhausting_balance_returns_402_without_second_outbound(self):
        _,quote=prepare_billable_request(self.request_payload(),protocol="chat.completions")
        self.fund(quote.amount_units)
        self.response_json={"model":MODEL,"choices":[]}
        self.assertEqual(self.generate().status_code,200)
        response=self.generate()
        self.assertEqual(response.status_code,402)
        self.assertEqual(response.json()["error"]["code"],"insufficient_credits")
        self.assertEqual(len(self.calls),1)
        usage,hold,wallet,ledger=self.accounting()
        self.assertEqual((usage["credit_status"],hold["actual_units"]),("reconciliation_required",None))
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"],wallet["available_units"]),
                         (quote.amount_units,quote.amount_units,0))
        self.assertFalse(any(row["kind"] in {"usage_charge","credit_release"} for row in ledger))

    def overrun_receipt(self):
        receipt=chat_response()
        receipt["usage"]["completion_tokens"]=1500
        receipt["usage"]["total_tokens"]=1600
        _,quote=prepare_billable_request(self.request_payload(),protocol="chat.completions")
        actual=calculate_charge(quote.snapshot,billing_details(receipt,protocol="chat.completions"))
        self.assertGreater(actual,quote.amount_units)
        return receipt,quote,actual

    def test_known_overrun_settles_from_unfrozen_available_credit(self):
        self.response_json,_,actual=self.overrun_receipt()
        self.fund()
        self.assertEqual(self.generate().status_code,200)
        self.assert_settled(charged=actual)

    def test_known_unfunded_overrun_blocks_next_request_with_409(self):
        self.response_json,quote,actual=self.overrun_receipt()
        self.fund(quote.amount_units)
        self.assertEqual(self.generate().status_code,200)
        response=self.generate()
        self.assertEqual(response.status_code,409)
        self.assertEqual(response.json()["error"]["code"],"credit_reconciliation_required")
        self.assertEqual(len(self.calls),1)
        usage,hold,wallet,ledger=self.accounting()
        self.assertEqual((usage["credit_status"],hold["actual_units"]),("reconciliation_required",actual))
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"],wallet["risk_units"],wallet["available_units"]),
                         (quote.amount_units,quote.amount_units,actual-quote.amount_units,quote.amount_units-actual))
        self.assertFalse(any(row["kind"] in {"usage_charge","credit_release"} for row in ledger))

    def test_late_complete_usage_recovers_unknown_hold_and_duplicate_never_double_charges(self):
        self.fund()
        self.response_json={"model":MODEL,"choices":[]}
        self.assertEqual(self.generate().status_code,200)
        usage_id=self.accounting()[0]["id"]
        receipt=billing_details(chat_response(),protocol="chat.completions")
        for _ in range(2):
            with closing(self.open_database()) as conn:
                complete_usage(conn,usage_id,status_code=200,response_time_ms=20,first_byte_ms=None,
                               outcome="succeeded",success=True,billing_usage=receipt)
        self.assert_settled()
        usage=self.accounting()[0]
        self.assertEqual((usage["usage_reported"],usage["input_tokens"],usage["output_tokens"],usage["total_tokens"]),(1,100,5,105))

    def test_late_rejection_without_usage_cannot_release_unknown_hold(self):
        self.fund()
        self.response_json={"model":MODEL,"choices":[]}
        self.assertEqual(self.generate().status_code,200)
        usage_id=self.accounting()[0]["id"]
        with closing(self.open_database()) as conn:
            complete_usage(conn,usage_id,status_code=400,response_time_ms=20,first_byte_ms=None,
                           outcome="upstream_error",success=False,billing_release=True)
        self.assert_pending()

    def test_manual_release_remains_terminal_after_late_complete_usage(self):
        self.fund()
        self.response_json={"model":MODEL,"choices":[]}
        self.assertEqual(self.generate().status_code,200)
        usage_id=self.accounting()[0]["id"]
        with closing(self.open_database()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            resolve_credit_hold(conn,usage_id,0,actor_id=self.user_id,reason="audited manual release")
        with closing(self.open_database()) as conn:
            complete_usage(conn,usage_id,status_code=200,response_time_ms=20,first_byte_ms=None,
                           billing_usage=billing_details(chat_response(),protocol="chat.completions"))
        usage,hold,wallet,ledger=self.accounting()
        self.assertEqual((usage["credit_status"],hold["status"],hold["actual_units"]),("released","released",0))
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"]),(FUND_UNITS,0))
        self.assertFalse(any(row["kind"]=="usage_charge" for row in ledger))

    def test_open_payment_review_keeps_409_and_never_reaches_upstream(self):
        self.fund()
        with closing(self.open_database()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            order=claim_order(conn,self.user_id,topup_nonce(self.user_id),100,{"account":"acct_TEST","live":False})
            conn.execute("""INSERT INTO credit_payment_reviews(order_id,charge_id,reason,event_id,state,kind,provider_status,
                            reversal_units,risk_units,created_at,updated_at) VALUES (?,'ch_fixture','fixture dispute','evt_fixture',
                            'open','dispute','needs_response',100000000,100000000,?,?)""",
                         (order["id"],order["created_at"],order["created_at"]))
        response=self.generate()
        self.assertEqual(response.status_code,409)
        self.assertEqual(response.json()["error"]["code"],"payment_reconciliation_required")
        self.assertEqual(self.calls,[])
        self.assertIsNone(self.accounting()[0])

    def test_blocked_user_cannot_generate_or_issue_another_key(self):
        self.fund()
        for user_status in ("disabled", "suspended"):
            with self.subTest(user_status=user_status):
                with closing(self.open_database()) as conn, conn:
                    conn.execute("UPDATE users SET status=? WHERE id=?", (user_status, self.user_id))
                response = self.generate()
                self.assertEqual(response.status_code, 403)
                self.assertEqual(self.calls, [])
                response = self.client.post("/developer/keys/request", data={"name": "blocked", "key_nonce": "invalid"},
                                            headers={"Origin": BASE_URL, "Accept": "application/json"})
                self.assertEqual(response.status_code, 401)
                self.assertIsNone(self.accounting()[0])

    def test_two_keys_share_atomic_balance_while_first_request_is_in_flight(self):
        second_key, _, _, _ = self.issue_key("concurrent-key")
        payload = self.request_payload()
        _, quote = prepare_billable_request(payload, protocol="chat.completions")
        self.assertGreater(quote.amount_units, EXPECTED_CHARGE_UNITS)
        self.fund(quote.amount_units)
        self.pause_outbound = True
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.generate, key=self.key)
            try:
                self.assertTrue(self.outbound_started.wait(5), "First request did not reach mock upstream")
                second = pool.submit(self.generate, key=second_key)
                rejected = second.result(timeout=5)
                self.assertEqual(rejected.status_code, 402)
                self.assertEqual(rejected.json()["error"]["code"], "insufficient_credits")
                self.assertEqual(len(self.calls), 1)
                usage, hold, wallet, _ = self.accounting()
                self.assertIsNone(usage["completed_at"])
                self.assertEqual(hold["status"], "held")
                self.assertEqual((wallet["available_units"], wallet["reserved_units"]), (0, quote.amount_units))
            finally:
                self.allow_completion.set()
            self.assertEqual(first.result(timeout=5).status_code, 200)
        self.assert_settled(fund=quote.amount_units)
        with closing(self.open_database()) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM credit_holds WHERE user_id=?", (self.user_id,)).fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_usage_logs WHERE user_id=?", (self.user_id,)).fetchone()[0], 1)

    def test_unknown_hold_then_concurrent_keys_reserve_remaining_balance_atomically(self):
        second_key,_,_,_=self.issue_key("second-concurrent-key")
        third_key,_,_,_=self.issue_key("third-concurrent-key")
        _,quote=prepare_billable_request(self.request_payload(),protocol="chat.completions")
        self.fund(2*quote.amount_units)
        self.response_json={"model":MODEL,"choices":[]}
        self.assertEqual(self.generate().status_code,200)
        pending_id=self.accounting()[0]["id"]
        self.response_json=chat_response()
        self.pause_outbound=True
        self.outbound_started.clear()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(self.generate,key=second_key)
            try:
                self.assertTrue(self.outbound_started.wait(5))
                rejected=pool.submit(self.generate,key=third_key).result(timeout=5)
                self.assertEqual(rejected.status_code,402)
                self.assertEqual(rejected.json()["error"]["code"],"insufficient_credits")
                self.assertEqual(len(self.calls),2)
                self.assertEqual(self.accounting()[2]["reserved_units"],2*quote.amount_units)
            finally:
                self.allow_completion.set()
            self.assertEqual(first.result(timeout=5).status_code,200)
        with closing(self.open_database()) as conn:
            pending=conn.execute("SELECT * FROM credit_holds WHERE usage_id=?",(pending_id,)).fetchone()
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM api_usage_logs WHERE user_id=?",(self.user_id,)).fetchone()[0],2)
        _,_,wallet,ledger=self.accounting()
        self.assertEqual((pending["status"],pending["actual_units"]),("reconciliation_required",None))
        self.assertEqual((wallet["balance_units"],wallet["reserved_units"],wallet["available_units"]),
                         (2*quote.amount_units-EXPECTED_CHARGE_UNITS,quote.amount_units,quote.amount_units-EXPECTED_CHARGE_UNITS))
        self.assertEqual(len([row for row in ledger if row["kind"]=="usage_charge"]),1)


if __name__ == "__main__":
    unittest.main()
