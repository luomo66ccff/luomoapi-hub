"""Owner-bound unmetered admission, real gateway routes, and SQLite audit.

Run from implementation: python -m unittest discover -s tests.
All keys, upstream responses, and databases are isolated local fixtures.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import time
import unittest
from contextlib import closing
from unittest.mock import patch

import test_credit_gateway as fixture

from app.admin_key_policy import ADMIN_UNMETERED_SCOPE
from app.ai_usage import reserve_usage


gateway = importlib.import_module("app.cliproxy_gateway")
UNKNOWN_MODEL = "fixture-unpriced-model"


class AdminUnmeteredTests(unittest.TestCase):
    # Reuse the integration fixture without inheriting/rerunning its tests.
    setUp = fixture.CreditGatewayTests.setUp
    cleanup = fixture.CreditGatewayTests.cleanup
    open_database = fixture.CreditGatewayTests.open_database
    register_and_login = fixture.CreditGatewayTests.register_and_login
    issue_key = fixture.CreditGatewayTests.issue_key
    fund = fixture.CreditGatewayTests.fund
    request_payload = fixture.CreditGatewayTests.request_payload
    generate = fixture.CreditGatewayTests.generate
    accounting = fixture.CreditGatewayTests.accounting
    overrun_receipt = fixture.CreditGatewayTests.overrun_receipt

    async def upstream(self, request):
        if request.method == "GET":
            self.calls.append({"path": request.url.path, "body": None})
            return fixture.httpx.Response(200, json={"object": "list", "data": [
                {"id": fixture.MODEL}, {"id": UNKNOWN_MODEL}]}, request=request)
        return await fixture.CreditGatewayTests.upstream(self, request)

    def update(self, sql, params=()):
        with closing(self.open_database()) as conn, conn:
            conn.execute(sql, params)

    def configure(self, *, exempt=True, role="admin", status="active"):
        self.update("UPDATE users SET role=?,status=? WHERE id=?", (role, status, self.user_id))
        scopes = fixture.SELF_SCOPES + (" " + ADMIN_UNMETERED_SCOPE if exempt else "")
        self.update("""UPDATE api_keys SET scopes=?,status='active',expires_at=NULL,model_policy='all',
                       rate_limit_per_minute=0,daily_quota=0,monthly_quota=0 WHERE id=?""", (scopes, self.key_id))
        self.update("DELETE FROM api_key_models WHERE api_key_id=?", (self.key_id,))

    def money_state(self):
        with closing(self.open_database()) as conn:
            return {table: [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
                    for table in ("credit_wallets", "credit_holds", "credit_ledger", "credit_admin_audit")}

    def usage_rows(self):
        with closing(self.open_database()) as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM api_usage_logs ORDER BY id")]

    def models(self):
        return self.client.get("/v1/models", headers={"Authorization": "Bearer " + self.key})

    def post(self, protocol, payload):
        endpoint = "/v1/chat/completions" if protocol == "chat" else "/v1/responses"
        return self.client.post(endpoint, json=payload, headers={"Authorization": "Bearer " + self.key})

    def assert_exempt_audit(self, *, outcome="succeeded", reported=True):
        row = self.usage_rows()[-1]
        self.assertEqual((row["credit_status"], row["credit_reserved_units"], row["credit_charged_units"]),
                         ("admin_exempt", 0, 0))
        self.assertIn(ADMIN_UNMETERED_SCOPE, row["credit_reason"])
        self.assertEqual(row["outcome"], outcome)
        self.assertIsNotNone(row["completed_at"])
        self.assertEqual(row["usage_reported"], int(reported))
        if reported:
            self.assertEqual((row["input_tokens"], row["output_tokens"], row["total_tokens"]), (100, 5, 105))
            self.assertIsInstance(json.loads(row["credit_usage_json"]), dict)
        return row

    def reserve(self, *, expected=True, key_row=None, quote=None, protocol="chat.completions"):
        with closing(self.open_database()) as conn:
            return reserve_usage(conn, key_row or {"id": self.key_id}, request_id="fixture-reservation",
                                 protocol=protocol, model=fixture.MODEL, streamed=False, method="POST",
                                 public_path="v1/chat/completions", require_private_grant=True,
                                 private_scope="chat:completions", model_id=fixture.MODEL,
                                 billing_quote=quote, expected_admin_unmetered=expected)

    def test_priced_and_unpriced_json_preserves_payload_and_zero_wallet(self):
        self.configure()
        self.update("DELETE FROM credit_wallets WHERE user_id=?", (self.user_id,))
        before = self.money_state()
        for protocol in ("chat", "responses"):
            for model in (fixture.MODEL, UNKNOWN_MODEL):
                with self.subTest(protocol=protocol, model=model):
                    payload = self.request_payload(protocol)
                    payload.update(model=model, service_tier="priority", n=2, store=True,
                                   previous_response_id="fixture-context", modalities=["text", "audio"],
                                   tools=[{"type": "web_search"}])
                    limit = "max_completion_tokens" if protocol == "chat" else "max_output_tokens"
                    payload[limit] = 50000
                    self.response_json = fixture.chat_response() if protocol == "chat" else fixture.responses_response()
                    self.response_json["model"] = model
                    response = self.post(protocol, payload)
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(self.calls[-1]["body"], payload)
                    self.assert_exempt_audit()
                    self.assertEqual(self.money_state(), before)

    def test_sse_both_protocols_keep_usage_without_price_or_cache_breakdown(self):
        self.configure()
        before = self.money_state()
        for protocol in ("chat", "responses"):
            for model in (fixture.MODEL, UNKNOWN_MODEL):
                with self.subTest(protocol=protocol, model=model):
                    if protocol == "chat":
                        receipt = {"model": model, "choices": [], "usage": {
                            "prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}}
                        self.response_sse = fixture.sse_event(receipt) + fixture.sse_event("[DONE]")
                    else:
                        receipt = {"type": "response.completed", "response": {
                            "model": model, "status": "completed", "usage": {
                                "input_tokens": 100, "output_tokens": 5, "total_tokens": 105}}}
                        self.response_sse = fixture.sse_event(receipt)
                    payload = self.request_payload(protocol, stream=True)
                    payload["model"] = model
                    response = self.post(protocol, payload)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.content, self.response_sse)
                    if protocol == "chat":
                        self.assertTrue(self.calls[-1]["body"]["stream_options"]["include_usage"])
                    self.assert_exempt_audit()
                    self.assertEqual(self.money_state(), before)

    def test_exempt_requests_do_not_invent_output_or_processing_limits(self):
        self.configure()
        for protocol in ("chat", "responses"):
            payload = {"model": UNKNOWN_MODEL, "messages": []} if protocol == "chat" else {"model": UNKNOWN_MODEL, "input": "x"}
            self.assertEqual(self.post(protocol, payload).status_code, 200)
            self.assertEqual(self.calls[-1]["body"], payload)

    def test_models_all_and_allowlist_endpoint_grants_still_apply(self):
        self.configure()
        self.assertEqual({item["id"] for item in self.models().json()["data"]}, {fixture.MODEL, UNKNOWN_MODEL})
        self.update("UPDATE api_keys SET model_policy='allowlist' WHERE id=?", (self.key_id,))
        self.update("INSERT INTO api_key_models(api_key_id,model_id) VALUES (?,?)", (self.key_id, fixture.MODEL))
        self.assertEqual([item["id"] for item in self.models().json()["data"]], [fixture.MODEL])
        payload = self.request_payload()
        payload["model"] = UNKNOWN_MODEL
        self.assertEqual(self.post("chat", payload).status_code, 403)
        self.assertEqual(self.generate().status_code, 200)
        self.update("UPDATE api_keys SET scopes=?,allowed_routes='' WHERE id=?", (ADMIN_UNMETERED_SCOPE, self.key_id))
        self.assertEqual(self.models().status_code, 403)
        self.assertEqual(self.generate().status_code, 403)
        self.assertEqual(self.generate("responses").status_code, 403)

    def test_old_admin_key_still_needs_funds_and_billable_shapes(self):
        self.configure(exempt=False)
        self.assertEqual(self.generate().status_code, 402)
        self.fund()
        payload = self.request_payload()
        payload["max_completion_tokens"] = 50000
        self.assertEqual(self.post("chat", payload).status_code, 400)
        payload.update(model=UNKNOWN_MODEL, max_completion_tokens=8)
        self.assertEqual(self.post("chat", payload).status_code, 400)
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(self.generate().status_code, 200)
        self.assertEqual(self.accounting()[0]["credit_status"], "settled")

    def test_known_pending_hold_blocks_ordinary_key_but_exempt_never_changes_money(self):
        self.configure(exempt=False)
        self.response_json, quote, _ = self.overrun_receipt()
        self.fund(quote.amount_units)
        self.assertEqual(self.generate().status_code, 200)
        self.assertEqual(self.generate().status_code, 409)
        self.configure()
        before = self.money_state()
        self.response_json = fixture.chat_response()
        self.assertEqual(self.generate().status_code, 200)
        self.assert_exempt_audit()
        self.assertEqual(self.money_state(), before)
        self.configure(exempt=False)
        self.assertEqual(self.generate().status_code, 409)

    def test_forged_scope_nonadmin_and_inactive_admin_denied_on_all_endpoints(self):
        for role, status in (("developer", "active"), ("admin", "pending"),
                             ("admin", "disabled"), ("admin", "suspended")):
            with self.subTest(role=role, status=status):
                self.configure(role=role, status=status)
                self.assertEqual(self.models().status_code, 403)
                self.assertEqual(self.generate().status_code, 403)
                self.assertEqual(self.generate("responses").status_code, 403)
                self.assertEqual(gateway._revalidate_model(self.key_id, "/v1/chat/completions", fixture.MODEL)[1][0], 403)
                self.assertEqual(self.reserve()[1].status_code, 403)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.usage_rows(), [])

    def test_scope_requires_exact_token(self):
        self.configure(exempt=False)
        for scope in ("admin:*", "admin:unmetered-extra", "prefix-admin:unmetered", "ADMIN:UNMETERED"):
            self.update("UPDATE api_keys SET scopes=? WHERE id=?", (fixture.SELF_SCOPES + " " + scope, self.key_id))
            self.assertEqual(self.generate().status_code, 402)
        self.assertEqual(self.calls, [])

    def test_expired_and_revoked_keys_remain_denied(self):
        self.configure()
        for expiry in ("2000-01-01T00:00:00+00:00", "invalid"):
            self.update("UPDATE api_keys SET expires_at=? WHERE id=?", (expiry, self.key_id))
            self.assertEqual(self.models().status_code, 403)
            self.assertEqual(self.generate().status_code, 403)
        self.update("UPDATE api_keys SET expires_at=NULL,status='revoked' WHERE id=?", (self.key_id,))
        self.assertEqual(self.generate().status_code, 401)
        self.assertEqual(self.reserve()[1].status_code, 403)
        self.assertEqual(self.calls, [])

    def test_scope_changes_after_auth_and_before_reservation_fail_closed(self):
        for hook in ("_load_authorization", "_reserve_gateway_usage"):
            for initial in (False, True):
                for protocol in ("chat", "responses", "models"):
                    with self.subTest(hook=hook, initial=initial, protocol=protocol):
                        self.configure(exempt=initial)
                        original = getattr(gateway, hook)
                        def mutate(*args, **kwargs):
                            if hook == "_load_authorization":
                                result = original(*args, **kwargs)
                                self.configure(exempt=not initial)
                                return result
                            self.configure(exempt=not initial)
                            return original(*args, **kwargs)
                        with patch.object(gateway, hook, side_effect=mutate):
                            response = self.models() if protocol == "models" else self.generate(protocol)
                        self.assertEqual(response.status_code, 403, response.text)
                        self.assertEqual(response.json()["error"]["code"], "authorization_changed")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.usage_rows(), [])

    def test_fresh_reservation_rejects_mutable_owner_key_and_model_policy(self):
        mutations = (
            ("UPDATE users SET role='developer' WHERE id=?", (self.user_id,)),
            ("UPDATE users SET status='pending' WHERE id=?", (self.user_id,)),
            ("UPDATE users SET status='disabled' WHERE id=?", (self.user_id,)),
            ("UPDATE api_keys SET status='revoked' WHERE id=?", (self.key_id,)),
            ("UPDATE api_keys SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (self.key_id,)),
            ("UPDATE api_keys SET scopes='admin:unmetered' WHERE id=?", (self.key_id,)),
            ("UPDATE api_keys SET model_policy='allowlist' WHERE id=?", (self.key_id,)),
        )
        for sql, params in mutations:
            with self.subTest(sql=sql):
                self.configure()
                original = gateway._reserve_gateway_usage
                def mutate(*args, **kwargs):
                    self.update(sql, params)
                    return original(*args, **kwargs)
                with patch.object(gateway, "_reserve_gateway_usage", side_effect=mutate):
                    response = self.generate()
                self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.usage_rows(), [])

    def test_reservation_cannot_trust_forged_dict_or_implicitly_exempt_old_caller(self):
        forged = {"id": self.key_id, "scopes": ADMIN_UNMETERED_SCOPE, "user_role": "admin",
                  "user_status": "active", "admin_unmetered": True}
        self.configure(exempt=False)
        self.assertEqual(self.reserve(key_row=forged)[1].code, "authorization_changed")
        self.assertEqual(self.reserve(expected=False, key_row=forged)[1].code, "billing_quote_missing")
        self.configure(role="developer")
        self.assertEqual(self.reserve(key_row=forged)[1].status_code, 403)
        self.configure()
        self.assertEqual(self.reserve(expected=None)[1].code, "authorization_changed")
        self.assertEqual(self.usage_rows(), [])

    def test_generic_json_validation_remains_enforced(self):
        self.configure()
        for payload in ([], {"model": ""}, {"model": "x", "stream": "yes"}, {"model": 2}):
            self.assertEqual(self.post("chat", payload).status_code, 400)
        response = self.client.post("/v1/chat/completions", content='{"model":"x","n":NaN}',
                                    headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.calls, [])

    def test_request_and_response_byte_bounds_still_apply(self):
        self.configure()
        response = self.client.post("/v1/chat/completions", content='{"model":"x"}', headers={
            "Authorization": "Bearer " + self.key, "Content-Type": "application/json",
            "Content-Length": str(gateway.MAX_REQUEST_BYTES + 1)})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.calls, [])
        before = self.money_state()
        with patch.object(gateway, "MAX_RESPONSE_BYTES", 1):
            self.assertEqual(self.generate().status_code, 502)
        self.assert_exempt_audit(outcome="response_too_large", reported=False)
        self.assertEqual(self.money_state(), before)

    def test_upstream_failure_and_missing_usage_keep_exempt_audit(self):
        self.configure()
        before = self.money_state()
        self.response_status = 500
        self.assertEqual(self.generate().status_code, 500)
        self.assert_exempt_audit(outcome="failed")
        self.response_status = 200
        self.response_json = {"model": UNKNOWN_MODEL, "choices": []}
        self.assertEqual(self.generate().status_code, 200)
        self.assert_exempt_audit(reported=False)
        self.assertEqual(self.money_state(), before)

    def test_sse_failed_receipts_remain_audited_for_both_protocols(self):
        self.configure()
        before = self.money_state()
        for protocol in ("chat", "responses"):
            if protocol == "chat":
                receipt = {"error": {"code": "upstream_error"}, "usage": {
                    "prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}}
            else:
                receipt = {"type": "response.failed", "response": {"status": "failed", "usage": {
                    "input_tokens": 100, "output_tokens": 5, "total_tokens": 105}}}
            self.response_sse = fixture.sse_event(receipt)
            self.assertEqual(self.generate(protocol, stream=True).status_code, 200)
            self.assert_exempt_audit(outcome="streamerror")
            self.assertEqual(self.money_state(), before)

    def test_stream_disconnect_retains_usage_and_never_mutates_wallet(self):
        self.configure()
        before = self.money_state()
        for protocol in ("chat.completions", "responses"):
            with self.subTest(protocol=protocol):
                reservation, rejection = self.reserve(protocol=protocol)
                self.assertIsNone(rejection)
                if protocol == "chat.completions":
                    receipt = {"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}}
                    events = fixture.sse_event(receipt) + fixture.sse_event("[DONE]")
                else:
                    receipt = {"type": "response.completed", "response": {"usage": {
                        "input_tokens": 100, "output_tokens": 5, "total_tokens": 105}}}
                    events = fixture.sse_event(receipt)
                body = fixture.sse_event({"choices": [{"delta": {"content": "first"}}]}) + events
                async def disconnect():
                    upstream = fixture.httpx.Response(200, headers={"content-type": "text/event-stream"},
                                                       stream=fixture.FixtureStream(body))
                    relay = gateway._relay_stream(upstream, None, reservation=reservation, key_row={"id": self.key_id},
                                                  request_id=reservation.request_id, protocol=protocol,
                                                  started=time.monotonic(), payload={"stream": True}, sse_expected=True)
                    await anext(relay)
                    await relay.aclose()
                    self.assertTrue(upstream.is_closed)
                asyncio.run(disconnect())
                self.assert_exempt_audit(outcome="client_disconnect")
                self.assertEqual(self.money_state(), before)


if __name__ == "__main__":
    unittest.main()
