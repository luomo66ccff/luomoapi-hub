"""Late receipts update billing without rewriting transport or manual decisions."""
from contextlib import closing
import unittest
from unittest.mock import AsyncMock, patch

import test_credit_gateway as fixtures
from app.ai_usage import complete_usage
from app.credit_ledger import resolve_credit_hold
from app.credit_pricing import billing_details
from app.cliproxy_gateway import MeteredStreamingResponse


class CreditRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.gateway = fixtures.CreditGatewayTests()
        self.gateway.setUp()
        self.addCleanup(self.gateway.doCleanups)
        self.gateway.fund()
        self.gateway.response_sse = fixtures.sse_event({"model": fixtures.MODEL,
            "choices": [{"delta": {"content": "partial"}, "finish_reason": None}]})
        self.assertEqual(self.gateway.generate(stream=True).status_code, 200)
        self.before = self.gateway.accounting()[0]
        self.usage_id = self.before["id"]
        self.receipt = billing_details(fixtures.chat_response(), protocol="chat.completions")

    def receive(self, receipt):
        with closing(self.gateway.open_database()) as conn:
            return complete_usage(conn, self.usage_id, status_code=200, response_time_ms=1,
                                  first_byte_ms=1, outcome="succeeded", success=True,
                                  billing_usage=receipt)

    def test_late_receipt_settles_and_fills_stats_without_rewriting_transport(self):
        self.assertEqual(self.before["outcome"], "stream_incomplete")
        self.assertTrue(self.receive(self.receipt))
        usage, hold, wallet, ledger = self.gateway.accounting()
        self.assertEqual(hold["status"], "settled")
        self.assertEqual(usage["credit_charged_units"], fixtures.EXPECTED_CHARGE_UNITS)
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["total_tokens"], usage["usage_reported"]), (100, 5, 105, 1))
        for field in ("outcome", "success", "completed_at", "response_time_ms", "first_byte_ms", "error_summary"):
            self.assertEqual(usage[field], self.before[field])
        self.assertEqual(wallet["reserved_units"], 0)
        self.assertEqual(len(self.gateway.calls), 1)
        self.assertEqual(sum(entry["kind"] == "usage_charge" for entry in ledger), 1)

    def test_duplicate_and_conflicting_callbacks_cannot_rewrite_terminal_stats(self):
        self.receive(self.receipt)
        settled = self.gateway.accounting()
        self.receive(self.receipt)
        changed = {**self.receipt, "output_tokens": 10, "total_tokens": 110}
        self.receive(changed)
        self.assertEqual(self.gateway.accounting(), settled)
        self.assertEqual(len(self.gateway.calls), 1)

    def test_manual_release_cannot_be_recharged_by_a_late_receipt(self):
        with closing(self.gateway.open_database()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            resolve_credit_hold(conn, self.usage_id, 0, actor_id=self.gateway.user_id, reason="Explicit fixture waiver")
            conn.commit()
        released = self.gateway.accounting()
        self.receive(self.receipt)
        self.assertEqual(self.gateway.accounting(), released)
        self.assertEqual(released[1]["status"], "released")

    def test_known_unfunded_late_cost_is_visible_and_blocks_more_dispatch(self):
        receipt = {**self.receipt, "output_tokens": 10000, "total_tokens": 10100}
        self.assertTrue(self.receive(receipt))
        usage, hold, wallet, ledger = self.gateway.accounting()
        self.assertEqual(hold["status"], "reconciliation_required")
        self.assertGreater(wallet["risk_units"], 0)
        self.assertEqual(wallet["available_units"], wallet["balance_units"] - wallet["reserved_units"] - wallet["risk_units"])
        data = self.gateway.client.get("/api/developer/credits").json()
        self.assertEqual(data["wallet"]["available_units"], wallet["available_units"])
        self.gateway.response_sse = None
        self.assertEqual(self.gateway.generate().status_code, 409)
        self.assertEqual(len(self.gateway.calls), 1)
        self.assertFalse(any(entry["kind"] == "usage_charge" for entry in ledger))

    def test_valid_late_receipt_replaces_only_partial_unpriced_token_statistics(self):
        # A complete token total can still be unpriceable when cache details
        # are missing. A later complete bill must replace those partial stats.
        self.gateway.response_sse = None
        self.gateway.response_json = {"model": fixtures.MODEL,
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}
        self.assertEqual(self.gateway.generate().status_code, 200)
        self.before = self.gateway.accounting()[0]
        self.usage_id = self.before["id"]
        self.assertEqual(self.before["total_tokens"], 12)
        self.assertTrue(self.receive(self.receipt))
        usage, hold, wallet, ledger = self.gateway.accounting()
        self.assertEqual(usage["total_tokens"], 105)
        self.assertEqual(usage["completed_at"], self.before["completed_at"])
        self.assertEqual(hold["status"], "settled")

    def test_failed_header_send_finalizes_a_never_started_stream(self):
        original = MeteredStreamingResponse.stream_response
        async def fail_headers(response, send):
            async def disconnected(message):
                raise OSError("Fixture disconnect before response headers")
            await original(response, disconnected)
        closer = AsyncMock()
        with patch.object(MeteredStreamingResponse, "stream_response", new=fail_headers), patch.object(fixtures.FixtureStream, "aclose", new=closer):
            try:
                response = self.gateway.generate(stream=True)
            except ExceptionGroup:
                pass
            else:
                self.assertGreaterEqual(response.status_code, 400, "Unexpected successful response after failed header send")
        usage, hold, wallet, ledger = self.gateway.accounting()
        self.assertEqual(usage["outcome"], "client_disconnect")
        self.assertIsNotNone(usage["completed_at"])
        self.assertEqual(hold["status"], "reconciliation_required")
        self.assertEqual(usage["credit_charged_units"], 0)
        self.assertEqual(len(self.gateway.calls), 2)
        self.assertEqual(closer.await_count, 1)


if __name__ == "__main__":
    unittest.main()
