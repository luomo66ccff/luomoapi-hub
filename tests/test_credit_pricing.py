import json
import unittest
from app.credit_pricing import (PRICE_DATA, PricingError, billing_details,
    billing_receipt_present, calculate_charge, prepare_billable_request, protected_ai_target)
from app.ai_usage import SSEUsageParser


class CreditPricingTests(unittest.TestCase):
    def quote(self, **changes):
        payload = {"model":"gpt-6-luna", "messages":[{"role":"user","content":"hello"}], "max_completion_tokens":64, **changes}
        return prepare_billable_request(payload, protocol="chat.completions")

    def receipt(self, **parts):
        return billing_details({"model":"gpt-6-luna", "usage":{"prompt_tokens":100,"completion_tokens":20,
            "prompt_tokens_details":{"cached_tokens":30,"cache_write_tokens":40,**parts}}}, protocol="chat.completions")

    def test_cache_parts_are_mutually_exclusive_in_input_total(self):
        _, quote = self.quote()
        # ordinary 30*.10 + cache read 30*.01 + cache write 40*.125 + output 20*.50
        self.assertEqual(calculate_charge(quote.snapshot, self.receipt()), 13176)

    def test_proxy_explicit_cache_alias_is_not_double_counted(self):
        details = self.receipt(cached_creation_tokens=40)
        self.assertEqual(details["cache_write_tokens"],40)
        self.assertTrue(details["cache_write_reported"])
        self.assertIsNone(self.receipt(cached_creation_tokens=41))
        body={"usage":{"prompt_tokens":305,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":0,"cached_creation_tokens":0}}}
        details=billing_details(body,protocol="chat.completions")
        _,quote=self.quote()
        self.assertEqual(calculate_charge(quote.snapshot,details),23760)

    def test_missing_cache_breakdown_requires_reconciliation(self):
        _,quote=self.quote()
        for parts in ({"cached_tokens":0},{"cache_write_tokens":0},{}):
            details=billing_details({"usage":{"prompt_tokens":10,"completion_tokens":2,"prompt_tokens_details":parts}},protocol="chat.completions")
            with self.subTest(parts=parts),self.assertRaises(PricingError):
                calculate_charge(quote.snapshot,details)

    def test_invalid_counts_fail_closed(self):
        for value in (True,-1,"1",1.5,10_000_001):
            with self.subTest(value=value):
                self.assertIsNone(self.receipt(cache_write_tokens=value))
        self.assertIsNone(self.receipt(cached_tokens=61))
        self.assertIsNone(billing_details({"usage":{"prompt_tokens":10,"total_tokens":10}},protocol="chat.completions"))

    def test_long_context_threshold_uses_actual_input(self):
        _,quote=self.quote()
        details=self.receipt(cached_tokens=0,cache_write_tokens=0)
        details["input_tokens"]=272000
        self.assertEqual(calculate_charge(quote.snapshot,details),(27200+10)*720)
        details["input_tokens"]=272001
        self.assertEqual(calculate_charge(quote.snapshot,details),39178944)

    def test_snapshot_is_immutable_across_price_changes(self):
        _,quote=self.quote()
        before=calculate_charge(quote.snapshot,self.receipt())
        card=PRICE_DATA["models"]["gpt-6-luna"]
        old=card["input"]
        try:
            card["input"]="999"
            self.assertEqual(calculate_charge(quote.snapshot,self.receipt()),before)
        finally:
            card["input"]=old

    def test_stream_request_forces_usage_and_copies_payload(self):
        outgoing,quote=self.quote(stream=True,stream_options={"include_usage":False})
        self.assertTrue(outgoing["stream_options"]["include_usage"])
        self.assertEqual(outgoing["service_tier"],"default")
        self.assertGreater(quote.amount_units,0)
        response,quote=prepare_billable_request({"model":"gpt-6-luna","input":"hello","store":True},protocol="responses")
        self.assertFalse(response["store"])
        self.assertEqual(response["max_output_tokens"],2048)

    def test_hidden_context_and_nontext_rejected_before_reserve(self):
        shapes=[{"previous_response_id":"resp_x"},{"conversation":"conv_x"},{"prompt":{"id":"pmpt_x"}},
            {"input":[{"type":"item_reference","id":"msg_x"}]},{"background":True},
            {"tools":[{"type":"web_search"}]},{"input":[{"type":"input_image","image_url":"https://example.test/i.png"}]},
            {"n":2},{"service_tier":"priority"},{"max_output_tokens":8193}]
        for shape in shapes:
            with self.subTest(shape=shape),self.assertRaises(PricingError):
                prepare_billable_request({"model":"gpt-6-luna","input":"hello",**shape},protocol="responses")

    def test_model_and_tier_mismatch_require_review(self):
        _,quote=self.quote()
        for changes in ({"model":"gpt-6-astra"},{"service_tier":"priority"}):
            with self.subTest(changes=changes),self.assertRaises(PricingError):
                calculate_charge(quote.snapshot,{**self.receipt(),**changes})

    def test_partial_and_invalid_receipts_cannot_be_released_as_no_usage(self):
        for usage in ({"prompt_tokens":100,"total_tokens":100},{"prompt_tokens":"invalid"},{}):
            self.assertTrue(billing_receipt_present({"usage":usage},protocol="chat.completions"))
        self.assertFalse(billing_receipt_present({"usage":None},protocol="chat.completions"))
        self.assertFalse(billing_receipt_present({"choices":[{"message":{"usage":{}}}]},protocol="chat.completions"))

    def test_sse_partial_failed_receipt_is_seen(self):
        parser=SSEUsageParser(protocol="responses")
        event={"type":"response.failed","response":{"model":"gpt-6-luna","usage":{"input_tokens":100,"total_tokens":100}}}
        encoded=("data: "+json.dumps(event)+"\n\n").encode()
        for chunk in (encoded[:15],encoded[15:]):
            parser.feed(chunk)
        parser.finish()
        self.assertTrue(parser.billing_receipt_seen)
        self.assertTrue(parser.error)
        self.assertIsNone(parser.billing_usage)

    def test_conflicting_token_aliases_and_totals_are_not_billable(self):
        base = {"prompt_tokens": 100, "completion_tokens": 20,
                "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
        for changes in ({"input_tokens": 99}, {"output_tokens": 19},
                        {"total_tokens": 119}, {"total_tokens": True},
                        {"input_tokens_details": {"cached_tokens": 1, "cache_write_tokens": 0}}):
            with self.subTest(changes=changes):
                self.assertIsNone(billing_details({"usage": {**base, **changes}}, protocol="chat.completions"))
        matching = {**base, "input_tokens": 100, "output_tokens": 20, "total_tokens": 120,
                    "input_tokens_details": dict(base["prompt_tokens_details"])}
        self.assertIsNotNone(billing_details({"usage": matching}, protocol="chat.completions"))

    def test_interim_usage_is_not_a_final_stream_bill(self):
        parser = SSEUsageParser(protocol="chat.completions")
        event = {"model": "gpt-6-luna", "choices": [{"delta": {"content": "partial"}, "finish_reason": None}],
                 "usage": {"prompt_tokens": 10, "completion_tokens": 1,
                           "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
        parser.feed(("data: " + json.dumps(event) + "\n\n").encode())
        parser.finish()
        self.assertTrue(parser.billing_receipt_seen)
        self.assertIsNone(parser.billing_usage)
        self.assertFalse(parser.usage[3])

    def test_finish_reason_does_not_hide_later_usage_receipt(self):
        parser = SSEUsageParser(protocol="chat.completions")
        parser.feed(b'data: {"choices":[{"finish_reason":"stop"}]}\n\n')
        self.assertTrue(parser.terminal)
        self.assertFalse(parser.stream_complete)
        event = {"model": "gpt-6-luna", "choices": [],
                 "usage": {"prompt_tokens": 10, "completion_tokens": 1,
                           "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
        parser.feed(("data: " + json.dumps(event) + "\n\ndata: [DONE]\n\n").encode())
        self.assertTrue(parser.stream_complete)
        self.assertEqual(parser.billing_usage["input_tokens"], 10)

    def test_conflicting_final_stream_receipts_remain_unknown(self):
        parser = SSEUsageParser(protocol="chat.completions")
        for tokens in (1, 2):
            event = {"model": "gpt-6-luna", "choices": [],
                     "usage": {"prompt_tokens": 10, "completion_tokens": tokens,
                               "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
            parser.feed(("data: " + json.dumps(event) + "\n\n").encode())
        self.assertTrue(parser.usage_unknown)
        self.assertFalse(parser.usage[3])

    def test_empty_final_receipt_cannot_reuse_an_earlier_bill(self):
        parser = SSEUsageParser(protocol="chat.completions")
        valid = {"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 1,
                  "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
        parser.feed(("data: " + json.dumps(valid) + "\n\n").encode())
        self.assertIsNotNone(parser.billing_usage)
        parser.feed(b'data: {"choices":[],"usage":{}}\n\ndata: [DONE]\n\n')
        self.assertTrue(parser.usage_unknown)
        self.assertFalse(parser.usage[3])

    def test_boolean_cache_detail_alias_is_not_equal_to_integer_alias(self):
        payload = {"usage": {"prompt_tokens": 10, "completion_tokens": 1,
                   "prompt_tokens_details": {"cached_tokens": 1, "cache_write_tokens": 0},
                   "input_tokens_details": {"cached_tokens": True, "cache_write_tokens": 0}}}
        self.assertIsNone(billing_details(payload, protocol="chat.completions"))

    def test_generic_protection_cannot_use_query_or_path_suffix(self):
        for path in ("/v1/responses?x=/models","/v1/%72esponses","/v1/foo/../responses"):
            self.assertTrue(protected_ai_target("http://codex-proxy:8085",path))
        self.assertFalse(protected_ai_target("http://codex-proxy:8085","/v1/models"))


if __name__ == "__main__":
    unittest.main()
