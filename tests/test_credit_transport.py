import asyncio
import json
import time
import unittest
from unittest.mock import AsyncMock, patch
import httpx
from app.cliproxy_gateway import _relay_stream, MeteredStreamingResponse, _explicit_generation_rejection
from app.ai_usage import SSEUsageParser


class LiveChunks(httpx.AsyncByteStream):
    def __init__(self):
        self.closed=False
        self.second=asyncio.Event()
    async def __aiter__(self):
        yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
        await self.second.wait()
        yield b'data: [DONE]\n\n'
    async def aclose(self):
        self.closed=True


class ReceiptChunks(LiveChunks):
    def __init__(self):
        super().__init__()
        self.reading = asyncio.Event()
        self.iterations = 0
    async def __aiter__(self):
        self.iterations += 1
        yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
        yield b'data: {"choices":[{"finish_reason":"stop"}]}\n\n'
        self.reading.set()
        await self.second.wait()
        receipt = {"model": "gpt-6-luna", "choices": [],
                   "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11,
                             "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
        yield ("data: " + json.dumps(receipt) + "\n\n").encode()
        yield b'data: [DONE]\n\n'


class CreditTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_small_sse_chunk_is_relayed_without_waiting_for_eof(self):
        stream=LiveChunks()
        upstream=httpx.Response(200,headers={"content-type":"text/event-stream"},stream=stream)
        finalizer=AsyncMock()
        with patch("app.cliproxy_gateway.run_in_threadpool",new=finalizer), patch("app.cliproxy_gateway.STREAM_USAGE_GRACE_SECONDS", .02):
            relay=_relay_stream(upstream,None,reservation=object(),key_row={"id":1},request_id="test",protocol="chat.completions",
                started=0,payload={"stream":True},sse_expected=True)
            first=await asyncio.wait_for(anext(relay),.5)
            self.assertIn(b"first",first)
            stream.second.set()
            remainder=[chunk async for chunk in relay]
            self.assertIn(b"[DONE]",b"".join(remainder))
        self.assertTrue(stream.closed)
        self.assertEqual(finalizer.await_count,1)

    async def test_downstream_close_closes_upstream_and_keeps_unknown_usage(self):
        stream=LiveChunks()
        upstream=httpx.Response(200,headers={"content-type":"text/event-stream"},stream=stream)
        finalizer=AsyncMock()
        with patch("app.cliproxy_gateway.run_in_threadpool",new=finalizer), patch("app.cliproxy_gateway.STREAM_USAGE_GRACE_SECONDS", .02):
            relay=_relay_stream(upstream,None,reservation=object(),key_row={"id":1},request_id="test",protocol="chat.completions",
                started=0,payload={"stream":True},sse_expected=True)
            await anext(relay)
            await relay.aclose()
        self.assertTrue(stream.closed)
        self.assertEqual(finalizer.await_count,1)
        kwargs=finalizer.await_args.kwargs
        self.assertEqual(kwargs["outcome"],"client_disconnect")
        self.assertIsNone(kwargs["billing_usage"])
        self.assertFalse(kwargs.get("billing_release",False))

    def relay(self, stream):
        upstream = httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
        return _relay_stream(upstream, None, reservation=object(), key_row={"id": 1}, request_id="test",
                             protocol="chat.completions", started=time.monotonic(), payload={"stream": True}, sse_expected=True)

    async def test_cancel_during_pending_read_recovers_final_usage_once(self):
        stream, finalizer = ReceiptChunks(), AsyncMock()
        with patch("app.cliproxy_gateway.run_in_threadpool", new=finalizer):
            relay = self.relay(stream)
            await anext(relay)
            await anext(relay)
            reading = asyncio.create_task(anext(relay))
            await stream.reading.wait()
            reading.cancel()
            asyncio.get_running_loop().call_later(.02, stream.second.set)
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(reading, .5)
        self.assertTrue(stream.closed)
        self.assertEqual(stream.iterations, 1)
        self.assertEqual(finalizer.await_count, 1)
        self.assertEqual(finalizer.await_args.kwargs["outcome"], "client_disconnect")
        self.assertEqual(finalizer.await_args.kwargs["billing_usage"]["total_tokens"], 11)

    async def test_send_failure_explicitly_closes_and_reconciles_iterator(self):
        stream, finalizer = ReceiptChunks(), AsyncMock()
        stream.second.set()
        sent = []
        async def send(message):
            sent.append(message)
            if message["type"] == "http.response.body":
                raise OSError("fixture client closed")
        with patch("app.cliproxy_gateway.run_in_threadpool", new=finalizer):
            response = MeteredStreamingResponse(self.relay(stream))
            with self.assertRaises(OSError):
                await response.stream_response(send)
        self.assertEqual(sum(m["type"] == "http.response.body" for m in sent), 1)
        self.assertTrue(stream.closed)
        self.assertEqual(stream.iterations, 1)
        self.assertEqual(finalizer.await_count, 1)
        self.assertIsNotNone(finalizer.await_args.kwargs["billing_usage"])

    async def test_asgi_disconnect_scope_preserves_pending_upstream_read(self):
        stream, finalizer = ReceiptChunks(), AsyncMock()
        async def receive():
            await stream.reading.wait()
            asyncio.get_running_loop().call_later(.02, stream.second.set)
            return {"type": "http.disconnect"}
        sent = []
        async def send(message):
            sent.append(message)
            await asyncio.sleep(0)
        with patch("app.cliproxy_gateway.run_in_threadpool", new=finalizer):
            response = MeteredStreamingResponse(self.relay(stream))
            await asyncio.wait_for(response({}, receive, send), .5)
        self.assertTrue(stream.closed)
        self.assertEqual(stream.iterations, 1)
        self.assertEqual(finalizer.await_count, 1)
        self.assertEqual(finalizer.await_args.kwargs["billing_usage"]["total_tokens"], 11)
        self.assertNotIn(b"prompt_tokens", b"".join(m.get("body", b"") for m in sent))

    async def test_receipt_recovery_byte_limit_retains_unknown_hold(self):
        stream, finalizer = ReceiptChunks(), AsyncMock()
        stream.second.set()
        with patch("app.cliproxy_gateway.run_in_threadpool", new=finalizer), patch("app.cliproxy_gateway.STREAM_USAGE_GRACE_BYTES", 1):
            relay = self.relay(stream)
            await anext(relay)
            await relay.aclose()
        self.assertTrue(stream.closed)
        self.assertEqual(finalizer.await_count, 1)
        self.assertIsNone(finalizer.await_args.kwargs["billing_usage"])
        self.assertFalse(finalizer.await_args.kwargs.get("billing_release", False))

    async def test_only_specific_generation_rejection_codes_release(self):
        for payload, status, expected in (
            ({"error": {"code": "model_not_found"}}, 404, True),
            ({"error": {"type": "invalid_request_error"}}, 400, False),
            ({"error": {"code": "model_not_found"}, "choices": [{"message": {"content": "partial"}}]}, 404, False),
            ({"error": {"code": "model_not_found"}, "usage": {}}, 404, False),
            ({"error": {"code": "server_error"}}, 500, False),
        ):
            self.assertEqual(_explicit_generation_rejection(payload, status, "chat.completions"), expected)


if __name__=="__main__":
    unittest.main()
