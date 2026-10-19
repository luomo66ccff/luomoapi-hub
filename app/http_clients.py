"""Pooled upstream HTTP clients that never retain or forward cookies."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from http.cookiejar import CookieJar, DefaultCookiePolicy

import httpx


class _RejectCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False

    def return_ok(self, cookie, request):
        return False


def create_http_client(timeout: httpx.Timeout | float,
                       transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    jar = CookieJar(policy=_RejectCookies())
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        cookies=jar,
        transport=transport,
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=8, keepalive_expiry=20.0),
    )


@asynccontextmanager
async def public_upstream_client(app, hostname: str):
    clients: OrderedDict[str, httpx.AsyncClient] = app.state.public_upstream_clients
    active: dict[str, int] = app.state.public_upstream_clients_active
    lock: asyncio.Lock = app.state.public_upstream_clients_lock
    key = hostname.lower().rstrip(".")
    async with lock:
        client = clients.get(key)
        if client is not None:
            clients.move_to_end(key)
        else:
            client = create_http_client(15.0)
            clients[key] = client
        active[key] = active.get(key, 0) + 1
    try:
        yield client
    finally:
        async with lock:
            active[key] = max(0, active.get(key, 1) - 1)
            while len(clients) > 32:
                stale_key = next((candidate for candidate in clients if active.get(candidate, 0) == 0), None)
                if stale_key is None:
                    break
                stale = clients.pop(stale_key)
                active.pop(stale_key, None)
                await stale.aclose()
