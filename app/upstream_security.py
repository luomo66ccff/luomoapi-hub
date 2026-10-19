"""Resolve HTTPS route hosts and pin each request to a public address."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class PinnedTarget:
    url: str
    host_header: str | None
    sni_hostname: bytes | None


def _is_public(value: str) -> bool:
    address = ip_address(value.split("%", 1)[0])
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def resolve_and_pin_target(url: str) -> PinnedTarget:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        explicit_port = parsed.port
        port = explicit_port if explicit_port is not None else 443
    except ValueError as exc:
        raise ValueError("Malformed HTTPS upstream URL.") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS upstream targets are allowed.")
    if parsed.username or parsed.password:
        raise ValueError("Upstream URL credentials are not allowed.")
    if not host:
        raise ValueError("Upstream URL host is missing.")
    if not 1 <= port <= 65535:
        raise ValueError("Upstream URL port is invalid.")

    try:
        literal = ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public(str(literal)):
            raise ValueError("Upstream IP target is not allowed.")
        return PinnedTarget(url=url, host_header=None, sni_hostname=None)

    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Upstream hostname could not be resolved.") from exc
    addresses = list(dict.fromkeys(result[4][0] for result in results))
    if not addresses:
        raise ValueError("Upstream hostname has no addresses.")
    if any(not _is_public(address) for address in addresses):
        raise ValueError("Upstream hostname resolves to a non-public address.")

    chosen = next((address for address in addresses if ip_address(address).version == 4), addresses[0])
    pinned_ip = ip_address(chosen)
    pinned_host = f"[{chosen}]" if pinned_ip.version == 6 else chosen
    netloc = pinned_host + (f":{explicit_port}" if explicit_port and explicit_port != 443 else "")
    pinned_url = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    host_ascii = host.encode("idna").decode("ascii")
    host_header = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
    if explicit_port and explicit_port != 443:
        host_header += f":{explicit_port}"
    return PinnedTarget(
        url=pinned_url,
        host_header=host_header,
        sni_hostname=host_ascii.encode("ascii"),
    )


async def resolve_and_pin_target_async(url: str) -> PinnedTarget:
    return await asyncio.to_thread(resolve_and_pin_target, url)
