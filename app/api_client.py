import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from app.models import ALLOWED_METHODS
from app.utils.redact import preview, redact_obj, redact_url


class TesterError(Exception):
    pass


@dataclass
class TestResult:
    url: str
    url_masked: str
    status_code: int | None
    response_time_ms: int | None
    success: bool
    error_summary: str | None
    request_preview: str
    response_preview: str
    response_headers_preview: str
    response_body_display: str


def parse_json_field(label: str, value: str, expected_type: type) -> dict | list | None:
    if not value.strip():
        return {} if expected_type is dict else None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise TesterError(f"{label} JSON is invalid: {exc.msg}") from exc
    if not isinstance(parsed, expected_type):
        raise TesterError(f"{label} must be a JSON {expected_type.__name__}.")
    return parsed


def build_url(base_url: str, path: str) -> str:
    if "://" in path:
        raise TesterError("Path must be relative, not a full URL.")
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    validate_url(url)
    return url


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise TesterError("Only http and https URLs are allowed.")
    host = parts.hostname
    if not host:
        raise TesterError("URL host is missing.")
    if host.lower() in {"localhost", "0.0.0.0"}:
        raise TesterError("Localhost and 0.0.0.0 are blocked.")
    try:
        ip = ipaddress.ip_address(host)
        validate_ip(ip)
        return
    except ValueError:
        pass
    try:
        for item in socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM):
            validate_ip(ipaddress.ip_address(item[4][0]))
    except OSError as exc:
        raise TesterError(f"DNS resolution failed: {exc}") from exc


def validate_ip(ip: ipaddress._BaseAddress) -> None:
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_private:
        raise TesterError("Loopback, private, link-local, and unspecified addresses are blocked.")
    if str(ip) == "169.254.169.254":
        raise TesterError("Metadata service address is blocked.")


def apply_saved_auth(headers: dict, api_row) -> None:
    if api_row["auth_type"] == "bearer":
        secret_ref = api_row["secret_ref"] or ""
        secret = os.getenv(secret_ref) if secret_ref else ""
        if not secret:
            raise TesterError(f"Saved auth is configured as bearer, but {secret_ref or 'secret'} is missing.")
        headers["Authorization"] = f"Bearer {secret}"


def send_test_request(api_row, method: str, path: str, headers_text: str, query_text: str,
                      body_text: str, use_saved_auth: bool) -> TestResult:
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise TesterError("Unsupported HTTP method.")
    headers = parse_json_field("Headers", headers_text, dict) or {}
    query = parse_json_field("Query", query_text, dict) or {}
    body = parse_json_field("Body", body_text, dict) if body_text.strip() else None
    headers = {str(key): str(value) for key, value in headers.items()}
    if use_saved_auth:
        apply_saved_auth(headers, api_row)
    url = build_url(api_row["base_url"], path)
    request_data = {"method": method, "url": redact_url(url), "headers": headers, "query": query, "body": body}
    start = time.perf_counter()
    try:
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            response = client.request(method, url, headers=headers, params=query, json=body if body is not None else None)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        response_text = response.text
        try:
            response_body_display = json.dumps(redact_obj(response.json()), ensure_ascii=False, indent=2)
        except ValueError:
            response_body_display = preview(response_text)
        return TestResult(
            url=url,
            url_masked=redact_url(str(response.url)),
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            success=200 <= response.status_code < 400,
            error_summary=None if response.status_code < 400 else f"HTTP {response.status_code}",
            request_preview=preview(request_data),
            response_preview=preview(response_text),
            response_headers_preview=preview(dict(response.headers)),
            response_body_display=response_body_display[:12000],
        )
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return TestResult(
            url=url,
            url_masked=redact_url(url),
            status_code=None,
            response_time_ms=elapsed_ms,
            success=False,
            error_summary=preview(str(exc), 500),
            request_preview=preview(request_data),
            response_preview="",
            response_headers_preview="",
            response_body_display="",
        )
