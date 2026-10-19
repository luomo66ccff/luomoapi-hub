"""One shared Jinja environment: fingerprinted assets, model line signage and Chinese labels."""
from __future__ import annotations

import hashlib
import re
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.model_lines import line_for

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))


@lru_cache(maxsize=256)
def _digest(path: Path, mtime_ns: int, size: int) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def fingerprint(name: str) -> str:
    """Content hash of a static file; re-read whenever its mtime or size changes."""
    path = (STATIC_DIR / name).resolve()
    if STATIC_DIR not in path.parents or not path.is_file():
        raise ValueError(f"unknown static asset: {name}")
    stat = path.stat()
    return _digest(path, stat.st_mtime_ns, stat.st_size)


def asset(name: str) -> str:
    """URL carrying the content hash; only an exactly matching ?v= is served as immutable."""
    return f"/static/{name}?v={fingerprint(name)}"


LABELS = {
    "active": "已启用", "pending": "已启用", "suspended": "已暂停", "disabled": "已停用",
    "revoked": "已撤销", "approved": "已签发", "rejected": "已拒绝", "expired": "已过期",
    "admin": "管理员", "developer": "开发者",
    "configured": "已配置", "missing": "未配置", "exists": "存在",
    "operational": "正常", "degraded": "异常",
    "enabled": "已启用", "redeemed": "已兑换",
}
TONES = {
    "active": "ok", "approved": "ok", "configured": "ok", "exists": "ok", "operational": "ok", "enabled": "ok",
    "pending": "ok", "suspended": "warn", "degraded": "warn", "missing": "off",
    "disabled": "off", "revoked": "off", "rejected": "off", "expired": "off",
}


def label(value) -> str:
    return LABELS.get(str(value), str(value) if value not in (None, "") else "—")


def tone(value) -> str:
    return TONES.get(str(value), "off")


def utc(value) -> str:
    """Compact ISO timestamp for tables: 2026-10-18 07:12."""
    if not value:
        return "—"
    text = str(value).replace("T", " ")
    return text[:16] if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", text) else text


def credit(value) -> str:
    """Exact decimal credits: thousands separators, no trailing zeros (7200.00 -> 7,200)."""
    if value is None or value == "":
        return "—"
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        return str(value)
    text = f"{number:,f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


templates.env.globals.update(asset=asset, line_for=line_for)
templates.env.filters.update(label=label, tone=tone, utc=utc, credit=credit)
