"""Public capability guidance and a bounded, non-generating upstream probe."""
import asyncio
import os
import time
from datetime import datetime, timezone
from pathlib import Path
import json

import httpx
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.credit_pricing import priced_models
from app.db import connect
from app.model_lines import board_state, line_for

GUIDANCE = {
    "gpt-6-luna": ("Luna", "轻快交互", "聊天、明确的小任务、重复性工作；新接入建议从这里开始。"),
    "gpt-6-sol": ("Sol", "复杂任务", "跨文件修改、规划和需要更多推理的工作。"),
    "gpt-6.1-sol": ("Sol 6.1", "复杂任务", "Sol 的较新版本，适合复杂编码与规划。"),
    "gpt-6-astra": ("Astra", "高难任务", "复杂、持续的端到端工作；实际延迟以调用为准。"),
    "gpt-5.6-luna": ("Luna 5.6", "轻快交互", "上一代 Luna；已有集成可继续使用。"),
    "gpt-5.6-terra": ("Terra", "日常开发", "日常编码与一般任务，兼顾响应与能力。"),
    "gpt-5.6-sol": ("Sol 5.6", "复杂任务", "上一代 Sol；已有集成可继续使用。"),
    "gpt-5.3-codex-spark": ("Codex Spark", "快速文本", "快速编码交互；不要用于图像输入。"),
    "gpt-5.5": ("GPT-5.5", "兼容选择", "已有集成的兼容选择，可与新模型对比后使用。"),
}
_cache = None
_expires = 0.0
_lock = asyncio.Lock()


def _database_snapshot():
    with connect() as conn:
        counts = {name: conn.execute(sql).fetchone()[0] for name, sql in {
            "routes_count": "SELECT COUNT(*) FROM public_gateway_routes",
            "enabled_routes_count": "SELECT COUNT(*) FROM public_gateway_routes WHERE enabled=1",
            "public_docs_routes_count": "SELECT COUNT(*) FROM public_gateway_routes WHERE public_docs=1",
            "apis_count": "SELECT COUNT(*) FROM apis",
            "enabled_apis_count": "SELECT COUNT(*) FROM apis WHERE enabled=1",
            "active_keys_count": "SELECT COUNT(*) FROM api_keys WHERE status='active'",
        }.items()}
        return conn.execute("SELECT 1").fetchone()[0] == 1, counts


def public_verification(data, model_id):
    value = data.get(model_id) if isinstance(data, dict) else None
    if not isinstance(value, dict):
        return {}
    protocols = value.get("protocols")
    if not isinstance(protocols, list):
        return {}
    protocols = [p for p in protocols if isinstance(p, str) and p in {"Chat Completions", "Chat SSE", "Responses", "Responses SSE"}]
    try:
        checked_at = datetime.fromisoformat(value["checked_at"].replace("Z", "+00:00")).isoformat()
    except (KeyError, TypeError, AttributeError, ValueError):
        return {}
    return {"protocols": protocols, "checked_at": checked_at} if protocols else {}


async def snapshot():
    global _cache, _expires
    if _cache is not None and time.monotonic() < _expires:
        return _cache
    async with _lock:
        if _cache is not None and time.monotonic() < _expires:
            return _cache
        checked_at = datetime.now(timezone.utc).isoformat()
        db_ok = False
        counts = {}
        try:
            db_ok, counts = await run_in_threadpool(_database_snapshot)
        except Exception:
            db_ok = False
            counts = {}
        models, upstream_ok, latency = [], False, None
        reason = "未配置上游凭据"
        secret = os.getenv("CODEXPROXY_API_KEY", "")
        if secret:
            start = time.monotonic()
            try:
                async with httpx.AsyncClient(timeout=6, follow_redirects=False, trust_env=False) as client:
                    response = await client.get(settings.codexproxy_base_url.rstrip("/") + "/v1/models", headers={"Authorization": "Bearer " + secret})
                latency = round((time.monotonic() - start) * 1000)
                data = response.json() if response.status_code == 200 else {}
                upstream_ok = isinstance(data.get("data"), list)
                if upstream_ok:
                    models = sorted({item["id"] for item in data["data"] if isinstance(item, dict) and isinstance(item.get("id"), str) and len(item["id"]) <= 120})
                reason = "模型目录可达" if upstream_ok else "上游暂不可用"
            except (httpx.HTTPError, ValueError):
                reason = "上游探测超时或响应异常"
        verification = {}
        try:
            verification = json.loads(Path(__file__).with_name("ai_verification.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        entries = []
        priced = set(priced_models())
        priority = {model: index for index, model in enumerate(GUIDANCE)}
        for model_id in sorted(models, key=lambda model: (model not in priced, priority.get(model, len(priority)), model)):
            billable = model_id in priced
            name, category, use = GUIDANCE.get(model_id, (model_id, "未评估", "上游列出的模型；用途和兼容性尚未验证。"))
            if model_id.startswith("gpt-image-"):
                category, use = "图像模型", "当前网关未开放图像生成接口，不能直接用于文本示例。"
            elif not billable:
                category, use = "暂未计价", "上游列出的模型，但没有官方标准文本价格；个人密钥暂不能调用。"
            text_candidate = billable and not model_id.startswith("gpt-image-")
            entries.append({"id": model_id, "name": name, "category": category, "use": use, "billable": billable,
                            "text_candidate": text_candidate, "line": line_for(model_id), "state": board_state(model_id, text_candidate),
                            "verification": public_verification(verification, model_id)})
        _cache = {"service": "LuomoAPI Hub", "version": "2026.10-interchange-t001", "status": "operational" if db_ok and upstream_ok else "degraded", "updated_at": checked_at, "cache_seconds": 30,
                  "components": [{"name": "网关应用", "status": "operational", "detail": "当前 HTTP 请求已到达应用"}, {"name": "数据库", "status": "operational" if db_ok else "degraded", "detail": "只读查询成功" if db_ok else "查询失败"}, {"name": "AI 上游目录", "status": "operational" if upstream_ok else "degraded", "detail": reason, "latency_ms": latency}],
                  "models": entries, "model_count": len(models), "billable_count": sum(1 for entry in entries if entry["billable"]), "note": "目录可达不代表生成成功；探测不发起付费生成。模型权限以你的密钥为准。", **counts}
        _expires = time.monotonic() + 30
        return _cache
