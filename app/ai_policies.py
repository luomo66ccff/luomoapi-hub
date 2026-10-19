import re
from datetime import datetime, timezone
from fastapi import HTTPException

AI_SCOPES = {"models:read", "chat:completions", "responses:create"}


def validate_policy(scopes, models, rpm, daily, monthly, expires_at, *, policy="allowlist", legacy=False):
    scope_list = sorted(set(re.split(r"[,\s]+", scopes.strip())) - {""})
    model_list = sorted(set(re.split(r"[,\s]+", models.strip())) - {""})
    if not legacy and any(scope in {"*", "codexproxy:use"} for scope in scope_list):
        raise HTTPException(400, "新密钥请使用明确的协议权限，不使用通配或旧版权限。")
    if policy not in {"all", "allowlist"} or (not legacy and policy != "allowlist"):
        raise HTTPException(400, "模型策略无效")
    if any(len(model) > 120 or not re.fullmatch(r"[A-Za-z0-9._:/-]+", model) for model in model_list) or len(model_list) > 100:
        raise HTTPException(400, "模型 ID 格式无效")
    if policy == "allowlist" and set(scope_list) & {"chat:completions", "responses:create"} and not model_list:
        raise HTTPException(400, "生成权限至少需要一个模型 ID")
    if any(value < 0 for value in (rpm, daily, monthly)):
        raise HTTPException(400, "配额不得为负数；0 表示不限")
    expiry = None
    if expires_at.strip():
        try:
            value = datetime.fromisoformat(expires_at.strip().replace("Z", "+00:00"))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            if value <= datetime.now(timezone.utc):
                raise ValueError()
            expiry = value.astimezone(timezone.utc).isoformat()
        except ValueError:
            raise HTTPException(400, "有效期必须为未来的 ISO 时间；未写时区时按 UTC。")
    return ",".join(scope_list), model_list, expiry
