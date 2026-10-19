from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.ai_catalog import snapshot
from app.auth import optional_user, require_developer, require_admin
from app.ai_usage import read_usage_summary, get_key_models
from app.db import connect
from app.ai_policies import validate_policy

router = APIRouter()
from app.web.templating import templates


@router.get("/models", response_class=HTMLResponse)
async def models_page(request: Request, user=Depends(optional_user)):
    return templates.TemplateResponse(request, "ai_models.html", {"user": user, "catalog": await snapshot()})


@router.get("/status", response_class=HTMLResponse)
async def status_page(request: Request, user=Depends(optional_user)):
    return templates.TemplateResponse(request, "ai_status.html", {"user": user, "status": await snapshot()})


@router.get("/api/public/ai-catalog")
async def public_catalog():
    return JSONResponse(await snapshot(), headers={"Cache-Control": "public, max-age=15"})


def key_views(user_id=None):
    with connect() as conn:
        rows = conn.execute("SELECT id,user_id,name,key_prefix,status,scopes,allowed_routes,model_policy,rate_limit_per_minute,daily_quota,monthly_quota,expires_at,last_used_at FROM api_keys" + (" WHERE user_id=?" if user_id is not None else "") + " ORDER BY created_at DESC", (user_id,) if user_id is not None else ()).fetchall()
        return [{**dict(row), "models": get_key_models(conn, row["id"])} for row in rows]


@router.get("/developer/usage", response_class=HTMLResponse)
def usage_page(request: Request, user=Depends(require_developer)):
    return templates.TemplateResponse(request, "ai_usage.html", {"user": user, "usage": read_usage_summary(user["id"]), "all_users": False})


@router.get("/admin/ai-usage", response_class=HTMLResponse)
def admin_usage(request: Request, user=Depends(require_admin)):
    return templates.TemplateResponse(request, "ai_usage.html", {"user": user, "usage": read_usage_summary(None), "all_users": True})


@router.get("/api/developer/usage")
def usage_api(user=Depends(require_developer)):
    return JSONResponse(read_usage_summary(user["id"]), headers={"Cache-Control": "no-store"})


@router.get("/developer/playground", response_class=HTMLResponse)
async def playground(request: Request, user=Depends(require_developer)):
    return templates.TemplateResponse(request, "ai_playground.html", {"user": user, "catalog": await snapshot()})


@router.get("/admin/ai-keys/{key_id}", response_class=HTMLResponse)
def edit_policy(request: Request, key_id: int, user=Depends(require_admin), saved: str = ""):
    key = next((row for row in key_views() if row["id"] == key_id), None)
    if not key:
        raise HTTPException(404, "密钥不存在")
    return templates.TemplateResponse(request, "ai_key_policy.html", {"user": user, "key": key, "saved": saved == "1"})


@router.post("/admin/ai-keys/{key_id}")
def save_policy(key_id: int, scopes: str = Form(...), models: str = Form(""), model_policy: str = Form("allowlist"), rate_limit_per_minute: int = Form(...), daily_quota: int = Form(...), monthly_quota: int = Form(...), expires_at: str = Form(""), user=Depends(require_admin)):
    scopes, model_ids, expiry = validate_policy(scopes, models, rate_limit_per_minute, daily_quota, monthly_quota, expires_at, policy=model_policy, legacy=True)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        key = conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if not key:
            raise HTTPException(404, "密钥不存在")
        routes = key["allowed_routes"] or ""
        conn.execute("UPDATE api_keys SET scopes=?,allowed_routes=?,model_policy=?,rate_limit_per_minute=?,daily_quota=?,monthly_quota=?,expires_at=? WHERE id=?", (scopes,routes,model_policy,rate_limit_per_minute,daily_quota,monthly_quota,expiry,key_id))
        conn.execute("DELETE FROM api_key_models WHERE api_key_id=?", (key_id,))
        conn.executemany("INSERT INTO api_key_models(api_key_id,model_id) VALUES (?,?)", [(key_id,model) for model in model_ids])
        conn.commit()
    return RedirectResponse(f"/admin/ai-keys/{key_id}?saved=1", status_code=303)
