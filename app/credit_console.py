"""Authenticated credit wallet and audited administrator operations."""
from __future__ import annotations

import json
import re
import secrets
from contextlib import closing
from functools import lru_cache
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.ai_catalog import snapshot
from app.auth import optional_user, require_admin, require_developer
from app.credit_ledger import (CreditError, add_credit, create_credit_code, credits_to_units,
    recover_stale_holds, redeem_credit_code, resolve_credit_hold, revoke_credit_code,
    units_to_credits, wallet_snapshot)
from app.db import connect

router = APIRouter()
from app.web.templating import templates


def _rows(conn,query,params=()):
    return [dict(row) for row in conn.execute(query,params).fetchall()]


@lru_cache(maxsize=1)
def _prices():
    data=json.loads(Path(__file__).with_name("credit_prices.json").read_text(encoding="utf-8"))
    rows=[]
    with localcontext() as context:
        context.prec=80
        for model,card in data["models"].items():
            row={"model":model,**card}
            for field in ("input","cached_input","cache_write","output","long_input","long_cached_input","long_cache_write","long_output"):
                value=card.get(field)
                row[field+"_credits"]=format(Decimal(str(value))*Decimal(720),"f") if value is not None else None
            rows.append(row)
    return {"models":rows,"version":data["version"],"source":data["source"],"retrieved_at":data.get("retrieved_at","")}


def _view_rows(rows):
    for row in rows:
        for key in ("delta_units","delta_reserved_units","balance_after_units","reserved_after_units","amount_units","actual_units"):
            if key in row and row[key] is not None:
                row[key.replace("_units","_credits")]=units_to_credits(row[key])
    return rows


def payment_context(request: Request, user) -> dict:
    """Optional root integration: a dict or synchronous callable on app.state."""
    configured=getattr(request.app.state,"credit_payment_context",None)
    context=configured(request,user) if callable(configured) else configured
    return context if isinstance(context,dict) else {"enabled":False,"message":"在线支付方式尚未配置。当前可使用兑换码，或联系管理员人工加分。"}


def _wallet_data(conn,user_id):
    return {"wallet":wallet_snapshot(conn,user_id),
            "ledger":_view_rows(_rows(conn,"SELECT id,reference,kind,delta_units,delta_reserved_units,balance_after_units,reserved_after_units,note,created_at,usage_id FROM credit_ledger WHERE user_id=? ORDER BY id DESC LIMIT 100",(user_id,))),
            "holds":_view_rows(_rows(conn,"SELECT usage_id,amount_units,actual_units,status,dispatch_state,reason,created_at,updated_at FROM credit_holds WHERE user_id=? AND status IN ('held','reconciliation_required') ORDER BY usage_id DESC",(user_id,)))}


def _wallet_page(request,user,*,error=None,message=None,status=200):
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        recover_stale_holds(conn)
        data=_wallet_data(conn,user["id"])
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credit_payment_reviews'").fetchone():
            data["payment_reviews"]=_rows(conn,"SELECT r.order_id,r.reason,r.kind,r.provider_status,r.created_at FROM credit_payment_reviews r JOIN credit_payment_orders o ON o.id=r.order_id WHERE o.user_id=? AND r.state='open'",(user["id"],))
        conn.commit()
    return templates.TemplateResponse(request,"credit_wallet.html",{"user":user,**data,"prices":_prices(),"payment":payment_context(request,user),"error":error,"message":message},status_code=status,headers={"Cache-Control":"no-store"})


def _admin_page(request,user,*,error=None,message=None,new_code=None,status=200):
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        recover_stale_holds(conn)
        users=_rows(conn,"SELECT u.id,u.username,u.email,u.role,u.status,COALESCE(w.balance_units,0) balance_units,COALESCE(w.reserved_units,0) reserved_units FROM users u LEFT JOIN credit_wallets w ON w.user_id=u.id ORDER BY u.username")
        for item in users:
            item.update(wallet_snapshot(conn,item["id"]))
        codes=_view_rows(_rows(conn,"SELECT c.id,c.code_tail,c.amount_units,c.status,c.expires_at,c.created_at,c.note,c.redeemed_at,u.username redeemed_username FROM credit_codes c LEFT JOIN users u ON u.id=c.redeemed_by ORDER BY c.id DESC LIMIT 100"))
        for code in codes:
            if code["status"] == "active" and code["expires_at"] and datetime.fromisoformat(code["expires_at"]) <= datetime.now(timezone.utc):
                code["status"]="expired"
        holds=_view_rows(_rows(conn,"SELECT h.*,u.username,a.model,a.request_id FROM credit_holds h JOIN users u ON u.id=h.user_id JOIN api_usage_logs a ON a.id=h.usage_id WHERE h.status='reconciliation_required' ORDER BY h.created_at"))
        ledger=_view_rows(_rows(conn,"SELECT l.*,u.username FROM credit_ledger l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 100"))
        audit=_view_rows(_rows(conn,"SELECT a.*,u.username actor_username FROM credit_admin_audit a JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 100"))
        payment_reviews=[]
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credit_payment_reviews'").fetchone():
            payment_reviews=_rows(conn,"SELECT r.*,o.user_id,o.credit_units,o.status order_status,u.username FROM credit_payment_reviews r JOIN credit_payment_orders o ON o.id=r.order_id JOIN users u ON u.id=o.user_id WHERE r.state='open' ORDER BY r.created_at")
        conn.commit()
    return templates.TemplateResponse(request,"admin_credits.html",{"user":user,"users":users,"codes":codes,"holds":holds,"ledger":ledger,"audit":audit,"payment_reviews":payment_reviews,"new_code":new_code,"error":error,"message":message,"add_nonce":secrets.token_hex(24),"code_nonce":secrets.token_hex(24)},status_code=status,headers={"Cache-Control":"no-store"})


def _nonce(raw: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{48}",raw):
        raise CreditError("invalid_nonce","表单编号无效，请刷新页面后重试。")
    return raw


@router.get("/pricing",response_class=HTMLResponse)
async def pricing_page(request: Request,user=Depends(optional_user)):
    catalog=await snapshot()
    live={model["id"] for model in catalog["models"]}
    prices=_prices()
    lines=[row for row in prices["models"] if row["model"] in live]
    others=[row for row in prices["models"] if row["model"] not in live]
    return templates.TemplateResponse(request,"pricing.html",{"user":user,"prices":prices,"lines":lines,"others":others,"catalog":catalog})


@router.get("/developer/credits",response_class=HTMLResponse)
def credits_page(request: Request,user=Depends(require_developer)):
    return _wallet_page(request,user)


@router.get("/api/developer/credits")
def credits_api(user=Depends(require_developer)):
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        recover_stale_holds(conn)
        data=_wallet_data(conn,user["id"])
        conn.commit()
    return JSONResponse({**data,"units_per_credit":1_000_000,"credits_per_cny":100,"credits_per_usd":720},headers={"Cache-Control":"no-store"})


@router.post("/developer/credits/redeem",response_class=HTMLResponse)
def redeem(request: Request,code: str=Form(...),user=Depends(require_developer)):
    error=None
    with closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            entry=redeem_credit_code(conn,user["id"],code)
        except CreditError as exc:
            error=exc
        except Exception:
            conn.rollback()
            raise
        # Rejected attempts must persist; no code/funds are changed on failure.
        conn.commit()
    return _wallet_page(request,user,error=error.message if error else None,message=f"已到账 {units_to_credits(entry['delta_units'])} 积分。" if error is None else None,status=error.status if error else 200)


@router.get("/admin/credits",response_class=HTMLResponse)
def admin_credits(request: Request,user=Depends(require_admin)):
    return _admin_page(request,user)


@router.post("/admin/credits/add",response_class=HTMLResponse)
def admin_add(request: Request,user_id: int=Form(...),amount_credits: str=Form(...),reason: str=Form(...),nonce: str=Form(...),user=Depends(require_admin)):
    try:
        amount=credits_to_units(amount_credits)
        reference=f"admin-add:{user['id']}:{_nonce(nonce)}"
        with closing(connect()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            add_credit(conn,user_id,amount,reference=reference,actor_id=user["id"],kind="admin_credit",note=reason)
    except CreditError as exc:
        return _admin_page(request,user,error=exc.message,status=exc.status)
    return _admin_page(request,user,message="积分已到账；重复提交相同编号不会重复加分。")


@router.post("/admin/credits/codes",response_class=HTMLResponse)
def admin_issue(request: Request,amount_credits: str=Form(...),reason: str=Form(...),nonce: str=Form(...),expires_at: str=Form(""),user=Depends(require_admin)):
    try:
        amount=credits_to_units(amount_credits)
        reference=f"admin-code:{user['id']}:{_nonce(nonce)}"
        with closing(connect()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            result=create_credit_code(conn,amount,actor_id=user["id"],note=reason,reference=reference,expires_at=expires_at.strip() or None)
    except CreditError as exc:
        return _admin_page(request,user,error=exc.message,status=exc.status)
    return _admin_page(request,user,new_code=result["raw_code"],message="请现在保存完整兑换码。数据库仅保留摘要和尾号，完整码只在本次响应中显示。" if result["raw_code"] else "该表单已发行过兑换码，未重复发行；完整码不能再次读取。")


@router.post("/admin/credits/codes/{code_id}/revoke",response_class=HTMLResponse)
def admin_revoke(request: Request,code_id: int,reason: str=Form(...),user=Depends(require_admin)):
    try:
        with closing(connect()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            revoke_credit_code(conn,code_id,actor_id=user["id"],reason=reason)
    except CreditError as exc:
        return _admin_page(request,user,error=exc.message,status=exc.status)
    return _admin_page(request,user,message="兑换码已作废。")


@router.post("/admin/credits/holds/{usage_id}/resolve",response_class=HTMLResponse)
def admin_resolve(request: Request,usage_id: int,actual_credits: str=Form(...),reason: str=Form(...),user=Depends(require_admin)):
    try:
        amount=credits_to_units(actual_credits)
        with closing(connect()) as conn,conn:
            conn.execute("BEGIN IMMEDIATE")
            resolve_credit_hold(conn,usage_id,amount,actor_id=user["id"],reason=reason)
    except CreditError as exc:
        return _admin_page(request,user,error=exc.message,status=exc.status)
    return _admin_page(request,user,message="待核记录已处理，金额、处理人和理由已写入审计记录。")
