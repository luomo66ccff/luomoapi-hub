"""Optional Stripe Checkout top-ups. Only verified provider receipts add credit."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from contextlib import closing
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from app.auth import require_developer
from app.config import settings
from app.credit_ledger import CreditError, add_credit, units_to_credits
from app.db import connect
from app.utils.timefmt import now_iso

router = APIRouter()
from app.web.templating import templates
logger = logging.getLogger("luomoapi.payments")


def initialize_payment_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS credit_payment_orders (
        id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
        nonce_hash TEXT NOT NULL, amount_fen INTEGER NOT NULL CHECK(amount_fen BETWEEN 100 AND 100000),
        credit_units INTEGER NOT NULL CHECK(credit_units=amount_fen*1000000),
        currency TEXT NOT NULL CHECK(currency='cny'), provider_account TEXT NOT NULL,
        livemode INTEGER NOT NULL CHECK(livemode IN (0,1)), status TEXT NOT NULL,
        session_id TEXT UNIQUE, payment_intent TEXT UNIQUE, checkout_url TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, paid_at TEXT,
        UNIQUE(user_id,nonce_hash))""")
    columns={row[1] for row in conn.execute("PRAGMA table_info(credit_payment_orders)")}
    if "reversed_units" not in columns:
        conn.execute("ALTER TABLE credit_payment_orders ADD COLUMN reversed_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reversed_units)='integer' AND reversed_units>=0)")
    conn.execute("""CREATE TABLE IF NOT EXISTS credit_payment_events (
        event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
        order_id TEXT REFERENCES credit_payment_orders(id), processed_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS credit_payment_reviews (
        order_id TEXT PRIMARY KEY REFERENCES credit_payment_orders(id), charge_id TEXT NOT NULL,
        reason TEXT NOT NULL, event_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','resolved')),
        kind TEXT NOT NULL CHECK(kind IN ('refund','dispute')), provider_status TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1),
        reversal_units INTEGER NOT NULL CHECK(typeof(reversal_units)='integer' AND reversal_units>=0),
        risk_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(risk_units)='integer' AND risk_units>=0),
        reversed_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reversed_units)='integer' AND reversed_units>=0),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT,
        actor_id INTEGER REFERENCES users(id), resolution_note TEXT)""")
    review_columns={row[1] for row in conn.execute("PRAGMA table_info(credit_payment_reviews)")}
    for name,declaration in {"kind":"TEXT NOT NULL DEFAULT 'refund' CHECK(kind IN ('refund','dispute'))",
            "provider_status":"TEXT NOT NULL DEFAULT 'unknown'","revision":"INTEGER NOT NULL DEFAULT 1 CHECK(revision>=1)",
            "risk_units":"INTEGER NOT NULL DEFAULT 0 CHECK(typeof(risk_units)='integer' AND risk_units>=0)"}.items():
        if name not in review_columns:
            conn.execute(f"ALTER TABLE credit_payment_reviews ADD COLUMN {name} {declaration}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_reviews_state ON credit_payment_reviews(state,order_id)")


def payment_config(*,for_webhook=False):
    key = os.getenv("CREDIT_STRIPE_SECRET_KEY", "")
    secret = os.getenv("CREDIT_STRIPE_WEBHOOK_SECRET", "")
    account = os.getenv("CREDIT_STRIPE_ACCOUNT_ID", "")
    live = os.getenv("CREDIT_STRIPE_LIVEMODE", "true").strip().lower() == "true"
    # Test Checkout can never fund a real application's wallet. Tests may
    # still pass False configs directly to pure in-memory accounting helpers.
    if (not live or (not for_webhook and os.getenv("CREDIT_PAYMENT_PROVIDER", "") != "stripe") or not secret.startswith("whsec_")
            or not re.fullmatch(r"acct_[A-Za-z0-9]+", account)
            or not key.startswith("sk_live_")):
        return None
    base = urlsplit(settings.app_base_url)
    if base.scheme != "https" or not base.netloc or base.username or base.password:
        return None
    return {"key":key, "secret":secret, "account":account, "live":live}


def topup_nonce(user_id):
    value = f"{int(time.time())}.{secrets.token_hex(16)}"
    signature = hmac.new(settings.session_secret.encode(), f"topup:{user_id}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{value}.{signature}"


def _nonce_hash(user_id, nonce):
    if not re.fullmatch(r"\d{10}\.[0-9a-f]{32}\.[0-9a-f]{64}", nonce):
        raise CreditError("invalid_nonce", "充值表单无效，请刷新积分页。")
    value, signature = nonce.rsplit(".",1)
    expected = hmac.new(settings.session_secret.encode(), f"topup:{user_id}:{value}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,signature) or not 0 <= time.time()-int(value.split(".")[0]) <= 3600:
        raise CreditError("invalid_nonce", "充值表单已过期，请刷新积分页。")
    return hashlib.sha256(nonce.encode()).hexdigest()


def payment_context(request, user):
    config = payment_config()
    if not config:
        return {"enabled":False,"message":"在线支付渠道尚未配置，暂未开放付款。可先使用兑换码或联系管理员加分。"}
    return {"enabled":True,"nonce":topup_nonce(user["id"]),"message":
            "Stripe 安全支付，1 元 = 100 积分，单笔 1–1000 元。确认到账后自动加分。"}


def amount_fen(value):
    if not isinstance(value,str) or not re.fullmatch(r"\d{1,4}(?:\.\d{1,2})?",value):
        raise CreditError("amount_invalid","请输入 1–1000 元，最多两位小数。")
    try:
        amount = Decimal(value)*100
        if not 100 <= amount <= 100000 or amount != amount.to_integral_value():
            raise InvalidOperation
        return int(amount)
    except InvalidOperation:
        raise CreditError("amount_invalid","请输入 1–1000 元，最多两位小数。")


def claim_order(conn,user_id,nonce,fen,config):
    if not conn.in_transaction:
        raise CreditError("transaction_required","充值订单需要事务。",503)
    hashed = _nonce_hash(user_id,nonce)
    row = conn.execute("SELECT * FROM credit_payment_orders WHERE user_id=? AND nonce_hash=?",(user_id,hashed)).fetchone()
    if row:
        if (row["amount_fen"],row["provider_account"],bool(row["livemode"])) != (fen,config["account"],config["live"]):
            raise CreditError("order_conflict","这份充值表单已用于其他金额，请刷新页面。",409)
        return dict(row)
    count = conn.execute("SELECT COUNT(*) FROM credit_payment_orders WHERE user_id=? AND julianday(created_at)>julianday('now','-10 minutes')",(user_id,)).fetchone()[0]
    if count >= 10:
        raise CreditError("topup_rate_limited","充值订单创建过于频繁，请稍后重试。",429)
    order_id = "topup_"+secrets.token_hex(20)
    now = now_iso()
    conn.execute("""INSERT INTO credit_payment_orders(id,user_id,nonce_hash,amount_fen,credit_units,currency,
        provider_account,livemode,status,created_at,updated_at) VALUES (?,?,?,?,?,'cny',?,?,'created',?,?)""",
        (order_id,user_id,hashed,fen,fen*1000000,config["account"],int(config["live"]),now,now))
    return dict(conn.execute("SELECT * FROM credit_payment_orders WHERE id=?",(order_id,)).fetchone())


async def stripe_call(config,method,path,*,data=None,params=None,idempotency_key=None):
    headers={"Authorization":"Bearer "+config["key"]}
    if idempotency_key:
        headers["Idempotency-Key"]=idempotency_key
    try:
        async with httpx.AsyncClient(timeout=20,trust_env=False,follow_redirects=False) as client:
            response=await client.request(method,"https://api.stripe.com/v1/"+path,headers=headers,data=data,params=params)
        if response.status_code >= 400:
            raise CreditError("payment_provider_error","支付渠道暂不可用，请稍后重试。",502)
        return response.json()
    except (httpx.HTTPError,ValueError):
        raise CreditError("payment_provider_error","支付渠道连接失败，请稍后重试。",502)


def valid_checkout_url(value):
    if not isinstance(value,str):
        return False
    try:
        url=urlsplit(value)
        return url.scheme=="https" and url.hostname=="checkout.stripe.com" and not url.username and not url.password and url.port in {None,443}
    except ValueError:
        return False


@router.get("/developer/credits/orders/{order_id}/pay")
async def continue_payment(order_id: str,user=Depends(require_developer)):
    # A same-origin link keeps the site's navigation CSP intact. Pausing new
    # orders still permits a previously created live Checkout to finish.
    config=payment_config(for_webhook=True)
    if config is None:
        return JSONResponse({"error":"payments_not_configured"},status_code=503)
    with closing(connect()) as conn:
        order=conn.execute("SELECT * FROM credit_payment_orders WHERE id=? AND user_id=?",(order_id,user["id"])).fetchone()
    if order is None:
        return JSONResponse({"error":"payment_order_missing"},status_code=404)
    if (order["provider_account"]!=config["account"] or bool(order["livemode"]) is not config["live"]
            or order["status"] not in {"created","awaiting_payment"} or not valid_checkout_url(order["checkout_url"])):
        return JSONResponse({"error":"payment_order_not_payable"},status_code=409)
    return RedirectResponse(order["checkout_url"],status_code=303,
                            headers={"Cache-Control":"no-store","Referrer-Policy":"no-referrer"})


@router.post("/developer/credits/topup",response_class=HTMLResponse)
async def topup(request: Request,amount_cny: str=Form(...),nonce: str=Form(...),user=Depends(require_developer)):
    from app.credit_console import _wallet_page
    config=payment_config()
    if config is None:
        return _wallet_page(request,user,error="在线支付尚未配置。",status=503)
    try:
        fen=amount_fen(amount_cny)
        with closing(connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            order=claim_order(conn,user["id"],nonce,fen,config)
            conn.commit()
        if order["status"]=="paid":
            return _wallet_page(request,user,message="这笔充值已到账，不会重复加分。")
        if order["status"] in {"expired","payment_failed","closed","payment_review"}:
            raise CreditError("order_closed","订单已关闭，请刷新积分页重新创建。",409)
        if not order["checkout_url"]:
            account=await stripe_call(config,"GET","account")
            if account.get("id") != config["account"]:
                raise CreditError("payment_account_mismatch","支付商户配置不匹配，请联系管理员。",503)
            base=settings.app_base_url.rstrip("/")
            session=await stripe_call(config,"POST","checkout/sessions",idempotency_key=order["id"],data={
                "mode":"payment","client_reference_id":order["id"],"metadata[order_id]":order["id"],
                "adaptive_pricing[enabled]":"false","automatic_tax[enabled]":"false","allow_promotion_codes":"false",
                "payment_intent_data[metadata][order_id]":order["id"],
                "line_items[0][price_data][currency]":"cny","line_items[0][price_data][unit_amount]":str(fen),
                "line_items[0][price_data][product_data][name]":"LuomoAPI 积分充值",
                "line_items[0][quantity]":"1","success_url":base+"/developer/credits?payment=returned",
                "cancel_url":base+"/developer/credits?payment=cancelled"})
            if not re.fullmatch(r"cs_[A-Za-z0-9_]+",str(session.get("id",""))) or not valid_checkout_url(session.get("url")) or session.get("livemode") is not config["live"]:
                raise CreditError("payment_response_invalid","支付渠道响应不完整，请联系管理员。",502)
            with closing(connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                if conn.execute("SELECT 1 FROM credit_payment_orders WHERE session_id=? AND id!=?",(session["id"],order["id"])).fetchone():
                    raise CreditError("payment_receipt_reused","支付会话已关联另一笔订单，请联系管理员。",409)
                changed=conn.execute("""UPDATE credit_payment_orders SET session_id=?,checkout_url=?,
                    status=CASE WHEN status='created' THEN 'awaiting_payment' ELSE status END,updated_at=? WHERE id=? AND (session_id IS NULL OR session_id=?)""",
                    (session["id"],session["url"],now_iso(),order["id"],session["id"])).rowcount
                if changed!=1:
                    raise CreditError("payment_receipt_mismatch","订单已关联另一笔支付，请联系管理员。",409)
                order=dict(conn.execute("SELECT * FROM credit_payment_orders WHERE id=?",(order["id"],)).fetchone())
                conn.commit()
        return templates.TemplateResponse(request,"credit_payment.html",{"user":user,"order":order,
            "amount_cny":format(Decimal(order["amount_fen"])/100,".2f"),"credits":units_to_credits(order["credit_units"])},headers={"Cache-Control":"no-store"})
    except CreditError as exc:
        return _wallet_page(request,user,error=exc.message,status=exc.status)


def verify_signature(body,header,secret,*,current_time=None):
    if not header or len(header)>2048:
        raise CreditError("signature_invalid","Invalid payment signature.",400)
    fields=[part.strip().partition("=") for part in header.split(",")]
    timestamps=[value for key,_,value in fields if key=="t"]
    signatures=[value for key,_,value in fields if key=="v1"]
    if len(timestamps)!=1 or not re.fullmatch(r"\d{10}",timestamps[0]):
        raise CreditError("signature_invalid","Invalid payment signature.",400)
    stamp=int(timestamps[0])
    if abs((time.time() if current_time is None else current_time)-stamp)>300:
        raise CreditError("signature_expired","Expired payment signature.",400)
    digest=hmac.new(secret.encode(),timestamps[0].encode()+b"."+body,hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(digest,value) for value in signatures):
        raise CreditError("signature_invalid","Invalid payment signature.",400)


def _intent_charge_order(conn,intent,charge,config,*,order=None):
    """Validate authoritative PI and expanded Charge against one local order."""
    metadata=intent.get("metadata")
    if not isinstance(metadata,dict):
        raise CreditError("payment_receipt_mismatch","Payment intent metadata is missing.",409)
    intent_id=intent.get("id")
    charge_id=charge.get("id")
    if (not isinstance(intent_id,str) or not re.fullmatch(r"pi_[A-Za-z0-9]+",intent_id)
            or not isinstance(charge_id,str) or not re.fullmatch(r"ch_[A-Za-z0-9]+",charge_id)):
        raise CreditError("payment_receipt_invalid","Invalid payment intent or charge.",409)
    if order is None:
        # Refund/dispute may precede Checkout completion, before session_id or
        # payment_intent has been stored locally. Trusted PI metadata links it.
        order=conn.execute("SELECT * FROM credit_payment_orders WHERE payment_intent=? OR id=? ORDER BY payment_intent IS NULL LIMIT 1",
                           (intent_id,metadata.get("order_id"))).fetchone()
    if order is None:
        raise CreditError("payment_order_missing","Unknown top-up order.",409)
    expanded=intent.get("latest_charge")
    if (not isinstance(expanded,dict) or expanded.get("id")!=charge_id
            or metadata.get("order_id")!=order["id"]
            or order["provider_account"]!=config["account"] or bool(order["livemode"]) is not config["live"]
            or order["payment_intent"] not in {None,intent_id}
            or intent.get("status")!="succeeded" or intent.get("currency")!="cny"
            or intent.get("livemode") is not config["live"]
            or type(intent.get("amount")) is not int or intent["amount"]!=order["amount_fen"]
            or type(intent.get("amount_received")) is not int or intent["amount_received"]!=order["amount_fen"]
            or charge.get("payment_intent")!=intent_id or charge.get("currency")!="cny"
            or charge.get("livemode") is not config["live"]
            or charge.get("paid") is not True or charge.get("captured") is not True
            or type(charge.get("amount")) is not int or charge["amount"]!=order["amount_fen"]
            or type(charge.get("amount_captured")) is not int or charge["amount_captured"]!=order["amount_fen"]
            or type(charge.get("amount_refunded")) is not int or not 0<=charge["amount_refunded"]<=order["amount_fen"]
            or type(charge.get("refunded")) is not bool or type(charge.get("disputed")) is not bool
            or (charge["refunded"] and charge["amount_refunded"]!=order["amount_fen"])):
        raise CreditError("payment_receipt_mismatch","Payment intent or charge does not match the order.",409)
    other=conn.execute("SELECT id FROM credit_payment_orders WHERE payment_intent=? AND id!=?",(intent_id,order["id"])).fetchone()
    if other:
        raise CreditError("payment_receipt_reused","Payment intent already belongs to another order.",409)
    return order


def _record_payment_event(conn,event,order_id):
    conn.execute("INSERT INTO credit_payment_events(event_id,event_type,order_id,processed_at) VALUES (?,?,?,?)",
                 (event["id"],event["type"],order_id,now_iso()))


def _persist_payment_review(conn,event,order,charge,*,dispute=False,provider_status=None):
    """Monotonic refund totals and sticky review; no wallet debit occurs here."""
    previous=conn.execute("SELECT * FROM credit_payment_reviews WHERE order_id=?",(order["id"],)).fetchone()
    disputed=dispute or charge["disputed"]
    if previous and previous["state"]=="open" and previous["kind"]=="dispute":
        # A partial refund notification cannot erase an unresolved dispute.
        if not disputed and provider_status is None:
            provider_status=previous["provider_status"]
        disputed=True
    # Disputes express exposure, not a confirmed refund. Only cumulative
    # refunded fen is eligible for later manual reversal accounting.
    reversal=charge["amount_refunded"]*1_000_000
    risk=order["credit_units"] if disputed else reversal
    kind="dispute" if disputed else "refund"
    provider_status=provider_status or ("disputed" if disputed else "refunded" if charge["refunded"] else "partially_refunded")
    reason="Stripe payment dispute requires administrator review." if disputed else "Stripe payment refund requires administrator review."
    now=now_iso()
    if previous is None:
        conn.execute("""INSERT INTO credit_payment_reviews(order_id,charge_id,reason,event_id,state,kind,provider_status,reversal_units,risk_units,created_at,updated_at)
            VALUES (?,?,?,?,'open',?,?,?,?,?,?)""",(order["id"],charge["id"],reason,event["id"],kind,provider_status,reversal,risk,now,now))
        state="open"
    else:
        increased=reversal>previous["reversal_units"] or risk>previous["risk_units"]
        state="open" if increased else previous["state"]
        conn.execute("""UPDATE credit_payment_reviews SET charge_id=?,reason=?,event_id=?,state=?,kind=?,provider_status=?,revision=revision+1,
            reversal_units=MAX(reversal_units,?),risk_units=MAX(risk_units,?),updated_at=?,
            resolved_at=CASE WHEN ? THEN NULL ELSE resolved_at END,
            actor_id=CASE WHEN ? THEN NULL ELSE actor_id END,
            resolution_note=CASE WHEN ? THEN NULL ELSE resolution_note END WHERE order_id=?""",
            (charge["id"],reason,event["id"],state,kind,provider_status,reversal,risk,now,int(increased),int(increased),int(increased),order["id"]))
    conn.execute("""UPDATE credit_payment_orders SET payment_intent=?,updated_at=?,
        status=CASE WHEN status='closed' THEN 'closed' WHEN ?='open' THEN 'payment_review' ELSE status END WHERE id=?""",
        (charge["payment_intent"],now,state,order["id"]))
    _record_payment_event(conn,event,order["id"])


def review_payment(conn,event,intent,charge,config,*,dispute=False,provider_status=None):
    """Process a re-fetched refund or dispute, including before first success."""
    if not conn.in_transaction:
        raise CreditError("transaction_required","Payment review needs a transaction.",503)
    if conn.execute("SELECT 1 FROM credit_payment_events WHERE event_id=?",(event["id"],)).fetchone():
        return False
    order=_intent_charge_order(conn,intent,charge,config)
    if not (dispute or charge["disputed"] or charge["refunded"] or charge["amount_refunded"]):
        raise CreditError("payment_reversal_unconfirmed","Provider has not confirmed this refund or dispute.",409)
    _persist_payment_review(conn,event,order,charge,dispute=dispute,provider_status=provider_status)
    return True


def fulfill_order(conn,event,session,intent,config):
    if not conn.in_transaction:
        raise CreditError("transaction_required","Payment fulfillment needs a transaction.",503)
    event_id=event["id"]
    if conn.execute("SELECT 1 FROM credit_payment_events WHERE event_id=?",(event_id,)).fetchone():
        return False
    order=conn.execute("SELECT * FROM credit_payment_orders WHERE id=?",(session.get("client_reference_id"),)).fetchone()
    if not order:
        raise CreditError("payment_order_missing","Unknown top-up order.",409)
    intent_id=session.get("payment_intent")
    if not isinstance(intent_id,str) or not re.fullmatch(r"pi_[A-Za-z0-9]+",intent_id):
        raise CreditError("payment_receipt_invalid","Invalid payment intent.",409)
    session_metadata=session.get("metadata")
    session_id=session.get("id")
    if (not isinstance(session_id,str) or not re.fullmatch(r"cs_[A-Za-z0-9_]+",session_id)
            or not isinstance(session_metadata,dict)
            or session.get("mode")!="payment" or session.get("payment_status")!="paid" or session.get("status")!="complete"
            or session.get("currency")!="cny" or type(session.get("amount_total")) is not int
            or session["amount_total"] != order["amount_fen"] or session_metadata.get("order_id") != order["id"]
            or session.get("livemode") is not config["live"] or order["provider_account"]!=config["account"]
            or bool(order["livemode"]) is not config["live"]
            or order["session_id"] not in {None,session.get("id")}
            or intent.get("id")!=intent_id or intent.get("status")!="succeeded"
            or intent.get("currency")!="cny" or type(intent.get("amount_received")) is not int
            or intent["amount_received"]!=order["amount_fen"] or intent.get("livemode") is not config["live"]
            or not isinstance(intent.get("metadata"),dict) or intent["metadata"].get("order_id")!=order["id"]):
        raise CreditError("payment_receipt_mismatch","Payment receipt does not match the order.",409)
    if conn.execute("SELECT 1 FROM credit_payment_orders WHERE session_id=? AND id!=?",(session_id,order["id"])).fetchone():
        raise CreditError("payment_receipt_reused","Checkout session already belongs to another order.",409)
    charge=intent.get("latest_charge")
    if not isinstance(charge,dict):
        raise CreditError("payment_charge_missing","Expanded payment charge is missing.",409)
    _intent_charge_order(conn,intent,charge,config,order=order)
    # Every delivery re-reads review state under the caller's write lock.
    # A delayed success can never clear a pending or closed refund decision.
    review=conn.execute("SELECT * FROM credit_payment_reviews WHERE order_id=?",(order["id"],)).fetchone()
    if charge["refunded"] or charge["amount_refunded"] or charge["disputed"]:
        _persist_payment_review(conn,event,order,charge)
        return False
    if order["status"] in {"payment_review","closed"} or (review and review["state"]=="open"):
        _record_payment_event(conn,event,order["id"])
        return False
    add_credit(conn,order["user_id"],order["credit_units"],reference="stripe:"+order["id"],actor_id=None,
               kind="payment",note="Stripe 充值到账")
    now=now_iso()
    conn.execute("UPDATE credit_payment_orders SET session_id=?,payment_intent=?,status='paid',paid_at=COALESCE(paid_at,?),updated_at=? WHERE id=?",
                 (session["id"],intent_id,now,now,order["id"]))
    _record_payment_event(conn,event,order["id"])
    return True


@router.post("/api/payments/stripe/webhook")
async def stripe_webhook(request: Request):
    # Pausing new Checkout sessions must not discard already-paid receipts.
    config=payment_config(for_webhook=True)
    if not config:
        return JSONResponse({"error":"payments_not_configured"},status_code=503)
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>131072:
            return JSONResponse({"error":"body_too_large"},status_code=413)
    try:
        verify_signature(bytes(body),request.headers.get("stripe-signature",""),config["secret"])
        event=json.loads(body)
        if not isinstance(event,dict) or not re.fullmatch(r"evt_[A-Za-z0-9]+",str(event.get("id",""))) or event.get("livemode") is not config["live"] or event.get("account") or event.get("context"):
            raise CreditError("payment_event_invalid","Unsupported payment event.",400)
        success_types={"checkout.session.completed","checkout.session.async_payment_succeeded"}
        reversal_types={"charge.refunded","charge.dispute.created","charge.dispute.updated","charge.dispute.closed"}
        if event.get("type") not in success_types | reversal_types:
            return JSONResponse({"received":True})
        obj=event.get("data",{}).get("object",{})
        # Re-fetch using our secret key: the browser and webhook data alone
        # never decide the amount, paid state or merchant account.
        account=await stripe_call(config,"GET","account")
        if account.get("id")!=config["account"]:
            raise CreditError("payment_account_mismatch","Payment merchant mismatch.",503)
        if event["type"] in reversal_types:
            dispute=event["type"].startswith("charge.dispute.")
            resource_id=obj.get("id")
            if not isinstance(resource_id,str) or not re.fullmatch(r"dp_[A-Za-z0-9]+" if dispute else r"ch_[A-Za-z0-9]+",resource_id):
                raise CreditError("payment_event_invalid","Invalid reversal resource.",400)
            dispute_receipt=None
            if dispute:
                dispute_receipt=await stripe_call(config,"GET","disputes/"+resource_id)
                if dispute_receipt.get("id")!=resource_id or dispute_receipt.get("livemode") is not config["live"]:
                    raise CreditError("payment_receipt_mismatch","Dispute receipt does not match.",409)
                charge_id=dispute_receipt.get("charge")
            else:
                charge_id=resource_id
            if not isinstance(charge_id,str) or not re.fullmatch(r"ch_[A-Za-z0-9]+",charge_id):
                raise CreditError("payment_event_invalid","Invalid reversed charge.",400)
            charge=await stripe_call(config,"GET","charges/"+charge_id)
            intent_id=charge.get("payment_intent")
            if charge.get("id")!=charge_id or not isinstance(intent_id,str) or not re.fullmatch(r"pi_[A-Za-z0-9]+",intent_id):
                raise CreditError("payment_receipt_mismatch","Reversed charge does not match.",409)
            intent=await stripe_call(config,"GET","payment_intents/"+intent_id,params={"expand[]":"latest_charge"})
            if (not isinstance(intent.get("latest_charge"),dict) or intent["latest_charge"].get("id")!=charge_id
                    or intent.get("id")!=intent_id):
                raise CreditError("payment_receipt_mismatch","Reversed charge is not the current captured payment.",409)
            if dispute_receipt is not None and (
                    dispute_receipt.get("currency")!="cny" or type(dispute_receipt.get("amount")) is not int
                    or not 0<dispute_receipt["amount"]<=charge.get("amount",0)
                    or not isinstance(dispute_receipt.get("status"),str) or not dispute_receipt["status"]
                    or dispute_receipt.get("payment_intent") not in {None,intent_id}):
                raise CreditError("payment_receipt_mismatch","Dispute amount or payment intent does not match.",409)
            # Use the expanded PI Charge as the latest authority; the earlier
            # Charge lookup establishes the notification's resource linkage.
            charge=intent["latest_charge"]
            with closing(connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                review_payment(conn,event,intent,charge,config,dispute=dispute,
                               provider_status=dispute_receipt.get("status") if dispute_receipt is not None else None)
                conn.commit()
            return JSONResponse({"received":True})
        session_id=obj.get("id")
        if not isinstance(session_id,str) or not re.fullmatch(r"cs_[A-Za-z0-9_]+",session_id):
            raise CreditError("payment_event_invalid","Invalid Checkout session.",400)
        session=await stripe_call(config,"GET","checkout/sessions/"+session_id)
        if session.get("id")!=session_id:
            raise CreditError("payment_receipt_mismatch","Checkout session does not match.",409)
        if session.get("payment_status")!="paid":
            return JSONResponse({"received":True})
        intent_id=session.get("payment_intent")
        if not isinstance(intent_id,str) or not re.fullmatch(r"pi_[A-Za-z0-9]+",intent_id):
            raise CreditError("payment_event_invalid","Invalid payment intent.",400)
        intent=await stripe_call(config,"GET","payment_intents/"+intent_id,params={"expand[]":"latest_charge"})
        with closing(connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            fulfill_order(conn,event,session,intent,config)
            conn.commit()
        return JSONResponse({"received":True})
    except (ValueError,TypeError,AttributeError):
        return JSONResponse({"error":"payment_event_invalid"},status_code=400)
    except CreditError as exc:
        logger.warning("payment_webhook_rejected code=%s",exc.code)
        return JSONResponse({"error":exc.code},status_code=exc.status)
