import asyncio
import logging
import re
import secrets
from collections import OrderedDict
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import httpx

from app.api_client import TesterError, send_test_request
from app.auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    authenticate_user,
    create_session,
    current_user,
    hash_password,
    optional_user,
    require_admin,
    require_developer,
    api_user_eligible,
)
from app.config import secret_status, settings
from app.http_clients import create_http_client
from app.db import connect, init_db
from app.email_verification import (
    claim_verification_send,
    hash_verification_token,
    is_verification_token_fresh,
    new_token_record,
    send_verification_email,
)
from app.keyring import generate_api_key, hash_api_key
from app.models import ALLOWED_METHODS, AUTH_TYPES
from app.security import security_headers
from app.utils.redact import preview, redact_url
from app.utils.timefmt import now_iso
from scripts.seed_default_apis import seed
from app.public_stats import router as public_stats_router
from app.public_gateway_secure import router as public_gateway_secure_router
from app.error_redirect import error_redirect_middleware
from app.cliproxy_gateway import router as cliproxy_gateway_router
from app.ai_console import router as ai_console_router, key_views
from app.ai_catalog import snapshot
from app.ai_usage import read_usage_summary
from app.credit_ledger import wallet_snapshot
from app.ai_policies import validate_policy
from app.credit_console import router as credit_console_router
from app.self_service_keys import init_self_key_schema, issue_self_key, self_key_nonce
from app.credit_payments import router as credit_payment_router, initialize_payment_schema, payment_context
from app.client_ip import client_address, client_identity
from app.login_throttle import cancel_login_attempt, init_login_throttle_schema, release_login_attempt, reserve_login_attempt
from app.web.templating import STATIC_DIR, fingerprint, templates


class CachedStaticFiles(StaticFiles):
    """Templates reference assets with a content hash (?v=…), so a matching response is immutable."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            requested = parse_qs(scope.get("query_string", b"").decode("latin-1")).get("v", [])
            try:
                current = fingerprint(path.replace("\\", "/"))
            except ValueError:
                current = None
            immutable = current is not None and requested == [current]
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable" if immutable else "public, max-age=3600"
        return response


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
app.include_router(public_stats_router)
app.include_router(public_gateway_secure_router)
app.include_router(cliproxy_gateway_router)
app.include_router(ai_console_router)
app.include_router(credit_console_router)
app.include_router(credit_payment_router)
app.mount("/static", CachedStaticFiles(directory=str(STATIC_DIR)), name="static")
app.middleware("http")(security_headers)
app.middleware("http")(error_redirect_middleware)
logger = logging.getLogger("luomoapi.mail")


@app.middleware("http")
async def restrict_codexproxy_hostname(request: Request, call_next):
    host = request.headers.get("host", "").split(":", 1)[0].lower()
    if host == "cli.luomo.moe" and request.url.path != "/health" and not request.url.path.startswith("/v1/"):
        return HTMLResponse("Not Found", status_code=404)
    return await call_next(request)


@app.middleware("http")
async def redirect_api_http_to_https(request: Request, call_next):
    host = request.headers.get("host", "").split(":", 1)[0].lower()
    forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
    cf_visitor = request.headers.get("cf-visitor", "").lower()
    is_http = forwarded_proto == "http" or '"scheme":"http"' in cf_visitor
    if host == "api.luomo.moe" and is_http:
        target = request.url.replace(scheme="https", netloc=request.headers.get("host", "api.luomo.moe"))
        return RedirectResponse(str(target), status_code=308)
    return await call_next(request)


@app.on_event("startup")
async def startup() -> None:
    if not settings.session_secret or len(settings.session_secret) < 32:
        raise RuntimeError("SESSION_SECRET must contain at least 32 characters.")
    init_db()
    seed()
    with connect() as conn:
        init_self_key_schema(conn)
        init_login_throttle_schema(conn)
        initialize_payment_schema(conn)
        conn.commit()
    app.state.credit_payment_context = payment_context
    app.state.public_upstream_clients = OrderedDict()
    app.state.public_upstream_clients_active = {}
    app.state.public_upstream_clients_lock = asyncio.Lock()
    app.state.codex_http_client = create_http_client(httpx.Timeout(connect=15.0, read=120.0, write=60.0, pool=15.0))


@app.on_event("shutdown")
async def shutdown() -> None:
    for client in list(getattr(app.state, "public_upstream_clients", {}).values()):
        await client.aclose()
    client = getattr(app.state, "codex_http_client", None)
    if client:
        await client.aclose()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.head("/health")
def health_head() -> None:
    return None


@app.get("/ready")
def ready():
    try:
        with connect() as conn:
            ready_tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','api_keys','public_gateway_routes','credit_wallets','credit_holds','credit_ledger','credit_codes','credit_payment_orders','credit_payment_reviews','self_key_claims','login_throttle')"
                ).fetchall()
            }
            conn.execute("SELECT 1").fetchone()
        if len(ready_tables) != 11:
            raise RuntimeError("Required database tables are missing.")
    except Exception:
        return JSONResponse({"status": "not_ready", "checks": {"database": "failed"}}, status_code=503)
    if not settings.session_secret or len(settings.session_secret) < 32:
        return JSONResponse({"status": "not_ready", "checks": {"database": "ok", "session_secret": "missing_or_too_short"}}, status_code=503)
    return JSONResponse({"status": "ready", "checks": {"database": "ok", "session_secret": "ok"}})


@app.get("/api/public/status")
async def api_public_status() -> dict:
    return await snapshot()


@app.head("/")
def public_home_head() -> None:
    return None


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"error": None, "message": None, "submitted": False})


@app.head("/register")
def register_head() -> None:
    return None


@app.post("/register", response_class=HTMLResponse)
def register_submit(request: Request, username: str = Form(...), email: str = Form(...),
                    password: str = Form(...), confirm_password: str = Form(...), usage_reason: str = Form("")):
    error = None
    username = username.strip()
    email = email.strip().lower()
    usage_reason = usage_reason.strip()
    if len(password) < 10:
        error = "密码至少需要 10 个字符。"
    elif password != confirm_password:
        error = "两次输入的密码不一致。"
    elif not username or not email:
        error = "请填写用户名和邮箱。"
    if error:
        return templates.TemplateResponse(request, "register.html", {"error": error, "message": None, "submitted": False}, status_code=400)
    message = "如注册信息可用，账户已创建，可直接登录并领取 AI API 密钥，无需人工审核。验证邮件用于确认邮箱，邮箱验证不影响使用；若未收到邮件，可登录后重新发送。"
    source_ip = client_address(request)
    if not claim_verification_send(email, source_ip):
        return templates.TemplateResponse(request, "register.html", {"error": None, "message": message, "submitted": True})
    now = now_iso()
    token, token_hash, sent_at = new_token_record()
    try:
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO users(username, email, password_hash, role, status, usage_reason,
                email_verified, email_verification_token_hash, email_verification_sent_at, created_at, updated_at)
                VALUES (?, ?, ?, 'developer', 'active', ?, 0, ?, ?, ?, ?)
                """,
                (username, email, hash_password(password), usage_reason, token_hash, sent_at, now, now),
            )
            conn.commit()
    except Exception:
        return templates.TemplateResponse(request, "register.html", {"error": None, "message": message, "submitted": True})
    try:
        send_verification_email(email, username, token)
    except Exception as exc:
        logger.warning("registration_verification_failed request_id=%s error_type=%s", diagnostic_request_id(request), type(exc).__name__)
    return templates.TemplateResponse(request, "register.html", {"error": None, "message": message, "submitted": True})


def diagnostic_request_id(request: Request) -> str:
    value = request.headers.get("x-request-id", "").strip()
    return value if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value) else secrets.token_hex(8)


@app.get("/verify-email", response_class=HTMLResponse)
def verify_email(request: Request, token: str = ""):
    token_hash = hash_verification_token(token.strip()) if token else ""
    with connect() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email_verification_token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not user:
            return templates.TemplateResponse(request, "verify_email.html", {"success": False, "valid": False, "token": "", "message": "验证链接无效或已经使用过。"}, status_code=400)
        if not is_verification_token_fresh(user["email_verification_sent_at"]):
            return templates.TemplateResponse(request, "verify_email.html", {"success": False, "valid": False, "token": "", "message": "验证链接已过期。请登录控制台后重新发送验证邮件。"}, status_code=400)
    return templates.TemplateResponse(request, "verify_email.html", {"success": False, "valid": True, "token": token, "message": "点击下方按钮，确认这个邮箱地址属于你。"})


@app.post("/verify-email", response_class=HTMLResponse)
def verify_email_confirm(request: Request, token: str = Form(...)):
    token_hash = hash_verification_token(token.strip())
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        user = conn.execute(
            "SELECT id, email_verification_sent_at FROM users WHERE email_verification_token_hash=? AND email_verified=0",
            (token_hash,),
        ).fetchone()
        if not user or not is_verification_token_fresh(user["email_verification_sent_at"]):
            conn.rollback()
            return templates.TemplateResponse(request, "verify_email.html", {"success": False, "valid": False, "token": "", "message": "验证链接无效或已过期。请登录控制台后重新发送验证邮件。"}, status_code=400)
        now = now_iso()
        changed = conn.execute(
            "UPDATE users SET email_verified=1, email_verified_at=?, email_verification_token_hash=NULL, email_verification_sent_at=NULL, updated_at=? WHERE id=? AND email_verification_token_hash=? AND email_verified=0",
            (now, now, user["id"], token_hash),
        ).rowcount
        if changed != 1:
            conn.rollback()
            return templates.TemplateResponse(request, "verify_email.html", {"success": False, "valid": False, "token": "", "message": "验证链接无效或已经使用过。"}, status_code=400)
        conn.commit()
    return templates.TemplateResponse(request, "verify_email.html", {"success": True, "valid": False, "token": "", "message": "邮箱已验证，可返回登录页面。"})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.head("/login")
def login_head() -> None:
    return None


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    identity = client_identity(request)
    reservation = reserve_login_attempt(username, identity.address, identity.verified)
    if reservation is None:
        return templates.TemplateResponse(request, "login.html", {"error": "尝试次数过多，请 15 分钟后再试。", "username": username}, status_code=429, headers={"Retry-After": "900"})
    try:
        user = authenticate_user(username, password)
    except Exception:
        cancel_login_attempt(reservation)
        raise
    if not user:
        return templates.TemplateResponse(request, "login.html", {"error": "用户名或密码不正确，请重试。", "username": username}, status_code=401)
    release_login_attempt(reservation)
    with connect() as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso(), user["id"]))
        conn.commit()
    response = RedirectResponse("/admin" if user["role"] == "admin" else "/developer", status_code=303)
    response.set_cookie(SESSION_COOKIE, create_session(user["username"]), max_age=SESSION_MAX_AGE_SECONDS, httponly=True, secure=True, samesite="lax")
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="lax")
    return response


@app.get("/developer", response_class=HTMLResponse)
def developer_home(request: Request, user=Depends(require_developer)):
    with connect() as conn:
        keys = conn.execute("SELECT id,name,key_prefix,status FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        today = now_iso()[:10]
        usage_today = conn.execute("SELECT COUNT(*) AS c FROM api_usage_logs WHERE user_id = ? AND created_at LIKE ?", (user["id"], f"{today}%")).fetchone()["c"]
        recent = conn.execute("SELECT * FROM api_usage_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10", (user["id"],)).fetchall()
        routes = conn.execute("SELECT * FROM public_gateway_routes WHERE public_docs = 1 ORDER BY public_path").fetchall()
        wallet = wallet_snapshot(conn, user["id"])
    usage = read_usage_summary(user["id"])
    return templates.TemplateResponse(request, "developer.html", {"user": user, "keys": keys, "usage_today": usage_today, "recent": recent, "routes": routes, "wallet": wallet, "usage": usage})


@app.post("/developer/resend-verification")
def resend_verification(request: Request, user=Depends(require_developer)):
    if int(user["email_verified"] or 0):
        return RedirectResponse("/developer?verification=already", status_code=303)
    source_ip = client_address(request)
    if not claim_verification_send(user["email"], source_ip):
        return RedirectResponse("/developer?verification=queued", status_code=303)
    token, token_hash, sent_at = new_token_record()
    try:
        send_verification_email(user["email"], user["username"], token)
    except Exception as exc:
        logger.warning("verification_resend_failed request_id=%s error_type=%s", diagnostic_request_id(request), type(exc).__name__)
        return RedirectResponse("/developer?verification=failed", status_code=303)
    try:
        with connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET email_verification_token_hash=?, email_verification_sent_at=?, updated_at=?
                WHERE id=? AND email_verified=0
                """,
                (token_hash, sent_at, now_iso(), user["id"]),
            )
            conn.commit()
    except Exception as exc:
        logger.warning("verification_token_activation_failed request_id=%s error_type=%s", diagnostic_request_id(request), type(exc).__name__)
        return RedirectResponse("/developer?verification=processing", status_code=303)
    return RedirectResponse("/developer?verification=sent", status_code=303)


@app.get("/developer/keys", response_class=HTMLResponse)
def developer_keys(request: Request, user=Depends(require_developer), created: str | None = None):
    with connect() as conn:
        requests = conn.execute("SELECT * FROM api_key_requests WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    keys = key_views(user["id"])
    return templates.TemplateResponse(request, "developer_keys.html", {"user": user, "keys": keys, "requests": requests, "created": created == "1", "key_nonce": self_key_nonce(user["id"])})


@app.post("/developer/keys/request")
def developer_key_request(request: Request, name: str = Form(...), key_nonce: str = Form(""), requested_scopes: str = Form(""), requested_reason: str = Form(""), user=Depends(require_developer)):
    scopes = {s for s in re.split(r"[,\s]+", requested_scopes.strip()) if s}
    if scopes - {"models:read", "chat:completions", "responses:create"}:
        raise HTTPException(400, "自助密钥只支持 AI 协议权限；业务服务权限请联系管理员。")
    with connect() as conn:
        result = issue_self_key(conn, user["id"], name, key_nonce)
    return templates.TemplateResponse(request, "developer_key_created.html", {"user": user, "result": result}, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.post("/developer/keys/{key_id}/revoke")
def developer_revoke_key(key_id: int, user=Depends(require_developer)):
    with connect() as conn:
        conn.execute("UPDATE api_keys SET status='revoked', revoked_at=? WHERE id=? AND user_id=?", (now_iso(), key_id, user["id"]))
        conn.commit()
    return RedirectResponse("/developer/keys", status_code=303)


@app.get("/developer/logs", response_class=HTMLResponse)
def developer_logs(request: Request, user=Depends(require_developer)):
    with connect() as conn:
        logs = conn.execute("SELECT * FROM api_usage_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100", (user["id"],)).fetchall()
    return templates.TemplateResponse(request, "developer_logs.html", {"user": user, "logs": logs})


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user=Depends(require_admin)):
    today = now_iso()[:10]
    with connect() as conn:
        stats = {
            "users": conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
            "pending_users": conn.execute("SELECT COUNT(*) AS c FROM users WHERE status='pending'").fetchone()["c"],
            "key_requests": conn.execute("SELECT COUNT(*) AS c FROM api_key_requests WHERE status='pending'").fetchone()["c"],
            "calls_today": conn.execute("SELECT COUNT(*) AS c FROM api_usage_logs WHERE created_at LIKE ?", (f"{today}%",)).fetchone()["c"],
        }
        recent = conn.execute("SELECT * FROM api_usage_logs ORDER BY created_at DESC LIMIT 10").fetchall()
    return templates.TemplateResponse(request, "admin.html", {"user": user, "stats": stats, "recent": recent})


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        users = conn.execute("SELECT users.*, (SELECT COUNT(*) FROM api_keys WHERE api_keys.user_id=users.id) AS key_count FROM users ORDER BY created_at DESC").fetchall()
    return templates.TemplateResponse(request, "admin_users.html", {"user": user, "users": users})


@app.post("/admin/users/{user_id}/status")
def admin_user_status(user_id: int, status_value: str = Form(...), user=Depends(require_admin)):
    if status_value not in {"pending", "active", "suspended", "disabled"}:
        raise HTTPException(status_code=400, detail="账户状态无效。")
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="不能修改自己的账户状态，以免失去管理权限。")
    with connect() as conn:
        conn.execute("UPDATE users SET status=?, updated_at=? WHERE id=?", (status_value, now_iso(), user_id))
        conn.commit()
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/admin/key-requests", response_class=HTMLResponse)
def admin_key_requests(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        rows = conn.execute(
            "SELECT api_key_requests.*, users.username FROM api_key_requests JOIN users ON users.id=api_key_requests.user_id ORDER BY api_key_requests.created_at DESC"
        ).fetchall()
    return templates.TemplateResponse(request, "admin_key_requests.html", {"user": user, "requests": rows, "new_key": None, "prefix": None})


@app.post("/admin/key-requests/{request_id}/approve")
def admin_approve_key(request: Request, request_id: int, scopes: str = Form("models:read,chat:completions"), rate_limit_per_minute: int = Form(60),
                      daily_quota: int = Form(1000), monthly_quota: int = Form(30000), expires_at: str = Form(""),
                      models: str = Form(""),
                      user=Depends(require_admin)):
    scopes, model_ids, expiry = validate_policy(scopes, models, rate_limit_per_minute, daily_quota, monthly_quota, expires_at)
    allowed_routes = ""
    raw_key, prefix = generate_api_key()
    encoded_key = hash_api_key(raw_key)
    now = now_iso()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        req = conn.execute("SELECT * FROM api_key_requests WHERE id=?", (request_id,)).fetchone()
        if not req:
            raise HTTPException(status_code=404)
        if req["status"] != "pending":
            raise HTTPException(409, "该申请已处理，不能重复签发。")
        owner = conn.execute("SELECT status,email_verified FROM users WHERE id=?", (req["user_id"],)).fetchone()
        if not owner or not api_user_eligible(owner["status"]):
            raise HTTPException(400, "账户已停用，无法签发密钥。")
        cursor = conn.execute(
            """
            INSERT INTO api_keys(user_id, name, key_prefix, key_hash, status, scopes, allowed_routes,
            rate_limit_per_minute, daily_quota, monthly_quota, created_at, approved_at, expires_at, model_policy)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, 'allowlist')
            """,
            (req["user_id"], req["name"], prefix, encoded_key, scopes, allowed_routes, rate_limit_per_minute, daily_quota, monthly_quota, now, now, expiry),
        )
        conn.executemany("INSERT INTO api_key_models(api_key_id,model_id) VALUES (?,?)", [(cursor.lastrowid, model) for model in model_ids])
        conn.execute("UPDATE api_key_requests SET status='approved', reviewed_at=?, reviewed_by=? WHERE id=?", (now, user["id"], request_id))
        conn.commit()
    return templates.TemplateResponse(request, "admin_key_approved.html", {"user": user, "new_key": raw_key, "prefix": prefix})


@app.post("/admin/key-requests/{request_id}/reject")
def admin_reject_key(request_id: int, admin_note: str = Form(""), user=Depends(require_admin)):
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        req = conn.execute("SELECT status FROM api_key_requests WHERE id=?", (request_id,)).fetchone()
        if not req:
            raise HTTPException(404, "申请不存在")
        if req["status"] != "pending":
            raise HTTPException(409, "该申请已经处理")
        conn.execute("UPDATE api_key_requests SET status='rejected', admin_note=?, reviewed_at=?, reviewed_by=? WHERE id=? AND status='pending'", (admin_note, now_iso(), user["id"], request_id))
        conn.commit()
    return RedirectResponse("/admin/key-requests", status_code=303)


@app.get("/admin/routes", response_class=HTMLResponse)
def admin_routes(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        routes = conn.execute("SELECT public_gateway_routes.*, apis.name AS api_name FROM public_gateway_routes JOIN apis ON apis.id=public_gateway_routes.target_api_id ORDER BY public_path").fetchall()
        apis = conn.execute("SELECT * FROM apis ORDER BY name").fetchall()
    return templates.TemplateResponse(request, "admin_routes.html", {"user": user, "routes": routes, "apis": apis, "methods": ALLOWED_METHODS})


@app.post("/admin/routes")
def admin_add_route(name: str = Form(...), public_path: str = Form(...), target_api_id: int = Form(...),
                    target_method: str = Form("GET"), target_path: str = Form(...), required_scope: str = Form(""),
                    enabled: str | None = Form(None), public_docs: str | None = Form(None), allow_anonymous: str | None = Form(None),
                    user=Depends(require_admin)):
    now = now_iso()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO public_gateway_routes(name, public_path, target_api_id, target_endpoint_id, target_method, target_path,
            required_scope, enabled, public_docs, allow_anonymous, created_at, updated_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name.strip(), public_path.strip("/"), target_api_id, target_method.upper(), target_path.strip(), required_scope.strip(),
             1 if enabled else 0, 1 if public_docs else 0, 1 if allow_anonymous else 0, now, now),
        )
        conn.commit()
    return RedirectResponse("/admin/routes", status_code=303)


@app.post("/admin/routes/{route_id}/toggle")
def admin_toggle_route(route_id: int, enabled: int = Form(0), user=Depends(require_admin)):
    with connect() as conn:
        conn.execute("UPDATE public_gateway_routes SET enabled=?, updated_at=? WHERE id=?", (1 if enabled else 0, now_iso(), route_id))
        conn.commit()
    return RedirectResponse("/admin/routes", status_code=303)


@app.get("/admin/logs", response_class=HTMLResponse)
def admin_usage_logs(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        logs = conn.execute("SELECT api_usage_logs.*, users.username FROM api_usage_logs LEFT JOIN users ON users.id=api_usage_logs.user_id ORDER BY api_usage_logs.created_at DESC LIMIT 200").fetchall()
    return templates.TemplateResponse(request, "admin_logs.html", {"user": user, "logs": logs})


@app.get("/apis", response_class=HTMLResponse)
def apis_page(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        apis = conn.execute("SELECT * FROM apis ORDER BY name").fetchall()
    return templates.TemplateResponse(request, "apis.html", {"user": user, "apis": apis, "auth_types": AUTH_TYPES})


@app.post("/apis")
def add_api(name: str = Form(...), slug: str = Form(...), base_url: str = Form(...), auth_type: str = Form("none"),
            secret_ref: str = Form(""), description: str = Form(""), tags: str = Form(""),
            enabled: str | None = Form(None), user=Depends(require_admin)):
    now = now_iso()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO apis(name, slug, base_url, auth_type, secret_ref, description, tags, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name.strip(), slug.strip(), base_url.strip(), auth_type, secret_ref.strip() or None, description.strip(), tags.strip(), 1 if enabled else 0, now, now),
        )
        conn.commit()
    return RedirectResponse("/apis", status_code=303)


@app.get("/apis/{api_id}", response_class=HTMLResponse)
def api_detail(api_id: int, request: Request, user=Depends(require_admin)):
    with connect() as conn:
        api = conn.execute("SELECT * FROM apis WHERE id = ?", (api_id,)).fetchone()
        if not api:
            raise HTTPException(status_code=404)
        endpoints = conn.execute("SELECT * FROM endpoints WHERE api_id = ? ORDER BY method, path", (api_id,)).fetchall()
    return templates.TemplateResponse(request, "api_detail.html", {"user": user, "api": api, "endpoints": endpoints, "methods": ALLOWED_METHODS})


@app.post("/apis/{api_id}/endpoints")
def add_endpoint(api_id: int, name: str = Form(...), method: str = Form("GET"), path: str = Form(...),
                 description: str = Form(""), default_headers: str = Form("{}"), default_query: str = Form("{}"),
                 default_body: str = Form(""), enabled: str | None = Form(None), user=Depends(require_admin)):
    now = now_iso()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO endpoints(api_id, name, method, path, description, default_headers, default_query, default_body, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (api_id, name.strip(), method.upper(), path.strip(), description.strip(), default_headers.strip() or "{}", default_query.strip() or "{}", default_body.strip(), 1 if enabled else 0, now, now),
        )
        conn.commit()
    return RedirectResponse(f"/apis/{api_id}", status_code=303)


@app.get("/tester", response_class=HTMLResponse)
def tester_page(request: Request, api_id: int | None = None, endpoint_id: int | None = None, user=Depends(require_admin)):
    return _tester_response(request, user, api_id=api_id, endpoint_id=endpoint_id)


@app.post("/tester", response_class=HTMLResponse)
def tester_submit(request: Request, api_id: int = Form(...), method: str = Form("GET"), path: str = Form(...),
                  headers_json: str = Form("{}"), query_json: str = Form("{}"), body_json: str = Form(""),
                  use_saved_auth: str | None = Form(None), user=Depends(require_admin)):
    with connect() as conn:
        api = conn.execute("SELECT * FROM apis WHERE id = ?", (api_id,)).fetchone()
    result = error = None
    try:
        result = send_test_request(api, method, path, headers_json, query_json, body_json, bool(use_saved_auth))
        _record_log(api_id, None, method.upper(), result, user["username"])
    except TesterError as exc:
        error = str(exc)
        _record_manual_error(api_id, method.upper(), path, error, user["username"])
    return _tester_response(request, user, api_id=api_id, form={"method": method.upper(), "path": path, "headers_json": headers_json, "query_json": query_json, "body_json": body_json, "use_saved_auth": bool(use_saved_auth)}, result=result, error=error)


def _tester_response(request: Request, user, api_id: int | None = None, endpoint_id: int | None = None, form: dict | None = None, result=None, error: str | None = None):
    with connect() as conn:
        apis = conn.execute("SELECT * FROM apis WHERE enabled = 1 ORDER BY name").fetchall()
        endpoints = conn.execute("SELECT * FROM endpoints WHERE enabled = 1 ORDER BY api_id, method, path").fetchall()
        selected_endpoint = conn.execute("SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)).fetchone() if endpoint_id else None
    form = form or {"method": selected_endpoint["method"] if selected_endpoint else "GET", "path": selected_endpoint["path"] if selected_endpoint else "", "headers_json": selected_endpoint["default_headers"] if selected_endpoint else "{}", "query_json": selected_endpoint["default_query"] if selected_endpoint else "{}", "body_json": selected_endpoint["default_body"] if selected_endpoint else "", "use_saved_auth": True}
    return templates.TemplateResponse(request, "tester.html", {"user": user, "apis": apis, "endpoints": endpoints, "selected_api_id": api_id, "methods": ALLOWED_METHODS, "form": form, "result": result, "error": error})


def _record_log(api_id: int | None, endpoint_id: int | None, method: str, result, caller: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO request_logs(created_at, api_id, endpoint_id, method, url_masked, status_code, response_time_ms,
            success, error_summary, caller, request_preview, response_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now_iso(), api_id, endpoint_id, method, result.url_masked, result.status_code, result.response_time_ms, 1 if result.success else 0, result.error_summary, caller, result.request_preview, result.response_preview),
        )
        conn.commit()


def _record_manual_error(api_id: int | None, method: str, path: str, error: str, caller: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO request_logs(created_at, api_id, endpoint_id, method, url_masked, status_code, response_time_ms,
            success, error_summary, caller, request_preview, response_preview)
            VALUES (?, ?, NULL, ?, ?, NULL, NULL, 0, ?, ?, ?, '')
            """,
            (now_iso(), api_id, method, redact_url(path), preview(error, 500), caller, preview({"path": path, "error": error})),
        )
        conn.commit()


@app.get("/secrets", response_class=HTMLResponse)
def secrets_page(request: Request, user=Depends(require_admin)):
    seed()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM secrets ORDER BY name").fetchall()
    return templates.TemplateResponse(request, "secrets.html", {"user": user, "secrets": rows})


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        logs = conn.execute("SELECT request_logs.*, apis.name AS api_name FROM request_logs LEFT JOIN apis ON apis.id = request_logs.api_id ORDER BY request_logs.created_at DESC LIMIT 100").fetchall()
    return templates.TemplateResponse(request, "logs.html", {"user": user, "logs": logs})


@app.head("/docs")
def docs_head() -> None:
    return None


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user=Depends(require_admin)):
    status_panel = {
        "Database": "exists" if Path(settings.database_path).exists() else "missing",
        "App port": settings.app_port,
        "Session secret": "configured" if settings.session_secret else "missing",
        "Admin": "configured",
        "Environment": settings.app_env,
        "AstrBot credential": secret_status("ASTRBOT_API_KEY"),
        "LuomoCore credential": secret_status("LUOMOCORE_API_TOKEN"),
        "SMTP host": settings.smtp_host or "missing",
        "SMTP username": "configured" if settings.smtp_username else "missing",
        "SMTP password": secret_status("SMTP_PASSWORD"),
        "Email verification TTL hours": settings.email_verification_ttl_hours,
    }
    return templates.TemplateResponse(request, "settings.html", {"user": user, "status": status_panel})



@app.get("/admin/api-keys", response_class=HTMLResponse)
def admin_api_keys(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        keys = conn.execute(
            """
            SELECT
                k.id,k.name,k.key_prefix,k.status,k.scopes,k.allowed_routes,k.rate_limit_per_minute,k.daily_quota,k.monthly_quota,k.expires_at,k.last_used_at,
                u.username,
                u.email
            FROM api_keys k
            LEFT JOIN users u ON u.id = k.user_id
            ORDER BY k.created_at DESC
            """
        ).fetchall()
    return templates.TemplateResponse(request, "admin_api_keys.html", {"user": user,
            "keys": keys,
        },
    )


@app.post("/admin/api-keys/{key_id}/status")
def admin_api_key_status(
    key_id: int,
    status_value: str = Form(...),
    user=Depends(require_admin),
):
    if status_value not in {"active", "revoked"}:
        status_value = "revoked"

    with connect() as conn:
        if status_value == "revoked":
            conn.execute(
                "UPDATE api_keys SET status='revoked', revoked_at=? WHERE id=?",
                (now_iso(), key_id),
            )
        else:
            conn.execute(
                "UPDATE api_keys SET status='active', revoked_at=NULL WHERE id=?",
                (key_id,),
            )
        conn.commit()

    return RedirectResponse("/admin/api-keys", status_code=303)
