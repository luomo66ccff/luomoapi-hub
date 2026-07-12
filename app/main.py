from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api_client import TesterError, send_test_request
from app.auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    authenticate_user,
    current_user,
    hash_password,
    optional_user,
    require_admin,
    require_developer,
)
from app.config import secret_status, settings
from app.db import connect, init_db
from app.email_verification import (
    hash_verification_token,
    is_verification_token_fresh,
    new_token_record,
    send_verification_email,
)
from app.gateway import router as gateway_router
from app.keyring import generate_api_key, hash_api_key
from app.models import ALLOWED_METHODS, AUTH_TYPES
from app.security import security_headers
from app.utils.redact import preview, redact_url
from app.utils.timefmt import now_iso
from scripts.seed_default_apis import seed
from app.public_stats import router as public_stats_router
from app.public_gateway_secure import router as public_gateway_secure_router
from app.error_redirect import error_redirect_middleware


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
app.include_router(public_stats_router)
app.include_router(public_gateway_secure_router)
templates = Jinja2Templates(directory="app/web/templates")
app.mount("/static", StaticFiles(directory="app/web/static"), name="static")
app.middleware("http")(security_headers)
app.middleware("http")(error_redirect_middleware)
app.include_router(gateway_router)


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
def startup() -> None:
    init_db()
    seed()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.head("/health")
def health_head() -> None:
    return None


@app.get("/api/public/status")
def api_public_status() -> dict:
    with connect() as conn:
        routes_count = conn.execute("SELECT COUNT(*) AS c FROM public_gateway_routes").fetchone()["c"]
        enabled_routes_count = conn.execute("SELECT COUNT(*) AS c FROM public_gateway_routes WHERE enabled=1").fetchone()["c"]
        public_docs_routes_count = conn.execute("SELECT COUNT(*) AS c FROM public_gateway_routes WHERE public_docs=1").fetchone()["c"]
        apis_count = conn.execute("SELECT COUNT(*) AS c FROM apis").fetchone()["c"]
        enabled_apis_count = conn.execute("SELECT COUNT(*) AS c FROM apis WHERE enabled=1").fetchone()["c"]
        active_keys_count = conn.execute("SELECT COUNT(*) AS c FROM api_keys WHERE status='active'").fetchone()["c"]
    return {
        "service": "LuomoAPI Hub",
        "status": "operational",
        "updated_at": now_iso(),
        "version": getattr(settings, "app_version", "0.1.0"),
        "apis_count": apis_count,
        "enabled_apis_count": enabled_apis_count,
        "routes_count": routes_count,
        "enabled_routes_count": enabled_routes_count,
        "public_docs_routes_count": public_docs_routes_count,
        "active_keys_count": active_keys_count,
    }


@app.get("/", response_class=HTMLResponse)
def public_home(request: Request, user=Depends(optional_user)):
    with connect() as conn:
        route_count = conn.execute("SELECT COUNT(*) AS c FROM public_gateway_routes WHERE public_docs = 1").fetchone()["c"]
    return templates.TemplateResponse("public_home.html", {"request": request, "user": user, "route_count": route_count})


@app.head("/")
def public_home_head() -> None:
    return None


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None, "message": None, "submitted": False})


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
        error = "Password must be at least 10 characters."
    elif password != confirm_password:
        error = "Passwords do not match."
    elif not username or not email:
        error = "Username and email are required."
    if error:
        return templates.TemplateResponse("register.html", {"request": request, "error": error, "message": None, "submitted": False}, status_code=400)
    now = now_iso()
    token, token_hash, sent_at = new_token_record()
    try:
        with connect() as conn:
            conn.execute(
                """
                INSERT INTO users(username, email, password_hash, role, status, usage_reason,
                email_verified, email_verification_token_hash, email_verification_sent_at, created_at, updated_at)
                VALUES (?, ?, ?, 'developer', 'pending', ?, 0, ?, ?, ?, ?)
                """,
                (username, email, hash_password(password), usage_reason, token_hash, sent_at, now, now),
            )
            conn.commit()
    except Exception:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Registration could not be submitted.", "message": None, "submitted": False}, status_code=400)
    try:
        send_verification_email(email, username, token)
        message = "Registration submitted. Please check your email and verify your account before requesting API keys."
    except Exception:
        message = "Registration submitted, but the verification email could not be sent. Sign in and use resend verification."
    return templates.TemplateResponse("register.html", {"request": request, "error": None, "message": message, "submitted": True})


@app.get("/verify-email", response_class=HTMLResponse)
def verify_email(request: Request, token: str = ""):
    token_hash = hash_verification_token(token.strip()) if token else ""
    with connect() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email_verification_token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not user:
            return templates.TemplateResponse("verify_email.html", {"request": request, "success": False, "message": "Verification link is invalid or already used."}, status_code=400)
        if not is_verification_token_fresh(user["email_verification_sent_at"]):
            conn.execute(
                "UPDATE users SET email_verification_token_hash=NULL, updated_at=? WHERE id=?",
                (now_iso(), user["id"]),
            )
            conn.commit()
            return templates.TemplateResponse("verify_email.html", {"request": request, "success": False, "message": "Verification link expired. Please sign in and resend verification."}, status_code=400)
        now = now_iso()
        conn.execute(
            """
            UPDATE users
            SET email_verified=1, email_verified_at=?, email_verification_token_hash=NULL,
            email_verification_sent_at=NULL, updated_at=?
            WHERE id=?
            """,
            (now, now, user["id"]),
        )
        conn.commit()
    return templates.TemplateResponse("verify_email.html", {"request": request, "success": True, "message": "Email verified. Your account can now be reviewed by an admin."})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.head("/login")
def login_head() -> None:
    return None


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password."}, status_code=401)
    with connect() as conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso(), user["id"]))
        conn.commit()
    response = RedirectResponse("/admin" if user["role"] == "admin" else "/developer", status_code=303)
    from app.auth import create_session
    response.set_cookie(SESSION_COOKIE, create_session(user["username"]), max_age=SESSION_MAX_AGE_SECONDS, httponly=True, secure=True, samesite="lax")
    return response


@app.get("/logout")
@app.post("/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/developer", response_class=HTMLResponse)
def developer_home(request: Request, user=Depends(require_developer)):
    with connect() as conn:
        keys = conn.execute("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        today = now_iso()[:10]
        usage_today = conn.execute("SELECT COUNT(*) AS c FROM api_usage_logs WHERE user_id = ? AND created_at LIKE ?", (user["id"], f"{today}%")).fetchone()["c"]
        recent = conn.execute("SELECT * FROM api_usage_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10", (user["id"],)).fetchall()
        routes = conn.execute("SELECT * FROM public_gateway_routes WHERE public_docs = 1 ORDER BY public_path").fetchall()
    return templates.TemplateResponse("developer.html", {"request": request, "user": user, "keys": keys, "usage_today": usage_today, "recent": recent, "routes": routes})


@app.post("/developer/resend-verification")
def resend_verification(user=Depends(require_developer)):
    if int(user["email_verified"] or 0):
        return RedirectResponse("/developer?verification=already", status_code=303)
    token, token_hash, sent_at = new_token_record()
    with connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET email_verification_token_hash=?, email_verification_sent_at=?, updated_at=?
            WHERE id=?
            """,
            (token_hash, sent_at, now_iso(), user["id"]),
        )
        conn.commit()
    try:
        send_verification_email(user["email"], user["username"], token)
        return RedirectResponse("/developer?verification=sent", status_code=303)
    except Exception:
        return RedirectResponse("/developer?verification=failed", status_code=303)


@app.get("/developer/keys", response_class=HTMLResponse)
def developer_keys(request: Request, user=Depends(require_developer), created: str | None = None):
    with connect() as conn:
        keys = conn.execute("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
        requests = conn.execute("SELECT * FROM api_key_requests WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    return templates.TemplateResponse("developer_keys.html", {"request": request, "user": user, "keys": keys, "requests": requests, "created": created == "1"})


@app.post("/developer/keys/request")
def developer_key_request(name: str = Form(...), requested_scopes: str = Form(""), requested_reason: str = Form(""), user=Depends(require_developer)):
    if user["status"] != "active" or not int(user["email_verified"] or 0):
        return RedirectResponse("/developer/keys?created=0", status_code=303)
    now = now_iso()
    with connect() as conn:
        conn.execute(
            "INSERT INTO api_key_requests(user_id, name, requested_scopes, requested_reason, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (user["id"], name.strip(), requested_scopes.strip(), requested_reason.strip(), now),
        )
        conn.commit()
    return RedirectResponse("/developer/keys?created=1", status_code=303)


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
    return templates.TemplateResponse("developer_logs.html", {"request": request, "user": user, "logs": logs})


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
    return templates.TemplateResponse("admin.html", {"request": request, "user": user, "stats": stats, "recent": recent})


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        users = conn.execute("SELECT users.*, (SELECT COUNT(*) FROM api_keys WHERE api_keys.user_id=users.id) AS key_count FROM users ORDER BY created_at DESC").fetchall()
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users})


@app.post("/admin/users/{user_id}/status")
def admin_user_status(user_id: int, status_value: str = Form(...), user=Depends(require_admin)):
    if status_value not in {"pending", "active", "suspended", "disabled"}:
        status_value = "pending"
    with connect() as conn:
        target = conn.execute("SELECT role, email_verified FROM users WHERE id=?", (user_id,)).fetchone()
        if status_value == "active" and target and target["role"] != "admin" and not int(target["email_verified"] or 0):
            status_value = "pending"
        conn.execute("UPDATE users SET status=?, updated_at=? WHERE id=?", (status_value, now_iso(), user_id))
        conn.commit()
    return RedirectResponse("/admin/users", status_code=303)


@app.get("/admin/key-requests", response_class=HTMLResponse)
def admin_key_requests(request: Request, user=Depends(require_admin), new_key: str | None = None, prefix: str | None = None):
    with connect() as conn:
        rows = conn.execute(
            "SELECT api_key_requests.*, users.username FROM api_key_requests JOIN users ON users.id=api_key_requests.user_id ORDER BY api_key_requests.created_at DESC"
        ).fetchall()
    return templates.TemplateResponse("admin_key_requests.html", {"request": request, "user": user, "requests": rows, "new_key": new_key, "prefix": prefix})


@app.post("/admin/key-requests/{request_id}/approve")
def admin_approve_key(request: Request, request_id: int, scopes: str = Form("*"), rate_limit_per_minute: int = Form(60),
                      daily_quota: int = Form(1000), monthly_quota: int = Form(30000), expires_at: str = Form(""),
                      user=Depends(require_admin)):
    raw_key, prefix = generate_api_key()
    now = now_iso()
    with connect() as conn:
        req = conn.execute("SELECT * FROM api_key_requests WHERE id=?", (request_id,)).fetchone()
        if not req:
            raise HTTPException(status_code=404)
        conn.execute(
            """
            INSERT INTO api_keys(user_id, name, key_prefix, key_hash, status, scopes, allowed_routes,
            rate_limit_per_minute, daily_quota, monthly_quota, created_at, approved_at, expires_at)
            VALUES (?, ?, ?, ?, 'active', ?, '', ?, ?, ?, ?, ?, ?)
            """,
            (req["user_id"], req["name"], prefix, hash_api_key(raw_key), scopes, rate_limit_per_minute, daily_quota, monthly_quota, now, now, expires_at or None),
        )
        conn.execute("UPDATE api_key_requests SET status='approved', reviewed_at=?, reviewed_by=? WHERE id=?", (now, user["id"], request_id))
        conn.commit()
    return templates.TemplateResponse("admin_key_approved.html", {"request": request, "user": user, "new_key": raw_key, "prefix": prefix})


@app.post("/admin/key-requests/{request_id}/reject")
def admin_reject_key(request_id: int, admin_note: str = Form(""), user=Depends(require_admin)):
    with connect() as conn:
        conn.execute("UPDATE api_key_requests SET status='rejected', admin_note=?, reviewed_at=?, reviewed_by=? WHERE id=?", (admin_note, now_iso(), user["id"], request_id))
        conn.commit()
    return RedirectResponse("/admin/key-requests", status_code=303)


@app.get("/admin/routes", response_class=HTMLResponse)
def admin_routes(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        routes = conn.execute("SELECT public_gateway_routes.*, apis.name AS api_name FROM public_gateway_routes JOIN apis ON apis.id=public_gateway_routes.target_api_id ORDER BY public_path").fetchall()
        apis = conn.execute("SELECT * FROM apis ORDER BY name").fetchall()
    return templates.TemplateResponse("admin_routes.html", {"request": request, "user": user, "routes": routes, "apis": apis, "methods": ALLOWED_METHODS})


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
    return templates.TemplateResponse("admin_logs.html", {"request": request, "user": user, "logs": logs})


@app.get("/apis", response_class=HTMLResponse)
def apis_page(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        apis = conn.execute("SELECT * FROM apis ORDER BY name").fetchall()
    return templates.TemplateResponse("apis.html", {"request": request, "user": user, "apis": apis, "auth_types": AUTH_TYPES})


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
    return templates.TemplateResponse("api_detail.html", {"request": request, "user": user, "api": api, "endpoints": endpoints, "methods": ALLOWED_METHODS})


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
    return templates.TemplateResponse("tester.html", {"request": request, "user": user, "apis": apis, "endpoints": endpoints, "selected_api_id": api_id, "methods": ALLOWED_METHODS, "form": form, "result": result, "error": error})


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
    return templates.TemplateResponse("secrets.html", {"request": request, "user": user, "secrets": rows})


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        logs = conn.execute("SELECT request_logs.*, apis.name AS api_name FROM request_logs LEFT JOIN apis ON apis.id = request_logs.api_id ORDER BY request_logs.created_at DESC LIMIT 100").fetchall()
    return templates.TemplateResponse("logs.html", {"request": request, "user": user, "logs": logs})


@app.get("/docs", response_class=HTMLResponse)
def docs_page(request: Request, user=Depends(optional_user)):
    with connect() as conn:
        routes = conn.execute("SELECT public_gateway_routes.*, apis.name AS api_name FROM public_gateway_routes JOIN apis ON apis.id=public_gateway_routes.target_api_id WHERE public_docs=1 ORDER BY public_path").fetchall()
    return templates.TemplateResponse("docs.html", {"request": request, "user": user, "routes": routes})


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
    return templates.TemplateResponse("settings.html", {"request": request, "user": user, "status": status_panel})



@app.get("/admin/api-keys", response_class=HTMLResponse)
def admin_api_keys(request: Request, user=Depends(require_admin)):
    with connect() as conn:
        keys = conn.execute(
            """
            SELECT
                k.*,
                u.username,
                u.email
            FROM api_keys k
            LEFT JOIN users u ON u.id = k.user_id
            ORDER BY k.created_at DESC
            """
        ).fetchall()
    return templates.TemplateResponse(
        "admin_api_keys.html",
        {
            "request": request,
            "user": user,
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
