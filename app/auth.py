import base64
import hashlib
import hmac
import secrets
import time
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request, status

from app.config import settings
from app.db import connect


SESSION_COOKIE = "luomoapi_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 12
PBKDF2_ITERATIONS = 260_000


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256:{PBKDF2_ITERATIONS}:{salt}:{base64.b64encode(digest).decode('ascii')}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        separator = ":" if ":" in encoded else "$"
        algorithm, iterations_text, salt, expected = encoded.split(separator, 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations_text))
        actual = base64.b64encode(digest).decode("ascii")
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def _sign(payload: str) -> str:
    return hmac.new(settings.session_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def create_session(username: str) -> str:
    expires_at = int(time.time()) + SESSION_MAX_AGE_SECONDS
    payload = base64.urlsafe_b64encode(f"{username}:{expires_at}".encode("utf-8")).decode("ascii")
    return f"{payload}.{_sign(payload)}"


def verify_session(token: str | None) -> str | None:
    if not token or "." not in token or not settings.session_secret:
        return None
    payload, _, signature = token.partition(".")
    if not secrets.compare_digest(signature, _sign(payload)):
        return None
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8")
        username, expires_text = raw.rsplit(":", 1)
        if int(expires_text) < int(time.time()):
            return None
    except Exception:
        return None
    return username


def get_user_by_username(username: str):
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user or user["status"] in {"disabled", "suspended"}:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def current_user(
    request: Request,
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) :
    username = verify_session(session_token)
    if username:
        user = get_user_by_username(username)
        if user and user["status"] not in {"disabled", "suspended"}:
            return user
    if "text/html" in request.headers.get("accept", ""):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


def optional_user(session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None):
    username = verify_session(session_token)
    return get_user_by_username(username) if username else None


def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_developer(user=Depends(current_user)):
    if user["role"] not in {"admin", "developer"}:
        raise HTTPException(status_code=403, detail="Developer access required")
    return user
