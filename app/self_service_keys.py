"""Self-service AI credentials with per-user form idempotency and precise grants."""
import hashlib
import hmac
import secrets
from fastapi import HTTPException
from app.auth import api_user_eligible
from app.config import settings
from app.credit_pricing import priced_models
from app.keyring import generate_api_key, hash_api_key
from app.utils.timefmt import now_iso

SELF_SCOPES = "models:read,chat:completions,responses:create"


def init_self_key_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS self_key_claims (
      user_id INTEGER NOT NULL REFERENCES users(id),
      nonce_hash TEXT NOT NULL,
      key_id INTEGER NOT NULL REFERENCES api_keys(id),
      created_at TEXT NOT NULL,
      PRIMARY KEY(user_id,nonce_hash)
    )""")


def _signature(user_id, nonce):
    return hmac.new(settings.session_secret.encode(), f"self-key:{user_id}:{nonce}".encode(), hashlib.sha256).hexdigest()


def self_key_nonce(user_id):
    nonce = secrets.token_hex(20)
    return nonce + "." + _signature(user_id, nonce)


def issue_self_key(conn, user_id, name, nonce):
    name = name.strip()
    if not 1 <= len(name) <= 100:
        raise HTTPException(400, "密钥名称需为 1–100 字符。")
    parts = nonce.split(".")
    if len(parts) != 2 or len(parts[0]) != 40 or not secrets.compare_digest(parts[1], _signature(user_id, parts[0])):
        raise HTTPException(400, "申请表单已失效，请重新打开密钥页面。")
    digest = hashlib.sha256(nonce.encode()).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    owner = conn.execute("SELECT status FROM users WHERE id=?", (user_id,)).fetchone()
    if not owner or not api_user_eligible(owner["status"]):
        raise HTTPException(403, "账户已停用，无法签发密钥。")
    old = conn.execute("SELECT key_id FROM self_key_claims WHERE user_id=? AND nonce_hash=?", (user_id, digest)).fetchone()
    if old:
        conn.commit()
        return {"key_id": old["key_id"], "raw_key": None, "duplicate": True}
    count = conn.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=? AND status!='revoked'", (user_id,)).fetchone()[0]
    if count >= 20:
        raise HTTPException(400, "最多保留 20 个有效密钥，请先撤销不再使用的密钥。")
    raw, prefix = generate_api_key()
    encoded = hash_api_key(raw)
    now = now_iso()
    cur = conn.execute("""INSERT INTO api_keys(user_id,name,key_prefix,key_hash,status,scopes,
        allowed_routes,model_policy,rate_limit_per_minute,daily_quota,monthly_quota,created_at,approved_at)
        VALUES (?,?,?,?,'active',?,'','allowlist',60,0,0,?,?)""", (user_id,name,prefix,encoded,SELF_SCOPES,now,now))
    key_id = cur.lastrowid
    conn.executemany("INSERT INTO api_key_models(api_key_id,model_id) VALUES (?,?)", [(key_id,m) for m in priced_models()])
    conn.execute("INSERT INTO self_key_claims(user_id,nonce_hash,key_id,created_at) VALUES (?,?,?,?)", (user_id,digest,key_id,now))
    conn.execute("""INSERT INTO api_key_requests(user_id,name,requested_scopes,requested_reason,status,admin_note,created_at,reviewed_at)
        VALUES (?,?,?,'注册用户积分自助签发','approved','无需管理员审核；AI 调用按用户积分结算',?,?)""", (user_id,name,SELF_SCOPES,now,now))
    conn.commit()
    return {"key_id": key_id, "raw_key": raw, "prefix": prefix, "duplicate": False}
