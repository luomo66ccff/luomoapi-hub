import sqlite3
from pathlib import Path

from app.config import ensure_dirs, settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    base_url TEXT NOT NULL,
    auth_type TEXT DEFAULT 'none',
    secret_ref TEXT,
    description TEXT,
    tags TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    description TEXT,
    default_headers TEXT,
    default_query TEXT,
    default_body TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(api_id) REFERENCES apis(id)
);
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    api_id INTEGER,
    endpoint_id INTEGER,
    method TEXT NOT NULL,
    url_masked TEXT NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    success INTEGER,
    error_summary TEXT,
    caller TEXT,
    request_preview TEXT,
    response_preview TEXT
);
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    value_encrypted TEXT,
    status TEXT DEFAULT 'missing',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    public_path TEXT NOT NULL UNIQUE,
    api_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    require_token INTEGER DEFAULT 1,
    rate_limit_per_minute INTEGER DEFAULT 60,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(api_id) REFERENCES apis(id),
    FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'developer',
    status TEXT NOT NULL DEFAULT 'pending',
    usage_reason TEXT,
    email_verified INTEGER DEFAULT 0,
    email_verification_token_hash TEXT,
    email_verification_sent_at TEXT,
    email_verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    scopes TEXT,
    allowed_routes TEXT,
    rate_limit_per_minute INTEGER DEFAULT 60,
    daily_quota INTEGER DEFAULT 1000,
    monthly_quota INTEGER DEFAULT 30000,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    revoked_at TEXT,
    expires_at TEXT,
    last_used_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS api_key_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    requested_scopes TEXT,
    requested_reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_note TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(reviewed_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS public_gateway_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    public_path TEXT NOT NULL UNIQUE,
    target_api_id INTEGER NOT NULL,
    target_endpoint_id INTEGER,
    target_method TEXT NOT NULL,
    target_path TEXT NOT NULL,
    required_scope TEXT,
    enabled INTEGER DEFAULT 1,
    public_docs INTEGER DEFAULT 1,
    allow_anonymous INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_api_id) REFERENCES apis(id),
    FOREIGN KEY(target_endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    user_id INTEGER,
    api_key_id INTEGER,
    route_id INTEGER,
    method TEXT NOT NULL,
    public_path TEXT NOT NULL,
    target_url_masked TEXT,
    status_code INTEGER,
    response_time_ms INTEGER,
    success INTEGER,
    client_ip_hash TEXT,
    user_agent_preview TEXT,
    error_summary TEXT,
    request_preview TEXT,
    response_preview TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id),
    FOREIGN KEY(route_id) REFERENCES public_gateway_routes(id)
);
"""


def connect() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(settings.database_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    ensure_dirs()
    with connect() as conn:
        conn.executescript(SCHEMA)
        _ensure_columns(conn)
        conn.commit()


def _ensure_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    additions = {
        "email_verified": "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
        "email_verification_token_hash": "ALTER TABLE users ADD COLUMN email_verification_token_hash TEXT",
        "email_verification_sent_at": "ALTER TABLE users ADD COLUMN email_verification_sent_at TEXT",
        "email_verified_at": "ALTER TABLE users ADD COLUMN email_verified_at TEXT",
    }
    for column, statement in additions.items():
        if column not in columns:
            conn.execute(statement)
