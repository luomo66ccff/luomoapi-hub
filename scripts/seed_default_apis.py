from app.config import settings, secret_status
from app.db import connect, init_db
from app.auth import hash_password
from app.utils.timefmt import now_iso


DEFAULT_APIS = [
    {
        "name": "AstrBot / ATRI",
        "slug": "astrbot",
        "base_url": settings.astrbot_base_url,
        "auth_type": "bearer",
        "secret_ref": "ASTRBOT_BRIDGE_TOKEN",
        "description": "AstrBot OpenAPI integration",
        "tags": "astrbot,bot,atri",
        "endpoints": [
            ("OpenAPI", "GET", "/openapi.json"),
            ("Health", "GET", "/health"),
            ("Plugins", "GET", "/astrbot/plugins"),
            ("Bots", "GET", "/astrbot/bots"),
            ("Coze health", "GET", "/coze/health"),
            ("Coze plugins", "GET", "/coze/astrbot/plugins"),
            ("Coze bots", "GET", "/coze/astrbot/bots"),
        ],
    },
    {
        "name": "LuomoCore",
        "slug": "luomocore",
        "base_url": settings.luomocore_base_url,
        "auth_type": "bearer",
        "secret_ref": "LUOMOCORE_API_TOKEN",
        "description": "LuomoCore operations and memory center",
        "tags": "ops,brain,core",
        "endpoints": [("Health", "GET", "/health")],
    },
]
DEFAULT_SECRETS = [
    ("AstrBot API Key", "ASTRBOT_API_KEY"),
    ("AstrBot Bridge Token", "ASTRBOT_BRIDGE_TOKEN"),
    ("LuomoCore API Token", "LUOMOCORE_API_TOKEN"),
    ("GitHub Token", "GITHUB_TOKEN"),
    ("Cloudflare API Token", "CLOUDFLARE_API_TOKEN"),
]
DEFAULT_PUBLIC_ROUTES = [
    ("LuomoCore health", "luomocore/health", "luomocore", "GET", "/health", "luomocore:health"),
    ("AstrBot OpenAPI", "astrbot/openapi", "astrbot", "GET", "/openapi.json", "astrbot:read"),
    ("AstrBot plugins", "astrbot/plugins", "astrbot", "GET", "/astrbot/plugins", "astrbot:read"),
]


def seed() -> None:
    init_db()
    now = now_iso()
    with connect() as conn:
        for item in DEFAULT_APIS:
            existing = conn.execute("SELECT id FROM apis WHERE slug = ?", (item["slug"],)).fetchone()
            if existing:
                api_id = existing["id"]
                conn.execute(
                    """
                    UPDATE apis SET name = ?, base_url = ?, auth_type = ?, secret_ref = ?,
                    description = ?, tags = ?, updated_at = ? WHERE id = ?
                    """,
                    (item["name"], item["base_url"], item["auth_type"], item["secret_ref"],
                     item["description"], item["tags"], now, api_id),
                )
            else:
                cur = conn.execute(
                    """
                    INSERT INTO apis(name, slug, base_url, auth_type, secret_ref, description, tags, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (item["name"], item["slug"], item["base_url"], item["auth_type"], item["secret_ref"],
                     item["description"], item["tags"], now, now),
                )
                api_id = cur.lastrowid
            for name, method, path in item["endpoints"]:
                row = conn.execute("SELECT id FROM endpoints WHERE api_id = ? AND method = ? AND path = ?", (api_id, method, path)).fetchone()
                if not row:
                    conn.execute(
                        """
                        INSERT INTO endpoints(api_id, name, method, path, description, default_headers, default_query, default_body, enabled, created_at, updated_at)
                        VALUES (?, ?, ?, ?, '', '{}', '{}', '', 1, ?, ?)
                        """,
                        (api_id, name, method, path, now, now),
                    )
        for name, key in DEFAULT_SECRETS:
            status = secret_status(key)
            existing = conn.execute("SELECT id FROM secrets WHERE key = ?", (key,)).fetchone()
            if existing:
                conn.execute("UPDATE secrets SET name = ?, status = ?, updated_at = ? WHERE key = ?", (name, status, now, key))
            else:
                conn.execute(
                    "INSERT INTO secrets(name, key, value_encrypted, status, created_at, updated_at) VALUES (?, ?, NULL, ?, ?, ?)",
                    (name, key, status, now, now),
                )
        admin = conn.execute("SELECT id FROM users WHERE username = ?", ("luomo",)).fetchone()
        if not admin and settings.admin_password_hash:
            conn.execute(
                """
                INSERT INTO users(username, email, password_hash, role, status, usage_reason, email_verified, email_verified_at, created_at, updated_at)
                VALUES (?, ?, ?, 'admin', 'active', 'Owner account', 1, ?, ?, ?)
                """,
                ("luomo", "luomo@luomo.moe", settings.admin_password_hash, now, now, now),
            )
        elif admin:
            conn.execute(
                "UPDATE users SET role='admin', status='active', email_verified=1, email_verified_at=COALESCE(email_verified_at, ?), updated_at=? WHERE username='luomo'",
                (now, now),
            )
        api_ids = {row["slug"]: row["id"] for row in conn.execute("SELECT id, slug FROM apis").fetchall()}
        for name, public_path, slug, method, target_path, scope in DEFAULT_PUBLIC_ROUTES:
            api_id = api_ids.get(slug)
            if not api_id:
                continue
            row = conn.execute("SELECT id FROM public_gateway_routes WHERE public_path = ?", (public_path,)).fetchone()
            if not row:
                conn.execute(
                    """
                    INSERT INTO public_gateway_routes(name, public_path, target_api_id, target_endpoint_id, target_method,
                    target_path, required_scope, enabled, public_docs, allow_anonymous, created_at, updated_at)
                    VALUES (?, ?, ?, NULL, ?, ?, ?, 0, 1, 0, ?, ?)
                    """,
                    (name, public_path, api_id, method, target_path, scope, now, now),
                )
            else:
                conn.execute(
                    """
                    UPDATE public_gateway_routes
                    SET name=?, target_api_id=?, target_method=?, target_path=?,
                    required_scope=?, public_docs=1, allow_anonymous=0, updated_at=?
                    WHERE public_path=?
                    """,
                    (name, api_id, method, target_path, scope, now, public_path),
                )
        conn.commit()


if __name__ == "__main__":
    seed()
    print("default APIs seeded")
