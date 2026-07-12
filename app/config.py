import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    app_name: str = env("APP_NAME", "LuomoAPI Hub")
    app_env: str = env("APP_ENV", "production")
    app_host: str = env("APP_HOST", "0.0.0.0")
    app_port: int = int(env("APP_PORT", "8790") or "8790")
    app_base_url: str = env("APP_BASE_URL", "https://api.luomo.moe")
    database_path: Path = Path(env("DATABASE_PATH", "/app/data/luomoapi.db"))
    admin_username: str = env("ADMIN_USERNAME", "luomo")
    admin_password_hash: str = env("ADMIN_PASSWORD_HASH", "")
    session_secret: str = env("SESSION_SECRET", "")
    astrbot_base_url: str = env("ASTRBOT_BASE_URL", "https://atri-api.luomo.moe")
    luomocore_base_url: str = env("LUOMOCORE_BASE_URL", "https://ops.luomo.moe")
    smtp_host: str = env("SMTP_HOST", "")
    smtp_port: int = int(env("SMTP_PORT", "465") or "465")
    smtp_username: str = env("SMTP_USERNAME", "")
    smtp_password: str = env("SMTP_PASSWORD", "")
    smtp_from: str = env("SMTP_FROM", env("SMTP_USERNAME", ""))
    smtp_use_tls: bool = env("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
    email_verification_ttl_hours: int = int(env("EMAIL_VERIFICATION_TTL_HOURS", "24") or "24")


settings = Settings()


def ensure_dirs() -> None:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)


def secret_status(key: str) -> str:
    return "configured" if os.getenv(key) else "missing"
