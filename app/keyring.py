import secrets

from app.auth import hash_password, verify_password


def generate_api_key() -> tuple[str, str]:
    raw = "lapi_" + secrets.token_urlsafe(32)
    return raw, raw[:14] + "..."


def hash_api_key(raw_key: str) -> str:
    return hash_password(raw_key)


def verify_api_key(raw_key: str, encoded: str) -> bool:
    return verify_password(raw_key, encoded)
