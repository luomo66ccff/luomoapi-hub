import getpass
import secrets
from pathlib import Path

from app.auth import hash_password


ENV_PATH = Path(".env")


def update_env(updates: dict[str, str]) -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    seen = set()
    out = []
    for line in lines:
        if not line.strip() or line.strip().startswith("#") or "=" not in line:
            out.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key}={value}")
    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> None:
    username = input("Admin username: ").strip() or "luomo"
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("passwords do not match")
    if len(password) < 12:
        raise SystemExit("password must be at least 12 characters")
    update_env({
        "ADMIN_USERNAME": username,
        "ADMIN_PASSWORD_HASH": hash_password(password),
        "SESSION_SECRET": secrets.token_urlsafe(48),
    })
    ENV_PATH.chmod(0o600)
    print("admin credential updated")


if __name__ == "__main__":
    main()
