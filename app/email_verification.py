import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import settings
from app.utils.timefmt import now_iso


def generate_verification_token() -> str:
    return secrets.token_urlsafe(40)


def hash_verification_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verification_link(token: str) -> str:
    return f"{settings.app_base_url.rstrip('/')}/verify-email?{urlencode({'token': token})}"


def is_verification_token_fresh(sent_at: str | None) -> bool:
    if not sent_at:
        return False
    try:
        created = datetime.fromisoformat(sent_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - created <= timedelta(hours=settings.email_verification_ttl_hours)


def smtp_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_port and settings.smtp_username and settings.smtp_password and settings.smtp_from)


def send_verification_email(email: str, username: str, token: str) -> None:
    if not smtp_configured():
        raise RuntimeError("SMTP is not configured.")

    link = verification_link(token)
    message = EmailMessage()
    message["Subject"] = "Verify your LuomoAPI Hub email"
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(
        "\n".join(
            [
                f"Hi {username},",
                "",
                "Please verify your LuomoAPI Hub account email:",
                link,
                "",
                f"This link expires in {settings.email_verification_ttl_hours} hours.",
                "If you did not request this account, you can ignore this email.",
            ]
        )
    )

    if settings.smtp_use_tls:
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)


def new_token_record() -> tuple[str, str, str]:
    token = generate_verification_token()
    return token, hash_verification_token(token), now_iso()
