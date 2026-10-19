import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

from app.config import settings
from app.db import connect
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
    message["Subject"] = "验证你的 LuomoAPI 邮箱 · Verify your LuomoAPI email"
    message["From"] = settings.smtp_from
    message["To"] = email
    hours = settings.email_verification_ttl_hours
    message.set_content(
        "\n".join(
            [
                f"{username}，你好：",
                "",
                "请打开下面的链接，确认这个邮箱属于你的 LuomoAPI 账户：",
                link,
                "",
                f"链接 {hours} 小时内有效。邮箱验证不影响领取密钥和调用 API。",
                "如果你没有注册过 LuomoAPI，可以忽略这封邮件。",
                "",
                "---",
                f"Hi {username}, please verify your LuomoAPI account email: {link}",
                f"This link expires in {hours} hours. If you did not create this account, ignore this email.",
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


def claim_verification_send(email: str, source_ip: str | None) -> bool:
    """Atomically cap sends per recipient and per observed client address."""
    now_dt = datetime.now(timezone.utc)
    now = now_iso()
    identities = [("email", email.strip().lower(), 5, 60)]
    if source_ip:
        identities.append(("source", source_ip.strip(), 120, 0))
    buckets = [
        (hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest(), limit, cooldown)
        for kind, value, limit, cooldown in identities
    ]
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = []
        for bucket_hash, limit, cooldown in buckets:
            row = conn.execute(
                "SELECT window_started_at, last_sent_at, send_count FROM verification_email_limits WHERE bucket_hash=?",
                (bucket_hash,),
            ).fetchone()
            if row:
                started = datetime.fromisoformat(row["window_started_at"])
                last_sent = datetime.fromisoformat(row["last_sent_at"])
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if last_sent.tzinfo is None:
                    last_sent = last_sent.replace(tzinfo=timezone.utc)
                if now_dt - started < timedelta(hours=1) and int(row["send_count"]) >= limit:
                    conn.rollback()
                    return False
                if cooldown and now_dt - last_sent < timedelta(seconds=cooldown):
                    conn.rollback()
                    return False
                current.append((bucket_hash, limit, started, int(row["send_count"])))
            else:
                current.append((bucket_hash, limit, None, 0))
        for bucket_hash, _, started, count in current:
            if started is None or now_dt - started >= timedelta(hours=1):
                conn.execute(
                    "INSERT INTO verification_email_limits(bucket_hash, window_started_at, last_sent_at, send_count) VALUES (?, ?, ?, 1) "
                    "ON CONFLICT(bucket_hash) DO UPDATE SET window_started_at=excluded.window_started_at, last_sent_at=excluded.last_sent_at, send_count=1",
                    (bucket_hash, now, now),
                )
            else:
                conn.execute(
                    "UPDATE verification_email_limits SET last_sent_at=?, send_count=? WHERE bucket_hash=?",
                    (now, count + 1, bucket_hash),
                )
        conn.commit()
    return True
