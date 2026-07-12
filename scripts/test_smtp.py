import os
from dotenv import load_dotenv

load_dotenv()

from app.email_verify import send_verification_email

to = input("Send test email to: ").strip()

ok = send_verification_email(
    email=to,
    username="smtp-test",
    token="test-token-not-valid"
)

print("SMTP send result:", "OK" if ok else "FAILED")
