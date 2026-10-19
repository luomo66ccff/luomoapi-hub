import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone


_temporary = tempfile.TemporaryDirectory(prefix="apihub-hardening-", ignore_cleanup_errors=True)
os.environ.update(
    DATABASE_PATH=str(Path(_temporary.name) / "apihub.db"),
    APP_ENV="test",
    APP_BASE_URL="https://api.example.test",
    SESSION_SECRET="test-session-secret-with-more-than-32-characters",
    SMTP_HOST="",
    CODEXPROXY_API_KEY="",
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from fastapi.testclient import TestClient

from app.db import connect
from app.email_verification import claim_verification_send, hash_verification_token, new_token_record
from app.http_clients import create_http_client
from app.main import app
from app.public_gateway_secure import MAX_RESPONSE_BYTES, ResponseTooLarge, read_bounded_response
from app.upstream_security import resolve_and_pin_target
from app.utils.timefmt import now_iso
from app.auth import SESSION_COOKIE, create_session, hash_password


class GatewayHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app, base_url="https://api.example.test")
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)
        _temporary.cleanup()

    def setUp(self):
        self.client.cookies.clear()
        self.addCleanup(self.client.cookies.clear)

    def test_verify_get_is_read_only_and_post_consumes(self):
        token, token_hash, sent_at = new_token_record()
        now = now_iso()
        with connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users(username,email,password_hash,role,status,usage_reason,email_verified,email_verification_token_hash,email_verification_sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("scanner_test", "scanner@example.test", "unused", "developer", "pending", "test", 0, token_hash, sent_at, now, now),
            )
            user_id = cursor.lastrowid
            conn.commit()

        response = self.client.get("/verify-email", params={"token": token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        with connect() as conn:
            row = conn.execute("SELECT email_verified,email_verification_token_hash FROM users WHERE id=?", (user_id,)).fetchone()
            self.assertEqual(row["email_verified"], 0)
            self.assertEqual(row["email_verification_token_hash"], token_hash)

        confirmed = self.client.post("/verify-email", data={"token": token})
        self.assertEqual(confirmed.status_code, 200)
        with connect() as conn:
            row = conn.execute("SELECT email_verified,email_verification_token_hash FROM users WHERE id=?", (user_id,)).fetchone()
            self.assertEqual(row["email_verified"], 1)
            self.assertIsNone(row["email_verification_token_hash"])
        replay = self.client.post("/verify-email", data={"token": token})
        self.assertEqual(replay.status_code, 400)

    def test_email_confirmation_preserves_account_status_including_blocked_users(self):
        password = "long-status-test-password"
        password_hash = hash_password(password)
        for user_status in ("active", "pending", "suspended", "disabled"):
            with self.subTest(user_status=user_status):
                token, token_hash, sent_at = new_token_record()
                now = now_iso()
                username = f"verify_status_{user_status}"
                with connect() as conn:
                    cursor = conn.execute(
                        "INSERT INTO users(username,email,password_hash,role,status,email_verified,email_verification_token_hash,email_verification_sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (username, f"{username}@example.test", password_hash, "developer", user_status, 0, token_hash, sent_at, now, now),
                    )
                    user_id = cursor.lastrowid
                    conn.commit()
                self.client.cookies.clear()
                response = self.client.post("/verify-email", data={"token": token})
                self.assertEqual(response.status_code, 200)
                with connect() as conn:
                    row = conn.execute("SELECT status,email_verified,email_verification_token_hash FROM users WHERE id=?", (user_id,)).fetchone()
                self.assertEqual((row["status"], row["email_verified"]), (user_status, 1))
                self.assertIsNone(row["email_verification_token_hash"])
                login = self.client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
                self.assertEqual(login.status_code, 401 if user_status in {"suspended", "disabled"} else 303)
                self.client.cookies.set(SESSION_COOKIE, create_session(username))
                page = self.client.get("/developer", headers={"Accept": "application/json"})
                self.assertEqual(page.status_code, 401 if user_status in {"suspended", "disabled"} else 200)

    def test_expired_email_confirmation_leaves_user_unchanged(self):
        token, token_hash, _ = new_token_record()
        now = now_iso()
        sent_at = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        with connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users(username,email,password_hash,status,email_verification_token_hash,email_verification_sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("expired_verification", "expired@example.test", "unused", "suspended", token_hash, sent_at, now, now),
            )
            user_id = cursor.lastrowid
            conn.commit()
        self.assertEqual(self.client.get("/verify-email", params={"token": token}).status_code, 400)
        self.assertEqual(self.client.post("/verify-email", data={"token": token}).status_code, 400)
        with connect() as conn:
            row = conn.execute("SELECT status,email_verified,email_verification_token_hash FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual((row["status"], row["email_verified"], row["email_verification_token_hash"]), ("suspended", 0, token_hash))

    def test_new_registration_is_active_and_usable_even_when_email_delivery_fails(self):
        password = "long-registration-test-password"
        with patch("app.main.send_verification_email", side_effect=RuntimeError("controlled SMTP failure")):
            response = self.client.post("/register", data={
                "username": "direct_registration", "email": "direct@example.test",
                "password": password, "confirm_password": password,
            })
        self.assertEqual(response.status_code, 200)
        self.assertIn("可直接登录", response.text)
        self.assertIn("邮箱验证不影响使用", response.text)
        with connect() as conn:
            user = conn.execute("SELECT role,status,usage_reason,email_verified,email_verification_token_hash FROM users WHERE username='direct_registration'").fetchone()
        self.assertEqual((user["role"], user["status"], user["usage_reason"], user["email_verified"]), ("developer", "active", "", 0))
        self.assertIsNotNone(user["email_verification_token_hash"])
        login = self.client.post("/login", data={"username": "direct_registration", "password": password}, follow_redirects=False)
        self.assertEqual(login.status_code, 303)
        page = self.client.get("/developer")
        self.assertEqual(page.status_code, 200)
        self.assertIn("可以正常领取密钥和使用 API", page.text)
        self.assertNotIn("账户等待审核", page.text)
        registration = self.client.get("/register")
        scenario = registration.text.split('id="usage-reason"', 1)[1].split("</textarea>", 1)[0]
        self.assertNotIn("required", scenario)

    def test_new_user_schema_defaults_to_active(self):
        now = now_iso()
        with connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users(username,email,password_hash,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("schema_default", "default@example.test", "unused", now, now),
            )
            row = conn.execute("SELECT role,status,email_verified FROM users WHERE id=?", (cursor.lastrowid,)).fetchone()
            conn.commit()
        self.assertEqual((row["role"], row["status"], row["email_verified"]), ("developer", "active", 0))

    def test_admin_can_activate_unverified_user_but_developer_cannot_change_status(self):
        now = now_iso()
        with connect() as conn:
            conn.execute(
                "INSERT INTO users(username,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("status_admin", "status-admin@example.test", "unused", "admin", "active", now, now),
            )
            cursor = conn.execute(
                "INSERT INTO users(username,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("unverified_activation", "activation@example.test", "unused", "developer", "suspended", now, now),
            )
            user_id = cursor.lastrowid
            conn.commit()
        headers = {"Origin": "https://api.example.test"}
        self.client.cookies.set(SESSION_COOKIE, create_session("status_admin"))
        page = self.client.get("/admin/users")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn('disabled>active</option>', page.text)
        response = self.client.post(f"/admin/users/{user_id}/status", data={"status_value": "active"}, headers=headers, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        with connect() as conn:
            row = conn.execute("SELECT status,email_verified FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual((row["status"], row["email_verified"]), ("active", 0))
        invalid = self.client.post(f"/admin/users/{user_id}/status", data={"status_value": "invalid"}, headers=headers, follow_redirects=False)
        self.assertEqual(invalid.status_code, 400)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION_COOKIE, create_session("unverified_activation"))
        forbidden = self.client.post(f"/admin/users/{user_id}/status", data={"status_value": "disabled"}, headers=headers, follow_redirects=False)
        self.assertEqual(forbidden.status_code, 403)
        with connect() as conn:
            row = conn.execute("SELECT status FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual(row["status"], "active")

    def test_mail_send_rate_limit_is_persistent_and_atomic(self):
        email = "rate-limit@example.test"
        source = "198.51.100.8"
        self.assertTrue(claim_verification_send(email, source))
        self.assertFalse(claim_verification_send(email, source))

    def test_cookie_authenticated_post_rejects_cross_origin_source(self):
        self.client.cookies.set(SESSION_COOKIE, create_session("csrf_test_user"))
        try:
            response = self.client.post(
                "/developer/resend-verification",
                headers={"origin": "https://attacker.example"},
                follow_redirects=False,
            )
        finally:
            self.client.cookies.clear()
        self.assertEqual(response.status_code, 403)
        self.assertIn("来源校验失败", response.text)

    def test_registration_response_does_not_disclose_existing_account(self):
        now = now_iso()
        with connect() as conn:
            conn.execute(
                "INSERT INTO users(username,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("duplicate_user", "duplicate@example.test", "unused", "developer", "pending", now, now),
            )
            conn.commit()
        common = {"password": "long-test-password", "confirm_password": "long-test-password", "usage_reason": "test"}
        duplicate = self.client.post("/register", data={**common, "username": "duplicate_user", "email": "duplicate@example.test"})
        fresh = self.client.post("/register", data={**common, "username": "fresh_user", "email": "fresh@example.test"})
        self.assertEqual(duplicate.status_code, fresh.status_code)
        self.assertEqual(duplicate.text, fresh.text)

    def test_failed_resend_keeps_previously_valid_token(self):
        token, old_hash, sent_at = new_token_record()
        now = now_iso()
        with connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users(username,email,password_hash,role,status,email_verified,email_verification_token_hash,email_verification_sent_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("resend_user", "resend@example.test", "unused", "developer", "pending", 0, old_hash, sent_at, now, now),
            )
            conn.commit()
            user_id = cursor.lastrowid
        self.client.cookies.set(SESSION_COOKIE, create_session("resend_user"))
        with patch("app.main.send_verification_email", side_effect=RuntimeError("controlled SMTP failure")):
            response = self.client.post("/developer/resend-verification", headers={"origin": "https://api.example.test"}, follow_redirects=False)
        self.client.cookies.clear()
        self.assertEqual(response.status_code, 303)
        with connect() as conn:
            user = conn.execute("SELECT email_verification_token_hash FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual(user["email_verification_token_hash"], old_hash)

    def test_dns_target_is_pinned_with_original_authority(self):
        public_result = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with patch("app.upstream_security.socket.getaddrinfo", return_value=public_result):
            pinned = resolve_and_pin_target("https://api.example.test:443/v1?x=1")
        self.assertEqual(pinned.url, "https://93.184.216.34/v1?x=1")
        self.assertEqual(pinned.host_header, "api.example.test")
        self.assertEqual(pinned.sni_hostname, b"api.example.test")

    def test_private_or_mixed_dns_answers_are_rejected(self):
        private = [(2, 1, 6, "", ("127.0.0.1", 443))]
        mixed = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.2", 443)),
        ]
        with patch("app.upstream_security.socket.getaddrinfo", return_value=private):
            with self.assertRaisesRegex(ValueError, "non-public"):
                resolve_and_pin_target("https://private.example.test/")
        with patch("app.upstream_security.socket.getaddrinfo", return_value=mixed):
            with self.assertRaisesRegex(ValueError, "non-public"):
                resolve_and_pin_target("https://mixed.example.test/")
        with self.assertRaisesRegex(ValueError, "not allowed"):
            resolve_and_pin_target("https://127.0.0.1/")

    def test_nonstream_response_body_is_bounded(self):
        async def check():
            response = httpx.Response(200, content=b"123456")
            with self.assertRaises(ResponseTooLarge):
                await read_bounded_response(response, max_bytes=5)
        asyncio.run(check())
        self.assertEqual(MAX_RESPONSE_BYTES, 100 * 1024 * 1024)

    def test_pooled_client_never_persists_upstream_cookies(self):
        seen = []

        async def handler(request: httpx.Request):
            seen.append(request.headers.get("cookie"))
            if len(seen) == 1:
                return httpx.Response(200, headers={"set-cookie": "session=upstream-secret; Path=/"}, request=request)
            return httpx.Response(200, request=request)

        async def check():
            client = create_http_client(2.0, transport=httpx.MockTransport(handler))
            try:
                await client.get("https://upstream.example.test/one")
                await client.get("https://upstream.example.test/two")
            finally:
                await client.aclose()

        asyncio.run(check())
        self.assertEqual(seen, [None, None])


if __name__ == "__main__":
    unittest.main()
