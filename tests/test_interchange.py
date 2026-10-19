"""Interchange redesign: page rendering, public pricing, login throttling and admin self-protection."""
import os
import re
import secrets
import threading
from types import SimpleNamespace
from unittest.mock import patch
import sys
import tempfile
import unittest
from pathlib import Path

_temporary = tempfile.TemporaryDirectory(prefix="apihub-interchange-", ignore_cleanup_errors=True)
os.environ.setdefault("DATABASE_PATH", str(Path(_temporary.name) / "apihub.db"))
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("APP_BASE_URL", "https://api.example.test")
os.environ.setdefault("SESSION_SECRET", "test-session-secret-with-more-than-32-characters")
os.environ.setdefault("SMTP_HOST", "")
os.environ.setdefault("CODEXPROXY_API_KEY", "")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app import login_throttle  # noqa: E402
from app.client_ip import ClientIdentity, client_identity  # noqa: E402
from app.web import templating  # noqa: E402
from app.auth import SESSION_COOKIE, create_session, hash_password  # noqa: E402
from app.config import settings  # noqa: E402
from app.db import connect  # noqa: E402
from app.main import app  # noqa: E402
from app.utils.timefmt import now_iso  # noqa: E402
from app.web.templating import asset, credit, line_for  # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "web" / "templates"
ORIGIN = {"Origin": settings.app_base_url.rstrip("/")}


def _user(prefix, role="developer", status="active", password="unused"):
    name = f"{prefix}_{secrets.token_hex(4)}"
    with connect() as conn:
        cursor = conn.execute(
            "INSERT INTO users(username,email,password_hash,role,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, name + "@example.test", hash_password(password) if password != "unused" else "unused", role, status, now_iso(), now_iso()),
        )
        conn.commit()
        return name, cursor.lastrowid


class InterchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = TestClient(app, base_url=settings.app_base_url)
        cls.client = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def setUp(self):
        self.client.cookies.clear()
        self.addCleanup(self.client.cookies.clear)

    def test_templates_never_use_inline_styles_blocked_by_csp(self):
        for path in TEMPLATES.glob("*.html"):
            self.assertIsNone(re.search(r"\sstyle\s*=", path.read_text(encoding="utf-8")), path.name)

    def test_public_pages_render_with_fingerprinted_assets(self):
        for path in ("/", "/models", "/pricing", "/docs", "/status", "/login", "/register"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(asset("interchange.css"), response.text, path)
            self.assertNotIn("style.css", response.text, path)

    def test_pricing_is_public_and_lists_official_prices(self):
        response = self.client.get("/pricing")
        self.assertEqual(response.status_code, 200)
        self.assertIn("gpt-6-luna", response.text)
        self.assertIn('id="estimator"', response.text)
        self.assertIn("$1<em>=</em>720", response.text)

    def test_every_console_page_renders_for_admin(self):
        name, _ = _user("render_admin", role="admin")
        self.client.cookies.set(SESSION_COOKIE, create_session(name))
        for path in ("/developer", "/developer/keys", "/developer/logs", "/developer/usage", "/developer/credits", "/developer/playground",
                     "/admin", "/admin/users", "/admin/api-keys", "/admin/key-requests", "/admin/credits", "/admin/ai-usage",
                     "/admin/routes", "/admin/logs", "/apis", "/tester", "/logs", "/secrets", "/settings"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn('class="line-nav"', response.text, path)

    def test_static_assets_are_cacheable_even_with_a_session(self):
        name, _ = _user("static_viewer")
        self.client.cookies.set(SESSION_COOKIE, create_session(name))
        fingerprinted = self.client.get(asset("interchange.css"))
        self.assertEqual(fingerprinted.status_code, 200)
        self.assertIn("immutable", fingerprinted.headers["cache-control"])
        for query in ("", "?v=wrong", "?rev=anything", "?v=" + templating.fingerprint("interchange.css") + "&v=x"):
            response = self.client.get("/static/interchange.css" + query)
            self.assertEqual(response.headers["cache-control"], "public, max-age=3600", query)
        self.assertEqual(self.client.get("/developer").headers["cache-control"], "no-store")

    def test_login_failures_are_throttled_per_account_and_cleared_on_success(self):
        password = "interchange-correct-password"
        name, _ = _user("throttle", password=password)
        for _ in range(login_throttle.MAX_FAILURES_PER_ACCOUNT):
            failed = self.client.post("/login", data={"username": name, "password": "wrong-password"}, follow_redirects=False)
            self.assertEqual(failed.status_code, 401)
            self.assertIn("用户名或密码不正确", failed.text)
        blocked = self.client.post("/login", data={"username": name, "password": password}, follow_redirects=False)
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["retry-after"], "900")
        with connect() as conn:
            conn.execute("DELETE FROM login_throttle WHERE bucket_hash=?", (login_throttle._digest("account", "testclient", name.lower()),))
            conn.commit()
        success = self.client.post("/login", data={"username": name, "password": password}, follow_redirects=False)
        self.assertEqual(success.status_code, 303)

    def test_client_identity_trusts_only_the_exact_proxy_peers(self):
        def request(peer, header=None):
            return SimpleNamespace(client=SimpleNamespace(host=peer), headers={"cf-connecting-ip": header} if header else {})
        self.assertEqual(client_identity(request("172.20.0.1", "203.0.113.9")), ClientIdentity("203.0.113.9", True))
        self.assertEqual(client_identity(request("127.0.0.1", "2001:db8::1")), ClientIdentity("2001:db8::1", True))
        self.assertEqual(client_identity(request("172.19.0.25", "203.0.113.9")), ClientIdentity("172.19.0.25", False))
        self.assertEqual(client_identity(request("10.0.0.8", "203.0.113.9")), ClientIdentity("10.0.0.8", False))
        self.assertEqual(client_identity(request("1.1.1.1", "203.0.113.9")), ClientIdentity("1.1.1.1", True))
        self.assertEqual(client_identity(request("172.20.0.1", "not-an-ip")), ClientIdentity("172.20.0.1", False))
        self.assertEqual(client_identity(request("172.20.0.1")), ClientIdentity("172.20.0.1", False))

    def test_unverified_hop_cannot_lock_out_every_visitor(self):
        hop = "172.19.0.25"
        for index in range(login_throttle.MAX_FAILURES_PER_SOURCE + 5):
            self.assertIsNotNone(login_throttle.reserve_login_attempt(f"spray_hop_{index}", hop, verified=False))
        self.assertIsNotNone(login_throttle.reserve_login_attempt("real_user", hop, verified=False))

    def test_visitors_behind_the_proxy_do_not_share_a_source_bucket(self):
        attacker, victim = "203.0.113.50", "203.0.113.51"
        for index in range(login_throttle.MAX_FAILURES_PER_SOURCE):
            self.assertIsNotNone(login_throttle.reserve_login_attempt(f"spray_{index}", attacker))
        self.assertIsNone(login_throttle.reserve_login_attempt("anyone", attacker))
        self.assertIsNotNone(login_throttle.reserve_login_attempt("anyone", victim))

    def test_concurrent_attempts_cannot_exceed_the_account_limit(self):
        name, source = f"burst_{secrets.token_hex(3)}", "203.0.113.60"
        barrier = threading.Barrier(16)
        results = []
        def attempt():
            barrier.wait()
            results.append(login_throttle.reserve_login_attempt(name, source) is not None)
        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), login_throttle.MAX_FAILURES_PER_ACCOUNT)

    def test_successful_sign_in_returns_its_source_slot(self):
        source = "203.0.113.70"
        for index in range(login_throttle.MAX_FAILURES_PER_SOURCE - 1):
            login_throttle.reserve_login_attempt(f"fill_{index}", source)
        reservation = login_throttle.reserve_login_attempt("good_user", source)
        self.assertIsNotNone(reservation)
        login_throttle.release_login_attempt(reservation)
        self.assertIsNotNone(login_throttle.reserve_login_attempt("another_user", source))
        self.assertIsNone(login_throttle.reserve_login_attempt("one_more", source))

    def test_settling_an_old_window_never_touches_the_new_window(self):
        source, name = "203.0.113.80", f"window_{secrets.token_hex(3)}"
        start = 1_900_000_000
        with patch.object(login_throttle.time, "time", return_value=start):
            old = login_throttle.reserve_login_attempt(name, source)
        with patch.object(login_throttle.time, "time", return_value=start + login_throttle.WINDOW_SECONDS + 1):
            for _ in range(login_throttle.MAX_FAILURES_PER_ACCOUNT):
                self.assertIsNotNone(login_throttle.reserve_login_attempt(name, source))
            login_throttle.release_login_attempt(old)
            login_throttle.cancel_login_attempt(old)
            self.assertIsNone(login_throttle.reserve_login_attempt(name, source))

    def test_authentication_errors_do_not_consume_the_failure_budget(self):
        password = "interchange-recovery-password"
        name, _ = _user("auth_fault", password=password)
        with patch("app.main.authenticate_user", side_effect=RuntimeError("database unavailable")):
            for _ in range(login_throttle.MAX_FAILURES_PER_ACCOUNT + 2):
                self.assertEqual(self.client.post("/login", data={"username": name, "password": password}, follow_redirects=False).status_code, 500)
        self.assertEqual(self.client.post("/login", data={"username": name, "password": password}, follow_redirects=False).status_code, 303)

    def test_ready_reports_missing_throttle_table_with_a_real_status(self):
        self.assertEqual(self.client.get("/ready").json()["status"], "ready")
        with connect() as conn:
            conn.execute("DROP TABLE login_throttle")
            conn.commit()
        try:
            response = self.client.get("/ready", follow_redirects=False)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["status"], "not_ready")
        finally:
            with connect() as conn:
                login_throttle.init_login_throttle_schema(conn)
                conn.commit()

    def test_fingerprint_follows_file_changes_without_restart(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(templating, "STATIC_DIR", Path(folder).resolve()):
            target = Path(folder) / "probe.js"
            target.write_text("one", encoding="utf-8")
            first = templating.fingerprint("probe.js")
            target.write_text("two!", encoding="utf-8")
            self.assertNotEqual(first, templating.fingerprint("probe.js"))
            with self.assertRaises(ValueError):
                templating.fingerprint("../escape.js")

    def test_live_board_is_mounted_and_catalog_carries_signage(self):
        from app import ai_catalog
        fake = {"service": "LuomoAPI Hub", "status": "operational", "updated_at": "2026-10-18T09:00:00+00:00", "cache_seconds": 30,
                "components": [], "model_count": 2, "billable_count": 1, "note": "",
                "models": [{"id": "gpt-6-luna", "name": "Luna", "category": "轻快交互", "use": "", "billable": True, "text_candidate": True,
                            "line": line_for("gpt-6-luna"), "state": {"tone": "ok", "label": "可乘车"}, "verification": {}},
                           {"id": "gpt-image-2", "name": "gpt-image-2", "category": "图像模型", "use": "", "billable": False, "text_candidate": False,
                            "line": line_for("gpt-image-2"), "state": {"tone": "off", "label": "暂未开放"}, "verification": {}}]}
        async def snapshot():
            return fake
        with patch("app.public_stats.snapshot", snapshot), patch("app.ai_console.snapshot", snapshot):
            home = self.client.get("/").text
            status = self.client.get("/status").text
        for page in (home, status):
            self.assertIn('data-board-live="/api/public/ai-catalog"', page)
            self.assertIn(asset("board.js"), page)
            self.assertIn('data-model="gpt-6-luna"', page)
            self.assertIn('class="lamp off">暂未开放', page)
        self.assertIn('data-limit="6"', home)
        for station in ("luomo.moe", "file.luomo.moe", "ops.luomo.moe/servers", "misskey.march7th.cn"):
            self.assertIn(station, home)
        from app.model_lines import board_state
        self.assertEqual(board_state("gpt-6-luna", True)["tone"], "ok")
        self.assertEqual(board_state("gpt-image-2", False)["tone"], "off")
        self.assertEqual(board_state("codex-auto-review", False)["label"], "未计价")

    def test_admin_cannot_change_own_status(self):
        name, user_id = _user("self_admin", role="admin")
        self.client.cookies.set(SESSION_COOKIE, create_session(name))
        response = self.client.post(f"/admin/users/{user_id}/status", data={"status_value": "disabled"}, headers=ORIGIN, follow_redirects=False)
        self.assertEqual(response.status_code, 400)
        with connect() as conn:
            self.assertEqual(conn.execute("SELECT status FROM users WHERE id=?", (user_id,)).fetchone()["status"], "active")

    def test_registration_errors_are_chinese(self):
        response = self.client.post("/register", data={"username": "short_pw", "email": "short@example.test", "password": "short", "confirm_password": "short"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("密码至少需要 10 个字符", response.text)

    def test_line_signage_and_credit_formatting(self):
        self.assertEqual(line_for("gpt-6-luna"), {"family": "luna", "letter": "L", "number": "60"})
        self.assertEqual(line_for("gpt-6.1-sol"), {"family": "sol", "letter": "S", "number": "61"})
        self.assertEqual(line_for("gpt-4o-mini")["letter"], "G")
        self.assertEqual(credit("7200.000000"), "7,200")
        self.assertEqual(credit("0.000001"), "0.000001")
        self.assertEqual(credit(None), "—")


if __name__ == "__main__":
    unittest.main()
