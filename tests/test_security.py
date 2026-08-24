import re
import unittest

from app import app, login_attempts


PANEL_URL = "https://panel.example.com"


class SecuritySmokeTests(unittest.TestCase):
    def setUp(self):
        login_attempts.clear()
        self.client = app.test_client()

    def csrf(self, response) -> str:
        match = re.search(rb'name="csrf" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def test_security_headers_and_trusted_host(self):
        response = self.client.get("/login", base_url=PANEL_URL)
        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/login", base_url="https://evil.example").status_code, 400)

    def test_login_requires_csrf(self):
        response = self.client.post(
            "/login", data={"password": "wrong"}, base_url=PANEL_URL
        )
        self.assertEqual(response.status_code, 400)

    def test_login_rate_limit(self):
        page = self.client.get("/login", base_url=PANEL_URL)
        token = self.csrf(page)
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={"password": "wrong", "csrf": token},
                base_url=PANEL_URL,
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            )
            self.assertEqual(response.status_code, 401)
        blocked = self.client.post(
            "/login",
            data={"password": "wrong", "csrf": token},
            base_url=PANEL_URL,
            environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)

    def test_successful_login_creates_timed_session(self):
        page = self.client.get("/login", base_url=PANEL_URL)
        response = self.client.post(
            "/login",
            data={"password": "testpassword123", "csrf": self.csrf(page)},
            base_url=PANEL_URL,
            environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
        )
        self.assertEqual(response.status_code, 302)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Expires=", cookie)


if __name__ == "__main__":
    unittest.main()
