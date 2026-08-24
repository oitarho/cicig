import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as app_module
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

    def test_client_network_policy_is_validated_and_queued(self):
        with self.client.session_transaction(base_url=PANEL_URL) as current_session:
            current_session["authenticated"] = True
            current_session["csrf"] = "policy-token"
        vpn_client = {"id": "client-1", "address": "10.8.0.12"}
        with (
            patch.object(app_module, "clients_for", return_value=[vpn_client]),
            patch.object(app_module, "write_network_policy") as write_policy,
            patch.object(app_module, "save_client_network_settings") as save_settings,
        ):
            response = self.client.post(
                "/clients/wg-easy/client-1/network",
                data={
                    "csrf": "policy-token",
                    "p2p_blocked": "on",
                    "download_limit_mbps": "25",
                },
                base_url=PANEL_URL,
            )
        self.assertEqual(response.status_code, 302)
        write_policy.assert_called_once_with(
            "wg-easy", "client-1", "10.8.0.12", True, 25
        )
        save_settings.assert_called_once_with("wg-easy", "client-1", True, 25)

    def test_client_network_policy_rejects_unsafe_limit(self):
        with self.client.session_transaction(base_url=PANEL_URL) as current_session:
            current_session["authenticated"] = True
            current_session["csrf"] = "policy-token"
        with patch.object(app_module, "clients_for") as clients_for:
            response = self.client.post(
                "/clients/wg-easy/client-1/network",
                data={"csrf": "policy-token", "download_limit_mbps": "1001"},
                base_url=PANEL_URL,
            )
        self.assertEqual(response.status_code, 400)
        clients_for.assert_not_called()

    def test_client_ipv4_normalizes_cidr_and_rejects_ipv6(self):
        self.assertEqual(app_module.client_ipv4("10.8.0.12/32"), "10.8.0.12")
        with self.assertRaises(ValueError):
            app_module.client_ipv4("fd00::12/128")

    def test_existing_database_gets_network_policy_columns(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "cicig.db"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """CREATE TABLE client_meta (
                    service TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    expires_at TEXT,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(service, client_id)
                    )"""
                )
                connection.commit()
            finally:
                connection.close()
            with patch.object(app_module, "DB_FILE", database):
                connection = app_module.db_connection()
                try:
                    columns = {
                        row["name"]
                        for row in connection.execute(
                            "PRAGMA table_info(client_meta)"
                        ).fetchall()
                    }
                finally:
                    connection.close()
            self.assertIn("p2p_blocked", columns)
            self.assertIn("download_limit_mbps", columns)


if __name__ == "__main__":
    unittest.main()
