import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn import native_api


SAMPLE_STATE = {
    "version": 1,
    "protocol": "wg",
    "serverPrivateKey": "server-private",
    "serverPublicKey": "server-public",
    "serverAddress": "10.8.0.1/24",
    "clients": [
        {
            "id": "client-1",
            "name": "Тестовый клиент",
            "address": "10.8.0.2/24",
            "privateKey": "client-private",
            "publicKey": "client-public",
            "presharedKey": "client-psk",
            "enabled": True,
            "createdAt": "2026-08-24T00:00:00Z",
            "expiredAt": None,
        }
    ],
}


class NativeVpnTests(unittest.TestCase):
    def test_next_address_skips_server_and_existing_clients(self):
        with patch.object(native_api, "NETWORK", ipaddress.ip_network("10.8.0.0/24")), patch.object(
            native_api, "SERVER_ADDRESS", "10.8.0.1/24"
        ):
            self.assertEqual(native_api.next_address(SAMPLE_STATE), "10.8.0.3/24")

    def test_server_config_contains_only_enabled_peers(self):
        state = {**SAMPLE_STATE, "clients": SAMPLE_STATE["clients"] + [{
            **SAMPLE_STATE["clients"][0], "id": "client-2", "publicKey": "disabled-key", "enabled": False
        }]}
        rendered = native_api.render_server_config(state)
        self.assertIn("PublicKey = client-public", rendered)
        self.assertNotIn("disabled-key", rendered)
        self.assertIn("AllowedIPs = 10.8.0.2/32", rendered)

    def test_client_config_uses_domain_and_contains_no_panel_dependency(self):
        with patch.object(native_api, "VPN_DOMAIN", "vpn.example.com"), patch.object(native_api, "PORT", 51820):
            rendered = native_api.render_client_config(SAMPLE_STATE, SAMPLE_STATE["clients"][0])
        self.assertIn("Endpoint = vpn.example.com:51820", rendered)
        self.assertIn("PrivateKey = client-private", rendered)
        self.assertNotIn("wg-easy", rendered)

    def test_awg_parameters_are_rendered_for_awg_only(self):
        with patch.object(native_api, "PROTOCOL", "awg"):
            rendered = native_api.render_client_config(SAMPLE_STATE, SAMPLE_STATE["clients"][0])
        for name in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
            self.assertIn(f"{name} = ", rendered)

    def test_legacy_state_migration_preserves_keys_and_clients(self):
        legacy = {
            "server": {"privateKey": "old-server-private", "publicKey": "old-server-public", "address": "10.8.0.1"},
            "clients": {"legacy-id": {
                "id": "legacy-id", "name": "Old client", "address": "10.8.0.7",
                "privateKey": "old-client-private", "publicKey": "old-client-public",
                "preSharedKey": "old-psk", "createdAt": "2025-01-01T00:00:00Z", "enabled": True,
            }},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "wg0.json").write_text(json.dumps(legacy), encoding="utf-8")
            with patch.object(native_api, "DATA_DIR", path):
                migrated = native_api.migrate_legacy_state()
        self.assertEqual(migrated["serverPrivateKey"], "old-server-private")
        self.assertEqual(migrated["serverAddress"], "10.8.0.1/24")
        self.assertEqual(migrated["clients"][0]["privateKey"], "old-client-private")
        self.assertEqual(migrated["clients"][0]["presharedKey"], "old-psk")
        self.assertEqual(migrated["clients"][0]["address"], "10.8.0.7/24")

    def test_imported_peer_without_psk_remains_valid(self):
        state = {**SAMPLE_STATE, "clients": [{**SAMPLE_STATE["clients"][0], "presharedKey": ""}]}
        self.assertNotIn("PresharedKey", native_api.render_server_config(state))
        self.assertNotIn("PresharedKey", native_api.render_client_config(state, state["clients"][0]))


if __name__ == "__main__":
    unittest.main()
