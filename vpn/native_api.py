#!/usr/bin/env python3
"""Small cicig-owned control API for native WireGuard and AmneziaWG."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


PROTOCOL = os.environ.get("CICIG_PROTOCOL", "wg")
if PROTOCOL not in {"wg", "awg"}:
    raise RuntimeError("CICIG_PROTOCOL must be wg or awg")

TOOL = "awg" if PROTOCOL == "awg" else "wg"
QUICK = "awg-quick" if PROTOCOL == "awg" else "wg-quick"
INTERFACE = os.environ.get("CICIG_INTERFACE", "awg0" if PROTOCOL == "awg" else "wg0")
NETWORK = ipaddress.ip_network(os.environ.get("CICIG_NETWORK", "10.8.0.0/24"))
SERVER_ADDRESS = os.environ.get("CICIG_SERVER_ADDRESS", f"{NETWORK.network_address + 1}/{NETWORK.prefixlen}")
PORT = int(os.environ.get("CICIG_PORT", "443" if PROTOCOL == "awg" else "51820"))
API_PORT = int(os.environ.get("CICIG_API_PORT", "8080"))
VPN_DOMAIN = os.environ.get("VPN_DOMAIN", "vpn.example.com")
CLIENT_DNS = os.environ.get("CICIG_CLIENT_DNS", "1.1.1.1")
DATA_DIR = Path(os.environ.get("CICIG_VPN_DATA", "/data"))
STATE_FILE = DATA_DIR / "state.json"
CONFIG_FILE = DATA_DIR / f"{INTERFACE}.conf"
LOCK = threading.RLock()

AWG_PARAMETERS = {
    "Jc": os.environ.get("AWG_JC", "4"),
    "Jmin": os.environ.get("AWG_JMIN", "40"),
    "Jmax": os.environ.get("AWG_JMAX", "70"),
    "S1": os.environ.get("AWG_S1", "86"),
    "S2": os.environ.get("AWG_S2", "122"),
    "H1": os.environ.get("AWG_H1", "1732165248"),
    "H2": os.environ.get("AWG_H2", "2012376621"),
    "H3": os.environ.get("AWG_H3", "1434254873"),
    "H4": os.environ.get("AWG_H4", "1325311552"),
}


def run(arguments: list[str], input_text: str | None = None, check: bool = True) -> str:
    result = subprocess.run(
        arguments,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or f"command failed: {arguments[0]}")
    return result.stdout.strip()


def generate_private_key() -> str:
    return run([TOOL, "genkey"])


def public_key(private_key: str) -> str:
    return run([TOOL, "pubkey"], private_key + "\n")


def generate_psk() -> str:
    return run([TOOL, "genpsk"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_state() -> dict:
    private = generate_private_key()
    state = {
        "version": 1,
        "protocol": PROTOCOL,
        "serverPrivateKey": private,
        "serverPublicKey": public_key(private),
        "serverAddress": SERVER_ADDRESS,
        "clients": [],
    }
    if PROTOCOL == "awg":
        state["parameters"] = AWG_PARAMETERS.copy()
    return state


def normalize_address(value: str) -> str:
    return value if "/" in value else f"{value}/{NETWORK.prefixlen}"


def migrate_legacy_state() -> dict | None:
    """Import the v14 JSON once so upgrades keep existing keys and peers."""
    legacy_file = DATA_DIR / "wg0.json"
    if not legacy_file.exists():
        return None
    legacy = json.loads(legacy_file.read_text(encoding="utf-8"))
    server = legacy.get("server") or {}
    private = server.get("privateKey")
    if not private:
        return None
    clients_value = legacy.get("clients") or {}
    entries = clients_value.items() if isinstance(clients_value, dict) else (
        (str(item.get("id") or uuid.uuid4().hex), item) for item in clients_value
    )
    clients = []
    for identifier, item in entries:
        client_private = item.get("privateKey")
        client_public = item.get("publicKey") or (public_key(client_private) if client_private else "")
        if not client_public or not item.get("address"):
            continue
        clients.append(
            {
                "id": str(item.get("id") or identifier),
                "name": str(item.get("name") or "imported-client")[:64],
                "address": normalize_address(str(item["address"])),
                "privateKey": client_private or "",
                "publicKey": client_public,
                "presharedKey": item.get("preSharedKey") or item.get("presharedKey") or "",
                "enabled": bool(item.get("enabled", True)),
                "createdAt": item.get("createdAt") or utc_now(),
                "expiredAt": item.get("expiredAt") or item.get("expiredDate"),
            }
        )
    state = {
        "version": 1,
        "protocol": PROTOCOL,
        "serverPrivateKey": private,
        "serverPublicKey": server.get("publicKey") or public_key(private),
        "serverAddress": normalize_address(str(server.get("address") or SERVER_ADDRESS)),
        "clients": clients,
    }
    if PROTOCOL == "awg":
        state["parameters"] = {
            name: str(server.get(name.lower(), AWG_PARAMETERS[name])) for name in AWG_PARAMETERS
        }
    return state


def load_state() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    if not STATE_FILE.exists():
        state = migrate_legacy_state() or new_state()
        save_state(state)
        return state
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if state.get("protocol") != PROTOCOL or not isinstance(state.get("clients"), list):
        raise RuntimeError("invalid or mismatched VPN state")
    return state


def save_state(state: dict) -> None:
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(STATE_FILE)


def next_address(state: dict) -> str:
    used = {ipaddress.ip_interface(client["address"]).ip for client in state["clients"]}
    server_ip = ipaddress.ip_interface(state.get("serverAddress", SERVER_ADDRESS)).ip
    for address in NETWORK.hosts():
        if address != server_ip and address not in used:
            return f"{address}/{NETWORK.prefixlen}"
    raise ValueError("VPN address pool is exhausted")


def awg_lines(state: dict) -> list[str]:
    parameters = state.get("parameters") or AWG_PARAMETERS
    return [f"{key} = {parameters[key]}" for key in AWG_PARAMETERS] if PROTOCOL == "awg" else []


def render_server_config(state: dict) -> str:
    subnet = str(NETWORK)
    lines = [
        "[Interface]",
        f"PrivateKey = {state['serverPrivateKey']}",
        f"Address = {state.get('serverAddress', SERVER_ADDRESS)}",
        f"ListenPort = {PORT}",
        *awg_lines(state),
        f"PostUp = iptables -A FORWARD -i {INTERFACE} -j ACCEPT; iptables -A FORWARD -o {INTERFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i {INTERFACE} -j ACCEPT; iptables -D FORWARD -o {INTERFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -j MASQUERADE",
    ]
    for client in state["clients"]:
        if not client.get("enabled", True):
            continue
        safe_name = str(client.get("name", "client")).replace("\n", " ").replace("\r", " ")
        lines.extend(["", f"# {safe_name}", "[Peer]", f"PublicKey = {client['publicKey']}"])
        if client.get("presharedKey"):
            lines.append(f"PresharedKey = {client['presharedKey']}")
        lines.append(f"AllowedIPs = {ipaddress.ip_interface(client['address']).ip}/32")
    return "\n".join(lines) + "\n"


def render_client_config(state: dict, client: dict) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {client['privateKey']}",
        f"Address = {client['address']}",
        f"DNS = {CLIENT_DNS}",
        *awg_lines(state),
        "",
        "[Peer]",
        f"PublicKey = {state['serverPublicKey']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {VPN_DOMAIN}:{PORT}",
        "PersistentKeepalive = 25",
    ]
    if client.get("presharedKey"):
        lines.insert(-3, f"PresharedKey = {client['presharedKey']}")
    return "\n".join(lines) + "\n"


def interface_is_up() -> bool:
    return INTERFACE in run([TOOL, "show", "interfaces"], check=False).split()


def apply_state(state: dict) -> None:
    CONFIG_FILE.write_text(render_server_config(state), encoding="utf-8")
    os.chmod(CONFIG_FILE, 0o600)
    if interface_is_up():
        stripped = run([QUICK, "strip", str(CONFIG_FILE)])
        sync_file = DATA_DIR / f".{INTERFACE}.sync"
        sync_file.write_text(stripped + "\n", encoding="utf-8")
        os.chmod(sync_file, 0o600)
        try:
            run([TOOL, "syncconf", INTERFACE, str(sync_file)])
        finally:
            sync_file.unlink(missing_ok=True)
    else:
        run([QUICK, "up", str(CONFIG_FILE)])


def mutate(state: dict, callback) -> None:
    previous = copy.deepcopy(state)
    callback()
    save_state(state)
    try:
        apply_state(state)
    except Exception:
        state.clear()
        state.update(previous)
        save_state(state)
        apply_state(state)
        raise


def peer_stats() -> dict[str, dict]:
    output = run([TOOL, "show", INTERFACE, "dump"], check=False)
    rows = output.splitlines()[1:] if output else []
    result = {}
    for row in rows:
        fields = row.split("\t")
        if len(fields) >= 8:
            result[fields[0]] = {
                "latestHandshakeAt": datetime.fromtimestamp(int(fields[4]), timezone.utc).isoformat().replace("+00:00", "Z") if fields[4] != "0" else None,
                "transferRx": int(fields[5]),
                "transferTx": int(fields[6]),
            }
    return result


def public_client(client: dict, stats: dict[str, dict]) -> dict:
    address = str(ipaddress.ip_interface(client["address"]).ip)
    return {
        "id": client["id"],
        "name": client["name"],
        "address": address,
        "publicKey": client["publicKey"],
        "enabled": bool(client.get("enabled", True)),
        "createdAt": client["createdAt"],
        "expiredAt": client.get("expiredAt"),
        **stats.get(client["publicKey"], {"latestHandshakeAt": None, "transferRx": 0, "transferTx": 0}),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "cicig-native-vpn/1"

    def log_message(self, message: str, *args) -> None:
        print(f"{self.address_string()} - {message % args}", flush=True)

    def body(self) -> dict:
        length = min(int(self.headers.get("Content-Length", "0")), 16 * 1024)
        return json.loads(self.rfile.read(length) or b"{}")

    def send(self, status: int, payload, content_type: str = "application/json") -> None:
        data = payload.encode() if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def client_id(self, suffix: str = "") -> str | None:
        prefix = "/api/wireguard/client/"
        path = urlparse(self.path).path
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        value = path[len(prefix):len(path) - len(suffix) if suffix else None]
        return value if value and "/" not in value else None

    def do_GET(self) -> None:
        try:
            with LOCK:
                state = load_state()
                path = urlparse(self.path).path
                if path == "/api/health":
                    up = interface_is_up()
                    self.send(200 if up else 503, {"status": "ok" if up else "down", "protocol": PROTOCOL, "interface": INTERFACE, "up": up})
                    return
                if path == "/api/wireguard/client":
                    stats = peer_stats()
                    self.send(200, [public_client(client, stats) for client in state["clients"]])
                    return
                client_id = self.client_id("/configuration")
                client = next((item for item in state["clients"] if item["id"] == client_id), None)
                if client:
                    self.send(200, render_client_config(state, client), "text/plain")
                    return
                self.send(404, {"error": "not found"})
        except Exception as exc:
            self.send(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            with LOCK:
                state = load_state()
                path = urlparse(self.path).path
                if path == "/api/wireguard/client":
                    payload = self.body()
                    name = str(payload.get("name", "")).strip()
                    if not name or len(name) > 64:
                        self.send(400, {"error": "invalid client name"})
                        return
                    private = generate_private_key()
                    client = {
                        "id": uuid.uuid4().hex,
                        "name": name,
                        "address": next_address(state),
                        "privateKey": private,
                        "publicKey": public_key(private),
                        "presharedKey": generate_psk(),
                        "enabled": True,
                        "createdAt": utc_now(),
                        "expiredAt": payload.get("expiredDate"),
                    }
                    mutate(state, lambda: state["clients"].append(client))
                    self.send(201, public_client(client, {}))
                    return
                for action in ("enable", "disable"):
                    client_id = self.client_id(f"/{action}")
                    if client_id:
                        client = next((item for item in state["clients"] if item["id"] == client_id), None)
                        if not client:
                            self.send(404, {"error": "client not found"})
                            return
                        mutate(state, lambda: client.update(enabled=action == "enable"))
                        self.send(204, "", "text/plain")
                        return
                self.send(404, {"error": "not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send(400, {"error": str(exc)})
        except Exception as exc:
            self.send(500, {"error": str(exc)})

    def do_DELETE(self) -> None:
        try:
            with LOCK:
                state = load_state()
                client_id = self.client_id()
                client = next((item for item in state["clients"] if item["id"] == client_id), None)
                if not client:
                    self.send(404, {"error": "client not found"})
                    return
                mutate(state, lambda: state["clients"].remove(client))
                self.send(204, "", "text/plain")
        except Exception as exc:
            self.send(500, {"error": str(exc)})

    def do_PUT(self) -> None:
        try:
            with LOCK:
                state = load_state()
                client_id = self.client_id("/expireDate")
                client = next((item for item in state["clients"] if item["id"] == client_id), None)
                if not client:
                    self.send(404, {"error": "client not found"})
                    return
                value = self.body().get("expireDate")
                client["expiredAt"] = value
                save_state(state)
                self.send(204, "", "text/plain")
        except Exception as exc:
            self.send(500, {"error": str(exc)})


def main() -> None:
    with LOCK:
        state = load_state()
        apply_state(state)
    ThreadingHTTPServer(("0.0.0.0", API_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
