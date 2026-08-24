from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import requests
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

PROJECT_DIR = Path(os.environ.get("CICIG_PROJECT_DIR", "/opt/cicig"))
DATA_DIR = Path(os.environ.get("CICIG_PANEL_DATA", "/data"))
SETTINGS_FILE = DATA_DIR / "settings.json"
DB_FILE = DATA_DIR / "cicig.db"
SERVICES = {
    "wg-easy": {"title": "WireGuard", "short": "WG", "endpoint": "51820/udp", "api": "http://wg-easy:51821"},
    "awg-easy": {"title": "AmneziaWG", "short": "AWG", "endpoint": "443/udp", "api": "http://awg-easy:51821"},
}

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ["PANEL_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

update_lock = threading.Lock()
update_state: dict[str, dict] = {
    name: {"running": False, "result": "", "updated_at": ""} for name in SERVICES
}


def db_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS client_meta (
        service TEXT NOT NULL,
        client_id TEXT NOT NULL,
        expires_at TEXT,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        PRIMARY KEY(service, client_id)
        )"""
    )
    connection.commit()
    return connection


def client_meta(service: str, client_id: str) -> dict:
    with db_connection() as connection:
        row = connection.execute(
            "SELECT * FROM client_meta WHERE service=? AND client_id=?", (service, client_id)
        ).fetchone()
    return dict(row) if row else {}


def save_client_meta(service: str, client_id: str, expires_at: datetime | None, note: str = "") -> None:
    with db_connection() as connection:
        connection.execute(
            """INSERT INTO client_meta(service,client_id,expires_at,note,created_at)
            VALUES(?,?,?,?,?) ON CONFLICT(service,client_id) DO UPDATE SET
            expires_at=excluded.expires_at,note=excluded.note""",
            (service, client_id, expires_at.isoformat() if expires_at else None, note, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()


def delete_client_meta(service: str, client_id: str) -> None:
    with db_connection() as connection:
        connection.execute("DELETE FROM client_meta WHERE service=? AND client_id=?", (service, client_id))
        connection.commit()


def parse_datetime(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def human_date(value: datetime | None) -> str:
    return value.astimezone().strftime("%d.%m.%Y") if value else "Без срока"


def load_settings() -> dict:
    defaults = {"auto_update": {name: False for name in SERVICES}, "interval_hours": 24}
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        defaults["auto_update"].update(saved.get("auto_update", {}))
        defaults["interval_hours"] = max(1, int(saved.get("interval_hours", 24)))
    except (OSError, ValueError, TypeError):
        pass
    return defaults


def save_settings(settings: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = SETTINGS_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    temporary.replace(SETTINGS_FILE)


def docker(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def service_status(name: str) -> dict:
    result = docker(
        "compose", "--project-directory", str(PROJECT_DIR), "ps", "-q", name
    )
    container_id = result.stdout.strip()
    if not container_id:
        return {"state": "not found", "image": "unknown", "healthy": False}
    inspected = docker(
        "inspect", "--format", "{{.State.Status}}|{{.Config.Image}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container_id
    )
    state, image, health = (inspected.stdout.strip().split("|") + ["", "", ""])[:3]
    return {"state": state, "image": image, "health": health, "healthy": state == "running" and health not in {"unhealthy"}}


def api_call(service: str, method: str, path: str, **kwargs) -> requests.Response:
    if service not in SERVICES:
        raise ValueError("unknown VPN service")
    response = requests.request(
        method,
        f"{SERVICES[service]['api']}/api{path}",
        timeout=20,
        **kwargs,
    )
    response.raise_for_status()
    return response


def clients_for(service: str) -> list[dict]:
    try:
        clients = api_call(service, "GET", "/wireguard/client").json()
    except (requests.RequestException, ValueError):
        return []
    for client in clients:
        metadata = client_meta(service, str(client.get("id", "")))
        expires = parse_datetime(metadata.get("expires_at")) or parse_datetime(client.get("expiredAt"))
        created = parse_datetime(client.get("createdAt"))
        handshake = parse_datetime(client.get("latestHandshakeAt"))
        age = (datetime.now(timezone.utc) - handshake).total_seconds() if handshake else None
        if age is not None and age <= 180:
            connection = "online"
        elif age is not None and age <= 86400:
            connection = "recent"
        else:
            connection = "offline"
        days_left = (expires.date() - datetime.now(timezone.utc).date()).days if expires else None
        if not client.get("enabled"):
            subscription = "disabled"
        elif days_left is not None and days_left < 0:
            subscription = "expired"
        elif days_left is not None and days_left <= 7:
            subscription = "expiring"
        else:
            subscription = "active"
        client["service"] = service
        client["service_title"] = SERVICES[service]["title"]
        client["service_short"] = SERVICES[service]["short"]
        client["transfer_rx_h"] = human_bytes(client.get("transferRx"))
        client["transfer_tx_h"] = human_bytes(client.get("transferTx"))
        client["expires_at_dt"] = expires
        client["expires_label"] = human_date(expires)
        client["days_left"] = days_left
        client["created_label"] = human_date(created)
        client["connection"] = connection
        client["subscription"] = subscription
        client["note"] = metadata.get("note", "")
    return clients


def human_bytes(value) -> str:
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "0 B"


def safe_client_id(client_id: str) -> bool:
    return (
        bool(client_id)
        and client_id not in {"__proto__", "constructor", "prototype"}
        and len(client_id) <= 128
        and all(c.isalnum() or c in "-_" for c in client_id)
    )


def perform_update(name: str) -> None:
    if name not in SERVICES:
        return
    with update_lock:
        update_state[name]["running"] = True
        try:
            pull = docker(
                "compose", "--project-directory", str(PROJECT_DIR), "pull", name, timeout=540
            )
            if pull.returncode != 0:
                raise RuntimeError((pull.stderr or pull.stdout)[-1200:])
            up = docker(
                "compose", "--project-directory", str(PROJECT_DIR),
                "up", "-d", "--no-deps", name, timeout=540
            )
            if up.returncode != 0:
                raise RuntimeError((up.stderr or up.stdout)[-1200:])
            update_state[name]["result"] = "Обновление завершено успешно"
        except Exception as exc:  # noqa: BLE001
            update_state[name]["result"] = f"Ошибка: {exc}"
        finally:
            update_state[name]["running"] = False
            update_state[name]["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def auto_update_loop() -> None:
    while True:
        settings = load_settings()
        time.sleep(settings["interval_hours"] * 3600)
        settings = load_settings()
        for name, enabled in settings["auto_update"].items():
            if enabled:
                perform_update(name)


def expiry_loop() -> None:
    """Disable expired clients even when the upstream panel has no expiry support."""
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        for service in SERVICES:
            for client in clients_for(service):
                expires = client.get("expires_at_dt")
                if expires and expires < now and client.get("enabled"):
                    try:
                        api_call(service, "POST", f"/wireguard/client/{client['id']}/disable")
                    except requests.RequestException:
                        pass


@app.before_request
def csrf_setup() -> None:
    session.setdefault("csrf", secrets.token_urlsafe(32))


def logged_in() -> bool:
    return bool(session.get("authenticated"))


def require_login():
    if not logged_in():
        return redirect(url_for("login"))
    return None


def valid_csrf() -> bool:
    return secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", ""))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "").encode()
        expected = os.environ["PANEL_PASSWORD_HASH"].encode()
        if bcrypt.checkpw(password, expected):
            session.clear()
            session["authenticated"] = True
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))
        flash("Неверный пароль", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    if not valid_csrf():
        return "Bad CSRF token", 400
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    denied = require_login()
    if denied:
        return denied
    settings = load_settings()
    cards = []
    for name, metadata in SERVICES.items():
        cards.append({
            "name": name,
            "title": metadata["title"],
            "endpoint": f"{os.environ['VPN_DOMAIN']}:{metadata['endpoint']}",
            "status": service_status(name),
            "auto_update": bool(settings["auto_update"].get(name)),
            "update": update_state[name].copy(),
        })
    all_clients = {name: clients_for(name) for name in SERVICES}
    flat_clients = [client for items in all_clients.values() for client in items]
    total_clients = len(flat_clients)
    enabled_clients = sum(1 for client in flat_clients if client.get("enabled"))
    counts = {
        "subscription": {key: sum(1 for client in flat_clients if client["subscription"] == key) for key in ("active", "expiring", "expired", "disabled")},
        "connection": {key: sum(1 for client in flat_clients if client["connection"] == key) for key in ("online", "recent", "offline")},
    }
    query = request.args.get("q", "").strip().lower()
    subscription_filter = request.args.get("subscription", "all")
    connection_filter = request.args.get("connection", "all")
    service_filter = request.args.get("service", "all")
    clients = {}
    for name, items in all_clients.items():
        if service_filter != "all" and service_filter != name:
            clients[name] = []
            continue
        clients[name] = [
            client for client in items
            if (not query or query in f"{client.get('name','')} {client.get('address','')} {client.get('publicKey','')}".lower())
            and (subscription_filter == "all" or client["subscription"] == subscription_filter)
            and (connection_filter == "all" or client["connection"] == connection_filter)
        ]
    return render_template(
        "index.html", cards=cards, clients=clients, settings=settings,
        total_clients=total_clients, enabled_clients=enabled_clients, counts=counts,
        query=query, subscription_filter=subscription_filter,
        connection_filter=connection_filter, service_filter=service_filter,
    )


@app.post("/clients")
def create_client():
    denied = require_login()
    if denied:
        return denied
    if not valid_csrf():
        return "Bad CSRF token", 400
    service = request.form.get("service", "")
    name = request.form.get("name", "").strip()
    if service not in SERVICES or not name or len(name) > 64:
        flash("Проверьте VPN и имя клиента", "error")
        return redirect(url_for("index") + "#clients")
    try:
        months = max(1, min(24, int(request.form.get("months", "1"))))
    except ValueError:
        months = 1
    expires_at = datetime.now(timezone.utc) + timedelta(days=30 * months)
    payload = {"name": name}
    if service == "awg-easy":
        payload["expiredDate"] = expires_at.date().isoformat()
    try:
        old_ids = {str(client.get("id")) for client in clients_for(service)}
        api_call(service, "POST", "/wireguard/client", json=payload)
        created = [client for client in clients_for(service) if str(client.get("id")) not in old_ids]
        if created:
            save_client_meta(service, str(created[0]["id"]), expires_at, request.form.get("note", "").strip()[:200])
        flash(f"Клиент «{name}» создан в {SERVICES[service]['title']}", "success")
    except requests.RequestException as exc:
        flash(f"Не удалось создать клиента: {exc}", "error")
    return redirect(url_for("index") + "#clients")


@app.post("/clients/<service>/<client_id>/<action>")
def client_action(service: str, client_id: str, action: str):
    denied = require_login()
    if denied:
        return denied
    if not valid_csrf() or service not in SERVICES or not safe_client_id(client_id):
        return "Bad request", 400
    try:
        if action in {"enable", "disable"}:
            api_call(service, "POST", f"/wireguard/client/{client_id}/{action}")
            flash("Состояние клиента изменено", "success")
        elif action == "delete":
            api_call(service, "DELETE", f"/wireguard/client/{client_id}")
            delete_client_meta(service, client_id)
            flash("Клиент удалён", "success")
        else:
            return "Unknown action", 404
    except requests.RequestException as exc:
        flash(f"Операция не выполнена: {exc}", "error")
    return redirect(url_for("index") + "#clients")


@app.get("/clients/<service>/<client_id>/config")
def client_config(service: str, client_id: str):
    denied = require_login()
    if denied:
        return denied
    if service not in SERVICES or not safe_client_id(client_id):
        return "Bad request", 400
    try:
        upstream = api_call(service, "GET", f"/wireguard/client/{client_id}/configuration")
    except requests.RequestException as exc:
        return f"Configuration unavailable: {exc}", 502
    disposition = upstream.headers.get("Content-Disposition", f'attachment; filename="{client_id}.conf"')
    return Response(upstream.content, content_type="text/plain", headers={"Content-Disposition": disposition})


@app.get("/clients/<service>/<client_id>/qr")
def client_qr(service: str, client_id: str):
    denied = require_login()
    if denied:
        return denied
    if service not in SERVICES or not safe_client_id(client_id):
        return "Bad request", 400
    try:
        upstream = api_call(service, "GET", f"/wireguard/client/{client_id}/qrcode.svg")
    except requests.RequestException as exc:
        return f"QR unavailable: {exc}", 502
    return Response(upstream.content, content_type="image/svg+xml")


@app.get("/clients/<service>/<client_id>")
def client_detail(service: str, client_id: str):
    denied = require_login()
    if denied:
        return denied
    if service not in SERVICES or not safe_client_id(client_id):
        return "Bad request", 400
    client = next((item for item in clients_for(service) if str(item.get("id")) == client_id), None)
    if not client:
        return "Client not found", 404
    return render_template("client.html", client=client, service=service, service_meta=SERVICES[service])


@app.post("/clients/<service>/<client_id>/extend")
def client_extend(service: str, client_id: str):
    denied = require_login()
    if denied:
        return denied
    if not valid_csrf() or service not in SERVICES or not safe_client_id(client_id):
        return "Bad request", 400
    try:
        months = max(1, min(24, int(request.form.get("months", "1"))))
    except ValueError:
        months = 1
    client = next((item for item in clients_for(service) if str(item.get("id")) == client_id), None)
    if not client:
        return "Client not found", 404
    current = client.get("expires_at_dt")
    base = current if current and current > datetime.now(timezone.utc) else datetime.now(timezone.utc)
    expires_at = base + timedelta(days=30 * months)
    try:
        if service == "awg-easy":
            api_call(service, "PUT", f"/wireguard/client/{client_id}/expireDate", json={"expireDate": expires_at.date().isoformat()})
        if not client.get("enabled"):
            api_call(service, "POST", f"/wireguard/client/{client_id}/enable")
        save_client_meta(service, client_id, expires_at, client.get("note", ""))
        flash(f"Срок продлён до {human_date(expires_at)}", "success")
    except requests.RequestException as exc:
        flash(f"Продление не выполнено: {exc}", "error")
    return redirect(url_for("client_detail", service=service, client_id=client_id))


@app.post("/update/<name>")
def update(name: str):
    denied = require_login()
    if denied:
        return denied
    if not valid_csrf() or name not in SERVICES:
        return "Bad request", 400
    if not update_state[name]["running"]:
        threading.Thread(target=perform_update, args=(name,), daemon=True).start()
        flash(f"Обновление {SERVICES[name]['title']} запущено", "success")
    return redirect(url_for("index"))


@app.post("/settings")
def settings():
    denied = require_login()
    if denied:
        return denied
    if not valid_csrf():
        return "Bad CSRF token", 400
    current = load_settings()
    current["auto_update"] = {name: request.form.get(name) == "on" for name in SERVICES}
    try:
        current["interval_hours"] = max(1, min(720, int(request.form.get("interval_hours", "24"))))
    except ValueError:
        current["interval_hours"] = 24
    save_settings(current)
    flash("Настройки автообновления сохранены", "success")
    return redirect(url_for("index"))


threading.Thread(target=auto_update_loop, daemon=True).start()
threading.Thread(target=expiry_loop, daemon=True).start()
