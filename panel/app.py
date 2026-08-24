from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import requests
from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

PROJECT_DIR = Path(os.environ.get("CICIG_PROJECT_DIR", "/opt/cicig"))
DATA_DIR = Path(os.environ.get("CICIG_PANEL_DATA", "/data"))
SETTINGS_FILE = DATA_DIR / "settings.json"
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
        client["service"] = service
        client["service_title"] = SERVICES[service]["title"]
        client["service_short"] = SERVICES[service]["short"]
        client["transfer_rx_h"] = human_bytes(client.get("transferRx"))
        client["transfer_tx_h"] = human_bytes(client.get("transferTx"))
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
    clients = {name: clients_for(name) for name in SERVICES}
    total_clients = sum(len(items) for items in clients.values())
    enabled_clients = sum(1 for items in clients.values() for client in items if client.get("enabled"))
    return render_template(
        "index.html", cards=cards, clients=clients, settings=settings,
        total_clients=total_clients, enabled_clients=enabled_clients,
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
    payload = {"name": name}
    if service == "awg-easy" and request.form.get("expired_date"):
        payload["expiredDate"] = request.form["expired_date"]
    try:
        api_call(service, "POST", "/wireguard/client", json=payload)
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
