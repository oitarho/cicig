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
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

PROJECT_DIR = Path(os.environ.get("CICIG_PROJECT_DIR", "/opt/cicig"))
DATA_DIR = Path(os.environ.get("CICIG_PANEL_DATA", "/data"))
SETTINGS_FILE = DATA_DIR / "settings.json"
SERVICES = {
    "wg-easy": {"title": "WireGuard", "endpoint": "51820/udp"},
    "awg-easy": {"title": "AmneziaWG", "endpoint": "443/udp"},
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
    return render_template("index.html", cards=cards, settings=settings)


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
