"""Admin session auth and API-key auth for the deploy agent."""

from __future__ import annotations

import hmac
import secrets
import sqlite3
import time
from functools import wraps

from flask import current_app, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import apikey, store
from .db import get_db, get_setting, log_event, set_setting

LOCKOUT_AFTER = 8
LOCKOUT_SECONDS = 300
_attempts: dict[str, list] = {}


# --------------------------------------------------------------------------
# Admin password
# --------------------------------------------------------------------------

def is_configured(conn: sqlite3.Connection) -> bool:
    return bool(get_setting(conn, "admin_password_hash"))


def set_password(conn: sqlite3.Connection, password: str) -> None:
    set_setting(conn, "admin_password_hash", generate_password_hash(password))


def _client_ip() -> str:
    """The address we treat as the caller's.

    X-Forwarded-For is only honoured when the operator has said this server sits
    behind a reverse proxy. That matters because the address is a security
    control here: trusting the header on a directly-exposed server would let
    anyone forge it and walk straight through a key's host pin.
    """
    if get_setting(get_db(), "trust_proxy", "") == "1":
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or "?"
    return request.remote_addr or "?"


def locked_out() -> int:
    """Seconds remaining on a lockout, or 0."""
    failures = _attempts.get(_client_ip(), [])
    recent = [t for t in failures if time.time() - t < LOCKOUT_SECONDS]
    _attempts[_client_ip()] = recent
    if len(recent) >= LOCKOUT_AFTER:
        return int(LOCKOUT_SECONDS - (time.time() - recent[0]))
    return 0


def check_password(conn: sqlite3.Connection, password: str) -> bool:
    stored = get_setting(conn, "admin_password_hash", "")
    if stored and check_password_hash(stored, password):
        _attempts.pop(_client_ip(), None)
        return True
    _attempts.setdefault(_client_ip(), []).append(time.time())
    log_event(conn, "Failed admin login from {0}".format(_client_ip()), "warn")
    return False


def login(conn: sqlite3.Connection) -> None:
    session.clear()
    session.permanent = True
    session["admin"] = True
    session["csrf"] = secrets.token_urlsafe(32)


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        conn = get_db()
        if not is_configured(conn):
            return redirect(url_for("setup"))
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify(error="Not signed in."), 401
            return redirect(url_for("login", next=request.path))
        if request.method in ("POST", "PUT", "DELETE"):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not hmac.compare_digest(sent or "", session.get("csrf", "")):
                return jsonify(error="Session expired -- reload the page."), 403
        return view(*args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------
# Deploy agent
# --------------------------------------------------------------------------

def api_key_required(binds: bool = False):
    """Authenticate a deploy agent from its X-Bootleg-Key header.

    Every deploy script carries its own key, and a key pins itself to the first
    host that deploys with it. That host can re-run the script as often as it
    likes -- to redeploy, or to pick up a new revision -- but the same key lifted
    onto a different machine is refused.

    ``binds=True`` marks the endpoint that establishes the pin: the archive
    download, i.e. an actual deployment.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            raw = request.headers.get("X-Bootleg-Key", "")
            try:
                parts = apikey.decode(raw)
            except apikey.KeyError_ as exc:
                return jsonify(error=str(exc)), 401

            conn = get_db()
            toolkit = conn.execute("SELECT * FROM toolkits WHERE slug = ?",
                                   (parts["toolkit"],)).fetchone()
            if toolkit is None:
                return jsonify(error="Unknown toolkit."), 404

            key = store.find_deploy_key(conn, parts["token"])
            if key is None or key["toolkit_id"] != toolkit["id"]:
                log_event(conn, "Deploy key rejected for '{0}' from {1}".format(
                    toolkit["slug"], _client_ip()), "warn", toolkit["id"])
                return jsonify(error="Invalid or unrecognised key."), 403
            if key["revoked"]:
                return jsonify(error="This key was revoked. Copy a fresh script "
                                     "from the Bootleg dashboard."), 403

            client = _client_ip()
            if key["bound_ip"] and key["bound_ip"] != client:
                log_event(conn, "Key #{0} refused: bound to {1}, tried from {2}".format(
                    key["id"], key["bound_ip"], client), "warn", toolkit["id"])
                return jsonify(error="This key is locked to the host that first deployed "
                                     "it ({0}) and cannot be used from {1}. Copy a fresh "
                                     "script from the Bootleg dashboard.".format(
                                         key["bound_ip"], client)), 403

            g.toolkit = toolkit
            g.deploy_key = key
            g.client_ip = client
            if binds:
                store.bind_deploy_key(conn, key["id"], client)
            return view(*args, **kwargs)
        return wrapper
    return decorator
