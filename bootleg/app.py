"""Bootleg -- the web application: admin dashboard plus the deploy API."""

from __future__ import annotations

import io
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

from . import archive, auth, store
from .config import Config
from .db import (close_db, connect, get_db, get_setting, init_db, log_event,
                 set_setting)
from .github import GitHubError
from .store import StoreError
from .util import human_size, safe_filename

SCRIPT_SOURCE = Path(__file__).resolve().parent.parent / "client" / "bootleg_deploy.py"
KEY_PLACEHOLDER = "%%BOOTLEG_KEY%%"


def create_app(config: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config)

    for folder in ("blobs", "archives", "tmp"):
        (Path(app.config["DATA_DIR"]) / folder).mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE"])

    boot = connect(app.config["DATABASE"])
    secret = get_setting(boot, "secret_key")
    if not secret:
        secret = secrets.token_hex(32)
        set_setting(boot, "secret_key", secret)
    if get_setting(boot, "public_url") is None:
        set_setting(boot, "public_url", config.DEFAULT_PUBLIC_URL or
                    "http://{0}:{1}".format(config.HOST, config.PORT))
    if get_setting(boot, "check_interval") is None:
        set_setting(boot, "check_interval", str(config.DEFAULT_CHECK_INTERVAL))
    boot.close()

    app.secret_key = secret
    app.teardown_appcontext(close_db)
    app.jinja_env.filters["human_size"] = human_size
    register_routes(app)
    start_updater(app)
    return app


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _data_dir() -> Path:
    from flask import current_app
    return Path(current_app.config["DATA_DIR"])


def _toolkit_json(row: sqlite3.Row) -> dict:
    data = {k: row[k] for k in row.keys() if k != "token"}
    data["dirty"] = bool(row["dirty"])
    return data


def _tool_json(row: sqlite3.Row) -> dict:
    data = {k: row[k] for k in row.keys() if k != "blob_path"}
    data["enabled"] = bool(row["enabled"])
    data["unpack"] = bool(row["unpack"])
    data["gh_prerelease"] = bool(row["gh_prerelease"])
    data["size_human"] = human_size(row["size"])
    return data


def render_script(key: str) -> str:
    """The deploy agent with a freshly minted key baked in."""
    return SCRIPT_SOURCE.read_text().replace(KEY_PLACEHOLDER, key)


def _key_json(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "label": row["label"],
        "created_at": row["created_at"],
        "used_at": row["used_at"],
        "revoked": bool(row["revoked"]),
        "bound_ip": row["bound_ip"],
        "last_used_at": row["last_used_at"],
        "use_count": row["use_count"],
        "state": "revoked" if row["revoked"] else ("bound" if row["bound_ip"] else "ready"),
    }


def _bool(value) -> bool:
    return str(value).lower() in ("1", "true", "yes", "on")


def register_routes(app: Flask) -> None:  # noqa: C901 - a flat route table reads better
    # ---------------------------------------------------------------- setup
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        conn = get_db()
        if auth.is_configured(conn):
            return redirect(url_for("login"))
        error = None
        if request.method == "POST":
            password = request.form.get("password", "")
            if len(password) < 10:
                error = "Use at least 10 characters."
            elif password != request.form.get("confirm", ""):
                error = "The two passwords do not match."
            else:
                auth.set_password(conn, password)
                auth.login(conn)
                log_event(conn, "Admin password set")
                return redirect(url_for("dashboard"))
        return render_template("setup.html", error=error)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        conn = get_db()
        if not auth.is_configured(conn):
            return redirect(url_for("setup"))
        error = None
        if request.method == "POST":
            wait = auth.locked_out()
            if wait:
                error = "Too many attempts. Try again in {0}s.".format(wait)
            elif auth.check_password(conn, request.form.get("password", "")):
                auth.login(conn)
                target = request.args.get("next", "")
                return redirect(target if target.startswith("/") else url_for("dashboard"))
            else:
                error = "Incorrect password."
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------- dashboard
    @app.route("/")
    @auth.login_required
    def dashboard():
        conn = get_db()
        toolkits = store.list_toolkits(conn)
        events = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 12").fetchall()
        return render_template("dashboard.html", toolkits=toolkits, events=events,
                               csrf=auth.csrf_token(), page="toolkits")

    @app.route("/toolkit/<slug>")
    @app.route("/toolkit/<slug>/<tab>")
    @auth.login_required
    def toolkit_view(slug: str, tab: str = "tools"):
        conn = get_db()
        try:
            toolkit = store.get_toolkit(conn, slug)
        except StoreError:
            abort(404)
        if tab not in ("tools", "deploy", "settings"):
            abort(404)
        tools = store.list_tools(conn, toolkit["id"])
        context = {
            "toolkit": toolkit, "tools": tools, "tab": tab,
            "csrf": auth.csrf_token(), "page": "toolkits",
            "keys": [_key_json(k) for k in store.list_deploy_keys(conn, toolkit["id"])],
            "public_url": store.public_url(conn),
        }
        return render_template("toolkit.html", **context)

    @app.route("/settings")
    @auth.login_required
    def settings_view():
        conn = get_db()
        events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 60").fetchall()
        return render_template("settings.html", page="settings", csrf=auth.csrf_token(),
                               public_url=store.public_url(conn),
                               github_token=bool(get_setting(conn, "github_token", "")),
                               trust_proxy=get_setting(conn, "trust_proxy", "") == "1",
                               check_interval=get_setting(conn, "check_interval", "60"),
                               events=events)

    # ------------------------------------------------------------- admin API
    @app.post("/api/toolkits")
    @auth.login_required
    def api_create_toolkit():
        data = request.get_json(silent=True) or {}
        conn = get_db()
        toolkit = store.create_toolkit(conn, data.get("name", ""), data.get("description", ""))
        store.rebuild(conn, toolkit, _data_dir())
        return jsonify(toolkit=_toolkit_json(store.get_toolkit(conn, toolkit["slug"])))

    @app.post("/api/toolkits/<slug>")
    @auth.login_required
    def api_update_toolkit(slug: str):
        data = request.get_json(silent=True) or {}
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        store.update_toolkit(conn, toolkit, name=data.get("name"),
                             description=data.get("description"),
                             setup_script=data.get("setup_script"))
        return jsonify(toolkit=_toolkit_json(store.get_toolkit(conn, slug)))

    @app.post("/api/toolkits/<slug>/delete")
    @auth.login_required
    def api_delete_toolkit(slug: str):
        conn = get_db()
        store.delete_toolkit(conn, store.get_toolkit(conn, slug), _data_dir())
        return jsonify(ok=True)

    @app.post("/api/toolkits/<slug>/rotate")
    @auth.login_required
    def api_rotate(slug: str):
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        store.rotate_token(conn, toolkit)
        toolkit = store.get_toolkit(conn, slug)
        store.rebuild(conn, toolkit, _data_dir())
        return jsonify(toolkit=_toolkit_json(store.get_toolkit(conn, slug)))

    @app.post("/api/toolkits/<slug>/rebuild")
    @auth.login_required
    def api_rebuild(slug: str):
        conn = get_db()
        stats = store.rebuild(conn, store.get_toolkit(conn, slug), _data_dir())
        return jsonify(stats=stats, toolkit=_toolkit_json(store.get_toolkit(conn, slug)))

    @app.post("/api/toolkits/<slug>/refresh")
    @auth.login_required
    def api_refresh_toolkit(slug: str):
        conn = get_db()
        result = store.refresh_toolkit(conn, store.get_toolkit(conn, slug), _data_dir())
        toolkit = store.get_toolkit(conn, slug)
        return jsonify(result=result, toolkit=_toolkit_json(toolkit),
                       tools=[_tool_json(t) for t in store.list_tools(conn, toolkit["id"])])

    @app.post("/api/toolkits/<slug>/tools/upload")
    @auth.login_required
    def api_upload(slug: str):
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        uploaded = request.files.getlist("file")
        if not uploaded or not any(f.filename for f in uploaded):
            return jsonify(error="Choose at least one file."), 400
        added = []
        for item in uploaded:
            if not item.filename:
                continue
            fd, tmp = tempfile.mkstemp(dir=_data_dir() / "tmp", prefix=".up-")
            os.close(fd)
            item.save(tmp)
            tool_id = store.add_upload(
                conn, toolkit, Path(tmp), safe_filename(item.filename), _data_dir(),
                name=request.form.get("name", "") if len(uploaded) == 1 else "",
                install_dir=request.form.get("install_dir", ""),
                unpack=_bool(request.form.get("unpack")),
                notes=request.form.get("notes", ""),
                version=request.form.get("version", ""))
            added.append(tool_id)
        tools = store.list_tools(conn, toolkit["id"])
        return jsonify(added=added, tools=[_tool_json(t) for t in tools],
                       toolkit=_toolkit_json(store.get_toolkit(conn, slug)))

    @app.post("/api/toolkits/<slug>/tools/github")
    @auth.login_required
    def api_add_github(slug: str):
        data = request.get_json(silent=True) or {}
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        tool_id = store.add_github(
            conn, toolkit, data.get("repo", ""), _data_dir(),
            name=data.get("name", ""), pattern=data.get("pattern", ""),
            prerelease=_bool(data.get("prerelease")),
            source=data.get("source", "release"),
            install_dir=data.get("install_dir", ""),
            unpack=_bool(data.get("unpack")), notes=data.get("notes", ""))
        tool = conn.execute("SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
        return jsonify(tool=_tool_json(tool),
                       tools=[_tool_json(t) for t in store.list_tools(conn, toolkit["id"])],
                       toolkit=_toolkit_json(store.get_toolkit(conn, slug)))

    @app.post("/api/tools/<int:tool_id>")
    @auth.login_required
    def api_update_tool(tool_id: int):
        data = request.get_json(silent=True) or {}
        conn = get_db()
        store.update_tool(conn, tool_id, **data)
        tool = conn.execute("SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
        if tool is None:
            abort(404)
        return jsonify(tool=_tool_json(tool))

    @app.post("/api/tools/<int:tool_id>/delete")
    @auth.login_required
    def api_delete_tool(tool_id: int):
        store.delete_tool(get_db(), tool_id)
        return jsonify(ok=True)

    @app.post("/api/tools/<int:tool_id>/refresh")
    @auth.login_required
    def api_refresh_tool(tool_id: int):
        conn = get_db()
        result = store.refresh_tool(conn, tool_id, _data_dir())
        tool = conn.execute("SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
        return jsonify(result=result, tool=_tool_json(tool))

    @app.get("/api/toolkits/<slug>/script")
    @auth.login_required
    def api_script_preview(slug: str):
        """Source for the on-page preview. Deliberately mints nothing: opening
        the tab should not burn a key."""
        store.get_toolkit(get_db(), slug)
        return jsonify(script=SCRIPT_SOURCE.read_text().replace(
            KEY_PLACEHOLDER, "<issued when you copy the script>"))

    @app.post("/api/toolkits/<slug>/issue-key")
    @auth.login_required
    def api_issue_key(slug: str):
        data = request.get_json(silent=True) or {}
        conn = get_db()
        toolkit = store.ensure_built(conn, store.get_toolkit(conn, slug), _data_dir())
        key, key_id = store.issue_deploy_key(conn, toolkit, data.get("label", ""))
        return jsonify(key=key, id=key_id, script=render_script(key),
                       keys=[_key_json(k) for k in store.list_deploy_keys(conn, toolkit["id"])])

    @app.get("/api/toolkits/<slug>/keys")
    @auth.login_required
    def api_list_keys(slug: str):
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        return jsonify(keys=[_key_json(k) for k in store.list_deploy_keys(conn, toolkit["id"])])

    @app.post("/api/keys/<int:key_id>/revoke")
    @auth.login_required
    def api_revoke_key(key_id: int):
        store.revoke_deploy_key(get_db(), key_id)
        return jsonify(ok=True)

    @app.post("/api/keys/<int:key_id>/unbind")
    @auth.login_required
    def api_unbind_key(key_id: int):
        """Let a key move hosts -- for a target whose address changed."""
        store.unbind_deploy_key(get_db(), key_id)
        return jsonify(ok=True)

    @app.post("/api/toolkits/<slug>/keys/prune")
    @auth.login_required
    def api_prune_keys(slug: str):
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        removed = store.prune_deploy_keys(conn, toolkit["id"])
        return jsonify(removed=removed,
                       keys=[_key_json(k) for k in store.list_deploy_keys(conn, toolkit["id"])])

    @app.get("/toolkit/<slug>/bootleg_deploy.py")
    @auth.login_required
    def download_script(slug: str):
        """Downloading the agent issues a key, exactly like copying it does."""
        conn = get_db()
        toolkit = store.ensure_built(conn, store.get_toolkit(conn, slug), _data_dir())
        key, _ = store.issue_deploy_key(conn, toolkit, "downloaded .py")
        buffer = io.BytesIO(render_script(key).encode())
        return send_file(buffer, mimetype="text/x-python", as_attachment=True,
                         download_name="bootleg_deploy_{0}.py".format(slug))

    @app.get("/toolkit/<slug>/download.zip")
    @auth.login_required
    def download_toolkit(slug: str):
        """The whole toolkit as a plain zip, for use right here rather than on a
        target host. Authenticated, so it is not sealed."""
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        fd, tmp = tempfile.mkstemp(dir=_data_dir() / "tmp", prefix=".zip-", suffix=".zip")
        os.close(fd)
        try:
            archive.pack(conn, toolkit, Path(tmp), revision=toolkit["archive_revision"])
            data = Path(tmp).read_bytes()
        finally:
            Path(tmp).unlink(missing_ok=True)
        log_event(conn, "Downloaded '{0}' as a zip".format(toolkit["name"]),
                  toolkit_id=toolkit["id"])
        return send_file(io.BytesIO(data), mimetype="application/zip",
                         as_attachment=True,
                         download_name="{0}.zip".format(toolkit["slug"]))

    @app.get("/toolkit/<slug>/tool/<int:tool_id>/download")
    @auth.login_required
    def download_tool(slug: str, tool_id: int):
        """One tool, exactly as archived."""
        conn = get_db()
        toolkit = store.get_toolkit(conn, slug)
        tool = conn.execute("SELECT * FROM tools WHERE id = ? AND toolkit_id = ?",
                            (tool_id, toolkit["id"])).fetchone()
        if tool is None:
            abort(404)
        blob = Path(tool["blob_path"] or "")
        if not blob.is_file():
            return jsonify(error="Nothing has been fetched for this tool yet."), 409
        return send_file(blob, as_attachment=True,
                         download_name=tool["filename"] or tool["name"],
                         mimetype="application/octet-stream")

    @app.post("/api/settings")
    @auth.login_required
    def api_settings():
        data = request.get_json(silent=True) or {}
        conn = get_db()
        if "public_url" in data:
            set_setting(conn, "public_url", (data["public_url"] or "").strip().rstrip("/"))
        if "github_token" in data:
            set_setting(conn, "github_token", (data["github_token"] or "").strip())
        if "trust_proxy" in data:
            set_setting(conn, "trust_proxy", "1" if _bool(data["trust_proxy"]) else "0")
        if "check_interval" in data:
            try:
                minutes = max(0, int(data["check_interval"]))
            except (TypeError, ValueError):
                return jsonify(error="Check interval must be a whole number of minutes."), 400
            set_setting(conn, "check_interval", str(minutes))
        if data.get("password"):
            if len(data["password"]) < 10:
                return jsonify(error="Use at least 10 characters."), 400
            auth.set_password(conn, data["password"])
            log_event(conn, "Admin password changed", "warn")
        return jsonify(ok=True, public_url=store.public_url(conn))

    # -------------------------------------------------------- deploy agent API
    @app.get("/api/v1/manifest")
    @auth.api_key_required()
    def api_manifest():
        conn = get_db()
        toolkit = store.ensure_built(conn, g.toolkit, _data_dir())
        tools = [t for t in store.list_tools(conn, toolkit["id"]) if t["enabled"]]
        return jsonify({
            "toolkit": toolkit["slug"],
            "name": toolkit["name"],
            "description": toolkit["description"],
            "revision": toolkit["archive_revision"],
            "built_at": toolkit["archive_built_at"],
            "size": toolkit["archive_size"],
            "sha256": toolkit["archive_sha256"],
            "has_setup": bool((toolkit["setup_script"] or "").strip()),
            "tools": [{
                "name": t["name"],
                "path": "{0}/{1}".format(t["install_dir"], t["filename"]).lstrip("/")
                        if t["install_dir"] else (t["filename"] or t["name"]),
                "version": t["version"] or "",
                "size": t["size"],
                "unpack": bool(t["unpack"]),
            } for t in tools],
        })

    @app.get("/api/v1/archive")
    @auth.api_key_required(binds=True)
    def api_archive():
        conn = get_db()
        toolkit = store.ensure_built(conn, g.toolkit, _data_dir())
        path = Path(toolkit["archive_path"] or "")
        if not path.is_file():
            return jsonify(error="No archive built for this toolkit."), 409
        log_event(conn, "Toolkit '{0}' rev {1} deployed to {2} (key #{3})".format(
            toolkit["slug"], toolkit["archive_revision"], g.client_ip, g.deploy_key["id"]),
            toolkit_id=toolkit["id"])
        return send_file(path, mimetype="application/octet-stream",
                         as_attachment=True,
                         download_name="{0}.blz".format(toolkit["slug"]))

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    # ------------------------------------------------------------- errors
    @app.errorhandler(StoreError)
    def handle_store_error(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(GitHubError)
    def handle_github_error(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(413)
    def handle_too_large(_exc):
        limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return jsonify(error="That file is over the {0} MB upload limit.".format(limit)), 413

    @app.errorhandler(404)
    def handle_404(_exc):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found."), 404
        return render_template("404.html"), 404


# --------------------------------------------------------------------------
# Background release checks
# --------------------------------------------------------------------------

def start_updater(app: Flask) -> None:
    """Poll tracked GitHub projects on a timer, rebuilding what changes."""
    def loop():
        time.sleep(15)  # let the server settle before the first sweep
        while True:
            conn = None
            try:
                conn = connect(app.config["DATABASE"])
                minutes = int(get_setting(conn, "check_interval", "60") or 0)
                if minutes <= 0:
                    conn.close()
                    time.sleep(60)
                    continue
                for row in conn.execute("SELECT slug FROM toolkits").fetchall():
                    toolkit = store.get_toolkit(conn, row["slug"])
                    result = store.refresh_toolkit(conn, toolkit, Path(app.config["DATA_DIR"]))
                    if result["updated"]:
                        log_event(conn, "Auto-update: {0} tool(s) refreshed in '{1}'".format(
                            result["updated"], toolkit["name"]), toolkit_id=toolkit["id"])
            except Exception as exc:  # a failed sweep must not kill the thread
                try:
                    if conn:
                        log_event(conn, "Auto-update sweep failed: {0}".format(exc), "error")
                except Exception:
                    pass
            finally:
                if conn:
                    conn.close()
            time.sleep(max(minutes, 5) * 60)

    threading.Thread(target=loop, name="bootleg-updater", daemon=True).start()
