"""Toolkit and tool operations -- everything the web layer needs, kept out of it."""

from __future__ import annotations

import secrets
import shutil
import sqlite3
from pathlib import Path

from . import archive, github
from .apikey import encode as encode_key, new_token, token_hash
from .db import get_setting, log_event, set_setting, _write_lock
from .util import now_iso, safe_filename, sha256_file, slugify


class StoreError(Exception):
    """A user-correctable problem (duplicate name, missing toolkit, ...)."""


# --------------------------------------------------------------------------
# Toolkits
# --------------------------------------------------------------------------

def list_toolkits(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT t.*, "
        "  (SELECT COUNT(*) FROM tools WHERE toolkit_id = t.id) AS tool_count, "
        "  (SELECT COUNT(*) FROM tools WHERE toolkit_id = t.id AND kind = 'github') AS tracked_count, "
        "  (SELECT COALESCE(SUM(size), 0) FROM tools WHERE toolkit_id = t.id AND enabled = 1) AS payload_size "
        "FROM toolkits t ORDER BY t.name COLLATE NOCASE"
    ).fetchall()


def get_toolkit(conn: sqlite3.Connection, slug: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM toolkits WHERE slug = ?", (slug,)).fetchone()
    if row is None:
        raise StoreError("No toolkit called '{0}'.".format(slug))
    return row


def list_tools(conn: sqlite3.Connection, toolkit_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM tools WHERE toolkit_id = ? ORDER BY install_dir, name COLLATE NOCASE",
        (toolkit_id,),
    ).fetchall()


def create_toolkit(conn: sqlite3.Connection, name: str, description: str = "") -> sqlite3.Row:
    name = (name or "").strip()
    if not name:
        raise StoreError("Give the toolkit a name.")
    slug = slugify(name)
    if conn.execute("SELECT 1 FROM toolkits WHERE slug = ?", (slug,)).fetchone():
        raise StoreError("A toolkit named '{0}' already exists.".format(name))
    with _write_lock, conn:
        conn.execute(
            "INSERT INTO toolkits (slug, name, description, token, archive_secret, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (slug, name, description.strip(), new_token(), new_token(), now_iso()),
        )
    log_event(conn, "Created toolkit '{0}'".format(name))
    return get_toolkit(conn, slug)


def update_toolkit(conn: sqlite3.Connection, toolkit: sqlite3.Row, *, name: str | None = None,
                   description: str | None = None, setup_script: str | None = None) -> None:
    fields, values = [], []
    if name is not None and name.strip() and name.strip() != toolkit["name"]:
        fields.append("name = ?")
        values.append(name.strip())
    if description is not None:
        fields.append("description = ?")
        values.append(description.strip())
    if setup_script is not None and setup_script != toolkit["setup_script"]:
        fields.append("setup_script = ?")
        values.append(setup_script)
        fields.append("dirty = 1")
    if not fields:
        return
    values.append(toolkit["id"])
    with _write_lock, conn:
        conn.execute("UPDATE toolkits SET {0} WHERE id = ?".format(", ".join(fields)), values)


def rotate_token(conn: sqlite3.Connection, toolkit: sqlite3.Row) -> str:
    """Re-key the toolkit: new archive secret, and every outstanding deploy key
    revoked. Anything already handed out stops working at once."""
    secret = new_token()
    with _write_lock, conn:
        conn.execute("UPDATE toolkits SET token = ?, archive_secret = ?, dirty = 1 WHERE id = ?",
                     (new_token(), secret, toolkit["id"]))
        cur = conn.execute(
            "UPDATE deploy_keys SET revoked = 1 WHERE toolkit_id = ? AND revoked = 0",
            (toolkit["id"],))
    log_event(conn, "Re-keyed '{0}' and revoked {1} deploy key(s)".format(
        toolkit["name"], cur.rowcount), "warn", toolkit["id"])
    return secret


def delete_toolkit(conn: sqlite3.Connection, toolkit: sqlite3.Row, data_dir: Path) -> None:
    shutil.rmtree(Path(data_dir) / "blobs" / str(toolkit["id"]), ignore_errors=True)
    if toolkit["archive_path"]:
        Path(toolkit["archive_path"]).unlink(missing_ok=True)
    with _write_lock, conn:
        conn.execute("DELETE FROM toolkits WHERE id = ?", (toolkit["id"],))
    log_event(conn, "Deleted toolkit '{0}'".format(toolkit["name"]), "warn")


# --------------------------------------------------------------------------
# Deploy keys
# --------------------------------------------------------------------------

def issue_deploy_key(conn: sqlite3.Connection, toolkit: sqlite3.Row,
                     label: str = "") -> tuple[str, int]:
    """Mint a fresh single-use key for one deployment.

    Only the hash is stored, so the key is unrecoverable after this call -- copy
    it now or issue another. That is also why a database read yields nothing an
    attacker could deploy with.
    """
    token = new_token()
    with _write_lock, conn:
        cur = conn.execute(
            "INSERT INTO deploy_keys (toolkit_id, token_hash, label, created_at) "
            "VALUES (?,?,?,?)",
            (toolkit["id"], token_hash(token), (label or "").strip()[:80], now_iso()),
        )
    key = encode_key(public_url(conn), toolkit["slug"], token, toolkit["archive_secret"])
    log_event(conn, "Issued deploy key #{0} for '{1}'".format(cur.lastrowid, toolkit["name"]),
              toolkit_id=toolkit["id"])
    return key, cur.lastrowid


def list_deploy_keys(conn: sqlite3.Connection, toolkit_id: int,
                     limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM deploy_keys WHERE toolkit_id = ? ORDER BY id DESC LIMIT ?",
        (toolkit_id, limit),
    ).fetchall()


def find_deploy_key(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """Look a key up by hash -- an indexed exact match, no token comparison."""
    return conn.execute(
        "SELECT * FROM deploy_keys WHERE token_hash = ?", (token_hash(token),)
    ).fetchone()


def bind_deploy_key(conn: sqlite3.Connection, key_id: int, client: str) -> None:
    """Record a deployment, pinning the key to this host the first time.

    The bind is conditional on the key still being unbound, so two hosts racing
    the same key cannot both claim it -- the first writer wins and the second is
    rejected on its next request.
    """
    stamp = now_iso()
    with _write_lock, conn:
        conn.execute(
            "UPDATE deploy_keys SET bound_ip = ? WHERE id = ? AND bound_ip = ''",
            (client[:64], key_id),
        )
        conn.execute(
            "UPDATE deploy_keys SET used_at = COALESCE(used_at, ?), last_used_at = ?, "
            "use_count = use_count + 1 WHERE id = ?",
            (stamp, stamp, key_id),
        )


def unbind_deploy_key(conn: sqlite3.Connection, key_id: int) -> sqlite3.Row:
    """Release the host pin so the same script works from a new address --
    for a host that changed IP, or a script being moved deliberately."""
    row = conn.execute("SELECT * FROM deploy_keys WHERE id = ?", (key_id,)).fetchone()
    if row is None:
        raise StoreError("That key no longer exists.")
    with _write_lock, conn:
        conn.execute("UPDATE deploy_keys SET bound_ip = '' WHERE id = ?", (key_id,))
    log_event(conn, "Released the host pin on deploy key #{0} (was {1})".format(
        key_id, row["bound_ip"] or "unbound"), "warn", row["toolkit_id"])
    return row


def revoke_deploy_key(conn: sqlite3.Connection, key_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM deploy_keys WHERE id = ?", (key_id,)).fetchone()
    if row is None:
        raise StoreError("That key no longer exists.")
    with _write_lock, conn:
        conn.execute("UPDATE deploy_keys SET revoked = 1 WHERE id = ?", (key_id,))
    log_event(conn, "Revoked deploy key #{0}".format(key_id), "warn", row["toolkit_id"])
    return row


def prune_deploy_keys(conn: sqlite3.Connection, toolkit_id: int) -> int:
    """Clear out revoked keys, and keys issued but never used."""
    with _write_lock, conn:
        cur = conn.execute(
            "DELETE FROM deploy_keys WHERE toolkit_id = ? AND (revoked = 1 OR used_at IS NULL)",
            (toolkit_id,))
    return cur.rowcount


def public_url(conn: sqlite3.Connection) -> str:
    return (get_setting(conn, "public_url", "") or "http://localhost:8000").rstrip("/")


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

def _blob_dir(data_dir: Path, toolkit_id: int) -> Path:
    path = Path(data_dir) / "blobs" / str(toolkit_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _store_blob(data_dir: Path, toolkit_id: int, source: Path, filename: str) -> Path:
    """Move a staged file into permanent blob storage."""
    dest = _blob_dir(data_dir, toolkit_id) / "{0}-{1}".format(secrets.token_hex(6), filename)
    shutil.move(str(source), dest)
    return dest


def mark_dirty(conn: sqlite3.Connection, toolkit_id: int) -> None:
    with _write_lock, conn:
        conn.execute("UPDATE toolkits SET dirty = 1 WHERE id = ?", (toolkit_id,))


def add_upload(conn: sqlite3.Connection, toolkit: sqlite3.Row, staged: Path,
               filename: str, data_dir: Path, *, name: str = "", install_dir: str = "",
               unpack: bool = False, notes: str = "", version: str = "") -> int:
    filename = safe_filename(filename)
    blob = _store_blob(data_dir, toolkit["id"], staged, filename)
    with _write_lock, conn:
        cur = conn.execute(
            "INSERT INTO tools (toolkit_id, name, kind, install_dir, unpack, notes, "
            "filename, blob_path, size, sha256, version, added_at, updated_at) "
            "VALUES (?,?,'upload',?,?,?,?,?,?,?,?,?,?)",
            (toolkit["id"], (name or "").strip() or filename, install_dir, int(unpack),
             notes, filename, str(blob), blob.stat().st_size, sha256_file(blob),
             version, now_iso(), now_iso()),
        )
    mark_dirty(conn, toolkit["id"])
    log_event(conn, "Added '{0}' to '{1}'".format(filename, toolkit["name"]),
              toolkit_id=toolkit["id"])
    return cur.lastrowid


def add_github(conn: sqlite3.Connection, toolkit: sqlite3.Row, repo: str, data_dir: Path, *,
               name: str = "", pattern: str = "", prerelease: bool = False,
               source: str = "release", install_dir: str = "", unpack: bool = False,
               notes: str = "") -> int:
    repo = github.parse_repo(repo)
    if conn.execute("SELECT 1 FROM tools WHERE toolkit_id = ? AND gh_repo = ?",
                    (toolkit["id"], repo)).fetchone():
        raise StoreError("'{0}' is already tracked in this toolkit.".format(repo))
    with _write_lock, conn:
        cur = conn.execute(
            "INSERT INTO tools (toolkit_id, name, kind, install_dir, unpack, notes, "
            "added_at, gh_repo, gh_pattern, gh_prerelease, gh_source, gh_status) "
            "VALUES (?,?,'github',?,?,?,?,?,?,?,?,'never checked')",
            (toolkit["id"], (name or "").strip() or repo.split("/")[1], install_dir,
             int(unpack), notes, now_iso(), repo, pattern, int(prerelease), source),
        )
    tool_id = cur.lastrowid
    # Pull it straight away so the toolkit is usable without a second click.
    refresh_tool(conn, tool_id, data_dir)
    return tool_id


def update_tool(conn: sqlite3.Connection, tool_id: int, **fields) -> None:
    allowed = {"name", "install_dir", "unpack", "notes", "enabled",
               "gh_pattern", "gh_prerelease", "gh_source"}
    sets, values = [], []
    for key, value in fields.items():
        if key in allowed and value is not None:
            sets.append("{0} = ?".format(key))
            values.append(int(value) if key in ("unpack", "enabled", "gh_prerelease") else value)
    if not sets:
        return
    values.append(tool_id)
    with _write_lock, conn:
        conn.execute("UPDATE tools SET {0} WHERE id = ?".format(", ".join(sets)), values)
        row = conn.execute("SELECT toolkit_id FROM tools WHERE id = ?", (tool_id,)).fetchone()
    if row:
        mark_dirty(conn, row["toolkit_id"])


def delete_tool(conn: sqlite3.Connection, tool_id: int) -> None:
    tool = conn.execute("SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
    if tool is None:
        raise StoreError("That tool is already gone.")
    if tool["blob_path"]:
        Path(tool["blob_path"]).unlink(missing_ok=True)
    with _write_lock, conn:
        conn.execute("DELETE FROM tools WHERE id = ?", (tool_id,))
    mark_dirty(conn, tool["toolkit_id"])
    log_event(conn, "Removed '{0}'".format(tool["name"]), toolkit_id=tool["toolkit_id"])


def refresh_tool(conn: sqlite3.Connection, tool_id: int, data_dir: Path) -> dict:
    """Check a tracked repo and pull the release if it moved on.

    Returns ``{"updated": bool, "version": str, "message": str}``.
    """
    tool = conn.execute("SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
    if tool is None or tool["kind"] != "github":
        raise StoreError("That tool is not tracking a GitHub project.")
    token = get_setting(conn, "github_token", "") or None

    def _status(text: str, updated: bool = False, version: str = "") -> dict:
        with _write_lock, conn:
            conn.execute("UPDATE tools SET gh_checked_at = ?, gh_status = ? WHERE id = ?",
                         (now_iso(), text, tool_id))
        return {"updated": updated, "version": version or tool["version"], "message": text}

    try:
        found = github.resolve(tool["gh_repo"], token, tool["gh_pattern"] or "",
                               bool(tool["gh_prerelease"]), tool["gh_source"])
    except github.GitHubError as exc:
        log_event(conn, "{0}: {1}".format(tool["gh_repo"], exc), "error", tool["toolkit_id"])
        return _status(str(exc))

    if found["version"] == tool["version"] and tool["blob_path"] and Path(tool["blob_path"]).is_file():
        return _status("up to date at {0}".format(found["version"]))

    try:
        staged = github.download(found["url"], _blob_dir(data_dir, tool["toolkit_id"]), token)
    except github.GitHubError as exc:
        log_event(conn, "{0}: {1}".format(tool["gh_repo"], exc), "error", tool["toolkit_id"])
        return _status(str(exc))

    filename = safe_filename(found["filename"])
    blob = _store_blob(data_dir, tool["toolkit_id"], staged, filename)
    if tool["blob_path"]:
        Path(tool["blob_path"]).unlink(missing_ok=True)

    previous = tool["version"]
    with _write_lock, conn:
        conn.execute(
            "UPDATE tools SET filename = ?, blob_path = ?, size = ?, sha256 = ?, "
            "version = ?, updated_at = ? WHERE id = ?",
            (filename, str(blob), blob.stat().st_size, sha256_file(blob),
             found["version"], now_iso(), tool_id),
        )
    mark_dirty(conn, tool["toolkit_id"])
    message = "updated {0} -> {1}".format(previous or "new", found["version"])
    log_event(conn, "{0} {1}".format(tool["gh_repo"], message), toolkit_id=tool["toolkit_id"])
    return _status(message, updated=True, version=found["version"])


def refresh_toolkit(conn: sqlite3.Connection, toolkit: sqlite3.Row, data_dir: Path) -> dict:
    """Check every tracked tool in a toolkit, then rebuild if anything moved."""
    tools = conn.execute(
        "SELECT id FROM tools WHERE toolkit_id = ? AND kind = 'github' AND enabled = 1",
        (toolkit["id"],),
    ).fetchall()
    results = [refresh_tool(conn, row["id"], data_dir) for row in tools]
    updated = [r for r in results if r["updated"]]
    if updated:
        rebuild(conn, get_toolkit(conn, toolkit["slug"]), data_dir)
    return {"checked": len(results), "updated": len(updated),
            "messages": [r["message"] for r in results]}


# --------------------------------------------------------------------------
# Archive
# --------------------------------------------------------------------------

def rebuild(conn: sqlite3.Connection, toolkit: sqlite3.Row, data_dir: Path) -> dict:
    stats = archive.build(conn, toolkit, Path(data_dir) / "archives")
    with _write_lock, conn:
        conn.execute(
            "UPDATE toolkits SET archive_path = ?, archive_sha256 = ?, archive_size = ?, "
            "archive_built_at = ?, archive_revision = ?, dirty = 0 WHERE id = ?",
            (stats["path"], stats["sha256"], stats["size"], stats["built_at"],
             stats["revision"], toolkit["id"]),
        )
    count = stats["tool_count"]
    log_event(conn, "Built revision {0} of '{1}' ({2} tool{3})".format(
        stats["revision"], toolkit["name"], count, "" if count == 1 else "s"),
        toolkit_id=toolkit["id"])
    return stats


def ensure_built(conn: sqlite3.Connection, toolkit: sqlite3.Row, data_dir: Path) -> sqlite3.Row:
    """Build on demand so a deploy never hits a stale or missing archive."""
    fresh = toolkit["archive_path"] and Path(toolkit["archive_path"]).is_file()
    if toolkit["dirty"] or not fresh:
        rebuild(conn, toolkit, data_dir)
        return get_toolkit(conn, toolkit["slug"])
    return toolkit
