"""Build the encrypted toolkit archive.

A toolkit is packed into a deflate zip and then sealed with AES-256 (see
:mod:`bootleg.envelope`). The sealed ``.blz`` is what sits on disk and what
crosses the wire -- opaque either way.

Layout inside the zip::

    MANIFEST.json          what is in here, and what the agent should do with it
    setup.sh               optional post-deploy script
    <install_dir>/<file>   one entry per enabled tool
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
import zipfile
from pathlib import Path

from .apikey import archive_password
from .envelope import seal
from .util import now_iso, safe_relpath, sha256_file

MANIFEST_NAME = "MANIFEST.json"
SETUP_NAME = "setup.sh"
ARCHIVE_SUFFIX = ".blz"

_EXEC_SUFFIXES = {"", ".sh", ".py", ".pl", ".rb", ".bin", ".elf", ".run"}
_EXEC_MAGIC = (b"\x7fELF", b"#!")
_UNPACKABLE = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar", ".zip")
# Already-compressed payloads: zip them stored, so we do not burn CPU twice.
_PRECOMPRESSED = (".gz", ".xz", ".bz2", ".zip", ".7z", ".zst", ".tgz", ".tbz2",
                  ".txz", ".jar", ".png", ".jpg", ".deb", ".rpm", ".whl")


def looks_executable(path: Path) -> bool:
    """Guess whether a payload should land on the target with the exec bit set."""
    if path.suffix.lower() in _EXEC_SUFFIXES:
        return True
    try:
        with open(path, "rb") as fh:
            return fh.read(4).startswith(_EXEC_MAGIC)
    except OSError:
        return False


def is_unpackable(filename: str) -> bool:
    name = (filename or "").lower()
    return any(name.endswith(ext) for ext in _UNPACKABLE)


def _compression_for(filename: str) -> int:
    name = (filename or "").lower()
    if any(name.endswith(ext) for ext in _PRECOMPRESSED):
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def _unique(entry: str, seen: set) -> str:
    """Two tools can name the same path; keep both rather than silently
    shadowing one with the other."""
    if entry not in seen:
        seen.add(entry)
        return entry
    stem, dot, suffix = entry.partition(".")
    for n in range(2, 1000):
        candidate = "{0}-{1}{2}{3}".format(stem, n, dot, suffix)
        if candidate not in seen:
            seen.add(candidate)
            return candidate
    seen.add(entry)
    return entry


def _entry_path(tool: sqlite3.Row) -> str:
    directory = safe_relpath(tool["install_dir"])
    name = tool["filename"] or tool["name"]
    return f"{directory}/{name}" if directory else name


def pack(conn: sqlite3.Connection, toolkit: sqlite3.Row, zip_path: Path,
         revision: int | None = None) -> dict:
    """Write the toolkit to a plain deflate zip. Returns the manifest.

    Used both as the first half of :func:`build` and on its own for the
    dashboard's direct download, which serves the zip as-is.
    """
    tools = conn.execute(
        "SELECT * FROM tools WHERE toolkit_id = ? AND enabled = 1 ORDER BY install_dir, name",
        (toolkit["id"],),
    ).fetchall()

    manifest = {
        "toolkit": toolkit["slug"],
        "name": toolkit["name"],
        "description": toolkit["description"] or "",
        "revision": int(toolkit["archive_revision"] or 0) + 1 if revision is None else revision,
        "built_at": now_iso(),
        "has_setup": bool((toolkit["setup_script"] or "").strip()),
        "tools": [],
    }

    seen: set[str] = set()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6, allowZip64=True) as zf:
        for tool in tools:
            blob = Path(tool["blob_path"] or "")
            if not blob.is_file():
                continue
            entry = _unique(_entry_path(tool), seen)
            info = zipfile.ZipInfo(entry)
            info.compress_type = _compression_for(tool["filename"] or "")
            mode = 0o755 if looks_executable(blob) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            with open(blob, "rb") as src, zf.open(info, "w") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)

            manifest["tools"].append({
                "name": tool["name"],
                "path": entry,
                "kind": tool["kind"],
                "version": tool["version"] or "",
                "size": int(tool["size"] or 0),
                "sha256": tool["sha256"] or "",
                "unpack": bool(tool["unpack"]) and is_unpackable(tool["filename"] or ""),
                "executable": mode == 0o755,
                "notes": tool["notes"] or "",
            })

        setup = (toolkit["setup_script"] or "").strip()
        if setup:
            info = zipfile.ZipInfo(SETUP_NAME)
            info.external_attr = (stat.S_IFREG | 0o755) << 16
            body = setup if setup.startswith("#!") else "#!/bin/sh\n" + setup
            zf.writestr(info, body.rstrip() + "\n")

        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))

    return manifest


def build(conn: sqlite3.Connection, toolkit: sqlite3.Row, archive_dir: Path) -> dict:
    """(Re)build the sealed archive for one toolkit. Returns archive stats."""
    archive_dir = Path(archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)

    # Pack to a scratch file, seal into a second, then swap the sealed one in
    # atomically -- an in-flight download never sees a half-written archive.
    plain_fd, plain_path = tempfile.mkstemp(dir=archive_dir, prefix=".pack-", suffix=".zip")
    os.close(plain_fd)
    sealed_fd, sealed_path = tempfile.mkstemp(dir=archive_dir, prefix=".seal-", suffix=".part")
    os.close(sealed_fd)
    plain_path, sealed_path = Path(plain_path), Path(sealed_path)

    try:
        manifest = pack(conn, toolkit, plain_path)
        seal(plain_path, sealed_path, archive_password(toolkit["archive_secret"]))
        final = archive_dir / f"{toolkit['slug']}{ARCHIVE_SUFFIX}"
        os.replace(sealed_path, final)
    finally:
        plain_path.unlink(missing_ok=True)
        sealed_path.unlink(missing_ok=True)

    return {
        "path": str(final),
        "size": final.stat().st_size,
        "sha256": sha256_file(final),
        "built_at": manifest["built_at"],
        "revision": manifest["revision"],
        "tool_count": len(manifest["tools"]),
    }
