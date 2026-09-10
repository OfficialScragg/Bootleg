"""Small shared helpers."""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import unicodedata
from pathlib import Path

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def slugify(text: str, fallback: str = "toolkit") -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return slug or fallback


def safe_relpath(text: str) -> str:
    """Normalize a user-supplied path so it can never escape the archive root."""
    parts = []
    for part in str(text or "").replace("\\", "/").split("/"):
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        parts.append(re.sub(r'[<>:"|?*\x00-\x1f]', "_", part))
    return "/".join(parts)


def safe_filename(name: str, fallback: str = "file.bin") -> str:
    name = Path(str(name or "")).name
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(". ")
    return name or fallback


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def human_size(num: float | int | None) -> str:
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:,.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"
