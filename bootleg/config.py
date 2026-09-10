"""Runtime configuration, all overridable by environment variable."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    DATA_DIR = Path(os.environ.get("BOOTLEG_DATA_DIR", BASE_DIR / "data"))
    DATABASE = DATA_DIR / "bootleg.db"
    UPLOAD_TMP = DATA_DIR / "tmp"
    MAX_CONTENT_LENGTH = _int("BOOTLEG_MAX_UPLOAD_MB", 4096) * 1024 * 1024
    HOST = os.environ.get("BOOTLEG_HOST", "127.0.0.1")
    PORT = _int("BOOTLEG_PORT", 8000)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("BOOTLEG_SECURE_COOKIE", "").lower() in ("1", "true", "yes")
    PERMANENT_SESSION_LIFETIME = _int("BOOTLEG_SESSION_HOURS", 12) * 3600
    # Defaults for first run; editable afterwards in Settings.
    DEFAULT_PUBLIC_URL = os.environ.get("BOOTLEG_PUBLIC_URL", "")
    DEFAULT_CHECK_INTERVAL = _int("BOOTLEG_CHECK_MINUTES", 60)
