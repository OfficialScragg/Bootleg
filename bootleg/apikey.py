"""Bootleg API key encoding.

A Bootleg key is a *decodable* (not encrypted) envelope carrying everything the
deploy script needs to phone home:

    BL1<base64url( zlib( json ) + checksum )>

    json = {"v": 2,
            "u": <server url>,
            "t": <toolkit slug>,
            "k": <single-use auth token>,
            "p": <archive secret>}

It is deliberately transparent -- the deploy script decodes it with the standard
library alone. Secrecy lives in the random values inside it, not in the encoding.

``k`` is minted fresh for every deploy script and is spent on first use, so a
leaked script cannot be replayed. ``p`` is per-toolkit and derives the archive
password on both sides, which is what lets one stored archive serve every key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import zlib

PREFIX = "BL1"
CHECKSUM_LEN = 3
TOKEN_BYTES = 32


class KeyError_(ValueError):
    """Raised when a key cannot be decoded."""


def new_token() -> str:
    """A securely random authentication token (256 bits, url-safe)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def encode(server_url: str, toolkit: str, token: str, secret: str = "") -> str:
    """Serialize the parts into a single copy-pasteable key."""
    payload = {"v": 2, "u": server_url.rstrip("/"), "t": toolkit, "k": token,
               "p": secret or token}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = zlib.compress(raw, 9)
    checksum = hashlib.sha256(body).digest()[:CHECKSUM_LEN]
    return PREFIX + _b64e(body + checksum)


def decode(key: str) -> dict:
    """Reverse of :func:`encode`. Returns {"url","toolkit","token","secret"}."""
    key = key.strip()
    if not key.startswith(PREFIX):
        raise KeyError_("not a Bootleg key (missing %s prefix)" % PREFIX)
    try:
        blob = _b64d(key[len(PREFIX):])
    except (binascii.Error, ValueError) as exc:
        raise KeyError_("key is not valid base64: %s" % exc) from exc
    if len(blob) <= CHECKSUM_LEN:
        raise KeyError_("key is truncated")
    body, checksum = blob[:-CHECKSUM_LEN], blob[-CHECKSUM_LEN:]
    if hashlib.sha256(body).digest()[:CHECKSUM_LEN] != checksum:
        raise KeyError_("key checksum mismatch -- it was copied incorrectly")
    try:
        payload = json.loads(zlib.decompress(body))
    except (zlib.error, ValueError) as exc:
        raise KeyError_("key payload is corrupt: %s" % exc) from exc
    if payload.get("v") not in (1, 2):
        raise KeyError_("unsupported key version %r" % payload.get("v"))
    for field in ("u", "t", "k"):
        if not payload.get(field):
            raise KeyError_("key is missing field %r" % field)
    return {
        "url": payload["u"],
        "toolkit": payload["t"],
        "token": payload["k"],
        # v1 keys had no separate archive secret: the auth token was both.
        "secret": payload.get("p") or payload["k"],
    }


def archive_password(secret: str) -> str:
    """Derive the archive password from the toolkit's archive secret.

    Both sides derive it the same way, so the password never travels: whoever
    holds a key for this toolkit can open its archive, and nobody else can.
    """
    digest = hashlib.sha256(("bootleg-archive-v1:" + secret).encode()).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def token_hash(token: str) -> str:
    """Index/lookup form of a deploy token. Only this is stored server side."""
    return hashlib.sha256(("bootleg-deploy-key-v1:" + token).encode()).hexdigest()
