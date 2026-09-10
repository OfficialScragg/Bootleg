"""The Bootleg archive envelope (.blz).

A toolkit is packed as a plain deflate zip, then sealed here. The sealed file is
opaque on the wire and at rest: without the toolkit token nothing about the
contents -- not even the file names -- is recoverable.

Format::

    0   magic    8   b"BOOTLEG\\x01"
    8   iters    4   uint32 big-endian, PBKDF2 iteration count
    12  mac     32   HMAC-SHA256(mac_key, bytes[0:12] || body)
    44  body    ..   b"Salted__" || salt(8) || AES-256-CTR ciphertext

``body`` is byte-for-byte an ``openssl enc -aes-256-ctr -pbkdf2`` file, which is
what lets the deploy agent hand decryption to the host's own openssl and stay
fast on large toolkits. Encrypt-then-MAC, so a tampered archive is rejected
before a single byte is decrypted.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"BOOTLEG\x01"
HEADER_LEN = 44
SALT_MAGIC = b"Salted__"
SALT_LEN = 8
MAC_LEN = 32
DEFAULT_ITERS = 600_000
_MAC_INFO = b"bootleg-mac-v1"
_CHUNK = 1 << 20


class EnvelopeError(Exception):
    """Raised when an archive is malformed, tampered with, or the key is wrong."""


def derive(password: str, salt: bytes, iters: int) -> tuple[bytes, bytes, bytes]:
    """Return (aes_key, iv, mac_key) exactly as the deploy agent derives them."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, 48)
    mac_key = hmac.new(dk, _MAC_INFO, hashlib.sha256).digest()
    return dk[:32], dk[32:48], mac_key


def _stream(src, dst, password: str, salt: bytes, iters: int, mac) -> None:
    key, iv, _ = derive(password, salt, iters)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    while chunk := src.read(_CHUNK):
        out = encryptor.update(chunk)
        mac.update(out)
        dst.write(out)
    out = encryptor.finalize()
    if out:
        mac.update(out)
        dst.write(out)


def seal(plain_path: str | Path, sealed_path: str | Path, password: str,
         iters: int = DEFAULT_ITERS) -> None:
    """Encrypt ``plain_path`` into ``sealed_path``."""
    salt = os.urandom(SALT_LEN)
    _, _, mac_key = derive(password, salt, iters)
    header = MAGIC + struct.pack(">I", iters)
    mac = hmac.new(mac_key, header, hashlib.sha256)
    mac.update(SALT_MAGIC + salt)

    with open(plain_path, "rb") as src, open(sealed_path, "wb") as dst:
        dst.write(header)
        dst.write(b"\x00" * MAC_LEN)          # placeholder, backfilled below
        dst.write(SALT_MAGIC + salt)
        _stream(src, dst, password, salt, iters, mac)
        dst.flush()
        dst.seek(len(header))
        dst.write(mac.digest())


def open_sealed(sealed_path: str | Path, password: str) -> bytes:
    """Verify and decrypt a sealed archive in memory. Used by tests and export."""
    data = Path(sealed_path).read_bytes()
    if len(data) < HEADER_LEN + len(SALT_MAGIC) + SALT_LEN or not data.startswith(MAGIC):
        raise EnvelopeError("not a Bootleg archive")
    iters = struct.unpack(">I", data[8:12])[0]
    stored_mac = data[12:HEADER_LEN]
    body = data[HEADER_LEN:]
    if not body.startswith(SALT_MAGIC):
        raise EnvelopeError("archive body is corrupt")
    salt = body[len(SALT_MAGIC):len(SALT_MAGIC) + SALT_LEN]
    key, iv, mac_key = derive(password, salt, iters)

    mac = hmac.new(mac_key, data[:12], hashlib.sha256)
    mac.update(body)
    if not hmac.compare_digest(mac.digest(), stored_mac):
        raise EnvelopeError("authentication failed -- wrong key or tampered archive")

    ciphertext = body[len(SALT_MAGIC) + SALT_LEN:]
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
