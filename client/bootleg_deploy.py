#!/usr/bin/env python3
"""Bootleg deploy agent -- pulls a toolkit from your Bootleg server onto this host.

Paste it on the target, run it, and the toolkit lands in the working directory.
Standard library only: no pip, no venv, nothing to install. Python 3.6+.

    python3 bootleg_deploy.py [-d DIR] [--list] [--setup] [--force] [--insecure]

The archive is AES-256 encrypted end to end. Decryption uses the host's own
openssl when it is present, and falls back to a built-in cipher when it is not.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Filled in by the Bootleg dashboard when you copy this script.
BOOTLEG_KEY = "%%BOOTLEG_KEY%%"

USER_AGENT = "bootleg-agent/1.0"
STATE_FILE = ".bootleg.json"
MAGIC = b"BOOTLEG\x01"
HEADER_LEN = 44
SALT_MAGIC = b"Salted__"
SALT_LEN = 8
CHUNK = 1 << 20

_IS_TTY = sys.stderr.isatty()
_C = {
    "reset": "\033[0m" if _IS_TTY else "", "dim": "\033[2m" if _IS_TTY else "",
    "bold": "\033[1m" if _IS_TTY else "", "green": "\033[32m" if _IS_TTY else "",
    "red": "\033[31m" if _IS_TTY else "", "yellow": "\033[33m" if _IS_TTY else "",
    "cyan": "\033[36m" if _IS_TTY else "",
}

QUIET = False


class Fail(Exception):
    """A fatal, already-explained error."""


def say(message, colour=None, force=False):
    if QUIET and not force:
        return
    tint = _C.get(colour or "", "")
    sys.stderr.write("{0}{1}{2}\n".format(tint, message, _C["reset"] if tint else ""))


def step(message):
    say("  {0}->{1} {2}".format(_C["cyan"], _C["reset"], message))


def human(num):
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return "{0:.0f} {1}".format(num, unit) if unit == "B" else "{0:.1f} {1}".format(num, unit)
        num /= 1024
    return "{0:.1f} GB".format(num)


# --------------------------------------------------------------------------
# API key
# --------------------------------------------------------------------------

def decode_key(key):
    """Unpack the key into its server URL, toolkit name and auth token."""
    key = (key or "").strip()
    if not key or key.startswith("%%"):
        raise Fail("No API key embedded. Copy the script from the Bootleg "
                   "dashboard's Deploy tab, or pass --key.")
    if not key.startswith("BL1"):
        raise Fail("That does not look like a Bootleg key (should start with BL1).")
    body = key[3:]
    try:
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        raise Fail("Key is not valid base64 -- it was probably truncated on copy.")
    if len(blob) <= 3:
        raise Fail("Key is truncated.")
    payload, checksum = blob[:-3], blob[-3:]
    if hashlib.sha256(payload).digest()[:3] != checksum:
        raise Fail("Key checksum mismatch -- it was copied incorrectly.")
    try:
        data = json.loads(zlib.decompress(payload).decode("utf-8"))
    except Exception:
        raise Fail("Key payload is corrupt.")
    return {
        "url": data["u"].rstrip("/"),
        "toolkit": data["t"],
        "token": data["k"],
        # "p" is the archive secret; older keys used the auth token for both.
        "secret": data.get("p") or data["k"],
    }


def archive_password(secret):
    digest = hashlib.sha256(("bootleg-archive-v1:" + secret).encode()).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

def _context(insecure):
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(cfg, path, insecure):
    url = cfg["url"] + path
    req = Request(url, headers={"X-Bootleg-Key": cfg["key"], "User-Agent": USER_AGENT})
    try:
        return urlopen(req, timeout=60, context=_context(insecure))
    except HTTPError as exc:
        # The server explains itself properly (spent key, revoked key, no
        # archive); pass that through rather than guessing from the status.
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get("error", "")
        except Exception:
            pass
        if detail:
            raise Fail(detail)
        if exc.code in (401, 403, 409):
            raise Fail("Server rejected the key (HTTP {0}). Copy a fresh script "
                       "from the dashboard.".format(exc.code))
        if exc.code == 404:
            raise Fail("Toolkit '{0}' is not on the server (HTTP 404).".format(cfg["toolkit"]))
        raise Fail("Server error HTTP {0} for {1}".format(exc.code, url))
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason).upper():
            raise Fail("TLS verification failed for {0}.\n  If the server uses a "
                       "self-signed certificate, re-run with --insecure.".format(url))
        raise Fail("Cannot reach {0}: {1}".format(url, reason))


def fetch_manifest(cfg, insecure):
    with _request(cfg, "/api/v1/manifest", insecure) as resp:
        return json.loads(resp.read().decode("utf-8"))


def download(cfg, dest, expect_size, insecure):
    started = time.time()
    got = 0
    with _request(cfg, "/api/v1/archive", insecure) as resp:
        total = int(resp.headers.get("Content-Length") or expect_size or 0)
        with open(dest, "wb") as out:
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                got += len(chunk)
                if _IS_TTY and not QUIET and total:
                    pct = got * 100.0 / total
                    sys.stderr.write("\r  {0}->{1} downloading {2:5.1f}%  {3}   ".format(
                        _C["cyan"], _C["reset"], pct, human(got)))
    if _IS_TTY and not QUIET:
        sys.stderr.write("\r" + " " * 60 + "\r")
    elapsed = max(time.time() - started, 0.001)
    step("downloaded {0} in {1:.1f}s ({2}/s)".format(human(got), elapsed, human(got / elapsed)))
    return got


# --------------------------------------------------------------------------
# AES-256-CTR (fallback only -- openssl does this natively when available)
# --------------------------------------------------------------------------

def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63

    def xt(a):
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

    t0 = []
    for a in range(256):
        s = sbox[a]
        t0.append((xt(s) << 24) | (s << 16) | (s << 8) | (xt(s) ^ s))
    return bytes(sbox), t0


_SBOX, _T0 = _aes_tables()
_T1 = [((v >> 8) | (v << 24)) & 0xFFFFFFFF for v in _T0]
_T2 = [((v >> 16) | (v << 16)) & 0xFFFFFFFF for v in _T0]
_T3 = [((v >> 24) | (v << 8)) & 0xFFFFFFFF for v in _T0]
_RCON = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
         0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]


def _expand_key(key):
    """AES-256 key schedule -> 60 round-key words."""
    w = list(struct.unpack(">8I", key))
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
            t = ((_SBOX[(t >> 24) & 0xFF] << 24) | (_SBOX[(t >> 16) & 0xFF] << 16) |
                 (_SBOX[(t >> 8) & 0xFF] << 8) | _SBOX[t & 0xFF]) ^ _RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = ((_SBOX[(t >> 24) & 0xFF] << 24) | (_SBOX[(t >> 16) & 0xFF] << 16) |
                 (_SBOX[(t >> 8) & 0xFF] << 8) | _SBOX[t & 0xFF])
        w.append(w[i - 8] ^ t)
    return w


def _encrypt_block(w, block):
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= w[0]; s1 ^= w[1]; s2 ^= w[2]; s3 ^= w[3]
    k = 4
    for _ in range(13):
        s0, s1, s2, s3 = (
            _T0[(s0 >> 24) & 0xFF] ^ _T1[(s1 >> 16) & 0xFF] ^ _T2[(s2 >> 8) & 0xFF] ^ _T3[s3 & 0xFF] ^ w[k],
            _T0[(s1 >> 24) & 0xFF] ^ _T1[(s2 >> 16) & 0xFF] ^ _T2[(s3 >> 8) & 0xFF] ^ _T3[s0 & 0xFF] ^ w[k + 1],
            _T0[(s2 >> 24) & 0xFF] ^ _T1[(s3 >> 16) & 0xFF] ^ _T2[(s0 >> 8) & 0xFF] ^ _T3[s1 & 0xFF] ^ w[k + 2],
            _T0[(s3 >> 24) & 0xFF] ^ _T1[(s0 >> 16) & 0xFF] ^ _T2[(s1 >> 8) & 0xFF] ^ _T3[s2 & 0xFF] ^ w[k + 3],
        )
        k += 4
    out = []
    for a, b, c, d in ((s0, s1, s2, s3), (s1, s2, s3, s0), (s2, s3, s0, s1), (s3, s0, s1, s2)):
        out.append(((_SBOX[(a >> 24) & 0xFF] << 24) | (_SBOX[(b >> 16) & 0xFF] << 16) |
                    (_SBOX[(c >> 8) & 0xFF] << 8) | _SBOX[d & 0xFF]) ^ w[k])
        k += 1
    return struct.pack(">4I", *out)


def _aes_ctr_python(src, dst, key, iv, on_progress=None):
    w = _expand_key(key)
    counter = int.from_bytes(iv, "big")
    done = 0
    while True:
        chunk = src.read(CHUNK)
        if not chunk:
            break
        stream = bytearray()
        for _ in range((len(chunk) + 15) // 16):
            stream += _encrypt_block(w, counter.to_bytes(16, "big"))
            counter = (counter + 1) & ((1 << 128) - 1)
        size = len(chunk)
        merged = int.from_bytes(chunk, "big") ^ int.from_bytes(stream[:size], "big")
        dst.write(merged.to_bytes(size, "big"))
        done += len(chunk)
        if on_progress:
            on_progress(done)


# --------------------------------------------------------------------------
# Unsealing
# --------------------------------------------------------------------------

def _have_openssl():
    return shutil.which("openssl") is not None


def unseal(sealed, plain, password):
    """Verify then decrypt a sealed archive. Raises Fail on tampering."""
    size = os.path.getsize(sealed)
    if size < HEADER_LEN + len(SALT_MAGIC) + SALT_LEN:
        raise Fail("Archive is truncated.")

    with open(sealed, "rb") as fh:
        header = fh.read(12)
        if not header.startswith(MAGIC):
            raise Fail("Not a Bootleg archive (bad magic).")
        iters = struct.unpack(">I", header[8:12])[0]
        stored_mac = fh.read(32)
        prefix = fh.read(len(SALT_MAGIC) + SALT_LEN)
        if not prefix.startswith(SALT_MAGIC):
            raise Fail("Archive body is corrupt.")
        salt = prefix[len(SALT_MAGIC):]

        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, 48)
        key, iv = dk[:32], dk[32:48]
        mac_key = hmac.new(dk, b"bootleg-mac-v1", hashlib.sha256).digest()

        mac = hmac.new(mac_key, header, hashlib.sha256)
        mac.update(prefix)
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            mac.update(chunk)
        if not hmac.compare_digest(mac.digest(), stored_mac):
            raise Fail("Archive failed authentication -- wrong key, or it was "
                       "modified in transit. Nothing was decrypted.")

        # Body from HEADER_LEN onward is a stock `openssl enc` file, so hand it
        # to the host's openssl when we can: native speed, no dependencies.
        body_start = HEADER_LEN + len(SALT_MAGIC) + SALT_LEN
        if _have_openssl():
            fh.seek(HEADER_LEN)  # openssl parses the Salted__ prefix itself
            env = dict(os.environ, BOOTLEG_PW=password)
            cmd = ["openssl", "enc", "-d", "-aes-256-ctr", "-pbkdf2",
                   "-iter", str(iters), "-md", "sha256", "-pass", "env:BOOTLEG_PW"]
            with open(plain, "wb") as out:
                proc = subprocess.run(cmd, stdin=fh, stdout=out,
                                      stderr=subprocess.PIPE, env=env)
            if proc.returncode == 0:
                return
            say("  openssl declined ({0}); using the built-in cipher".format(
                proc.stderr.decode("utf-8", "replace").strip() or "unknown error"), "yellow")

        step("decrypting with the built-in cipher (slower; install openssl to speed this up)")
        fh.seek(body_start)
        with open(plain, "wb") as out:
            _aes_ctr_python(fh, out, key, iv)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def _safe_join(root, name):
    target = os.path.realpath(os.path.join(root, name))
    if target != root and not target.startswith(root + os.sep):
        raise Fail("Archive contains an unsafe path: {0}".format(name))
    return target


def extract(zip_path, target):
    """Unpack the toolkit, preserving the exec bits the server recorded."""
    root = os.path.realpath(target)
    written = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            dest = _safe_join(root, info.filename)
            if info.is_dir():
                os.makedirs(dest, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out, CHUNK)
            mode = (info.external_attr >> 16) & 0o7777
            os.chmod(dest, mode if mode else 0o644)
            written.append(info.filename)
    return written


ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz",
                    ".txz", ".tar", ".zip")


def _strip_archive_suffix(name):
    """nuclei_3.11.1_linux_amd64.zip -> nuclei_3.11.1_linux_amd64"""
    lowered = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return name[:-len(suffix)]
    return os.path.splitext(name)[0]


def _is_metadata(name):
    """Packaging junk that should not count as a root directory."""
    base = name.split("/")[0]
    return (base.startswith("._") or base in ("__MACOSX", ".DS_Store")
            or base.startswith("PaxHeader") or base == "pax_global_header")


def _destination(path, names):
    """Extract beside the archive when it already has one root, else into a
    folder named after it -- so we never end up with tool-1.0/tool-1.0/."""
    parent = os.path.dirname(path)
    tops = set(n.split("/")[0] for n in names
               if n.strip("/") and not _is_metadata(n))
    if len(tops) == 1:
        return parent
    return os.path.join(parent, _strip_archive_suffix(os.path.basename(path)))


def _unpack_one(path):
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            names = tf.getnames()
            dest = _destination(path, names)
            os.makedirs(dest, exist_ok=True)
            root = os.path.realpath(dest)
            for name in names:
                _safe_join(root, name)
            try:
                tf.extractall(dest, filter="data")   # python 3.12+
            except TypeError:
                tf.extractall(dest)
        return True

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            dest = _destination(path, [i.filename for i in infos])
            os.makedirs(dest, exist_ok=True)
            root = os.path.realpath(dest)
            for info in infos:
                out = _safe_join(root, info.filename)
                if info.is_dir():
                    os.makedirs(out, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with zf.open(info) as src, open(out, "wb") as fh:
                    shutil.copyfileobj(src, fh, CHUNK)
                # zipfile drops unix modes on extract, so reapply them: a
                # toolkit whose binaries are not executable is no toolkit.
                mode = (info.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(out, mode)
        return True

    return False


def unpack_nested(target, entries):
    """Expand tool payloads flagged for extraction on the target."""
    for entry in entries:
        path = os.path.join(target, entry["path"])
        if not os.path.isfile(path):
            continue
        try:
            if not _unpack_one(path):
                continue
        except Fail:
            say("  ! refused to unpack {0}: unsafe paths inside".format(entry["path"]), "yellow")
            continue
        except Exception as exc:
            say("  ! could not unpack {0}: {1}".format(entry["path"], exc), "yellow")
            continue
        os.remove(path)
        step("unpacked {0}".format(entry["path"]))


def run_setup(target):
    script = os.path.join(target, "setup.sh")
    if not os.path.isfile(script):
        say("  no setup script in this toolkit", "dim")
        return
    os.chmod(script, 0o755)
    step("running setup.sh")
    code = subprocess.call(["/bin/sh", script], cwd=target)
    if code:
        say("  setup.sh exited {0}".format(code), "yellow")
    else:
        say("  setup.sh finished", "green")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="bootleg_deploy.py",
        description="Deploy a Bootleg toolkit onto this host.")
    ap.add_argument("-d", "--dir", help="where to put the toolkit (default: ./<toolkit>)")
    ap.add_argument("-k", "--key", help="override the embedded API key")
    ap.add_argument("-l", "--list", action="store_true",
                    help="show what the toolkit holds and exit")
    ap.add_argument("-s", "--setup", action="store_true",
                    help="run the toolkit's setup.sh after deploying")
    ap.add_argument("-f", "--force", action="store_true",
                    help="redeploy even if this revision is already here")
    ap.add_argument("--keep-archive", action="store_true",
                    help="leave the encrypted archive next to the toolkit")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification (self-signed servers)")
    ap.add_argument("-q", "--quiet", action="store_true", help="only report problems")
    return ap.parse_args(argv)


def read_state(target):
    try:
        with open(os.path.join(target, STATE_FILE)) as fh:
            return json.load(fh)
    except Exception:
        return {}


def write_state(target, manifest, files):
    state = {
        "toolkit": manifest["toolkit"],
        "revision": manifest["revision"],
        "sha256": manifest.get("sha256", ""),
        "built_at": manifest.get("built_at", ""),
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
    }
    with open(os.path.join(target, STATE_FILE), "w") as fh:
        json.dump(state, fh, indent=2)


def main(argv=None):
    global QUIET
    args = parse_args(argv if argv is not None else sys.argv[1:])
    QUIET = args.quiet

    cfg = decode_key(args.key or BOOTLEG_KEY)
    cfg["key"] = (args.key or BOOTLEG_KEY).strip()

    say("")
    say("  {0}Bootleg{1} {2}{3}{4}".format(
        _C["bold"], _C["reset"], _C["dim"], cfg["url"], _C["reset"]))
    say("")

    manifest = fetch_manifest(cfg, args.insecure)
    tools = manifest.get("tools", [])
    say("  {0}{1}{2}  rev {3}  {4} tool{5}  {6}".format(
        _C["bold"], manifest.get("name") or cfg["toolkit"], _C["reset"],
        manifest.get("revision"), len(tools), "" if len(tools) == 1 else "s",
        human(manifest.get("size"))))
    if manifest.get("description"):
        say("  {0}{1}{2}".format(_C["dim"], manifest["description"], _C["reset"]))
    say("")

    if args.list:
        for tool in tools:
            version = " {0}".format(tool["version"]) if tool.get("version") else ""
            say("  {0:<40} {1}{2}{3}".format(
                tool["path"], _C["dim"], human(tool.get("size")) + version, _C["reset"]),
                force=True)
        if manifest.get("has_setup"):
            say("  {0}setup.sh{1} (run with --setup)".format(_C["dim"], _C["reset"]), force=True)
        return 0

    target = os.path.abspath(args.dir or os.path.join(os.getcwd(), cfg["toolkit"]))
    state = read_state(target)
    if (not args.force and state.get("revision") == manifest.get("revision")
            and state.get("sha256") == manifest.get("sha256")):
        say("  {0}Already up to date{1} (revision {2}) at {3}".format(
            _C["green"], _C["reset"], manifest["revision"], target))
        say("  {0}Re-run with --force to redeploy.{1}".format(_C["dim"], _C["reset"]))
        return 0

    os.makedirs(target, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix=".bootleg-", dir=target)
    sealed = os.path.join(workdir, "archive.blz")
    plain = os.path.join(workdir, "archive.zip")
    try:
        download(cfg, sealed, manifest.get("size"), args.insecure)

        digest = hashlib.sha256()
        with open(sealed, "rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                digest.update(chunk)
        if manifest.get("sha256") and digest.hexdigest() != manifest["sha256"]:
            raise Fail("Archive digest does not match the manifest -- download corrupted.")

        step("verifying and decrypting")
        unseal(sealed, plain, archive_password(cfg["secret"]))

        files = extract(plain, target)
        step("extracted {0} file{1} to {2}".format(
            len(files), "" if len(files) == 1 else "s", target))

        unpack_nested(target, [t for t in tools if t.get("unpack")])

        if args.keep_archive:
            shutil.move(sealed, os.path.join(target, "{0}.blz".format(cfg["toolkit"])))

        manifest["sha256"] = digest.hexdigest()
        write_state(target, manifest, files)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if args.setup:
        run_setup(target)
    elif manifest.get("has_setup"):
        say("  {0}This toolkit ships a setup.sh -- run with --setup to execute it.{1}".format(
            _C["dim"], _C["reset"]))

    say("")
    say("  {0}Deployed{1} {2} tool{3} to {4}{5}{6}".format(
        _C["green"], _C["reset"], len(tools), "" if len(tools) == 1 else "s",
        _C["bold"], target, _C["reset"]))
    say("  {0}export PATH=\"{1}:$PATH\"{2}".format(_C["dim"], target, _C["reset"]))
    say("")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as err:
        say("")
        say("  {0}x{1} {2}".format(_C["red"], _C["reset"], err), force=True)
        say("")
        sys.exit(1)
    except KeyboardInterrupt:
        say("\n  interrupted", force=True)
        sys.exit(130)
