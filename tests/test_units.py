"""Unit tests for the parts that must not quietly break: key encoding, the
archive envelope, the agent's own crypto, and path-traversal defences."""

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

import bootleg_deploy as agent  # noqa: E402
from bootleg import apikey, envelope, github  # noqa: E402
from bootleg.util import safe_filename, safe_relpath, slugify  # noqa: E402


def check(label, condition, detail=""):
    print("{0} {1}{2}".format("  ok  " if condition else "  FAIL", label,
                              "" if condition else "  <- " + str(detail)))
    if not condition:
        check.failed = True


check.failed = False


def test_apikey():
    print("\n-- api key --")
    token, secret = apikey.new_token(), apikey.new_token()
    key = apikey.encode("https://bootleg.example.com:8443", "red-team", token, secret)
    parts = apikey.decode(key)
    check("round trips through encode/decode",
          parts == {"url": "https://bootleg.example.com:8443", "toolkit": "red-team",
                    "token": token, "secret": secret}, parts)
    check("the agent decodes it identically", agent.decode_key(key) == parts)
    check("archive password matches on both sides",
          apikey.archive_password(secret) == agent.archive_password(secret))
    check("a 256-bit token is used", len(token) >= 43, len(token))
    check("auth token and archive secret are independent", token != secret)

    # Every issued key must be distinct even for the same toolkit.
    others = {apikey.encode("https://x", "kit", apikey.new_token(), secret) for _ in range(200)}
    check("minted keys never collide", len(others) == 200)

    # v1 keys predate the split and used one value for both roles.
    import base64 as _b64, hashlib as _hl, json as _json, zlib as _zlib
    raw = _json.dumps({"v": 1, "u": "https://old", "t": "kit", "k": "OLD"},
                      separators=(",", ":")).encode()
    body = _zlib.compress(raw, 9)
    legacy = "BL1" + _b64.urlsafe_b64encode(
        body + _hl.sha256(body).digest()[:3]).decode().rstrip("=")
    check("v1 keys still decode", apikey.decode(legacy)["secret"] == "OLD")
    check("the agent reads v1 keys too", agent.decode_key(legacy)["secret"] == "OLD")

    check("only the token hash is ever stored",
          apikey.token_hash(token) != token and len(apikey.token_hash(token)) == 64)
    check("hashing is deterministic", apikey.token_hash(token) == apikey.token_hash(token))

    for label, bad in [("garbage", "hello"),
                       ("wrong prefix", "BL9" + key[3:]),
                       ("truncated", key[:12]),
                       ("flipped character", key[:-4] + ("zzzz" if not key.endswith("zzzz") else "yyyy"))]:
        try:
            apikey.decode(bad)
            check("rejects a {0} key".format(label), False, "accepted it")
        except apikey.KeyError_:
            check("rejects a {0} key".format(label), True)

    # Trailing whitespace is what a terminal paste actually looks like.
    check("tolerates whitespace around a pasted key",
          apikey.decode("  " + key + "\n ")["toolkit"] == "red-team")


def test_envelope(tmp):
    print("\n-- archive envelope --")
    plain = tmp / "plain.bin"
    plain.write_bytes(os.urandom(300_000))
    sealed = tmp / "sealed.blz"
    password = "a-derived-password"
    envelope.seal(plain, sealed, password, iters=20_000)

    check("sealed output hides the plaintext",
          plain.read_bytes()[:64] not in sealed.read_bytes())
    check("server can reopen it", envelope.open_sealed(sealed, password) == plain.read_bytes())

    for label, mutate in [("a flipped ciphertext byte", lambda d: d[:200] + bytes([d[200] ^ 1]) + d[201:]),
                          ("a flipped header byte", lambda d: d[:9] + bytes([d[9] ^ 1]) + d[10:]),
                          ("truncation", lambda d: d[:-20])]:
        broken = tmp / "broken.blz"
        broken.write_bytes(mutate(sealed.read_bytes()))
        try:
            envelope.open_sealed(broken, password)
            check("rejects {0}".format(label), False, "accepted it")
        except envelope.EnvelopeError:
            check("rejects {0}".format(label), True)

    try:
        envelope.open_sealed(sealed, "not-the-password")
        check("rejects the wrong password", False, "accepted it")
    except envelope.EnvelopeError:
        check("rejects the wrong password", True)

    # The agent's two decryption paths must agree with each other and with us.
    out_openssl, out_python = tmp / "a.bin", tmp / "b.bin"
    agent.unseal(str(sealed), str(out_openssl), password)
    real_have = agent._have_openssl
    agent._have_openssl = lambda: False
    try:
        agent.unseal(str(sealed), str(out_python), password)
    finally:
        agent._have_openssl = real_have
    check("agent decrypts via openssl", out_openssl.read_bytes() == plain.read_bytes())
    check("agent decrypts via the built-in cipher", out_python.read_bytes() == plain.read_bytes())

    try:
        agent.unseal(str(sealed), str(tmp / "c.bin"), "wrong")
        check("agent rejects the wrong password", False, "accepted it")
    except agent.Fail:
        check("agent rejects the wrong password", True)


def test_aes():
    print("\n-- built-in cipher --")
    # FIPS-197 C.3
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "8ea2b7ca516745bfeafc49904b496089"
    got = agent._encrypt_block(agent._expand_key(key), block).hex()
    check("AES-256 matches the FIPS-197 vector", got == expected, got)


def test_traversal(tmp):
    print("\n-- path traversal --")
    check("relative paths are flattened", safe_relpath("../../etc/passwd") == "etc/passwd")
    check("absolute paths are flattened", safe_relpath("/etc/shadow") == "etc/shadow")
    check("filenames lose their directories", safe_filename("../../evil.sh") == "evil.sh")
    check("slugs stay url-safe", slugify("Red Team // Internal!") == "red-team-internal")

    evil = tmp / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../escaped.txt", "pwned")
    target = tmp / "extract-here"
    target.mkdir()
    try:
        agent.extract(evil, target)
        check("agent refuses a zip-slip archive", False, "it extracted")
    except agent.Fail:
        check("agent refuses a zip-slip archive", True)
    check("nothing escaped the target", not (tmp / "escaped.txt").exists())


def test_github():
    print("\n-- github asset selection --")
    check("owner/repo parses", github.parse_repo("rapid7/metasploit-framework.git")
          == "rapid7/metasploit-framework")
    check("a project URL parses",
          github.parse_repo("https://github.com/BloodHoundAD/BloodHound")
          == "BloodHoundAD/BloodHound")
    try:
        github.parse_repo("not a repo")
        check("nonsense is rejected", False, "accepted it")
    except github.GitHubError:
        check("nonsense is rejected", True)

    assets = [{"name": "checksums.txt.sha256"}, {"name": "tool_darwin_arm64.zip"},
              {"name": "tool_linux_arm64.tar.gz"}, {"name": "tool_linux_amd64.tar.gz"},
              {"name": "tool_windows_amd64.zip"}]
    check("prefers the linux x86-64 build",
          github.pick_asset(assets)["name"] == "tool_linux_amd64.tar.gz",
          github.pick_asset(assets))
    check("an explicit glob wins",
          github.pick_asset(assets, "*windows*")["name"] == "tool_windows_amd64.zip")
    check("skips checksum files",
          github.pick_asset([{"name": "x.sha256"}, {"name": "real.tar.gz"}])["name"] == "real.tar.gz")
    check("falls back when only ARM is published",
          github.pick_asset([{"name": "tool-linux-arm64.tar.gz"}])["name"] == "tool-linux-arm64.tar.gz")
    check("reports no match for an impossible glob",
          github.pick_asset(assets, "*solaris*") is None)


def test_unpack_naming():
    print("\n-- unpack naming --")
    check("dotted versions survive",
          agent._strip_archive_suffix("nuclei_3.11.1_linux_amd64.zip") == "nuclei_3.11.1_linux_amd64")
    check("tar.gz is stripped whole",
          agent._strip_archive_suffix("SecLists-2026.1.tar.gz") == "SecLists-2026.1")
    check("a single root extracts in place",
          agent._destination("/kit/x.tar.gz", ["proj-1.0", "proj-1.0/bin"]) == "/kit")
    check("many roots get their own folder",
          agent._destination("/kit/x.zip", ["a", "b"]) == "/kit/x")
    check("macos metadata does not count as a root",
          agent._destination("/kit/x.tar.gz", ["._proj", "proj", "proj/bin"]) == "/kit")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="bootleg-unit-"))
    try:
        test_apikey()
        test_envelope(tmp)
        test_aes()
        test_traversal(tmp)
        test_github()
        test_unpack_naming()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if check.failed:
        print("  SOME CHECKS FAILED")
        return 1
    print("  all unit checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
