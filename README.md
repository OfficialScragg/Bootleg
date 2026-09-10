# Bootleg

Keep your pentest toolkit in one place, then put it on a fresh Linux host with a single paste.

Bootleg is two halves:

- **The server** — a Flask dashboard where you upload tools and track GitHub projects. Everything in a
  toolkit is packed into one AES-256 encrypted archive.
- **The agent** — a standard-library Python script you paste onto a target. It calls home, pulls the
  archive, verifies it, decrypts it, and unpacks the toolkit into your working directory.

Nothing readable crosses the wire, and the agent needs no pip, no venv, and no internet beyond your
own server.

---

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
```

Open <http://127.0.0.1:8000>, set an admin password, and create a toolkit.

Then, before you hand out any keys, set **Settings → Public URL** to an address your targets can
actually reach. That URL is baked into every API key, so `localhost` will produce keys that only work
on the server itself.

To make it reachable from your targets:

```bash
.venv/bin/python run.py --host 0.0.0.0 --port 8000
```

For anything internet-facing, put it behind nginx or Caddy with TLS and run it under gunicorn:

```bash
.venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 --timeout 600 'bootleg.app:create_app()'
```

## Using it

**Add tools.** Drop files onto the dashboard — binaries, scripts, tarballs, wordlists — or point
Bootleg at a GitHub project. Tracked projects are re-checked on a timer (Settings → GitHub tracking);
when a new release lands, Bootleg downloads it and rebuilds the archive on its own. Left to guess,
it picks the Linux x86-64 asset.

For each tool you can set the folder it lands in, whether it is extracted on the target, and whether
it is included in the archive at all.

**Download.** *Download zip* on the Tools tab gives you the whole toolkit as a plain zip, and each row
has its own download button for a single tool. These are for use right here rather than on a target,
so they are served unencrypted over your authenticated session.

**Deploy.** Open the toolkit's **Deploy** tab and hit *Copy one-line command*. Paste it into a shell
on the target:

```
echo <base64> | base64 -d > bootleg_deploy.py && python3 bootleg_deploy.py
```

The toolkit lands in `./<toolkit-slug>`. Useful flags:

```
python3 bootleg_deploy.py -d /opt/kit   # deploy somewhere else
python3 bootleg_deploy.py --list        # show contents, download nothing
python3 bootleg_deploy.py --setup       # run the toolkit's setup.sh afterwards
python3 bootleg_deploy.py --force       # redeploy an unchanged archive
python3 bootleg_deploy.py --insecure    # self-signed TLS on the server
```

Re-running is cheap: the agent compares the archive revision it already has and exits early when
nothing changed.

## How the API key works

The key is a compressed, checksummed envelope:

```
BL1<base64url( zlib({"u": server url, "t": toolkit, "k": token, "p": secret}) + checksum )>
```

The agent decodes it locally and uses each part: `u` to know where to call, `t` to say which toolkit
it wants, `k` to authenticate, `p` to derive the archive password. The encoding is transparent by
design — decode one yourself and you will see its contents. The secrecy is in the random values.

**Every deploy script gets its own key.** Copying a script or downloading the `.py` mints a new one.
Only its hash is stored, so the server can verify a key but a database read yields nothing anyone
could deploy with — and the key is never shown again after you copy it.

**A key locks to the first host that deploys with it.** That host can re-run the script as often as
it likes, to redeploy or to pick up a new revision. The same key lifted onto a different machine is
refused, and the refusal is logged with both addresses. The Deploy tab shows every key, where it is
locked, and how many times it has been used, with:

- **Unlock** — release the pin, for a target whose address changed.
- **Revoke** — kill the key outright.
- **Tidy up** — delete revoked keys and ones that were issued but never used.

**Re-key a toolkit** from its Settings tab. It generates a new archive secret, re-encrypts the
archive, and revokes every key ever issued for that toolkit.

> The host lock depends on Bootleg seeing the true client address, so `X-Forwarded-For` is
> **ignored by default**. If you run behind nginx or Caddy, turn on *Settings → Network → behind a
> reverse proxy*; if you do not, leave it off, or anyone could forge the header and walk through
> the lock.

## How the archive is protected

Each toolkit is packed into a deflate zip and sealed into a `.blz`:

```
0   magic    8   BOOTLEG\x01
8   iters    4   PBKDF2 iteration count
12  mac     32   HMAC-SHA256 over the header and body
44  body    ..   "Salted__" + salt(8) + AES-256-CTR ciphertext
```

- **AES-256-CTR**, key derived with PBKDF2-HMAC-SHA256 at 600,000 iterations.
- **Encrypt-then-MAC.** A tampered or truncated archive is rejected before a single byte is decrypted.
- The body is byte-for-byte an `openssl enc -aes-256-ctr -pbkdf2` file. That is deliberate: the agent
  hands decryption to the host's own openssl and moves at native speed on large toolkits. When openssl
  is missing, it falls back to an AES-256 implementation built into the script — slower, but it means
  a stripped container with nothing but `python3` still works.

Both paths are tested against each other and against the FIPS-197 vectors.

## Security notes

- One admin account, password-hashed, with lockout after 8 failed attempts from an address.
- Deploy keys are per-script, host-locked, revocable, and stored only as hashes.
- CSRF tokens on every state-changing request; session cookies are `HttpOnly` and `SameSite=Lax`.
  Set `BOOTLEG_SECURE_COOKIE=1` when serving over HTTPS.
- Toolkit tokens are stored in plaintext in the database, because the server must derive archive
  passwords from them. Treat `data/` as secret material.
- The agent refuses archives containing paths that escape the target directory, and re-applies unix
  permissions that `zipfile` would otherwise drop — your binaries arrive executable.
- A key that has not been used yet is bearer credential: whoever runs it first claims it and gets the
  toolkit. Once it has deployed, it is tied to that host.
- Anyone holding a key can decrypt an archive they already have, since `p` derives the password.
  Re-key the toolkit to invalidate that.

## Configuration

All optional; every one has a working default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BOOTLEG_DATA_DIR` | `./data` | Database, blobs and built archives |
| `BOOTLEG_HOST` / `BOOTLEG_PORT` | `127.0.0.1` / `8000` | Bind address |
| `BOOTLEG_PUBLIC_URL` | bind address | Seeds the public URL on first run |
| `BOOTLEG_MAX_UPLOAD_MB` | `4096` | Upload size limit |
| `BOOTLEG_SECURE_COOKIE` | off | Mark the session cookie `Secure` |
| `BOOTLEG_SESSION_HOURS` | `12` | Admin session lifetime |
| `BOOTLEG_CHECK_MINUTES` | `60` | Default GitHub polling interval |

Reverse-proxy trust is a dashboard setting rather than an environment variable, because getting it
wrong weakens the host lock — see *Settings → Network*.

## Layout

```
bootleg/                 the server
  app.py                 routes: dashboard, admin API, deploy API
  store.py               toolkit and tool operations
  archive.py             packs a toolkit into a zip
  envelope.py            seals the zip with AES-256
  apikey.py              key encode/decode, password derivation
  github.py              release tracking and asset selection
client/bootleg_deploy.py the agent; the dashboard injects the key into it
tests/                   run them directly, no pytest needed
```

## Tests

```bash
.venv/bin/python tests/test_units.py   # keys, crypto, path traversal, asset picking
.venv/bin/python tests/test_e2e.py     # builds a toolkit, then really deploys it
```

The end-to-end test starts a server, creates a toolkit through the API, and runs the actual agent
against it — including exec bits, nested unpacking, revision skipping, host locking (a second host is
refused, a forged `X-Forwarded-For` does not help it, unlocking works), downloads, and re-keying.
