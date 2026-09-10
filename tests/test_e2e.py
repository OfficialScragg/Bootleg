"""End-to-end: build a toolkit through the dashboard API, then deploy it with
the real agent script against a real server."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bootleg.app import create_app  # noqa: E402
from bootleg.config import Config  # noqa: E402

PASSWORD = "a-very-good-password"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Harness:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.port = free_port()

        class Cfg(Config):
            DATA_DIR = self.tmp / "data"
            DATABASE = self.tmp / "data" / "bootleg.db"
            UPLOAD_TMP = self.tmp / "data" / "tmp"
            DEFAULT_PUBLIC_URL = "http://127.0.0.1:{0}".format(self.port)
            DEFAULT_CHECK_INTERVAL = 0        # no background sweeps during tests

        self.app = create_app(Cfg)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.csrf = None

    def start_server(self):
        from werkzeug.serving import make_server
        self.server = make_server("127.0.0.1", self.port, self.app, threaded=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.port), 0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not come up")

    def stop_server(self):
        self.server.shutdown()

    def sign_in(self):
        self.client.post("/setup", data={"password": PASSWORD, "confirm": PASSWORD})
        with self.client.session_transaction() as sess:
            self.csrf = sess["csrf"]

    def post(self, path, payload=None, **kwargs):
        if payload is not None:
            kwargs["json"] = payload
        return self.client.post(path, headers={"X-CSRF-Token": self.csrf}, **kwargs)


def check(label, condition, detail=""):
    mark = "  ok  " if condition else "  FAIL"
    print("{0} {1}{2}".format(mark, label, "" if condition else "  <- " + str(detail)))
    if not condition:
        check.failed = True


check.failed = False


def main():
    tmp = tempfile.mkdtemp(prefix="bootleg-e2e-")
    try:
        run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if check.failed:
        print("  SOME CHECKS FAILED")
        return 1
    print("  all end-to-end checks passed")
    return 0


def run(tmp):
    tmp = Path(tmp)
    h = Harness(tmp)

    print("\n-- dashboard --")
    resp = h.client.get("/")
    check("unauthenticated request redirects to setup", resp.status_code == 302)
    h.sign_in()
    check("signed in after first-run setup", h.client.get("/").status_code == 200)

    resp = h.post("/api/toolkits", {"name": "Internal Engagement",
                                    "description": "Standard internal kit"})
    slug = resp.get_json()["toolkit"]["slug"]
    check("toolkit created", slug == "internal-engagement", slug)

    # A tool that must land executable, and a tarball flagged for unpacking.
    payload = tmp / "recon.sh"
    payload.write_text("#!/bin/sh\necho recon\n")
    nested = tmp / "nested"
    (nested / "wordlists").mkdir(parents=True)
    (nested / "wordlists" / "common.txt").write_text("admin\nroot\n")
    tarball = tmp / "lists.tar.gz"
    subprocess.run(["tar", "-czf", str(tarball), "-C", str(nested), "wordlists"], check=True)

    # A zip with a dotted version in its name and several roots -- pins both the
    # "truncated at the first dot" bug and the dropped-exec-bit bug.
    flat = tmp / "flat"
    flat.mkdir()
    (flat / "scanner").write_text("#!/bin/sh\necho scan\n")
    (flat / "scanner").chmod(0o755)
    (flat / "README.md").write_text("docs\n")
    dotted = tmp / "scanner_1.2.3_linux_amd64.zip"
    subprocess.run(["zip", "-q", "-r", str(dotted), "scanner", "README.md"],
                   cwd=flat, check=True)

    with open(payload, "rb") as fh:
        resp = h.post("/api/toolkits/{0}/tools/upload".format(slug), None,
                      data={"file": (fh, "recon.sh"), "install_dir": "bin"},
                      content_type="multipart/form-data")
    check("uploaded a script", resp.status_code == 200, resp.get_data(as_text=True)[:200])

    with open(tarball, "rb") as fh:
        resp = h.post("/api/toolkits/{0}/tools/upload".format(slug), None,
                      data={"file": (fh, "lists.tar.gz"), "unpack": "1"},
                      content_type="multipart/form-data")
    check("uploaded a tarball marked for unpacking", resp.status_code == 200)

    with open(dotted, "rb") as fh:
        resp = h.post("/api/toolkits/{0}/tools/upload".format(slug), None,
                      data={"file": (fh, dotted.name), "install_dir": "bin", "unpack": "1"},
                      content_type="multipart/form-data")
    check("uploaded a dotted-name zip", resp.status_code == 200)

    h.post("/api/toolkits/{0}".format(slug),
           {"setup_script": "echo 'setup ran' > setup-was-here.txt"})

    resp = h.post("/api/toolkits/{0}/rebuild".format(slug))
    stats = resp.get_json()["stats"]
    check("archive built", stats["tool_count"] == 3, stats)
    check("archive is not readable as a plain zip",
          not Path(stats["path"]).read_bytes().startswith(b"PK"))

    resp = h.client.get("/api/toolkits/{0}/script".format(slug))
    check("the preview mints nothing", "%%BOOTLEG_KEY%%" not in resp.get_json()["script"])
    check("no keys exist until one is asked for",
          h.client.get("/api/toolkits/{0}/keys".format(slug)).get_json()["keys"] == [])

    body = h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()
    script, key = body["script"], body["key"]
    check("key is embedded in the issued script", key in script and "%%BOOTLEG_KEY%%" not in script)
    second = h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()
    check("each issue mints a different key", second["key"] != key)

    print("\n-- api auth --")
    check("manifest without a key is rejected",
          h.client.get("/api/v1/manifest").status_code == 401)
    check("manifest with a junk key is rejected",
          h.client.get("/api/v1/manifest", headers={"X-Bootleg-Key": "BL1nonsense"}).status_code == 401)
    forged = key[:-6] + ("aaaaaa" if not key.endswith("aaaaaa") else "bbbbbb")
    check("manifest with a tampered key is rejected",
          h.client.get("/api/v1/manifest", headers={"X-Bootleg-Key": forged}).status_code in (401, 403))
    check("manifest with the real key works",
          h.client.get("/api/v1/manifest", headers={"X-Bootleg-Key": key}).status_code == 200)
    check("csrf is enforced on state changes",
          h.client.post("/api/toolkits", json={"name": "no csrf"}).status_code == 403)

    print("\n-- host-locked keys --")
    fresh = h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()["key"]
    hdr = {"X-Bootleg-Key": fresh}
    check("an unused key reads the manifest",
          h.client.get("/api/v1/manifest", headers=hdr).status_code == 200)
    check("first deploy works",
          h.client.get("/api/v1/archive", headers=hdr).status_code == 200)
    check("the same host may deploy again",
          h.client.get("/api/v1/archive", headers=hdr).status_code == 200)
    check("re-use is counted",
          [k for k in h.client.get("/api/toolkits/{0}/keys".format(slug)).get_json()["keys"]
           if k["bound_ip"]][0]["use_count"] == 2)

    elsewhere = {"X-Bootleg-Key": fresh, "REMOTE_ADDR": "203.0.113.77"}
    other = h.client.get("/api/v1/archive", headers={"X-Bootleg-Key": fresh},
                         environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    check("another host cannot use the same key", other.status_code == 403, other.status_code)
    check("the refusal names both addresses",
          "203.0.113.77" in other.get_json()["error"], other.get_json())
    check("another host cannot even read the manifest",
          h.client.get("/api/v1/manifest", headers={"X-Bootleg-Key": fresh},
                       environ_overrides={"REMOTE_ADDR": "203.0.113.77"}).status_code == 403)
    del elsewhere

    # The pin is only meaningful if the address cannot be forged.
    spoof = h.client.get("/api/v1/archive",
                         headers={"X-Bootleg-Key": fresh, "X-Forwarded-For": "127.0.0.1"},
                         environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    check("a forged X-Forwarded-For does not defeat the lock", spoof.status_code == 403,
          spoof.status_code)

    h.post("/api/settings", {"trust_proxy": True})
    proxied = h.client.get("/api/v1/archive",
                           headers={"X-Bootleg-Key": fresh, "X-Forwarded-For": "127.0.0.1"},
                           environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    check("behind a trusted proxy the forwarded address is used", proxied.status_code == 200,
          proxied.status_code)
    h.post("/api/settings", {"trust_proxy": False})

    bound = [k for k in h.client.get("/api/toolkits/{0}/keys".format(slug)).get_json()["keys"]
             if k["bound_ip"]][0]
    h.post("/api/keys/{0}/unbind".format(bound["id"]))
    moved = h.client.get("/api/v1/archive", headers={"X-Bootleg-Key": fresh},
                         environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    check("unlocking lets a key move host", moved.status_code == 200, moved.status_code)
    check("it then locks to the new host",
          h.client.get("/api/v1/archive", headers={"X-Bootleg-Key": fresh}).status_code == 403)

    revocable = h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()
    h.post("/api/keys/{0}/revoke".format(revocable["id"]))
    revoked = h.client.get("/api/v1/archive", headers={"X-Bootleg-Key": revocable["key"]})
    check("a revoked key is refused", revoked.status_code == 403, revoked.status_code)

    keys = h.client.get("/api/toolkits/{0}/keys".format(slug)).get_json()["keys"]
    check("the dashboard records where a key is locked",
          any(k["bound_ip"] == "203.0.113.77" for k in keys), keys)

    print("\n-- downloads --")
    resp = h.client.get("/toolkit/{0}/download.zip".format(slug))
    check("toolkit downloads as a zip", resp.status_code == 200
          and resp.data.startswith(b"PK"), resp.status_code)
    import io as _io
    with zipfile.ZipFile(_io.BytesIO(resp.data)) as zf:
        names = zf.namelist()
    check("the zip holds the tools and manifest",
          "bin/recon.sh" in names and "MANIFEST.json" in names, names)

    tool_id = h.client.get("/api/toolkits/{0}/keys".format(slug)) and None
    tools_now = h.app.test_client()
    del tools_now
    first_tool = None
    with h.app.app_context():
        from bootleg.db import connect as _connect
        c = _connect(h.app.config["DATABASE"])
        first_tool = c.execute(
            "SELECT id FROM tools WHERE name = 'recon.sh'").fetchone()["id"]
        c.close()
    resp = h.client.get("/toolkit/{0}/tool/{1}/download".format(slug, first_tool))
    check("a single tool downloads on its own",
          resp.status_code == 200 and resp.data == b"#!/bin/sh\necho recon\n", resp.status_code)
    check("downloads require a session",
          h.app.test_client().get("/toolkit/{0}/download.zip".format(slug)).status_code == 302)

    print("\n-- deploy agent --")
    h.start_server()
    try:
        script_path = tmp / "bootleg_deploy.py"

        def fresh_script():
            """Each deploy needs its own key -- that is the point."""
            return h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()["script"]

        script_path.write_text(fresh_script())
        workdir = tmp / "target"
        workdir.mkdir()

        listing = subprocess.run([sys.executable, str(script_path), "--list"],
                                 cwd=workdir, capture_output=True, text=True)
        check("--list works without downloading", listing.returncode == 0, listing.stderr[-400:])
        check("--list names the tools", "recon.sh" in listing.stderr, listing.stderr)
        check("--list leaves nothing behind", not list(workdir.iterdir()))

        run1 = subprocess.run([sys.executable, str(script_path), "--setup"],
                              cwd=workdir, capture_output=True, text=True)
        check("deploy succeeded", run1.returncode == 0, run1.stderr[-600:])

        deployed = workdir / slug
        recon = deployed / "bin" / "recon.sh"
        check("file landed at its configured path", recon.is_file())
        check("file kept its executable bit", recon.exists() and os.access(recon, os.X_OK))
        check("file contents survived the round trip",
              recon.is_file() and recon.read_text() == "#!/bin/sh\necho recon\n")
        check("tarball was unpacked on the target",
              (deployed / "wordlists" / "common.txt").is_file())
        unzipped = deployed / "bin" / "scanner_1.2.3_linux_amd64"
        check("unpack directory keeps the full dotted name", unzipped.is_dir(),
              sorted(p.name for p in (deployed / "bin").iterdir()))
        check("nested archive kept its executable bit",
              (unzipped / "scanner").is_file() and os.access(unzipped / "scanner", os.X_OK))
        check("unpacked archives were cleaned up",
              not (deployed / "lists.tar.gz").exists()
              and not (deployed / "bin" / dotted.name).exists())
        check("setup.sh ran", (deployed / "setup-was-here.txt").is_file())
        check("no scratch files left behind",
              not [p for p in deployed.iterdir() if p.name.startswith(".bootleg-")])
        state = json.loads((deployed / ".bootleg.json").read_text())
        check("deploy state was recorded", state["revision"] == stats["revision"], state)

        run2 = subprocess.run([sys.executable, str(script_path)],
                              cwd=workdir, capture_output=True, text=True)
        check("re-running skips an unchanged archive", "up to date" in run2.stderr.lower(), run2.stderr)

        run3 = subprocess.run([sys.executable, str(script_path), "--force"],
                              cwd=workdir, capture_output=True, text=True)
        check("the same script redeploys on its own host",
              run3.returncode == 0 and "Deployed" in run3.stderr, run3.stderr[-300:])

        # Re-keying must revoke keys issued before it, even unused ones.
        unused = h.post("/api/toolkits/{0}/issue-key".format(slug)).get_json()["script"]
        script_path.write_text(unused)
        h.post("/api/toolkits/{0}/rotate".format(slug))
        run4 = subprocess.run([sys.executable, str(script_path), "--force"],
                              cwd=workdir, capture_output=True, text=True)
        check("re-keying revokes outstanding keys", run4.returncode != 0, run4.stderr[-300:])
        check("revocation is explained clearly",
              "revoked" in run4.stderr.lower(), run4.stderr[-300:])

        script_path.write_text(fresh_script())
        run5 = subprocess.run([sys.executable, str(script_path), "--force"],
                              cwd=workdir, capture_output=True, text=True)
        check("freshly issued script works", run5.returncode == 0, run5.stderr[-400:])
    finally:
        h.stop_server()


if __name__ == "__main__":
    sys.exit(main())
