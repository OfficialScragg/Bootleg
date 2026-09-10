"""Track GitHub projects and pull their latest release asset."""

from __future__ import annotations

import fnmatch
import re
import tempfile
from pathlib import Path

import requests

API = "https://api.github.com"
TIMEOUT = 30
_REPO_RE = re.compile(r"^(?:https?://(?:www\.)?github\.com/)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")

# Without an explicit pattern, prefer what a pentester on a Linux box wants.
_PREFERRED = ("*linux*x86_64*", "*linux*amd64*", "*linux*x64*", "*linux*64*", "*linux*",
              "*x86_64*", "*amd64*", "*.tar.gz", "*.tgz", "*.zip")
# Guessing should not hand a Linux operator an ARM or 32-bit build.
_WRONG_ARCH = ("*arm*", "*aarch64*", "*riscv*", "*ppc*", "*s390*", "*mips*",
               "*i386*", "*686*", "*armv*")
_IGNORED = ("*.sha256", "*.sha256sum", "*.sig", "*.asc", "*.pem", "*checksums*", "*.sbom*")


class GitHubError(Exception):
    """Anything that stops us resolving or fetching a release."""


def parse_repo(text: str) -> str:
    """Normalise 'owner/name', a clone URL or a project URL to 'owner/name'."""
    match = _REPO_RE.match((text or "").strip())
    if not match:
        raise GitHubError("Expected 'owner/repo' or a github.com project URL.")
    return "{0}/{1}".format(match.group(1), match.group(2))


def _headers(token: str | None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "bootleg/1.0"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _get(url: str, token: str | None, **kwargs):
    try:
        resp = requests.get(url, headers=_headers(token), timeout=TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise GitHubError("Cannot reach GitHub: {0}".format(exc)) from exc
    if resp.status_code == 404:
        raise GitHubError("Not found on GitHub (private repo, or no releases yet).")
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise GitHubError("GitHub rate limit hit. Add a personal access token in Settings.")
    if not resp.ok:
        raise GitHubError("GitHub returned HTTP {0}".format(resp.status_code))
    return resp


def pick_asset(assets: list[dict], pattern: str = "") -> dict | None:
    """Choose which release asset to archive."""
    usable = [a for a in assets
              if not any(fnmatch.fnmatch(a["name"].lower(), p) for p in _IGNORED)]
    if not usable:
        return None
    if pattern:
        matches = [a for a in usable if fnmatch.fnmatch(a["name"].lower(), pattern.lower())]
        return matches[0] if matches else None
    # Two sweeps: x86-64-friendly candidates first, then anything at all, so a
    # repo that only ships ARM builds still resolves.
    native = [a for a in usable
              if not any(fnmatch.fnmatch(a["name"].lower(), p) for p in _WRONG_ARCH)]
    for pool in (native, usable):
        for preference in _PREFERRED:
            for asset in pool:
                if fnmatch.fnmatch(asset["name"].lower(), preference):
                    return asset
    return usable[0]


def latest_release(repo: str, token: str | None = None, prerelease: bool = False) -> dict:
    """Resolve the newest release for a repo."""
    if prerelease:
        releases = _get("{0}/repos/{1}/releases?per_page=20".format(API, repo), token).json()
        releases = [r for r in releases if not r.get("draft")]
        if not releases:
            raise GitHubError("This repo has no published releases.")
        return releases[0]
    return _get("{0}/repos/{1}/releases/latest".format(API, repo), token).json()


def default_branch(repo: str, token: str | None = None) -> str:
    return _get("{0}/repos/{1}".format(API, repo), token).json().get("default_branch", "main")


def resolve(repo: str, token: str | None = None, pattern: str = "",
            prerelease: bool = False, source: str = "release") -> dict:
    """Work out what the current version is and where to download it.

    Returns ``{"version", "filename", "url", "size", "published_at", "notes"}``.
    """
    if source == "source":
        try:
            release = latest_release(repo, token, prerelease)
            version = release.get("tag_name") or release.get("name") or "latest"
            notes = "source archive for {0}".format(version)
        except GitHubError:
            version = default_branch(repo, token)
            release = {}
            notes = "source archive from branch {0}".format(version)
        name = repo.split("/")[1]
        return {
            "version": version,
            "filename": "{0}-{1}.tar.gz".format(name, version.lstrip("v")),
            "url": "https://codeload.github.com/{0}/tar.gz/{1}".format(repo, version),
            "size": 0,
            "published_at": release.get("published_at", ""),
            "notes": notes,
        }

    release = latest_release(repo, token, prerelease)
    version = release.get("tag_name") or release.get("name") or "latest"
    asset = pick_asset(release.get("assets") or [], pattern)
    if asset is None:
        if pattern:
            available = ", ".join(a["name"] for a in (release.get("assets") or [])[:8]) or "none"
            raise GitHubError("No asset in {0} matches '{1}'. Available: {2}".format(
                version, pattern, available))
        raise GitHubError(
            "Release {0} publishes no binary assets. Switch this tool to "
            "'Source archive' to track the source tarball instead.".format(version))
    return {
        "version": version,
        "filename": asset["name"],
        "url": asset["browser_download_url"],
        "size": asset.get("size", 0),
        "published_at": release.get("published_at", ""),
        "notes": "asset {0} from {1}".format(asset["name"], version),
    }


def download(url: str, dest_dir: Path, token: str | None = None) -> Path:
    """Stream a release asset to a temp file inside ``dest_dir``."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    headers = _headers(token)
    headers["Accept"] = "application/octet-stream"
    try:
        with requests.get(url, headers=headers, timeout=TIMEOUT,
                          stream=True, allow_redirects=True) as resp:
            if not resp.ok:
                raise GitHubError("Download failed: HTTP {0}".format(resp.status_code))
            fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".gh-")
            with open(fd, "wb") as out:
                for chunk in resp.iter_content(1 << 20):
                    out.write(chunk)
    except requests.RequestException as exc:
        raise GitHubError("Download failed: {0}".format(exc)) from exc
    return Path(tmp)
