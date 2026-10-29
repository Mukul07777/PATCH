"""Push the patched branch and open a pull request via the GitHub REST API."""
import base64
import re
import subprocess

import httpx

from patchpilot.core import config

REPO_URL = re.compile(r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def parse_repo(url):
    m = REPO_URL.match((url or "").strip())
    if not m:
        raise ValueError(f"Not a GitHub repository URL: {url!r}")
    return m.group(1), m.group(2)


def _scrub(text, token):
    if not token:
        return text
    for s in (token, base64.b64encode(f"x-access-token:{token}".encode()).decode()):
        text = text.replace(s, "***")
    return text


def _git(cwd, *args, token=""):
    try:
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        msg = _scrub(f"git {args[-2:]} failed ({e.returncode}): {e.stderr or ''}", token)
        raise RuntimeError(msg) from None


def _auth_header(token):
    return "AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()


def open_pull_request(work, repo_url, run_id, plan, body):
    owner, name = parse_repo(repo_url)
    token = config.github_token()
    branch = f"patchpilot/{run_id}"
    try:
        with httpx.Client(base_url="https://api.github.com", timeout=30, headers={
                "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}) as api:
            base = api.get(f"/repos/{owner}/{name}").json().get("default_branch", "main")
            _git(work, "checkout", "-b", branch)
            _git(work, "add", "-A")
            _git(work, "-c", "user.name=PatchPilot", "-c", "user.email=patchpilot@users.noreply.github.com",
                 "commit", "-m", "security: " + ", ".join(f"{u['package']} {u['to']}" for u in plan["upgrades"]))
            _git(work, "-c", f"http.extraheader={_auth_header(token)}",
                 "push", f"https://github.com/{owner}/{name}.git", branch, token=token)
            r = api.post(f"/repos/{owner}/{name}/pulls", json={
                "title": "PatchPilot: security upgrade " + ", ".join(u["package"] for u in plan["upgrades"]),
                "head": branch, "base": base, "body": body})
            r.raise_for_status()
            return {"url": r.json()["html_url"], "branch": branch}
    except Exception as e:
        raise RuntimeError(_scrub(f"{type(e).__name__}: {e}", token)) from None
