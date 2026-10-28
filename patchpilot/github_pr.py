"""Push the patched branch and open a pull request via the GitHub REST API."""
import re
import subprocess

import httpx

from . import config


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def open_pull_request(work, repo_url, run_id, plan, body):
    m = re.match(r"https://github\.com/([^/]+)/([^/.]+)", repo_url)
    owner, name = m.group(1), m.group(2)
    branch = f"patchpilot/{run_id}"
    api = httpx.Client(base_url="https://api.github.com", timeout=30, headers={
        "Authorization": f"Bearer {config.GITHUB_TOKEN}", "Accept": "application/vnd.github+json"})
    base = api.get(f"/repos/{owner}/{name}").json().get("default_branch", "main")
    remote = f"https://x-access-token:{config.GITHUB_TOKEN}@github.com/{owner}/{name}.git"
    _git(work, "checkout", "-b", branch)
    _git(work, "add", "-A")
    _git(work, "-c", "user.name=PatchPilot", "-c", "user.email=patchpilot@users.noreply.github.com",
         "commit", "-m", "security: " + ", ".join(f"{u['package']} {u['to']}" for u in plan["upgrades"]))
    _git(work, "push", remote, branch)
    r = api.post(f"/repos/{owner}/{name}/pulls", json={
        "title": "PatchPilot: security upgrade " + ", ".join(u["package"] for u in plan["upgrades"]),
        "head": branch, "base": base, "body": body})
    r.raise_for_status()
    return {"url": r.json()["html_url"], "branch": branch}
