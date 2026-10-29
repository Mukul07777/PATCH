"""Rescue mode: take an existing (usually red) Dependabot/Renovate PR, fix the code it breaks, push onto its branch."""
import base64
import re
import subprocess

import httpx

from patchpilot.core import config
from patchpilot.agent.common import PIN
from patchpilot.agent.github_pr import _auth_header, _git, _scrub

PR_URL = re.compile(r"https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/pull/(\d{1,7})/?")


def parse_pr(url):
    m = PR_URL.fullmatch((url or "").strip())
    if not m:
        raise ValueError(f"Not a GitHub pull request URL: {url!r}")
    return m.group(1), m.group(2), int(m.group(3))


def pins(text):
    out = {}
    for line in (text or "").splitlines():
        m = PIN.match(line.split("#")[0])
        if m:
            out[m.group(1)] = m.group(2)
    return out


def bumps(base_text, head_text):
    """Packages whose pin the PR changes: [{package, from, to}]."""
    old = {k.lower(): (k, v) for k, v in pins(base_text).items()}
    rows = []
    for name, ver in pins(head_text).items():
        prev = old.get(name.lower())
        if prev and prev[1] != ver:
            rows.append({"package": name, "from": prev[1], "to": ver})
    return rows


def _api():
    headers = {"Accept": "application/vnd.github+json"}
    if config.github_token():
        headers["Authorization"] = f"Bearer {config.github_token()}"
    return httpx.Client(base_url="https://api.github.com", timeout=30, headers=headers)


def fetch(url):
    """PR metadata plus requirements.txt on its base commit: what the repo ran before the bot's bump."""
    owner, name, number = parse_pr(url)
    with _api() as api:
        r = api.get(f"/repos/{owner}/{name}/pulls/{number}")
        r.raise_for_status()
        pr = r.json()
        c = api.get(f"/repos/{owner}/{name}/contents/requirements.txt", params={"ref": pr["base"]["sha"]})
        if c.status_code == 404:
            raise RuntimeError("PR rescue needs a pinned requirements.txt at the repository root, and this "
                               "pull request's base branch has none")
        c.raise_for_status()
        base_req = base64.b64decode(c.json()["content"]).decode("utf-8", "replace")
    head = pr["head"]["repo"] or {}
    return {"owner": owner, "name": name, "number": number, "title": pr.get("title", ""),
            "author": (pr.get("user") or {}).get("login", ""), "state": pr.get("state"),
            "head_ref": pr["head"]["ref"], "head_clone": head.get("clone_url", ""),
            "same_repo": head.get("full_name", "").lower() == f"{owner}/{name}".lower(),
            "base_requirements": base_req}


def clone(info, work):
    subprocess.run(["git", "clone", "--depth", "1", "--branch", info["head_ref"], info["head_clone"], str(work)],
                   check=True, capture_output=True, text=True)


def push_fix(work, info, report, upgrades):
    """Commit the repair onto the PR's own branch and leave a comment; the PR turns green in place."""
    token = config.github_token()
    owner, name = info["owner"], info["name"]
    try:
        _git(work, "add", "-A")
        _git(work, "-c", "user.name=PatchPilot", "-c", "user.email=patchpilot@users.noreply.github.com",
             "commit", "-m", "fix: make code compatible with " + ", ".join(f"{u['package']} {u['to']}" for u in upgrades))
        _git(work, "-c", f"http.extraheader={_auth_header(token)}",
             "push", f"https://github.com/{owner}/{name}.git", f"HEAD:{info['head_ref']}", token=token)
        with _api() as api:
            r = api.post(f"/repos/{owner}/{name}/issues/{info['number']}/comments",
                         json={"body": "PatchPilot pushed a commit that repairs the code this bump broke.\n\n" + report})
            r.raise_for_status()
        return {"url": f"https://github.com/{owner}/{name}/pull/{info['number']}", "branch": info["head_ref"],
                "rescued": True}
    except Exception as e:
        raise RuntimeError(_scrub(f"{type(e).__name__}: {e}", token)) from None
