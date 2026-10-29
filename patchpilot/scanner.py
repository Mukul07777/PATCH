"""Scan-only mode: read a project's dependency manifests, look every pinned package up on OSV.dev, enrich with
EPSS / CISA KEV / PyPI, and store the findings. No LLM, no API key, and no repository code is ever executed:
manifests are fetched as plain text (GitHub raw files) and parsed, never installed or imported."""
import logging
import os
import re
import threading
from pathlib import Path
from urllib.parse import quote

import httpx

from . import config, db, manifests, sources

log = logging.getLogger(__name__)
GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?")
MAX_DEPS = 50_000  # sanity bound per scan; anything beyond it is reported, never dropped silently
MAX_ACTIVE_SCANS = 4  # scans running at once; more wait in the queue (scans.status = 'queued')


class ScanError(RuntimeError):
    pass


class GitHubError(ScanError):
    """A GitHub lookup failed in a way the user can act on; `status` is the HTTP code the API should answer."""
    def __init__(self, msg, status=422):
        super().__init__(msg)
        self.status = status


# ---------- GitHub ----------
def _gh_client():
    token = config.github_token()
    headers = {"User-Agent": "patchpilot/0.1", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(timeout=20, headers=headers, follow_redirects=True)


def _gh_fail(r, not_found):
    if r.status_code in (403, 429) and (r.headers.get("x-ratelimit-remaining") == "0" or "rate limit" in r.text.lower()):
        hint = "" if config.github_token() else " (60 requests/hour without a token: add a GitHub token in Settings)"
        raise GitHubError(f"GitHub API rate limit reached{hint}. Try again later.", 429)
    if r.status_code == 401:
        raise GitHubError("GitHub rejected the configured token (HTTP 401). Check it in Settings.")
    if r.status_code in (404, 422):
        raise GitHubError(not_found)
    raise GitHubError(f"GitHub returned HTTP {r.status_code}", 502)


def _gh_get(gh, url, params=None, immutable=False):
    """GET a GitHub API URL through the response cache. immutable=True (a tree by commit sha) is served from the
    cache without a request; otherwise a cached ETag is sent as If-None-Match and a 304 (which GitHub does not
    count against the rate limit) is answered from the cache."""
    key = url + ("?" + "&".join(f"{k}={v}" for k, v in sorted(params.items())) if params else "")
    hit = None
    if not config.NO_DB:
        try:
            hit = db.gh_cache_get(key)
        except Exception:
            log.debug("GitHub cache unavailable", exc_info=True)
    if hit and immutable:
        return httpx.Response(200, content=hit["body"].encode(), headers={"content-type": "application/json"})
    headers = {"If-None-Match": hit["etag"]} if hit and hit["etag"] else {}
    r = gh.get(url, params=params, headers=headers)
    if r.status_code == 304 and hit:
        return httpx.Response(200, content=hit["body"].encode(), headers={"content-type": "application/json"})
    if r.status_code == 200 and not config.NO_DB and (immutable or r.headers.get("etag")):
        try:
            db.gh_cache_put(key, r.headers.get("etag"), r.text)
        except Exception:
            log.debug("could not cache %s", key, exc_info=True)
    return r


def parse_github(url):
    m = GITHUB.fullmatch(url or "")
    if not m:
        raise ScanError("Only https://github.com/owner/repo URLs can be scanned")
    return m.groups()


def check_github(url, ref=None, gh=None):
    """Resolve a repository + ref through the GitHub API: {owner, repo, ref, sha}. Raises GitHubError with a
    message the user can act on (missing / private repo, unknown branch or tag, rate limit)."""
    owner, repo = parse_github(url)
    own = gh is None
    gh = gh or _gh_client()
    try:
        r = _gh_get(gh, f"https://api.github.com/repos/{owner}/{repo}")
        if r.status_code != 200:
            _gh_fail(r, "Repository not found or private (add a GitHub token in Settings)")
        ref = ref or r.json().get("default_branch") or "HEAD"
        c = _gh_get(gh, f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref, safe='/')}",
                    immutable=bool(re.fullmatch(r"[0-9a-f]{40}", ref)))
        if c.status_code != 200:
            _gh_fail(c, f"Branch or tag '{ref}' not found")
        return {"owner": owner, "repo": repo, "ref": ref, "sha": c.json()["sha"]}
    except httpx.HTTPError as e:
        raise GitHubError(f"Could not reach GitHub ({type(e).__name__})", 502) from None
    finally:
        if own:
            gh.close()


def _fetch_github(url, ref, subdir=""):
    """(files, notes): every manifest in the repository tree (monorepos included, up to 3 folders deep)."""
    notes = []
    with _gh_client() as gh:
        info = check_github(url, ref, gh)
        owner, repo, sha = info["owner"], info["repo"], info["sha"]
        try:
            t = _gh_get(gh, f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}", {"recursive": "1"},
                        immutable=True)  # a tree by commit sha never changes
        except httpx.HTTPError as e:
            raise ScanError(f"Could not reach GitHub ({type(e).__name__})") from None
        if t.status_code != 200:
            _gh_fail(t, "Could not list the repository files")
        data = t.json()
        if data.get("truncated"):
            notes.append("The repository is too large for GitHub to list in full; some manifests may be missed")
        sizes = {e["path"]: e.get("size") or 0 for e in data.get("tree", []) if e.get("type") == "blob"}
        paths, more = manifests.select(sizes, subdir)
        notes += more
        files, skipped = [], []
        raw_headers = {"Authorization": gh.headers["Authorization"]} if "Authorization" in gh.headers else {}
        for path in paths:
            limit = manifests.size_limit(path)
            if sizes[path] > limit:
                skipped.append({"path": path, "reason": f"larger than {limit // 1_000_000} MB"})
                continue
            try:
                r = gh.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{quote(path)}", headers=raw_headers)
            except httpx.HTTPError as e:
                skipped.append({"path": path, "reason": f"download failed ({type(e).__name__})"})
                continue
            if r.status_code != 200:
                skipped.append({"path": path, "reason": f"download failed (HTTP {r.status_code})"})
                continue
            files.append((path, r.text))
    return files, notes, skipped, info


def _read_dir(root, subdir=""):
    """(files, notes, skipped) for a folder on disk: the same file selection as a repository scan."""
    root = Path(root)
    sizes = {}
    for d, dirs, names in os.walk(root):
        rel = Path(d).relative_to(root).as_posix()
        depth = 0 if rel == "." else rel.count("/") + 1
        dirs[:] = [x for x in dirs if depth < manifests.MAX_DEPTH and x.lower() not in manifests.SKIP_DIRS
                   and not x.startswith(".")]
        for n in names:
            path = n if rel == "." else f"{rel}/{n}"
            if manifests.is_manifest_path(path):
                sizes[path] = (Path(d) / n).stat().st_size
    paths, notes = manifests.select(sizes, subdir)
    files, skipped = [], []
    for path in paths:
        limit = manifests.size_limit(path)
        if sizes[path] > limit:
            skipped.append({"path": path, "reason": f"larger than {limit // 1_000_000} MB"})
            continue
        files.append((path, (root / path).read_text(encoding="utf-8", errors="replace")))
    return files, notes, skipped


def fetch_manifests(project):
    """(files, notes, skipped, ref info or None) for a project row (with its stored manifest)."""
    kind, src, subdir = project["source_type"], project["source"], project.get("subdir") or ""
    if kind == "upload":
        return [(src, project.get("manifest") or "")], [], [], None
    if kind == "git":
        return _fetch_github(src, project.get("ref"), subdir)
    if kind == "sample":
        path = config.CASES_DIR / src
        if not (path.is_dir() and path.parent == config.CASES_DIR):
            raise ScanError(f"Sample '{src}' no longer exists")
        return (*_read_dir(path, subdir), None)
    if kind == "path":
        if not config.ALLOW_LOCAL_PATHS:
            raise ScanError("Local path projects are disabled (ALLOW_LOCAL_PATHS=0)")
        if not Path(src).is_dir():
            raise ScanError("Project directory not found")
        return (*_read_dir(src, subdir), None)
    raise ScanError(f"Unknown project type {kind}")


def collect(files):
    """(merged deps, errors, warnings, {(name, version): [files]}, {(name, version): first declaration line})."""
    deps, errors, warnings = [], [], []
    for name, text in files:
        try:
            found, warn = manifests.parse_ex(name, text)
            deps += found
            warnings += warn
        except manifests.ManifestError as e:
            errors.append(str(e))
    where = {}
    lines = {}
    for d in deps:
        where.setdefault((manifests.normalize(d.name), d.version), [])
        if d.source_file not in where[(manifests.normalize(d.name), d.version)]:
            where[(manifests.normalize(d.name), d.version)].append(d.source_file)
            lines.setdefault((manifests.normalize(d.name), d.version), d.line)
    return manifests.merge(deps), errors, warnings, where, lines


def _lowest_fix_above(version, fixed):
    above = [f for f in fixed if not sources.version_gte(version, f)]
    return min(above, key=sources._vkey) if above else None


def coverage(total, pinned, checked, unpinned):
    """How much of the dependency set was actually checked. verified = every dependency had an exact version
    and was looked up; partial = some; unverified = none (a clean result then proves nothing)."""
    state = "unverified" if checked == 0 else "verified" if checked >= total else "partial"
    return {"state": state, "total": total, "pinned": pinned, "checked": checked, "unpinned": len(unpinned)}


def scan_project(project):
    """Run one scan synchronously; returns (findings, summary). Raises ScanError for user-facing failures."""
    return scan_files(*fetch_manifests(project))


MAX_SBOM = 20_000  # dependencies kept in a scan summary for SBOM export


def scan_files(files, notes=(), skipped=(), info=None):
    """Scan already-read manifests [(path, text)]: (findings, summary). Used by the server and the CLI."""
    skipped = list(skipped)
    warnings = list(notes) + [f"{s['path']} skipped: {s['reason']}" for s in skipped]
    if not files:
        if skipped:
            raise ScanError("Every manifest found was skipped: " + "; ".join(warnings))
        raise ScanError("No supported manifest found (requirements*.txt, pyproject.toml, poetry.lock, uv.lock, "
                        "Pipfile.lock, up to 3 folders deep)")
    deps, errors, warn, where, lines = collect(files)
    warnings += warn
    invalid = sum(1 for w in warn if w.endswith(manifests.INVALID_MARK))  # unparsable lines: total, never checked
    pinned = [d for d in deps if d.version]
    if len(pinned) > MAX_DEPS:
        warnings.append(f"{len(pinned)} pinned dependencies; only the first {MAX_DEPS} were checked")
        pinned = pinned[:MAX_DEPS]
    unpinned = sorted({d.name for d in deps if not d.version})

    try:
        results = sources.osv_batch([(d.name, d.version) for d in pinned]) if pinned else {}
        checked = len(pinned)
    except Exception as e:  # OSV down: the scan finishes, but says it verified nothing
        log.warning("OSV batch lookup failed", exc_info=True)
        errors.append(f"OSV lookup failed ({type(e).__name__}); no dependency was checked")
        results, checked = {}, 0
    cves = [v["cve"] for vulns in results.values() for v in vulns if v.get("cve")]
    epss, epss_ok = {}, True
    if cves:
        try:
            epss = sources.epss(cves)
        except Exception:
            log.warning("EPSS lookup failed", exc_info=True)
            epss_ok = False
            warnings.append("EPSS unavailable: exploit probabilities could not be fetched from FIRST.org")
    try:
        kev = sources.kev() if cves else {}
    except Exception:
        log.warning("CISA KEV lookup failed", exc_info=True)
        warnings.append("CISA KEV catalog unavailable: known-exploited flags may be missing")
        kev = {}
    try:
        missing = sorted(sources.pypi_missing([d.name for d in deps]))
    except Exception:
        log.warning("PyPI existence check failed", exc_info=True)
        missing = []
    warnings += [f"{n}: not on PyPI — private package or typo (possible dependency confusion)" for n in missing]

    findings, packages = [], []
    for d in pinned:
        vulns = results.get((d.name, d.version)) or []
        if not vulns:
            continue
        latest = None
        try:
            latest = sources.pypi_latest(d.name)
        except Exception:
            log.info("PyPI lookup failed for %s", d.name)
        source_file = ", ".join(where.get((manifests.normalize(d.name), d.version)) or [d.source_file])
        source_line = lines.get((manifests.normalize(d.name), d.version), d.line)
        packages.append({"package": d.name, "version": d.version, "advisories": len(vulns), "latest": latest,
                         "safe": sources.min_safe_version(d.version, vulns), "source_file": source_file})
        for v in vulns:
            aliases = sorted(set(v.get("aliases") or ([v["cve"]] if v.get("cve") else [])))
            findings.append({
                "package": d.name, "version": d.version, "vuln_id": v["id"], "aliases": aliases,
                "severity": (v.get("severity") or "").upper() or None, "cvss": v.get("cvss"),
                "cvss_score": v.get("cvss_score"),
                "epss": (epss.get(v.get("cve")) or {}).get("epss"), "kev": v.get("cve") in kev,
                "fixed_in": _lowest_fix_above(d.version, v.get("fixed") or []), "summary": (v.get("summary") or "")[:500],
                "reachable": None, "source_file": source_file, "source_line": source_line,
            })
    summary = {"files": [n for n, _ in files], "skipped_files": skipped, "dependencies": len(deps),
               "pinned": len(pinned), "unpinned": unpinned, "vulnerable_packages": packages, "errors": errors,
               "warnings": warnings, "not_on_pypi": missing,
               "coverage": coverage(len(deps) + invalid, len(pinned), checked, unpinned) | ({"invalid": invalid} if invalid else {}),
               "epss": "ok" if epss_ok else "unavailable",
               # every dependency (for SBOM export): [name, version or None, first file, line]
               "deps": [[d.name, d.version, (where.get((manifests.normalize(d.name), d.version)) or [d.source_file])[0],
                         lines.get((manifests.normalize(d.name), d.version), d.line)] for d in deps[:MAX_SBOM]]}
    if info:
        summary["ref"], summary["commit"] = info["ref"], info["sha"]
    return findings, summary


def run_scan(scan_id, project_id):
    """Scan one queued/claimed scan row: fetch -> parse -> OSV -> store; the row always ends as done or error."""
    db.update_scan(scan_id, "running")
    try:
        project = db.get_project(project_id, with_manifest=True)
        if project is None:
            raise ScanError("Project was deleted")
        findings, summary = scan_project(project)
        db.add_findings(scan_id, project_id, findings)
        summary["diff"] = db.track_findings(scan_id, project_id, findings)  # new / fixed since the last scan
        db.update_scan(scan_id, "done", summary)
        ok = True
    except ScanError as e:
        db.update_scan(scan_id, "error", {"error": str(e)})
        ok = False
    except Exception as e:
        log.exception("scan %s crashed", scan_id)
        db.update_scan(scan_id, "error", {"error": f"{type(e).__name__}: {e}"[:300]})
        ok = False
    for hook in AFTER_SCAN:  # notifications, auto-fix: never allowed to break the queue
        try:
            hook(scan_id, project_id, ok)
        except Exception:
            log.exception("after-scan hook %s failed for scan %s", getattr(hook, "__name__", hook), scan_id)


AFTER_SCAN = []  # fn(scan_id, project_id, ok) called after every scan ends (registered by notify / server)


# ---------- queue ----------
# Scans are rows with status 'queued'; up to MAX_ACTIVE_SCANS worker threads claim them oldest first. The queue
# lives in SQLite, so a restart re-queues scans that were running (requeue_interrupted) and nothing is lost.
_active = 0
_qlock = threading.RLock()


def drain():
    """Worker body: run queued scans until none is left. Claiming and retiring happen under the same lock
    that kick() takes, so a scan queued while the last worker is exiting is never stranded."""
    global _active
    while True:
        with _qlock:
            job = db.claim_queued_scan()
            if job is None:
                _active -= 1
                return
        run_scan(*job)


def kick(spawn):
    """Start a worker (via spawn(fn)) if fewer than MAX_ACTIVE_SCANS are running; otherwise the scan waits."""
    global _active
    with _qlock:
        if _active >= MAX_ACTIVE_SCANS:
            return False
        _active += 1
    spawn(drain)
    return True


def active():
    return _active
