"""Scan-only mode: read a project's dependency manifests, look every pinned package up on OSV.dev, enrich with
EPSS / CISA KEV / PyPI, and store the findings. No LLM, no API key, and no repository code is ever executed:
manifests are fetched as plain text (GitHub raw files) and parsed, never installed or imported."""
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from . import config, db, manifests, sources

log = logging.getLogger(__name__)
GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?")
MAX_MANIFEST = 200_000
MAX_DEPS = 400  # OSV lookups per scan


class ScanError(RuntimeError):
    pass


def _read_dir(root):
    out = []
    for name in manifests.MANIFEST_FILES:
        p = Path(root) / name
        if p.is_file() and p.stat().st_size <= MAX_MANIFEST:
            out.append((name, p.read_text(encoding="utf-8", errors="replace")))
    return out


def _fetch_github(url, ref):
    m = GITHUB.fullmatch(url)
    if not m:
        raise ScanError("Only https://github.com/owner/repo URLs can be scanned")
    owner, repo = m.groups()
    headers = {"Authorization": f"Bearer {config.GITHUB_TOKEN}"} if config.GITHUB_TOKEN else {}
    out = []
    with httpx.Client(timeout=20, headers={"User-Agent": "patchpilot/0.1", **headers}, follow_redirects=True) as gh:
        for name in manifests.MANIFEST_FILES:
            try:
                r = gh.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref or 'HEAD'}/{name}")
            except httpx.HTTPError as e:
                raise ScanError(f"Could not reach GitHub ({type(e).__name__})") from None
            if r.status_code == 200 and len(r.content) <= MAX_MANIFEST:
                out.append((name, r.text))
            elif r.status_code not in (200, 404):
                raise ScanError(f"GitHub returned HTTP {r.status_code} for {name}")
    return out


def fetch_manifests(project):
    """[(filename, text)] for a project row (with its stored manifest)."""
    kind, src = project["source_type"], project["source"]
    if kind == "upload":
        return [(src, project.get("manifest") or "")]
    if kind == "git":
        return _fetch_github(src, project.get("ref"))
    if kind == "sample":
        path = config.CASES_DIR / src
        if not (path.is_dir() and path.parent == config.CASES_DIR):
            raise ScanError(f"Sample '{src}' no longer exists")
        return _read_dir(path)
    if kind == "path":
        if not config.ALLOW_LOCAL_PATHS:
            raise ScanError("Local path projects are disabled (ALLOW_LOCAL_PATHS=0)")
        if not Path(src).is_dir():
            raise ScanError("Project directory not found")
        return _read_dir(src)
    raise ScanError(f"Unknown project type {kind}")


def collect(files):
    deps, errors = [], []
    for name, text in files:
        try:
            deps += manifests.parse(name, text)
        except manifests.ManifestError as e:
            errors.append(str(e))
    return manifests.merge(deps), errors


def _lowest_fix_above(version, fixed):
    above = [f for f in fixed if not sources.version_gte(version, f)]
    return min(above, key=sources._vkey) if above else None


def scan_project(project):
    """Run one scan synchronously; returns (findings, summary). Raises ScanError for user-facing failures."""
    files = fetch_manifests(project)
    if not files:
        raise ScanError("No supported manifest found (requirements.txt, pyproject.toml, poetry.lock, uv.lock, Pipfile.lock)")
    deps, errors = collect(files)
    pinned = [d for d in deps if d.version][:MAX_DEPS]
    unpinned = sorted({d.name for d in deps if not d.version})

    def lookup(d):
        try:
            return d, sources.osv_vulns(d.name, d.version), None
        except Exception as e:  # one package failing must not sink the whole scan
            log.warning("OSV lookup failed for %s %s", d.name, d.version, exc_info=True)
            return d, [], f"{d.name}: OSV lookup failed ({type(e).__name__})"

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lookup, pinned))
    errors += [e for _, _, e in results if e]
    cves = [v["cve"] for _, vulns, _ in results for v in vulns if v.get("cve")]
    try:
        epss = sources.epss(cves) if cves else {}
    except Exception:
        log.warning("EPSS lookup failed", exc_info=True)
        epss = {}
    try:
        kev = sources.kev() if cves else {}
    except Exception:
        log.warning("CISA KEV lookup failed", exc_info=True)
        kev = {}

    findings, packages = [], []
    for d, vulns, _ in results:
        if not vulns:
            continue
        latest = None
        try:
            latest = sources.pypi_latest(d.name)
        except Exception:
            log.info("PyPI lookup failed for %s", d.name)
        packages.append({"package": d.name, "version": d.version, "advisories": len(vulns), "latest": latest,
                         "safe": sources.min_safe_version(d.version, vulns)})
        for v in vulns:
            aliases = sorted(set(v.get("aliases") or ([v["cve"]] if v.get("cve") else [])))
            findings.append({
                "package": d.name, "version": d.version, "vuln_id": v["id"], "aliases": aliases,
                "severity": (v.get("severity") or "").upper() or None, "cvss": v.get("cvss"),
                "epss": (epss.get(v.get("cve")) or {}).get("epss"), "kev": v.get("cve") in kev,
                "fixed_in": _lowest_fix_above(d.version, v.get("fixed") or []), "summary": (v.get("summary") or "")[:500],
                "reachable": None,
            })
    summary = {"files": [n for n, _ in files], "dependencies": len(deps), "pinned": len(pinned),
               "unpinned": unpinned, "vulnerable_packages": packages, "errors": errors}
    return findings, summary


def run_scan(scan_id, project_id):
    """Thread target: fetch -> parse -> OSV -> store; the scan row always ends as done or error."""
    db.update_scan(scan_id, "running")
    try:
        project = db.get_project(project_id, with_manifest=True)
        if project is None:
            raise ScanError("Project was deleted")
        findings, summary = scan_project(project)
        db.add_findings(scan_id, project_id, findings)
        db.update_scan(scan_id, "done", summary)
    except ScanError as e:
        db.update_scan(scan_id, "error", {"error": str(e)})
    except Exception as e:
        log.exception("scan %s crashed", scan_id)
        db.update_scan(scan_id, "error", {"error": f"{type(e).__name__}: {e}"[:300]})
