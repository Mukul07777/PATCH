"""Real-world data sources: OSV.dev advisories, PyPI releases, Tavily web research."""
import logging
import re
import httpx

from . import config
from .reach import parse_imports

log = logging.getLogger(__name__)

_http = httpx.Client(timeout=30, headers={"User-Agent": "patchpilot/0.1"})


def osv_vulns(package, version):
    r = _http.post("https://api.osv.dev/v1/query",
                   json={"package": {"name": package, "ecosystem": "PyPI"}, "version": version})
    r.raise_for_status()
    out, seen = [], set()
    # GHSA records come first so the richer summary wins when PYSEC duplicates the same CVE
    vulns = sorted(r.json().get("vulns", []), key=lambda v: not v["id"].startswith("GHSA"))
    for v in vulns:
        fixed, symbols = [], []
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() != package.lower():
                continue
            symbols += parse_imports((aff.get("ecosystem_specific") or {}).get("imports"))
            for rng in aff.get("ranges", []):
                fixed += [e["fixed"] for e in rng.get("events", [])
                          if "fixed" in e and re.match(r"^\d+(\.\d+)*$", e["fixed"])]
        aliases = v.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        key = cve or v["id"]
        if key in seen or any(a in seen for a in aliases):
            continue
        seen.add(key)
        seen.update(aliases)
        seen.add(v["id"])
        sev = (v.get("database_specific") or {}).get("severity")
        cvss = next((s.get("score") for s in v.get("severity") or [] if str(s.get("type", "")).startswith("CVSS")), None)
        out.append({
            "id": v["id"], "cve": cve, "summary": v.get("summary") or (v.get("details") or "")[:200],
            "details": (v.get("details") or "")[:1200], "severity": sev, "fixed": sorted(set(fixed), key=_vkey),
            "url": f"https://osv.dev/vulnerability/{v['id']}", "published": v.get("published"),
            "symbols": sorted(set(symbols)), "aliases": sorted(set(aliases) | {v["id"]}), "cvss": cvss,
        })
    return out


def epss(cves):
    """FIRST.org EPSS: probability each CVE is exploited in the wild in the next 30 days."""
    cves = sorted({c for c in cves if c})
    if not cves:
        return {}
    r = _http.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves)})
    r.raise_for_status()
    return {d["cve"]: {"epss": float(d["epss"]), "percentile": float(d["percentile"])} for d in r.json().get("data", [])}


_kev = None


def kev():
    """CISA Known Exploited Vulnerabilities: {cve: date added}. Cached for the process."""
    global _kev
    if _kev is None:
        r = _http.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        r.raise_for_status()
        _kev = {v["cveID"]: v.get("dateAdded") for v in r.json().get("vulnerabilities", [])}
    return _kev


def min_safe_version(current, vulns):
    """Smallest release that clears every advisory: per advisory, the lowest fixed version above `current`."""
    need = []
    for v in vulns:
        above = [f for f in v["fixed"] if not version_gte(current, f)]
        if above:
            need.append(min(above, key=_vkey))
    return max(need, key=_vkey) if need else None


def pypi_latest(package):
    r = _http.get(f"https://pypi.org/pypi/{package}/json")
    r.raise_for_status()
    return r.json()["info"]["version"]


def pypi_json(package):
    r = _http.get(f"https://pypi.org/pypi/{package}/json")
    r.raise_for_status()
    return r.json()


def tavily_search(query, max_results=4):
    if not config.TAVILY_API_KEY:
        return []
    r = _http.post("https://api.tavily.com/search", json={
        "api_key": config.TAVILY_API_KEY, "query": query, "max_results": max_results,
        "search_depth": "advanced", "include_answer": True,
    })
    r.raise_for_status()
    data = r.json()
    results = [{"title": x.get("title"), "url": x.get("url"), "content": (x.get("content") or "")[:900],
                "tavily_score": x.get("score")}
               for x in data.get("results", [])]
    if data.get("answer"):
        results.insert(0, {"title": "Tavily answer", "url": "", "content": data["answer"]})
    return results


def _vkey(v):
    parts = []
    for p in v.replace("-", ".").split("."):
        parts.append((0, int(p)) if p.isdigit() else (1, p))
    return parts


def version_gte(a, b):
    return _vkey(a) >= _vkey(b)


# ---------- deps.dev (release trust) ----------
_DEPSDEV = "https://api.deps.dev/v3"
_dd_cache = {}


def _depsdev_get(path):
    """GET a deps.dev v3 path; None on 404, timeout or any error. Cached per process."""
    if path in _dd_cache:
        return _dd_cache[path]
    try:
        r = _http.get(_DEPSDEV + path, timeout=10)
        data = r.json() if r.status_code == 200 else None
    except Exception:
        data = None
    _dd_cache[path] = data
    return data


def _q(s):
    from urllib.parse import quote
    return quote(str(s), safe="")


def depsdev_version(name, version):
    """Raw deps.dev version record (publishedAt, attestations, slsaProvenances, links, relatedProjects...)."""
    return _depsdev_get(f"/systems/pypi/packages/{_q(name.lower())}/versions/{_q(version)}")


def depsdev_dependencies(name, version):
    """Names of the resolved transitive dependencies (excluding the package itself), or None if unknown."""
    d = _depsdev_get(f"/systems/pypi/packages/{_q(name.lower())}/versions/{_q(version)}:dependencies")
    if not d or "nodes" not in d:
        return None
    return sorted({n["versionKey"]["name"].lower() for n in d["nodes"] if n.get("relation") != "SELF"})


def depsdev_project(project_id):
    return _depsdev_get(f"/projects/{_q(project_id)}")


KEY_CHECKS = ("Code-Review", "Maintained", "Signed-Releases", "Dangerous-Workflow")


def release_trust(name, version):
    """Summarise one release: publish date, provenance, source repo, OpenSSF Scorecard, deps. Never raises."""
    out = {"version": version, "found": False, "published": None, "provenance": None,
           "source_repo": None, "scorecard": None, "checks": {}, "deps": None}
    try:
        v = depsdev_version(name, version)
        if not v:
            return out
        out["found"] = True
        out["published"] = v.get("publishedAt")
        att = [a for a in v.get("attestations") or [] if a.get("verified")]
        slsa = [s for s in v.get("slsaProvenances") or [] if s.get("verified")]
        out["provenance"] = bool(att or slsa)
        if att or slsa:
            out["provenance_repo"] = (att or slsa)[0].get("sourceRepository")
            out["provenance_commit"] = (att or slsa)[0].get("commit")
        repo = next((p["projectKey"]["id"] for p in v.get("relatedProjects") or []
                     if p.get("relationType") == "SOURCE_REPO"), None)
        out["source_repo"] = repo or next((l["url"] for l in v.get("links") or []
                                           if l.get("label") == "SOURCE_REPO"), None)
        if repo:
            sc = (depsdev_project(repo) or {}).get("scorecard") or {}
            if "overallScore" in sc:
                out["scorecard"] = sc["overallScore"]
                out["scorecard_date"] = sc.get("date")
                out["checks"] = {c["name"]: c.get("score") for c in sc.get("checks") or [] if c.get("name") in KEY_CHECKS}
        out["deps"] = depsdev_dependencies(name, version)
    except Exception:
        log.warning("deps.dev lookup failed for %s %s", name, version, exc_info=True)
    return out
