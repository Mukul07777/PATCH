"""Real-world data sources: OSV.dev advisories, PyPI releases, Tavily web research."""
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
from cvss import CVSS3, CVSS4
from packaging.version import InvalidVersion, Version

from . import config
from .reach import parse_imports

log = logging.getLogger(__name__)

_http = httpx.Client(timeout=30, headers={"User-Agent": "patchpilot/0.1"})


OSV = "https://api.osv.dev/v1"
OSV_BATCH = 1000  # queries per /v1/querybatch request (the API maximum)
EPSS_BATCH = 100  # CVEs per FIRST.org request
SEVERITY_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MODERATE"), (0.1, "LOW"))
_vuln_cache = {}  # OSV id -> full record (records change rarely; the process cache keeps rescans cheap)
_cache_lock = threading.Lock()


def cvss_base(vector):
    """Numeric base score of a CVSS v3.x or v4.0 vector, or None if it can't be parsed."""
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).scores()[0])
    except Exception:  # malformed vector in an advisory
        return None
    return None


def band(score):
    """CVSS base score -> CRITICAL / HIGH / MODERATE / LOW (None for 0 or unknown)."""
    if score is None:
        return None
    return next((name for floor, name in SEVERITY_BANDS if score >= floor), None)


def _vector(v):
    """The advisory's preferred CVSS vector: v3 over v4 (v3 is what most tools still report), never v2."""
    vecs = {str(s.get("type", "")): s.get("score") for s in v.get("severity") or []}
    return vecs.get("CVSS_V3") or vecs.get("CVSS_V4")


def _rate(v, lookup=None):
    """(severity, cvss vector, numeric score) for one OSV record. PYSEC records carry no database_specific
    severity, so it is computed from the CVSS vector, or taken from the GHSA alias when there is no vector."""
    vector = _vector(v)
    score = cvss_base(vector) if vector else None
    sev = (v.get("database_specific") or {}).get("severity")
    sev = str(sev).upper() if sev else None
    if (sev is None or score is None) and lookup:
        for alias in (a for a in v.get("aliases") or [] if a.startswith("GHSA-")):
            g = lookup(alias)
            if not g:
                continue
            gv = _vector(g)
            vector = vector or gv
            score = score if score is not None else (cvss_base(gv) if gv else None)
            sev = sev or ((g.get("database_specific") or {}).get("severity") or "").upper() or None
            break
    sev = sev or band(score)
    return ("MODERATE" if sev == "MEDIUM" else sev), vector, score


def normalize(package, records, lookup=None):
    """Raw OSV records for one package -> our advisory dicts, deduplicated across GHSA / PYSEC / CVE ids."""
    out, seen = [], set()
    # GHSA records come first so the richer summary wins when PYSEC duplicates the same CVE
    for v in sorted(records, key=lambda v: not v["id"].startswith("GHSA")):
        fixed, symbols = [], []
        for aff in v.get("affected", []):
            if normalize_name(aff.get("package", {}).get("name", "")) != normalize_name(package):
                continue
            symbols += parse_imports((aff.get("ecosystem_specific") or {}).get("imports"))
            for rng in aff.get("ranges", []):
                fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e and _valid(e["fixed"])]
        aliases = v.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        key = cve or v["id"]
        if key in seen or any(a in seen for a in aliases):
            continue
        seen.add(key)
        seen.update(aliases)
        seen.add(v["id"])
        sev, vector, score = _rate(v, lookup)
        out.append({
            "id": v["id"], "cve": cve, "summary": v.get("summary") or (v.get("details") or "")[:200],
            "details": (v.get("details") or "")[:1200], "severity": sev, "fixed": sorted(set(fixed), key=_vkey),
            "url": f"https://osv.dev/vulnerability/{v['id']}", "published": v.get("published"),
            "symbols": sorted(set(symbols)), "aliases": sorted(set(aliases) | {v["id"]}), "cvss": vector,
            "cvss_score": score,
        })
    return out


def osv_vulns(package, version):
    """Advisories affecting one exact package version (single /v1/query call; used by fix mode)."""
    r = _http.post(f"{OSV}/query", json={"package": {"name": package, "ecosystem": "PyPI"}, "version": version})
    r.raise_for_status()
    return normalize(package, r.json().get("vulns", []), osv_record)


def osv_record(vuln_id):
    """Full OSV record by id (cached); None if it can't be fetched."""
    with _cache_lock:
        if vuln_id in _vuln_cache:
            return _vuln_cache[vuln_id]
    try:
        r = _http.get(f"{OSV}/vulns/{vuln_id}")
        rec = r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None
    if rec is not None:
        with _cache_lock:
            _vuln_cache[vuln_id] = rec
    return rec


def osv_batch(pairs):
    """{(name, version): [advisory, ...]} for every pair, via /v1/querybatch in chunks of 1000, then the full
    record of each hit (cached by id). Raises httpx errors when OSV itself is unreachable."""
    pairs = list(dict.fromkeys(pairs))
    ids = {}
    for i in range(0, len(pairs), OSV_BATCH):
        chunk = pairs[i:i + OSV_BATCH]
        r = _http.post(f"{OSV}/querybatch", json={"queries": [
            {"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]})
        r.raise_for_status()
        for (n, v), res in zip(chunk, r.json().get("results", [])):
            found = [x["id"] for x in (res or {}).get("vulns") or []]
            if (res or {}).get("next_page_token"):  # very long advisory list: ask for this one in full
                found += [x["id"] for x in _osv_query_all(n, v)]
            ids[(n, v)] = list(dict.fromkeys(found))
    wanted = sorted({i for found in ids.values() for i in found})
    with ThreadPoolExecutor(8) as pool:
        records = dict(zip(wanted, pool.map(osv_record, wanted)))
    out = {}
    for (n, v) in pairs:
        recs = [records[i] for i in ids.get((n, v), []) if records.get(i)]
        out[(n, v)] = normalize(n, recs, osv_record) if recs else []
    return out


def _osv_query_all(package, version):
    out, token = [], None
    for _ in range(20):
        body = {"package": {"name": package, "ecosystem": "PyPI"}, "version": version}
        if token:
            body["page_token"] = token
        r = _http.post(f"{OSV}/query", json=body)
        r.raise_for_status()
        data = r.json()
        out += data.get("vulns", [])
        token = data.get("next_page_token")
        if not token:
            break
    return out


def epss(cves):
    """FIRST.org EPSS: probability each CVE is exploited in the wild in the next 30 days.
    Queried 100 CVEs per request (the API pages at 100 rows); raises if any request fails."""
    cves = sorted({c for c in cves if c})
    out = {}
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i:i + EPSS_BATCH]
        r = _http.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(chunk), "limit": EPSS_BATCH})
        r.raise_for_status()
        out.update({d["cve"]: {"epss": float(d["epss"]), "percentile": float(d["percentile"])}
                    for d in r.json().get("data", [])})
    return out


def pypi_missing(names):
    """Names PyPI answers 404 for (private package, typo, or a dependency-confusion target). Network errors
    count as present: this is a warning, not a verdict."""
    def gone(name):
        try:
            return _http.head(f"https://pypi.org/pypi/{name}/json", timeout=10).status_code == 404
        except httpx.HTTPError:
            return False
    names = sorted(set(names))
    if not names:
        return set()
    with ThreadPoolExecutor(16) as pool:
        return {n for n, g in zip(names, pool.map(gone, names)) if g}


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
    if not config.tavily_api_key():
        return []
    r = _http.post("https://api.tavily.com/search", json={
        "api_key": config.tavily_api_key(), "query": query, "max_results": max_results,
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


def _valid(v):
    try:
        Version(v)
        return True
    except InvalidVersion:
        return False


def _vkey(v):
    """Sort key following PEP 440 (1.0rc1 < 1.0 < 1.0.post1; 1.0.dev0 first). Strings that are not PEP 440
    versions sort before all real versions, by their numeric parts."""
    try:
        return (1, Version(str(v)), ())
    except InvalidVersion:
        return (0, Version("0"), tuple(int(p) for p in re.findall(r"\d+", str(v))))


def version_gte(a, b):
    return _vkey(a) >= _vkey(b)


def normalize_name(name):
    return re.sub(r"[-_.]+", "-", name or "").lower()


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
