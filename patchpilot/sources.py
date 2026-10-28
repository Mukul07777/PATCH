"""Real-world data sources: OSV.dev advisories, PyPI releases, Tavily web research."""
import re
import httpx

from . import config

_http = httpx.Client(timeout=30, headers={"User-Agent": "patchpilot/0.1"})


def osv_vulns(package, version):
    r = _http.post("https://api.osv.dev/v1/query",
                   json={"package": {"name": package, "ecosystem": "PyPI"}, "version": version})
    r.raise_for_status()
    out, seen = [], set()
    # GHSA records come first so the richer summary wins when PYSEC duplicates the same CVE
    vulns = sorted(r.json().get("vulns", []), key=lambda v: not v["id"].startswith("GHSA"))
    for v in vulns:
        fixed = []
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() != package.lower():
                continue
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
        out.append({
            "id": v["id"], "cve": cve, "summary": v.get("summary") or (v.get("details") or "")[:200],
            "details": (v.get("details") or "")[:1200], "severity": sev, "fixed": sorted(set(fixed), key=_vkey),
            "url": f"https://osv.dev/vulnerability/{v['id']}",
        })
    return out


def pypi_latest(package):
    r = _http.get(f"https://pypi.org/pypi/{package}/json")
    r.raise_for_status()
    return r.json()["info"]["version"]


def tavily_search(query, max_results=4):
    if not config.TAVILY_API_KEY:
        return []
    r = _http.post("https://api.tavily.com/search", json={
        "api_key": config.TAVILY_API_KEY, "query": query, "max_results": max_results,
        "search_depth": "advanced", "include_answer": True,
    })
    r.raise_for_status()
    data = r.json()
    results = [{"title": x.get("title"), "url": x.get("url"), "content": (x.get("content") or "")[:900]}
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
