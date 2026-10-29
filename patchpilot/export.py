"""Scan result exports: SARIF 2.1.0 (GitHub code scanning), CycloneDX 1.5 JSON SBOM with vulnerabilities,
plain JSON and CSV. Shared by the CLI (`python -m patchpilot scan`) and GET /api/scans/{id}/export.

A report is {"name", "findings": [finding dicts as stored by the scanner], "deps": [[name, version, file, line]],
"files": [manifest paths], "commit": optional sha}.
"""
import csv
import io
import json
import time
import uuid

from . import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MODERATE": "warning", "LOW": "note"}
# GitHub ranks code-scanning alerts by rules[].properties["security-severity"] (a CVSS-like 0-10 number)
SEC_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MODERATE": "5.5", "LOW": "2.0"}
CDX_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}


def _sev(f):
    s = (f.get("severity") or "").upper()
    return "MODERATE" if s == "MEDIUM" else s


def purl(name, version=None):
    n = name.lower().replace("_", "-").replace(".", "-")
    return f"pkg:pypi/{n}" + (f"@{version}" if version else "")


def _first_file(f, files):
    src = (f.get("source_file") or "").split(", ")[0]
    return src or (files[0] if files else "requirements.txt")


def _advisory_url(vid):
    return f"https://osv.dev/vulnerability/{vid}"


def sarif(report):
    rules, index, results = [], {}, []
    files = report.get("files") or []
    for f in report["findings"]:
        if f.get("suppressed"):
            continue
        vid, sev = f["vuln_id"], _sev(f)
        if vid not in index:
            index[vid] = len(rules)
            score = f.get("cvss_score")
            rules.append({
                "id": vid,
                "name": "VulnerableDependency",
                "shortDescription": {"text": (f.get("summary") or vid)[:200]},
                "fullDescription": {"text": f.get("summary") or vid},
                "helpUri": _advisory_url(vid),
                "help": {"text": f"{vid} affects {f['package']}. "
                                 + (f"Upgrade to {f['fixed_in']} or later." if f.get("fixed_in") else "No fix released yet."),
                         "markdown": f"[{vid}]({_advisory_url(vid)}) affects `{f['package']}`. "
                                     + (f"Upgrade to `{f['fixed_in']}` or later." if f.get("fixed_in") else "No fix released yet.")},
                "defaultConfiguration": {"level": LEVEL.get(sev, "warning")},
                "properties": {"tags": ["security", "dependency", "pypi"],
                               "security-severity": f"{score:.1f}" if isinstance(score, (int, float)) else SEC_SEVERITY.get(sev, "5.0"),
                               "aliases": f.get("aliases") or []},
            })
        line = f.get("source_line") or 1
        results.append({
            "ruleId": vid,
            "ruleIndex": index[vid],
            "level": LEVEL.get(sev, "warning"),
            "message": {"text": f"{f['package']} {f.get('version') or ''} is affected by {vid}"
                                + (f" ({sev.lower()})" if sev in LEVEL else "")
                                + (f"; fixed in {f['fixed_in']}" if f.get("fixed_in") else "; no fixed version yet")
                                + ("; listed in CISA KEV" if f.get("kev") else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _first_file(f, files), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(line))}}}],
            "partialFingerprints": {"patchpilot/v1": f"{f['package'].lower()}:{f.get('version')}:{vid}"},
            "properties": {"package": f["package"], "version": f.get("version"), "fixed_in": f.get("fixed_in"),
                           "epss": f.get("epss"), "kev": bool(f.get("kev"))},
        })
    run = {
        "tool": {"driver": {"name": "PatchPilot", "informationUri": "https://github.com/Mukul07777/PATCH", "version": __version__,
                            "semanticVersion": __version__, "rules": rules}},
        "results": results,
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Repository root"}}},
    }
    if report.get("commit"):
        run["versionControlProvenance"] = [{"repositoryUri": report.get("repository") or "https://github.com/",
                                            "revisionId": report["commit"]}]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def cyclonedx(report):
    comps, seen = [], set()
    for name, version, *_ in report.get("deps") or []:
        ref = purl(name, version)
        if ref in seen:
            continue
        seen.add(ref)
        c = {"type": "library", "bom-ref": ref, "name": name, "purl": ref}
        if version:
            c["version"] = version
        comps.append(c)
    vulns, vseen = [], {}
    for f in report["findings"]:
        if f.get("suppressed"):
            continue
        ref = purl(f["package"], f.get("version"))
        if ref not in seen:
            seen.add(ref)
            comps.append({"type": "library", "bom-ref": ref, "name": f["package"], "version": f.get("version"),
                          "purl": ref})
        if f["vuln_id"] in vseen:  # one vulnerability, several affected components
            vseen[f["vuln_id"]]["affects"].append({"ref": ref})
            continue
        sev = _sev(f)
        rating = {"source": {"name": "OSV"}, "severity": CDX_SEVERITY.get(sev, "unknown")}
        if isinstance(f.get("cvss_score"), (int, float)):
            rating["score"] = f["cvss_score"]
        if f.get("cvss"):
            rating["vector"] = f["cvss"]
            rating["method"] = "CVSSv4" if f["cvss"].startswith("CVSS:4") else "CVSSv31" if f["cvss"].startswith("CVSS:3.1") else "CVSSv3"
        v = {"bom-ref": f"vuln-{f['vuln_id']}", "id": f["vuln_id"],
             "source": {"name": "OSV", "url": _advisory_url(f["vuln_id"])},
             "ratings": [rating], "description": f.get("summary") or "",
             "affects": [{"ref": ref}]}
        if f.get("aliases"):
            v["references"] = [{"id": a, "source": {"name": "NVD" if a.startswith("CVE-") else "OSV",
                                                    "url": f"https://nvd.nist.gov/vuln/detail/{a}" if a.startswith("CVE-") else _advisory_url(a)}}
                               for a in f["aliases"]]
        if f.get("fixed_in"):
            v["recommendation"] = f"Upgrade {f['package']} to {f['fixed_in']} or later"
        props = []
        if f.get("epss") is not None:
            props.append({"name": "patchpilot:epss", "value": str(f["epss"])})
        if f.get("kev"):
            props.append({"name": "patchpilot:cisa-kev", "value": "true"})
        if props:
            v["properties"] = props
        vseen[f["vuln_id"]] = v
        vulns.append(v)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "tools": {"components": [{"type": "application", "name": "PatchPilot", "version": __version__}]},
                     "component": {"type": "application", "bom-ref": "root", "name": report.get("name") or "project"}},
        "components": comps,
        "dependencies": [{"ref": "root", "dependsOn": [c["bom-ref"] for c in comps]}],
        "vulnerabilities": vulns,
    }


CSV_FIELDS = ("package", "version", "vuln_id", "aliases", "severity", "cvss_score", "epss", "kev", "fixed_in",
              "source_file", "source_line", "suppressed", "summary")


def to_csv(report):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for f in report["findings"]:
        row = []
        for k in CSV_FIELDS:
            v = f.get(k)
            v = ";".join(v) if isinstance(v, list) else ("" if v is None else v)
            v = str(v)
            if v[:1] in ("=", "+", "-", "@"):  # spreadsheet formula injection
                v = "'" + v
            row.append(v)
        w.writerow(row)
    return buf.getvalue()


def to_json(report):
    return {"name": report.get("name"), "files": report.get("files") or [], "findings": report["findings"],
            "summary": report.get("summary")}


FORMATS = {"sarif": ("application/sarif+json", "sarif"), "cyclonedx": ("application/vnd.cyclonedx+json", "cdx.json"),
           "json": ("application/json", "json"), "csv": ("text/csv", "csv")}


def render(report, fmt):
    """The export as text (str)."""
    if fmt == "csv":
        return to_csv(report)
    doc = {"sarif": sarif, "cyclonedx": cyclonedx, "json": to_json}[fmt](report)
    return json.dumps(doc, indent=2)
