"""OpenVEX v0.2.0 export (https://github.com/openvex/spec): one statement per advisory for the run.

Status rules (conservative, evidence-backed only):
  fixed         the OSV re-scan of the upgraded pin no longer lists the advisory AND the test suite is green
  not_affected  static reachability says "not reachable" (package never imported) from AST evidence;
                never derived from llm-inferred symbol data
  affected      everything else (requires an action_statement per spec)
"""
import hashlib
import json
import time

CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"}


def purl(name, version):
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build(run_id, findings, plan, reach, remaining, tests_ok, ledger=None, exploit=None, timestamp=None):
    """findings: agent findings; plan: {"upgrades":[{package,to}]}; reach: {advisory id: reach row};
    remaining: ids still listed by the OSV re-scan (or "<pkg>: OSV re-scan failed")."""
    ts = timestamp or _now()
    cert = (ledger or {}).get("certificate")
    targets = {u["package"].lower(): u["to"] for u in (plan or {}).get("upgrades") or []}
    failed = {r.split(":")[0].strip().lower() for r in remaining or [] if "re-scan failed" in r}
    statements = []
    for f in findings:
        pkg = f["package"]
        for v in f["vulns"]:
            name = v.get("cve") or v["id"]
            aliases = sorted({v["id"], *(v.get("aliases") or [])} - {name})
            to = targets.get(pkg.lower())
            r = (reach or {}).get(v["id"]) or {}
            proof = f"proof certificate {cert}" if cert else "no proof certificate"
            ex = ""
            if exploit and exploit.get("advisory") in (name, v["id"]):
                ex = f"; exploit verdict: {exploit.get('verdict', 'not run')}"
            st = {"vulnerability": {"name": name, **({"aliases": aliases} if aliases else {})},
                  "products": [{"@id": purl(pkg, f["current"])}], "timestamp": ts}
            cleared = to and pkg.lower() not in failed and name not in (remaining or []) \
                and v["id"] not in (remaining or [])
            if cleared and tests_ok:
                st.update(status="fixed",
                          status_notes=f"Upgraded {pkg} {f['current']} -> {to}; OSV re-scan of {to} no longer lists "
                                       f"{name}; project tests green; {proof}{ex}",
                          action_statement=f"Upgrade {pkg} to {to} ({purl(pkg, to)}).")
            elif r.get("status") == "not reachable" and r.get("source") != "llm-inferred":
                st.update(status="not_affected", justification="vulnerable_code_not_in_execute_path",
                          impact_statement=f"Static analysis: {r.get('note') or 'package never imported'}; "
                                           f"{proof}{ex}")
            else:
                why = "upgrade not verified (OSV re-scan or tests)" if to else "no upgrade planned"
                st.update(status="affected", status_notes=f"{why}; reachability: {r.get('status', 'unknown')}; "
                                                          f"{proof}{ex}",
                          action_statement=f"Upgrade {pkg} to {to}." if to else f"Upgrade {pkg} to a fixed release.")
            statements.append(st)
    doc = {"@context": CONTEXT, "author": "PatchPilot", "role": "Automated remediation agent",
           "timestamp": ts, "version": 1, "tooling": "PatchPilot", "statements": statements}
    digest = hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()
    doc["@id"] = f"https://openvex.dev/docs/patchpilot/{run_id}-{digest[:12]}"
    validate(doc)
    return doc


def validate(doc):
    """Raise ValueError if required OpenVEX v0.2.0 fields are missing or inconsistent."""
    for k in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if k not in doc or doc[k] in (None, ""):
            raise ValueError(f"document missing {k}")
    if doc["@context"] != CONTEXT:
        raise ValueError("bad @context")
    if not isinstance(doc["version"], int) or doc["version"] < 1:
        raise ValueError("version must be an integer >= 1")
    for i, s in enumerate(doc["statements"]):
        if not (s.get("vulnerability") or {}).get("name"):
            raise ValueError(f"statement {i}: vulnerability.name required")
        if not s.get("products") or not all(p.get("@id") for p in s["products"]):
            raise ValueError(f"statement {i}: products with @id required")
        if s.get("status") not in STATUSES:
            raise ValueError(f"statement {i}: bad status")
        if s["status"] == "not_affected":
            if not (s.get("justification") or s.get("impact_statement")):
                raise ValueError(f"statement {i}: not_affected needs justification or impact_statement")
            if s.get("justification") and s["justification"] not in JUSTIFICATIONS:
                raise ValueError(f"statement {i}: bad justification")
        if s["status"] == "affected" and not s.get("action_statement"):
            raise ValueError(f"statement {i}: affected needs action_statement")
    return True
