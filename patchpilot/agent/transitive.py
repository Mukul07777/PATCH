"""Transitive dependencies: scan what is really installed, not just what requirements.txt pins.

Most vulnerable code arrives through a dependency of a dependency, which a top-level requirements.txt never
names. After the baseline install the sandbox lists every distribution in the venv; the unpinned ones are checked
against OSV in one batch, and each vulnerable one gets an explicit pin to the smallest release that clears every
advisory (least change, so the parent's version range is most likely still satisfied).
"""
import json

from patchpilot.intel import sources

INVENTORY = ".patchpilot/inventory.py"
INVENTORY_SCRIPT = r'''
import importlib.metadata as md, json
seen = {}
for d in md.distributions():
    name = d.metadata["Name"]
    if name:
        seen[name.lower()] = {"name": name, "version": d.version}
print(json.dumps(sorted(seen.values(), key=lambda x: x["name"].lower())))
'''
# tooling the sandbox itself brings in; never pinned into the project's requirements
TOOLING = {"pip", "setuptools", "wheel", "pytest", "pluggy", "iniconfig", "packaging", "colorama", "exceptiongroup",
           "tomli"}
MARK = "# transitive dependency, pinned by PatchPilot to clear a known vulnerability"


def unpinned(inventory, pins):
    """Installed distributions that requirements.txt does not pin (and that are not test tooling)."""
    pinned = {sources.normalize_name(n) for n in pins}
    return [d for d in inventory
            if sources.normalize_name(d["name"]) not in pinned and sources.normalize_name(d["name"]) not in TOOLING]


def findings_for(dists, batch):
    """Finding rows (same shape as direct ones, plus transitive=True) for every vulnerable distribution."""
    out = []
    for d in dists:
        vulns = batch.get((d["name"], d["version"])) or []
        if vulns:
            out.append({"package": d["name"], "current": d["version"], "vulns": vulns, "transitive": True,
                        "min_safe": sources.min_safe_version(d["version"], vulns)})
    return out


class TransitiveMixin:
    def _inventory(self, sandbox):
        path = self.work / INVENTORY
        path.parent.mkdir(exist_ok=True)
        path.write_text(INVENTORY_SCRIPT, encoding="utf-8")
        ok, out = sandbox.python(str(path))
        if not ok:
            raise RuntimeError(out.strip().splitlines()[-1] if out.strip() else "inventory failed")
        return json.loads(out.strip().splitlines()[-1])

    def _transitive(self, pins, sandbox):
        """Vulnerable distributions installed only as dependencies of the pinned ones; [] when none or on error."""
        try:
            dists = unpinned(self._inventory(sandbox), pins)
            found = findings_for(dists, sources.osv_batch([(d["name"], d["version"]) for d in dists]))
        except Exception as e:  # a bonus check; the direct pins are still fixed
            self.log(f"Transitive scan skipped: {e}"[:300], "scan")
            return []
        for f in found:
            try:
                f["latest"] = sources.pypi_latest(f["package"])
            except Exception:
                f["latest"] = f["min_safe"]
        self.log(f"Transitive scan: {len(dists)} unpinned installed package(s), {len(found)} vulnerable"
                 + (": " + ", ".join(f"{f['package']}=={f['current']}" for f in found) if found else ""), "scan")
        return found

    def _add_transitive(self, findings, plan, found):
        """Merge transitive findings into the run and plan a least-change pin for each fixable one."""
        if not found:
            return
        findings += [f for f in found if f not in findings]
        self._emit({"type": "findings", "findings": findings})
        for f in found:
            if not f["min_safe"]:
                self.log(f"{f['package']}=={f['current']}: no fixed release published; left for review", "plan")
                continue
            # a transitive package the planner already picked up still gets the least-change target
            plan["upgrades"] = [u for u in plan["upgrades"] if u["package"].lower() != f["package"].lower()]
            plan["upgrades"].append({"package": f["package"], "from": f["current"], "to": f["min_safe"],
                                     "breaking": str(f["current"]).split(".")[0] != str(f["min_safe"]).split(".")[0],
                                     "transitive": True,
                                     "reason": "Transitive dependency: pinned to the smallest release that clears "
                                               "every advisory"})
        self._emit({"type": "plan", "plan": plan})
