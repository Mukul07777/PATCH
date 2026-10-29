"""Symbol-level reachability: does the project's code touch the advisory's vulnerable symbols?

Statuses per advisory:
  reachable      a call / attribute use / import of the symbol (or a parent/child of it), with file:line sites
  imported       the package is imported, but none of the vulnerable symbols are used
  not reachable  the package is never imported by project code
  unknown        no symbol data, or the symbol is reached in a way static analysis can't see (e.g. Jinja filters)
"""
import re

IMPORT_NAMES = {"pyjwt": "jwt", "pillow": "PIL", "pyyaml": "yaml", "beautifulsoup4": "bs4", "scikit-learn": "sklearn"}


def import_name(package):
    return IMPORT_NAMES.get(package.lower(), package.lower().replace("-", "_"))


def parse_imports(imports):
    """OSV/PyPA ecosystem_specific.imports -> dotted paths. Accepts
    [{"attribute": "ImageFont", "modules": ["PIL"]}] and [{"module"|"path": "x", "symbols": [...]}]."""
    out = []
    for imp in imports or []:
        if not isinstance(imp, dict):
            continue
        mods = imp.get("modules") or [m for m in (imp.get("module"), imp.get("path")) if m]
        names = imp.get("symbols") or ([imp["attribute"]] if imp.get("attribute") else [])
        for m in mods:
            out += [f"{m}.{n}" for n in names] if names else [m]
    return sorted(set(out))


def _norm(s):
    return s.lower()


def _template_filter(symbol):
    m = re.match(r"jinja2\.filters\.do_(\w+)$", symbol)
    return m.group(1) if m else None


def analyse(usage, advisories, files=None):
    """usage: drift.usages() output. advisories: {id: {"package", "symbols", "source"}}.
    files: optional {path: text}, used to find template filter uses (`|xmlattr`)."""
    keys = {_norm(k): k for k in usage}
    result = {}
    for vid, adv in advisories.items():
        symbols, top = adv.get("symbols") or [], import_name(adv["package"])
        tops = {_norm(s.split(".")[0]) for s in symbols} | {_norm(top)}
        imported = [k for k in keys if k.split(".")[0] in tops]
        row = {"symbols": symbols, "source": adv.get("source") if symbols else None, "sites": [], "note": ""}
        if not imported:
            row.update(status="not reachable", note="package never imported by project code")
            result[vid] = row
            continue
        if not symbols:
            row.update(status="unknown", note="no symbol data; package is imported")
            result[vid] = row
            continue
        sites, hidden = [], []
        for s in symbols:
            ns, last = _norm(s), _norm(s.split(".")[-1])
            for k in imported:
                exact = k == ns or k.startswith(ns + ".") or ns.startswith(k + ".") and k.count(".") >= 1
                # re-export: jwt.decode reaches jwt.api_jwt.decode (same package, same final name)
                reexport = k.split(".")[0] == ns.split(".")[0] and k.split(".")[-1] == last and k.count(".") >= 1
                if exact or reexport:
                    sites += [x for x in usage[keys[k]]["sites"] if x not in sites]
            flt = _template_filter(s)
            if flt:
                hit = [f"{p}:{i}" for p, t in (files or {}).items() if not p.endswith(".py")
                       for i, line in enumerate(t.splitlines(), 1) if re.search(r"\|\s*" + flt + r"\b", line)]
                sites += [x for x in hit if x not in sites]
                if not hit:
                    hidden.append(s)
        if sites:
            row.update(status="reachable", sites=sites[:8])
        elif hidden:
            row.update(status="unknown", note=f"{', '.join(hidden)} is reached through templates; not statically visible")
        else:
            row["status"] = "imported"
        result[vid] = row
    return result


def counts(result):
    c = {"reachable": 0, "imported": 0, "not reachable": 0, "unknown": 0}
    for r in result.values():
        c[r["status"]] += 1
    return c
