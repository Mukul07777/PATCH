"""API drift radar: predict which lines an upgrade breaks, before running any test.

1. `usages()` walks the project's AST on the host and records every third-party symbol it touches
   (`from jinja2 import Markup`, `jwt.decode`, `Retry(method_whitelist=...)`) with file:line.
2. PROBE runs inside the sandbox venv and checks each symbol against the *installed* library:
   does it exist, and does its signature still accept the keyword arguments the project passes?
3. Probing once on the old pins and once on the new pins and diffing the two gives the drift.
"""
import ast
import json

PROBE = r'''
import importlib, importlib.metadata as md, inspect, json, sys

wanted = {d.lower().replace("_", "-") for d in json.loads(sys.argv[2])}
owner = {m: [d.lower().replace("_", "-") for d in ds] for m, ds in md.packages_distributions().items()}
usage = json.load(open(sys.argv[1], encoding="utf-8"))
out = {}

def resolve(path):
    parts = path.split(".")
    for i in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:i]))
        except Exception:
            continue
        for a in parts[i:]:
            obj = getattr(obj, a)
        return obj
    raise ImportError(path)

for path, info in usage.items():
    if not set(owner.get(path.split(".")[0], [])) & wanted:
        continue
    row = {"exists": True, "missing_kwargs": []}
    try:
        obj = resolve(path)
    except Exception:
        row["exists"] = False
        out[path] = row
        continue
    if info["kwargs"]:
        try:
            params = inspect.signature(obj).parameters.values()
            if not any(p.kind is p.VAR_KEYWORD for p in params):
                names = {p.name for p in params}
                row["missing_kwargs"] = sorted(k for k in info["kwargs"] if k not in names)
        except (TypeError, ValueError):
            pass
    out[path] = row
print(json.dumps(out))
'''


def usages(files):
    """{dotted symbol: {"kwargs": [...], "sites": ["file:line", ...]}} for every imported-name use."""
    out = {}

    def add(path, site, kwargs=()):
        row = out.setdefault(path, {"kwargs": set(), "sites": []})
        row["kwargs"].update(kwargs)
        if site not in row["sites"]:
            row["sites"].append(site)

    for fname, text in files.items():
        if not fname.endswith(".py") or fname.startswith("tests/"):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        alias = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    alias[a.asname or a.name.split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    alias[a.asname or a.name] = f"{node.module}.{a.name}"
                    add(f"{node.module}.{a.name}", f"{fname}:{node.lineno}")

        def dotted(n):
            parts = []
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name) and n.id in alias:
                return ".".join([alias[n.id], *reversed(parts)])
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                p = dotted(node.func)
                if p:
                    add(p, f"{fname}:{node.lineno}", [k.arg for k in node.keywords if k.arg])
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                p = dotted(node)
                if p:
                    add(p, f"{fname}:{node.lineno}")
    return {k: {"kwargs": sorted(v["kwargs"]), "sites": v["sites"][:6]} for k, v in out.items()}


def diff(usage, old, new):
    """Symbols/kwargs that worked on the old pins and don't on the new ones."""
    breaks = []
    for path, o in old.items():
        n = new.get(path)
        if n is None:
            continue
        sites = usage.get(path, {}).get("sites", [])
        if o["exists"] and not n["exists"]:
            breaks.append({"symbol": path, "kind": "removed", "detail": f"{path} no longer exists", "sites": sites})
        elif o["exists"] and n["exists"]:
            gone = sorted(set(n["missing_kwargs"]) - set(o["missing_kwargs"]))
            if gone:
                breaks.append({"symbol": path, "kind": "signature",
                               "detail": f"{path}() no longer accepts {', '.join(k + '=' for k in gone)}", "sites": sites})
    return breaks


def dump(usage):
    return json.dumps(usage)
