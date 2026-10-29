"""Missing-dependency detection for the repair loop.

Upgrades often move optional features behind extras (bleach 6 needs `tinycss2` for CSS sanitizing via
`bleach[css]`). A repair model that sees `No module named 'tinycss2'` tends to write a fallback that drops the
feature. We detect these failures in pytest output, tell the model explicitly that adding a pinned requirement
is preferred, and can add the requirement deterministically before spending an LLM call.
"""
import ast
import re
import sys
from datetime import datetime, timezone

from . import sources

try:  # optional: precise PEP 440 / requires_python matching
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - simple fallback parser below
    SpecifierSet = None

# import name -> PyPI distribution, where they differ
IMPORT_TO_DIST = {
    "yaml": "PyYAML", "PIL": "Pillow", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "jwt": "PyJWT", "Crypto": "pycryptodome",
    "dotenv": "python-dotenv", "attr": "attrs", "magic": "python-magic", "OpenSSL": "pyOpenSSL",
    "serial": "pyserial", "usb": "pyusb", "docx": "python-docx", "multipart": "python-multipart",
    "jose": "python-jose", "git": "GitPython", "MySQLdb": "mysqlclient", "psycopg2": "psycopg2-binary",
    "socks": "PySocks", "nacl": "PyNaCl", "zmq": "pyzmq", "Levenshtein": "python-Levenshtein",
}
# dist -> (package that offers it as an extra, extra spec) for the hint text
EXTRA_HINT = {"tinycss2": "bleach[css]", "brotli": "urllib3[brotli]", "socks": "requests[socks]"}
# library warnings that name a missing optional dependency without an ImportError
WARNING_HINTS = [
    (re.compile(r"NoCssSanitizerWarning"), "tinycss2"),
]
NO_MODULE = re.compile(r"No module named ['\"]([A-Za-z_][\w.]*)['\"]")
REQ_NAME = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")
STDLIB_LIKE = {"tests", "test", "conftest", "__main__"}
STDLIB = set(getattr(sys, "stdlib_module_names", ()))
DIST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MIN_AGE_DAYS = 90  # typosquat / slopsquat guard: never auto-add a package first published recently


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def detect_missing(output, local_modules=()):
    """Top-level import names that pytest output says are missing (ordered, de-duplicated)."""
    found = []
    local = {m.lower() for m in local_modules}
    for m in NO_MODULE.finditer(output or ""):
        found.append(m.group(1).split(".")[0])
    for rx, mod in WARNING_HINTS:
        if rx.search(output or ""):
            found.append(mod)
    out = []
    for name in found:
        if (name not in out and name.lower() not in local and name not in STDLIB_LIKE and name not in STDLIB
                and not name.startswith("_")):
            out.append(name)
    return out


def dist_for(module):
    return IMPORT_TO_DIST.get(module, module)


def requirement_names(req_text):
    names = set()
    for line in req_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = REQ_NAME.match(line)
        if m:
            names.add(_norm(m.group(1)))
    return names


def hints(missing):
    """Structured hints for the repair prompt."""
    out = []
    for mod in missing:
        dist = dist_for(mod)
        h = {"missing_module": mod, "pypi_package": dist,
             "advice": (f"Tests fail because module '{mod}' is not installed. Prefer adding a pinned requirement "
                        f"to requirements.txt (e.g. {dist}==<version>) over removing or disabling functionality.")}
        if dist.lower() in EXTRA_HINT:
            h["via_extra"] = EXTRA_HINT[dist.lower()]
            h["advice"] += f" It is the optional dependency behind the `{EXTRA_HINT[dist.lower()]}` extra."
        out.append(h)
    return out


def top_level_imports(files):
    """Top-level module names imported by the given {path: source} .py files (syntax errors are skipped)."""
    names = set()
    for path, text in files.items():
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names.add(node.module.split(".")[0])
    return names


def trusted(module, original_imports=()):
    """Only modules we have a curated mapping for, or that the ORIGINAL repo already imported, may be auto-added.
    Anything else (e.g. a module an LLM edit hallucinated) only becomes a prompt hint."""
    return module in IMPORT_TO_DIST or module.lower() in EXTRA_HINT or module in set(original_imports)


def _simple_version(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def python_ok(requires, py=None):
    """Does the interpreter version `py` (tuple) satisfy a requires_python spec? Empty spec matches."""
    py = py or sys.version_info[:3]
    if not requires or not requires.strip():
        return True
    if SpecifierSet is not None:
        try:
            return SpecifierSet(requires).contains(".".join(map(str, py)), prereleases=True)
        except (InvalidSpecifier, InvalidVersion):
            return False
    ops = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b,
           "<": lambda a, b: a < b, "==": lambda a, b: a == b, "!=": lambda a, b: a != b}
    for part in requires.split(","):
        m = re.match(r"\s*(>=|<=|==|!=|>|<|~=)\s*([\d.*]+)\s*$", part)
        if not m:
            return False
        op, ver = m.groups()
        star = ver.endswith(".*")
        want = _simple_version(ver)
        have = tuple(py)[:len(want)] if (star or op in ("==", "!=")) else tuple(py)
        if op == "~=":
            if not (tuple(py) >= want and tuple(py)[:len(want) - 1] == want[:-1]):
                return False
        elif not ops[op](have, want):
            return False
    return True


def _vkey(v):
    if SpecifierSet is not None:
        try:
            return (1, Version(v))
        except InvalidVersion:
            return (0, _simple_version(v))
    return (0, _simple_version(v))


def _is_pre(v):
    return bool(re.search(r"(a|b|rc|dev)\d*", v, re.I))


def _uploaded(files):
    times = []
    for f in files:
        t = f.get("upload_time_iso_8601") or f.get("upload_time")
        if t:
            try:
                d = datetime.fromisoformat(t.replace("Z", "+00:00"))
                times.append(d if d.tzinfo else d.replace(tzinfo=timezone.utc))
            except ValueError:
                pass
    return min(times) if times else None


def pick_release(data, py=None, now=None, min_age_days=MIN_AGE_DAYS):
    """(version, None) for the newest non-yanked, final release whose files support `py`; else (None, reason).
    Rejects packages with no releases or whose first release is younger than `min_age_days`."""
    releases = {v: fs for v, fs in (data.get("releases") or {}).items() if fs}
    if not releases:
        return None, "no releases on PyPI"
    first = min((t for t in (_uploaded(fs) for fs in releases.values()) if t), default=None)
    now = now or datetime.now(timezone.utc)
    if first is None or (now - first).days < min_age_days:
        return None, f"first release is younger than {min_age_days} days"
    for v in sorted(releases, key=_vkey, reverse=True):
        fs = releases[v]
        if _is_pre(v) or all(f.get("yanked") for f in fs):
            continue
        if any(not f.get("yanked") and python_ok(f.get("requires_python"), py) for f in fs):
            return v, None
    return None, "no non-yanked release supports this Python"


def resolve(module, lookup=sources.pypi_json, original_imports=(), py=None, now=None):
    """(dist, version, None) when it is safe to auto-add `module`, else (dist, None, reason)."""
    dist = dist_for(module)
    if module in STDLIB or module.startswith("_"):
        return dist, None, "standard-library or private module"
    if not DIST_NAME.match(dist):
        return dist, None, "invalid distribution name"
    if not trusted(module, original_imports):
        return dist, None, "not imported by the original repository and not a known mapping"
    try:
        data = lookup(dist)
    except Exception:
        return dist, None, f"no PyPI package '{dist}'"
    version, reason = pick_release(data or {}, py=py, now=now)
    return dist, version, reason


def add_requirements(req_path, pins):
    """Append `dist==version` lines not already present; returns the list actually added."""
    text = req_path.read_text(encoding="utf-8") if req_path.exists() else ""
    have = requirement_names(text)
    added = [(d, v) for d, v in pins if _norm(d) not in have]
    if added:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "".join(f"{d}=={v}\n" for d, v in added)
        req_path.write_text(text, encoding="utf-8")
    return added
