"""Missing-dependency detection for the repair loop.

Upgrades often move optional features behind extras (bleach 6 needs `tinycss2` for CSS sanitizing via
`bleach[css]`). A repair model that sees `No module named 'tinycss2'` tends to write a fallback that drops the
feature. We detect these failures in pytest output, tell the model explicitly that adding a pinned requirement
is preferred, and can add the requirement deterministically before spending an LLM call.
"""
import re

from . import sources

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
        if name not in out and name.lower() not in local and name not in STDLIB_LIKE:
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


def resolve(module, lookup=sources.pypi_latest):
    """(dist, latest version) if the distribution exists on PyPI, else None."""
    dist = dist_for(module)
    try:
        version = lookup(dist)
    except Exception:
        return None
    return (dist, version) if version else None


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
