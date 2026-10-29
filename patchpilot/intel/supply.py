"""Supply-chain intelligence beyond CVEs: typosquats, known-malicious packages, licenses and package health.

A CVE scan answers "is this version vulnerable?". It says nothing about a package that was malicious from day
one, a name one keystroke away from a popular one, a GPL dependency inside a proprietary product, a version the
maintainer yanked, or a project nobody has released in years. Every check here works from public data (PyPI JSON
API, OSV MAL- advisories) and plain string analysis; no model is involved.
"""
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from patchpilot.intel import sources

# Well-known PyPI distributions: the names typosquatters imitate. Reference data, not results.
POPULAR = """
boto3 botocore urllib3 requests setuptools certifi idna charset-normalizer typing-extensions python-dateutil
packaging s3transfer six aiobotocore numpy pyyaml cryptography pip grpcio-status fsspec s3fs pydantic cffi
google-api-core attrs pycparser pandas importlib-metadata protobuf jmespath rsa pyasn1 wheel zipp click markupsafe
jinja2 platformdirs pydantic-core pytz colorama awscli filelock tomli pluggy virtualenv pyjwt wrapt jsonschema
cachetools pytest googleapis-common-protos sqlalchemy psutil aiohttp pyarrow werkzeug flask django fastapi
starlette uvicorn gunicorn httpx httpcore anyio sniffio h11 tqdm scipy matplotlib pillow lxml beautifulsoup4
soupsieve openpyxl redis celery kombu billiard vine amqp psycopg2 psycopg2-binary pymysql mysqlclient pymongo
paramiko bcrypt pynacl docker kubernetes requests-oauthlib oauthlib google-auth tensorflow torch keras
scikit-learn transformers tokenizers huggingface-hub openai anthropic langchain tiktoken regex rich pygments
decorator greenlet tornado websocket-client websockets pyopenssl coverage mock black isort flake8 mypy pylint
toml tomlkit sphinx docutils babel alembic marshmallow itsdangerous blinker pexpect ptyprocess ipython
jupyter notebook selenium scrapy twisted pyparsing networkx sympy nltk opencv-python simplejson ujson orjson
msgpack xmltodict defusedxml chardet html5lib python-dotenv pyserial pywin32 colorlog loguru structlog sentry-sdk
"""
POPULAR_SET = set(POPULAR.split())

# Licenses that impose obligations on the distributor of a combined work
STRONG = re.compile(r"\b(A?GPL|GNU (Affero )?General Public|SSPL|Server Side Public|EUPL|OSL)\b", re.I)
WEAK = re.compile(r"\b(LGPL|Lesser General|MPL|Mozilla Public|EPL|Eclipse Public|CDDL)\b", re.I)
PERMISSIVE = re.compile(r"\b(MIT|BSD|Apache|ISC|PSF|Python Software Foundation|Unlicense|Zlib|0BSD|CC0|HPND|"
                        r"Public Domain|Historical Permission)\b", re.I)

STALE_DAYS = 730  # no release for two years: likely unmaintained
NEW_DAYS = 90  # first release under three months ago: too new to trust blindly

_cache, _cache_lock = {}, threading.Lock()
CACHE_TTL = 6 * 3600


def norm(name):
    return re.sub(r"[-_.]+", "-", (name or "").lower())


def distance(a, b, cap=3):
    """Damerau-Levenshtein distance (adjacent swaps count as one edit), stopping early above cap."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def typosquat(name):
    """The popular package this name imitates, or None. Catches one or two edits, swapped letters, a separator
    trick (python-requests vs requests) and a popular name with a decoy prefix or suffix (requests-py)."""
    n = norm(name)
    if n in POPULAR_SET or len(n) < 4:
        return None
    for p in POPULAR_SET:
        if len(p) < 4:
            continue
        d = distance(n, p, 2)
        if d == 1 or (d == 2 and len(p) >= 8):
            return {"imitates": p, "why": f"{d} edit{'s' if d > 1 else ''} away from '{p}'"}
        flat, pflat = n.replace("-", ""), p.replace("-", "")
        if flat == pflat:
            return {"imitates": p, "why": f"same letters as '{p}' with different separators"}
        for affix in ("python-", "py-", "-py", "-python", "-lib", "lib-", "-dev", "-sdk", "-api"):
            if n in (affix + p, p + affix) and len(p) >= 5:
                return {"imitates": p, "why": f"'{p}' with a decoy '{affix.strip('-')}' added"}
    return None


def license_of(info):
    """(license text, class) from PyPI metadata: license_expression, then classifiers, then the license field."""
    text = (info.get("license_expression") or "").strip()
    if not text:
        cls = [c.split("::")[-1].strip() for c in info.get("classifiers") or [] if c.startswith("License ::")]
        text = "; ".join(c for c in cls if c != "OSI Approved")
    if not text:
        raw = (info.get("license") or "").strip()
        text = raw.splitlines()[0][:80] if raw and len(raw) < 2000 else ("custom license text" if raw else "")
    if not text:
        return "unknown", "unknown"
    if STRONG.search(text) and not WEAK.search(text) and "LGPL" not in text.upper():
        return text, "strong-copyleft"
    if WEAK.search(text):
        return text, "weak-copyleft"
    if PERMISSIVE.search(text):
        return text, "permissive"
    return text, "unknown"


def _date(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    except ValueError:
        return None


def health(data, version, now=None):
    """Maintenance signals from a PyPI JSON document for one pinned version."""
    now = now or datetime.now(timezone.utc)
    info, releases = data.get("info") or {}, data.get("releases") or {}
    dates = {}
    for v, files in releases.items():
        ts = [_date(f.get("upload_time_iso_8601") or (f.get("upload_time", "") + "Z")) for f in files or []]
        ts = [t for t in ts if t]
        if ts:
            dates[v] = min(ts)
    last = max(dates.values()) if dates else None
    first = min(dates.values()) if dates else None
    files = releases.get(version) or []
    yanked = bool(files) and all(f.get("yanked") for f in files)
    reason = next((f.get("yanked_reason") for f in files if f.get("yanked_reason")), None)
    inactive = any("Development Status :: 7 - Inactive" in c for c in info.get("classifiers") or [])
    days_since = (now - last).days if last else None
    return {"latest": info.get("version"), "last_release": last.date().isoformat() if last else None,
            "days_since_release": days_since, "first_release": first.date().isoformat() if first else None,
            "age_days": (now - first).days if first else None, "releases": len(dates),
            "yanked": yanked, "yanked_reason": reason, "inactive": inactive,
            "stale": days_since is not None and days_since > STALE_DAYS,
            "new": first is not None and (now - first).days < NEW_DAYS,
            "repo": next((u for k, u in (info.get("project_urls") or {}).items()
                          if re.search(r"source|code|repo|github|homepage", k, re.I) and "github.com" in (u or "")),
                         None)}


def established(data, now=None):
    """True when a PyPI project has a long, real history (a year old and five or more releases)."""
    h = health(data, None, now)
    return (h["age_days"] or 0) >= 365 and h["releases"] >= 5


def _pypi(name):
    key = norm(name)
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
    try:
        data = sources.pypi_json(name)
    except Exception as e:
        data = {"error": f"{type(e).__name__}"}
    with _cache_lock:
        _cache[key] = (time.monotonic(), data)
    return data


def analyse(deps, malicious_ids=None, limit=300):
    """One row per dependency [(name, version or None)] plus a summary. malicious_ids maps a normalized package
    name to OSV MAL- advisory ids already found by the vulnerability scan."""
    malicious_ids = malicious_ids or {}
    deps = list(dict.fromkeys((n, v) for n, v in deps))[:limit]
    with ThreadPoolExecutor(8) as pool:
        docs = dict(zip([n for n, _ in deps], pool.map(_pypi, [n for n, _ in deps])))
    rows = []
    for name, version in deps:
        data = docs.get(name) or {}
        info = data.get("info") or {}
        lic, lic_class = license_of(info) if info else ("unknown", "unknown")
        h = health(data, version) if info and version else {}
        flags = []
        mal = malicious_ids.get(norm(name)) or []
        if mal:
            flags.append({"level": "critical", "kind": "malicious", "text": "Known malicious package: " + ", ".join(mal)})
        squat = typosquat(name)
        # a lookalike name alone is weak evidence (authlib vs oauthlib); squats are new, short-lived or unlisted
        if squat and (not info or established(data) is False):
            flags.append({"level": "high", "kind": "typosquat", "text": f"Possible typosquat: {squat['why']}"
                          + ("" if not info else "; published recently with few releases")})
        if data.get("error") and not info:
            flags.append({"level": "medium", "kind": "not-on-pypi",
                          "text": "Not found on PyPI: private package, typo, or a dependency-confusion target"})
        if h.get("yanked"):
            flags.append({"level": "high", "kind": "yanked", "text": f"Pinned version {version} was yanked by the "
                          "maintainer" + (f": {h['yanked_reason']}" if h.get("yanked_reason") else "")})
        if h.get("inactive"):
            flags.append({"level": "medium", "kind": "inactive", "text": "Marked 'Development Status :: Inactive'"})
        elif h.get("stale"):
            flags.append({"level": "medium", "kind": "stale",
                          "text": f"No release for {h['days_since_release'] // 365} years (last {h['last_release']})"})
        if h.get("new"):
            flags.append({"level": "medium", "kind": "new",
                          "text": f"First published {h['age_days']} days ago with {h['releases']} release(s)"})
        if lic_class == "strong-copyleft":
            flags.append({"level": "medium", "kind": "license", "text": f"Strong copyleft license ({lic}): "
                          "distributing a combined work may require releasing its source"})
        elif lic_class == "unknown" and info:
            flags.append({"level": "low", "kind": "license", "text": "License not declared in PyPI metadata"})
        rows.append({"package": name, "version": version, "license": lic, "license_class": lic_class,
                     "health": h, "flags": flags})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda r: (min((order[f["level"]] for f in r["flags"]), default=9), r["package"].lower()))
    count = lambda k: sum(1 for r in rows for f in r["flags"] if f["kind"] == k)
    lic = {}
    for r in rows:
        lic[r["license_class"]] = lic.get(r["license_class"], 0) + 1
    return {"packages": rows, "checked": len(rows),
            "summary": {"malicious": count("malicious"), "typosquat": count("typosquat"), "yanked": count("yanked"),
                        "stale": count("stale") + count("inactive"), "new": count("new"),
                        "not_on_pypi": count("not-on-pypi"), "licenses": lic,
                        "flagged": sum(1 for r in rows if r["flags"])}}
