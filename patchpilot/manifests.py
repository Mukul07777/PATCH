"""Python dependency manifest parsers: requirements.txt, pyproject.toml (PEP 621 + Poetry), poetry.lock, uv.lock,
Pipfile.lock. Pure text parsing: nothing is installed, imported or executed, and -r/-c includes are never followed."""
import json
import re
import tomllib
from collections import namedtuple

Dep = namedtuple("Dep", "name version source_file pinned")

# Names checked, in this order, when a project folder or repository is scanned
MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock")
NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
EXACT = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
POETRY_EXACT = re.compile(r"^=?=?\s*(\d[A-Za-z0-9._+!-]*)$")


class ManifestError(ValueError):
    pass


def kind_of(filename):
    """Parser kind for a file name, or None if unsupported. Any *.txt is read as a requirements file."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base in ("pyproject.toml", "poetry.lock", "uv.lock", "pipfile.lock"):
        return base
    if base.endswith(".txt") or base.endswith(".in"):
        return "requirements"
    return None


def parse(filename, text):
    kind = kind_of(filename)
    if kind is None:
        raise ManifestError(f"Unsupported manifest '{filename}'. Use requirements.txt, pyproject.toml, poetry.lock, "
                            "uv.lock or Pipfile.lock")
    fn = {"requirements": parse_requirements, "pyproject.toml": parse_pyproject, "poetry.lock": parse_lock,
          "uv.lock": parse_lock, "pipfile.lock": parse_pipfile_lock}[kind]
    return fn(text, filename)


def pep508(spec, source_file):
    """One PEP 508 requirement string -> Dep (version only for an exact == pin), or None if not a plain package."""
    spec = spec.split(";", 1)[0].strip()  # drop environment markers
    if not spec or "@" in spec or "://" in spec:
        return None  # direct URL / VCS reference: no PyPI version to look up
    m = NAME.match(spec)
    if not m:
        return None
    rest = m.group(2).strip().strip("()").strip()
    pin = EXACT.match(rest)
    if pin and "*" not in pin.group(1):
        return Dep(m.group(1), pin.group(1), source_file, True)
    return Dep(m.group(1), None, source_file, False)


def parse_requirements(text, source_file="requirements.txt"):
    out, buf = [], ""
    for raw in text.splitlines():
        line = buf + raw
        if line.rstrip().endswith("\\"):  # line continuation
            buf = line.rstrip()[:-1] + " "
            continue
        buf = ""
        line = re.split(r"(?:^|\s)#", line, 1)[0].strip()
        if not line or line.startswith("-"):  # options, -r/-c includes, -e editables: never followed
            continue
        line = re.split(r"\s--?\w", line, 1)[0]  # trailing per-line options such as --hash
        dep = pep508(line, source_file)
        if dep:
            out.append(dep)
    return out


def _toml(text, source_file):
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ManifestError(f"{source_file}: invalid TOML ({e})") from None


def _poetry_dep(name, spec, source_file):
    if name.lower() == "python":
        return None
    if isinstance(spec, list):  # multiple-constraint form: unpinned for our purposes
        return Dep(name, None, source_file, False)
    if isinstance(spec, dict):
        if any(k in spec for k in ("git", "path", "url")):
            return None
        spec = spec.get("version", "")
    m = POETRY_EXACT.match(str(spec).strip())
    return Dep(name, m.group(1), source_file, True) if m else Dep(name, None, source_file, False)


def parse_pyproject(text, source_file="pyproject.toml"):
    data = _toml(text, source_file)
    out = []
    project = data.get("project") or {}
    specs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs += list(group or [])
    for group in (data.get("dependency-groups") or {}).values():
        specs += [s for s in group or [] if isinstance(s, str)]
    out += [d for d in (pep508(s, source_file) for s in specs if isinstance(s, str)) if d]
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
    tables += [(g or {}).get("dependencies") or {} for g in (poetry.get("group") or {}).values()]
    for table in tables:
        out += [d for d in (_poetry_dep(n, s, source_file) for n, s in table.items()) if d]
    return out


def parse_lock(text, source_file):
    """poetry.lock and uv.lock both list resolved packages as [[package]] name/version tables."""
    data = _toml(text, source_file)
    out = []
    for pkg in data.get("package") or []:
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source") or {}
        # uv: {editable|virtual|directory|path|git|url = ...}; poetry: type = git|directory|file|url (legacy = a mirror)
        local = any(k in source for k in ("editable", "virtual", "directory", "path", "git")) or (
            "url" in source and "type" not in source)
        if not name or not version or local or source.get("type") in ("git", "directory", "file", "url"):
            continue  # the project itself or a non-PyPI source
        out.append(Dep(name, str(version), source_file, True))
    return out


def parse_pipfile_lock(text, source_file="Pipfile.lock"):
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ManifestError(f"{source_file}: invalid JSON ({e})") from None
    if not isinstance(data, dict):
        raise ManifestError(f"{source_file}: expected a JSON object")
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = (info or {}).get("version", "") if isinstance(info, dict) else ""
            m = EXACT.match(ver.strip())
            out.append(Dep(name, m.group(1), source_file, True) if m else Dep(name, None, source_file, False))
    return out


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def merge(deps):
    """Deduplicate across manifests: one entry per (package, version); an unpinned mention is dropped
    when the same package is pinned elsewhere (e.g. pyproject range + lock file pin)."""
    pinned = {normalize(d.name) for d in deps if d.version}
    out, seen = [], set()
    for d in deps:
        key = (normalize(d.name), d.version)
        if key in seen or (d.version is None and key[0] in pinned):
            continue
        seen.add(key)
        out.append(d)
    return out
