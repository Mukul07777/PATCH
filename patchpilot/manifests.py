"""Python dependency manifest parsers: requirements.txt, pyproject.toml (PEP 621 + Poetry), poetry.lock, uv.lock,
Pipfile.lock. Pure text parsing: nothing is installed, imported or executed, and -r/-c includes are never followed."""
import json
import posixpath
import re
import tomllib
from collections import namedtuple

from packaging.requirements import InvalidRequirement, Requirement

Dep = namedtuple("Dep", "name version source_file pinned line", defaults=(None,))  # line: 1-based, where declared

# Names checked, in this order, when a project folder or repository is scanned
MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock")
LOCK_FILES = ("poetry.lock", "uv.lock", "pipfile.lock")
MAX_MANIFEST = 1_000_000  # bytes: requirements*.txt / pyproject.toml
MAX_LOCK = 5_000_000  # bytes: lock files list every transitive package and get big
MAX_DEPTH = 3  # folders below the repository root searched for manifests
MAX_FILES = 40  # manifests read per scan
# Folders never searched: virtualenvs, vendored code and test fixtures (their pins are not your dependencies)
SKIP_DIRS = {"node_modules", ".venv", "venv", "env", ".env", ".tox", ".nox", ".git", "site-packages", "vendor",
             "vendored", "_vendor", "third_party", "fixtures", "testdata", "test_data", "__pycache__", "build", "dist"}
NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
EXACT = re.compile(r"^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
DECL = re.compile(r"""^\s*(?:name\s*=\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)["']|"([A-Za-z0-9][A-Za-z0-9._-]*)"\s*:\s*\{)""")
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


def is_lock(filename):
    return kind_of(filename) in LOCK_FILES


def size_limit(filename):
    return MAX_LOCK if is_lock(filename) else MAX_MANIFEST


def is_manifest_path(path):
    """True for the files a repository scan reads: requirements*.txt (and any .txt in a requirements/ folder),
    pyproject.toml and the three lock files."""
    parts = path.replace("\\", "/").split("/")
    base, dirs = parts[-1].lower(), [d.lower() for d in parts[:-1]]
    if len(dirs) > MAX_DEPTH or any(d in SKIP_DIRS or (d.startswith(".") and d != ".") for d in dirs):
        return False
    if base in ("pyproject.toml", "poetry.lock", "uv.lock", "pipfile.lock"):
        return True
    return base.endswith(".txt") and (base.startswith("requirements") or (dirs and dirs[-1] == "requirements"))


def select(paths, subdir=""):
    """Manifest paths to read from a repository listing, lock files preferred: a pyproject.toml is skipped when
    a lock file sits next to it (the lock has the exact versions). Returns (chosen, notes)."""
    subdir = subdir.strip("/")
    cand = [p for p in paths if is_manifest_path(p) and (not subdir or p.startswith(subdir + "/"))]
    locked = {posixpath.dirname(p) for p in cand if is_lock(p)}
    notes = []
    out = []
    for p in sorted(cand, key=lambda p: (p.count("/"), p.lower())):
        if posixpath.basename(p).lower() == "pyproject.toml" and posixpath.dirname(p) in locked:
            continue
        out.append(p)
    if len(out) > MAX_FILES:
        notes.append(f"{len(out)} manifests found; only the {MAX_FILES} nearest the root were read")
        out = out[:MAX_FILES]
    return out, notes


def parse(filename, text):
    return parse_ex(filename, text)[0]


def parse_ex(filename, text):
    """(deps, warnings) for one manifest; warnings name lines that were deliberately not followed."""
    kind = kind_of(filename)
    if kind is None:
        raise ManifestError(f"Unsupported manifest '{filename}'. Use requirements.txt, pyproject.toml, poetry.lock, "
                            "uv.lock or Pipfile.lock")
    if kind == "requirements":
        return requirements_ex(text, filename)
    fn = {"pyproject.toml": parse_pyproject, "poetry.lock": parse_lock, "uv.lock": parse_lock,
          "pipfile.lock": parse_pipfile_lock}[kind]
    return locate(fn(text, filename), text), []


def locate(deps, text):
    """Fill each Dep's line from the text in one pass: a `name = "pkg"` table entry (lock files) or a
    `"pkg": {` key (Pipfile.lock); otherwise, for small files, the first line naming the package as a whole word
    (pyproject dependency lists)."""
    lines = text.splitlines()
    index = {}
    for i, l in enumerate(lines, 1):
        m = DECL.match(l)
        if m:
            index.setdefault(normalize(m.group(1) or m.group(2)), i)
    out = []
    for d in deps:
        if d.line is None:
            hit = index.get(normalize(d.name))
            if hit is None and len(text) <= 200_000:
                word = re.compile(rf"(?<![\w.-]){re.escape(d.name)}(?![\w-])", re.I)
                hit = next((i for i, l in enumerate(lines, 1) if word.search(l)), None)
            d = d._replace(line=hit)
        out.append(d)
    return out


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


INCLUDE = re.compile(r"^(-r|--requirement|-c|--constraint)\s*=?\s*(\S+)")
EDITABLE = re.compile(r"^(-e|--editable)\s*=?\s*(\S+)")


def _lines(text):
    for _, line in _numbered(text):
        yield line


def _numbered(text):
    """(1-based line number where the logical line starts, line) with comments and continuations folded."""
    buf, start = "", None
    for n, raw in enumerate(text.splitlines(), 1):
        start = n if not buf else start
        line = buf + raw
        if line.rstrip().endswith("\\"):  # line continuation
            buf = line.rstrip()[:-1] + " "
            continue
        buf = ""
        line = re.split(r"(?:^|\s)#", line, 1)[0].strip()
        if line:
            yield start, line


def requirements_ex(text, source_file="requirements.txt"):
    """(deps, warnings). Includes (-r/-c), editables (-e) and URL / VCS requirements are never followed or
    fetched; each one becomes a warning so the user knows what was not checked."""
    out, warnings = [], []
    for lineno, line in _numbered(text):
        m = INCLUDE.match(line)
        if m:
            what = "constraints file" if m.group(1) in ("-c", "--constraint") else "file"
            warnings.append(f"{source_file}: '{m.group(1)} {m.group(2)}' not followed; upload that {what} too")
            continue
        m = EDITABLE.match(line)
        if m:
            warnings.append(f"{source_file}: editable '{m.group(2)[:80]}' not checked (local or VCS source)")
            continue
        if line.startswith("-"):  # index / hash / other pip options
            continue
        line = re.split(r"\s--?\w", line, 1)[0]  # trailing per-line options such as --hash
        if "://" in line or re.match(r"^[\w.-]+\s*(\[[^\]]*\])?\s*@", line):
            warnings.append(f"{source_file}: '{line[:80]}' is a URL / VCS requirement; not checked against OSV")
            continue
        dep = pep508(line, source_file)
        if dep:
            out.append(dep._replace(line=lineno))
    return out, warnings


def parse_requirements(text, source_file="requirements.txt"):
    return requirements_ex(text, source_file)[0]


def _requirement_ok(line):
    """True for a line pip would accept: an option, or a PEP 508 requirement (name + valid specifier)."""
    if line.startswith("-") or "://" in line:
        return True
    try:
        Requirement(re.split(r"\s--?\w", line, 1)[0])
        return True
    except InvalidRequirement:
        return False


def check_upload(filename, text):
    """Reject uploads that are not text manifests (binary, mostly non-printable, or mostly unparsable lines)."""
    if "\x00" in text:
        raise ManifestError(f"{filename} is a binary file, not a dependency manifest")
    sample = text[:200_000]
    bad = sum(1 for c in sample if not (c.isprintable() or c in "\r\n\t"))
    if sample and bad / len(sample) > 0.05:
        raise ManifestError(f"{filename} doesn't look like a text manifest (too many non-printable characters)")
    if kind_of(filename) == "requirements":
        lines = list(_lines(text))
        unparsable = [l for l in lines if not _requirement_ok(l)]
        if lines and len(unparsable) * 2 > len(lines):
            raise ManifestError(f"{filename} doesn't look like a requirements file: {len(unparsable)} of "
                                f"{len(lines)} lines are not valid requirements (e.g. '{unparsable[0][:60]}')")


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
