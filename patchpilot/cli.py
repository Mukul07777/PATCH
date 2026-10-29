"""Command line: `python -m patchpilot scan | serve | fix` (see patchpilot/__main__.py).

  python -m patchpilot fix case:authsvc https://github.com/org/repo ...   (also: python -m patchpilot.cli ...)

Fix mode runs the agent on each repo, records events to runs/<id>.jsonl, and writes runs/batch-summary.json.
Scan mode (scan_main) needs no server, database or LLM key: manifests are parsed locally and only OSV.dev,
FIRST EPSS, CISA KEV and PyPI are contacted (plus the GitHub API for --repo).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import config


def run_one(repo):
    run_id = time.strftime("%Y%m%d-%H%M%S-") + "job"
    path = config.RUNS_DIR / f"{run_id}.jsonl"
    result = {}

    def emit(ev):
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        if ev["type"] in ("step", "test", "error"):
            print(f"[{repo}] {ev['type']}: {ev.get('key') or ev.get('label') or ''} {ev.get('status') or ev.get('summary') or ev.get('msg') or ''}",
                  flush=True)
        if ev["type"] == "done":
            result.update(ev)
        elif ev["type"] == "findings":
            result["advisories"] = sum(len(f["vulns"]) for f in ev["findings"])
        elif ev["type"] == "exploit" and ev.get("stage") == "after":
            result["exploit"] = ev.get("verdict")
        elif ev["type"] == "redteam" and ev.get("stage") == "after":
            result["redteam"] = {"blocked": len(ev["rows"]) - ev["open"], "total": len(ev["rows"])}
        elif ev["type"] == "ledger":
            result["trust"] = ev.get("trust")

    from .agent import Agent  # imported lazily: scan mode never needs the LLM stack

    emit({"type": "start", "repo": repo, "t": 0})
    Agent(run_id, repo, emit).run()
    return {"repo": repo, "run": run_id, "ok": result.get("ok"), "attempts": result.get("attempts"),
            "seconds": result.get("seconds"), "usage": result.get("usage"), "advisories": result.get("advisories"),
            "exploit": result.get("exploit"), "redteam": result.get("redteam"), "trust": result.get("trust"),
            "provider": result.get("provider") or config.provider_name(), "models": result.get("models"),
            "proven": result.get("proven")}


def main(argv):
    config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    repos = argv or [f"case:{p.name}" for p in sorted(config.CASES_DIR.iterdir()) if (p / "requirements.txt").exists()]
    results = [run_one(r) for r in repos]
    (config.RUNS_DIR / "batch-summary.json").write_text(json.dumps(results, indent=2))
    print(json.dumps([{k: r[k] for k in ("repo", "ok", "attempts", "seconds")} for r in results], indent=2))
    return 0 if all(r["ok"] for r in results) else 1


# ---------- scan mode ----------
FAIL_ON = ("low", "moderate", "high", "critical", "none")
FORMATS = ("table", "json", "sarif", "cyclonedx")
_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}


class CliError(Exception):
    pass


def scan_parser():
    p = argparse.ArgumentParser(prog="python -m patchpilot scan",
                                description="Scan Python dependency manifests for known vulnerabilities (OSV.dev).")
    p.add_argument("target", nargs="?", default=".", help="folder or manifest file (default: current folder)")
    p.add_argument("--repo", help="scan a GitHub repository instead: https://github.com/owner/repo")
    p.add_argument("--ref", help="branch, tag or commit for --repo (default: the default branch)")
    p.add_argument("--subdir", default="", help="only manifests below this folder (monorepos)")
    p.add_argument("--format", choices=FORMATS, default="table")
    p.add_argument("--fail-on", choices=FAIL_ON, default="high",
                   help="exit 1 when a finding is at least this severe (default: high; unrated counts as low)")
    p.add_argument("--ignore", action="append", default=[], metavar="ID",
                   help="advisory id or alias to ignore (repeatable)")
    p.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    return p


def _rel(path):
    try:
        return Path(path).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return Path(path).resolve().as_posix()


def _read_target(args):
    """(files, notes, skipped, info, prefix) for the CLI target."""
    from . import manifests, scanner
    if args.repo:
        files, notes, skipped, info = scanner._fetch_github(args.repo, args.ref, args.subdir)
        return files, notes, skipped, info, ""
    target = Path(args.target)
    if target.is_file():
        if manifests.kind_of(target.name) is None:
            raise CliError(f"{target} is not a supported manifest (requirements*.txt, pyproject.toml, poetry.lock, "
                           "uv.lock, Pipfile.lock)")
        if target.stat().st_size > manifests.size_limit(target.name):
            raise CliError(f"{target} is larger than {manifests.size_limit(target.name) // 1_000_000} MB")
        return [(_rel(target), target.read_text(encoding="utf-8", errors="replace"))], [], [], None, ""
    if target.is_dir():
        files, notes, skipped = scanner._read_dir(target, args.subdir)
        rel = _rel(target)
        return files, notes, skipped, None, "" if rel in (".", "") else rel + "/"
    raise CliError(f"{target}: no such file or folder")


def _prefixed(findings, summary, prefix):
    """Make manifest paths relative to the current folder (what SARIF consumers resolve against)."""
    if not prefix:
        return
    for f in findings:
        f["source_file"] = ", ".join(prefix + x for x in (f.get("source_file") or "").split(", ") if x)
    summary["files"] = [prefix + x for x in summary["files"]]
    summary["deps"] = [[n, v, prefix + (src or ""), line] for n, v, src, line in summary["deps"]]


def _apply_ignores(findings, ignores):
    ign = {i.upper() for i in ignores}
    for f in findings:
        hit = next((i for i in [f["vuln_id"], *(f.get("aliases") or [])] if i.upper() in ign), None)
        f["suppressed"] = f"ignored: {hit}" if hit else None


def failing(findings, fail_on):
    """Unsuppressed findings at or above the --fail-on threshold (unrated advisories count as low)."""
    if fail_on == "none":
        return []
    floor = FAIL_ON.index(fail_on)

    def rank(f):
        s = (f.get("severity") or "").upper()
        return _RANK.get("MODERATE" if s == "MEDIUM" else s, 0)
    return [f for f in findings if not f.get("suppressed") and rank(f) >= floor]


def table(findings, summary):
    rows = [f for f in findings if not f.get("suppressed")]
    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    rows.sort(key=lambda f: (order.get((f.get("severity") or "").upper(), 4), f["package"].lower(), f["vuln_id"]))
    head = ("SEVERITY", "PACKAGE", "VERSION", "ADVISORY", "FIXED IN", "WHERE")
    data = [((f.get("severity") or "unrated").lower() + (" KEV" if f.get("kev") else ""), f["package"],
             f.get("version") or "", f["vuln_id"], f.get("fixed_in") or "-",
             f"{(f.get('source_file') or '').split(', ')[0]}:{f.get('source_line') or '?'}") for f in rows]
    out = []
    if data:
        w = [max(len(str(r[i])) for r in [head, *data]) for i in range(len(head))]
        for r in [head, *data]:
            out.append("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)).rstrip())
    cov = summary["coverage"]
    supp = sum(1 for f in findings if f.get("suppressed"))
    out.append(f"{len(rows)} finding{'' if len(rows) == 1 else 's'} in {len({f['package'].lower() for f in rows})} "
               f"package(s); {cov['checked']} of {cov['total']} dependencies checked ({cov['state']})"
               + (f"; {supp} ignored" if supp else ""))
    return "\n".join(out) + "\n"


def scan_main(argv):
    """Exit 0: nothing at or above --fail-on. 1: findings at or above it. 2: the scan could not be completed."""
    args = scan_parser().parse_args(argv)
    config.NO_DB = True
    from . import export, scanner
    try:
        files, notes, skipped, info, prefix = _read_target(args)
        findings, summary = scanner.scan_files(files, notes, skipped, info)
    except (CliError, scanner.ScanError, OSError) as e:
        print(f"patchpilot: error: {e}", file=sys.stderr)
        return 2
    _prefixed(findings, summary, prefix)
    _apply_ignores(findings, args.ignore)
    for w in summary["warnings"] + summary["errors"]:
        print(f"patchpilot: {w}", file=sys.stderr)
    if summary["pinned"] and summary["coverage"]["checked"] == 0:
        print("patchpilot: error: no dependency could be checked (OSV unreachable)", file=sys.stderr)
        return 2
    report = {"name": args.repo or _rel(args.target), "findings": findings, "deps": summary["deps"],
              "files": summary["files"], "commit": summary.get("commit"), "repository": args.repo,
              "summary": {k: v for k, v in summary.items() if k != "deps"}}
    text = table(findings, summary) if args.format == "table" else export.render(report, args.format) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"patchpilot: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    bad = failing(findings, args.fail_on)
    if bad:
        print(f"patchpilot: {len(bad)} finding(s) at or above '{args.fail_on}'", file=sys.stderr)
        return 1
    return 0


def serve_main(argv):
    p = argparse.ArgumentParser(prog="python -m patchpilot serve", description="Start the PatchPilot web server.")
    p.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    args = p.parse_args(argv)
    import uvicorn
    uvicorn.run("patchpilot.server:app", host=args.host, port=args.port, proxy_headers=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
