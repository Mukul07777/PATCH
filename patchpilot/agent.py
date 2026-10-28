"""PatchPilot pipeline: advisory -> triage -> research -> upgrade -> test -> fix loop -> PR."""
import difflib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import config, sources
from .llm import Router
from .sandbox import Sandbox
from .github_pr import open_pull_request

PIN = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")
TEXT_EXT = {".py", ".txt", ".toml", ".cfg", ".ini", ".md"}


class Agent:
    def __init__(self, run_id, repo, emit):
        self.run_id = run_id
        self.repo_src = repo
        self.emit = emit
        self.work = config.WORK_DIR / run_id / "repo"
        self.router = Router(self._emit)
        self.started = time.time()
        self.evidence = []

    # ---------- event helpers ----------
    def _emit(self, ev):
        ev.setdefault("t", round(time.time() - self.started, 2))
        self.emit(ev)

    def step(self, key, status, title=None, **extra):
        self._emit({"type": "step", "key": key, "status": status, "title": title, **extra})

    def log(self, msg, key=None):
        self._emit({"type": "log", "key": key, "msg": msg})

    # ---------- pipeline ----------
    def run(self):
        try:
            self._run()
        except Exception as e:  # surface every failure to the UI
            self._emit({"type": "error", "msg": f"{type(e).__name__}: {e}"})
            self._emit({"type": "done", "ok": False, "usage": self.router.cost_report()})

    def _run(self):
        self.step("models", "running", "Connecting to Nebius Token Factory")
        models = self.router.discover()
        self.step("models", "done", detail=models)

        self.step("checkout", "running", "Checking out repository")
        self._checkout()
        original = self._snapshot()
        pins = self._pins()
        self.step("checkout", "done", detail={"files": len(original), "pins": pins})

        # 1. real advisories from OSV.dev
        self.step("scan", "running", "Scanning dependencies against OSV.dev")
        findings = []
        for name, ver in pins.items():
            vulns = sources.osv_vulns(name, ver)
            latest = sources.pypi_latest(name)
            if vulns:
                findings.append({"package": name, "current": ver, "latest": latest, "vulns": vulns})
            self.log(f"{name}=={ver}: {len(vulns)} advisories, latest {latest}", "scan")
        self._emit({"type": "findings", "findings": findings})
        self.step("scan", "done", detail={"vulnerable": len(findings),
                                           "advisories": sum(len(f["vulns"]) for f in findings)})
        if not findings:
            self._emit({"type": "done", "ok": True, "clean": True, "usage": self.router.cost_report()})
            return

        # 2. Nano triage: is each advisory actually reachable from our code?
        self.step("triage", "running", "Triage with Nemotron Nano")
        triage = self._triage(findings, original)
        self._emit({"type": "triage", "triage": triage})
        self.step("triage", "done")

        # 3. Tavily research: migration guides + breaking changes
        self.step("research", "running", "Researching upgrade paths with Tavily")
        research = {}
        for f in findings:
            q = f"{f['package']} upgrade {f['current']} to {f['latest']} breaking changes migration guide"
            hits = sources.tavily_search(q)
            research[f["package"]] = hits
            self._emit({"type": "research", "package": f["package"], "query": q,
                        "results": [{"title": h["title"], "url": h["url"]} for h in hits]})
        if not config.TAVILY_API_KEY:
            self.log("TAVILY_API_KEY not set - skipping web research", "research")
        self.step("research", "done")

        # 4. Super plans target versions
        self.step("plan", "running", "Planning upgrades with Nemotron Super")
        plan = self._plan(findings, triage)
        self._emit({"type": "plan", "plan": plan})
        self.step("plan", "done")

        # 5. baseline + apply upgrade
        sandbox = Sandbox(self.work, lambda m: self.log(m, "test"))
        self.step("test", "running", "Running baseline tests on current pins")
        ok_install, out = sandbox.install()
        base_ok, base_summary, _ = sandbox.test() if ok_install else (False, "install failed", out)
        self._emit({"type": "test", "label": "baseline", "ok": base_ok, "summary": base_summary})

        self._apply_pins({u["package"]: u["to"] for u in plan["upgrades"]})
        self.log("Bumped: " + ", ".join(f"{u['package']} -> {u['to']}" for u in plan["upgrades"]), "test")
        ok_install, out = sandbox.install()
        if not ok_install:
            raise RuntimeError("pip install failed after upgrade:\n" + out)
        ok, summary, output = sandbox.test()
        self._emit({"type": "test", "label": "after upgrade", "ok": ok, "summary": summary, "output": output[-3000:]})
        self.step("test", "done")

        # 6. fix loop: Super first, escalate to Ultra if it keeps failing
        attempts = 0
        self.step("fix", "running", "Repairing breaking changes")
        while not ok and attempts < config.MAX_FIX_ATTEMPTS:
            attempts += 1
            tier = "super" if attempts == 1 else "ultra"
            self.log(f"Attempt {attempts} with Nemotron {tier.title()}", "fix")
            change = self._fix(tier, plan, research, output, attempts)
            self.evidence += [e for e in change.get("evidence", []) if isinstance(e, dict) and e.get("quote")]
            self._write_files(change.get("files", []))
            self._emit({"type": "patch", "attempt": attempts, "tier": tier,
                        "explanation": change.get("explanation", ""), "evidence": change.get("evidence", [])[:4],
                        "files": [f["path"] for f in change.get("files", [])]})
            ok, summary, output = sandbox.test()
            self._emit({"type": "test", "label": f"attempt {attempts}", "ok": ok, "summary": summary,
                        "output": output[-3000:]})
        self.step("fix", "done" if ok else "failed", detail={"attempts": attempts})

        # 7. diff + report + PR
        diff = self._diff(original)
        self._emit({"type": "diff", "diff": diff})
        report = self._report(findings, triage, plan, research, attempts, ok, base_summary, summary)
        self._emit({"type": "report", "markdown": report})
        pr = None
        if ok and config.GITHUB_TOKEN and str(self.repo_src).startswith("https://github.com/"):
            self.step("pr", "running", "Opening pull request")
            pr = open_pull_request(self.work, self.repo_src, self.run_id, plan, report)
            self.step("pr", "done", detail=pr)
        else:
            self.step("pr", "done" if ok else "failed", detail={"patch": "patchpilot.patch"})
            self.log("Patch file ready (set GITHUB_TOKEN and use a GitHub URL to open a real PR)", "pr")
        (config.WORK_DIR / self.run_id / "patchpilot.patch").write_text(diff, encoding="utf-8")
        self._emit({"type": "done", "ok": ok, "attempts": attempts, "pr": pr,
                    "seconds": round(time.time() - self.started, 1), "usage": self.router.cost_report()})

    # ---------- steps ----------
    def _checkout(self):
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.parent.mkdir(parents=True, exist_ok=True)
        src = str(self.repo_src)
        if src.startswith("https://"):
            if not config.ALLOW_REMOTE_REPOS:
                raise RuntimeError("Remote repositories are disabled on this deployment (ALLOW_REMOTE_REPOS=0)")
            subprocess.run(["git", "clone", "--depth", "1", src, str(self.work)], check=True,
                           capture_output=True, text=True)
        else:
            name = src.removeprefix("case:") or config.DEFAULT_CASE
            path = config.CASES_DIR / name
            if not (path.is_dir() and path.parent == config.CASES_DIR):
                raise RuntimeError(f"Unknown case '{name}'. Use a bundled case or a https:// GitHub URL")
            shutil.copytree(path, self.work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*venv*"))
            subprocess.run(["git", "init", "-q"], cwd=self.work)

    def _snapshot(self):
        files = {}
        for p in self.work.rglob("*"):
            if p.is_file() and p.suffix in TEXT_EXT and ".git" not in p.parts and p.stat().st_size < 60_000:
                files[p.relative_to(self.work).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
        return files

    def _pins(self):
        req = self.work / "requirements.txt"
        if not req.exists():
            raise RuntimeError("No requirements.txt found (PatchPilot currently supports pinned Python projects)")
        pins = {}
        for line in req.read_text().splitlines():
            m = PIN.match(line.split("#")[0])
            if m and m.group(1).lower() != "pytest":
                pins[m.group(1)] = m.group(2)
        return pins

    def _apply_pins(self, targets):
        req = self.work / "requirements.txt"
        lines = []
        lower = {k.lower(): v for k, v in targets.items()}
        for line in req.read_text().splitlines():
            m = PIN.match(line.split("#")[0])
            if m and m.group(1).lower() in lower:
                line = f"{m.group(1)}=={lower[m.group(1).lower()]}"
            lines.append(line)
        req.write_text("\n".join(lines) + "\n")

    def _usage_snippets(self, package, files):
        mod = package.lower().replace("-", "_").replace("pyjwt", "jwt")
        hits = []
        for path, text in files.items():
            if not path.endswith(".py"):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if mod in line.lower():
                    hits.append(f"{path}:{i}: {line.strip()}")
        return hits[:40]

    def _triage(self, findings, files):
        items = []
        for f in findings:
            for v in f["vulns"]:
                items.append({"package": f["package"], "id": v["id"], "cve": v["cve"], "summary": v["summary"],
                              "details": v["details"][:600], "fixed": v["fixed"]})
        usage = {f["package"]: self._usage_snippets(f["package"], files) for f in findings}
        data = self.router.chat_json(
            "nano",
            "You are a security triage engineer. For each advisory decide whether the project's code "
            "actually exercises the vulnerable functionality. Be concise.",
            json.dumps({"advisories": items, "code_usage": usage}),
            "Triage advisories against code usage",
            max_tokens=2048,
        )
        return data.get("advisories") or data.get("results") or data

    def _plan(self, findings, triage):
        data = self.router.chat_json(
            "super",
            "You are a senior engineer planning dependency security upgrades. For each package choose a target "
            "version that fixes ALL listed advisories. Prefer the latest stable release when the fixed versions "
            "span a major version, to avoid repeated migrations. Output: "
            '{"upgrades":[{"package":str,"from":str,"to":str,"breaking":bool,"reason":str}],"risk":str}',
            json.dumps({"findings": [{k: f[k] for k in ("package", "current", "latest")} |
                                     {"fixed_in": sorted({x for v in f["vulns"] for x in v["fixed"]})}
                                     for f in findings], "triage": triage}),
            "Plan target versions",
            max_tokens=2048,
        )
        valid = {f["package"].lower(): f for f in findings}
        ups = []
        for u in data.get("upgrades", []):
            f = valid.get(str(u.get("package", "")).lower())
            if not f:
                continue
            to = str(u.get("to") or f["latest"])
            # guardrail: target must be at or above the highest fixed version of every advisory
            if not all(sources.version_gte(to, v["fixed"][-1]) for v in f["vulns"] if v["fixed"]):
                self.log(f"Guardrail: {f['package']} {to} does not clear all advisories, using {f['latest']}", "plan")
                to = f["latest"]
            ups.append({**u, "package": f["package"], "from": f["current"], "to": to})
        for name, f in valid.items():  # never drop a vulnerable package
            if not any(u["package"].lower() == name for u in ups):
                ups.append({"package": f["package"], "from": f["current"], "to": f["latest"], "breaking": None,
                            "reason": "Added by guardrail: upgrade to latest to clear advisories"})
        data["upgrades"] = ups
        return data

    def _fix(self, tier, plan, research, test_output, attempt):
        files = {k: v for k, v in self._snapshot().items() if k.endswith(".py") and not k.startswith("tests/")}
        notes = {pkg: [{"url": h["url"], "text": h["content"]} for h in hits][:5] for pkg, hits in research.items()}
        system = (
            "You are an expert Python engineer fixing code broken by a security dependency upgrade. "
            "The dependency versions are FIXED and must not be downgraded. Do not edit tests; make the source "
            "code compatible with the new library versions while preserving behaviour and security. "
            "Return the COMPLETE new content of every file you change. In evidence, quote the exact line(s) from "
            "migration_research (with its url) that justify each change; use an empty list if research did not help. Output: "
            '{"explanation":str,"evidence":[{"url":str,"quote":str}],"files":[{"path":str,"content":str}]}'
        )
        user = json.dumps({
            "attempt": attempt, "upgrades": plan["upgrades"], "migration_research": notes,
            "failing_test_output": test_output[-6000:], "source_files": files,
        })
        return self.router.chat_json(tier, system, user, f"Fix attempt {attempt}", max_tokens=8192)

    def _write_files(self, changes):
        for c in changes:
            rel = str(c.get("path", "")).replace("\\", "/").lstrip("/")
            target = (self.work / rel).resolve()
            if not rel or self.work.resolve() not in target.parents or rel.startswith("tests/"):
                self.log(f"Rejected write outside allowed paths: {rel}", "fix")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(c["content"], encoding="utf-8")

    def _diff(self, original):
        now = self._snapshot()
        chunks = []
        for path in sorted(set(original) | set(now)):
            a, b = original.get(path, ""), now.get(path, "")
            if a != b:
                chunks += difflib.unified_diff(a.splitlines(True), b.splitlines(True), f"a/{path}", f"b/{path}")
        return "".join(chunks)

    def _report(self, findings, triage, plan, research, attempts, ok, base, final):
        lines = ["## PatchPilot security upgrade", ""]
        lines.append("### Advisories resolved")
        for f in findings:
            for v in f["vulns"]:
                lines.append(f"- **{f['package']} {f['current']}** - [{v['cve'] or v['id']}]({v['url']}): {v['summary']}")
        lines += ["", "### Upgrades"]
        for u in plan["upgrades"]:
            lines.append(f"- `{u['package']}` {u['from']} -> **{u['to']}** - {u.get('reason', '')}")
        lines += ["", "### Verification", f"- Baseline (old pins): `{base}`", f"- Final: `{final}`",
                  f"- Fix attempts: {attempts}", f"- Status: {'all tests passing' if ok else 'needs human review'}"]
        if self.evidence:
            lines += ["", "### Why these changes (evidence quoted by the agent)"]
            for e in self.evidence[:5]:
                lines += [f"> {e['quote'].strip()[:300]}", f"> — {e.get('url') or 'migration notes'}", ""]
        refs = [h for hits in research.values() for h in hits if h.get("url")]
        if refs:
            lines += ["", "### Sources consulted (Tavily)"] + [f"- [{h['title']}]({h['url']})" for h in refs[:8]]
        lines += ["", "### Models (NVIDIA Nemotron on Nebius Token Factory)"]
        for tier, u in self.router.usage.items():
            if u["calls"]:
                lines.append(f"- {tier}: `{self.router.models[tier]}` - {u['calls']} calls, {u['in']}+{u['out']} tokens")
        return "\n".join(lines)
