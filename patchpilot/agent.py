"""PatchPilot pipeline: advisory -> triage -> research -> upgrade -> test -> fix loop -> PR."""
import difflib
import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import config, deps, drift, exploits, guard, reach, sources, vex
from .llm import LLMError, Router, parse_json
from .sandbox import Sandbox
from .github_pr import open_pull_request

log = logging.getLogger(__name__)

PIN = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")
TEXT_EXT = {".py", ".txt", ".toml", ".cfg", ".ini", ".md"}
# lives in a dot-dir: the normal pytest run skips it and the diff ignores it
EXPLOIT_TEST = ".patchpilot/test_exploit.py"
MUTATION_TEST = ".patchpilot/test_mutations.py"


def extract_test_code(text):
    """Pull a compilable pytest file out of a reply (content or leaked reasoning); None if there isn't one."""
    blocks = re.findall(r"```(?:python|py)?[ \t]*\n(.*?)```", text or "", re.S)
    if not blocks and "def test" in (text or ""):
        blocks = [text]
    for code in sorted(blocks, key=len, reverse=True):
        code = code.strip()
        if not re.search(r"^def test\w*\(", code, re.M):
            continue
        try:
            compile(code, "test_exploit.py", "exec")
        except SyntaxError:
            continue
        return code + "\n"
    return None


class Agent:
    def __init__(self, run_id, repo, emit):
        self.run_id = run_id
        self.repo_src = repo
        self.emit = emit
        self.work = config.WORK_DIR / run_id / "repo"
        self.router = Router(self._emit)
        self.started = time.time()
        self.evidence = []
        self.drift = []
        self.trust = {}
        self.reach = {}
        self.guarded = []  # one entry per screened piece of AI-written code
        self.dep_hints = []  # missing-module hints for the repair prompt
        self.original_imports = set()  # top-level imports of the checked-out repo, captured before LLM edits
        self.deps_added = []  # requirements added deterministically by the dependency pre-repair step
        self.guard_rejects = []  # patch writes blocked by the gate, fed into the next repair attempt

    # ---------- event helpers ----------
    def _emit(self, ev):
        ev.setdefault("t", round(time.time() - self.started, 2))
        self.emit(ev)

    def step(self, key, status, title=None, **extra):
        self._emit({"type": "step", "key": key, "status": status, "title": title, **extra})

    def log(self, msg, key=None):
        self._emit({"type": "log", "key": key, "msg": msg})

    def _meta(self):
        return {"provider": config.provider_name(), "models": dict(getattr(self.router, "models", None) or {})}

    # ---------- pipeline ----------
    def run(self):
        try:
            self._run()
        except Exception as e:  # surface every failure to the UI
            msg = f"{type(e).__name__}: {e}"
            self._emit({"type": "error", "msg": msg})
            self._emit({"type": "done", "ok": False, "error": msg, "proven": False, **self._meta(), "usage": self.router.cost_report()})

    def _run(self):
        self.step("models", "running", "Connecting to Nemotron")
        models = self.router.discover()
        self.step("models", "done", detail=models)

        self.step("checkout", "running", "Checking out repository")
        self._checkout()
        original = self._snapshot()
        # imports present before any LLM edit: the only unmapped modules dep-repair may auto-add
        self.original_imports = deps.top_level_imports(original)
        pins = self._pins()
        self.step("checkout", "done", detail={"files": len(original), "pins": pins})
        # venv + baseline install run in the background while the LLM stages think
        sandbox = Sandbox(self.work, lambda m: self.log(m, "test"))
        sandbox.prepare()

        # 1. real advisories from OSV.dev
        self.step("scan", "running", "Scanning dependencies against OSV.dev")
        findings = []
        for name, ver in pins.items():
            vulns = sources.osv_vulns(name, ver)
            latest = sources.pypi_latest(name)
            if vulns:
                findings.append({"package": name, "current": ver, "latest": latest, "vulns": vulns})
            self.log(f"{name}=={ver}: {len(vulns)} advisories, latest {latest}", "scan")
        for f in findings:
            f["min_safe"] = sources.min_safe_version(f["current"], f["vulns"])
        self._emit({"type": "findings", "findings": findings})
        self._threat(findings)
        self.step("scan", "done", detail={"vulnerable": len(findings),
                                           "advisories": sum(len(f["vulns"]) for f in findings)})
        if not findings:
            self._emit({"type": "done", "ok": True, "clean": True, "proven": False, **self._meta(), "usage": self.router.cost_report()})
            return

        # 2+3. concurrently: reachability (symbol inference) -> Nano triage, and Tavily research; join before plan
        triage, research = self._analyse(findings, original)

        # 4. Super plans target versions
        self.step("plan", "running", "Planning upgrades with Nemotron Super")
        plan = self._plan(findings, triage)
        self._emit({"type": "plan", "plan": plan})
        self.step("plan", "done")
        self._emit({"type": "trust", "packages": self._trust(plan)})

        # 5. baseline + apply upgrade
        self.step("test", "running", "Running baseline tests on current pins")
        ok_install, out = sandbox.wait_ready()
        base_ok, base_summary, _ = sandbox.test() if ok_install else (False, "install failed", out)
        self._emit({"type": "test", "label": "baseline", "ok": base_ok, "summary": base_summary})
        exploit = self._exploit_before(findings, original, research, sandbox) if ok_install else None
        mutations = self._mutations_before(exploit, sandbox) if exploit else None
        usage = drift.usages(original)
        drift_old = self._probe(sandbox, usage, plan) if ok_install else None

        self._apply_pins({u["package"]: u["to"] for u in plan["upgrades"]})
        self.log("Bumped: " + ", ".join(f"{u['package']} -> {u['to']}" for u in plan["upgrades"]), "test")
        ok_install, out = sandbox.install()
        if not ok_install:
            raise RuntimeError("pip install failed after upgrade:\n" + out)
        if drift_old is not None:
            self._drift(usage, drift_old, self._probe(sandbox, usage, plan))
        ok, summary, output = sandbox.test()
        self._emit({"type": "test", "label": "after upgrade", "ok": ok, "summary": summary, "output": output[-3000:]})
        self.step("test", "done")

        # 6. fix loop: Super first, escalate to Ultra if it keeps failing
        attempts = 0
        self.step("fix", "running", "Repairing breaking changes")
        while not ok and attempts < config.MAX_FIX_ATTEMPTS:
            ok, summary, output = self._dep_repair(output, sandbox, ok, summary)
            if ok:
                break
            attempts += 1
            tier = "super" if attempts == 1 else "ultra"
            self.log(f"Attempt {attempts} with Nemotron {tier.title()}", "fix")
            try:
                change = self._fix(tier, plan, research, output, attempts)
            except Exception as e:  # one malformed reply shouldn't end the run; the next attempt escalates
                self.log(f"Attempt {attempts} returned an unusable reply: {e}"[:300], "fix")
                self._emit({"type": "patch", "attempt": attempts, "tier": tier, "explanation": "unusable model reply",
                            "diagnosis": "", "evidence": [], "files": []})
                continue
            self.evidence += [e for e in change.get("evidence", []) if isinstance(e, dict) and e.get("quote")]
            self._write_files(change.get("files", []))
            if any(str(f.get("path", "")).strip("/") == "requirements.txt" for f in change.get("files", [])):
                self.log("Repair changed requirements.txt; reinstalling", "fix")
                ok_install, out = sandbox.install()
                if not ok_install:
                    self.log("pip install failed after repair:\n" + out[-800:], "fix")
            self._emit({"type": "patch", "attempt": attempts, "tier": tier,
                        "explanation": change.get("explanation", ""), "diagnosis": change.get("diagnosis", ""),
                        "evidence": change.get("evidence", [])[:4],
                        "files": [f["path"] for f in change.get("files", [])]})
            ok, summary, output = sandbox.test()
            self._emit({"type": "test", "label": f"attempt {attempts}", "ok": ok, "summary": summary,
                        "output": output[-3000:]})
        self.step("fix", "done" if ok else "failed", detail={"attempts": attempts})
        if exploit:
            self._exploit_after(exploit, sandbox)
        if mutations:
            self._mutations_after(mutations, sandbox)

        # 7. diff + report + PR
        diff = self._diff(original)
        self._emit({"type": "diff", "diff": diff})
        self._emit({"type": "risk", **self._risk(diff, plan, attempts, ok, exploit)})
        ledger = self._ledger(findings, plan, ok, base_summary, summary, exploit, mutations, diff)
        self._emit({"type": "ledger", **ledger})
        try:
            doc = vex.build(self.run_id, findings, plan, self.reach, getattr(self, "remaining", []), ok, ledger, exploit)
            self._emit({"type": "vex", "document": doc})
            (config.WORK_DIR / self.run_id).mkdir(parents=True, exist_ok=True)
            (config.WORK_DIR / self.run_id / "openvex.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
        except Exception as e:
            self.log(f"OpenVEX export skipped: {e}", "pr")
        report = self._report(findings, triage, plan, research, attempts, ok, base_summary, summary, exploit, ledger)
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
        self._emit({"type": "done", "ok": ok, "attempts": attempts, "pr": pr, **self._meta(),
                    "proven": bool(exploit) and exploit.get("verdict") == "proven closed",
                    "seconds": round(time.time() - self.started, 1), "usage": self.router.cost_report()})

    # ---------- steps ----------
    def _analyse(self, findings, original):
        """Reachability -> triage, and Tavily research, on a small pool (max 3 so the free tier is not hammered)."""
        self.step("triage", "running", "Triage with Nemotron Nano")
        self.step("research", "running", "Researching upgrade paths with Tavily")

        def triage_chain():
            self.reach = self._reachability(findings, original)
            triage = self._triage(findings, original)
            self._emit({"type": "triage", "triage": triage})
            self._emit({"type": "reach", "packages": {f["package"]: self._usage_snippets(f["package"], original)
                                                       for f in findings}})
            self.step("triage", "done")
            return triage

        def research_one(f):
            q = f"{f['package']} upgrade {f['current']} to {f['latest']} breaking changes migration guide"
            try:
                hits = self._rerank(q, sources.tavily_search(q, max_results=8))
            except Exception as e:
                self.log(f"Research for {f['package']} failed: {e}", "research")
                hits = []
            self._emit({"type": "research", "package": f["package"], "query": q,
                        "results": [{"title": h["title"], "url": h["url"], "score": h.get("score")} for h in hits]})
            return f["package"], hits

        with ThreadPoolExecutor(max_workers=3) as pool:
            tri = pool.submit(triage_chain)
            res = [pool.submit(research_one, f) for f in findings]
            research = dict(r.result() for r in res)
            if not config.TAVILY_API_KEY:
                self.log("TAVILY_API_KEY not set - skipping web research", "research")
            self.step("research", "done")
            triage = tri.result()
        return triage, research

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
            if (p.is_file() and p.suffix in TEXT_EXT and ".git" not in p.parts and ".patchpilot" not in p.parts
                    and p.stat().st_size < 60_000):
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

    def _reachability(self, findings, files):
        """Symbol-level reachability per advisory: OSV `imports` data first, Nano-inferred symbols as a fallback."""
        advs = {v["id"]: {"package": f["package"], "symbols": v.get("symbols") or [], "source": "osv"}
                for f in findings for v in f["vulns"]}
        missing = {k: a for k, a in advs.items() if not a["symbols"]}
        if missing:
            try:
                byid = {v["id"]: v for f in findings for v in f["vulns"]}
                data = self.router.chat_json(
                    "nano",
                    "For each Python security advisory, name the vulnerable public functions/classes as fully dotted "
                    "import paths (e.g. jinja2.filters.do_xmlattr, jwt.decode). Only list symbols the advisory text "
                    'supports; use [] if unsure. Output: {"advisories":[{"id":str,"symbols":[str]}]}',
                    json.dumps([{"id": k, "package": a["package"], "summary": byid[k]["summary"],
                                 "details": byid[k]["details"][:400]} for k, a in missing.items()]),
                    "Infer vulnerable symbols", max_tokens=1500, reasoning="off")
                for row in data.get("advisories") or []:
                    syms = [s for s in row.get("symbols") or [] if isinstance(s, str) and re.match(r"^[\w.]+$", s)]
                    if row.get("id") in missing and syms:
                        advs[row["id"]].update(symbols=syms, source="llm-inferred")
            except Exception as e:  # rate limits etc.: those advisories stay "unknown"
                self.log(f"Symbol inference skipped: {e}", "triage")
        result = reach.analyse(drift.usages(files), advs, files)
        self._emit({"type": "reachability", "advisories": result, "counts": reach.counts(result)})
        return result

    def _triage(self, findings, files):
        items = []
        for f in findings:
            for v in f["vulns"]:
                items.append({"package": f["package"], "id": v["id"], "cve": v["cve"], "summary": v["summary"],
                              "details": v["details"][:600], "fixed": v["fixed"],
                              "reachability": (self.reach.get(v["id"]) or {}).get("status", "unknown")})
        if self.reach and all(i["reachability"] != "unknown" for i in items):
            self.log("Triage from static reachability: every advisory has a conclusive label, Nano call skipped",
                     "triage")
            notes = {"reachable": "Vulnerable symbol is called from project code (static AST match).",
                     "imported": "Package is imported but the vulnerable symbol is never called.",
                     "not reachable": "Package is never imported by project code."}
            return [{"id": i["id"], "cve": i["cve"], "affected": i["reachability"] == "reachable",
                     "rationale": notes.get(i["reachability"], i["reachability"]), "source": "static"} for i in items]
        usage = {f["package"]: self._usage_snippets(f["package"], files) for f in findings}
        try:
            data = self.router.chat_json(
                "nano",
                "You are a security triage engineer. For each advisory decide whether the project's code "
                "actually exercises the vulnerable functionality. Each advisory carries a static `reachability` "
                "label (symbol-level AST match); trust 'reachable' and 'not reachable' unless the code says otherwise. Be concise: one short sentence of rationale. "
                'Output: {"advisories":[{"id":str,"cve":str,"affected":bool,"rationale":str}]}',
                json.dumps({"advisories": items, "code_usage": usage}),
                "Triage advisories against code usage",
                max_tokens=1500, reasoning="off",
            )
        except Exception as e:  # triage only annotates; the upgrade still covers every advisory
            self.log(f"Triage skipped: {e}", "triage")
            return {}
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
            max_tokens=2048, reasoning="low",
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
            "code compatible (predicted_api_breaks lists APIs that were verified removed or changed, with call sites; "
            "fix every one of them; rejected_writes lists earlier file writes a safety gate blocked and why: do "
            "not repeat them) "
            "code compatible with the new library versions while preserving behaviour and security. "
            "You MAY edit requirements.txt: if tests fail because a module is missing (see dependency_hints), add a "
            "pinned requirement for it (e.g. the package behind the library's extra) instead of removing, disabling "
            "or falling back away from the feature. Never drop functionality the tests expect. "
            "Return the COMPLETE new content of every file you change. In evidence, quote the exact line(s) from "
            "migration_research (with its url) that justify each change; use an empty list if research did not help. "
            "In diagnosis, state the root cause of the failing tests in one or two sentences. Output: "
            '{"diagnosis":str,"explanation":str,"evidence":[{"url":str,"quote":str}],"files":[{"path":str,"content":str}]}'
        )
        user = json.dumps({
            "attempt": attempt, "upgrades": plan["upgrades"], "migration_research": notes,
            "predicted_api_breaks": self.drift,
            "rejected_writes": self.guard_rejects[-6:],
            "dependency_hints": self.dep_hints,
            "failing_test_output": test_output[-6000:], "source_files": files,
        })
        kw = {"reasoning": "low"} if attempt == 1 and tier == "super" else {}
        try:
            # hard per-call cap: a slow reply raises LLMError and the loop escalates to Ultra
            text = self.router.chat(tier, system + "\nRespond with a single JSON object only. No prose.", user,
                                    f"Fix attempt {attempt}", max_tokens=8192, json_mode=True,
                                    timeout=config.FIX_TIMEOUT, **kw)
            return parse_json(text)
        except LLMError as first:
            # content ran out or was not JSON: the JSON reply is sometimes sitting in the reasoning text
            if "timed out" in str(first) or not self.router.last_reasoning:
                raise
            try:
                return parse_json(self.router.last_reasoning)
            except LLMError:
                raise first

    def _dep_repair(self, output, sandbox, ok, summary):
        """Deterministic pre-repair: a missing module that the original repo imported (or that has a curated mapping)
        and that has an established, non-yanked PyPI release for this Python is added pinned, reinstalled and
        retested before another LLM call. Anything else only becomes a prompt hint."""
        local = {p.stem if p.is_file() else p.name for p in self.work.iterdir()}
        missing = deps.detect_missing(output, local)
        req = self.work / "requirements.txt"
        have = deps.requirement_names(req.read_text(encoding="utf-8")) if req.exists() else set()
        for h in deps.hints(missing):
            if h not in self.dep_hints:
                self.dep_hints.append(h)
        if getattr(self, "dep_repair_disabled", False):
            return ok, summary, output
        pins = []
        for mod in missing:
            if deps._norm(deps.dist_for(mod)) in have:
                continue  # already required: the model must fix usage, not the requirement
            dist, version, reason = deps.resolve(mod, original_imports=getattr(self, "original_imports", ()))
            if version:
                pins.append((dist, version))
            else:
                self.log(f"Missing module '{mod}' not auto-added ({reason}); left to the model as a hint", "fix")
        if not pins:
            return ok, summary, output
        before = req.read_text(encoding="utf-8")
        added = deps.add_requirements(req, pins)
        if not added:
            return ok, summary, output
        self.log("Missing dependency detected; adding " + ", ".join(f"{d}=={v}" for d, v in added), "fix")
        ok_install, out = sandbox.install()
        if not ok_install:
            req.write_text(before, encoding="utf-8")
            self.log("pip install failed for added dependency; reverted: " + out[-600:], "fix")
            ok_revert, rout = sandbox.install()
            if not ok_revert:
                msg = "Reinstall after reverting the added dependency failed; dependency repair stopped: " + rout[-600:]
                self.log(msg, "fix")
                self._emit({"type": "error", "msg": msg})
                self.dep_repair_disabled = True
            return ok, summary, output
        self.deps_added += [{"package": d, "version": v} for d, v in added]
        for d, v in added:
            self.evidence.append({"url": f"https://pypi.org/project/{d}/{v}/",
                                  "quote": f"Tests failed with a missing module; added {d}=={v} (verified on PyPI) "
                                           f"to requirements.txt instead of removing functionality."})
        ok, summary, output = sandbox.test()
        self._emit({"type": "deps", "added": [{"package": d, "version": v} for d, v in added], "missing": missing})
        self._emit({"type": "test", "label": "after adding dependency", "ok": ok, "summary": summary,
                    "output": output[-3000:]})
        return ok, summary, output

    # ---------- exploit proof ----------
    def _exploit_before(self, findings, files, research, sandbox):
        """Run a proof-of-exploit pytest (asserts the SAFE outcome); it should fail on the vulnerable pins."""
        self.step("exploit", "running", "Preparing exploit proof")
        try:
            sev = {"CRITICAL": 0, "HIGH": 1}
            pairs = [(f, v) for f in findings for v in f["vulns"]]
            # prefer an advisory with a curated, verified proof; else the top-severity one
            curated = [(f, v, hit) for f, v in pairs for hit in [exploits.find(v)] if hit]
            if curated:
                f, v, (cve, code) = min(curated, key=lambda x: sev.get(x[1].get("severity"), 2))
                source = "curated"
                self.log(f"Using curated exploit proof for {cve}", "exploit")
            elif config.DEMO:
                self.log("Demo mode: no curated proof for these advisories, LLM exploit generation skipped", "exploit")
                self.step("exploit", "failed")
                return None
            else:
                f, v = min(pairs, key=lambda fv: sev.get(fv[1].get("severity"), 2))
                code, source = self._generate_exploit(f, v, files, research), "generated"
        except Exception as e:  # the proof is a bonus; never block the fix on it
            self.log(f"Exploit proof skipped: {e}", "exploit")
            self.step("exploit", "failed")
            return None
        g = self._guard("exploit", code, curated=source == "curated")
        if g["verdict"] == "block":
            self.log("Exploit proof skipped: blocked by guard: " + "; ".join(g["reasons"])[:400], "exploit")
            self.step("exploit", "failed")
            return None
        try:
            title = code.splitlines()[0].lstrip("# ").strip() if code.startswith("#") else v["summary"]
            path = self.work / EXPLOIT_TEST
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code, encoding="utf-8")
            ok, summary, _ = sandbox.test(EXPLOIT_TEST)
        except Exception as e:
            self.log(f"Exploit proof could not run: {e}", "exploit")
            self.step("exploit", "failed")
            return None
        ex = {"title": title, "advisory": v["cve"] or v["id"], "package": f["package"], "code": code,
              "source": source, "before": summary, "vulnerable": not ok}
        self._emit({"type": "exploit", "stage": "before", **ex})
        self.step("exploit", "done")
        return ex

    def _generate_exploit(self, f, v, files, research):
        system = (
            "You are a security engineer writing a proof-of-exploit regression test. Write ONE self-contained "
            "pytest file that attempts the attack described in the advisory against the library (and the "
            "project code if relevant) and ASSERTS THE SAFE OUTCOME (attack rejected). It must FAIL on the "
            "vulnerable version and PASS once patched. Import ONLY the library under test, pytest and the standard "
            "library (cryptography and other extras are NOT installed); no network. It must run on both the old "
            "and new library versions, so guard API differences with try/except or hasattr. Start the file with a "
            "one-line comment naming the attack. Keep your reasoning brief. "
            "Reply with the file in a single ```python code block and nothing else.")
        user = json.dumps({"package": f["package"], "vulnerable_version": f["current"], "advisory": v,
                           "project_usage": self._usage_snippets(f["package"], files),
                           "research": [h["content"][:800] for h in research.get(f["package"], [])[:2]]})
        errors = []
        for tier in ("super", "ultra"):
            try:
                text = self.router.chat(tier, system, user, f"Write exploit proof ({tier})", max_tokens=32000)
                code = extract_test_code(text) or extract_test_code(self.router.last_reasoning)
                if code:
                    return code
                errors.append(f"{tier}: no valid pytest test in reply")
            except Exception as e:
                errors.append(f"{tier}: {e}")
            self.log(f"Exploit generation with {tier} failed: {errors[-1]}", "exploit")
        raise ValueError("; ".join(errors))

    def _exploit_after(self, ex, sandbox):
        try:
            ok, summary, _ = sandbox.test(EXPLOIT_TEST)
        except Exception as e:
            self.log(f"Exploit re-run failed: {e}", "exploit")
            return
        ex["after"] = summary
        ex["verdict"] = ("proven closed" if ex["vulnerable"] and ok else
                         "inconclusive: old version passed the test too" if ok else "not proven")
        self._emit({"type": "exploit", "stage": "after", "after": summary, "closed": ok, "verdict": ex["verdict"]})

    # ---------- threat clock ----------
    def _threat(self, findings):
        """Real-world urgency per advisory: EPSS exploit probability, CISA KEV status, days exposed."""
        cves = [v["cve"] for f in findings for v in f["vulns"] if v["cve"]]
        try:
            scores = sources.epss(cves)
        except Exception as e:
            self.log(f"EPSS lookup failed: {e}", "scan")
            scores = {}
        try:
            known = sources.kev()
        except Exception as e:
            self.log(f"CISA KEV lookup failed: {e}", "scan")
            known = {}
        now = datetime.now(timezone.utc)
        rows = {}
        for f in findings:
            for v in f["vulns"]:
                days = None
                if v.get("published"):
                    try:
                        days = (now - datetime.fromisoformat(v["published"].replace("Z", "+00:00"))).days
                    except ValueError:
                        pass
                e = scores.get(v["cve"] or "", {})
                rows[v["id"]] = {"epss": e.get("epss"), "percentile": e.get("percentile"),
                                 "kev": known.get(v["cve"] or ""), "days": days}
        top = max(rows.values(), key=lambda r: r["epss"] or 0, default={})
        oldest = max((r["days"] for r in rows.values() if r["days"] is not None), default=None)
        self._emit({"type": "threat", "advisories": rows, "kev": sum(1 for r in rows.values() if r["kev"]),
                    "max_epss": top.get("epss"), "oldest_days": oldest,
                    "least_change": {f["package"]: {"min_safe": f["min_safe"], "latest": f["latest"]} for f in findings}})
        self.log(f"Threat clock: {sum(1 for r in rows.values() if r['kev'])} in CISA KEV, max EPSS "
                 f"{(top.get('epss') or 0) * 100:.2f}%, oldest exposure {oldest} days", "scan")

    # ---------- API drift radar ----------
    def _probe(self, sandbox, usage, plan):
        try:
            d = self.work / ".patchpilot"
            d.mkdir(exist_ok=True)
            (d / "drift_probe.py").write_text(drift.PROBE, encoding="utf-8")
            (d / "usage.json").write_text(json.dumps(usage), encoding="utf-8")
            ok, out = sandbox.python(str(d / "drift_probe.py"), str(d / "usage.json"),
                                     json.dumps([u["package"] for u in plan["upgrades"]]))
            return json.loads(out.strip().splitlines()[-1]) if ok else None
        except Exception as e:
            self.log(f"Drift probe failed: {e}", "drift")
            return None

    def _drift(self, usage, old, new):
        if new is None:
            return
        self.drift = drift.diff(usage, old, new)
        self._emit({"type": "drift", "probed": len(old), "breaks": self.drift})
        self.log(f"Drift radar: {len(self.drift)} API break(s) predicted across {len(old)} probed symbols", "drift")

    # ---------- red-team mutations ----------
    def _mutations_before(self, ex, sandbox):
        """Variants of the proven attack: run on the vulnerable pins now, on the patched code after the fix."""
        self.step("redteam", "running", "Red-teaming: generating attack variants")
        code, source = exploits.mutations(ex["advisory"]), "curated"
        if not code and config.DEMO:
            self.log("Demo mode: no curated variants, LLM variant generation skipped", "redteam")
        elif not code:
            source = "generated"
            try:
                text = self.router.chat(
                    "super",
                    "You are a red-team engineer. Given a proof-of-exploit pytest, write ONE pytest file with 5-8 "
                    "VARIANTS of the same attack (other algorithms, encodings, payload shapes, boundary values) using "
                    "@pytest.mark.parametrize with readable ids. Each case asserts the SAFE outcome, like the original. "
                    "Same imports rules as the original: only the library under test, pytest and the standard library. "
                    "Keep your reasoning brief. Reply with the file in a single ```python code block and nothing else.",
                    json.dumps({"advisory": ex["advisory"], "package": ex["package"], "original_proof": ex["code"]}),
                    "Generate attack variants", max_tokens=32000)
                code = extract_test_code(text) or extract_test_code(self.router.last_reasoning)
            except Exception as e:
                self.log(f"Variant generation failed: {e}", "redteam")
                code = None
        if code and self._guard("redteam", code, curated=source == "curated")["verdict"] == "block":
            self.log("Attack variants skipped: blocked by guard", "redteam")
            code = None
        if not code:
            self.step("redteam", "failed")
            return None
        try:
            path = self.work / MUTATION_TEST
            path.write_text(code, encoding="utf-8")
            before = sandbox.test_cases(MUTATION_TEST)
        except Exception as e:
            self.log(f"Variants could not run: {e}", "redteam")
            self.step("redteam", "failed")
            return None
        if not before:
            self.log("Variant file collected no tests", "redteam")
            self.step("redteam", "failed")
            return None
        landed = sum(1 for v in before.values() if not v)
        self.log(f"{landed}/{len(before)} attack variants succeed against the vulnerable pins", "redteam")
        m = {"source": source, "code": code, "before": before}
        self._emit({"type": "redteam", "stage": "before", "source": source, "variants": before, "code": code})
        return m

    def _mutations_after(self, m, sandbox):
        try:
            after = sandbox.test_cases(MUTATION_TEST)
        except Exception as e:
            self.log(f"Variant re-run failed: {e}", "redteam")
            self.step("redteam", "failed")
            return
        rows = []
        for name, was_blocked in m["before"].items():
            now = after.get(name)
            status = ("still open" if now is False else "closed by fix" if not was_blocked and now
                      else "already blocked" if now else "not run")
            rows.append({"variant": name, "status": status})
        m["rows"] = rows
        m["open"] = sum(r["status"] == "still open" for r in rows)
        m["closed"] = sum(r["status"] == "closed by fix" for r in rows)
        self._emit({"type": "redteam", "stage": "after", "rows": rows, "open": m["open"], "closed": m["closed"]})
        self.log(f"Red-team: {m['closed']} variants closed by the fix, {m['open']} still open", "redteam")
        self.step("redteam", "done" if not m["open"] else "failed")

    # ---------- evidence ledger ----------
    def _ledger(self, findings, plan, ok, base, final, exploit, mutations, diff):
        """Every claim the PR makes, each checked by something other than the model that made it."""
        claims = []

        def add(claim, status, evidence):
            claims.append({"claim": claim, "status": status, "evidence": evidence})

        # independent re-scan: query OSV again for the NEW pinned versions
        original = {(f["package"].lower(), x) for f in findings for v in f["vulns"] for x in (v["cve"] or v["id"],)}
        remaining = []
        for u in plan["upgrades"]:
            try:
                remaining += [v["cve"] or v["id"] for v in sources.osv_vulns(u["package"], u["to"])
                              if (u["package"].lower(), v["cve"] or v["id"]) in original]
            except Exception:
                remaining.append(f"{u['package']}: OSV re-scan failed")
        self.remaining = remaining
        add("All reported advisories resolved", "unverified" if remaining else "verified",
            f"OSV re-scan of new pins still lists: {', '.join(remaining)}" if remaining
            else f"OSV re-scan of {len(plan['upgrades'])} upgraded package(s): 0 of {len(original)} advisories remain")

        if getattr(self, "reach", None):
            c = reach.counts(self.reach)
            srcs = {r["source"] for r in self.reach.values() if r["status"] != "unknown"} - {None}
            add("Reachability analysed", "verified" if srcs == {"osv"} else "partial",
                ", ".join(f"{n} {k}" for k, n in c.items() if n)
                + (f"; symbols from {', '.join(sorted(srcs))}" if srcs else "; no symbol data"))
        add("Project test suite passes", "verified" if ok else "unverified", f"pytest: {final}")
        passed = lambda t: int((re.search(r"(\d+) passed", t or "") or [0, 0])[1])
        add("No tests lost", "verified" if passed(final) >= passed(base) else "partial",
            f"baseline {passed(base)} passed → final {passed(final)} passed")
        touched = re.findall(r"^\+\+\+ b/(\S+)", diff, re.M)
        add("Tests were not edited to pass", "unverified" if any(t.startswith("tests/") for t in touched) else "verified",
            f"diff touches {len(touched)} file(s), none under tests/" if touched else "no files changed")
        if exploit:
            v = exploit.get("verdict", "not run")
            add(f"Exploit {exploit['advisory']} closed", "verified" if v == "proven closed" else "partial",
                f"{exploit['source']} proof: old pins `{exploit['before']}`, patched `{exploit.get('after', 'not run')}`")
        else:
            add("Exploit closed", "unverified", "no exploit proof could be run")
        if mutations and "rows" in mutations:
            n = len(mutations["rows"])
            add("Attack variants blocked", "verified" if not mutations["open"] else "partial",
                f"{n - mutations['open']}/{n} variants blocked after the fix ({mutations['closed']} closed by it)"
                + (f"; still open: {', '.join(r['variant'] for r in mutations['rows'] if r['status'] == 'still open')}"
                   if mutations["open"] else ""))
        if self.drift:
            add("Predicted API breaks all repaired", "verified" if ok else "partial",
                f"{len(self.drift)} break(s) predicted by the drift radar before testing; suite now "
                + ("green" if ok else "still failing"))
        tr = getattr(self, "trust", None) or {}
        known = {k: v for k, v in tr.items() if v.get("provenance") is not None}
        if not known:
            add("Fix release provenance checked", "unverified", "deps.dev data unavailable for the target release(s)")
        else:
            ok_prov = [k for k, v in known.items() if v["provenance"]]
            status = "verified" if len(ok_prov) == len(tr) else "partial"
            add("Fix release provenance checked", status,
                "deps.dev: " + "; ".join(
                    f"{k} {v['to']['version']} " + ("has verified PyPI attestation" if v["provenance"]
                                                     else "has NO verified provenance")
                    + (f", scorecard {v['scorecard']}" if v.get("scorecard") is not None else "")
                    for k, v in known.items())
                + (f"; unknown: {', '.join(k for k in tr if k not in known)}" if len(known) < len(tr) else ""))
        ai = [g for g in getattr(self, "guarded", []) if not g["curated"] and g["verdict"] == "allow"]
        if ai:
            unscreened = [g for g in ai if g["source"] != "nvidia-guard+static"]
            blocked = sum(g["verdict"] == "block" for g in self.guarded)
            add("AI-written code screened before execution", "partial" if unscreened else "verified",
                f"{len(ai)} AI-written file(s) executed; "
                + (f"{len(unscreened)} screened by the static scan only (guard model unavailable)" if unscreened
                   else "all passed the NVIDIA Nemotron guard and the static scan")
                + (f"; {blocked} blocked before execution" if blocked else ""))
        cited = len(self.evidence)
        add("Code changes cite migration sources", "verified" if cited else "partial",
            f"{cited} quoted line(s) from researched sources" if cited else "no quotes returned by the model")
        body = json.dumps({"claims": claims, "diff": diff}, sort_keys=True).encode()
        score = {"verified": 1, "partial": .5, "unverified": 0}
        return {"claims": claims, "certificate": "pp-" + hashlib.sha256(body).hexdigest()[:16],
                "sha256": hashlib.sha256(body).hexdigest(),
                "trust": round(100 * sum(score[c["status"]] for c in claims) / len(claims))}

    # ---------- release trust (deps.dev) ----------
    def _trust(self, plan):
        """Compare old vs target release on deps.dev: provenance, scorecard, publish date, new transitive deps."""
        out = {}
        try:
            for u in plan.get("upgrades", []):
                try:
                    old = sources.release_trust(u["package"], u["from"])
                    new = sources.release_trust(u["package"], u["to"])
                    added = (sorted(set(new["deps"]) - set(old["deps"]))
                             if new["deps"] is not None and old["deps"] is not None else None)
                    out[u["package"]] = {"from": old, "to": new, "new_deps": added,
                                         "provenance": new["provenance"], "had_provenance": old["provenance"],
                                         "scorecard": new["scorecard"], "checks": new["checks"],
                                         "source_repo": new["source_repo"] or old["source_repo"]}
                except Exception as e:
                    out[u["package"]] = {"error": f"{type(e).__name__}: {e}", "provenance": None, "scorecard": None,
                                         "new_deps": None}
        except Exception:
            log.exception("trust lookup failed")
        self.trust = out
        return out

    def _trust_points(self):
        """(points, detail) for the risk score; 0 when deps.dev returned nothing."""
        t = [v for v in (getattr(self, "trust", None) or {}).values() if v.get("provenance") is not None]
        if not t:
            return 0, "unknown (deps.dev unavailable)"
        noprov = sum(1 for v in t if v["provenance"] is False)
        low = sum(1 for v in t if v.get("scorecard") is not None and v["scorecard"] < 5)
        newdeps = sum(len(v.get("new_deps") or []) for v in t)
        pts = min(20, noprov * 8 + low * 5 + min(8, newdeps * 2))
        return pts, (f"{len(t) - noprov}/{len(t)} target(s) with verified provenance, {low} low scorecard, "
                     f"{newdeps} new transitive dep(s)")

    # ---------- research rerank ----------
    def _rerank(self, query, hits, keep=4):
        """Nemotron Nano scores each Tavily result for relevance; keep the best."""
        docs = [h for h in hits if h.get("url")]
        answer = [h for h in hits if not h.get("url")]
        if len(docs) <= 1:
            return hits
        if all(isinstance(d.get("tavily_score"), (int, float)) for d in docs):
            # Tavily already scores relevance (0-1): no model call needed. Shown on the same 0-10 scale.
            for d in docs:
                d["score"] = round(d["tavily_score"] * 10, 1)
            docs.sort(key=lambda d: d["score"], reverse=True)
            self.log(f"Ranked {len(docs)} results by Tavily relevance score (no model call)", "research")
            return answer + docs[:keep]
        try:
            # a one-line format survives reasoning models far better than JSON
            text = self.router.chat(
                "nano",
                "You rerank search results for an engineer upgrading a dependency. Score each document 0-10 for how "
                "useful it is to answer the query (breaking changes, migration steps, security fix details). "
                "Do not explain. Reply with exactly one line in this format: SCORES: 0=7, 1=3, 2=9",
                json.dumps({"query": query, "documents": [{"i": i, "title": d["title"], "text": d["content"][:500]}
                                                          for i, d in enumerate(docs)]}),
                "Rerank research", max_tokens=1500, reasoning="off")
            line = (re.findall(r"SCORES:([^\n]*)", text) or re.findall(r"SCORES:([^\n]*)", self.router.last_reasoning or "")
                    or [""])[-1]
            scores = {int(i): float(v) for i, v in re.findall(r"(\d+)\s*=\s*(\d+(?:\.\d+)?)", line)}
            if not scores:
                raise ValueError("no SCORES line in reply")
        except Exception as e:  # keep Tavily's order if reranking fails
            self.log(f"Rerank skipped: {e}", "research")
            return hits[:keep + len(answer)]
        for i, d in enumerate(docs):
            d["score"] = scores.get(i, 0.0)
        docs.sort(key=lambda d: d["score"], reverse=True)
        return answer + docs[:keep]

    # ---------- risk score ----------
    def _risk(self, diff, plan, attempts, ok, exploit):
        files = len(re.findall(r"^\+\+\+ ", diff, re.M))
        added = len(re.findall(r"^\+(?!\+\+)", diff, re.M))
        removed = len(re.findall(r"^-(?!--)", diff, re.M))
        major = sum(1 for u in plan["upgrades"] if str(u["from"]).split(".")[0] != str(u["to"]).split(".")[0])
        proven = bool(exploit) and exploit.get("verdict") == "proven closed"
        factors = [
            ("Code churn", min(30, (added + removed) // 3), f"+{added} / -{removed} lines"),
            ("Files touched", min(15, files * 3), f"{files} file(s)"),
            ("Major version jumps", min(25, major * 12), f"{major} major upgrade(s)"),
            ("Repair attempts", min(15, max(0, attempts - 1) * 5), f"{attempts} attempt(s)"),
            ("Test result", 0 if ok else 40, "all green" if ok else "failing"),
            ("Exploit proof", -10 if proven else 0, exploit.get("verdict", "not run") if exploit else "skipped"),
            ("Supply-chain trust", *self._trust_points()),
        ]
        c = reach.counts(self.reach) if getattr(self, "reach", None) else {}
        score = max(0, min(100, sum(p for _, p, _ in factors)))
        return {"score": score, "level": "low" if score < 30 else "medium" if score < 60 else "high",
                "factors": [{"name": n, "points": p, "detail": d} for n, p, d in factors],
                # urgency of the advisories (not of the upgrade): unreachable ones can wait, reachable ones can't
                "urgency": "unknown" if not c else "high" if c["reachable"] else "medium" if c["imported"] + c["unknown"]
                else "low",
                "reachability": c}

    def _guard(self, kind, code, path="", curated=False):
        """Screen code before it runs: static AST scan always, NVIDIA guard model for AI-written code."""
        if not config.GUARD:
            return {"verdict": "allow", "reasons": [], "source": "disabled"}
        reasons = guard.static_screen(code, path)
        source = "static"
        if not curated:
            try:
                v = self.router.guard(kind, code)
                source = "nvidia-guard+static"
                if not v["safe"]:
                    reasons.append("NVIDIA guard: unsafe" + (f" ({', '.join(v['categories'])})" if v["categories"] else ""))
            except Exception as e:  # 429, timeout, no model: the static screen alone decides; never crash the run
                self.log(f"Guard model unavailable, static screen only: {e}"[:200], "guard")
        verdict = "block" if reasons else "allow"
        self.guarded.append({"kind": kind, "path": path, "verdict": verdict, "source": source, "curated": curated})
        self._emit({"type": "guard", "kind": kind, "path": path, "verdict": verdict, "reasons": reasons,
                    "source": source, "curated": curated})
        return {"verdict": verdict, "reasons": reasons, "source": source}

    def _write_files(self, changes):
        for c in changes:
            rel = str(c.get("path", "")).replace("\\", "/").lstrip("/")
            target = (self.work / rel).resolve()
            if not rel or self.work.resolve() not in target.parents or rel.startswith("tests/"):
                self.log(f"Rejected write outside allowed paths: {rel}", "fix")
                continue
            g = self._guard("patch", str(c.get("content", "")), path=rel)
            if g["verdict"] == "block":
                self.guard_rejects.append({"path": rel, "reasons": g["reasons"][:5]})
                self.log(f"Rejected write to {rel}: blocked by guard: " + "; ".join(g["reasons"])[:300], "fix")
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

    def _report(self, findings, triage, plan, research, attempts, ok, base, final, exploit=None, ledger=None):
        lines = ["## PatchPilot security upgrade", ""]
        lines.append("### Advisories resolved")
        for f in findings:
            for v in f["vulns"]:
                lines.append(f"- **{f['package']} {f['current']}** - [{v['cve'] or v['id']}]({v['url']}): {v['summary']}")
        lines += ["", "### Upgrades"]
        for u in plan["upgrades"]:
            lines.append(f"- `{u['package']}` {u['from']} -> **{u['to']}** - {u.get('reason', '')}")
        if getattr(self, "deps_added", None):
            lines += ["", "### Dependencies added (missing-module repair)"]
            lines += [f"- `{d['package']}=={d['version']}` - tests failed with a missing module; pinned to the latest "
                      f"PyPI release and verified by reinstall + test rerun" for d in self.deps_added]
        lines += ["", "### Verification", f"- Baseline (old pins): `{base}`", f"- Final: `{final}`",
                  f"- Fix attempts: {attempts}", f"- Status: {'all tests passing' if ok else 'needs human review'}"]
        if exploit:
            lines += ["", "### Exploit proof", f"- {exploit['title']} ({exploit['advisory']})",
                      f"- Vulnerable pins: `{exploit['before']}` · Patched: `{exploit.get('after', 'not run')}`",
                      f"- Verdict: **{exploit.get('verdict', 'not run')}**"]
        if ledger:
            icon = {"verified": "✅", "partial": "🟡", "unverified": "❌"}
            lines += ["", f"### Proof certificate `{ledger['certificate']}`"]
            lines += [f"- {icon[c['status']]} **{c['claim']}**: {c['evidence']}" for c in ledger["claims"]]
        if self.evidence:
            lines += ["", "### Why these changes (evidence quoted by the agent)"]
            for e in self.evidence[:5]:
                lines += [f"> {e['quote'].strip()[:300]}", f"> — {e.get('url') or 'migration notes'}", ""]
        refs = [h for hits in research.values() for h in hits if h.get("url")]
        if refs:
            lines += ["", "### Sources consulted (Tavily)"] + [f"- [{h['title']}]({h['url']})" for h in refs[:8]]
        lines += ["", "### Models (NVIDIA Nemotron)"]
        for tier, u in self.router.usage.items():
            if u["calls"]:
                lines.append(f"- {tier}: `{self.router.models[tier]}` - {u['calls']} calls, {u['in']}+{u['out']} tokens")
        return "\n".join(lines)
