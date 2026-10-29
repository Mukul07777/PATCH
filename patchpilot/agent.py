"""PatchPilot pipeline: advisory -> triage -> research -> upgrade -> test -> fix loop -> PR."""
import json
import logging
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, deps, drift, reach, rescue, sources, vex
from .llm import LLMError, Router, parse_json
from .sandbox import Sandbox
from .github_pr import open_pull_request

log = logging.getLogger(__name__)

from .agent_common import PIN, TEXT_EXT, extract_test_code

__all__ = ["Agent", "PIN", "TEXT_EXT", "extract_test_code"]
from .agent_behaviour import BehaviourMixin, describe as describe_behaviour
from .agent_proof import ProofMixin
from .agent_report import ReportMixin


class Agent(BehaviourMixin, ProofMixin, ReportMixin):
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
        self.pr_info = None  # rescue mode: the Dependabot/Renovate PR being repaired in place
        self.bumps = []  # rescue mode: the pin changes that PR makes
        self.lock = None  # behaviour lock recorded on the vulnerable pins
        self.behaviour_regressions = ""  # behaviour lock changes, fed into the next repair attempt

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
        if self.pr_info:  # baseline on the pins the repo ran before the bot's bump; the diff stays against the PR head
            head_req = (self.work / "requirements.txt").read_text(encoding="utf-8")
            self.bumps = rescue.bumps(self.pr_info["base_requirements"], head_req)
            if not self.bumps:
                raise RuntimeError("This pull request does not change any pinned version in requirements.txt")
            (self.work / "requirements.txt").write_text(self.pr_info["base_requirements"], encoding="utf-8")
            self.log(f"Rescuing PR #{self.pr_info['number']} by {self.pr_info['author'] or 'unknown'}: "
                     + ", ".join(f"{b['package']} {b['from']} -> {b['to']}" for b in self.bumps), "checkout")
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
        if not findings and not self.pr_info:
            self._emit({"type": "done", "ok": True, "clean": True, "proven": False, **self._meta(), "usage": self.router.cost_report()})
            return

        # 2+3. concurrently: reachability (symbol inference) -> Nano triage, and Tavily research; join before plan
        triage, research = self._analyse(findings, original) if findings else ({}, self._research_bumps())

        # 4. Super plans target versions
        self.step("plan", "running", "Planning upgrades with Nemotron Super")
        plan = self._rescue_plan(findings) if self.pr_info else self._plan(findings, triage)
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
        lock = self._behaviour_lock(findings, original, plan, sandbox) if ok_install else None

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

        def regressed():
            # green tests are not enough: every locked behaviour must come back identical
            if not (ok and lock):
                return False
            bad = self._behaviour_check(lock, sandbox)
            self.behaviour_regressions = describe_behaviour(bad)
            if bad:
                self.log(f"Tests pass but {len(bad)} locked behaviour(s) changed; repairing", "fix")
            return bool(bad)

        while (not ok or regressed()) and attempts < config.max_fix_attempts():
            if not ok:
                ok, summary, output = self._dep_repair(output, sandbox, ok, summary)
                if ok and not regressed():
                    break
            if ok:  # only behaviour drifted: show the model what changed
                output = self.behaviour_regressions
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
        if lock:
            self._behaviour_check(lock, sandbox, final=True)
        self.lock = lock
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
        if ok and self.pr_info and config.github_token() and self.pr_info["same_repo"]:
            self.step("pr", "running", f"Pushing the repair onto PR #{self.pr_info['number']}")
            pr = rescue.push_fix(self.work, self.pr_info, report, plan["upgrades"])
            self.step("pr", "done", detail=pr)
        elif ok and config.github_token() and str(self.repo_src).startswith("https://github.com/") and not self.pr_info:
            self.step("pr", "running", "Opening pull request")
            pr = open_pull_request(self.work, self.repo_src, self.run_id, plan, report)
            self.step("pr", "done", detail=pr)
        else:
            self.step("pr", "done" if ok else "failed", detail={"patch": "patchpilot.patch"})
            self.log("Patch file ready (set GITHUB_TOKEN and use a GitHub URL to open a real PR)", "pr")
        (config.WORK_DIR / self.run_id / "patchpilot.patch").write_text(diff, encoding="utf-8")
        self._emit({"type": "done", "ok": ok, "attempts": attempts, "pr": pr, **self._meta(),
                    "rescue": bool(self.pr_info),
                    "behaviour": {"locked": len(lock["locked"]), "preserved": lock.get("preserved", 0)} if lock else None,
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
            if not config.tavily_api_key():
                self.log("TAVILY_API_KEY not set - skipping web research", "research")
            self.step("research", "done")
            triage = tri.result()
        return triage, research

    def _checkout(self):
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.parent.mkdir(parents=True, exist_ok=True)
        src = str(self.repo_src)
        if rescue.PR_URL.fullmatch(src):
            if not config.remote_fix_allowed():
                raise RuntimeError("Fix runs on remote repositories are disabled on this deployment: use the Docker "
                                   "sandbox (SANDBOX=docker) or let an admin allow remote repos in Settings")
            self.pr_info = rescue.fetch(src)
            rescue.clone(self.pr_info, self.work)
        elif src.startswith("https://"):
            if not config.remote_fix_allowed():
                raise RuntimeError("Fix runs on remote repositories are disabled on this deployment: use the Docker "
                                   "sandbox (SANDBOX=docker) or let an admin allow remote repos in Settings")
            subprocess.run(["git", "clone", "--depth", "1", src, str(self.work)], check=True,
                           capture_output=True, text=True)
        else:
            name = src.removeprefix("case:")
            path = config.CASES_DIR / name
            if not name or not (path.is_dir() and path.parent == config.CASES_DIR):
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

    def _rescue_plan(self, findings):
        """Rescue mode keeps the bot's chosen versions; the job is making the code work with them."""
        vulnerable = {f["package"].lower(): f for f in findings}
        ups = []
        for b in self.bumps:
            f = vulnerable.get(b["package"].lower())
            clears = f is None or all(sources.version_gte(b["to"], v["fixed"][-1]) for v in f["vulns"] if v["fixed"])
            if not clears:
                self.log(f"{b['package']} {b['to']} from the PR does not clear every advisory", "plan")
            ups.append({**b, "breaking": str(b["from"]).split(".")[0] != str(b["to"]).split(".")[0],
                        "reason": f"From PR #{self.pr_info['number']}" + ("" if clears else "; does not clear all advisories")})
        return {"upgrades": ups, "risk": "rescue of an existing dependency PR"}

    def _research_bumps(self):
        self.step("research", "running", "Researching upgrade paths with Tavily")
        out = {}
        for b in self.bumps:
            q = f"{b['package']} upgrade {b['from']} to {b['to']} breaking changes migration guide"
            try:
                out[b["package"]] = self._rerank(q, sources.tavily_search(q, max_results=8))
            except Exception as e:
                self.log(f"Research for {b['package']} failed: {e}", "research")
                out[b["package"]] = []
            self._emit({"type": "research", "package": b["package"], "query": q,
                        "results": [{"title": h["title"], "url": h["url"], "score": h.get("score")}
                                    for h in out[b["package"]]]})
        self.step("research", "done")
        return out

    def _fix(self, tier, plan, research, test_output, attempt):
        files = {k: v for k, v in self._snapshot().items() if k.endswith(".py") and not k.startswith("tests/")}
        notes = {pkg: [{"url": h["url"], "text": h["content"]} for h in hits][:5] for pkg, hits in research.items()}
        system = (
            "You are an expert Python engineer fixing code broken by a security dependency upgrade. "
            "The dependency versions are FIXED and must not be downgraded. Do not edit tests; make the source "
            "code compatible (predicted_api_breaks lists APIs that were verified removed or changed, with call sites; "
            "fix every one of them; behaviour_regressions lists project functions whose output changed versus the old version even though tests may pass: restore the old observable behaviour; rejected_writes lists earlier file writes a safety gate blocked and why: do "
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
            "behaviour_regressions": self.behaviour_regressions,
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

    def _local_modules(self):
        """Top-level names importable from the repo itself: root entries, src/ children and package dirs."""
        skip = {"venv", ".venv", "env", "site-packages", "node_modules", "__pycache__"}
        local = {p.stem if p.is_file() else p.name for p in self.work.iterdir()}
        src = self.work / "src"
        if src.is_dir():
            local |= {p.stem if p.is_file() else p.name for p in src.iterdir()}
        for init in self.work.rglob("__init__.py"):
            parts = init.relative_to(self.work).parts[:-1]
            if not parts or any(x in skip or x.startswith(".") for x in parts):
                continue
            local.add(init.parent.name)
        return local

    def _dep_repair(self, output, sandbox, ok, summary):
        """Deterministic pre-repair: a missing module that the original repo imported (or that has a curated mapping)
        and that has an established, non-yanked PyPI release for this Python is added pinned, reinstalled and
        retested before another LLM call. Anything else only becomes a prompt hint."""
        local = self._local_modules()
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
        before = req.read_text(encoding="utf-8") if req.exists() else None
        added = deps.add_requirements(req, pins)
        if not added:
            return ok, summary, output
        self.log("Missing dependency detected; adding " + ", ".join(f"{d}=={v}" for d, v in added), "fix")
        ok_install, out = sandbox.install()
        if not ok_install:
            if before is None:
                req.unlink(missing_ok=True)
            else:
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
