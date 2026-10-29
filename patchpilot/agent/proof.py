"""Agent stages that prove a fix: exploit test before/after, threat model, behaviour probe, API drift, mutation tests."""
import json
from datetime import datetime, timezone

from patchpilot.core import config
from patchpilot.intel import drift, exploits, sources

from patchpilot.agent.common import EXPLOIT_TEST, MUTATION_TEST, extract_test_code


class ProofMixin:
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
