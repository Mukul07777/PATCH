"""Agent stages that explain a fix: evidence ledger, trust points, reranking, risk score, guard, file writes, diff and report."""
import difflib
import hashlib
import json
import logging
import re

from . import config, guard, reach, sources


log = logging.getLogger("patchpilot.agent")


class ReportMixin:
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
