# Research 1: novel, buildable ideas (2026-10-29)

Sources listed are only pages actually opened or returned by search during this pass. Anything marked **(guess)** is unverified.

## Context findings

- **Dependabot noise is a live, quotable pain.** Filippo Valsorda (Go crypto maintainer) called Dependabot a "noise machine": a one-line fix triggered thousands of PRs against repos that never call the changed function, plus a 73% "compatibility score". His remedy is reachability analysis (govulncheck) and sandboxed testing of updates. https://www.theregister.com/2026/02/24/github_dependabot_noise_machine/
- Major-bump PRs that break builds are a long-running complaint (Dependabot compatibility score under 25% on node-fetch 2 to 3): https://github.com/orgs/community/discussions/10441 . Some teams just ignore majors: https://gitlab.com/postgres-ai/database-lab/-/merge_requests/1125 . thoughtbot built a Claude skill only to sort Dependabot PRs: https://thoughtbot.com/blog/reviewing-dependabot-prs-is-boring-let-claude-do-it-for-you
- **Papers and the metrics they report:**
  - LLM Agents for Automated Dependency Upgrades (arXiv 2510.03480, Java, Summary/Control/Code agents): reports precision 71.4% and token cost. https://arxiv.org/html/2510.03480v2
  - arXiv 2505.09569 (repo-level migration benchmark): "compilation success significantly overestimates true migration success"; minimal vs maximal efficacy 62% vs 27% (from search snippet, not opened in full). https://alphaxiv.org/overview/2505.09569v2
  - CyberGym (2506.02548): PoCs judged by running on pre-patch AND post-patch builds; best agent around 12%. https://arxiv.org/abs/2506.02548v1
  - CVE-GENIE (2509.01835): reproduces about 51% of 841 CVEs, reports $2.77 per CVE. https://arxiv.org/html/2509.01835v2
  - Cve2PoC (2602.05721): planner/executor/refiner dual loop that routes failures to a code fix or to replanning; 82.9% SecBench.js, 54.3% PatchEval. https://arxiv.org/html/2602.05721v1
  - CVE-Bench (2503.17332, ICML 2025): sandboxed exploit grading, 13% best. https://arxiv.org/abs/2503.17332
  - Takeaway: papers report **success rate, cost per CVE, and pre/post differential validation**. We should report the same numbers.
- **Free data we don't use yet:**
  - PyPA advisory DB `ecosystem_specific.imports` = `[{"attribute": "ImageFont", "modules": ["PIL"]}]`, i.e. which symbols are vulnerable (served through OSV). https://github.com/pypa/advisory-database ; schema for ecosystem_specific (Go affected functions, Rust `functions`): https://ossf.github.io/osv-schema/
  - deps.dev v3 (no key): `GET /v3/systems/pypi/packages/{name}/versions/{v}` returns `attestations[]` (type, verified, sourceRepository, commit) and `relatedProjects`; `GET /v3/projects/{id}` returns OpenSSF Scorecard checks; `...versions/{v}:dependencies` returns a resolved graph (PyPI supported); `/v3/query?hash.type=SHA256&hash.value=` identifies a file by hash. https://docs.deps.dev/api/v3/index.html , https://blog.deps.dev/pypi-attestations/ , https://docs.pypi.org/attestations/
- **Hackathon winners:** NVIDIA NeMo Agent Toolkit hackathon winners all used specialized multi-agent teams, combined NVIDIA tech with open APIs, made models swappable by config; judged on real-world applicability, technical execution, agentic AI in action. 2nd place was OpenCodeReview (security code review), so security tooling places, but we need more than "flags issues". https://developer.nvidia.com/blog/hackathon-winners-bring-agentic-ai-to-life-with-the-nvidia-nemo-agent-toolkit/ ; Nemotron hackathon Seoul grand prize (Nota AI): https://www.nota.ai/community/nvidia-nemotron-hackathon-grand-prize-among-20-teams-behind-two-sleepless-days
- **Nebius / Nemotron (verified):** Token Factory lists Nemotron 3 Nano 30B, Nano Omni, Super 120B (12B active, up to 1M context), Ultra 550B; serverless fine-tuning, dedicated endpoints, OpenAI-compatible API, optional zero-retention inference. https://nebius.com/services/token-factory/nemotron , https://nebius.com/blog/posts/nemotron3-super-now-available . I found **no** documented batch/async API (unverified either way).

---

## Ideas

### 1. Symbol-level reachability from advisory `imports` ("Valsorda filter")
- **What:** For each OSV advisory, read `affected[].ecosystem_specific.imports` (PyPA format). AST-scan the repo for imports/attribute uses of exactly those symbols (`from PIL import ImageFont`, `PIL.ImageFont.x`, re-export paths). Label each finding REACHABLE (file:line), IMPORTED-NOT-CALLED, or NOT REACHABLE. When the field is missing, have Nano pull candidate symbols from the advisory text and fix commit, and label them "LLM-inferred".
- **Why novel:** Dependabot checks only that the dependency is present (Register article). govulncheck does this for Go only. pip-audit consumes PyPA data but, as far as I know, does not do symbol matching **(guess)**. Our current reachability is likely package-level **(guess; verify in agent.py)**.
- **Pain:** Alert fatigue, "thousands of PRs to unaffected repos".
- **Sketch:** In `patchpilot/agent.py`, keep the full OSV vuln JSON in the scan step and add `symbol_reachability(repo_dir, vuln)` using `ast` and an import-alias map. Feed the result into triage, the risk score and the evidence ledger. In the UI, show the matching code line.
- **Effort:** S. **Demo impact:** 5. The pitch line: "Dependabot would open 3 PRs; PatchPilot proves 2 are unreachable."

### 2. Upgrade trust delta: is the fix release itself safe? (deps.dev)
- **What:** Before bumping, compare old and target versions on deps.dev: verified PyPI publish or SLSA attestation present, source repo and commit match, the project's Scorecard checks (Maintained, Code-Review, Signed-Releases), and new transitive deps added (`:dependencies` diff). Flag "target lost its attestation" or "adds 4 new transitive packages".
- **Why novel:** deps.dev only recently started serving PyPI attestations (blog). Dependabot, Renovate and our pipeline don't check that the fix release is trustworthy **(guess for Renovate)**. Valsorda warns that fast updates risk malicious code.
- **Pain:** Supply-chain attacks shipped as "security updates".
- **Sketch:** Add `depsdev_trust(name, old, new)` in `agent.py` after the Super plan step. Add a risk-score term and a ledger entry, and pass a "trust gate" verdict to Super so it can choose a different target.
- **Effort:** S-M. **Demo impact:** 4.

### 3. Measured efficacy scoreboard ("PatchPilot-Bench")
- **What:** Over our 4+ benchmark cases, report the numbers papers report. Proof fail-to-pass rate (fails pre-upgrade, passes post, as in CyberGym), pass-to-pass of the original tests, repair success, attempts, tokens and $ per CVE (CVE-GENIE reports $2.77/CVE), and wall time. Add a "beyond tests" count, because 2505.09569 shows build/test success overstates migration success. That count is how often the red-team variants or API drift probes caught regressions the tests missed.
- **Why novel:** No dependency bot reports a measured efficacy table. Papers do, but they don't ship a tool.
- **Pain:** Trust. "How often does it actually work?"
- **Sketch:** Extend the bench runner (`runs/bench.log`, `runs/*-job.jsonl` exist) to emit a summary JSON, then render a table on the web page and in the README. Only measured numbers.
- **Effort:** M. **Demo impact:** 4.

### 4. Evidence-backed OpenVEX output
- **What:** Emit an OpenVEX document. Unreachable advisories get `not_affected`, justification `vulnerable_code_not_in_execute_path`, plus the evidence from idea 1. Fixed ones get `fixed`, citing the proof certificate.
- **Why novel:** Scanners consume VEX, but bots don't auto-produce evidence-backed VEX **(guess; not researched this pass)**.
- **Pain:** Teams must justify suppressions to auditors and customers.
- **Sketch:** Add a small `vex` helper called next to proof-certificate generation; write `openvex.json` to the artifacts and attach it to the PR.
- **Effort:** S. **Demo impact:** 3.

### 5. Dual-loop failure routing in the repair loop (from Cve2PoC)
- **What:** Classify each failed attempt as either a code-level slip (retry the fix with Super) or a wrong strategy (replan: other target version, compatibility shim, or patched backport). Ultra then acts as replanner rather than just a bigger fixer.
- **Why novel:** Cve2PoC shows the gain for PoC generation. Applying it to upgrade repair is new as far as I found **(guess)**.
- **Sketch:** Have Nano classify the pytest failure inside the repair loop in `agent.py` and branch back to planning. Log the decision in the ledger and show it as a "replanned" node in the live graph.
- **Effort:** S-M. **Demo impact:** 3.

### 6. Transitive fix-path solver (deps.dev graph)
- **What:** When the vulnerable package is transitive, use the deps.dev `:dependencies` graph to find which direct dependency to bump, picking the minimal version whose resolved graph excludes the vulnerable range. Feed the result into the least-change upgrade step.
- **Why novel:** Python transitive handling in bots is weak **(guess, not sourced)**.
- **Effort:** M. **Demo impact:** 3.

### 7. Vendored-code detection via hash query
- **What:** Hash files in `vendor/`, `third_party/` and `_vendor`, then query deps.dev `/v3/query?hash` to find copied packages that `requirements.txt` misses.
- **Effort:** M. **Demo impact:** 2. Hit rate for single files is uncertain **(guess)**.

### 8. NVIDIA-native polish
- All the NVIDIA hackathon winners above used NeMo Agent Toolkit (blog), so expose the pipeline as a NAT workflow or at least show it is compatible. Use Super's 1M context to ingest the full changelog plus the migration guide in one shot. Promote Nebius zero-retention as a privacy point for scanning private repos.
- **Effort:** S for config and copy, M for a real NAT integration. **Demo impact:** 3.

---

## Ranked top 5
1. **Symbol-level reachability from `ecosystem_specific.imports`** (S, impact 5).
2. **Upgrade trust delta via deps.dev attestations, Scorecard and new-transitive diff** (S-M, impact 4).
3. **Measured efficacy scoreboard: fail-to-pass, $ per CVE, beyond-tests oracle catches** (M, impact 4).
4. **Evidence-backed OpenVEX output** (S, impact 3). Cheap once #1 exists.
5. **Dual-loop failure routing / replanning in the repair loop** (S-M, impact 3).
