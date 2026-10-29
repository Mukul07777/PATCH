# Research 2: how to win the room (2026-10-29)

Angle: pitch, demo, judge Q&A, sponsor integration. (Research 1 covered product ideas, so this round doesn't repeat them.)
Legend: **[verified]** = I opened the source and read it. **[search-only]** = only seen in a search snippet. **[guess]** = my own judgement.

## 1. Winning submissions and the patterns they share

| Project (event) | One-line pitch | Demo / page structure | What judges or organisers praised | Status |
|---|---|---|---|---|
| SOC-CERT (DEV n8n + Bright Data Real-Time AI Agents, Sep 2025) | Merges government and community threat feeds, scores them with AI, and sends alerts to Slack, Gmail and Sheets | Workflow screenshot, then the alert landing in Slack | The announcement called it "production-ready" and quoted "100+ CVEs daily, 99.8% uptime". No judge quotes were given. | [verified] dev.to post |
| Release & Deprecation Sentinel (same event) | An SRE copilot that tracks release and deprecation notices from 18+ vendors every 6 hours | Shows the sources, then the digest | Concrete scope ("18+ vendors", "every 6h") | [verified] |
| Gitdefender (GitLab AI Hackathon on Devpost, Feb-Mar 2026, Google Cloud Grand Prize) | Finds and fixes security issues inside code review | Runs inside the MR, where the reviewer already works | Won the grand prize. I didn't open the Devpost page, so I can't give its praise. | [search-only] |
| Aegis (same event, runner-up) | Security agent | n/a | n/a | [search-only] |
| Symbiotic Security Copilot (Blackbox.ai track, RAISE Summit 2025) | A GitHub App that finds and suggests fixes for vulnerabilities in PRs | PR, then the bot comment with a fix | The blog URL returned 404 | [search-only] |

Only 2 of the 5 sources were fully readable, so the patterns below lean on [guess] where the evidence is thin.

**Patterns**
- **Pitch**: one sentence saying where it lives and what it outputs (Slack alert, PR comment), followed by one hard number. The winners quote measured scale ("100+ CVEs/day", "18+ vendors"). Ours should be "N/6 benchmark cases end green, M exploits proven closed", using only measured numbers (bench.log).
- **Demo**: show the result inside the tool the developer already uses (PR, MR, Slack). Gitdefender and Symbiotic both live in code review. We need one real GitHub PR on screen. The scorecard notes every run so far has `"pr": null`, and that is our biggest demo gap.
- **README / Devpost page**: hero GIF, then the problem, then how it works, then "what's real vs. mocked". Judges reward honesty about scope [guess, common judging practice].

## 2. NVIDIA NeMo Agent Toolkit (NAT)

What it is [verified, docs.nvidia.com/nemo/agent-toolkit/1.7]: an open-source framework-agnostic library, CLI `nat`. It wraps functions, tools and workflows in a YAML config and adds profiling, evaluation and observability. It can act as an **MCP client** (the `mcp_client` function group discovers a server's tools and registers them as functions) and as an **MCP server**.

Exposing it as an MCP server [verified, run-workflows/mcp-server.html]:
```bash
uv pip install nvidia-nat-mcp
nat mcp serve --config_file configs/patchpilot.yml --host 127.0.0.1 --port 9901 --tool_names scan,fix
nat mcp client tool list            # verify
nat mcp client ping --url http://localhost:9901/mcp
```
The docs warn that the server has **no built-in auth**, so keep it on localhost.

Minimal path for us [guess on exact API; check against the docs' "Functions" page before building]: write a `patchpilot/nat_plugin.py` that uses NAT's `@register_function` to wrap `cli.run_one(repo)` (a "fix" tool) and the OSV scan (a "scan" tool), plus a YAML that sets `llms:` to an OpenAI-compatible Nemotron on Nebius. That's roughly 60 lines and one optional dependency.

**Worth it?** Partly. Sponsors reward visible use of their stack, and "PatchPilot is callable as an MCP tool from any NAT / Claude / Cursor agent" makes a good 10-second demo beat. NAT's profiler could also give us per-tier token and latency charts, which is real evidence for the "Nemotron tiers" criterion (scorecard: 9/15). Effort is about half a day. The risk is dependency weight, so keep it optional, as an extra. Recommendation: do the MCP serve plus profiler only after the real-PR item ships.

## 3. Nebius: models and Serverless

- Base URL `https://api.tokenfactory.nebius.com/v1`. It matches our `config.py` default. [verified via mastra.ai provider page]
- Nemotron IDs listed on Token Factory (mastra.ai list, strip the `nebius/` prefix) [verified on a third-party page; confirm with `GET /v1/models`]:
  - Super: `nvidia/nemotron-3-super-120b-a12b`
  - Ultra: `nvidia/Nemotron-3-Ultra-550b-a55b`
  - Nano / fast tier: `nvidia/Nemotron-3_5-Lightning` [guess that this is the Nano-class tier]
  - Older ids still seen on aggregators: `nvidia/Llama-3_1-Nemotron-Ultra-253B-v1`, `nvidia/Llama-3_3-Nemotron-Super-49B-v1(_5)` [search-only]
- `llm.py` already auto-discovers models by matching "nano/super/ultra" in `/models` ids. **"Lightning" will not match "nano"**, so discovery would fall back. Pin the ids in `.env`:
  ```
  NEBIUS_API_KEY=...
  NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1
  MODEL_NANO=nvidia/Nemotron-3_5-Lightning
  MODEL_SUPER=nvidia/nemotron-3-super-120b-a12b
  MODEL_ULTRA=nvidia/Nemotron-3-Ultra-550b-a55b
  ```
- Serverless Job [verified, docs.nebius.com/serverless/quickstart/jobs.md]: `nebius ai job create --name pp-job --image <registry>/patchpilot:latest --container-command python --args "-m patchpilot.cli case:authsvc" --platform <cpu-platform> --preset <preset> --timeout 1h --subnet-id <id>`. Then `nebius ai job list` / `cancel` / `delete`. The page doesn't document an env-var flag or a CPU preset name [unverified], so check `nebius ai job create --help` for `--env`. Our Dockerfile already supports this: its CMD is uvicorn, which suits an Endpoint, and the comment says to override the command for a Job. `cli.main` accepts repo args or runs all cases.
- Billing is per running VM only [verified]. For the demo, record the job id and logs as evidence that it ran on Nebius.

## 4. Judge Q&A sheet (12 hard questions)

1. **What if the exploit test itself is wrong?** For known CVEs we use curated, hand-verified proofs (`patchpilot/exploits/cve_2022_29217.py`, `cve_2023_23934.py`, `cve_2023_25577.py`). They must go red on the old version before they count (`agent.py` ~l.350). A Nemotron-written proof that doesn't fail before the fix is not claimed as proof, and the ledger marks it partial/unverified. Honest gap: a generated exploit has not yet been proven red-then-green end to end (scorecard).
2. **Running untrusted repo tests is dangerous.** True. Today the sandbox is a separate venv with subprocess timeouts (`sandbox.py`: `run(..., timeout=600)`, 120 s for scripts). That is not a security boundary. Mitigation: run as a Nebius Serverless Job, an ephemeral container billed per run. Roadmap: no-network container or gVisor.
3. **How is this different from Snyk Agent Fix / Dependabot / Copilot Autofix?** Those fix code-level findings or bump pins. PatchPilot handles the *major-bump breaks the build* case: it bumps, repairs the code until the tests pass, proves the exploit is closed, attacks its own fix, and signs a claim ledger. [guess on competitors' exact current features; check before stating]
4. **Why trust LLM-written code?** Don't trust it, verify it. Every claim in the certificate is checked independently (`agent.py` ~l.550-585): no tests lost, tests not edited (flagged if anything under `tests/` was touched), a fresh OSV re-scan of the new pins, and a SHA-256 over claims and diff. A human still merges the PR.
5. **Couldn't the model just edit the tests?** It's detected: "Tests were not edited to pass" becomes unverified if any `tests/` file was touched, and "No tests lost" compares the pass count with the baseline (`agent.py` l.557-560).
6. **Red-team found a variant "still open". Isn't that a failure?** No. It's the feature. We report it rather than hide it (`agent.py` l.524-531), and the claim drops to partial. Say so on stage.
7. **Why three Nemotron tiers rather than one big model?** Nano handles cheap triage and reranking, Super plans and makes first fixes, and Ultra is only used on escalation (`llm.py` header). `llm.py` computes the cost against an all-Ultra baseline, so quote the measured saving from a run log, not a guess.
8. **Python only?** Yes, pip/`requirements.txt`. The OSV and drift design is ecosystem-agnostic, but npm is not built.
9. **How do you know the code is reachable at all?** The reachability map plus Nano triage. Import-level only, not call-graph (research-1 idea #1 would tighten it).
10. **Isn't the drift radar just a diff of APIs?** It probes the *installed* old and new versions in the sandbox against the symbols your AST uses (`drift.py`), so its predictions are specific to your code. Behaviour changes are left to the tests.
11. **What's your success rate?** Quote `runs/bench.log` only. Admit failures: redteam failed on authsvc/fetcher, and the mailer run stopped early (scorecard).
12. **Was it real or replayed?** The replay mode exists to save credits. Say which clips are live, and show one live Nebius run with its job id.

## 5. Two-minute demo script

| Time | Shot | Voice-over |
|---|---|---|
| 0:00-0:10 | Red Dependabot PR (PyJWT 1.x to 2.x, build failing) | "Dependabot opened the PR. The build broke. The CVE is still in prod." |
| 0:10-0:15 | Title card with the pitch line | "PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate." |
| 0:15-0:30 | Console: scan, then the **threat clock** (EPSS %, KEV badge, days public) | "First: which of these do attackers actually use?" |
| 0:30-0:45 | **Drift radar** listing the exact lines that will break, plus least-change version | "Before any test runs, it predicts which of your lines the upgrade breaks." |
| 0:45-0:55 | **Exploit proof goes RED** on the old version | "We prove the vuln is real in your code first." |
| 0:55-1:20 | **Repair loop**: attempt 1 Super fails, escalates to Ultra, tests turn green. Model debate panel | "Super's fix fails. It escalates to Nemotron Ultra. Green." |
| 1:20-1:30 | Exploit proof re-run goes GREEN | "The same exploit, now closed." |
| 1:30-1:45 | **Red-team**: variants table with one **"still open"** row highlighted | "Then it attacks its own fix, and tells you what's still open. No other bot admits that." |
| 1:45-1:55 | **Proof certificate**: claims ledger, trust score, SHA-256, real GitHub PR | "Every claim is checked independently and hashed into the PR." |
| 1:55-2:00 | Logos (Nemotron Nano/Super/Ultra, Nebius) plus one measured number from bench.log | "Three Nemotron tiers on Nebius. Measured, not promised." |

Prerequisite: record a real PR (`GITHUB_TOKEN`). Without one, the 1:45 shot shows the `.patch` file.

## Sources opened
- https://dev.to/devteam/congrats-to-the-winners-of-the-real-time-ai-agents-challenge-powered-by-n8n-and-bright-data-104c
- https://docs.nvidia.com/nemo/agent-toolkit/1.7/run-workflows/mcp-server.html
- https://docs.nvidia.com/nemo/agent-toolkit/1.7/extend/custom-components/mcp-server.html (navigation only)
- https://docs.nebius.com/serverless/quickstart/jobs.md
- https://mastra.ai/models/providers/nebius
- https://www.symbioticsec.ai/blog/symbiotic-security-wins-blackbox-ai-hackathon-raise-summit-2025 (404)
- Search-only: GitLab AI Hackathon 2026 winners (Gitdefender, Aegis); docs.nebius.com/serverless/jobs/manage; huggingface.co/nvidia/Llama-3_3-Nemotron-Super-49B-v1
