# PatchPilot

**Fix the code a security upgrade breaks, not just the version number.**

PatchPilot is an autonomous coding agent. It finds real vulnerabilities in your dependencies, researches the breaking changes, upgrades, **repairs your code until the test suite passes**, and opens a pull request with an evidence report. It runs on **NVIDIA Nemotron** models served by **Nebius Token Factory**.

> Track: **Coding and Agentic Engineering** · License: MIT

---

## The problem
A CVE lands in a dependency. Dependabot or Renovate opens a version bump, and if the fix is a **major** version, the build breaks. The PR then sits unmerged for weeks while vulnerable code stays in production. Version-bump bots stop at the bump. The open-source AI SRE agents (OpsGentic, OpenSRE, AutoSRE) focus on incidents, not dependency migrations. Tools that rewrite broken code (Snyk Agent Fix, Copilot Autofix) are closed and proprietary.

PatchPilot closes that gap with an open agent that does the whole job: **advisory → plan → upgrade → repair → verified PR**.

## How it works

```
 requirements.txt
       │
       ▼
 ┌─────────────┐   real advisories    ┌──────────────────────────┐
 │  OSV.dev     │ ───────────────────▶ │ Nemotron NANO  · triage   │  is the vulnerable code reachable?
 │  PyPI        │                      └──────────────────────────┘
 └─────────────┘                                  │
       ┌──────────────────────────────────────────┘
       ▼
 ┌─────────────┐  migration guides    ┌──────────────────────────┐
 │  Tavily      │ ───────────────────▶ │ Nemotron SUPER · plan     │  target versions + guardrail
 └─────────────┘                       └──────────────────────────┘
                                                  │
                                                  ▼
                                   ┌───────────────────────────────┐
                                   │ Sandbox: fresh venv + pytest   │◀──────┐
                                   └───────────────────────────────┘       │ failing output
                                                  │ red                    │
                                                  ▼                        │
                                   ┌───────────────────────────────┐       │
                                   │ attempt 1: Nemotron SUPER      │───────┘
                                   │ attempt 2+: escalate to ULTRA  │
                                   └───────────────────────────────┘
                                                  │ green
                                                  ▼
                                   Diff + evidence report → GitHub PR
```

### Why three Nemotron tiers
| Tier | Job | Why |
|---|---|---|
| **Nano** | Triage every advisory against how the code uses the package | High volume, simple classification. Fast and cheap. |
| **Super** | Plan target versions, write the first repair | Strong coder, sensible cost |
| **Ultra** | Called **only** when a repair fails | Deep reasoning where it actually pays off |

Each call's model, tokens and latency stream live to the UI. With prices set, every run reports its cost against the cost of sending every call to Ultra.

### Safety guardrails
- The model can't choose a version that leaves an advisory open (`agent._plan` checks every advisory's fixed version).
- The model **can't edit tests** or write outside the repository. Those writes are rejected.
- Every change is verified by actually running the project's test suite in an isolated virtualenv. A patch that fails tests is never reported as passing.

## Real data, no mocks
- **OSV.dev** for advisories (GHSA and PyPI advisory records, de-duplicated by CVE)
- **PyPI JSON API** for the latest releases
- **Tavily** for migration guides and changelogs
- `cases/authsvc` pins **PyJWT 1.7.1** and **requests 2.25.1**. These are real vulnerable versions with 16 live advisories (including CVE-2022-29217). Upgrading PyJWT to 2.x breaks 7 of 9 tests, and PatchPilot has to repair the code.
- `cases/webhooks` pins **Werkzeug 2.0.3** (CVE-2023-25577, CVE-2024-34069 and more). Werkzeug 3 removed `safe_str_cmp`, `url_quote` and `url_encode`, so the upgrade breaks the imports.
- Public deployments should set `ALLOW_REMOTE_REPOS=0`, because remote repos run their own test code on the server.

## Run it

```bash
python -m venv .venv            # Windows shortcut: just double-click run.bat
.venv/Scripts/activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env            # add NEBIUS_API_KEY and TAVILY_API_KEY
uvicorn patchpilot.server:app --port 8000
```
Open http://localhost:8000 and click **Run agent**. Pick a bundled case, or paste a public GitHub URL with a pinned `requirements.txt` and a pytest suite.

The Nemotron models are **auto-discovered** from Token Factory's `/models` endpoint. You can pin them with `MODEL_NANO`, `MODEL_SUPER` and `MODEL_ULTRA`. To open real pull requests, set `GITHUB_TOKEN` and use a GitHub URL.

### Headless / batch (Nebius Serverless Jobs)
```bash
python -m patchpilot.cli case:authsvc case:webhooks https://github.com/org/repo-a https://github.com/org/repo-b
```
This writes each run to `runs/<id>.jsonl` (which can be replayed in the UI) and writes `runs/batch-summary.json`.

### Deploy
The `Dockerfile` serves the web app on port 8000 (Nebius Serverless Endpoint). The same image runs as a **Serverless Job** if you override the command with `python -m patchpilot.cli …`, for example as a nightly scan across all of an organization's repos.

## Project layout
```
patchpilot/
  agent.py      pipeline: scan → triage → research → plan → test → fix loop → report/PR
  llm.py        Nemotron router on Token Factory (discovery, retries, usage + cost)
  sources.py    OSV.dev, PyPI, Tavily
  sandbox.py    isolated virtualenv + pytest runner
  github_pr.py  branch, push, open PR
  server.py     FastAPI + Server-Sent Events, run recording and replay
  cli.py        headless / Serverless Job entrypoint
web/            dashboard (vanilla JS, no build step)
cases/          real vulnerable target projects (authsvc: PyJWT+requests, webhooks: Werkzeug)
```

## How we used NVIDIA and Nebius
- **NVIDIA Nemotron (Nano / Super / Ultra)**: all reasoning in the agent, routed by difficulty.
- **Nebius Token Factory**: OpenAI-compatible inference for all three tiers. Model discovery uses `/models`.
- **Nebius Serverless Endpoints / Jobs**: deployment target for the web app and the batch scanner (see Deploy above).
- **Tavily**: live research on migration guides and changelogs. Sources are cited in each PR.

## Feedback on the tools
See [PROGRESS.md](PROGRESS.md#feedback-for-nebius--nvidia). We fill it in as we build.

## Data sources and credits
Vulnerability data from [OSV.dev](https://osv.dev) (sourced from the GitHub Advisory Database and the PyPI Advisory Database). Package metadata from the [PyPI JSON API](https://pypi.org). Web research by [Tavily](https://tavily.com).

## License
MIT. See [LICENSE](LICENSE).
