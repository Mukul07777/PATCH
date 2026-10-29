# PatchPilot

**Dependabot opens the PR. PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate.**

Built on NVIDIA Nemotron (Nano / Super / Ultra), with OpenAI-compatible endpoints for Nebius Token Factory. External data sources: OSV.dev, PyPI, FIRST EPSS, CISA KEV, deps.dev, Tavily and the GitHub API.

**Track:** Coding and Agentic Engineering (NVIDIA Global AI Hackathon).

## Inspiration
The security fix is usually one line in `requirements.txt`. The problem is the major version behind it: PyJWT 1.x to 2.x, Werkzeug 3, urllib3 2, Jinja2 3.1, bleach 6. The bot bumps the pin, the build goes red, the PR sits there, and the CVE stays in production. Nobody gets paged for a stale Dependabot PR. We wanted an agent that does the part that actually costs time, which is making the upgrade pass, and then proves the vulnerability is really gone instead of just saying so.

## What it does
Given a Python repo (pinned `requirements.txt` + pytest suite), PatchPilot:
1. **Finds**: scans pins against OSV + PyPI.
2. **Prioritizes**: a threat clock shows EPSS probability, CISA KEV status and days public. Reachability is checked per symbol: OSV symbols when OSV has them, otherwise Nemotron infers them and the result is **labelled `llm-inferred`**.
3. **Predicts**: an API drift radar lists the lines in your code the upgrade will break, and picks a least-change target version.
4. **Fixes**: a repair loop in a sandboxed venv. Nemotron Super writes the patch and Ultra takes over when Super fails. A guardrail forces the target to at least the highest fixed version.
5. **Attacks**: runs an exploit proof before the upgrade (must fail, so the vuln is real) and after it (must pass, so it's closed), then red-team variants of the same exploit, and reports any that are **still open**.
6. **Proves**: a claims ledger checks each claim on its own (tests green, no tests edited, no tests lost, exploit closed, variants blocked). On top of that come a trust score, a SHA-256 certificate, an OpenVEX v0.2.0 document and a deps.dev release trust check (provenance, OpenSSF Scorecard, new transitive deps).
7. **Ships**: a PR or `.patch` file, with the certificate in the body.

## How we built it
- **Pipeline**: `patchpilot/agent.py` streams every step as SSE (`server.py`) to a multipage web UI (`web/`): landing, live console with a graph, run history with replay, org scan, architecture.
- **Model routing**:
  - **Nano** (`nvidia/Nemotron-3_5-Lightning` on Token Factory) does cheap, high-volume work: triage, reachability inference, classification.
  - **Super** (`nvidia/nemotron-3-super-120b-a12b`) writes the first patch attempts.
  - **Ultra** (`nvidia/Nemotron-3-Ultra-550b-a55b`) only joins after Super fails, so the most expensive tier runs only when it is needed. In Token Factory run `20261029-153834-job` Super's patch failed and Ultra's went green on attempt 2. Across the recorded six-case benchmark Ultra was called once in total (23 model calls).
  - Every `done` event records usage per tier: calls, tokens, seconds, model id and provider.
- **Tavily**: a live runtime call on every run with advisories (`sources.tavily_search`, `search_depth: "advanced"`, 8 results) for each vulnerable package: "`<package>` upgrade `<old>` to `<new>` breaking changes migration guide". Results are ranked by Tavily's relevance score with no extra LLM call (Nemotron Nano reranks only if scores are missing); the top 4 go to the repair model, which must quote the lines it used with their URL. The console shows them under "Research via Tavily" in the Evidence tab, and the PR report lists them as "Sources consulted (Tavily)". Research runs in parallel with triage. In recorded run `20261029-153834-job` (authsvc), Tavily returned 8 sources across PyJWT and requests. Ultra's green patch quoted the PyJWT changelog (`pyjwt.readthedocs.io/en/stable/changelog.html`): "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer". Five of the six shipped demo runs include live Tavily research; the sanitizer recording predates it.
- **OSV / EPSS / KEV**: vulnerability, exploit-likelihood and known-exploited data (`sources.py`).
- **deps.dev**: release trust check before we recommend a version.
- **PyPI**: latest versions for upgrade targets and release metadata for the missing-dependency step.
- **GitHub API**: opening the pull request (needs `GITHUB_TOKEN`), org scans, and cloning remote repos (only with `ALLOW_REMOTE_REPOS=1`).
- **Sandbox**: one venv per run (`sandbox.py`), prepared with `uv` in the background. The environment is an allow-list, so no API keys or tokens reach the scanned repo's `setup.py` or `conftest.py`.
- **Exploits**: a curated, verified library in `patchpilot/exploits/` (6 CVEs, each with a proof and mutation variants). Nemotron writes the proof when the CVE isn't in the library.
- **Self-tests**: 44 offline tests pass for the agent itself (after the speed build, per `docs/team/LOG.md`).

## Challenges (honest)
- **Free-tier rate limits.** Our first benchmark used OpenRouter `:free` Nemotron models and ran out of daily quota after 3 of 6 cases. We re-ran all six on **Nebius Token Factory**: 6/6 green. The shipped set (five runs with live Tavily research plus the earlier sanitizer run) took 528.6 s in total, with 45,904 input / 39,321 output tokens over 23 model calls. Run ids are in the README.
- **A model that won't add a dependency.** The bleach case (`20261029-151849-job`) failed in 3 of 3 Token Factory runs: bleach 6 needs `tinycss2`, and Nemotron wrote an import fallback that drops `style` attributes instead of adding it to `requirements.txt`. PatchPilot reported it as not green. We fixed this generically: the repair loop now detects missing-module failures, tells the model that adding a pinned requirement beats removing a feature, and adds a pin itself before the next model call (only for curated or originally imported modules with an established, non-yanked PyPI release). The rerun (`20261029-153214-job`) went green in 1 attempt with `tinycss2==1.5.1` added.
- **Research text broke our JSON parser.** With Tavily on, a model reply quoted a changelog line together with its Markdown code fence (`pip install 'bleach[css]'`), and our parser took that inner fence for the reply's own. Two Ultra replies were thrown away and the sanitizer run failed (`20261029-154409-job`). The parser now tries the whole reply first. A regression test covers it.
- **Thinking budget.** On Token Factory our `reasoning="off"` switch was not being sent, so Nano used its whole 1500-token budget thinking and triage was skipped. Sending vLLM's `enable_thinking: false` cut Nano output from 3,000 to 203-1,721 tokens per run.
- **Slow free models.** Measured runs took 390–723 s. Nano alone took 279 s in `113639-job`. The speed work added reasoning control, JSON mode, parallel triage and research, and `uv`. With `uv`, venv+install measured 0.19–0.23 s vs 5.8–5.9 s with pip. On Token Factory after the speed work, the six cases took 42-83 s each (authsvc: 75 s vs 723 s on the free tier).
- **Model JSON reliability.** Malformed JSON from free models broke steps. We added JSON mode, retries and fallbacks.
- **Generated exploits are unreliable.** In the fetcher run (`114842-job`), the generated proof was "not proven" and blocked 0/8 variants. In the mailer run (`115625-job`) it was "inconclusive: old version passed the test too". We built a **curated, verified exploit library**: each proof fails on the old version and passes on the new one (e.g. bleach CVE-2021-23980: 9 failed → 9 passed; sqlparse CVE-2024-4340: 6 failed → 8 passed). We report "not proven" when that's the truth.
- **OSV rarely has symbol data.** Reachability falls back to Nemotron and is labelled `llm-inferred`. OpenVEX never emits `not_affected` from LLM-inferred evidence.
- **We found a hole in our own agent.** The sandbox originally passed the full `os.environ`, API keys included, to the scanned repo's code. We fixed it with an allow-list and a test (`tests/test_sandbox_env.py`).

## Accomplishments
- Nebius Token Factory benchmark: **6/6 cases green**, every case's exploit **proven closed**.
- `20261029-153834-job` (authsvc, PyJWT CVE-2022-29217, Token Factory, Tavily on): Super → Ultra escalation, tests green on attempt 2, 8 Tavily sources with 3 quoted lines in the patch, exploit **proven closed**, red-team **7/8 blocked** (1 reported still open), trust score 85, 110.7 s.
- All 6 benchmark CVEs have curated proofs verified fail-old / pass-new.
- A dependency bot that tells you what it *couldn't* prove: "partial" ledger claims, "still open" variants, "not proven" exploits.
- A finding from the trust check: the least-change targets (PyJWT 2.4.0, urllib3 1.26.19/2.2.2, Jinja2 3.1.3) have **no PyPI attestation**, while the latest releases do. That gives a data-backed reason to jump to latest.

## What we learned
- Green tests aren't the same as safe. You need an exploit that fails before the fix and passes after, or you're only claiming.
- Routing by failure (Super first, Ultra on failure) keeps the big model for the hard cases.
- Free-tier endpoints are fine for development but not for a benchmark. Measure early and record everything so it can be replayed.
- An agent that runs untrusted repo code is itself an attack surface.

## What's next
- Per-tier cost table for the Token Factory benchmark (set `PRICE_*`).
- NVIDIA content-safety gate (`patchpilot/guard.py`, in progress): an AST screen plus `nemotron-3.5-content-safety` that screens AI-written code before it runs.
- <!-- TODO(owner): one real PR on a public repo; add the PR link here once it exists, or delete this line. -->
- npm support (feasibility done: jsonwebtoken 8.5.1 → 9.0.0, CVE-2022-23540).
- Container sandbox. Today the venv is **not a security boundary**.

## Testing instructions
Hosted demo: <!-- TODO(owner): hosted demo URL. --> no login or API key is needed to watch a run. Open `/console` (a recorded run replays automatically, or pick one from "Replay a recorded run"), `/console?demo=1` for the captioned walkthrough, or `/runs` to replay any recording; failed runs show their reason. Launching a live run needs `NEBIUS_API_KEY` on the server; without it the console disables "Launch agent" and points to replay. The judged deployment keeps `PATCHPILOT_TOKEN` unset (otherwise the browser cannot start runs) and `ALLOW_REMOTE_REPOS=0`. Locally: copy `.env.example` to `.env`, set `NEBIUS_API_KEY` and `TAVILY_API_KEY`, `pip install -r requirements.txt`, `uvicorn patchpilot.server:app --port 8000`. The repo ships six recorded Token Factory runs in `demo-runs/`, so a fresh clone or deployment can replay them without an API key.

## Proof
| Run id | Case | Result |
|---|---|---|
| `20261029-113639-job` | authsvc (PyJWT) | ok, 3 attempts, 723 s, exploit proven closed, red-team 7/8, trust 93 |
| `20261029-114842-job` | fetcher | ok, 1 attempt, 463 s, exploit **not proven**, red-team 0/8, trust 79 |
| `20261029-115625-job` | mailer | ok, 1 attempt, 390 s, exploit **inconclusive**, trust 92 |
| `20261029-120256/120418/120442-job` | sanitizer / sqlfmt / webhooks | **failed**: 429 rate limit |

Source: `runs/batch-summary.json`, raw events in `runs/<id>.jsonl`. n=1 per case.

**Replay with no API key:** start the server (`uvicorn patchpilot.server:app --port 8000`, see README), then open
- `http://localhost:8000/console?replay=20261029-113639-job` to replay the full run event by event
- `http://localhost:8000/console?demo=1` for the guided demo (Find → Prioritize → Predict → Fix → Attack → Prove → Ship)
- `http://localhost:8000/runs` for history and replay
