# PatchPilot

**Dependabot opens the PR. PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate.**

Built on NVIDIA Nemotron (Nano / Super / Ultra), with OpenAI-compatible endpoints for Nebius Token Factory, plus Tavily, OSV, EPSS/KEV and deps.dev.

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
  - **Nano** (`nemotron-3.5-lightning`) does cheap, high-volume work: triage, reachability inference, classification.
  - **Super** (`nemotron-3.5-super-vl`) writes the first patch attempts.
  - **Ultra** (`nemotron-3-ultra-550b-a55b`) only joins after Super fails, so the most expensive tier runs only when it is needed. In run `20261029-113639-job` Super's attempts failed, Ultra was called twice, and the run ended green on attempt 3.
  - Every `done` event records usage per tier: calls, tokens, seconds, model id and provider.
- **Tavily**: web research on the advisory and migration notes. Results are reranked by Tavily score with no extra LLM call, and research runs in parallel with triage.
- **OSV / EPSS / KEV**: vulnerability, exploit-likelihood and known-exploited data (`sources.py`).
- **deps.dev**: release trust check before we recommend a version.
- **Sandbox**: one venv per run (`sandbox.py`), prepared with `uv` in the background. The environment is an allow-list, so no API keys or tokens reach the scanned repo's `setup.py` or `conftest.py`.
- **Exploits**: a curated, verified library in `patchpilot/exploits/` (6 CVEs, each with a proof and mutation variants). Nemotron writes the proof when the CVE isn't in the library.
- **Self-tests**: 44 offline tests pass for the agent itself (after the speed build, per `docs/team/LOG.md`).

## Challenges (honest)
- **Free-tier rate limits.** All recorded runs used OpenRouter `:free` Nemotron models. The daily limit (50 requests) ran out mid-benchmark: sanitizer, sqlfmt and webhooks (`20261029-120256/120418/120442-job`) ended `ok:false` with a 429 at the plan step. The benchmark is 3/6 completed, not 6/6.
- **Slow free models.** Measured runs took 390–723 s. Nano alone took 279 s in `113639-job`. The speed work added reasoning control, JSON mode, parallel triage and research, and `uv`. With `uv`, venv+install measured 0.19–0.23 s vs 5.8–5.9 s with pip. **End-to-end time after the speed work is not measured yet** (quota ran out).
- **Model JSON reliability.** Malformed JSON from free models broke steps. We added JSON mode, retries and fallbacks.
- **Generated exploits are unreliable.** In the fetcher run (`114842-job`), the generated proof was "not proven" and blocked 0/8 variants. In the mailer run (`115625-job`) it was "inconclusive: old version passed the test too". We built a **curated, verified exploit library**: each proof fails on the old version and passes on the new one (e.g. bleach CVE-2021-23980: 9 failed → 9 passed; sqlparse CVE-2024-4340: 6 failed → 8 passed). We report "not proven" when that's the truth.
- **OSV rarely has symbol data.** Reachability falls back to Nemotron and is labelled `llm-inferred`. OpenVEX never emits `not_affected` from LLM-inferred evidence.
- **We found a hole in our own agent.** The sandbox originally passed the full `os.environ`, API keys included, to the scanned repo's code. We fixed it with an allow-list and a test (`tests/test_sandbox_env.py`).

## Accomplishments
- `20261029-113639-job` (authsvc, PyJWT CVE-2022-29217): 16 advisories, Super → Ultra escalation, tests green on attempt 3, exploit **proven closed**, red-team **7/8 blocked** (1 reported still open), trust score 93.
- All 6 benchmark CVEs have curated proofs verified fail-old / pass-new.
- A dependency bot that tells you what it *couldn't* prove: "partial" ledger claims, "still open" variants, "not proven" exploits.
- A finding from the trust check: the least-change targets (PyJWT 2.4.0, urllib3 1.26.19/2.2.2, Jinja2 3.1.3) have **no PyPI attestation**, while the latest releases do. That gives a data-backed reason to jump to latest.

## What we learned
- Green tests aren't the same as safe. You need an exploit that fails before the fix and passes after, or you're only claiming.
- Routing by failure (Super first, Ultra on failure) keeps the big model for the hard cases.
- Free-tier endpoints are fine for development but not for a benchmark. Measure early and record everything so it can be replayed.
- An agent that runs untrusted repo code is itself an attack surface.

## What's next
- A full recorded benchmark run on **Nebius Token Factory** (ids pinned in `.env.example`, still to be verified), with a per-tier latency/cost table.
- NVIDIA content-safety gate (`patchpilot/guard.py`, in progress): an AST screen plus `nemotron-3.5-content-safety` that screens AI-written code before it runs.
- One real PR on a public repo (shortlist: greyli/bluelog, todoism, sayhello, hack4impact/flask-base).
- Re-run the 6-case benchmark with curated proofs and publish the results table.
- npm support (feasibility done: jsonwebtoken 8.5.1 → 9.0.0, CVE-2022-23540).
- Container sandbox. Today the venv is **not a security boundary**.

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
