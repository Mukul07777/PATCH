# PatchPilot

**An agentic DevSecOps tool for software supply chain security: it finds CVEs, upgrades dependencies, rewrites code until the tests pass, and proves the exploit is closed.**

Built on NVIDIA Nemotron (Nano / Super / Ultra) served by **Nebius Token Factory** (the default provider), with Tavily, OSV.dev and PyPI. Any other OpenAI-compatible endpoint (NVIDIA NIM, or OpenRouter as a fallback) also works.

- **Hackathon:** NVIDIA Global AI Hackathon · **Track: Coding and Agentic Engineering** · LLMs: NVIDIA Nemotron on Nebius Token Factory · Research: Tavily
- **Live demo:** TODO <!-- TODO(owner): public URL of the deployed app; leave as TODO until it exists -->
- **Video:** TODO <!-- TODO(owner): link to the demo video -->

---

## Testing instructions for judges

**Hosted demo, no credentials needed.** <!-- TODO(owner): hosted demo URL (same as "Live demo" above). -->
1. Open `/console`. If the deployment has recorded runs, one replays automatically (the "LIVE REPLAY" badge); `/console?demo=1` is a guided walkthrough of a recorded run with captions.
2. To pick a specific recording, use **Replay a recorded run** under the launch box, or open `/runs` and click **Replay** on any card. Failed runs show their failure reason on the card.
3. To start a live run, pick a case (e.g. `case:authsvc`) and click **Launch agent**. This needs `NEBIUS_API_KEY` on the server; without it the button is disabled and the console says so and points to replay.
4. Tabs to look at after a run: **Advisories**, **Evidence (Tavily)**, **Certificate**, **Proof & risk**, **Drift radar**, **Diff**, **PR report**.

Recorded runs live in `runs/*.jsonl`, which is git-ignored, so a fresh clone has none until you run the agent once. <!-- TODO(owner): confirm the judged deployment ships with recorded runs. -->

**Judged deployment settings.** Leave `PATCHPILOT_TOKEN` **unset** on the judged deployment: when it is set, `POST /api/runs` requires `Authorization: Bearer <token>`, which the browser console does not send, so judges could not launch runs. Keep `ALLOW_REMOTE_REPOS=0` (only the bundled cases run).

**Local run.** `cp .env.example .env`, set `NEBIUS_API_KEY` (and `TAVILY_API_KEY` for research), then `pip install -r requirements.txt` and `uvicorn patchpilot.server:app --port 8000` (or `run.bat` on Windows); see [Quickstart](#quickstart). Tests: `pytest`.

## The problem

Dependency bots open a version-bump PR and stop there. When the fix needs a **major** version, the bump breaks the build, the PR goes red, and the known vulnerability stays in production until someone finds time to migrate the code. The bump is easy. The fix is the hard part.

## How it works

```mermaid
flowchart LR
  A[Discover models] --> B[Checkout repo]
  B --> C[OSV.dev + PyPI scan]
  C -->|no advisories| Z[Done: clean]
  C --> D[Nano triage + reachability]
  D --> E[Tavily research]
  E --> F[Super upgrade plan]
  F --> G[Baseline tests + exploit proof]
  G --> H[Bump pins + pytest]
  H -->|fail| I[Repair: Super, then Ultra]
  I --> H
  H -->|pass or max attempts| J[Re-run exploit proof]
  J --> K[PR risk score]
  K --> L[Diff + report + PR or .patch]
```

1. **Scan**: every pin in `requirements.txt` is checked against OSV.dev; the latest version comes from PyPI.
2. **Triage**: Nemotron Nano judges each advisory against how your code actually uses the package.
3. **Research**: Tavily finds migration guides and breaking-change notes for each upgrade.
4. **Plan**: Nemotron Super picks target versions (with a version guardrail).
5. **Exploit proof**: a pytest demonstrating the vulnerability (from a curated, verified library for known CVEs, otherwise written by Nemotron) is run before the upgrade, then again after.
6. **Upgrade and repair**: pins are bumped in a fresh venv and pytest runs. On failure, Super writes the first fix; later attempts escalate to Ultra, up to `MAX_FIX_ATTEMPTS`.
7. **Ship**: risk score, unified diff, Markdown report with cited evidence, and a GitHub PR (when `GITHUB_TOKEN` is set and the repo is a GitHub URL) or a `.patch` file.

## Features

- **Live agent graph**: each pipeline step streams to the console over SSE.
- **Exploit proof**: a curated or Nemotron-written test shows the vulnerability before the upgrade and checks it is closed after.
- **Threat clock**: each advisory gets its live EPSS exploit probability (FIRST.org), CISA Known Exploited status and how many days it has been public, so you fix what attackers actually use first.
- **API drift radar**: before any test runs, PatchPilot walks your code's AST, then probes the *installed* old and new library versions in the sandbox to predict exactly which lines break (removed symbols, dropped keyword arguments), and hands that list to the repair model. Behaviour changes are left to the tests.
- **Least-change upgrade**: the smallest release that clears every advisory is computed from OSV fix ranges and shown next to the latest version.
- **Content-safety gate**: every AI-written exploit proof, red-team variant and patch file is screened before it runs or is written: a deterministic AST scan (shell/subprocess calls, eval/exec, environment reads, network calls to non-local hosts, deletes and opens outside the repo, reverse-shell and miner strings, non-PyPI requirement sources) plus NVIDIA's `nemotron-3.5-content-safety` guard model in custom-policy mode (`MODEL_GUARD` selects it; it is filled in automatically only on OpenRouter, so on Nebius Token Factory set `MODEL_GUARD` to the content-safety model id your account lists; `GUARD=0` disables the gate). Blocked proofs are skipped and blocked patch files are rejected, with the reason fed to the next repair attempt. If the guard model errors (e.g. 429), only the static scan runs and the ledger claim drops to partial. Curated proofs get the static scan only.
- **Red-team variants**: after the fix, 5-8 variants of the attack (other algorithms, key types, encodings) run against the patched code; each is reported as closed by fix, already blocked, or still open.
- **Proof certificate (evidence ledger)**: every claim the PR makes, each checked independently, including a fresh OSV re-scan of the new pins, a trust score, and a SHA-256 over claims + diff.
- **OpenVEX export**: each run emits an [OpenVEX v0.2.0](https://github.com/openvex/spec) document (`runs/work/<run>/openvex.json`, also `GET /api/runs/{id}/vex`) with one statement per advisory on `pkg:pypi/<name>@<old version>`: `fixed` only when the OSV re-scan cleared it and tests are green, `not_affected` only when static analysis shows the package is never imported (never from LLM-inferred data), otherwise `affected`. Notes cite the proof certificate id and exploit verdict.
- **Ranked research**: Tavily returns 8 results; they are ranked by Tavily's relevance score (Nemotron Nano scores them instead when Tavily gives no score) and only the top 4 reach the repair model.
- **PR risk score**: 0 to 100 from code churn, files touched, major-version jumps, repair attempts, test result and exploit proof.
- **Release trust check**: before upgrading, each old and target release is looked up on the free deps.dev v3 API: publish date, whether the target carries a *verified* PyPI publish attestation (and whether the old one did), its source repo, the repo's OpenSSF Scorecard (overall plus Code-Review, Maintained, Signed-Releases, Dangerous-Workflow) and any transitive dependencies the target adds. This feeds a "Supply-chain trust" risk factor (0 when deps.dev has no data) and a ledger claim. In our cases the latest releases (PyJWT 2.15.1, urllib3 2.8.0, Jinja2 3.1.6) all had verified attestations, while the old pins and the least-change targets from 2022-2024 (PyJWT 2.4.0, urllib3 1.26.19, Jinja2 3.1.3) had none; Scorecard is per repository, not per release (pyjwt 6.9, urllib3 8.6, jinja 5.9), and no upgrade added a new transitive dependency. slsaProvenances was empty for all of them.
- **Reachability map**: where each vulnerable package is used in your code.
- **Symbol-level reachability**: each advisory is labelled reachable (with file:line), imported-but-unused, not reachable, or unknown by matching its vulnerable symbols against an AST scan of your code (including re-exports and Jinja `|filter` uses in templates). Symbols come from OSV's PyPA `ecosystem_specific.imports` field when present, but in practice the OSV API returned that field for 0 of the advisories in our six benchmark cases, so most symbols are Nemotron Nano-inferred from the advisory text and labelled `llm-inferred`; if the LLM is unavailable those advisories stay `unknown`. The result feeds triage, an advisory-urgency rating next to the risk score, and a ledger claim (verified only when every symbol came from OSV).
- **Model debate**: each repair attempt's diagnosis (Super, then Ultra) side by side.
- **Org-wide heat map**: scans a GitHub user or org's public Python repos for vulnerable pins.
- **Replay**: recorded runs in `runs/` replay without spending API credits.
- **Voice briefing**: a spoken run summary using the browser's speech synthesis.
- **Cited evidence**: fixes quote the Tavily sources they relied on.

## How Tavily is used

Tavily is called at runtime on every run that has advisories, when `TAVILY_API_KEY` is set (`patchpilot/sources.py: tavily_search`, called from `patchpilot/agent.py: _analyse`):

1. **Research query** per vulnerable package: `"<package> upgrade <current> to <latest> breaking changes migration guide"`, sent to `POST https://api.tavily.com/search` with `search_depth: "advanced"`, `include_answer: true`, `max_results: 8`. Up to 3 packages are researched in parallel, alongside triage.
2. **Ranking**: results are sorted by Tavily's own relevance score (shown 0-10). If Tavily returns no scores, Nemotron Nano reranks them. The top 4 (plus Tavily's answer) are kept.
3. **Used by the models**: the kept results' URLs and text go to the repair model (Super / Ultra) as `migration_research`, and the top 2 to the exploit-proof writer when no curated proof exists. The repair model must quote the exact lines it relied on, with their URL.
4. **Citations**: the console's **Evidence (Tavily)** tab lists every source under "Research via Tavily" plus the quoted lines, and the PR report has a "Sources consulted (Tavily)" section and the quotes with their URLs. The ledger records how many quoted lines came from researched sources.

Without `TAVILY_API_KEY`, research is skipped and logged; the rest of the pipeline still runs.

## Model routing

| Tier | Job |
|---|---|
| Nemotron **Nano** | Advisory triage against code usage (cheap, high volume) |
| Nemotron **Super** | Upgrade plan, exploit-proof test when no curated one exists (Ultra as fallback), first repair attempt |
| Nemotron **Ultra** | Escalated repair attempts when Super's fix still fails tests |

### Nemotron model roles

| Model | What | Why | When escalated |
|---|---|---|---|
| **Nano** | Advisory triage, vulnerable-symbol inference for reachability, research rerank (when Tavily gives no scores) | High volume, short answers: cheapest and fastest | Never; failures fall back to `unknown` / Tavily order |
| **Super** | Upgrade plan, exploit-proof test (no curated one), first repair attempt | Good code quality at moderate cost | Exploit writing falls back to Ultra; repair moves to Ultra after a failed attempt |
| **Ultra** | Later repair attempts | Deepest reasoning, used only when needed | Reached when Super's fix fails tests or a fix call exceeds `FIX_TIMEOUT` |
| **Guard** (`MODEL_GUARD`, optional) | Content-safety screen of AI-written proofs, variants and patch files | Blocks unsafe code before it runs | On error (e.g. 429) only the static AST scan runs |

Models are auto-discovered from `/models` unless pinned with `MODEL_NANO` / `MODEL_SUPER` / `MODEL_ULTRA`. Tokens, latency and (if `PRICE_*` is set) cost are tracked per tier.

## Quickstart

**Windows**

```bat
run.bat
```

Creates `.venv`, installs dependencies, copies `.env.example` to `.env` on first run (opens it in Notepad for your keys), then serves http://localhost:8000.

**Manual (any OS, Python 3.10+)**

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # add your keys
uvicorn patchpilot.server:app --port 8000
```

CLI / batch mode: `python -m patchpilot.cli`. Container: see `Dockerfile`.

- Pages: `/` landing, `/console` run the agent, `/runs` history and replay, `/org` org scan, `/how` architecture.
- API: `/api/health` (GET/HEAD), `/api/cases`, `/api/runs`, `/api/runs/{id}/events`, `/api/org/{owner}`, `/api/bench`.
- Demo cases in `cases/` (pins from each `requirements.txt`):
  - `authsvc`: PyJWT 1.7.1 + requests 2.25.1
  - `fetcher`: urllib3 1.26.17
  - `mailer`: Jinja2 2.11.3 + MarkupSafe 2.0.1
  - `sanitizer`: bleach 3.2.1
  - `sqlfmt`: sqlparse 0.4.1
  - `webhooks`: Werkzeug 2.0.3

## Tests

Fast, offline unit tests for the agent itself (drift radar, OSV version math, JSON parsing, exploit library,
risk score and trust ledger). No network, no LLM calls:

```bash
pip install pytest
.venv/Scripts/python.exe -m pytest -q
```

`pytest.ini` limits collection to `tests/`; the bundled `cases/*/tests` suites need their own pinned venvs and
are run by PatchPilot's sandbox instead.

## Speed

Recorded runs on free OpenRouter Nemotron endpoints showed that model calls take 97 to 98 % of wall time
(authsvc: 709 of 723 s, mostly hidden reasoning tokens). The current pipeline makes these changes:

- Reasoning control per call (`reasoning="off"|"low"`). It uses OpenRouter's `reasoning` object or NIM/vLLM's
  `enable_thinking`. If the provider rejects the field, PatchPilot retries without it and stops sending it.
  JSON mode is used where accepted. Fix calls have a 90 s cap, and a call that hits it escalates to Ultra.
- Nano triage is capped at 1500 tokens with reasoning off. It is skipped when static reachability is conclusive.
  Research is ranked by Tavily's own relevance score, with no model call.
- Reachability and triage run alongside Tavily research (3 workers).
- The sandbox is prepared in the background right after checkout, using `uv` when it is on PATH.
  Measured locally for authsvc's pins: `uv` venv + install takes 0.2 to 0.3 s, against 5.8 to 5.9 s for
  `venv` + pip.
- `PATCHPILOT_DEMO=1`: at most 2 fix attempts, and curated exploit proofs and variants only.

An end-to-end timing of the new pipeline has not been measured yet, because the free tier's daily quota was used up.

## Provider setup

The LLM client is OpenAI-compatible and reads `NEBIUS_API_KEY` and `NEBIUS_BASE_URL`. Nebius Token Factory is the default (`NEBIUS_BASE_URL` falls back to `https://api.tokenfactory.nebius.com/v1` when unset); the other providers are optional.

**1. Nebius Token Factory (default)**
```ini
NEBIUS_API_KEY=your-nebius-key
NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1
# optional: content-safety gate model (not auto-filled outside OpenRouter)
MODEL_GUARD=<content-safety model id listed by GET /v1/models>
```
Auto-discovery matches `nano`/`lightning`/`mini`, `super` and `ultra` in Nemotron model ids. To be safe, pin the ids (e.g. `MODEL_NANO=nvidia/Nemotron-3_5-Lightning`, `MODEL_SUPER=nvidia/nemotron-3-super-120b-a12b`, `MODEL_ULTRA=nvidia/Nemotron-3-Ultra-550b-a55b`; see `.env.example`). Check them against `GET /v1/models` first. Without `MODEL_GUARD` the content-safety gate still runs its static AST screen.

**2. NVIDIA NIM**
```ini
NEBIUS_API_KEY=nvapi-...
NEBIUS_BASE_URL=https://integrate.api.nvidia.com/v1
```

**3. OpenRouter (free tier, fallback)**
```ini
NEBIUS_API_KEY=sk-or-...
NEBIUS_BASE_URL=https://openrouter.ai/api/v1
MODEL_NANO=nvidia/nemotron-3.5-lightning:free
MODEL_SUPER=nvidia/nemotron-3.5-super-vl:free
MODEL_ULTRA=nvidia/nemotron-3-ultra-550b-a55b:free
```
On OpenRouter `MODEL_GUARD` defaults to `nvidia/nemotron-3.5-content-safety:free`.

Optional: `TAVILY_API_KEY` (research; skipped if unset), `GITHUB_TOKEN` (real PRs, higher org-scan rate limit), `PRICE_*`, `MAX_FIX_ATTEMPTS`, `PATCHPILOT_TOKEN` (requires `Authorization: Bearer <token>` on `POST /api/runs`), and `ALLOW_REMOTE_REPOS=1` to enable remote GitHub repos (off by default: remote repos run arbitrary test code).

## Built on Nebius

- **Token Factory is the default LLM host.** `patchpilot/config.py` defaults `NEBIUS_BASE_URL` to `https://api.tokenfactory.nebius.com/v1`, and `patchpilot/llm.py` sends every model call there with the `NEBIUS_API_KEY` bearer token. Models are discovered from Token Factory's `/models` list, or pinned with `MODEL_NANO` / `MODEL_SUPER` / `MODEL_ULTRA`.
- **Nemotron roles** (router in `patchpilot/llm.py`):
  - **Nano** (`nano` / `lightning` / `mini` ids): fast, cheap triage and classification: advisory triage and symbol inference for reachability.
  - **Super**: planning and first-pass code changes: upgrade plan, exploit-proof test when no curated one exists, first repair attempt.
  - **Ultra**: deep reasoning on escalation: later repair attempts when Super's fix still fails tests, or when a fix call hits the `FIX_TIMEOUT` cap.
  - **Guard** (`MODEL_GUARD`, optional): NVIDIA Nemotron content-safety model screening AI-written code before it runs.
- Tokens, latency and (with `PRICE_*`) cost are recorded per tier for every run.

<!-- TODO(owner): state whether a recorded end-to-end run on Token Factory exists and link its run id / numbers. Do not claim one until it does. -->

### Deploying on Nebius AI Cloud (how-to)

The `Dockerfile` supports both Nebius serverless modes. These steps describe how to deploy; they have not been carried out for this submission. <!-- TODO(owner): update if/when deployed. -->

- **Serverless Endpoint (web app + API).** Build the image and push it to a registry Nebius can pull from, then create an endpoint from it exposing port `8000`. Pass `NEBIUS_API_KEY` (and optionally `TAVILY_API_KEY`, `GITHUB_TOKEN`, `PATCHPILOT_TOKEN`, `MODEL_*`, `MODEL_GUARD`) as environment variables or secrets, and keep `ALLOW_REMOTE_REPOS=0` on a public endpoint. The image's `HEALTHCHECK` polls `/api/health`, which also answers `HEAD`.
- **Serverless Job (benchmark / batch).** Run the same image with the command overridden to the CLI: `python -m patchpilot.cli <repo-or-case> https://github.com/org/repo`. Runs are recorded under `runs/`; mount or copy that directory out to keep them.

## Screenshots

| View | Image |
|---|---|
| Landing | `docs/screenshots/landing.png` |
| Live console | `docs/screenshots/console.png` |
| Exploit proof + risk score | `docs/screenshots/risk.png` |
| Model debate | `docs/screenshots/debate.png` |
| Org heat map | `docs/screenshots/org.png` |

## Comparison

| | Dependabot | Renovate | Snyk | PatchPilot |
|---|---|---|---|---|
| Detects vulnerable dependencies | Yes | Yes | Yes | Yes (OSV.dev) |
| Opens upgrade PRs | Yes | Yes | Yes | Yes |
| Rewrites your code to fix breaking changes | No | No | not verified | Yes (LLM repair loop) |
| Runs your tests before proposing the PR | No (relies on your CI) | No (relies on your CI) | not verified | Yes, in a sandbox venv |
| Generates an exploit-proof test | No | No | not verified | Yes |
| Open source | Yes | Yes | No | Yes (MIT) |
| Ecosystems | Many | Many | Many | Python only |

## Limitations

- The content-safety gate's static AST screen and guard-reply parsing are unit-tested; its behaviour against a live hosted guard model has not yet been recorded in a benchmark run.
- Python only: needs a pinned `requirements.txt` (`pkg==x.y.z`) and a pytest suite.
- Tests run on the host in a venv, not a container; keep `ALLOW_REMOTE_REPOS=0` on public deployments.
- Free-tier models (e.g. OpenRouter `:free`) can be rate-limited, slow, or return malformed JSON, so runs may fail or need a retry.
- Green tests are only as strong as the repo's test suite.

## Feedback on Nebius & NVIDIA tools

<!-- TODO(owner): write this from first-hand experience. Prompts:
  - Token Factory: onboarding, finding the Nemotron model ids, /v1/models accuracy, rate limits, latency, pricing clarity.
  - Nemotron Nano / Super / Ultra: JSON reliability, reasoning control, where each tier surprised you.
  - Nemotron content-safety guard: custom-policy prompt format, false positives/negatives.
  - Nebius Serverless Endpoints / Jobs: if used, what worked and what was missing.
  - Differences between NVIDIA NIM and Token Factory (e.g. enable_thinking).
  - One concrete change you would ask each team for. -->
TODO

## Changes during the submission period

Every commit in this repository is dated 2026-10-29 (check with `git log --format=%ad`). <!-- TODO(owner): confirm the official submission-period dates and whether any work predates them. --> In order:

- **Initial agent** (00:29): security advisory to tested PR on NVIDIA Nemotron + Nebius Token Factory.
- **Core features**: multipage UI, verified exploit proofs, risk score, reachability, model debate, org scan, red-team variants, proof certificate, Nemotron rerank, threat clock, API drift radar, least-change upgrade, real-world benchmark cases.
- **Benchmark and self-tests**: benchmark round 1 (3/3 completed cases secured; 3 cases blocked by API rate limit), agent self-test suite, provider and models recorded per run.
- **Supply-chain depth**: curated exploit proofs for urllib3, Jinja2, bleach and sqlparse CVEs; symbol-level reachability; deps.dev release trust check; OpenVEX export; Nebius model id pinning.
- **Speed and safety**: reasoning control, parallel triage/research, `uv` sandbox prep, demo mode; API keys kept out of the sandboxed repo's environment; NVIDIA content-safety gate + static AST screen.
- **UI**: guided demo mode, auto-replay console, trust / OpenVEX / guardrails panels, per-tier charts.
- **Hardening**: auth + rate limits, token-safe PR push, CI, CSP and security headers, no inline scripts, XSS-safe report links, org-scan limits, accessibility, SEO meta, gzip.
- **Submission drafts**: Devpost text, video script, judge Q&A, 30-second pitch.
- **Hardening round 4**: no inline styles (CSP without `style-src 'unsafe-inline'`), `HEAD` on `/api/health` and `/api/runs`, `/robots.txt`, org-scan `reason` field, reduced-motion CSS, this README's Nebius sections.

## Roadmap

- Auto-rollback guard: revert an upgrade if post-merge checks regress.
- Slack bot: briefings and approvals in chat.
- npm ecosystem support.

## Credits

Vulnerability data from [OSV.dev](https://osv.dev). Package metadata from PyPI. Web research by [Tavily](https://tavily.com).

## License

MIT, see [LICENSE](LICENSE).
