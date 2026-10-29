# PatchPilot: Hackathon Progress Tracker

## Handoff: current workstream (last updated 2026-10-29)

This section is the living task list. Anyone picking this up should read it first. Ticked items are done, verified (pytest + pyflakes, and browser checks where relevant) and pushed to `main`.

### How the work is run
- **Loop.** Research agent → engineer agent implements a round → strict tester agent scores it and lists defects with file:line → the next engineer round fixes them. Each verified round is committed and pushed straight to `main`.
- **Commands.**
  - Venv: `python -m venv .venv && pip install -r requirements.txt -r requirements-dev.txt`
  - Tests: `pytest -q`
  - Lint: `pyflakes patchpilot tests cases`
- **Secrets.** Never commit `.env`, `runs/`, `*.db` or `secret.key` (all git-ignored).
- **Current `.env` setup.** It points at **OpenRouter's free Nemotron models** while Nebius credits are pending. The shipped `demo-runs/` are genuine **Token Factory** recordings. Do not replace them with OpenRouter runs.
- **Scoring rule set by the owner.** Exclude demo URL, video, feedback text and submission dates from site scores.

### Phase 1: hackathon polish (score 66 → 100 on strict rubric) ✅
- [x] Hardening rounds 1–11:
  - auth and rate limits
  - token-safe PR push
  - CSP without unsafe-inline
  - XSS fixes
  - accessibility (axe-clean)
  - mobile
  - SEO
  - CI
- [x] Benchmark recorded on Nebius Token Factory: 6/6 green, shipped in `demo-runs/`, with 5 of them showing live Tavily research.
- [x] Bug fixes found along the way:
  - `enable_thinking=false` for Token Factory
  - JSON fence parsing
  - deterministic missing-dependency repair
  - SSE no longer gzipped
- [x] Live NVIDIA guard model evaluation (`docs/guard-eval.md`) plus 3 guard fixes.

### Phase 2: from hardcoded demo to real product
Practicality score history: **58** (after round 1) → **78** (after round 4) → round 5 in progress.

- [x] **Round 1 (`f198b95`).**
  - Projects (GitHub URL or uploaded manifest) with SQLite history.
  - Keyless OSV scan mode.
  - Parsers for requirements, pyproject, poetry.lock, uv.lock and Pipfile.lock.
  - Projects UI and sample projects.
  - Honest landing page with no fake numbers.
- [x] **Round 2 (`1104c1d`).**
  - Dashboard built from the DB, with new/fixed tracking.
  - Encrypted settings UI with connection tests.
  - Users, sessions, API keys and audit log.
  - Per-project policy and ignores.
- [x] **Round 3 (`be49e9e`).**
  - Honest coverage (no false all-clear).
  - Monorepos; 5 MB lock files; garbage uploads rejected.
  - OSV batch with no dependency cap; CVSS-derived severity; EPSS batching.
  - Scan queue that survives restarts.
  - Repo and ref validation.
  - Password change and reset.
- [x] **Round 4 (`ab5af05`).**
  - Scheduled re-scans.
  - Slack, webhook (HMAC-signed) and email alerts.
  - CLI scan with table/json/SARIF/CycloneDX output and exit codes; GitHub Action; pre-commit hook.
  - Exports, auto-fix, Docker sandbox and docker-compose.
- [ ] **Round 5 (in progress, engineer running).** Fixes from the 78/100 test:
  - [ ] Notifications sent off the scan worker (a dead webhook stalled the queue), with a circuit breaker.
  - [ ] CLI exits 2 on unverified or errored scans (no false CI pass); single-file scans accept only requirements-like names.
  - [ ] SSRF protection for webhook, Slack and SMTP targets (block private, loopback and metadata IPs; pin DNS; no redirects).
  - [ ] Login rate limit counts failures per (IP, email), so an attacker can't lock out the admin; document `--proxy-headers`.
  - [ ] Invalid requirement lines become warnings and count against coverage.
  - [ ] Fonts self-hosted, so the CSP is `'self'` only with zero console noise.
  - [ ] Tests for email channel e2e, the auto-fix enqueue path and CycloneDX schema fields.
- [ ] **Next.** Re-run the full practicality test (three personas: security lead, CI developer, attacker). Feed defects into round 6 and repeat until the product is adoptable (target 95+).

### Planned after the practicality target is met
- [ ] Re-check the hackathon docs (README, DEVPOST, JUDGE-QA, VIDEO-SCRIPT) against the new product features. The product changed a lot since they were written.
- [ ] Judged deployment needs `PATCHPILOT_PUBLIC_DEMO=1`, an admin created via `/setup`, and a GitHub token in Settings (the unauthenticated GitHub API limit is 60 requests per hour).
- [ ] Real Docker-sandbox run. So far only the docker argv has been unit-tested with mocks; no real containers have run.

### Waiting on the owner
- [ ] Nebius credits. Then:
  - switch `.env` back to Token Factory (`NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1`, `MODEL_NANO=nvidia/Nemotron-3_5-Lightning`, `MODEL_SUPER=nvidia/nemotron-3-super-120b-a12b`, `MODEL_ULTRA=nvidia/Nemotron-3-Ultra-550b-a55b`)
  - re-record the sanitizer case with Tavily
  - optionally deploy on Nebius Serverless
- [ ] Hosted demo URL, ≤3-min YouTube video, feedback text (README TODO), submission-period dates, one real PR link.
- [ ] Confirm GitHub shows "MIT license" in the repo About sidebar.
- [ ] Rotate the Tavily key after judging (it was pasted in chat).

---

## Earlier tracker (pre-handoff)

## Hackathon at a glance
| | |
|---|---|
| Event | Nebius × NVIDIA Global AI Hackathon 2026 (Devpost) |
| **Deadline** | **30 Oct 2026, 10:00 AM Pacific** (from a third-party listing; **confirm on Devpost**). That's 10:30 PM IST. |
| Judging | 1–15 Dec 2026 |
| Our track | **Coding and Agentic Engineering** |
| Also eligible | Grand / 2nd / 3rd prize · **Best Use of Tavily ($3,000)** · Most Valuable Feedback ($100 × 10) · City Winner ($500, only if we attended a Builders & Brews event) |
| Hard requirement | Runs on Nebius Token Factory or AI Cloud, and uses at least one NVIDIA open model ✅ (Nemotron) |

### Judging criteria and how we hit each one
| Criterion | Our evidence |
|---|---|
| Technological implementation | 3-tier Nemotron routing with escalation; a real sandboxed test loop; guardrails; live SSE dashboard; Tavily, OSV and PyPI integrations |
| Design | A complete product: launch form, live pipeline, advisories, model routing, test timeline, diff, PR report, run replay, dark/light themes, mobile layout |
| Potential impact | Every team using dependency bots has unmerged security PRs. We cut the time a known vulnerability stays open from weeks to minutes. |
| Quality of idea | Bots stop at the version bump, and the AI tools that repair code are closed source. We built an open agent that repairs the code the upgrade breaks. |

### Submission checklist
- [x] Working project
- [x] Open-source license (MIT) at the repo root
- [x] README with setup steps and the NVIDIA/Nebius usage
- [x] `.env.example` documents all three provider options (Token Factory, NIM, OpenRouter)
- [ ] Capture screenshots into `docs/screenshots/` (README references them)
- [ ] Add `NEBIUS_API_KEY` and `TAVILY_API_KEY` to `.env` and do a **real** run on the demo repo
- [ ] Record 2–3 real runs (committed in `runs/`) so judges can use **Replay** without spending credits
- [ ] Set `PRICE_*` from the Token Factory pricing page so the cost and savings figures show
- [ ] Push to a **public GitHub repo** (the license must appear at the top of the repo page)
- [ ] Deploy to a public URL (Nebius Serverless Endpoint, or Render/Railway as a fallback) → **demo URL**
- [ ] Optional: a real PR against a throwaway public GitHub repo (set `GITHUB_TOKEN`)
- [ ] Demo video **≤ 3 min**, public on YouTube
- [ ] Fill in the feedback section below and paste it into Devpost
- [ ] Devpost form: track, description, demo URL, video, repo URL
- [ ] Submit **at least 2 hours before the deadline**

## Official rules compliance (checked 29 Oct 2026)
| Rule | Status / action |
|---|---|
| Deadline **30 Oct 2026, 10:00 AM PT** (confirmed in the official rules) | Submit early. No edits are allowed after the deadline. |
| "Runs on Token Factory" = a runtime call to the Token Factory inference API | ✅ Every run calls Nemotron on Token Factory |
| Stage 1 pass/fail: a genuine attempt at the track | ✅ Coding track: the agent writes, runs and tests code |
| Working demo URL, **free and unrestricted until 15 Dec 2026** | ⚠️ Keep the host running and the API credits funded until judging ends. Replay mode means judges can see a run without spending credits. |
| Must install and run consistently, matching the video and description | ⚠️ Only show in the video what the app really does. Test a fresh clone using the README steps. |
| Public repo containing everything needed to run it | ⚠️ Commit `.env.example` but **never `.env`**. Commit the recorded runs. |
| License detectable in the GitHub **About** section | ✅ MIT `LICENSE` at the repo root. Check that GitHub shows "MIT license" after pushing. |
| README: setup steps, Nemotron usage, where Token Factory helped, other Nebius services | ✅ Done. Add real numbers after the first real run. |
| Video < 3 min, public on YouTube, **no third-party trademarks or copyrighted music** | ⚠️ Don't show other companies' logos; mention competitors only in text. Use no music or royalty-free music only. |
| Feedback section | ⚠️ Fill in with real observations (this also enters us for the Most Valuable Feedback prize) |
| Third-party APIs used within their terms | OSV.dev, PyPI and Tavily are public APIs. Credit OSV.dev in the README. |
| Original work, owned by the entrant | Code written during the Submission Period (new project, so no "significant update" note is needed). Be ready to explain your role in building it if asked during winner verification. |
| Prize stacking: **one Overall OR one Track award, plus one Bonus** | We target Overall or the Coding track, **plus Best Use of Tavily**. Tavily must be **active at runtime** on the hosted demo. |
| Tie-breaker order: Technological Implementation first, then Design, Impact, Idea | Put engineering quality first: real test loop, guardrails, model routing, evaluation numbers |
| Eligibility | Individual entrants who are of age and not in a sanctioned region. If entering as a team, name one Representative. |

## What's built (29 Oct 2026)
| Area | Status | Notes |
|---|---|---|
| Demo target repo | ✅ | PyJWT 1.7.1 + requests 2.25.1. Baseline 9/9 tests pass; after the upgrade 7 fail (verified) |
| OSV.dev + PyPI scan | ✅ | Live: 16 de-duplicated advisories on the demo repo |
| Nemotron router | ✅ | Auto-discovers models from `/models`, retries, strips `<think>`, tracks tokens/latency/cost |
| Nano triage, Super plan | ✅ | JSON outputs, plus a version guardrail |
| Tavily research | ✅ | Skipped cleanly when there's no key |
| Sandbox test loop | ✅ | Fresh venv per run; Super → Ultra escalation, up to `MAX_FIX_ATTEMPTS` |
| Diff, report, PR | ✅ | GitHub PR via REST when a token is set; otherwise a `.patch` file |
| Web dashboard | ✅ | Live SSE, replay, themes, responsive |
| CLI / batch job | ✅ | `python -m patchpilot.cli …` |
| Dockerfile | ✅ | Endpoint by default; the Job overrides the command |
| Multipage UI | ✅ | `/`, `/console`, `/runs`, `/org`, `/how` |
| Exploit proof | ✅ | Generated pytest run before and after the upgrade |
| PR risk score | ✅ | 0–100 from churn, files, major jumps, attempts, tests, exploit proof |
| Reachability map, model debate, voice briefing | ✅ | Console tabs; voice uses browser speech synthesis |
| Org-wide scan | ✅ | `/api/org/{owner}` heat map over public Python repos |
| Multi-provider | ✅ | Nebius Token Factory, NVIDIA NIM, OpenRouter via `NEBIUS_BASE_URL` |
| Submission README | ✅ | Pitch, mermaid pipeline, routing table, providers, comparison, limits, roadmap |
| Screenshots in `docs/screenshots/` | ⬜ | README has placeholders |
| End-to-end smoke test | ✅ | Full pipeline verified with a **local stub LLM** (not committed). **Not yet run against real Nemotron.** |

## Next steps, in priority order
1. **Real run with the Nebius key.** Check the Nemotron JSON outputs parse. If a tier is missing, pin it with `MODEL_*`.
2. Tune the prompts if Super's first fix attempt fails often. (Ultra escalating to fix it is actually a good thing to show in the demo.)
3. Deploy and confirm the public URL works in a private browser window.
4. Record the video (script below).
5. Stretch goal: an eval table across 5 known breaking upgrades (PyJWT 1→2, pydantic 1→2, SQLAlchemy 1.4→2, Flask 1→3, urllib3 1→2), with success rate and cost for routed vs. Ultra-only.

## Demo video script (≤ 3:00)
| Time | Shot |
|---|---|
| 0:00–0:20 | Problem: a Dependabot PR that's been red for weeks. "The bump is easy. The fix isn't." |
| 0:20–0:35 | PatchPilot UI. Paste the repo, click Run. |
| 0:35–1:05 | 16 real CVEs from OSV. Nano triage verdicts. Tavily migration sources. |
| 1:05–1:40 | Super's plan → upgrade → **7 tests fail** → repair attempt (escalation to Ultra if it happens) → **9/9 green**. |
| 1:40–2:10 | Diff, PR report with citations, model routing panel (tokens and cost per tier). |
| 2:10–2:40 | Architecture: Nemotron tiers on Token Factory, Serverless Endpoint and Job, Tavily. |
| 2:40–3:00 | Impact plus the open-source repo link. |

## Devpost description (draft)
**PatchPilot** is an open-source coding agent that turns a security advisory into a tested pull request. Dependabot-style bots stop at the version bump, so when the fix is a major version the build breaks and the vulnerability stays in production for weeks. PatchPilot scans your pins against OSV.dev. **Nemotron Nano** triages each advisory against your code, **Tavily** researches the migration path, and **Nemotron Super** plans the upgrade and writes the repair. If tests still fail, it escalates to **Nemotron Ultra**. Every change is verified by running your real test suite in an isolated sandbox before a PR is opened with cited sources and a cost breakdown per model. Everything runs on **Nebius Token Factory**, and the batch scanner is packaged for **Nebius Serverless Jobs**.

## Feedback for Nebius / NVIDIA
*(Fill this in honestly as you go. 10 × $100 prizes go to the most valuable feedback. Be specific: what you tried, what happened, what you expected.)*
- Token Factory onboarding / API keys:
- Model discovery (`/models`) and naming consistency for the Nemotron tiers:
- JSON / structured output reliability per Nemotron tier:
- Latency and rate limits during the agent loop:
- Reasoning traces (`<think>`) and how to turn them off:
- Serverless Endpoints / Jobs deployment experience:
- Docs gaps:

## Log
- **29 Oct 2026**: Researched existing open-source tools (OpsGentic, OpenSRE, AutoSRE, OpenGrants OS; Dependabot and Renovate only bump versions) and picked PatchPilot. Built the whole stack, verified the demo repo with real CVEs, and ran an end-to-end smoke test with a stub LLM.
- **29 Oct 2026 (later)**: Added a second real case (Werkzeug 2→3). Fixes now cite Tavily evidence quotes; added handling for Nemotron reasoning output, a remote-repo safety flag, a Benchmarks tab and `run.bat`. UI rebuilt around a live animated agent graph, an exposure counter, a terminal stream and confetti. Both cases verified with the stub: success path (authsvc) and honest failure path (webhooks, 4 attempts → "needs review").
