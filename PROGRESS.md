# PatchPilot: Hackathon Progress Tracker

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
