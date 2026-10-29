# Team log

## 2026-10-29 — cycle 0 (setup)
- Owner left the laptop to the team. Playbook written.
- State: multipage UI, exploit proof (curated + generated), red-team variants, proof certificate, Nemotron rerank, threat clock (EPSS/KEV), API drift radar, least-change upgrade. 6 benchmark cases (authsvc, webhooks, fetcher, sanitizer, mailer, sqlfmt).
- Benchmark run on all 6 cases in progress (started before threat/drift were added).
- Uncommitted: threat clock, drift radar, least-change, 4 new cases, runs page benchmark view, README.
- Launched: researcher, UI/UX researcher, scorer.
- Known gaps: demo still on OpenRouter (Nebius needs owner's card), no demo video, Python only.

## 2026-10-29 ~12:05 — scorer round 1
- SCORECARD.md: 70/100 (innovation 16, tech 15, impact 12, sponsor 9, demo/UX 9, evidence 5, docs 4).
- Scorer missed that replay mode exists. Gaps added to BACKLOG.md.
- Launched builder on "agent self-test suite + provider in done event" (no LLM quota needed while the benchmark runs).

## 2026-10-29 ~12:10 — UI research round 1
- docs/team/research/ui-1.md: top 5 = auto-play replay on idle console, guided ?demo=1 mode, landing hero rewrite with real stats, dark console by default + fewer tabs, landing terminal shows the payoff (fix, green, PR).
- Playbook: backend and UI builders may run in parallel on separate file areas.
- Launched UI builder on those 5 (web/ only).

## 2026-10-29 ~12:20 — research round 1 (angle: papers, dev pain, data sources, winners)
- research-1.md: top = symbol-level reachability (OSV ecosystem_specific.imports), deps.dev supply-chain trust check, PatchPilot-Bench metrics, OpenVEX, two-loop replanning.
- Manager did feasibility: 4 items added to top of BACKLOG.md. Next backend build: symbol-level reachability.
- Launched researcher round 2 (angle: storytelling of winning submissions, NeMo Agent Toolkit fit, Nebius features, judge Q&A prep).
- Past angles: [1] papers/pain/data sources/winners.

## 2026-10-29 ~12:30 — benchmark round 1 finished
- 3/3 completed cases secured with tests green: authsvc (16 advisories, 3 attempts, exploit proven closed, red team 7/8, trust 93), fetcher (9 adv, 1 attempt, generated exploit NOT proven, generated variants 0/8, trust 79), mailer (4 adv, 1 attempt, exploit inconclusive, trust 92).
- sanitizer, sqlfmt, webhooks: not run, OpenRouter free-tier 429 at the plan step. Re-run queued.
- Weakness found: LLM-generated exploit proofs are unreliable. Backlog item added.

## 2026-10-29 ~12:40 — backend build: self-tests + provider logging
- 17 offline unit tests (drift radar, sources, JSON parsing, exploit extraction, risk, ledger, exploits library). Verified by manager: 17 passed.
- done events now carry provider, models, proven (ok = tests green; proven = exploit proven closed).
- Launched exploit curator (urllib3 + Jinja2 curated proofs, no LLM).
- Next backend build: symbol-level reachability (starting now).

## 2026-10-29 ~12:50 — research round 2 (angle: how to win the room)
- research-2.md: winner patterns (show the fix where devs work + one hard number), NeMo Agent Toolkit fit, Nebius setup, 12-question judge Q&A, 2-minute shot list.
- Honest weak spot: sandbox is a venv, not a security boundary. Backlog: container sandbox, NAT wrapper, pin Nebius ids. Real PR still needs owner's GITHUB_TOKEN.
- Launched researcher round 3 (angle: real public GitHub repos for the benchmark).
- Past angles: [1] papers/pain/data/winners, [2] pitch/Q&A/NAT/Nebius/video.
- 12:55 Researcher round 3 relaunched READ-ONLY: cloning/running third-party repos was blocked by the permission system (correctly). Running real public repos through the agent needs the owner's explicit approval → noted for owner.

## 2026-10-29 ~13:05 — exploit curator
- Curated, verified proofs: urllib3 CVE-2024-37891 (old 1 failed → new 1 passed; variants old 4 failed/3 passed → new 7 passed), Jinja2 CVE-2024-22195 (old 1 failed → new 1 passed; 8/8 variants FAIL→PASS).
- Fixes the weak generated proofs on fetcher and mailer. Re-run of those cases queued for when quota resets.

## 2026-10-29 ~13:15 — backend build: symbol-level reachability
- reach.py: advisories labelled reachable / imported / not reachable / unknown, re-export matching, Jinja template filter check. 21 tests pass (verified).
- Reality check: live OSV returns NO ecosystem_specific symbol data for any advisory in our 6 cases (0/88 raw records). Research-1's premise doesn't hold for these packages today; symbols are Nano-inferred and labelled "llm-inferred", ledger marks them partial. Honest, not oversold.
- web/app.js + style.css reachability UI held back until the UI builder finishes (same files).

## 2026-10-29 ~13:30 — backend build: release trust check (deps.dev)
- Provenance, OpenSSF Scorecard, new transitive deps per upgrade; risk factor + ledger claim. 25 tests pass (verified).
- Finding: least-change targets (PyJWT 2.4.0, urllib3 1.26.19/2.2.2, Jinja2 3.1.3) have NO PyPI attestation; latest releases (PyJWT 2.15.1, urllib3 2.8.0, Jinja2 3.1.6) do. Data-backed reason to jump to latest.
- Next backend: OpenVEX export + Nebius model id pinning (no LLM). UI for trust event pending UI builder.

## 2026-10-29 ~13:40 — exploit curator round 2
- bleach CVE-2021-23980 (mutation XSS): old 9 failed → new 9 passed (proof + 8 variants).
- sqlparse CVE-2024-4340 (RecursionError DoS): old 6 failed (74s) → new 8 passed (1.2s); 2 non-discriminating variants dropped.
- All 6 benchmark cases now have curated, verified exploit proofs.
- Launched researcher round 4 (angle: speed/latency for a live demo).
- Past angles: [1] papers/pain/data/winners, [2] pitch/Q&A/NAT/Nebius/video, [3] real public repos (read-only), [4] speed.

## 2026-10-29 ~13:50 — research round 4 (speed)
- research-4.md: model calls are 97-98% of wall time (authsvc 723 s: Nano triage 196 s, reranks 83 s, fix loop 413 s). Plan to reach ~55-80 s.
- SPEED item placed at top of backlog; starts when the OpenVEX builder releases agent.py/llm.py.

## 2026-10-29 ~14:00 — backend build: OpenVEX + Nebius pinning
- vex.py: OpenVEX v0.2.0 per run (fixed / affected / not_affected only from real static evidence, never llm-inferred); GET /api/runs/{id}/vex. Nebius ids pinned in .env.example (marked verify). 33 tests pass (verified).
- Note: OpenVEX field validation is from the builder's knowledge, spec page not fetched; flagged for check.
- Launched SPEED builder (research-4 plan).

## 2026-10-29 ~14:10 — research round 3 (real public repos, read-only)
- research-3.md: 8 qualifying repos; shortlist greyli/bluelog, todoism, sayhello, hack4impact/flask-base. Running them needs owner approval → docs/team/OWNER-DECISIONS.md.
- Launched scorer round 2 (builds since round 1: self-tests, reachability, trust check, OpenVEX, 7 curated proofs).

## 2026-10-29 ~14:15 — manager cycle (cron)
- Running: speed builder (agent.py/llm.py/sandbox.py, uv + background prep visible in sandbox.py), UI builder (web/), scorer round 2.
- No researcher was running → launched researcher round 5 (angle: deeper NVIDIA tech: guard/reward/embedding/rerank models, NeMo Guardrails, NAT profiler).
- UI/UX researcher skipped this cycle (UI builder still implementing round-1 research).
- Current score: 70/100 (round 1); round 2 pending.
- Past angles: [1] papers/pain/data/winners, [2] pitch/Q&A/NAT/Nebius/video, [3] real repos, [4] speed, [5] NVIDIA depth.

## 2026-10-29 ~14:25 — scorer round 2: 73/100 (+3)
- Innovation 17 (+1), tech 17 (+2), impact 12, sponsor 9, demo/UX 9, evidence 5, docs 4. Scored HEAD f323bd7 (33 tests pass); working-tree llm.py mid-edit by speed builder.
- Team-closable: re-run 6-case benchmark with curated proofs (+4), finish speed + replay video (+4), commit UI redesign (+2).
- Owner-needed: Nebius run (+4-5), real repo + PR (+3).

## 2026-10-29 ~14:35 — research round 5 (NVIDIA depth)
- research-5.md: free nvidia/nemotron-3.5-content-safety guard on OpenRouter; embed models on NVIDIA catalog (need nvapi key); rerank endpoint 410 Gone; reward model poor fit.
- Backlog: content-safety gate (backend, queued behind speed builder), per-tier chart (UI, queued behind UI builder), Embed rerank (needs owner key).
- Launched researcher round 6 (angle: agent self-security, prompt injection via repo/advisory/web content).

## 2026-10-29 ~14:45 — backend build: speed
- Reasoning control per provider (+400 fallback), JSON mode, 90 s fix cap with escalation, triage ∥ research, Tavily-score rerank (no LLM), triage skipped when reachability conclusive, uv + background sandbox prep, PATCHPILOT_DEMO=1. 44 tests pass (verified).
- Measured: uv venv+install 0.19-0.23 s vs 5.8-5.9 s with pip. End-to-end timing NOT measured: OpenRouter free daily limit (50 req) exhausted (429).
- Next backend: NVIDIA content-safety gate (built with graceful skip; verified live when quota resets).

## 2026-10-29 ~14:55 — research round 6 (agent self-security) + urgent fix
- research-6.md: 11-row threat model. CRITICAL found in our code: sandbox passed full os.environ (API keys/tokens) to the scanned repo's setup.py/conftest.py.
- FIXED by manager: sandbox env allow-list (patchpilot/sandbox.py), tests/test_sandbox_env.py; verified real uv install + 9 passed, child process sees no keys.
- Backlog: requirements/_write_files guard, injection spotlighting, poisoned demo case, /api/runs rate limit.

## 2026-10-29 ~15:10 — UI build: judge-first redesign
- Dark by default; 6 primary tabs + "More"; console auto-replays the best recorded run (LIVE REPLAY badge, "Run it for real"); guided demo /console?demo=1 with Find→Prioritize→Predict→Fix→Attack→Prove→Ship story bar; landing headline + live stat row from real runs; demo terminal shows the payoff; timeline wrap fixed. Also includes the reachability chips UI.
- Manager checked screenshots (landing + guided demo): good.
- Launched UI builder round 2: panels for trust check, VEX download, guard events, per-tier cost/latency chart.

## 2026-10-29 ~15:20 — research round 7 (npm feasibility)
- research-7.md: Node 24 + npm 11 present; OSV npm works; demo case jsonwebtoken 8.5.1→9.0.0 (CVE-2022-23540, offline alg:none proof, real breaking changes). ~9 h. Backlog item added (after security items).
- Launched UI/UX researcher round 2 (critique of redesigned pages, shots3).

## 2026-10-29 ~15:30 — UI/UX research round 2
- ui-2.md: 11 issues + 8 changes (landing reveal blanks, demo should end on Certificate, caption bar, surface the "still open" variant, graph node status, neutral replay badge, phone layout). Backlog "UI round 3" added (after current UI builder).
- Launched submission writer (Devpost text, pitch, video script final) — research angle 8.
