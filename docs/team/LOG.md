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
