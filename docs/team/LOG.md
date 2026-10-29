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
