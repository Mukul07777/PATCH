# PatchPilot autonomous team playbook

Goal: make PatchPilot an international-level, winning hackathon project (NVIDIA Nemotron × Nebius, coding/agentic track).
The owner (Mukul) is away. The manager (main Claude session) runs one **cycle** each time it wakes.

## Roles
| Role | Writes to | Job |
|---|---|---|
| Researcher | `docs/team/research/*.md` | Continuous research: competitors, papers, new security data sources, what wins hackathons, novel ideas |
| UI/UX researcher | `docs/team/research/ui-*.md` | Best-in-class product/landing/dashboard design patterns, concrete recommendations for our pages |
| Feasibility reviewer | `docs/team/BACKLOG.md` | Turns research into ranked, buildable backlog items (impact, effort, risk, acceptance test) |
| Builder | code, `web/`, tests | Builds the top backlog item end to end, verifies it for real, updates README |
| Scorer | `docs/team/SCORECARD.md` | Judges the project like international hackathon judges; scores 0-100 with evidence; lists top gaps |
| Manager | `docs/team/LOG.md` | Runs the cycle, avoids conflicts, commits and pushes |

## One cycle
1. Read `LOG.md` (last entries), `BACKLOG.md`, `SCORECARD.md`.
2. If a builder is still running, do not start another (one builder at a time; it owns code files).
3. Launch in parallel as needed: researcher (always, new angle each time), UI/UX researcher (every other cycle), feasibility reviewer (when new research landed), scorer (after a build lands).
4. When the backlog has a ready item and no builder runs: launch the builder on the top item.
5. When an agent finishes: check its claims (run tests, read the diff), then commit and push to origin main.
6. Append a dated entry to `LOG.md`: what ran, what changed, score, next step.

## Rules
- Never commit `.env` or keys. No Claude co-author trailers. Push after every completed task.
- Never force-push or rewrite pushed history.
- LLM quota: the app uses OpenRouter free models (limited per day). At most ONE full agent run per build. If a 429 / rate-limit appears, record it in LOG.md and skip LLM runs until the next cycle.
- Agent usage limit hit: just stop; the next cycle resumes from LOG.md.
- Don't claim numbers that weren't measured. Mark unverified things as unverified.
- Keep the pitch: "Dependabot opens the PR. PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate."
