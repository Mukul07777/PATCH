# Video script (2:20, hard cap 2:50)

Record from replay so nothing stalls: `uvicorn patchpilot.server:app --port 8000`, default light theme, 1080p, browser zoom 110%.
Base run: `20261029-153834-job` (authsvc, PyJWT CVE-2022-29217, Nebius Token Factory, live Tavily research, Super → Ultra, green on attempt 2, proven closed, 7/8 variants, trust 85, 110.7 s).
**[OWNER]** = needs an owner action. Each one has a fallback.

Per-scene durations below add up to 2:20, which leaves 30 s of headroom under a 2:50 cap (and 40 s under 3:00).

| Time | On screen (exact) | Voice-over |
|---|---|---|
| 0:00–0:10 (10 s) | **[OWNER]** A real red Dependabot PR on a fork (PyJWT 1.x → 2.x, CI failing). *Fallback:* `cases/authsvc` in an editor with `PyJWT==1.7.1`, then a terminal showing `pytest` red after a naive bump. | "Dependabot opened the PR. The build broke. The CVE is still in prod." |
| 0:10–0:15 (5 s) | Title card: the tagline. | "PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate." |
| 0:15–0:35 (20 s) | `localhost:8000/settings` → Providers: base URL `https://api.tokenfactory.nebius.com/v1`, the three pinned Nemotron ids (Nano `nvidia/Nemotron-3_5-Lightning`, Super `nvidia/nemotron-3-super-120b-a12b`, Ultra `nvidia/Nemotron-3-Ultra-550b-a55b`), then **Test connection** (key never shown). | "Everything runs on Nebius Token Factory: three NVIDIA Nemotron models, each with one job." |
| 0:35–0:50 (15 s) | `localhost:8000/console?demo=1`, Find → Prioritize. Threat clock: EPSS, KEV badge, days public. Reachability chip (point at the `llm-inferred` label). | "First: which of these sixteen advisories do attackers actually use, and does your code even reach them?" |
| 0:50–1:02 (12 s) | Same tab, Predict. The drift radar lists the breaking lines and the least-change version. Trust panel: no attestation on the least-change target. | "Before any test runs, it predicts which lines the upgrade breaks, and it checks whether the release itself can be trusted." |
| 1:02–1:12 (10 s) | Switch to `localhost:8000/console?replay=20261029-153834-job`. The exploit proof goes **RED** on the old version. | "We prove the vulnerability is real in your code first." |
| 1:12–1:35 (23 s) | Repair loop: Super's attempt fails, escalation to **Nemotron Ultra**, tests green on attempt 2. Per-tier usage panel. | "Nano triages. Super writes the fix. It fails, so it escalates to Ultra. Green on attempt two." |
| 1:35–1:45 (10 s) | Exploit re-run goes **GREEN**. | "Same exploit. Now closed." |
| 1:45–2:00 (15 s) | Red-team table: 7/8 blocked, **the one "still open" row highlighted**. | "Then it attacks its own fix, and tells you the one variant still open. No other bot admits that." |
| 2:00–2:12 (12 s) | **Certificate**: claims ledger, trust 85, SHA-256, OpenVEX download. **[OWNER]** The real PR body with the certificate (needs `GITHUB_TOKEN`). *Fallback:* the `.patch` file and the certificate panel. | "Every claim is checked on its own and hashed into the PR." |
| 2:12–2:20 (8 s) | Hold on the certificate. Lower third: "3 Nemotron tiers on Nebius Token Factory · run 20261029-153834-job · 110.7 s · replayable". | "Three Nemotron tiers. Measured, recorded, replayable. Not promised." |

Total: 2:20 (10+5+20+15+12+10+23+10+15+12+8 = 140 s). Do not let any overrun push the cut past 2:50.

## Rules
- Only measured numbers on screen (from `demo-runs/batch-summary.json`): 16 advisories, attempt 2, 7/8, trust 85, 110.7 s for this run; 6/6 green on Token Factory, 528.6 s for all six.
- Five of the six shipped runs include live Tavily research; the sanitizer run (`20261029-153214-job`) was recorded without Tavily, so don't use it for the research shot.
- If the guided demo doesn't end on the certificate yet (ui-2 issue), cut to `/console?replay=...` for the last 20 s.
