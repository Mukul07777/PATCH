# Video script (2:00)

Record from replay so nothing stalls: `uvicorn patchpilot.server:app --port 8000`, dark theme, 1080p, browser zoom 110%.
Base run: `20261029-113639-job` (authsvc, PyJWT CVE-2022-29217, Super → Ultra, proven closed, 7/8 variants, trust 93).
**[OWNER]** = needs an owner action. Each one has a fallback.

| Time | On screen (exact) | Voice-over |
|---|---|---|
| 0:00–0:10 | **[OWNER]** A real red Dependabot PR on a fork (PyJWT 1.x → 2.x, CI failing). *Fallback:* `cases/authsvc` in an editor with `PyJWT==1.7.1`, then a terminal showing `pytest` red after a naive bump. | "Dependabot opened the PR. The build broke. The CVE is still in prod." |
| 0:10–0:15 | Title card: the tagline. | "PatchPilot makes it pass, attacks its own fix, and hands you a proof certificate." |
| 0:15–0:30 | `localhost:8000/console?demo=1`, Find → Prioritize. Threat clock: EPSS, KEV badge, days public. Reachability chip (point at the `llm-inferred` label). | "First: which of these sixteen advisories do attackers actually use, and does your code even reach them?" |
| 0:30–0:42 | Same tab, Predict. The drift radar lists the breaking lines and the least-change version. Trust panel: no attestation on the least-change target. | "Before any test runs, it predicts which lines the upgrade breaks, and it checks whether the release itself can be trusted." |
| 0:42–0:52 | Switch to `localhost:8000/console?replay=20261029-113639-job`. The exploit proof goes **RED** on the old version. | "We prove the vulnerability is real in your code first." |
| 0:52–1:15 | Repair loop: Super's attempts fail, escalation to **Nemotron Ultra**, tests green on attempt 3. Per-tier usage panel. | "Nano triages. Super writes the fix. It fails, so it escalates to Ultra. Green on attempt three." |
| 1:15–1:25 | Exploit re-run goes **GREEN**. | "Same exploit. Now closed." |
| 1:25–1:40 | Red-team table: 7/8 blocked, **the one "still open" row highlighted**. | "Then it attacks its own fix, and tells you the one variant still open. No other bot admits that." |
| 1:40–1:52 | **Certificate**: claims ledger, trust 93, SHA-256, OpenVEX download. **[OWNER]** The real PR body with the certificate (needs `GITHUB_TOKEN`). *Fallback:* the `.patch` file and the certificate panel. | "Every claim is checked on its own and hashed into the PR." |
| 1:52–2:00 | Hold on the certificate. Lower third: "3 Nemotron tiers · run 20261029-113639-job · replayable". **[OWNER]** If a Nebius run exists, show `provider: nebius` and its measured time. *Fallback:* say "OpenAI-compatible, Nebius-ready" and **don't** claim a Nebius run. | "Three Nemotron tiers. Measured, recorded, replayable. Not promised." |

## Rules
- Only measured numbers on screen: 16 advisories, attempt 3, 7/8, trust 93, 723 s (don't show the runtime unless a faster run is measured).
- Don't show speed claims until an end-to-end run after the speed work is recorded.
- If the guided demo doesn't end on the certificate yet (ui-2 issue), cut to `/console?replay=...` for the last 20 s.
