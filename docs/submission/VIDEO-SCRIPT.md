# Video script (2:20, hard cap 2:30)

One story, told in this order: **Dependency bots bump the version and the build breaks. PatchPilot rewrites your code, proves the exploit is dead, and opens the PR.**

Record from replay so nothing stalls: `uvicorn patchpilot.server:app --port 8000`, default light theme, 1080p, browser zoom 110%.
Base run: `20261029-153834-job` (authsvc, PyJWT, Nebius Token Factory, live Tavily research, Super then Ultra, green on attempt 2, exploit proven closed, trust 85, 110.7 s).
**[OWNER]** = needs an owner action. Each one has a fallback.

| Time | On screen (exact) | Voice-over |
|---|---|---|
| 0:00–0:12 (12 s) | **[OWNER]** A real red Dependabot PR on a fork (PyJWT 1.x to 2.x, CI failing). *Fallback:* `cases/authsvc` in an editor with `PyJWT==1.7.1`, then a terminal showing `pytest` red after a naive bump. | "Dependency bots bump the version. The build breaks. The CVE stays in prod." |
| 0:12–0:25 (13 s) | `localhost:8000/` landing: hero headline, the three-step graphic (Find the CVE, Fix the code until tests pass, Prove the exploit closed), then the model strip: Nano, Super, Ultra, Tavily. | "PatchPilot rewrites your code, proves the exploit is dead, and opens the PR. Three NVIDIA Nemotron models on Nebius Token Factory, plus Tavily, each with one job." |
| 0:25–0:40 (15 s) | `localhost:8000/settings` (signed in as admin) → Providers: LLM base URL `https://api.tokenfactory.nebius.com/v1`, the Nano / Super / Ultra model fields (pinned ids `nvidia/Nemotron-3_5-Lightning`, `nvidia/nemotron-3-super-120b-a12b`, `nvidia/Nemotron-3-Ultra-550b-a55b`; fields show what is stored, otherwise the `.env` pins apply), then **Test LLM** (key field stays masked). | "One OpenAI-compatible endpoint, three pinned models, and a test button that never shows the key." |
| 0:40–0:55 (15 s) | `localhost:8000/console?demo=1`, step 1 Find. The tier strip lights **Nano**; threat clock with EPSS, KEV and days public; reachability chip. | "Step one, find it. Nano triages the advisories, and ranks them by what attackers actually use." |
| 0:55–1:10 (15 s) | Same tab, Predict then Fix. Tavily lights up with the migration source; drift radar lists the lines the upgrade breaks. | "Tavily finds the migration guide. Before any test runs, we know which lines will break." |
| 1:10–1:35 (25 s) | Fix: tests red, Super's patch fails, the strip moves to **Ultra**, tests green on attempt 2. Show the Test timeline. | "Now fix it. Super writes the patch, it fails, so Ultra takes over. Green on attempt two. This is the part version-bump bots never do." |
| 1:35–1:55 (20 s) | Prove: the exploit goes **Exploited** on the old pins, then **Blocked** after the fix; red-team table with the one row still open highlighted. | "Then prove it. Same real exploit: it works on the old version and is closed on ours. And it tells you the one variant still open." |
| 1:55–2:12 (17 s) | End-of-run **Run summary** card (CVEs fixed, tests before to after, exploit before to after, files changed, calls by tier), then the Certificate tab with trust 85 and the SHA-256. **[OWNER]** The real PR with the certificate (needs `GITHUB_TOKEN`). *Fallback:* the Diff tab and the `.patch` download. | "Every claim is checked on its own and hashed into the PR." |
| 2:12–2:20 (8 s) | Hold on the summary. Lower third: "3 Nemotron tiers on Nebius Token Factory · run 20261029-153834-job · 110.7 s · replayable". | "Measured, recorded, replayable. Not promised." |

Total: 2:20 (12+13+15+15+15+25+20+17+8 = 140 s). Headroom of 10 s under the 2:30 cap.

## Rules
- Only measured numbers on screen, taken from `demo-runs/batch-summary.json` and the run itself. The landing results strip is computed from `/api/bench`; do not quote anything it does not show.
- Five of the six shipped runs include live Tavily research; the sanitizer run (`20261029-153214-job`) was recorded without Tavily, so don't use it for the research shot.
- Settings needs an admin session; sign in before recording. The Providers section shows stored values only, so if the model fields are empty say "pinned in the environment" and keep the Test LLM shot.
- If the guided demo stops before the summary card, cut to `/console?replay=20261029-153834-job`.
