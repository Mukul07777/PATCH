# UI research 2: review of the redesign, the 8 next changes, and a 90-second judge path

Screenshots reviewed (shots3/): land_desk, land_desk_full, land_phone, land_phone_full, console_desk, console_phone, demo_desk, demo_phone, demo_desk_tabs/_side/_more, demo_phone_tabs/_side, console_desk_tabs.

References opened:
- GitHub Actions visualization graph: https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-the-visualization-graph. Each node is a job with a status icon on the left, and clicking a node opens that job's log.
- Vercel deployments: https://vercel.com/docs/deployments. Every deployment gets a unique URL. The details page leads with the result (the preview URL, build time, framework) and keeps the logs a click away.
- LangSmith LangGraph tracing: https://docs.langchain.com/langsmith/trace-with-langgraph. It offers a "Trajectory" view (a simple, chat-like run story: request, tool calls, final answer) alongside a "Details" view.

What they teach: lead with the result, put status on every node, make each node open its own evidence, and offer one simple story view next to the full detail.

## What improved since round 1
The landing headline now says what the product does. Live stats render (3 / 2 / 7/16 / 88). The console defaults to dark. The guided demo has a 7-step stepper. The certificate tab (console_desk_tabs) is strong: a trust ring, a VERIFIED or PARTIAL label per claim, a SHA, and a download button. The test timeline (demo_desk_side) tells the fail, fail, green story by itself.

## Issues found
1. **land_desk_full / land_phone_full, middle of the page: there are two huge blank bands**, about 1,100px on desktop and about 3,000px on phone, between the stats row and "Choose your model". The "Choose your model" section is also empty. Scroll-reveal content almost certainly never fires (or fires only when a full-page capture or a fast scroll triggers it). A judge who scrolls fast sees a broken page. This is the worst defect.
2. **land_desk, hero: "PATCH" still fills about 30% of the fold** and says nothing. The stats row (the best proof) sits below the fold at about 900px. A stray caret or cursor glyph appears mid-row next to the CTAs (land_desk around x=720,y=850; land_phone around x=195,y=770).
3. **land_phone: the "RUN LOG" CTA wraps onto its own orphan line.** The header subtitle crowds the menu button.
4. **console_desk: the hero headline ("The CVE fix that actually ships.") differs from the landing headline** ("...prove the exploit is closed"). Two pitches confuse the message. The animated "SEC0RED" glyph overlap reads as a glitch.
5. **console_desk / demo_desk, agent-graph header: "LIVE REPLAY" in red reads as an error or recording state.** "Run it for real" next to "secured ✓" is ambiguous. The graph nodes carry no per-node status (✓, ✗, or retry count), no timing, and can't be clicked. GitHub Actions shows all three.
6. **demo_desk, stepper at 7/7: the payoff lands on Diff**, a wall of code. The certificate (93 trust) and the red-team "still open" row are not on screen at the end of the guided demo. The caption sits in small body text and isn't large enough for a video recorded at 1080p.
7. **console_desk_tabs, certificate: the "still open" variant is buried** as monospace sub-text inside the PARTIAL row (`hs256-ed25519-leading-space`). It is our most differentiating, honest claim and it has the least visual weight. The trust ring also doesn't explain why the score is 93 and not 100.
8. **demo_desk_more: Evidence, Reachability, Debate, PR report and Benchmarks sit hidden under "More".** Debate (the model-escalation story, 0:55-1:20 in the script) and the PR report are story beats, not extras.
9. **demo_phone: the agent graph shrinks to unreadable text, about 6px.** Phone order is stepper, graph, 5 KPIs, pipeline, and the payoff is several screens down. demo_phone_tabs: the diff overflows horizontally and gets clipped.
10. **The GitHub PRs pill is grey on every page.** There's no real PR link, which research-2 flags as the biggest demo gap. The Model routing panel's "Set PRICE_* in .env" text is developer-facing copy shown to judges.
11. **No step-to-tab sync is visible.** At step "5. ATTACK" a judge should see the red-team view, but the screenshots suggest the active tab doesn't follow the step.

## The 8 highest-impact next changes
| # | Page / section | What | Why | Effort |
|---|---|---|---|---|
| 1 | Landing, every section below the stats | Fix the scroll-reveal: render content visible by default and animate only as an enhancement (IntersectionObserver with threshold 0, plus a fallback timeout). Fill or remove "Choose your model". | Blank pages look broken to every judge who scrolls. | S |
| 2 | Console, guided demo | Make each step drive its tab: 1 Advisories, 2 threat clock / Advisories, 3 Drift radar, 4 Live terminal, then Debate, 5 Red-team / Proof & risk, 6 Proof (exploit red then green), 7 **Certificate**, not Diff. End on the certificate, with a "View diff / Download .patch / Open PR" row. | The payoff the video promises has to be the final frame. | M |
| 3 | Console, guided demo caption | Large caption bar (about 20-24px) pinned to the bottom of the viewport. One sentence per step, taken from the research-2 voiceover. Auto-advance about every 8s with pause and next controls. Step dots on phone. | Readable in the 2-minute video without voiceover. Gives the right pacing. | S |
| 4 | Certificate tab and a new "Still open" callout | Promote any PARTIAL claim to an amber callout card above the ledger: "1 attack variant still open: leading-space ed25519 key, not claimed fixed." Add a trust breakdown under the ring ("-7: 1 of 8 variants open"). | Honest disclosure is our differentiator, and right now it's the least visible text. | S |
| 5 | Agent graph | Add per-node status badges (✓, ✗, ↻ retry count) and durations. Clicking a node opens the matching tab, GitHub Actions style. Rename "LIVE REPLAY" to a neutral "Replay · recorded run" and make "Run it for real" a clear secondary button. | Turns decoration into a navigable run trace. | M |
| 6 | Landing hero | Shrink "PATCH" by about 50% (or drop it), move the 4-stat row into the fold, remove the stray caret glyph, and use one headline across landing and console. | Proof above the fold, one consistent pitch. | S |
| 7 | Mobile console and demo | On phone, replace the graph with a vertical step list (node, status, time). Put the active-step tab content directly under the stepper. Collapse the KPIs into a 2x2 grid plus one line. Wrap or scroll the diff inside its own box. Fix the orphaned RUN LOG CTA on the landing page. | Judges open links on phones. Today the payoff is 4+ screens down. | M |
| 8 | Tabs and PR | Promote Debate and PR report out of "More" (rename "Proof & risk" to "Red-team"). Show a real GitHub PR link chip on the certificate. Until a PR exists, show "PR ready: preview" rather than a grey pill. Hide the PRICE_* dev hint. | Fills the biggest demo gap and keeps the story beats one click away. | S, plus a real PR run |

## Revised 90-second judge click path
1. **0-10s, Landing.** Read the headline. The 4 live stats are visible in the fold. Click **Guided demo**.
2. **10-25s, Steps 1-2.** The Advisories tab auto-opens: 16 advisories, the CVE threat clock, and graph nodes OSV and Nano tick ✓.
3. **25-35s, Step 3.** Drift radar shows the predicted breaking lines.
4. **35-55s, Step 4.** Live terminal and test timeline go red, red, green. The Super node shows ↻2 and then the Ultra node lights up. One click shows Debate.
5. **55-70s, Steps 5-6.** Red-team: 7/8 blocked, with the amber "still open" card. The exploit proof flips red to green.
6. **70-85s, Step 7.** Certificate: 93 trust with its breakdown, the SHA, the PR link chip.
7. **85-90s.** Click the PR link chip, or Download certificate. Judge leaves with the artifact.
