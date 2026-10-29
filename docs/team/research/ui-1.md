# UI research 1: first-10-seconds critique, top 10 changes, judge demo path

Sources I opened: linear.app, snyk.io, warp.dev. socket.dev and devpost.com both returned 403, so anything about them below is general knowledge and isn't cited.
Screenshots reviewed: shots2/landing_desk.png, shots2/console_desk.png. The others are in the same folder.

## (a) Critique

### Landing (landing.html)
- **The first 10 seconds give a judge no information.** The fold is the word "PATCH" and a three-line tagline in 11px mono. Nothing says *what* gets patched (CVEs in Python dependencies), *who* does it (Nemotron agents), or *what proof* exists. Linear puts a one-sentence value prop in the headline and real product UI right below it. Snyk puts a product image and quantified proof (stats, logos) above the fold. We do neither.
- **Most of the hero is dead space.** "PATCH" fills about 55% of the viewport height and carries no message. The CTAs sit at the bottom edge and are easy to miss on a 768px-tall laptop.
- **The story is pushed below the fold.** The best asset, the typed terminal showing `upgrade: FAIL` and then a repair, is in the second section and stops at FAIL. The payoff (tests green, PR opened) never appears on the landing page.
- **The model "editions" cards look like generic orb art.** All four cards look alike, and none shows a number such as tokens, cost or a pass rate. They read as decoration, not evidence.
- **No proof numbers anywhere.** The benchmarks, verified exploit proofs and proof certificate already exist, but the landing page shows none of their results. "3 models" is the only stat on the page.
- The feature strip and the "loop" section repeat the same scan/research/fix/ship message twice.

### Console (console.html)
- **The visual identity breaks.** The console is a light theme while the landing page is dark editorial. A judge clicking "Launch agent" lands in a page that looks like a different product. Default the console to dark and keep light as the toggle.
- **The idle state shows nothing.** The KPIs read "–", the vulnerability card is a black bar, and the panels say "Scanning…" and "No test runs yet". A judge who opens the page without pressing anything sees an empty dashboard. There is no pre-loaded result.
- **The hierarchy is inverted.** The hero headline and copy (about 300px) repeat the landing pitch, and the actual controls sit below them. The agent graph takes about 400px of height but is greyed out, with no active state until a run starts.
- **There are 11 tabs and they overflow** ("Benchma…" is clipped). There's no indication of which tab matters at which moment of the run, so a judge won't find Proof, Certificate or Diff by themselves.
- The test timeline panel wraps one word per line ("No / test / runs / yet"), a visible layout bug. The pipeline list duplicates the agent graph.
- The phone layout stacks everything, so the graph and KPIs push the run outcome far down.

## (b) Ten highest-impact changes

| # | Page / section | Change | Why (reference) | Effort |
|---|---|---|---|---|
| 1 | console.html, idle state | **Auto-play a recorded replay on first load** (case:authsvc, about 2x speed) behind a "LIVE REPLAY · press Launch for a real run" badge. End on the verified PR state. | Warp's hero is a "live" status grid with real counters (224 tasks, 1,422 PRs shipped), so it is never empty (https://www.warp.dev). An empty dashboard loses the judge. | M |
| 2 | Global | **Guided demo mode**: `?demo=1` or a "Take the 90s tour" button shows a top story progress bar (Find → Research → Fix → Fail → Repair → Prove → Ship), auto-switches to the right tab at each stage, and shows a one-line caption ("Tests failed: PyJWT 2.x renamed `decode` args. Escalating to Super."). | Judges have 2-3 minutes; the narrative has to drive the UI rather than wait for clicks. | M |
| 3 | landing.html hero | Shrink "PATCH" to about 40% height. Add a plain headline: "Finds the CVE, rewrites your code until tests pass, opens a verified PR, on NVIDIA Nemotron." Put a **real product frame** (console screenshot or embedded replay) directly below it, Linear-style. | Linear: a headline with the value prop, then two product UI images above the fold (https://linear.app). | S |
| 4 | landing.html, below hero | **Proof stat row** with real numbers from the benchmarks: e.g. "4/4 real-world cases fixed · N exploit proofs verified · avg X min · Y Nemotron tokens · $Z per fix". | Snyk leads with quantified proof (288% ROI, 80% faster scans) plus logos (https://snyk.io). Judges score evidence. | S |
| 5 | console.html theme | **Default the console to dark** to match the landing page (green accent, same type). Keep the light toggle. | One product identity; judges perceive it as polish. | S |
| 6 | console.html tabs | Cut the tabs to 5 primary ones (**Live · Evidence · Proof · Diff · PR**) and put the rest (Drift, Reachability, Debate, Benchmarks, Advisories) under "More". Auto-focus a tab as its stage runs and add a dot badge on new content. | Removes the clipped "Benchma…" overflow and the decision fatigue. | S |
| 7 | landing "loop" terminal | Extend the typed terminal past `FAIL` to the repair (`super → patch jwt.decode(...)`), `pytest 42 passed ✓`, and `PR #12 opened · certificate sha256:…`. | The fail-then-repair payoff is our unique point; right now it stops on red. | S |
| 8 | console.html hero | Collapse the hero to one line (title + case pickers + Launch) so the agent graph sits above the fold. Turn the "Open vulnerabilities" card into a live **before → after counter** (2 → 0). | The first screen should be the product working, not marketing copy repeated. | S |
| 9 | console agent graph | Animate edges (a moving dash or pulse along the active edge), light up the active node in green, and show a token/time chip on each node. When Ultra escalates, draw the escalation edge in orange. | Makes multi-model routing on Nemotron Nano/Super/Ultra visible, which is the NVIDIA track's core criterion. | M |
| 10 | landing "editions" cards | Replace the orb art with per-model real stats from runs (calls, tokens, the step where it won) and a tiny sparkline. Fix the test-timeline one-word wrap bug on the console. | Turns decoration into evidence; fixes a visible bug a judge would notice. | S |

## (c) Judge demo path (90 s)

1. **0-10s · Landing.** The headline says what it does; the proof stat row shows that it works. Click "Watch a replay".
2. **10-25s · Console, demo mode starts.** The story bar sits at "Find". The agent graph lights up OSV.dev, then Nano triage, and the KPI shows "2 advisories (HIGH PyJWT)".
3. **25-40s · Research.** The Evidence tab auto-opens on the Tavily migration-guide citation, with the exact line highlighted.
4. **40-60s · Fix → FAIL → Repair.** The Live terminal shows pytest red, a caption explains the breaking API, the graph draws the Super → Ultra escalation in orange, and the test timeline goes red, then green.
5. **60-75s · Prove.** The Proof tab shows the exploit succeeding before the fix and blocked after, plus the risk score drop. The Certificate tab shows a hash.
6. **75-90s · Ship.** The Diff tab shows the code rewrite (not just a version bump), and the PR report opens with a link. The story bar is complete. A final card reads "1 verified PR · 0 open vulns · X tokens · Y s", with a "Run on your repo" input.

**UI missing for this path:**
- A demo-mode controller (`?demo=1`) with timed tab switching and captions
- A story progress bar component
- Auto-play of a replay on idle
- A final "outcome card" overlay
- A tab-switch event hook on each pipeline stage
- An exploit before/after side-by-side layout in the Proof tab
