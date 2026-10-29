# Demo video script (2:50, public YouTube, no music or royalty-free music only, no third-party logos)

Record at 1440×900, browser zoom 100%, dark or light theme. Say the lines in **bold**; the rest is what is on screen.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:15 | A red Dependabot PR on GitHub: "Bump pyjwt from 1.7.1 to 2.10.1", checks failing, opened weeks ago. | **"This is a security fix. It's been red for weeks, because the new version breaks the code. So the vulnerability is still in production. Every team has a pile of these."** |
| 0:15–0:25 | PatchPilot landing page, scroll once. | **"PatchPilot is a coding agent on Nebius Token Factory with NVIDIA Nemotron. It doesn't just bump the version. It makes the upgrade work, and proves it."** |
| 0:25–0:40 | `/console`: the start screen with three choices. Click **Watch it fix a real project**. | **"Nothing runs until you choose. Here's a real recorded run on Token Factory."** |
| 0:40–1:05 | Findings tab: the **In plain words** box, then "Being attacked right now: None", "Chance of an attack in 30 days". | **"First it finds the holes and says what they mean in plain English, including whether your own code actually calls the broken function. Nemotron Nano does this triage: it's the fast, cheap tier."** |
| 1:05–1:35 | Test timeline: baseline 9 passed → after upgrade 7 failed → attempt 1 (Super) 1 failed → attempt 2 (Ultra) 9 passed → "AI repairs what the upgrade broke". Model routing panel: Super, then Ultra. | **"The upgrade breaks seven of nine tests. Nemotron Super repairs all but one. For the last one the job escalates to Ultra, the big reasoning model, only now. Ultra's fix quotes the exact changelog line Tavily found. Nine of nine green."** |
| 1:35–2:00 | Proof tab: Exploit card "Old version: Exploited ✗ → Patched: Blocked ✓ → Verdict: proven closed", then the attack-variant list. | **"Green tests aren't proof. PatchPilot runs the real attack: it works on the old version and is blocked on the fix. Then it tries eight variations. Seven are blocked, one is still open, and it says so instead of hiding it."** |
| 2:00–2:15 | Proof tab: the certificate with its SHA-256. <!-- The authsvc recording predates the behaviour lock. Show its card here only after a new Token Factory recording has it; until then keep the line about it short. --> | **"It also records how your functions behaved before the upgrade and checks they still return the same thing, even if you have no tests. Every claim goes into a signed certificate."** |
| 2:15–2:35 | `/projects`: add a `requirements.txt` with `reqeusts==1.0` and `PyQt5`. The project shows grade **F** and the **What to do** list. | **"No AI key? You still get a grade from A to F and a to-do list anyone can read: a fake package pretending to be requests, a GPL license, upgrades with exact versions. And a one-click fixed requirements file."** |
| 2:35–2:50 | Console: paste a PR URL in the box. Cut to the GitHub PR turning green with PatchPilot's commit. <!-- TODO(owner): record once a real rescue PR exists; otherwise show the PR URL being pasted and the README comparison table --> | **"And for a red Dependabot PR, paste the link. PatchPilot pushes the repair onto that PR. Open source, on Nebius Token Factory and NVIDIA Nemotron."** |

**Before recording:**
- Set the server to Token Factory, so the provider pill reads "Token Factory".
- Close other tabs.
- Hide the bookmarks bar.
- Do one dry run of the guided demo so its timing is familiar.
