# PatchPilot scorecard

Date: 2026-10-29 · Scorer: strict judge panel · Basis: repo at `65bd4ce` plus untracked runs `runs/20261029-113639/114842/115625-job.jsonl` and `runs/bench.log`.

## Total: 70 / 100

| Criterion | Score | Evidence | What would raise it |
|---|---|---|---|
| Innovation / novelty (20) | **16** | Goes past "bump the pin": exploit proof run before and after (`patchpilot/exploits/cve_2022_29217.py`), red-team mutation variants (`cve_2022_29217_mutations.py`), a claim ledger that marks each claim verified/partial (run `113639-job`: 7 claims, 6 verified, "Attack variants blocked" partial), threat clock (EPSS/KEV), API drift radar (`drift.py`). The "proof certificate" framing is new for a dependency bot. | Show a generated (not curated) exploit that goes red before the fix and green after, end to end. Today the only proven-closed exploit is the curated PyJWT one. |
| Technical depth & execution (20) | **15** | Real pipeline in `agent.py` (681 lines): OSV + PyPI scan, venv sandbox (`sandbox.py`), repair loop that escalates Super to Ultra (run `113639-job`: 3 attempts, Ultra called twice, ended green). SSE server (`server.py`). Guards against cheating ("Tests were not edited to pass", "No tests lost" in the ledger). | No unit tests for PatchPilot itself (only the `cases/*/tests`). Python/pip only. `redteam failed` appears as a step state in `bench.log` for authsvc and fetcher. Run 115625 (mailer) stopped after the exploit step with no `done` event. |
| Real-world impact & problem clarity (15) | **12** | The problem is stated clearly in the README: a bump that needs a major version breaks the build and the PR is abandoned. Cases use real CVEs and real breaking APIs (PyJWT 2.x, Werkzeug 3, urllib3 2, Jinja2 3.1, bleach 6). | One real public repo fixed, with an opened GitHub PR (no run has `pr` set; every run reports `"pr": null`). Some numbers on how common major-bump CVEs are. |
| Sponsor tech: Nemotron tiers + Nebius (15) | **9** | Three Nemotron tiers really used, with per-tier usage in each `done` event: nano=`nemotron-3.5-lightning:free`, super=`nemotron-3.5-super-vl:free`, ultra=`nemotron-3-ultra-550b-a55b:free`. Nebius base URL is in `config.py`. | **Every recorded run is on OpenRouter free models, none on Nebius Token Factory.** One recorded Nebius run (with `provider` in the `done` event, which is missing today) would gain about 4 points. Show why each tier was picked: latency and cost per tier from the usage data. |
| Demo & UX (15) | **9** | Multipage web UI (`web/landing.html`, `console.html` with a live graph, `runs.html` benchmark view, `org.html`, `how.html`). Live SSE stream. | No demo video. Runs take 110 to 720 s on free models (run `113639-job` took 723 s), too slow to run live: a replay mode and a short recorded video are needed. Not checked here in a browser. |
| Evidence / measured results & reliability (10) | **5** | Real runs exist: authsvc green with exploit proven closed (`110329-1b62`, `112104-b758`, `113639-job`). The fetcher run (`114842-job`) is honest: exploit "not proven", ledger partial. | The benchmark is incomplete: 2 of 6 cases finished, mailer cut off, webhooks/sanitizer/sqlfmt not run, no `runs/batch-summary.json`. n=1 per case, so there is no pass rate or variance. Fetcher ends `ok: true` while its exploit is not proven, and a judge will challenge that. |
| Presentation / docs (5) | **4** | README has a clear pitch, a mermaid flow and a feature list. Each case has a README naming the CVE and the breaking API. | A results table with measured numbers in the README, and a known-limitations section. |

## Risks a judge will poke at
- Runs go through OpenRouter, not Nebius, so the sponsor integration is unproven.
- Python and requirements.txt only: no npm, Maven or Go.
- Small benchmark built by the team itself (6 toy cases, 2 completed). It can look cherry-picked.
- Free models are flaky and slow (Nano took up to 279 s in run `113639-job`). The live demo could stall.
- Only the PyJWT exploit is proven closed, and it is curated. Generated exploits have not yet shown a full before/after flip.
- `done.ok` is true even when the security claim is only partial, so the "success" label is too generous.
- No self-tests for the agent code.

## Top 5 gaps to close next (ranked by points gained per effort)
1. **Finish the 6-case benchmark and write `runs/batch-summary.json` plus a README results table** (+4, low effort: the cases already exist). Evidence and docs.
2. **Record one full run on Nebius Token Factory and log the provider in the `done` event** (+4, low effort, but it needs the owner's key). Sponsor.
3. **Add a replay mode and a 2-3 minute demo video of a recorded green run with the certificate** (+4, medium effort). Demo.
4. **Make `ok` reflect the proof (green, partial or unproven) and get one generated exploit through a before-red, after-green flip** (+3, medium effort). Evidence and innovation.
5. **Open one real PR against a public GitHub repo, plus a small pytest suite for `agent.py`, `drift.py` and `sources.py`** (+3, medium effort). Impact and execution.
