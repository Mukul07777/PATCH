# PatchPilot scorecard

## Round 2: 73 / 100 (+3)

Date: 2026-10-29 · Scorer: strict judge panel · Basis: HEAD `f323bd7`, tested from a clean `git archive` (the working tree `patchpilot/llm.py` is mid-edit by the speed builder and currently fails to import: SyntaxError at line 143, so `pytest` in the working tree errors 5/5 at collection). HEAD: **33 passed**.

| Criterion | R2 | Δ | Evidence |
|---|---|---|---|
| Innovation (20) | **17** | +1 | New since R1: symbol-level reachability (`reach.py`, honestly labelled `llm-inferred`), deps.dev release trust check (provenance, Scorecard, new transitive deps; finding that least-change targets lack attestations), OpenVEX export (`vex.py`), curated verified proofs for all 6 CVEs (`patchpilot/exploits/`, 12 files). Held back: no *generated* exploit has yet flipped red to green (fetcher run: "not proven", variants 0/8). |
| Technical depth & execution (20) | **17** | +2 | 33 offline unit tests pass at HEAD (R1 had none). `done` events carry provider, models, `proven`. Held back: Python/pip only; the venv sandbox is not a security boundary; the uncommitted working tree is currently broken. |
| Real-world impact (15) | **12** | 0 | Still no real public repo run and no opened PR (`pr: null` everywhere). Shortlist exists (research-3) but is blocked on the owner. |
| Sponsor: Nemotron + Nebius (15) | **9** | 0 | Every recorded run, including the 3 newest (`120256/120418/120442-job`), uses OpenRouter `:free` models. The Nebius ids are pinned in `.env.example` but marked "verify". Zero Nebius runs. |
| Demo & UX (15) | **9** | 0 | Replay exists (README l.57). Still no video. Runs take 390 to 723 s. The UI redesign is uncommitted, so it is not scored. |
| Evidence & reliability (10) | **5** | 0 | `batch-summary.json` now exists but shows 3/6: sanitizer, sqlfmt and webhooks are `ok:false` (429 at the plan step; the 3 retry runs ended `ok:false`, two with 0 LLM calls). The new curated proofs are verified standalone but not yet exercised in an agent run. Fetcher and mailer remain "not proven" and "inconclusive" in the recorded runs. n=1. |
| Presentation / docs (5) | **4** | 0 | README has a Limitations section and an honest reachability caveat. Still no measured results table. |

### Top 5 gaps (points per effort)
**Team can close alone:**
1. **Re-run the 6-case benchmark once quota resets, now with curated proofs.** Expect 6/6 "proven closed", then put a results table in the README. About +4 (Evidence +3, Docs +1). Low effort.
2. **Land the speed work and commit a working tree that passes the tests**, targeting runs under 90 s, then record a 2-minute video from replay. About +4 (Demo). Medium effort.
3. **Commit the UI redesign** with a guided `?demo=1` that shows the certificate, the VEX and the trust panel. About +2 (Demo). Medium effort.

**Needs the owner:**
4. **Nebius key: one full recorded run with `provider: nebius`** and a per-tier latency table. About +4 to +5 (Sponsor). Low effort once the key exists.
5. **Approve a run on greyli/bluelog and provide a GITHUB_TOKEN to open one real PR on a fork.** About +3 (Impact +2, Innovation +1). Medium effort.

---

## Round 1
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
