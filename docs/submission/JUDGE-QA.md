# Judge Q&A

**1. Isn't this just Dependabot plus an LLM?**
No. Dependabot bumps the pin and stops. PatchPilot makes the major upgrade pass (`agent.py` repair loop), proves the exploit fails before the fix and passes after (`patchpilot/exploits/`), attacks its own fix with variants, and checks every claim on its own in a ledger. Run `20261029-153834-job` (authsvc, Token Factory): Super → Ultra, green on attempt 2, proven closed, 7/8 variants blocked (the open one is reported).

**2. Did you actually run on Nebius?**
Yes. All six shipped runs in `demo-runs/` were recorded on Nebius Token Factory, and every `done` event records `"provider": "Token Factory"`. 6/6 green; totals from `demo-runs/batch-summary.json`: 528.6 s, 45,904 input / 39,321 output tokens over 23 model calls. Five runs include live Tavily research; the sanitizer run (`20261029-153214-job`) was recorded without Tavily.

**3. Why three Nemotron tiers?**
Cost and latency go to where they're needed. Nano handles high-volume triage and inference. Super writes the patch. Ultra only runs after Super fails. In `153834-job` (authsvc) Ultra was called once, against 2 Nano and 2 Super calls. In the other five shipped runs Ultra was never called.

**4. Your benchmark is 6 toy cases you built yourselves.**
True. All 6 are green on Token Factory (`demo-runs/batch-summary.json`). The cases use real CVEs and real breaking APIs. A real public repo is shortlisted (greyli/bluelog), but running it needs the owner's approval.

**5. Did a generated exploit ever go red then green?**
Not in a shipped run. All six shipped runs used a curated, verified proof (logged as "Using curated exploit proof for <CVE>") and each reports "proven closed". We label which kind was used, and a run without a proof reports "not proven" instead of hiding it.

**6. Doesn't `ok: true` hide a missing proof?**
`ok` means tests are green. The proof status is reported separately per run; without a proof the ledger marks the security claim as partial or not proven and the trust score drops. In the shipped runs trust ranges from 83 to 91.

**7. How do you know the model didn't edit the tests to pass?**
The ledger checks "Tests were not edited to pass" and "No tests lost" against the original suite (e.g. run `153834-job`).

**8. Reachability: is it real or vibes?**
OSV symbols are used when present. OSV usually doesn't have them, so Nano infers them and the result is **labelled `llm-inferred`** (`reach.py`). OpenVEX (`vex.py`) never emits `not_affected` from LLM-inferred evidence.

**9. You run arbitrary repo code. Isn't that dangerous?**
Yes, and we found our own bug. The sandbox used to pass the full `os.environ`, API keys included, to the repo's `setup.py` and `conftest.py`. It now uses an allow-list (`sandbox.py`, `tests/test_sandbox_env.py`). The venv is **not** a security boundary: keep `ALLOW_REMOTE_REPOS=0` on public hosts. A container sandbox is next.

**10. What stops the LLM from writing malicious code into your sandbox?**
`patchpilot/guard.py` adds a deterministic AST screen plus, when `MODEL_GUARD` is configured, NVIDIA `nemotron-3.5-content-safety` with a custom policy (no exfiltration, no external network, no secret reads). Rejected patches go back into the next repair attempt. The shipped recordings ran with the static screen only, because Token Factory lists no content-safety model for our account. We checked the guard live on OpenRouter's free tier (`docs/guard-eval.md`, n=2 over 6 samples). It got 10 of 12 verdicts right: one false positive on a benign proof and one missed base64 `exec`. That run also surfaced three request/parsing bugs, which are now fixed. The static screen caught all three malicious samples, and either layer blocking is enough.

**11. Why upgrade to latest rather than the minimum fix?**
The deps.dev trust check (`35e831d`) found that the least-change targets (PyJWT 2.4.0, urllib3 1.26.19/2.2.2, Jinja2 3.1.3) have no PyPI attestation, while the latest releases do. Both options are shown, along with provenance, Scorecard and the new transitive deps.

**12. Is it fast enough?**
On Token Factory the six shipped runs took 64.7 s to 136.4 s each (528.6 s in total, `demo-runs/batch-summary.json`). The speed work (`4a14cf3`) added reasoning control, JSON mode, a 90 s fix cap, parallel triage and research, Tavily-score rerank with no LLM call, and `uv`. Measured: venv+install 0.2 s vs 5.9 s.

**13. How do I verify any of this without an API key?**
`/console?replay=20261029-153834-job` replays the recorded events. `/console?demo=1` runs the guided story. Raw events are in `demo-runs/*.jsonl`.

**14. Is the agent itself tested?**
Yes: 171 offline tests (`tests/`), including sandbox env, VEX, dependency repair and replay of the shipped runs.

**15. Other languages?**
Python/pip only today. npm feasibility is done (jsonwebtoken CVE-2022-23540, offline alg:none proof). It's about 9 h of work and not built.
