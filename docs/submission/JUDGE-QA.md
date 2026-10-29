# Judge Q&A

**1. Isn't this just Dependabot plus an LLM?**
No. Dependabot bumps the pin and stops. PatchPilot makes the major upgrade pass (`agent.py` repair loop), proves the exploit fails before the fix and passes after (`patchpilot/exploits/`), attacks its own fix with variants, and checks every claim on its own in a ledger. Run `20261029-113639-job`: green on attempt 3, proven closed, 7/8 variants blocked.

**2. Did you actually run on Nebius?**
Not yet. All recorded runs used OpenRouter `:free` Nemotron models. The client is OpenAI-compatible and the Nebius ids are pinned in `.env.example` (marked "verify"). Every `done` event records `provider`, so a Nebius run will show up in the logs.

**3. Why three Nemotron tiers?**
Cost and latency go to where they're needed. Nano handles high-volume triage and inference. Super writes the patch. Ultra only runs after Super fails. In `113639-job` Ultra was called 2 times, against 3 Nano and 2 Super calls. In `114842-job` and `115625-job` Ultra was never called.

**4. Your benchmark is 6 toy cases you built yourselves.**
True, and only 3/6 completed (`runs/batch-summary.json`). The other 3 hit a 429 rate limit. The cases use real CVEs and real breaking APIs. A real public repo is shortlisted (greyli/bluelog), but running it needs the owner's approval.

**5. Did a generated exploit ever go red then green?**
Not in a recorded run. The fetcher run reports "not proven" (0/8) and the mailer run "inconclusive". That's why we curate verified proofs for all 6 CVEs (e.g. bleach: 9 failed old → 9 passed new). We label which kind was used, and we report "not proven" instead of hiding it.

**6. The fetcher run says `ok: true` with no proof. Isn't that misleading?**
`ok` means tests are green. The ledger marks the security claim as partial or not proven, and the trust score drops (79 vs 93). The proof status is reported separately per run.

**7. How do you know the model didn't edit the tests to pass?**
The ledger checks "Tests were not edited to pass" and "No tests lost" against the original suite (run `113639-job`).

**8. Reachability: is it real or vibes?**
OSV symbols are used when present. OSV usually doesn't have them, so Nano infers them and the result is **labelled `llm-inferred`** (`reach.py`). OpenVEX (`vex.py`) never emits `not_affected` from LLM-inferred evidence.

**9. You run arbitrary repo code. Isn't that dangerous?**
Yes, and we found our own bug. The sandbox used to pass the full `os.environ`, API keys included, to the repo's `setup.py` and `conftest.py`. It now uses an allow-list (`sandbox.py`, `tests/test_sandbox_env.py`). The venv is **not** a security boundary: keep `ALLOW_REMOTE_REPOS=0` on public hosts. A container sandbox is next.

**10. What stops the LLM from writing malicious code into your sandbox?**
`patchpilot/guard.py` (in the working tree, not yet verified live) adds a deterministic AST screen plus NVIDIA `nemotron-3.5-content-safety` with a custom policy (no exfiltration, no external network, no secret reads). Rejected patches go back into the next repair attempt.

**11. Why upgrade to latest rather than the minimum fix?**
The deps.dev trust check (`35e831d`) found that the least-change targets (PyJWT 2.4.0, urllib3 1.26.19/2.2.2, Jinja2 3.1.3) have no PyPI attestation, while the latest releases do. Both options are shown, along with provenance, Scorecard and the new transitive deps.

**12. 723 seconds is too slow.**
Agreed. 97–98% of that time is model calls on free tiers. The speed work (`4a14cf3`) added reasoning control, JSON mode, a 90 s fix cap, parallel triage and research, Tavily-score rerank with no LLM call, and `uv`. Measured: venv+install 0.2 s vs 5.9 s. End-to-end time after the change is **not measured yet**.

**13. How do I verify any of this without an API key?**
`/console?replay=20261029-113639-job` replays the recorded events. `/console?demo=1` runs the guided story. Raw events are in `runs/*.jsonl`.

**14. Is the agent itself tested?**
Yes: 44 offline tests after the speed build (`tests/`), including sandbox env and VEX.

**15. Other languages?**
Python/pip only today. npm feasibility is done (jsonwebtoken CVE-2022-23540, offline alg:none proof). It's about 9 h of work and not built.
