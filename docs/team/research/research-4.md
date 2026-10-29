# Research round 4: speed (live demo under 90 s)

Source: the recorded events in `runs/*.jsonl` (`t` = seconds since start, `model_call.seconds`). Read-only. No LLM calls made.

## 1. Profile: where the time goes

Full runs: authsvc 723 s, fetcher 463 s, mailer 390 s (sanitizer, sqlfmt and webhooks stopped on 429 at 24 to 82 s).

| Phase | authsvc | fetcher | mailer | Notes |
|---|---|---|---|---|
| OSV scan + PyPI latest + EPSS/KEV | 1.7 | 0.8 | 1.0 | Sequential per package, but already fast |
| Nano triage (1 call) | **196.0** (6000 out tok, hit max_tokens) | 72.1 (4055 tok) | 14.4 | Reasoning tokens make up most of the output |
| Tavily + Nano rerank (1 per package) | 85.3 (2 reranks: 52.7 + 30.5) | 47.0 (42.6) | 26.6 (22.3) | Rerank is 6000-token reasoning on Nano |
| Super plan | 18.6 | 9.3 | 5.7 | |
| venv create | 3.0 | 2.9 | 2.9 | `python -m venv` |
| pip install baseline | 2.5 | 1.9 | 1.9 | warm pip cache |
| Exploit proof | 0.2 (curated) | **236.7** (Super, 29k tok) | **238.3** (Super, 15.6k tok) | Curated proofs now exist for all 6 cases, so this goes to about 0 |
| Red-team variants | 0 (curated) | 58.3 (Super) | 33.3 (Super) | Also curated now |
| pip install after bump | 1.7 | 1.4 | 1.4 | |
| Fix loop | **412.6** (Super 155 s, 8192 tok, invalid JSON; Ultra 127 s; Ultra 130 s) | 30.1 | 62.8 | 3 sequential attempts on authsvc |
| pytest runs (each) | 0.2 to 0.3 | 0.2 to 0.3 | 0.2 to 0.3 | Negligible |
| exploit/redteam after, report | under 2 | under 2 | under 2 | |

**Summary:** model calls are **97 to 98 %** of wall time. For authsvc that is 709 of 723 s. Sandbox work (venv, pip, pytest) is about 10 s, and OSV/EPSS/KEV take about 2 s. Output-token volume drives the time: the free OpenRouter Nemotron endpoints run at roughly 30 to 120 tok/s, and most of those tokens are hidden reasoning. Without curated proofs, LLM exploit and variant generation cost another 270 to 300 s. The 429s on the free tier are a second, separate latency and reliability risk.

## 2. Ranked speedups

| # | Speedup | Est. saving (authsvc) | Effort | Risk |
|---|---|---|---|---|
| 1 | **Turn off or cap reasoning for Nano triage and rerank.** Send `reasoning: {"effort":"low"}` or `{"enabled": false}` (OpenRouter unified param), or `{"max_tokens": 512}`. Also send `"exclude": true` so reasoning text is not returned. On NIM/vLLM-served Nemotron: `chat_template_kwargs: {"enable_thinking": false}`, or the `/no_think` system-prompt flag (Nemotron Nano v2 / Super v1.5 convention; v1 uses `detailed thinking off`). Also drop `max_tokens` 6000 to 1500. | 200 to 250 s (triage 196 to about 15, reranks 83 to about 10) | S (llm.py: add `reasoning=` kwarg) | Low. Verify with a single call that the field is accepted. Unknown fields are ignored, so it degrades to today's behaviour. |
| 2 | **Fix loop: kill the failure mode, not just the latency.** Attempt 1 burned 8192 tokens and returned non-JSON. (a) Use `response_format: {"type":"json_object"}` where supported, plus reasoning effort `medium` and a hard cap. (b) Salvage code from `last_reasoning`, which already exists. (c) Prefetch: start the Super fix call as soon as the after-upgrade test fails, and use **streaming** with a timeout (abort at about 45 s and escalate). (d) Demo: `MAX_FIX_ATTEMPTS=2`. | 250 to 330 s | M | Medium. Fewer attempts mean more chance of not going green, so pair it with the fast path in #6. |
| 3 | **Parallelize the research stage.** Tavily per package plus rerank per package run concurrently in a `ThreadPoolExecutor`. Run triage (Nano), reachability inference and research **concurrently**: they all depend only on `findings` and `original`. Plan needs triage, so join before plan. | about 50 to 85 s now (rerank 2 to 1 critical path, research hidden behind triage); about 10 to 20 s after #1 | S/M (agent.py `_run`, emit is already a callback; guard the `self.router.usage` dict with a lock) | Low. Watch the free-tier 429 rate limit, so cap concurrency at 3. |
| 4 | **Skip LLM rerank and triage when it is not needed.** Rerank: use Tavily's own `score` and keep the top 4 (zero LLM). Triage: when reach.py labels every advisory `reachable` or `not reachable` from static evidence, skip the Nano call and template the triage. Run the LLM only for `imported`/`unknown`. | 30 to 200 s depending on case | S | Low/Med. It loses a "Nano did X" beat in the UI, so keep one Nano call (triage) and drop rerank. |
| 5 | **Overlap sandbox with the LLM stages, and cache venvs.** Start `venv + pip install + baseline pytest + curated exploit/redteam before` in a background thread right after checkout, since none of it needs the plan. Use `uv venv` + `uv pip install --python <venv>` (uv 0.12.19 is installed here), with a persistent per-pins cache dir. uv installs from its global cache in about 0.1 to 0.5 s compared with pip's about 2 s, and venv creation takes about 0.05 s compared with 3 s. | about 8 to 10 s (fully hidden) | S/M (sandbox.py, fall back to pip if `uv` is missing) | Low |
| 6 | **Demo fast path (`PATCHPILOT_DEMO=1`)**: curated proofs and variants only (already true for the 6 cases), rerank off, reasoning low on all tiers, fix attempts at most 2, prewarm (the `/models` call and a 1-token ping to each tier on server start, plus a uv venv pre-built for the case pins). Optionally **replay**: if live exceeds a budget, fall back to streaming the recorded jsonl at real pace with a visible "recorded" label. | Guarantees under 90 s | M | Low if honestly labelled |
| 7 | Paid or provisioned endpoint (Nebius Token Factory / NIM) instead of `:free`: higher tok/s, no 429 retries (each retry costs 2 to 6 s plus a failure risk). | 2 to 3x on all model time | config only | Cost |
| 8 | OSV `querybatch` + PyPI + EPSS/KEV/deps.dev in parallel. | about 1 to 2 s | S | Low (cosmetic) |
| 9 | Shrink prompts: the fix prompt is 5.9k tokens in. Send only failing-test output plus the files in tracebacks. | 5 to 15 s per fix call (prefill) | S | Low |

Not worth it: pytest itself (0.2 s per run), and pip `--prefer-binary` (installs are already about 2 s with wheels).

### Reasoning-control notes (verify with one live call before relying on them)
- **OpenRouter** has a unified `reasoning` object on `/chat/completions`: `effort` (`low|medium|high`), or `max_tokens` (a reasoning budget), `exclude` (do not return reasoning), and `enabled`. Providers that do not support a field ignore it. Reasoning tokens are billed and timed as output, which is exactly the cost we see (triage hit its 6000 cap).
- **NVIDIA Nemotron** reasoning models toggle thinking by system prompt. Llama-Nemotron v1 uses `detailed thinking on|off`. Nemotron Nano 9B v2 and Super v1.5 use `/think` and `/no_think`. Nemotron Nano v2 also documents a **thinking budget** (NIM / vLLM `max_thinking_tokens`, done client-side by truncating and re-prompting). On vLLM/NIM, `chat_template_kwargs={"enable_thinking": false}` is the template switch for Nemotron 3 family models.
- Model ids here (`nemotron-3.5-lightning`, `-super-vl`, `-3-ultra`) are newer than the documented ones. Check which switch is honoured by sending the same triage prompt with and without it and comparing `completion_tokens`.

## 3. Target plan: case:authsvc under 90 s

Projected critical path after the changes:

| Stage | Today | Target | How |
|---|---|---|---|
| models/checkout/scan/threat | 2 s | 2 s | parallel OSV/PyPI/EPSS (#8) |
| sandbox + baseline + exploit/redteam before | 10 s | 0 s on path | background thread + uv (#5) |
| triage ‖ research | 281 s | 12 to 18 s | reasoning off, max_tokens 1500 (#1), concurrent (#3), Tavily-score rerank (#4) |
| plan (Super) | 19 s | 6 to 10 s | reasoning low |
| fix | 413 s | 30 to 50 s | JSON mode + reasoning medium + 45 s stream cutoff, at most 2 attempts (#2), smaller prompt (#9) |
| tests, exploit/redteam after, report | 2 s | 2 s | |
| **Total** | **723 s** | **about 55 to 80 s** | |

Order of work: #1 (one-line param, biggest win), then #4 rerank-off, then #3, then #2, then #5, then #6. Measure after #1 alone: authsvc should drop to about 450 s, and below 150 s once fix attempt 1 stops failing JSON. The fix-loop reliability (#2) decides whether the demo hits 60 s or 300 s. If attempt 1 cannot reliably go green on authsvc, use the demo fast path plus a pre-recorded replay as the safety net.
