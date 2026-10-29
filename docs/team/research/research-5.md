# Research 5: NVIDIA tech used for real work (2026-10-29)

Angle: the sponsor-tech score is 9/15. Research 2 already covers NAT and Nebius setup. This round asks which *extra* NVIDIA models could do a real job in the pipeline. Each claim is marked **[verified]** (an endpoint or list we queried today) or **[guess]**.

## 1. nvidia/* ids on OpenRouter today [verified, GET /api/v1/models]
| id | price in/out per token | ctx |
|---|---|---|
| nvidia/nemotron-3.5-lightning(:free) | 7e-8 / 2e-7 (free: 0) | 262k / 1M |
| nvidia/nemotron-3.5-super-vl(:free) | 1.5e-7 / 5e-7 (free: 0) | 1M |
| nvidia/nemotron-3-ultra-550b-a55b(:free) | 6e-7 / 2.4e-6 (free: 0) | 262k / 1M |
| **nvidia/nemotron-3.5-content-safety(:free)** | 2e-7 / 2e-7 (free: 0) | 131k / 128k |
| **nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free** | free | 256k |
| nvidia/nemotron-3-super-120b-a12b | 3e-7 / 2.4e-6 | 1M |
| nvidia/nemotron-3-nano-30b-a3b | 6e-8 / 2.4e-7 | 262k |
| **nvidia/switchyard** | dynamic (-1) | 1M |

New since our tier choice: **content-safety** (4B guard model, fine-tuned from Gemma-3-4B; it screens LLM inputs and outputs, multimodal), **nano-omni** (30B-A3B multimodal "perception sub-agent": text, image, video), **switchyard** (NVIDIA's open-source cost router across models).

## 2. NVIDIA API catalog (integrate.api.nvidia.com/v1/models) [verified, list queried without a key]
Relevant ids: `nvidia/nemotron-3.5-content-safety`, `nvidia/llama-3.1-nemoguard-8b-content-safety`, `nvidia/llama-3.1-nemoguard-8b-topic-control`, `nvidia/llama-3.1-nemotron-safety-guard-8b-v3`, `nvidia/nemotron-4-340b-reward`, `nvidia/nemotron-3.5-embed-1b`, `nvidia/nemotron-3.5-embed-8b`, `nvidia/nemotron-3-embed-1b`, `nvidia/llama-3.2-nv-embedqa-1b-v1`, `nvidia/nv-embedqa-mistral-7b-v2`, `nvidia/nemotron-3.5-super-vl-120b-a12b`.
- Chat and guard models: OpenAI-compatible `POST https://integrate.api.nvidia.com/v1/chat/completions`. Embeddings: `/v1/embeddings` with `input_type: query|passage` [verified that the ids exist; the request shape is from memory of NVIDIA docs, so **guess**].
- Free tier: build.nvidia.com gives developer credits and a rate-limited free key (nvapi-…) [**guess**: the exact quota was not checked].
- Rerank: the old `ai.api.nvidia.com/v1/retrieval/nvidia/llama-3_2-nv-rerankqa-1b-v2/reranking` returned **HTTP 410 Gone** today, and no rerank id appears in /v1/models. **Don't build on the rerank NIM.** Use embeddings plus cosine similarity instead.
- Reward: `nemotron-4-340b-reward` is listed, but it is an old, large model. It scores chat turns on helpfulness and correctness. Ranking patches is not what it was built for [**guess** on fit].
- Nebius Token Factory: its model list needs a key and could not be checked. Research 2 covers it.

## 3. Candidate integrations
| # | Integration | Job in PatchPilot | Where | Effort | Demo line |
|---|---|---|---|---|---|
| A | **Content-safety gate** (`nvidia/nemotron-3.5-content-safety:free` on OpenRouter; NIM fallback) | Screen every LLM-written exploit and patch before it runs in the sandbox. A verdict of unsafe (exfiltration, reverse shell, rm -rf outside the sandbox) blocks the run and records it in the evidence ledger. | `patchpilot/sandbox.py`: a pre-exec hook that calls a new `llm.safety_check(text)`. Tier config in `config.py`. | S (0.5 day) | "Every line of AI-written code is screened by NVIDIA's Nemotron guard model before it touches a sandbox." |
| B | **Nemotron embeddings for evidence rerank** (`nvidia/nemotron-3.5-embed-1b` via the NIM) | Replace the LLM rerank of Tavily and OSV results with cosine similarity to the CVE description: cheaper and deterministic. Log the scores. | `patchpilot/sources.py` `tavily_search` (wrap the results) | S | "Evidence ranked by Nemotron Embed in 80 ms instead of a 20 s LLM call." [the latency figure is a **guess**; measure it] |
| C | **Per-tier cost/latency profile** (NAT profiler, or our own from `done` usage) | A chart of tokens, seconds and $ per tier and step, so judges can see why each tier was chosen. NAT ships a profiler and evaluator (`nat eval` with profiler config) [**guess**: the docs page did not render via curl]. Cheaper: plot the usage we already emit. | `runs/` and `web/runs.html` | S-M | "Lightning does 70 % of the calls for 5 % of the cost." |
| D | **Topic-control / policy guard** (`llama-3.1-nemoguard-8b-topic-control`, or NeMo Guardrails rails) | Enforce policy on the agent's planned edits: never edit tests, never downgrade, stay inside the repo. A deterministic diff check does most of this better; the guard model adds an NVIDIA-branded second opinion. | `patchpilot/agent.py` patch acceptance | M | "Policy rails powered by NeMo Guardrails." Risk: a judge may see it as decoration unless it catches a real case. |
| E | **Nano-Omni / Super-VL reads CI logs and screenshots** | Feed a failing CI log or a screenshot of an error to the multimodal tier for triage. | New input path | M | Weak link to the core flow, so lower priority. |
| F | **Switchyard router** | Compare our hand-picked tiers with NVIDIA's router on one run. | `llm.py` model id | XS | "Our tiering beats or matches NVIDIA Switchyard on cost." Pricing is dynamic, not free: **guess** on cost. |
| G | Reward model ranking of patches | Rank N candidate patches | agent | M | Poor fit (above). Skip. |
| — | cuOpt | No real job here. Skip. | | | |

## 4. Ranking (judge impact × feasibility)
1. **A: content-safety gate.** Free on OpenRouter, a real security job, one call, and it fits the "safe autonomous agent" story.
2. **C: per-tier cost/latency chart.** Judges like charts, and the data already exists.
3. **B: Nemotron Embed evidence rerank.** A real, measurable speed and cost gain. Needs an NVIDIA API key (owner).
4. **F: Switchyard comparison run.** Trivial to wire. Gives a benchmark story with NVIDIA's own router.
5. **D: NeMoGuard topic-control or Guardrails policy check**, used alongside a deterministic diff check.

## Sources opened
- https://openrouter.ai/api/v1/models (queried and filtered to nvidia/*)
- https://integrate.api.nvidia.com/v1/models (queried and filtered)
- https://ai.api.nvidia.com/v1/retrieval/nvidia/llama-3_2-nv-rerankqa-1b-v2/reranking (POST returned 410)
- https://docs.nvidia.com/nemo/agent-toolkit/latest/workflows/profiler.html (fetched; content did not render, so the profiler claims are marked guess)
