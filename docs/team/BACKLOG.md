# Backlog (ranked; feasibility reviewer maintains this)

Format: `- [ ] **Title**: impact 1-5 · effort S/M/L · risk · acceptance test`

- [x] **Strip secrets from sandbox env** (done by manager 14:55): allow-list env for pip/pytest; verified keys absent in child process
- [ ] **SECURITY: requirements.txt guard + _write_files allow-list**: impact 5 · S · none · reject option/URL lines, only re-pin planned packages (never below fix) or add deps from target metadata; lower-case paths, block dot-dirs (.git/.github), conftest/setup/pyproject/.pth/sitecustomize, Tests/ case-insensitive; guardrail events
- [ ] **SECURITY: untrusted-text spotlighting + injection scanner + generated-test AST check**: impact 5 · S-M · none · untrusted_* fields, neutralise injection phrases/bidi chars, event with file:line
- [ ] **Demo case cases/poisoned/**: impact 5 · S · none · planted injection + conftest reading NEBIUS_API_KEY; guardrails card shows neutralised/blocked/0 secrets; fix still ships
- [ ] **POST /api/runs auth/rate limit**: impact 3 · S · none · token or localhost-only by default
- [ ] **NVIDIA content-safety gate on AI-written code**: impact 4 · S-M · free on OpenRouter (nvidia/nemotron-3.5-content-safety:free); needs quota · screen generated exploits/patches before sandbox execution; verdict in ledger + UI; skip gracefully on 429 (backend, after speed builder)
- [ ] **Per-tier cost/latency chart**: impact 3 · S · none · Runs page chart of tokens/seconds per tier from done.usage across recorded runs (UI, after UI builder)
- [ ] **Nemotron Embed rerank**: impact 3 · S · needs owner's nvapi key · cosine rerank of Tavily results with nemotron-3.5-embed-1b
- [ ] **SPEED: demo under 90 s (research-4.md plan)**: impact 5 · M · reasoning-control params unverified for our model ids (test with one call when quota allows) · Nano reasoning low/off + max_tokens 1500; triage ∥ research ∥ reach-inference; skip rerank (use Tavily score) / skip triage when reach conclusive; JSON mode + 45 s cutoff in fix loop; sandbox prep in background thread with uv; PATCHPILOT_DEMO=1 fast path
- [ ] **Container sandbox (network off)**: impact 4 · M · Docker may not be installed on the demo machine · when Docker is available, run install+pytest in `docker run --network none` (install step with network, test step without); fall back to venv and say so in the ledger
- [ ] **NeMo Agent Toolkit wrapper (nat mcp serve)**: impact 3 · S-M · register_function API unconfirmed · expose scan + run_one as NAT functions; 10-second 'callable from any agent' demo beat
- [ ] **Pin Nebius model ids**: impact 3 · S · ids from a third-party list (unverified) · .env.example Nebius block with explicit MODEL_*; auto-discovery also matches 'lightning' for nano
- [ ] **Re-run benchmark for sanitizer, sqlfmt, webhooks**: impact 5 · S · free API rate limit (429) stopped them on 2026-10-29 · run `python -m patchpilot.cli case:sanitizer case:sqlfmt case:webhooks` when quota resets, merge into batch-summary.json
- [ ] **Stronger generated exploit proofs**: impact 4 · M · LLM-heavy · generated proofs were 'not proven' (fetcher) and 'inconclusive' (mailer); add curated proofs for urllib3 CVE-2023-45803 and Jinja2 CVE-2024-22195, and make the generator validate fail-on-old before accepting (retry with feedback)
- [ ] **Symbol-level reachability (OSV ecosystem_specific.imports)**: impact 5 · S · OSV field may be missing for some advisories (fallback: Nano-inferred, labelled) · each advisory labelled reachable (file:line) / imported-not-called / not reachable; feeds triage, risk, ledger; Reachability tab shows it
- [ ] **Supply-chain trust check of the fix release (deps.dev)**: impact 4 · S-M · API coverage for PyPI attestations unverified · old vs target: attestation/provenance, OpenSSF Scorecard, new transitive deps; risk term + ledger claim
- [ ] **OpenVEX output from evidence**: impact 3 · S · depends on symbol reachability · openvex.json download with not_affected/fixed + justification
- [ ] **Two-loop repair: replan on wrong strategy**: impact 3 · S-M · needs LLM runs · Nano classifies failure (slip vs strategy); Ultra replans; 'replanned' shown in graph
- [ ] **Verify threat clock + drift radar end to end**: impact 5 · S · needs 1 LLM run · a recorded run shows threat and drift events and the Drift radar tab renders (fetcher or mailer case)
- [ ] **Publish benchmark numbers**: impact 5 · S · none · runs/batch-summary.json committed, Runs page shows headline stats, README quotes measured numbers only
- [ ] **Landing page shows new differentiators**: impact 4 · S · none · landing mentions drift radar, threat clock, red team, certificate with real numbers from the benchmark
- [ ] **Agent self-test suite + provider in done event**: impact 3 · M · none (no LLM) · `tests/` at repo root covers drift.usages/diff, sources.min_safe_version, llm.parse_json, agent.extract_test_code, _risk, _ledger; `done` event records provider + models; `ok` stays "tests green" and a new `proven` field says whether the exploit was proven closed; pytest passes
- [ ] **Demo video script + judge demo mode**: impact 4 · M · none · scripted 2-3 min path using an existing recorded replay, ending on the certificate (replay mode already exists: /console?replay=<id>)
- [ ] **One real PR on a public repo**: impact 3 · M · needs GITHUB_TOKEN from owner
- [ ] **Nebius run**: impact 4 · S · needs owner's Nebius key/card
