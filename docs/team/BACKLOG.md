# Backlog (ranked; feasibility reviewer maintains this)

Format: `- [ ] **Title**: impact 1-5 · effort S/M/L · risk · acceptance test`

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
