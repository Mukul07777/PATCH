# Backlog (ranked; feasibility reviewer maintains this)

Format: `- [ ] **Title**: impact 1-5 · effort S/M/L · risk · acceptance test`

- [ ] **Verify threat clock + drift radar end to end**: impact 5 · S · needs 1 LLM run · a recorded run shows threat and drift events and the Drift radar tab renders (fetcher or mailer case)
- [ ] **Publish benchmark numbers**: impact 5 · S · none · runs/batch-summary.json committed, Runs page shows headline stats, README quotes measured numbers only
- [ ] **Landing page shows new differentiators**: impact 4 · S · none · landing mentions drift radar, threat clock, red team, certificate with real numbers from the benchmark
- [ ] **Agent self-test suite + provider in done event**: impact 3 · M · none (no LLM) · `tests/` at repo root covers drift.usages/diff, sources.min_safe_version, llm.parse_json, agent.extract_test_code, _risk, _ledger; `done` event records provider + models; `ok` stays "tests green" and a new `proven` field says whether the exploit was proven closed; pytest passes
- [ ] **Demo video script + judge demo mode**: impact 4 · M · none · scripted 2-3 min path using an existing recorded replay, ending on the certificate (replay mode already exists: /console?replay=<id>)
- [ ] **One real PR on a public repo**: impact 3 · M · needs GITHUB_TOKEN from owner
- [ ] **Nebius run**: impact 4 · S · needs owner's Nebius key/card
