# PatchPilot

**Dependabot opens the PR. PatchPilot makes it mergeable, and proves it.**

An open-source coding agent on **Nebius Token Factory** with NVIDIA Nemotron:
- **Nano** handles the fast, high-volume calls.
- **Super** writes the fixes.
- **Ultra** is called only when Super fails.

**Track:** Coding and Agentic Engineering.

## Inspiration
The fix for a vulnerability in a Python dependency is usually one line in `requirements.txt`. The real problem is the major version behind that line: PyJWT 1→2, Werkzeug 3, urllib3 2, bleach 6. The bot bumps the pin, the build goes red, the PR sits there for weeks, and the CVE stays in production. Every team that uses Dependabot has a pile of these. We wanted an agent that does the part that actually costs engineering time, making the upgrade work. It should then **prove** the hole is closed instead of just saying so.

## What it does
**For a developer (the agent, on Nemotron):**
1. **Find.** Scans the pins against OSV.dev. It also scans the dependency tree that is actually installed, because most vulnerable code comes in through a dependency of a dependency that `requirements.txt` never names.
2. **Prioritise.** Shows whether each hole is being exploited right now (CISA KEV), the 30-day attack chance (EPSS), and whether *your* code calls the vulnerable function (AST reachability, with Nano inferring symbols when OSV has none).
3. **Predict.** Before any test runs, it probes the old and new library APIs and lists the exact lines of your code that will break.
4. **Lock behaviour.** Super writes calls into your own functions. A fixed harness, not the model, records what they return twice on the vulnerable versions and drops anything non-deterministic.
5. **Fix.** Upgrades in a sandbox and runs your tests. Super repairs the code, and Ultra takes over if Super fails. Green tests are not enough: if any locked behaviour changed, that goes back to the model as a failure.
6. **Attack.** An exploit test must **succeed** on the old version and **fail** on the patched one. After that, 5–8 variations of the attack are run against the patched code.
7. **Prove and ship.** It writes a certificate where every claim is checked independently and hashed with the diff, plus OpenVEX, then opens a PR. **Rescue mode:** paste the URL of an existing red Dependabot PR, and PatchPilot pushes the repair onto *that* PR's branch.

**For everyone else (scan mode, no AI key needed, never runs your code):**
- **Inputs:** a GitHub repo, a manifest or lock file (`requirements.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`), a **CycloneDX/SPDX SBOM**, or a whole GitHub org.
- **Security grade A–F** with an "In plain words" summary and a to-do list ordered Do now / Do soon / When you can. It is written for people who have never seen a CVE id.
- **Supply-chain checks beyond CVEs:**
  - known-malicious packages
  - typosquats like `reqeusts` (a lookalike name is only flagged when PyPI history backs it up)
  - versions their maintainers withdrew (yanked) and packages nobody has updated in years
  - license classes, including GPL/AGPL warnings
- **One-click fixed `requirements.txt`**, plus a signed public README badge.
- **Team features:** dashboard, scheduled scans, Slack/webhook/email alerts, a CLI with SARIF and CycloneDX output, and a GitHub Action.

## How we built it (Nemotron and Token Factory)
- **Routing by failure.** Every call goes to the cheapest tier that can do it. Across the six-case Token Factory benchmark there were 23 model calls and Ultra was called **once**: in run `20261029-153834-job`, Super's patch failed, and Ultra's went green on attempt 2.
- **Usage tracking.** Every run records calls, tokens, seconds, model id and provider per tier, and the console shows it live.
- **Token Factory specifics we built for:**
  - `enable_thinking: false` on Nano for classification calls. This cut Nano output from about 3,000 tokens to 200–1,700 per run.
  - JSON mode, plus a parser that copes with Markdown fences quoted from research text.
  - Model discovery from `/models`.
- **Tavily.** A live call per vulnerable package on every run ("`<pkg>` upgrade `<old>` to `<new>` breaking changes migration guide"). Results are ranked by Tavily's score; Nano reranks them only when scores are missing. The repair model must quote the lines it used, with their URL, and those quotes appear in the PR. Example from run `153834`: Ultra's fix quoted the PyJWT changelog, "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer".
- **Sandbox.** One isolated virtualenv per run, built with `uv` (0.2 s instead of about 6 s with pip). The environment is an allow-list, so no API key reaches the scanned repo's code. AI-written code is screened by an AST safety scan, and by NVIDIA's content-safety guard model when the account lists it.
- **Stack:** Python, FastAPI, Server-Sent Events, SQLite, plain HTML/JS with no build step.
- **Code layout:** `patchpilot/core` (router, sandbox, guard), `intel` (sources, scanner, supply chain, grading), `agent` (pipeline, proof, behaviour lock, rescue), `app` (web product).
- **Tests:** 368 offline tests, plus browser end-to-end tests at desktop and phone widths.

## Proof (shipped recordings, Nebius Token Factory, replayable without a key)
| Run | Case | Result |
|---|---|---|
| `20261029-153834-job` | authsvc (PyJWT 1→2) | green on attempt 2 (Super → Ultra), exploit **proven closed**, variants 7/8 blocked, trust 85, 110.7 s |
| `20261029-154025-job` | fetcher (urllib3) | green, 1 attempt, proven closed, 7/7, trust 91, 136.4 s |
| `20261029-154242-job` | mailer | green, 1 attempt, proven closed, 8/8, trust 91, 85.9 s |
| `20261029-153214-job` | sanitizer (bleach 6) | green, 1 attempt, proven closed, 8/8, trust 86, 65.4 s |
| `20261029-154551-job` | sqlfmt (sqlparse) | green, 0 attempts needed, proven closed, 5/5, trust 83, 65.5 s |
| `20261029-154657-job` | webhooks | green, 1 attempt, proven closed, 8/8, trust 91, 64.7 s |

**6/6 green, 6/6 exploits proven closed, 43/44 attack variants blocked.** The one still open is reported as still open, not hidden.

**Verified outside the agent, on real data:**
- **Behaviour lock:** on PyJWT 1.7.1 → 2.10.1 it caught 4 behaviour changes and dropped a time-dependent token as unstable.
- **Transitive fixes:** `requests==2.19.0` led to `idna 2.7` and `urllib3 1.23` (14 advisories, neither named in the file). After the pins, 0 remained.
- **Org scan:** 9 of pallets' 11 repos scanned through their `uv.lock`.
- **Typosquat check:** 2 alerts across 358 real dependencies (`httpx2` and `httpcore2`, both lookalike names published recently).

## Challenges (honest)
- **A model that would not add a dependency.** bleach 6 needs `tinycss2`. Nemotron kept writing an import fallback that silently dropped a feature (3 of 3 runs). We added a deterministic missing-dependency repair, and the rerun went green with `tinycss2==1.5.1` pinned.
- **Generated exploits can be wrong.** A Nemotron-written proof was sometimes "inconclusive" because the old version passed too. We built a curated, verified exploit library, and we report "not proven" when that is the truth.
- **Green tests are not the same as unchanged behaviour.** That is why the behaviour lock exists: repos with weak tests could otherwise "pass" with changed behaviour.
- **Free tiers do not work for a benchmark.** Our first benchmark on a free endpoint hit rate limits after 3 of 6 cases. All six were re-run on Token Factory.
- **We found holes in our own tool and fixed them:**
  - the sandbox once passed API keys to repo code
  - tests were writing fake runs into the demo folder
  - a Docker build would have copied the local database into the image
  - oversized ids crashed API routes (found by fuzzing all 48)

## What's next
npm and Go ecosystems; a Nebius Serverless Job for the nightly scan queue; a patch for vulnerabilities that have no fixed release yet (guard the call site, prove it with the exploit test).

## Testing instructions
- **Hosted demo:** <!-- TODO(owner): hosted demo URL --> It runs with `PATCHPILOT_PUBLIC_DEMO=1`, so no login is needed.
- **Watch the agent:** open **/console** and choose **Watch it fix a real project** for the guided replay.
- **Scan your own code:** open **/projects → Projects** and add a GitHub repo, a `requirements.txt` or an SBOM. Scanning needs no key.
- **Run locally:**
  1. `cp .env.example .env`
  2. Set `NEBIUS_API_KEY` and `TAVILY_API_KEY`.
  3. `pip install -r requirements.txt`
  4. `python -m patchpilot serve` (on Windows, `run.bat` does all of this).

## Feedback for Nebius and NVIDIA
- **Thinking control:** a `reasoning: off`-style parameter on the OpenAI-compatible endpoint was not honoured; only vLLM's `chat_template_kwargs.enable_thinking: false` worked. Before we found it, Nano spent its whole 1,500-token budget thinking and returned nothing usable. One documented, provider-neutral switch would save every agent builder this hunt.
- **Model id consistency:** the Nemotron ids mix styles (`nvidia/Nemotron-3_5-Lightning`, `nvidia/nemotron-3-super-120b-a12b`, `nvidia/Nemotron-3-Ultra-550b-a55b`). Mixed case and `_` vs `-` make tier discovery from `/models` fragile; a `family`/`tier` field in the model listing would fix it.
- **JSON reliability:** JSON mode on Super and Ultra was much better than free endpoints. When a reply quotes Markdown with code fences, the JSON was still sometimes wrapped in an outer fence. A strict-schema option would remove our fallback parser.
- **Guard model availability:** the NVIDIA content-safety model was not listed for our Token Factory account, so our gate fell back to static analysis. Making the guard model generally available next to Nemotron would make safe agent loops (screening AI-written code before it runs) easy to adopt.
- **What worked very well:** latency on Token Factory turned 390–723 s free-tier runs into 64–136 s, and the three-tier Nemotron lineup made routing by failure a natural design. Our most expensive model ran once in six cases.
