# Research 7 — Answering "Python only": a cheap, credible npm ecosystem

Date: 2026-10-29 · Angle: second ecosystem (npm) for a ~1 day hackathon build.

## Machine check
- `node --version` → **v24.19.0**, `npm --version` → **11.17.0**. Node 24 includes `node:test` and `--test-reporter`, so no jest/vitest install is needed for our own demo case.

## Live OSV checks (ecosystem `"npm"`, run today)
`POST https://api.osv.dev/v1/query {"package":{"name":X,"ecosystem":"npm"},"version":V}`. It is the same endpoint as PyPI, so `sources.osv_vulns` only needs an `ecosystem` parameter.

| pkg@ver | CVEs returned |
|---|---|
| jsonwebtoken@8.5.1 | CVE-2022-23539, **CVE-2022-23540**, CVE-2022-23541 (GHSA-qwph-4952-7xr6, -8cf7-32gw-wr33, -hjrf-2m68-5959) |
| minimist@1.2.5 | CVE-2021-44906 (prototype pollution) |
| node-fetch@2.6.6 | CVE-2022-0235 |
| axios@0.21.1 | 27 CVEs (too noisy for a demo) |
| lodash@4.17.20 | CVE-2020-28500, CVE-2021-23337 + 2025/2026 records |

Note: **CVE-2022-23529** (the well-known jsonwebtoken RCE) was *withdrawn* by GitHub/NVD as not exploitable, and OSV does not return it. Don't headline it, because a judge who checks will catch it. Use CVE-2022-23540 instead.

## Demo case candidates
| Case | Proof (offline, deterministic) | Breaking change (drift) | Verdict |
|---|---|---|---|
| **jsonwebtoken 8.5.1 → 9.0.0** (CVE-2022-23540) | Sign with `alg:"none"`, then `jwt.verify(tok, undefined)`. v8 accepts it (auth bypass). v9 throws `JsonWebTokenError: please specify "none" in "algorithms"`. Takes 5 lines with `node:test` and `assert.throws`. | v9 has real breaking changes: RSA keys under 2048 bits are rejected (`allowInsecureKeySizes`), legacy key types are rejected, there is no default `none`, and Node ≥12 is required. A sample app that signs with a 1024-bit key, or calls `verify(tok)` without algorithms, fails its tests after the bump, so the LLM fix loop has real work. | **Recommended** |
| minimist 1.2.5 → 1.2.6 (CVE-2021-44906) | `minimist(['--__proto__.x','1'])`, then check `({}).x`. Very clean. | Patch-level bump, so nothing breaks. No fix-loop story. | Good backup proof, weak story |
| node-fetch 2.6.6 → 3.x | CVE-2022-0235 leaks Cookie/Authorization headers on a cross-host redirect, so the proof needs 2 local http servers. That is doable, but more moving parts. | v3 is ESM-only, so `require('node-fetch')` breaks: a dramatic drift. A fix is also available in 2.6.7, though, so "min safe" picks 2.6.7 and there's no break. | Shows drift well, but the story is muddled |
| lodash 4.17.20 → 4.17.21 | `_.template` command injection / ReDoS | No break | Weak |
| axios 0.21 → 1.x | SSRF needs a network | Big API changes | Too noisy (27 CVEs) |

## Applying pins
- In package.json, set an exact `"dependencies": {"jsonwebtoken": "9.0.0"}`. Edit the JSON directly instead of running `npm install pkg@ver --save-exact`, because it's deterministic and doesn't hit the network. Then run `npm install --no-audit --no-fund --ignore-scripts` (or `npm ci` once a lockfile exists).
- Offline-ish options: `npm install --prefer-offline` uses the `~/.npm/_cacache` cache. Warm the cache once before the demo (`npm cache add jsonwebtoken@8.5.1 jsonwebtoken@9.0.0`). Use `--offline` for a hard guarantee.
- **Security:** always pass `--ignore-scripts`, because install scripts are npm's RCE vector. This mirrors the existing "no keys in sandbox env" rule (commit 016cb64), and the same `sandbox_env()` scrub applies.
- Pins come from package.json (deps + devDeps), with resolved versions read from `package-lock.json` (`packages["node_modules/<name>"].version`, lockfileVersion 2/3). Ranges like `^8.5.1` count as "pinned" to the lockfile's resolved version.

## Running tests and parsing results
- Our demo repo uses `node --test --test-reporter=tap` (built in). Parse the TAP lines `ok N - name` / `not ok N - name`, or use `--test-reporter=junit` → XML, which `xml.etree` parses into per-test cases. That is the equivalent of `test_cases()`.
- Generic repos use `npm test`. Jest supports `--json --outputFile=r.json` (`testResults[].assertionResults[].status`) and vitest supports `--reporter=json`. For the 1-day build, support only node:test and fall back to the `npm test` exit code.
- Exploit files go in `.patchpilot/exploit.test.js` and run with `node --test .patchpilot/exploit.test.js`. This mirrors the dot-dir trick in agent.py.

## JS drift radar
1. **Usage (static):** a regex over `**/*.{js,cjs,mjs,ts}` excluding node_modules:
   - `require\(['"]PKG['"]\)` binds to `const X =` / destructuring `{a,b}`
   - `import X from 'PKG'`, `import {a,b} from 'PKG'`, `import * as X`
   - then `X\.(\w+)` member accesses → the symbol set. This covers about 90% of demo code. Skip acorn, because it would add a dependency.
2. **Probe (dynamic):** inside the sandbox, run this for each version:
   `node -e "const m=require(process.argv[1]);console.log(JSON.stringify(Object.keys(m).concat(Object.keys(m.default||{}))))" jsonwebtoken`
   Use `await import()` when the package is ESM-only. ERR_REQUIRE_ESM is itself a drift signal ("default export is now ESM-only"), which is exactly the node-fetch 3 story. To get signatures, also record `typeof` and `fn.length` (arity) per key.
3. `drift.diff(usage, old, new)` can be reused unchanged if the probe emits the same `{symbol: signature}` shape.

## Proposed abstraction
```python
class Ecosystem(Protocol):
    name: str            # "PyPI" | "npm"  (OSV ecosystem string)
    def detect(work) -> bool                       # requirements.txt / package.json
    def pins(work) -> dict[str, str]               # name -> exact version
    def apply_pins(work, targets: dict) -> None    # rewrite manifest
    def install(sandbox) -> tuple[int, str]        # pip/uv  |  npm install --ignore-scripts
    def test(sandbox, path=None) -> tuple[int, str]  # pytest | node --test / npm test
    def test_cases(output) -> dict[str, bool]      # junit/TAP parse
    def probe(sandbox, pkg) -> dict                # exported symbols + arity
    def usages(files, pkg) -> set                  # static import scan
    exploit_prompt: str; exploit_path: str         # pytest vs node:test wording
```
Registry `ECOSYSTEMS=[PyPI(), Npm()]`. `Agent._checkout` picks the first ecosystem where `detect()` is true.

### agent.py touch points
- `_pins` / `_apply_pins` (L265-285) → delegate to `eco`.
- The install calls and the "requirements.txt changed → reinstall" check (L134, L157-161) → `eco.manifest_files`.
- `_exploit_before`, `_generate_exploit`, `_mutations_before` prompts (L424-600) contain the literal word "pytest", so make them `eco.exploit_prompt`. `extract_test_code` needs a JS variant (look for `test(` / `it(` from `node:test`).
- `_probe` / `_drift` (L536-556) → `eco.probe` / `eco.usages`.
- `sources.osv_vulns(pkg, ver, ecosystem="PyPI")`, plus `npm_latest` via `https://registry.npmjs.org/<pkg>/latest`. deps.dev already supports `NPM` system.
- `reach.py` and the curated `exploits/` registry are keyed by CVE. Add `exploits/cve_2022_23540.js` (a static proof, no LLM needed for the demo).
- `_vkey` / `version_gte` work for semver except prereleases. That's fine for the demo.

## Effort (1 builder-day)
| Piece | Est. |
|---|---|
| Ecosystem protocol + move Python code behind it (no behaviour change; existing tests must stay green) | 2.5 h |
| Npm: detect/pins/apply_pins/install (+ cache warm, --ignore-scripts) | 1.5 h |
| Npm: test + TAP/junit parse | 1 h |
| JS probe + regex usages | 1.5 h |
| osv/latest ecosystem param | 0.5 h |
| `cases/node-jwt-demo/` (app signing with a 1024-bit RSA key + verify without algorithms, with node:test tests) + curated proof for CVE-2022-23540 | 1.5 h |
| UI badge "npm" + README | 0.5 h |
| **Total** | **~9 h** |

## Risks
- **Refactor regressions** in the Python path: do the protocol extraction as a separate commit, gated by the existing test suite.
- **Network during the demo:** registry fetches. Mitigate with `--prefer-offline` and a warmed cache, and commit a package-lock.
- **Install-script RCE**: always pass `--ignore-scripts`. Never run `npm test` from an untrusted repo outside the scrubbed sandbox.
- **LLM fix quality in JS:** free models are weaker at the JS fix loop. The curated proof plus a small, obvious break (key size or the algorithms option) keeps it tractable.
- **Windows:** `npm` is `npm.cmd`, so subprocess needs `shutil.which("npm")` or `shell=True`.
- Lockfile-only transitive vulns (e.g. minimist pulled in by another package) need `npm install pkg@ver` overrides (the `"overrides"` field). Leave this out of scope; say "direct deps only" honestly.

## Sources opened
- https://api.osv.dev/v1/query (live POSTs above, ecosystem "npm")
- https://google.github.io/osv.dev/post-v1-query/
- https://github.com/advisories/GHSA-qwph-4952-7xr6 (CVE-2022-23540)
- https://github.com/advisories/GHSA-27h2-hvpr-p74q (CVE-2022-23529, withdrawn)
- https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes:-v8-to-v9
- https://nodejs.org/api/test.html#test-reporters
- https://docs.npmjs.com/cli/v11/commands/npm-install (--ignore-scripts, --prefer-offline, --save-exact)
- https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json
- https://github.com/advisories/GHSA-xvch-5gv4-984h (minimist CVE-2021-44906)
