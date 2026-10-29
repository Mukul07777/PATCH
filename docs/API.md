# PatchPilot HTTP API

Base URL: your server, e.g. `http://localhost:8000`. Bodies are JSON. Errors answer `{"detail": "<reason>"}`;
`429` carries `Retry-After`.

## Authentication

| Caller | How |
| --- | --- |
| Browser | session cookie from `POST /api/auth/login`; writes must send `X-Requested-With: patchpilot` (CSRF) |
| Scripts / CI | `Authorization: Bearer pp_...` (API key from Settings → API keys; acts as its owner, capped at the key's role) |
| Legacy | `Authorization: Bearer $PATCHPILOT_TOKEN` (admin) |

Access levels below: **public** (no sign-in), **reader** (signed in; with `PATCHPILOT_PUBLIC_DEMO=1` anonymous
visitors may read sample projects and demo runs), **member** (signed in), **admin**.

```bash
export PP=http://localhost:8000 KEY=pp_your_key_here
alias ppcurl='curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json"'
```

## Health and info

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET, HEAD | `/api/health` | public | provider flags, model ids, `sandbox {mode, image, docker, ready}`, `remote_fix`, `scheduler`, `public_url` (bool); never secrets |
| GET | `/api/stats` | reader | projects, finished scans, open findings |
| GET | `/api/dashboard` | reader | severity totals, KEV, at-risk projects, top packages, 30-day trend, MTTR |
| GET | `/api/cases` | public | bundled sample cases and their pins |
| GET | `/api/bench` | public | recorded benchmark summary |

## Projects and scans

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET | `/api/projects` | reader | each with `last_scan` (status, counts, coverage) |
| POST | `/api/projects` | member | exactly one of `{"git_url", "ref"?, "subdir"?}`, `{"filename", "content"}`, `{"path"}` (needs `ALLOW_LOCAL_PATHS=1`); `name` optional |
| POST | `/api/projects/samples` | member | add the bundled sample projects |
| POST | `/api/projects/scan-all` | admin | queue a scan for every project without one queued/running → `{"queued", "scan_ids"}` |
| GET | `/api/projects/{id}` | reader | |
| DELETE | `/api/projects/{id}` | member | 204 |
| GET | `/api/projects/{id}/scans` | reader | scan + fix-run history |
| POST | `/api/projects/{id}/scan` | member | 202 `{"id", "status", "position"?}`; returns the running scan if there is one |
| GET | `/api/scans/{id}` | reader | status `queued\|running\|done\|error`, `findings` (with `new`, `suppressed`, `source_file`, `source_line`), `summary` (coverage, warnings, diff) |
| GET | `/api/scans/{id}/export?format=sarif\|cyclonedx\|json\|csv` | reader | download (`Content-Disposition: attachment`); 409 until the scan is done. SARIF 2.1.0 for GitHub code scanning, CycloneDX 1.5 JSON SBOM with `vulnerabilities`. Policy-suppressed findings are omitted from SARIF/CycloneDX and marked in JSON/CSV |

```bash
ppcurl -X POST $PP/api/projects -d '{"git_url": "https://github.com/pallets/flask", "ref": "main"}'
ppcurl -X POST $PP/api/projects/1/scan                     # {"id": 7, "status": "running"}
ppcurl $PP/api/scans/7                                     # poll until status is done
curl -s -H "Authorization: Bearer $KEY" "$PP/api/scans/7/export?format=sarif" -o flask.sarif
```

## Policy, schedules and ignores

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET | `/api/projects/{id}/policy` | reader | `severity_threshold`, `auto_fix`, `schedule`, `schedule_hour`, `next_run_at`, `channels`, `ignores` |
| PUT | `/api/projects/{id}/policy` | member | `{"severity_threshold": "low\|moderate\|high\|critical", "auto_fix": bool, "schedule": "off\|daily\|weekly", "schedule_hour": 0-23, "channels": [ids] or null}`; omitted `schedule`/`schedule_hour`/`channels` keep their stored values; `channels: null` = every channel |
| POST | `/api/projects/{id}/ignores` | member | `{"vuln_id", "reason", "expires_at"?}` |
| DELETE | `/api/projects/{id}/ignores/{iid}` | member | |

Schedules run at `schedule_hour`:00 UTC, daily or on Mondays (weekly). A scheduler thread checks every 30 s;
one process at a time holds the `scheduler` lease row, so several servers on one database never double-queue.
`PATCHPILOT_SCHEDULER=0` disables it in a process.

`auto_fix: true` starts an agent fix run when a scan (manual or scheduled) finds new fixable findings (a fixed
version exists, not suppressed by the threshold or ignore list), if fix mode can run: an LLM key, a GitHub or
sample project, remote fix runs allowed (Docker sandbox or the admin switch), a usable sandbox and a free run slot
(at most 3 at once). Every start or skip is audit-logged (`autofix.start` / `autofix.skipped` with the reason).

```bash
ppcurl -X PUT $PP/api/projects/1/policy -d '{"severity_threshold": "moderate", "schedule": "daily", "schedule_hour": 4}'
```

## Fix runs

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| POST | `/api/runs` | member | `{"project": id}` or `{"repo": "https://github.com/o/r" or "case:<name>"}`; 400 without an LLM key, 403 for remote repos unless allowed, 503 when `SANDBOX=docker` but Docker is unavailable, 429 at 3 active runs |
| GET, HEAD | `/api/runs` | public (demo runs) / reader | recent runs |
| GET | `/api/runs/{id}/events` | reader | Server-Sent Events; `?replay=<speed>` replays a recording |
| GET | `/api/runs/{id}/vex` | reader | OpenVEX document of a run |
| GET | `/api/org/{owner}` | member | quick scan of a GitHub user's / org's public repos |

## Notification channels (see [notifications.md](notifications.md))

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET | `/api/channels` | member | admins: masked config; members: `id, type, name, events, enabled` only |
| POST | `/api/channels` | admin | `{"type": "slack\|webhook\|email", "name", "config", "events": [...], "min_severity", "enabled"}`; webhook response includes `secret` once |
| PUT | `/api/channels/{id}` | admin | same body; blank URL / secret keep the stored ones |
| DELETE | `/api/channels/{id}` | admin | 204 (its delivery log goes with it) |
| POST | `/api/channels/{id}/test` | admin | sends a sample payload → `{"ok", "status", "delivery"}` |
| GET | `/api/deliveries?channel=&limit=` | admin | delivery log: status, response code, attempts, error |

```bash
ppcurl -X POST $PP/api/channels -d '{"type": "webhook", "name": "siem", "config": {"url": "https://siem.example.com/hook"},
                                     "events": ["new_findings", "kev", "scan_failed"], "min_severity": "high"}'
```

## Accounts

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET | `/api/auth/state` | public | `setup_needed`, current user |
| POST | `/api/auth/setup` | public, first run only | `{"email", "name"?, "password"}` creates the admin and signs in |
| POST | `/api/auth/login` | public | `{"email", "password"}` → session cookie (5 attempts a minute per IP) |
| POST | `/api/auth/logout` | public | 204 |
| POST | `/api/auth/password` | member | `{"current_password", "new_password"}`; other sessions are signed out |
| POST | `/api/auth/logout-all` | member | 204 |
| GET, POST | `/api/users` | admin | list / `{"email", "name"?, "password", "role"}` |
| PUT | `/api/users/{id}/role` | admin | `{"role"}` |
| POST | `/api/users/{id}/password` | admin | `{"password"}` (signs the user out everywhere) |
| DELETE | `/api/users/{id}` | admin | |
| GET, POST | `/api/keys` | admin | list / `{"name", "role"}` → the key once |
| DELETE | `/api/keys/{id}` | admin | |
| GET | `/api/audit?page=&per_page=` | admin | audit log |

## Settings

| Method | Path | Access | Notes |
| --- | --- | --- | --- |
| GET | `/api/settings` | admin | effective values and their source; secrets only as `{set, last4, source}` |
| PUT | `/api/settings` | admin | any of `llm_base_url, llm_api_key, model_nano, model_super, model_ultra, model_guard, tavily_api_key, github_token, max_fix_attempts, allow_remote_repos, public_url, sandbox (local\|docker), sandbox_image, smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, smtp_starttls`; `""` or `null` clears a value |
| POST | `/api/settings/test/{llm\|tavily\|github}` | admin | connection test → `{"ok", "error"}` |

## Limits

Project and scan calls: 60 a minute per user or API key. Sign-in attempts, fix runs, org scans and connection /
channel tests: 5 a minute per IP. Up to 4 scans run at once; more wait in a queue that survives restarts.
