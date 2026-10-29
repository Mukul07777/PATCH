# Notifications

Admins add channels on **Settings → Notifications** (`/api/channels`). Each channel has a type, the events it
wants, a minimum severity and an enabled switch. Projects opt in per channel in their policy (all channels by
default). Channel configuration (webhook URLs, signing secrets, recipients) is encrypted at rest with the same key
as the other stored secrets (`PATCHPILOT_SECRET_KEY` or `secret.key`).

| Type | Config | Notes |
| --- | --- | --- |
| `slack` | `{"url": "https://hooks.slack.com/services/..."}` | Slack incoming webhook; Block Kit message with project, counts, top 5 findings and an *Open in PatchPilot* button |
| `webhook` | `{"url": "https://...", "secret": "optional, 16-200 chars"}` | Signed JSON (below). A 64-hex-char secret is generated when none is given and shown once in the create response |
| `email` | `{"to": ["a@example.com", ...]}` or `"a@example.com, b@example.com"` | Sent through the SMTP server in Settings (host, port, user, password, from; STARTTLS on by default, port 465 uses implicit TLS) |

## Events

| Event | Sent when |
| --- | --- |
| `new_findings` | a finished scan has findings that were not open before it (first seen, or reopened after being fixed) at or above the channel's minimum severity and not suppressed by the project policy |
| `new_critical` | as above, and at least one of them is CRITICAL |
| `kev` | as above, and at least one of them is in the CISA Known Exploited Vulnerabilities catalog |
| `scan_failed` | a scan ended in error (manifest fetch failed, repository gone, ...) |
| `fix_completed` | an agent fix run linked to the project finished (`run.ok` says whether tests pass) |

Only *new* findings trigger a message: a re-scan that sees the same open findings sends nothing. A channel gets
**one message per scan**: when several finding events match, the most specific one the channel subscribed to is
used (`kev`, then `new_critical`, then `new_findings`), its findings are those matching that event, and
`events` lists every event that matched. Unrated advisories count as `low` for the minimum severity.

**Dedupe**: every delivery claims a unique `(channel, dedupe_key)` row first (`scan:<id>` or `run:<id>`), so a
scan replayed after a restart never notifies twice. **Retries**: network errors, HTTP 5xx and 429 are retried
3 times in total with 1 s and 4 s backoff; other 4xx answers are not retried. Every delivery is in the delivery
log (`GET /api/deliveries`) with its status (`ok` / `failed`), last response code, attempts and error.
**Send test** posts a sample `new_findings` payload with `"test": true` (one attempt, no dedupe).

Links use the **Public URL** setting (`public_url`, or `PATCHPILOT_PUBLIC_URL`); without it the `url` fields are `null`.

## Webhook request

```
POST <your url>
Content-Type: application/json
User-Agent: PatchPilot/0.4.0
X-PatchPilot-Event: new_findings
X-PatchPilot-Delivery: 42
X-PatchPilot-Timestamp: 1793268000
X-PatchPilot-Signature: sha256=5d1c...e9
```

`X-PatchPilot-Signature` is `sha256=` + hex `HMAC-SHA256(secret, "<X-PatchPilot-Timestamp>.<raw request body>")`.
Verify it with a constant-time comparison and reject old timestamps (for example older than 5 minutes) to stop
replays:

```python
import hashlib, hmac, time

def verify(secret: str, headers, body: bytes, max_age=300) -> bool:
    ts = headers["X-PatchPilot-Timestamp"]
    if abs(time.time() - int(ts)) > max_age:
        return False
    want = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-PatchPilot-Signature"])
```

Answer with any 2xx within 15 seconds. Redirects are not followed.

## Payload schema

```jsonc
{
  "event": "new_findings",          // new_findings | new_critical | kev | scan_failed | fix_completed
  "events": ["new_findings"],       // every event that matched for this channel
  "test": false,                    // true for "Send test"
  "timestamp": "2026-10-29T10:00:00Z",
  "patchpilot_version": "0.4.0",
  "project": {"id": 3, "name": "shop", "source_type": "git", "url": "https://pp.example.com/projects?id=3"},
  "scan": {"id": 17, "status": "done", "url": "https://pp.example.com/projects?id=3&scan=17"},   // scan events
  "counts": {"CRITICAL": 0, "HIGH": 1, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0},                  // finding events
  "new_findings": [                                                                              // finding events, worst first, max 50
    {
      "package": "jinja2", "version": "2.10",
      "vuln_id": "GHSA-462w-v97r-4m45", "aliases": ["CVE-2019-10906"],
      "severity": "HIGH", "cvss_score": 8.6, "epss": 0.0123, "kev": false,
      "fixed_in": "2.10.1", "summary": "Jinja2 sandbox escape ...",
      "source_file": "requirements.txt",
      "url": "https://osv.dev/vulnerability/GHSA-462w-v97r-4m45"
    }
  ],
  "truncated": false,               // more than 50 new findings: the rest are only in counts
  "error": "Branch or tag 'x' not found",                                  // scan_failed only
  "run": {"id": "20261029-100000-ab12", "ok": true, "error": null,          // fix_completed only
          "url": "https://pp.example.com/console?replay=20261029-100000-ab12"}
}
```

Fields not relevant to an event are omitted.
