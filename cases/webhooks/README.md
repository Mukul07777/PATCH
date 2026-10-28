# hooksvc (demo target)

Webhook signing service pinned to `Werkzeug==2.0.3`, which has real advisories (e.g. CVE-2023-25577, CVE-2024-34069) fixed only in 2.2.3 / 3.0.x.
Werkzeug 2.1+ removed `safe_str_cmp`, and 3.0 removed `werkzeug.urls.url_quote` / `url_encode`, so the security upgrade breaks this code.
