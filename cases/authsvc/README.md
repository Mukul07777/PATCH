# authsvc (demo target)

A small auth service pinned to real, vulnerable versions:
- `PyJWT==1.7.1` — CVE-2022-29217 (algorithm confusion), fixed in 2.4.0 (a **breaking** major upgrade)
- `requests==2.25.1` — CVE-2023-32681 (Proxy-Authorization leak), fixed in 2.31.0

PatchPilot uses this repo to show the full advisory → patch → tested PR loop.
