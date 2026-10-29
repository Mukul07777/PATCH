# Decisions waiting for Mukul

1. **Run real public repos** (executes third-party test code on this laptop). Shortlist from research-3.md:
   - `python -m patchpilot.cli https://github.com/greyli/bluelog` (safest: Werkzeug 1→3, Jinja2 2→3)
   - `https://github.com/greyli/todoism`, `https://github.com/greyli/sayhello`, `https://github.com/hack4impact/flask-base` (psycopg2 may not build on 3.12)
2. **Nebius Token Factory key/card**: switch .env to the pinned Nebius block in .env.example and do one recorded run.
3. **GITHUB_TOKEN**: lets the agent open one real PR (on a fork you own) for the demo.
4. **Docker Desktop**: enables a network-off container sandbox (honest answer to "is running untrusted tests safe?").
5. **PyJWT leading-space finding**: report privately to PyJWT maintainers before demoing it publicly.
