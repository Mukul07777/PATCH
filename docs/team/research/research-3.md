# Research 3: real public repos for the benchmark (2026-10-29)

Angle: find real small/medium public Python repos PatchPilot can run on, to replace the
self-written-only benchmark. Rounds 1-2 covered product ideas and pitch/demo, so this round
doesn't repeat them.

PatchPilot needs, per README: a pinned `requirements.txt` (`pkg==ver` lines), a pytest-collectable
suite, and at least one pinned package whose fix is a **breaking (major) upgrade** — the whole
point of the tool. The sweet-spot pins are `Werkzeug<2.2`, `Jinja2<3`, `PyJWT<2`, `urllib3<2`,
`bleach<6`, `requests<2.31`.

Method (all read-only): GitHub REST API (unauthenticated) for repo metadata + recursive tree
listing (default branch, license, last push, `requirements*.txt`, `test_*.py`/`tests/`/`conftest.py`);
`requirements.txt` fetched from `raw.githubusercontent.com` and parsed for `==` pins; each pin
queried against OSV (`POST https://api.osv.dev/v1/query`, PyPI ecosystem). `gh` CLI is not
installed in this environment, so no `gh search code` was used. grep.app's search API was blocked
by a bot wall.

Legend: **[verified]** = I fetched the file / API and read it. **[judgement]** = my own call,
labelled as such.

## Caveats on the numbers

- **Advisory counts are the raw OSV `vulns` length** for that exact version, including the large
  batch of `PYSEC-2026-*` entries OSV added recently. They are real OSV records but inflated
  versus "classic" CVE counts; treat them as "lots" vs "a few", not as precise CVE totals. All
  counts below are **[verified]** against the live API today.
- "Last commit" is the GitHub `pushed_at` date (last push to the default branch) as a proxy.
- Tests "present" means pytest can collect them (a `tests/` dir, `test_*.py`, or a `conftest.py`);
  unittest-style `TestCase` files still collect under pytest.
- "Likely 3.12 issue" is a **[judgement]** from the pins: old C-extension packages that shipped no
  `cp312` wheel (SQLAlchemy 1.x, psycopg2, aiohttp 3.8.x, gevent/greenlet/eventlet, asyncpg 0.27)
  typically fail to build on Python 3.12 and would break `pip install` in PatchPilot's sandbox
  before any test runs. Pure-Python Flask/Werkzeug/Jinja2 stacks install fine; only their runtime
  behaviour may differ.

## Candidate table

| Repo | License | Last push | Key vulnerable pins (OSV advisory count) | Breaking upgrade target | Tests (pytest) | Likely 3.12 install issue [judgement] |
|---|---|---|---|---|---|---|
| [greyli/bluelog](https://github.com/greyli/bluelog) | MIT | 2024-04-17 | Werkzeug 1.0.1 (18), Jinja2 2.11.1 (10), Flask 1.1.2 (4) | Werkzeug 1.x→3, Jinja2 2→3 | Yes — `tests/` (`test_auth.py`, `test_admin.py`, `test_blog.py`) | **Low**: pure-Python stack, no C-ext pins |
| [greyli/todoism](https://github.com/greyli/todoism) | MIT | 2022-12-08 | Werkzeug 1.0.1 (18), Jinja2 2.11.1 (10), urllib3 1.25.8 (22), requests 2.23.0 (8), Flask 1.1.2 (4) | Werkzeug 1.x→3, Jinja2 2→3, urllib3 1→2 | Yes — `tests/` (`test_api.py`, `test_auth.py`) + `test_app.py` | **Low-moderate**: app deps pure-Python; `selenium 3.141`/`watchdog` are dev-only |
| [greyli/sayhello](https://github.com/greyli/sayhello) | MIT | 2023-07-16 | Werkzeug 1.0.1 (18), Jinja2 2.11.1 (10), Flask 1.1.2 (4), SQLAlchemy 1.3.15 (0) | Werkzeug 1.x→3, Jinja2 2→3 | Yes — `test_sayhello.py` (single file) | **Low-moderate**: pure-Python; SQLAlchemy 1.3.15 may lack cp312 wheel but often builds |
| [hack4impact/flask-base](https://github.com/hack4impact/flask-base) | MIT (archived) | 2024-03-21 | Werkzeug 0.15.5 (18), Jinja2 2.11.3 (8), urllib3 1.25.8 (22), requests 2.22.0 (8), Flask 1.1.1 (4) | Werkzeug 0.15→3, Jinja2 2→3, urllib3 1→2 | Yes — `tests/test_basics.py`, `tests/test_user_model.py` | **High**: `psycopg2 2.8.3` (non-binary, needs build + pg_config, no cp312 wheel) |
| [amitt001/pygmy](https://github.com/amitt001/pygmy) | MIT | 2024-03-07 | urllib3 1.26.10 (20), Werkzeug 2.1.2 (20), PyJWT 2.4.0 (26), requests 2.28.1 (8), Django 4.0.6 (28), Flask 2.1.2 (4) | Werkzeug 2.1→3, urllib3 1→2, PyJWT→2.10+, Django 4.0→4.2+ | Yes — `pygmy/tests/` (`test_url_shorten_unshorten.py`, `test_click_stats.py`) | **High**: `aiohttp 3.8.1` (no cp312 wheel, build fails), `bcrypt 3.2.2`, `greenlet 1.1.2` |
| [miguelgrinberg/flasky](https://github.com/miguelgrinberg/flasky) | MIT | 2025-04-06 | Werkzeug 0.12.2 (22), Jinja2 2.9.6 (12), bleach 2.0.0 (10), requests 2.18.2 (10), urllib3 1.22 (24), Flask 0.12.2 (8) | Werkzeug 0.12→3, Jinja2 2→3, bleach 2→6, urllib3 1→2 | Yes — `tests/` (`test_api.py`, `test_basics.py`, `test_client.py`) | **High**: `SQLAlchemy 1.1.11` (C-ext, no cp312 wheel); whole stack is 2017-era |
| [miguelgrinberg/flack](https://github.com/miguelgrinberg/flack) | non-standard (check LICENSE) | 2022-07-06 | bleach 1.4.2 (OSV n/a for 1.x via query), Jinja2 2.10.1, Werkzeug 0.15.2, requests 2.9.1, Flask 1.1.1 (4) | bleach 1→6, Werkzeug 0.15→3, Jinja2 2→3 | Yes — `tests/tests.py` (unittest) | **Very high**: `gevent 1.4.0`, `greenlet 0.4.15`, `eventlet 0.19`, `uWSGI`, `SQLAlchemy 1.0.12` all need builds |
| [testdrivenio/fastapi-crud-async](https://github.com/testdrivenio/fastapi-crud-async) | MIT | 2024-02-05 | fastapi 0.87.0 (1, PYSEC-2024-38), SQLAlchemy 1.4.41 (0), uvicorn 0.20.0 (0) | fastapi 0.87→0.109+ (ReDoS fix) | Yes — `src/tests/` (`test_notes.py`, `test_ping.py`) | **High**: `asyncpg 0.27.0` (no cp312 wheel), SQLAlchemy 1.4.41 C-ext |

### Near-misses (don't qualify)

- [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) (MIT, tests `tests.py`): pins are
  already **modern** — Werkzeug 3.0.1, Jinja2 3.1.2, PyJWT 2.8.0, requests 2.31.0, urllib3 2.1.0. Nothing to
  fix, so no breaking-upgrade demo. [verified]
- [realpython/flask-by-example](https://github.com/realpython/flask-by-example): good old pins (Jinja2 2.11.1,
  Werkzeug 1.0.0, urllib3 1.25.8) but **no tests** and **no license**. [verified]
- [pallets/flask](https://github.com/pallets/flask) tutorial (`examples/tutorial`): has a real pytest suite but
  **no pinned `requirements.txt`** for the tutorial app itself (only `examples/celery` pins, which are modern-ish). [verified]
- [CoreyMSchafer/code_snippets](https://github.com/CoreyMSchafer/code_snippets): Django 2.1 / urllib3 1.23 pins, but
  tests are Django `tests.py` run via `manage.py test` (not pytest) and Django 2.1 is incompatible with Python 3.12. [verified]
- [cookiecutter-flask/cookiecutter-flask](https://github.com/cookiecutter-flask/cookiecutter-flask): it's a
  `{{cookiecutter}}` template; the generated app's `requirements.txt` is templated/unpinned until rendered. [verified]
- [gothinkster/flask-realworld-example-app](https://github.com/gothinkster/flask-realworld-example-app): pytest
  suite present but `requirements` are mostly unpinned (only SQLAlchemy 1.1.9 pinned). [verified]

## Ranked shortlist (4) with commands

Chosen for: a real breaking-version upgrade, a pytest suite PatchPilot can run, and the best
chance of a clean `pip install` on Python 3.12 (so the demo doesn't die at the install step).
Pure-Python Flask stacks are ranked above ones gated on old C-extensions.

> **Approval required.** Each command below checks out a third-party repo and runs **its** test
> suite on the host venv (`ALLOW_REMOTE_REPOS=1` must be set; README warns remote repos run
> arbitrary test code). Do not run these without the owner's (Mukul's) approval. Also note the LLM
> quota rule in the playbook: at most one full agent run per cycle.

1. **greyli/bluelog** — safest install + a clean Werkzeug 1→3 / Jinja2 2→3 breaking upgrade, real
   `tests/` suite. Best first real-repo demo.
   ```
   python -m patchpilot.cli https://github.com/greyli/bluelog
   ```

2. **greyli/todoism** — same pure-Python reliability, and adds urllib3 1→2 and requests 2.23 to the
   advisory set, with `tests/test_api.py` + `tests/test_auth.py`.
   ```
   python -m patchpilot.cli https://github.com/greyli/todoism
   ```

3. **hack4impact/flask-base** — richest classic vuln set (Werkzeug 0.15, Jinja2 2.11.3, urllib3
   1.25.8, requests 2.22.0) and a real `tests/` suite. **Caveat:** `psycopg2 2.8.3` likely fails to
   build on 3.12; if install breaks, either pre-provision it or fall back to #4.
   ```
   python -m patchpilot.cli https://github.com/hack4impact/flask-base
   ```

4. **greyli/sayhello** — simplest reliable backup: pure-Python, Werkzeug 1→3 / Jinja2 2→3, one
   `test_sayhello.py`.
   ```
   python -m patchpilot.cli https://github.com/greyli/sayhello
   ```

**High-vuln-density alternative:** `amitt001/pygmy` exercises the most target pins at once (PyJWT
2.4.0, urllib3 1.26.10, Werkzeug 2.1.2, requests, Django) and has a pytest suite, but `aiohttp
3.8.1` will likely fail to build on 3.12 — use only if the sandbox can pin Python 3.10/3.11 or
pre-build aiohttp.
