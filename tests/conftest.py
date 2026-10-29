import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_demo_runs(monkeypatch, tmp_path_factory):
    """Keep the shipped demo-runs/ folder out of tests unless a test opts in."""
    from patchpilot import config
    monkeypatch.setattr(config, "DEMO_RUNS_DIR", tmp_path_factory.mktemp("no-demo"))


@pytest.fixture(autouse=True)
def _isolate_db(monkeypatch, tmp_path):
    """Every test gets its own empty SQLite file instead of runs/patchpilot.db."""
    from patchpilot import config, db
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "pp.db")
    yield
    db.close()


@pytest.fixture(autouse=True)
def _offline_dns_and_inline_notify(monkeypatch):
    """Destinations resolve to a public test address (IP literals and localhost to themselves) without DNS, and
    notification deliveries run inline unless a test opts into the background pool."""
    import ipaddress
    from patchpilot import netguard, notify

    def resolve(host, port):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return ["127.0.0.1"] if host == "localhost" else ["93.184.216.34"]
    monkeypatch.setattr(netguard, "_resolve", resolve)
    monkeypatch.setattr(notify, "_submit", notify.process)
    monkeypatch.delenv("PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS", raising=False)


TEST_TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture(autouse=True)
def _legacy_token(monkeypatch):
    """API tests authenticate with the legacy PATCHPILOT_TOKEN bearer (an admin), unless a test overrides it."""
    monkeypatch.setenv("PATCHPILOT_TOKEN", TEST_TOKEN)
    monkeypatch.delenv("PATCHPILOT_PUBLIC_DEMO", raising=False)
    monkeypatch.delenv("PATCHPILOT_SECRET_KEY", raising=False)


@pytest.fixture(autouse=True)
def _no_pypi_probe(monkeypatch):
    """Scans HEAD-check every package on PyPI; keep tests offline unless a test opts in."""
    from patchpilot import sources
    monkeypatch.setattr(sources, "pypi_missing", lambda names: set())


def osv_from(fn):
    """A sources.osv_batch stand-in built from a per-package lookup fn(name, version) -> advisories."""
    return lambda pairs: {(n, v): fn(n, v) for n, v in pairs}
