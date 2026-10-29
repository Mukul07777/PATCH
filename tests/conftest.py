import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_demo_runs(monkeypatch, tmp_path_factory):
    """Keep the shipped demo-runs/ folder out of tests unless a test opts in."""
    from patchpilot import config
    monkeypatch.setattr(config, "DEMO_RUNS_DIR", tmp_path_factory.mktemp("no-demo"))
