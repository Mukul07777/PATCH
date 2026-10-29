import sys

from patchpilot.core import sandbox


def test_secrets_never_reach_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv("NEBIUS_API_KEY", "sk-secret")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-secret")
    env = sandbox.sandbox_env()
    assert not any("secret" in v for v in env.values())
    assert "PATH" in {k.upper() for k in env}


def test_child_process_cannot_read_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("NEBIUS_API_KEY", "sk-secret")
    code, out = sandbox.run([sys.executable, "-c", "import os; print(os.environ.get('NEBIUS_API_KEY'))"], cwd=tmp_path)
    assert code == 0 and out.strip() == "None"
