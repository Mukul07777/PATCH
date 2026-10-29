"""Round 6: docker timeout cleanup, public-API pinned transport."""
import subprocess

import httpx
import pytest

from patchpilot.core import netguard, sandbox


def test_docker_timeout_force_removes_named_container(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox.docker_run(tmp_path, ["python", "-V"], network=False, timeout=1)
    name = calls[0][calls[0].index("--name") + 1]
    assert name.startswith("patchpilot-") and calls[1] == ["docker", "rm", "-f", name]
    assert "none" == calls[0][calls[0].index("--network") + 1]


def test_guarded_client_uses_public_transport_and_blocks_private():
    c = netguard.client()
    assert isinstance(c._transport, netguard.PinnedTransport)
    with pytest.raises(netguard.Blocked):
        c.get("http://127.0.0.1:9/")


def test_pinned_transport_maps_connect_errors(monkeypatch):
    monkeypatch.setenv("PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS", "1")
    with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
        netguard.client(timeout=2).get("http://127.0.0.1:9/")
