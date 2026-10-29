"""Isolated test runner: a fresh virtualenv per run, so the agent's changes are verified for real."""
import contextlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import config


def venv_python(venv):
    win = Path(venv) / "Scripts" / "python.exe"
    return str(win if win.exists() else Path(venv) / "bin" / "python")


def uv_path():
    """The `uv` binary when it is on PATH (10x faster venv + install), else None."""
    return shutil.which("uv")


# Only what pip/pytest need. The scanned repo's setup.py / conftest.py run with this env,
# so API keys and tokens must never be in it.
ENV_ALLOW = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR",
             "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
             "LANG", "LC_ALL", "PYTHONIOENCODING", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
             "UV_CACHE_DIR", "PIP_CACHE_DIR", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}


def sandbox_env():
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_ALLOW}
    env.update(PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1")
    return env


def run(cmd, cwd, timeout=600):
    env = sandbox_env()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


# ---------- Docker mode ----------
DOCKER_WORK = "/work"
DOCKER_VENV = "/work/.patchpilot/venv"  # inside the mounted work dir: the container's root filesystem is read-only
_docker_cache = {}


class SandboxUnavailable(RuntimeError):
    pass


def docker_available(now=None):
    """True when a docker CLI is on PATH and its daemon answers (cached for 60 s)."""
    now = time.monotonic() if now is None else now
    hit = _docker_cache.get("ok")
    if hit and now - hit[0] < 60:
        return hit[1]
    exe = shutil.which("docker")
    ok = False
    if exe:
        try:
            ok = subprocess.run([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                                timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
    _docker_cache["ok"] = (now, ok)
    return ok


def check_mode():
    """Raise SandboxUnavailable when SANDBOX=docker is configured but docker cannot be used."""
    if config.sandbox_mode() == "docker" and not docker_available():
        raise SandboxUnavailable("SANDBOX=docker is configured but Docker is not available on this server "
                                 "(docker CLI missing or daemon not running); fix runs are refused until it is")


def _user():
    getuid = getattr(os, "getuid", None)
    uid = getuid() if getuid else 1000
    gid = os.getgid() if getuid else 1000
    return f"{uid}:{gid}" if uid else "1000:1000"  # never root inside the container


def docker_argv(repo, cmd, network, image=None, name=None):
    """`docker run` for one sandbox step. Only the work dir is mounted (rw); the root filesystem is read-only,
    /tmp is a tmpfs, the process runs as a non-root user with no extra capabilities and bounded memory, CPU
    and process count. network=False (tests, scripts) runs with --network none; only the install step has a
    network."""
    named = ["--name", name, "--label", "patchpilot.sandbox=1"] if name else []
    return ["docker", "run", "--rm", "-i", *named,
            "--network", "bridge" if network else "none",
            "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=512m",
            "--user", _user(), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-e", "HOME=/tmp", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PIP_CACHE_DIR=/tmp/pip-cache",
            "-v", f"{Path(repo).resolve()}:{DOCKER_WORK}:rw", "-w", DOCKER_WORK,
            image or config.sandbox_image(), *cmd]


def docker_run(repo, cmd, network, timeout=600):
    """Run one sandbox step in a named container. On timeout the container itself is force-removed (killing
    the docker CLI alone would leave it running), then TimeoutExpired propagates like a local timeout."""
    name = f"patchpilot-{uuid.uuid4().hex[:12]}"
    try:
        return run(docker_argv(repo, cmd, network, name=name), cwd=repo, timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        raise


def _to_container(arg, repo):
    """Host paths inside the work dir become /work/...; anything else passes through unchanged."""
    try:
        rel = Path(arg).resolve().relative_to(Path(repo).resolve())
    except (ValueError, OSError):
        return arg
    return f"{DOCKER_WORK}/{rel.as_posix()}" if Path(arg).exists() else arg


class Sandbox:
    def __init__(self, repo_dir, log, mode=None):
        self.repo = Path(repo_dir)
        self.venv = self.repo.parent / (self.repo.name + "-venv")
        self.log = log
        self.mode = mode or config.sandbox_mode()
        if self.mode == "docker":
            check_mode()
        self.uv = uv_path() if self.mode == "local" else None
        self._prep = None
        self._prep_result = None

    def _py(self, args, network=False, timeout=600):
        """Run the sandbox interpreter with args: (exit code, output)."""
        if self.mode == "docker":
            args = [_to_container(a, self.repo) for a in args]
            return docker_run(self.repo, [f"{DOCKER_VENV}/bin/python", *args], network, timeout=timeout)
        return run([venv_python(self.venv), *args], cwd=self.repo, timeout=timeout)

    def ensure_venv(self):
        if self.mode == "docker":
            return
        if not self.venv.exists():
            self.log("Creating isolated virtualenv" + (" (uv)" if self.uv else ""))
            cmd = ([self.uv, "venv", "-q", "--python", sys.executable, str(self.venv)] if self.uv
                   else [sys.executable, "-m", "venv", str(self.venv)])
            code, out = run(cmd, cwd=self.repo)
            if code:
                raise RuntimeError(out)

    def install(self):
        if self.mode == "docker":
            self.log(f"Installing requirements.txt in a Docker sandbox ({config.sandbox_image()})")
            script = (f"test -x {DOCKER_VENV}/bin/python || python -m venv {DOCKER_VENV}; "
                      f"{DOCKER_VENV}/bin/python -m pip install -q -r requirements.txt pytest")
            code, out = docker_run(self.repo, ["sh", "-c", script], network=True)
            return code == 0, out[-4000:]
        self.ensure_venv()
        self.log("Installing requirements.txt")
        if self.uv:
            cmd = [self.uv, "pip", "install", "-q", "--python", venv_python(self.venv), "-r", "requirements.txt", "pytest"]
        else:
            cmd = [venv_python(self.venv), "-m", "pip", "install", "-q", "-r", "requirements.txt", "pytest"]
        code, out = run(cmd, cwd=self.repo)
        return code == 0, out[-4000:]

    def prepare(self):
        """Create the venv and install the current pins in a background thread (off the critical path)."""
        def work():
            try:
                self._prep_result = self.install()
            except Exception as e:
                self._prep_result = (False, f"{type(e).__name__}: {e}")
        self._prep = threading.Thread(target=work, daemon=True)
        self._prep.start()

    def wait_ready(self):
        """Join the background prep (or install now if none was started); (ok, output)."""
        if self._prep is None:
            return self.install()
        self._prep.join()
        self._prep = None
        return self._prep_result

    def python(self, script, *args):
        """Run a script with the sandbox interpreter; (ok, stdout+stderr)."""
        code, out = self._py([script, *args], timeout=120)
        return code == 0, out

    def test_cases(self, target):
        """Per-test outcome for one file: {"test_name[param]": True/False}."""
        _, out = self._py(["-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider", "--tb=no", target])
        return {m.group(2): m.group(1) == "PASSED"
                for m in re.finditer(r"^(PASSED|FAILED|ERROR) \S*?::(\S+)", out, re.M)}

    def test(self, target=None):
        code, out = self._py(["-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                              *([target] if target else [])])
        summary = next((l for l in reversed(out.splitlines()) if "passed" in l or "failed" in l or "error" in l),
                       out.strip().splitlines()[-1] if out.strip() else "no output")
        return code == 0, summary.strip("= "), out[-8000:]
