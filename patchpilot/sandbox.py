"""Isolated test runner: a fresh virtualenv per run, so the agent's changes are verified for real."""
import os
import re
import subprocess
import sys
from pathlib import Path


def venv_python(venv):
    win = Path(venv) / "Scripts" / "python.exe"
    return str(win if win.exists() else Path(venv) / "bin" / "python")


def run(cmd, cwd, timeout=600):
    env = dict(os.environ, PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


class Sandbox:
    def __init__(self, repo_dir, log):
        self.repo = Path(repo_dir)
        self.venv = self.repo.parent / (self.repo.name + "-venv")
        self.log = log

    def ensure_venv(self):
        if not self.venv.exists():
            self.log("Creating isolated virtualenv")
            code, out = run([sys.executable, "-m", "venv", str(self.venv)], cwd=self.repo)
            if code:
                raise RuntimeError(out)

    def install(self):
        self.ensure_venv()
        self.log("Installing requirements.txt")
        code, out = run([venv_python(self.venv), "-m", "pip", "install", "-q", "-r", "requirements.txt", "pytest"],
                        cwd=self.repo)
        return code == 0, out[-4000:]

    def python(self, script, *args):
        """Run a script with the sandbox interpreter; (ok, stdout+stderr)."""
        code, out = run([venv_python(self.venv), script, *args], cwd=self.repo, timeout=120)
        return code == 0, out

    def test_cases(self, target):
        """Per-test outcome for one file: {"test_name[param]": True/False}."""
        _, out = run([venv_python(self.venv), "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider", "--tb=no", target],
                     cwd=self.repo)
        return {m.group(2): m.group(1) == "PASSED"
                for m in re.finditer(r"^(PASSED|FAILED|ERROR) \S*?::(\S+)", out, re.M)}

    def test(self, target=None):
        code, out = run([venv_python(self.venv), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                         *([target] if target else [])], cwd=self.repo)
        summary = next((l for l in reversed(out.splitlines()) if "passed" in l or "failed" in l or "error" in l),
                       out.strip().splitlines()[-1] if out.strip() else "no output")
        return code == 0, summary.strip("= "), out[-8000:]
