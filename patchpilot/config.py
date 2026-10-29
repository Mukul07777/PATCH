import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "")
NEBIUS_BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1").rstrip("/")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
# Demo fast path: fewer fix attempts, curated proofs/variants only (no LLM exploit or variant generation)
DEMO = os.getenv("PATCHPILOT_DEMO", "") == "1"


def _num(name, default, cast=float):
    try:
        return cast(os.getenv(name, "") or default)
    except ValueError:
        return default


MAX_FIX_ATTEMPTS = _num("MAX_FIX_ATTEMPTS", 4, int)
if DEMO:
    MAX_FIX_ATTEMPTS = min(MAX_FIX_ATTEMPTS, 2)
FIX_TIMEOUT = _num("FIX_TIMEOUT", 90.0)  # seconds per fix call before escalating to Ultra

MODEL_OVERRIDES = {
    "nano": os.getenv("MODEL_NANO", ""),
    "super": os.getenv("MODEL_SUPER", ""),
    "ultra": os.getenv("MODEL_ULTRA", ""),
}


def _price(name):
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        parts = [float(p) for p in raw.split("/")]
    except ValueError:
        return None
    return (parts[0], parts[-1])  # ($/1M input, $/1M output)


PRICES = {"nano": _price("PRICE_NANO"), "super": _price("PRICE_SUPER"), "ultra": _price("PRICE_ULTRA")}

RUNS_DIR = ROOT / "runs"
# Tracked, read-only recorded runs shipped with the repo so fresh clones/deploys have something to replay
DEMO_RUNS_DIR = ROOT / "demo-runs"
WORK_DIR = RUNS_DIR / "work"
CASES_DIR = ROOT / "cases"
# SQLite store for projects, scans, findings and the audit log (JSONL files stay the per-run event log)
DB_PATH = Path(os.getenv("PATCHPILOT_DB", "") or RUNS_DIR / "patchpilot.db")
# Public deployments should keep this off: remote repos run arbitrary test code on the server.
# It gates fix mode only; scan-only mode never executes repo code, so it may read remote manifests regardless.
ALLOW_REMOTE_REPOS = os.getenv("ALLOW_REMOTE_REPOS", "0") == "1"
# Projects that point at a directory on the server's filesystem (self-hosted use only)
ALLOW_LOCAL_PATHS = os.getenv("ALLOW_LOCAL_PATHS", "0") == "1"


def provider_name(base_url=None):
    """Human name of the OpenAI-compatible LLM host (Settings base URL, else NEBIUS_BASE_URL)."""
    host = (base_url or llm_base_url()).split("//")[-1].split("/")[0]
    return {"openrouter.ai": "OpenRouter", "integrate.api.nvidia.com": "NVIDIA NIM",
            "api.groq.com": "Groq"}.get(host, "Token Factory")


# Content-safety gate: AI-written exploit proofs, red-team variants and patch files are screened before they run.
# GUARD=0 disables it. MODEL_GUARD defaults to NVIDIA's Nemotron content-safety model on OpenRouter only
# (other hosts use different ids; set MODEL_GUARD explicitly there). Without a model the static AST screen still runs.
GUARD = os.getenv("GUARD", "1") != "0"
MODEL_GUARD = os.getenv("MODEL_GUARD", "").strip() or (
    "nvidia/nemotron-3.5-content-safety:free" if "openrouter.ai" in NEBIUS_BASE_URL else "")
GUARD_TIMEOUT = _num("GUARD_TIMEOUT", 30.0)


# ---------- live getters: Settings page values (SQLite) first, then the environment ----------
# Call sites use these instead of the module constants so a settings change applies without a restart.
def _stored(key):
    try:
        from . import settings
        return settings.get(key)
    except Exception:  # unreadable DB or key: fall back to the environment
        return None


def llm_api_key():
    return _stored("llm_api_key") or NEBIUS_API_KEY


def llm_base_url():
    return (_stored("llm_base_url") or NEBIUS_BASE_URL).rstrip("/")


def tavily_api_key():
    return _stored("tavily_api_key") or TAVILY_API_KEY


def github_token():
    return _stored("github_token") or GITHUB_TOKEN


def model(tier):
    return _stored(f"model_{tier}") or MODEL_OVERRIDES.get(tier, "")


def model_overrides():
    return {t: model(t) for t in MODEL_OVERRIDES}


def model_guard():
    return _stored("model_guard") or MODEL_GUARD or (
        "nvidia/nemotron-3.5-content-safety:free" if "openrouter.ai" in llm_base_url() else "")


def max_fix_attempts():
    try:
        n = int(_stored("max_fix_attempts") or MAX_FIX_ATTEMPTS)
    except ValueError:
        n = MAX_FIX_ATTEMPTS
    return min(n, 2) if DEMO else n


def allow_remote_repos():
    v = _stored("allow_remote_repos")
    return ALLOW_REMOTE_REPOS if v is None else v == "1"
