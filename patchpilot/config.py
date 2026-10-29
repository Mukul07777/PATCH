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
MAX_FIX_ATTEMPTS = int(os.getenv("MAX_FIX_ATTEMPTS", "4"))
if DEMO:
    MAX_FIX_ATTEMPTS = min(MAX_FIX_ATTEMPTS, 2)
FIX_TIMEOUT = float(os.getenv("FIX_TIMEOUT", "90"))  # seconds per fix call before escalating to Ultra

MODEL_OVERRIDES = {
    "nano": os.getenv("MODEL_NANO", ""),
    "super": os.getenv("MODEL_SUPER", ""),
    "ultra": os.getenv("MODEL_ULTRA", ""),
}


def _price(name):
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    parts = [float(p) for p in raw.split("/")]
    return (parts[0], parts[-1])  # ($/1M input, $/1M output)


PRICES = {"nano": _price("PRICE_NANO"), "super": _price("PRICE_SUPER"), "ultra": _price("PRICE_ULTRA")}

RUNS_DIR = ROOT / "runs"
WORK_DIR = RUNS_DIR / "work"
CASES_DIR = ROOT / "cases"
DEFAULT_CASE = "authsvc"
# Public deployments should keep this off: remote repos run arbitrary test code on the server
ALLOW_REMOTE_REPOS = os.getenv("ALLOW_REMOTE_REPOS", "1") == "1"


def provider_name(base_url=None):
    """Human name of the OpenAI-compatible LLM host behind NEBIUS_BASE_URL."""
    host = (base_url or NEBIUS_BASE_URL).split("//")[-1].split("/")[0]
    return {"openrouter.ai": "OpenRouter", "integrate.api.nvidia.com": "NVIDIA NIM",
            "api.groq.com": "Groq"}.get(host, "Token Factory")
