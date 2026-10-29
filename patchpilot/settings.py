"""Runtime settings stored in SQLite, editable from the Settings page; secrets are Fernet-encrypted at rest.

The encryption key comes from PATCHPILOT_SECRET_KEY. Without it a random key is generated once into
secret.key next to the database (runs/secret.key by default) with owner-only permissions, and a warning is
logged: anyone who can read that file and the database can read the stored secrets.
Secret values never leave the server: the API only reports whether one is set and its last four characters.
"""
import base64
import hashlib
import logging
import os
import re
import threading

from cryptography.fernet import Fernet, InvalidToken

from . import config, db

log = logging.getLogger(__name__)

SECRETS = ("llm_api_key", "tavily_api_key", "github_token")
PLAIN = ("llm_base_url", "model_nano", "model_super", "model_ultra", "model_guard", "max_fix_attempts",
         "allow_remote_repos")
KEYS = SECRETS + PLAIN
MODEL = re.compile(r"[\w./:@+-]{1,200}")

_fernet = {}  # key source -> Fernet
_lock = threading.Lock()


class SettingsError(ValueError):
    pass


def _key_file():
    return config.DB_PATH.parent / "secret.key"


def _cipher():
    env = os.getenv("PATCHPILOT_SECRET_KEY", "").strip()
    src = "env:" + env if env else "file:" + str(_key_file())
    with _lock:
        if src in _fernet:
            return _fernet[src]
        if env:
            try:
                f = Fernet(env.encode())
            except (ValueError, TypeError):  # any passphrase works: derive a Fernet key from it
                f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(env.encode()).digest()))
        else:
            path = _key_file()
            if not path.is_file():
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(Fernet.generate_key())
                log.warning("PATCHPILOT_SECRET_KEY is not set: generated %s to encrypt stored secrets. "
                            "Set PATCHPILOT_SECRET_KEY in production and keep it out of backups of the database.", path)
            f = Fernet(path.read_bytes().strip())
        _fernet[src] = f
        return f


def get(key):
    """Stored value (decrypted) or None when unset or unreadable."""
    row = db.get_setting(key)
    if row is None:
        return None
    if not row["secret"]:
        return row["value"]
    try:
        return _cipher().decrypt(row["value"].encode()).decode()
    except InvalidToken:
        log.warning("stored setting %s cannot be decrypted with the current PATCHPILOT_SECRET_KEY", key)
        return None


def _clean(key, value):
    value = value.strip() if isinstance(value, str) else value
    if key in SECRETS:
        if not isinstance(value, str) or len(value) > 500 or any(c.isspace() for c in value):
            raise SettingsError(f"{key} must be a single token")
        return value
    if key == "llm_base_url":
        if not isinstance(value, str) or len(value) > 300 or not re.fullmatch(r"https?://[^\s]+", value):
            raise SettingsError("llm_base_url must be an http(s) URL")
        return value.rstrip("/")
    if key.startswith("model_"):
        if not isinstance(value, str) or not MODEL.fullmatch(value):
            raise SettingsError(f"{key} must be a model id")
        return value
    if key == "max_fix_attempts":
        try:
            n = int(value)
        except (TypeError, ValueError):
            raise SettingsError("max_fix_attempts must be a whole number") from None
        if not 1 <= n <= 10:
            raise SettingsError("max_fix_attempts must be between 1 and 10")
        return str(n)
    if key == "allow_remote_repos":
        if value not in (True, False, "1", "0", "true", "false"):
            raise SettingsError("allow_remote_repos must be true or false")
        return "1" if value in (True, "1", "true") else "0"
    raise SettingsError(f"Unknown setting {key}")


def update(changes, actor):
    """Apply {key: value}; None or "" clears the stored value (falling back to the environment).

    Validates everything before writing anything. Returns the list of changed keys (for the audit log).
    """
    unknown = [k for k in changes if k not in KEYS]
    if unknown:
        raise SettingsError(f"Unknown setting {unknown[0]}")
    plan = {k: (None if v is None or v == "" else _clean(k, v)) for k, v in changes.items()}
    for k, v in plan.items():
        if v is None:
            db.delete_setting(k)
        elif k in SECRETS:
            db.set_setting(k, _cipher().encrypt(v.encode()).decode(), True, actor)
        else:
            db.set_setting(k, v, False, actor)
    return sorted(plan)


def _effective(key):
    return {"llm_api_key": config.llm_api_key, "tavily_api_key": config.tavily_api_key,
            "github_token": config.github_token, "llm_base_url": config.llm_base_url,
            "model_nano": lambda: config.model("nano"), "model_super": lambda: config.model("super"),
            "model_ultra": lambda: config.model("ultra"), "model_guard": config.model_guard,
            "max_fix_attempts": config.max_fix_attempts, "allow_remote_repos": config.allow_remote_repos}[key]()


def public():
    """What the Settings page shows: effective values, where they come from, and never a secret's value."""
    out = {}
    for k in KEYS:
        stored = db.get_setting(k) is not None
        val = _effective(k)
        source = "settings" if stored else ("env" if val not in (None, "") else None)
        if k in SECRETS:
            out[k] = {"set": bool(val), "last4": val[-4:] if val and len(val) >= 8 else None, "source": source}
        else:
            out[k] = {"value": val if val != "" else None, "source": source}
    return out
