"""Local accounts: scrypt password hashes, cookie sessions and hashed API keys (all in SQLite).

Session tokens and API keys are random secrets; only their SHA-256 is stored, so a leaked database does not
yield usable credentials. Roles: admin (settings, users, API keys) and member (projects, scans, fix runs).
"""
import hashlib
import hmac
import secrets
import threading
import time

from . import db

ROLES = ("admin", "member")
SESSION_TTL = 7 * 86400
SESSION_COOKIE = "pp_session"
KEY_PREFIX = "pp_"
_N, _R, _P = 2 ** 14, 8, 1
_setup_lock = threading.Lock()


class AuthError(ValueError):
    pass


def hash_password(password):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${h.hex()}"


def verify_password(password, stored):
    try:
        algo, n, r, p, salt, want = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want) // 2)
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(got.hex(), want)


def _sha(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _public(u):
    return {k: u[k] for k in ("id", "email", "name", "role", "created_at")} if u else None


def _check_password(password):
    if not isinstance(password, str) or not 10 <= len(password) <= 200:
        raise AuthError("Password must be 10 to 200 characters")


# ---------- users ----------
def user_count():
    return db._q("SELECT COUNT(*) AS n FROM users")[0]["n"]


def list_users():
    return [_public(u) for u in db._q("SELECT * FROM users ORDER BY id")]


def get_user(uid):
    rows = db._q("SELECT * FROM users WHERE id = ?", (uid,))
    return _public(rows[0]) if rows else None


def create_user(email, name, password, role="member"):
    email = (email or "").strip()
    if role not in ROLES:
        raise AuthError("role must be admin or member")
    if not (3 <= len(email) <= 200 and "@" in email and not any(c.isspace() for c in email)):
        raise AuthError("Enter a valid email address")
    _check_password(password)
    if db._q("SELECT 1 FROM users WHERE email = ?", (email,)):
        raise AuthError("A user with that email already exists")
    return db._x("INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                 (email, (name or "").strip()[:100] or None, hash_password(password), role, time.time()))


def setup_admin(email, name, password):
    """Create the first admin. Only allowed while there are no users at all (serialised, so it happens once)."""
    with _setup_lock:
        if user_count():
            raise AuthError("Setup is already complete")
        return create_user(email, name, password, "admin")


def authenticate(email, password):
    rows = db._q("SELECT * FROM users WHERE email = ?", ((email or "").strip(),))
    if not rows:
        verify_password(password or "", hash_password("timing-equaliser"))  # same cost for unknown emails
        return None
    return _public(rows[0]) if verify_password(password or "", rows[0]["password_hash"]) else None


def admin_count():
    return db._q("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")[0]["n"]


def delete_user(uid):
    return db._x("DELETE FROM users WHERE id = ?", (uid,))


def set_role(uid, role):
    if role not in ROLES:
        raise AuthError("role must be admin or member")
    db._x("UPDATE users SET role = ? WHERE id = ?", (role, uid))


# ---------- sessions ----------
def create_session(uid, now=None):
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(32)
    db._x("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    db._x("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
          (_sha(token), uid, now, now + SESSION_TTL))
    return token


def session_user(token, now=None):
    if not token:
        return None
    now = time.time() if now is None else now
    rows = db._q("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? "
                 "AND s.expires_at > ?", (_sha(token), now))
    return _public(rows[0]) if rows else None


def end_session(token):
    if token:
        db._x("DELETE FROM sessions WHERE token_hash = ?", (_sha(token),))


# ---------- API keys ----------
def create_key(uid, name, role):
    if role not in ROLES:
        raise AuthError("role must be admin or member")
    name = (name or "").strip()
    if not 1 <= len(name) <= 80:
        raise AuthError("Give the key a name (up to 80 characters)")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    kid = db._x("INSERT INTO api_keys (user_id, name, prefix, key_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, name, key[:10], _sha(key), role, time.time()))
    return kid, key


def list_keys():
    return db._q("SELECT k.id, k.name, k.prefix, k.role, k.created_at, k.last_used, u.email AS owner "
                 "FROM api_keys k JOIN users u ON u.id = k.user_id ORDER BY k.id DESC")


def delete_key(kid):
    with db._lock:
        return db._connect().execute("DELETE FROM api_keys WHERE id = ?", (kid,)).rowcount > 0


def key_user(key):
    """(user, key row) for a valid API key; the effective role is the lower of the key's and its owner's."""
    if not key or not key.startswith(KEY_PREFIX):
        return None
    rows = db._q("SELECT k.id AS kid, k.prefix, k.role AS key_role, u.* FROM api_keys k JOIN users u "
                 "ON u.id = k.user_id WHERE k.key_hash = ?", (_sha(key),))
    if not rows:
        return None
    r = rows[0]
    db._x("UPDATE api_keys SET last_used = ? WHERE id = ?", (time.time(), r["kid"]))
    user = _public(r)
    user["role"] = "admin" if r["key_role"] == "admin" and r["role"] == "admin" else "member"
    return user, r["prefix"]
