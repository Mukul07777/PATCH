"""Webhook signing and callback URL helpers (written against Werkzeug 2.0)."""
import hashlib
import hmac

from werkzeug.security import safe_str_cmp, generate_password_hash, check_password_hash
from werkzeug.urls import url_quote, url_encode

SECRET = b"whsec_dev"


def sign(body: bytes) -> str:
    return hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def verify(body: bytes, signature: str) -> bool:
    return safe_str_cmp(sign(body), signature)


def callback_url(base: str, event: str, params: dict) -> str:
    return base.rstrip("/") + "/hooks/" + url_quote(event) + "?" + url_encode(params, sort=True)


def hash_api_key(key: str) -> str:
    return generate_password_hash(key)


def check_api_key(stored: str, key: str) -> bool:
    return check_password_hash(stored, key)
