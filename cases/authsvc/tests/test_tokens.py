import jwt
import pytest

from authsvc import tokens
from authsvc.client import build_session, directory_url


def test_issue_returns_str():
    t = tokens.issue_token("u1", ["admin"])
    assert isinstance(t, str)
    assert t.count(".") == 2


def test_roundtrip():
    t = tokens.issue_token("u1", ["admin", "dev"])
    claims = tokens.verify_token(t)
    assert claims["sub"] == "u1"
    assert claims["roles"] == ["admin", "dev"]


def test_peek_without_secret():
    t = tokens.issue_token("u2", [])
    assert tokens.peek_claims(t)["sub"] == "u2"


def test_has_role():
    t = tokens.issue_token("u3", ["admin"])
    assert tokens.has_role(t, "admin")
    assert not tokens.has_role(t, "root")


def test_expired_token_rejected():
    t = tokens.issue_token("u4", ["admin"], ttl_minutes=-1)
    assert not tokens.has_role(t, "admin")


def test_tampered_token_rejected():
    t = tokens.issue_token("u5", ["admin"])
    forged = jwt.encode({"sub": "u5", "roles": ["admin"]}, "wrong-key", algorithm="HS256")
    if isinstance(forged, bytes):
        forged = forged.decode()
    assert not tokens.has_role(forged, "admin")


def test_alg_none_rejected():
    import base64, json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64({"sub": "x", "roles": ["admin"]}) + "."
    with pytest.raises(Exception):
        tokens.verify_token(forged)


def test_client_session_has_bearer():
    s = build_session()
    assert s.headers["Authorization"].startswith("Bearer ")


def test_directory_url():
    assert directory_url("https://dir.example.com/", 42) == "https://dir.example.com/users/42"
