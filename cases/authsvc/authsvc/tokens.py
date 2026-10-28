"""Session token helpers for the auth service (written against PyJWT 1.x)."""
import datetime

import jwt

SECRET = "dev-secret-change-me"
ALGORITHM = "HS256"


def issue_token(user_id, roles, ttl_minutes=30):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user_id,
        "roles": roles,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ttl_minutes),
    }
    # PyJWT 1.x returns bytes
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM).decode("utf-8")


def verify_token(token):
    return jwt.decode(token, SECRET)


def peek_claims(token):
    """Read claims without verifying the signature (for logging only)."""
    return jwt.decode(token, verify=False)


def has_role(token, role):
    try:
        claims = verify_token(token)
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    return role in claims.get("roles", [])
