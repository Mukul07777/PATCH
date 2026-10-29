"""Admin-side API routes: per-project policy, dashboard, accounts, API keys, audit log, settings and
notification channels. Mounted onto the app by server.py; shared helpers (auth, rate limits, audit) live there."""
import time

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from patchpilot.app import auth, db, notify, settings
from patchpilot.core import config
from patchpilot.app import server as S
from patchpilot.app.server import (CSRF_HEADER, CSRF_VALUE, _audit, _project_or_404, principal, _ip, _limit, _need, _public_demo, _rate_wait, _reader,
                     _sample_ids, _visible)

router = APIRouter()


# ---------- per-project policy ----------
class PolicyRequest(BaseModel):
    severity_threshold: str = Field("low", pattern="^(low|moderate|high|critical)$")
    auto_fix: bool = False  # start a fix run when a scan finds new fixable findings (if fix mode can run)
    schedule: str | None = Field(None, pattern="^(off|daily|weekly)$")  # None keeps the stored schedule
    schedule_hour: int | None = Field(None, ge=0, le=23)  # UTC
    channels: list[int] | None = Field(None, max_length=100)  # None = every notification channel


class IgnoreRequest(BaseModel):
    vuln_id: str = Field(..., min_length=3, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    reason: str = Field(..., min_length=3, max_length=300)
    expires_at: float | None = Field(None, gt=0)


@router.get("/api/projects/{pid}/policy")
def get_policy(pid: int, request: Request):
    _visible(request, pid)
    return db.get_policy(pid)


@router.put("/api/projects/{pid}/policy")
def put_policy(pid: int, req: PolicyRequest, request: Request):
    user = _need(request)
    _project_or_404(pid)
    chans = req.channels if "channels" in req.model_fields_set else False
    if chans:
        known = {c["id"] for c in db.list_channels()}
        if any(c not in known for c in chans):
            raise HTTPException(422, "channels: unknown notification channel id")
    db.set_policy(pid, req.severity_threshold, req.auto_fix, user["label"], schedule=req.schedule,
                  schedule_hour=req.schedule_hour, channels=chans)
    pol = db.get_policy(pid)
    _audit(request, "policy.update", {"project_id": pid, "severity_threshold": req.severity_threshold,
                                      "auto_fix": req.auto_fix, "schedule": pol["schedule"],
                                      "schedule_hour": pol["schedule_hour"], "channels": pol["channels"]})
    return pol


@router.post("/api/projects/{pid}/ignores", status_code=201)
def add_ignore(pid: int, req: IgnoreRequest, request: Request):
    user = _need(request)
    _project_or_404(pid)
    if req.expires_at is not None and req.expires_at <= time.time():
        raise HTTPException(422, "expires_at must be in the future")
    iid = db.add_ignore(pid, req.vuln_id, req.reason.strip(), req.expires_at, user["label"])
    _audit(request, "finding.ignore", {"project_id": pid, "ignore_id": iid, "vuln_id": req.vuln_id,
                                       "reason": req.reason.strip(), "expires_at": req.expires_at})
    return db.get_policy(pid)


@router.delete("/api/projects/{pid}/ignores/{iid}")
def delete_ignore(pid: int, iid: int, request: Request):
    _need(request)
    if not db.delete_ignore(pid, iid):
        raise HTTPException(404, "Unknown ignore entry")
    _audit(request, "finding.unignore", {"project_id": pid, "ignore_id": iid})
    return db.get_policy(pid)


# ---------- dashboard ----------
@router.get("/api/dashboard")
def dashboard(request: Request):
    user = _reader(request)
    return db.dashboard(None if user else _sample_ids())


# ---------- accounts ----------
class SetupRequest(BaseModel):
    email: str = Field(..., max_length=200)
    name: str = Field("", max_length=100)
    password: str = Field(..., max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=200)
    password: str = Field(..., max_length=200)


class UserRequest(SetupRequest):
    role: str = Field("member", pattern="^(admin|member)$")


class RoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|member)$")


class PasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=200)
    new_password: str = Field(..., max_length=200)


class ResetRequest(BaseModel):
    password: str = Field(..., max_length=200)


class KeyRequest(BaseModel):
    name: str = Field(..., max_length=80)
    role: str = Field("member", pattern="^(admin|member)$")


def _csrf(request):
    """Login and setup set a cookie, so they need the same custom header as cookie writes (no login CSRF)."""
    if request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
        raise HTTPException(403, "Missing X-Requested-With: patchpilot header")


def _signed_in(request, uid):
    token = auth.create_session(uid)
    resp = JSONResponse({"user": auth.get_user(uid)})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"
    resp.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="lax",
                    secure=https, path="/")
    return resp


@router.get("/api/auth/state")
def auth_state(request: Request):
    user = principal(request)
    return {"setup_needed": auth.user_count() == 0, "public_demo": _public_demo(),
            "user": {k: user[k] for k in ("id", "email", "name", "role", "via")} if user else None}


@router.post("/api/auth/setup")
def auth_setup(req: SetupRequest, request: Request):
    _csrf(request)
    try:
        uid = auth.setup_admin(req.email, req.name, req.password)
    except auth.AuthError as e:
        raise HTTPException(409 if "already" in str(e) else 422, str(e))
    db.audit(req.email.strip(), "auth.setup", {"user_id": uid, "ip": _ip(request)})
    return _signed_in(request, uid)


@router.post("/api/auth/login")
def auth_login(req: LoginRequest, request: Request):
    """Only failed attempts count: per (IP, email) and, looser, per IP. A successful sign-in clears its
    (IP, email) counter, so a user who mistyped once is not locked out by the people sharing their NAT."""
    _csrf(request)
    ip, email = _ip(request), req.email.strip().lower()[:200]
    acct, per_ip = f"loginfail:{ip}:{email}", f"loginfail:{ip}"
    wait = max(S._blocked_for(acct, S.LOGIN_FAILS_PER_ACCOUNT), S._blocked_for(per_ip, S.LOGIN_FAILS_PER_IP))
    if wait:
        raise HTTPException(429, "Too many failed sign-in attempts; try again in a minute",
                            headers={"Retry-After": str(wait)})
    user = auth.authenticate(req.email, req.password)
    if user is None:
        _rate_wait(acct, limit=S.LOGIN_FAILS_PER_ACCOUNT + 1)
        _rate_wait(per_ip, limit=S.LOGIN_FAILS_PER_IP + 1)
        db.audit(req.email.strip()[:200], "auth.login_failed", {"ip": ip})
        raise HTTPException(401, "Wrong email or password")
    with S._lock:
        S._hits.pop(acct, None)
    db.audit(user["email"], "auth.login", {"ip": ip})
    return _signed_in(request, user["id"])


@router.post("/api/auth/logout", status_code=204)
def auth_logout(request: Request):
    _csrf(request)
    auth.end_session(request.cookies.get(auth.SESSION_COOKIE))
    resp = Response(status_code=204)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@router.post("/api/auth/password")
def change_password(req: PasswordRequest, request: Request):
    """Change your own password (the current one is required); every other session of yours is signed out."""
    me = _need(request)
    if me["id"] is None:
        raise HTTPException(400, "The legacy token has no account password")
    _limit("login:" + _ip(request), "Too many attempts; try again in a minute")
    if auth.authenticate(me["email"], req.current_password) is None:
        raise HTTPException(403, "Current password is wrong")
    try:
        auth.set_password(me["id"], req.new_password)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    ended = auth.end_user_sessions(me["id"], keep=request.cookies.get(auth.SESSION_COOKIE))
    _audit(request, "auth.password_change", {"user_id": me["id"], "other_sessions_ended": ended})
    return {"ok": True, "other_sessions_ended": ended}


@router.post("/api/auth/logout-all", status_code=204)
def logout_all(request: Request):
    """Sign out every session of the current user, this one included."""
    me = _need(request)
    if me["id"] is None:
        raise HTTPException(400, "The legacy token has no sessions")
    ended = auth.end_user_sessions(me["id"])
    _audit(request, "auth.logout_all", {"user_id": me["id"], "sessions_ended": ended})
    resp = Response(status_code=204)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@router.get("/api/users")
def list_users(request: Request):
    _need(request, "admin")
    return auth.list_users()


@router.post("/api/users", status_code=201)
def create_user(req: UserRequest, request: Request):
    _need(request, "admin")
    try:
        uid = auth.create_user(req.email, req.name, req.password, req.role)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    _audit(request, "user.create", {"user_id": uid, "email": req.email.strip(), "role": req.role})
    return auth.get_user(uid)


def _other_user(request, uid):
    me = _need(request, "admin")
    target = auth.get_user(uid)
    if target is None:
        raise HTTPException(404, "Unknown user")
    if me["id"] == uid:
        raise HTTPException(400, "You cannot change or delete your own account here")
    return target


@router.put("/api/users/{uid}/role")
def set_user_role(uid: int, req: RoleRequest, request: Request):
    target = _other_user(request, uid)
    if target["role"] == "admin" and req.role != "admin" and auth.admin_count() <= 1:
        raise HTTPException(400, "Keep at least one admin")
    auth.set_role(uid, req.role)
    _audit(request, "user.role", {"user_id": uid, "email": target["email"], "role": req.role})
    return auth.get_user(uid)


@router.post("/api/users/{uid}/password")
def reset_user_password(uid: int, req: ResetRequest, request: Request):
    """Admin: set a new password for another user and sign out all of their sessions."""
    target = _other_user(request, uid)
    try:
        auth.set_password(uid, req.password)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    ended = auth.end_user_sessions(uid)
    _audit(request, "user.password_reset", {"user_id": uid, "email": target["email"], "sessions_ended": ended})
    return {"ok": True, "sessions_ended": ended}


@router.delete("/api/users/{uid}", status_code=204)
def delete_user(uid: int, request: Request):
    target = _other_user(request, uid)
    if target["role"] == "admin" and auth.admin_count() <= 1:
        raise HTTPException(400, "Keep at least one admin")
    auth.delete_user(uid)
    _audit(request, "user.delete", {"user_id": uid, "email": target["email"]})


@router.get("/api/keys")
def list_keys(request: Request):
    _need(request, "admin")
    return auth.list_keys()


@router.post("/api/keys", status_code=201)
def create_key(req: KeyRequest, request: Request):
    me = _need(request, "admin")
    if me["id"] is None:
        raise HTTPException(400, "Sign in as a user to create API keys (the legacy token has no account)")
    try:
        kid, key = auth.create_key(me["id"], req.name, req.role)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    _audit(request, "apikey.create", {"key_id": kid, "name": req.name.strip(), "role": req.role, "prefix": key[:10]})
    return {"id": kid, "key": key, "prefix": key[:10], "name": req.name.strip(), "role": req.role}


@router.delete("/api/keys/{kid}", status_code=204)
def delete_key(kid: int, request: Request):
    _need(request, "admin")
    if not auth.delete_key(kid):
        raise HTTPException(404, "Unknown API key")
    _audit(request, "apikey.delete", {"key_id": kid})


@router.get("/api/audit")
def audit_log(request: Request, page: int = Query(1, ge=1, le=10_000), per_page: int = Query(50, ge=1, le=200)):
    _need(request, "admin")
    return db.audit_page(page, per_page)


# ---------- settings ----------
@router.get("/api/settings")
def get_settings(request: Request):
    _need(request, "admin")
    return settings.public()


@router.put("/api/settings")
async def put_settings(request: Request):
    me = _need(request, "admin")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(422, "Body must be a JSON object")
    if not isinstance(body, dict):
        raise HTTPException(422, "Body must be a JSON object")
    try:
        changed = settings.update(body, me["label"])
    except settings.SettingsError as e:
        raise HTTPException(422, str(e))
    _audit(request, "settings.update", {"keys": changed})  # key names only, never values
    return settings.public()


def _probe(fn):
    """Run a connection test; report ok or a short error, never response bodies (they may echo secrets)."""
    try:
        r = fn()
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"Could not connect ({type(e).__name__})"}
    if 200 <= r.status_code < 300:
        return {"ok": True, "error": None}
    return {"ok": False, "error": {401: "Rejected: invalid key (HTTP 401)", 403: "Forbidden (HTTP 403)"}.get(
        r.status_code, f"HTTP {r.status_code}")}


@router.post("/api/settings/test/{service}")
def test_connection(service: str, request: Request):
    _need(request, "admin")
    _limit("probe:" + _ip(request), "Too many tests; try again in a minute")
    with httpx.Client(timeout=15) as http:
        if service == "llm":
            if not config.llm_api_key():
                return {"ok": False, "error": "No LLM API key set"}
            result = _probe(lambda: http.get(config.llm_base_url() + "/models",
                                             headers={"Authorization": f"Bearer {config.llm_api_key()}"}))
        elif service == "tavily":
            if not config.tavily_api_key():
                return {"ok": False, "error": "No Tavily API key set"}
            result = _probe(lambda: http.post("https://api.tavily.com/search", json={
                "api_key": config.tavily_api_key(), "query": "OSV", "max_results": 1}))
        elif service == "github":
            if not config.github_token():
                return {"ok": False, "error": "No GitHub token set"}
            result = _probe(lambda: http.get("https://api.github.com/user", headers={
                "Authorization": f"Bearer {config.github_token()}", "Accept": "application/vnd.github+json"}))
        else:
            raise HTTPException(404, "Unknown service")
    _audit(request, "settings.test", {"service": service, "ok": result["ok"]})
    return result


# ---------- notification channels ----------
class ChannelRequest(BaseModel):
    type: str = Field(..., pattern="^(slack|webhook|email)$")
    name: str = Field(..., max_length=80)
    config: dict = Field(default_factory=dict)  # slack {url}; webhook {url, secret?}; email {to: [..] or "a, b"}
    events: list[str] = Field(..., max_length=len(notify.EVENTS))
    min_severity: str = Field("low", pattern="^(low|moderate|high|critical)$")
    enabled: bool = True


@router.get("/api/channels")
def list_channels(request: Request):
    """Admins see each channel's (masked) config; members only what they need to opt projects in or out."""
    user = _need(request)
    rows = db.list_channels()
    if user["role"] != "admin":
        return [{k: c[k] for k in ("id", "type", "name", "events", "enabled")} for c in rows]
    return [notify.public(c) for c in rows]


def _save_channel(request, cid, req):
    _need(request, "admin")
    try:
        cid = notify.save(cid, req.type, req.name, req.config, req.events, req.min_severity, req.enabled)
    except notify.ChannelError as e:
        raise HTTPException(422, str(e))
    except LookupError:
        raise HTTPException(404, "Unknown channel")
    return cid


@router.post("/api/channels", status_code=201)
def create_channel(req: ChannelRequest, request: Request):
    cid = _save_channel(request, None, req)
    _audit(request, "channel.create", {"channel_id": cid, "type": req.type, "name": req.name.strip(),
                                       "events": sorted(req.events)})
    row = notify.public(db.get_channel(cid))
    if req.type == "webhook":  # the signing secret is shown once, when it is set (generated if left blank)
        row["secret"] = notify.config_of(db.get_channel(cid)).get("secret")
    return row


@router.put("/api/channels/{cid}")
def update_channel(cid: int, req: ChannelRequest, request: Request):
    _save_channel(request, cid, req)
    _audit(request, "channel.update", {"channel_id": cid, "type": req.type, "name": req.name.strip(),
                                       "events": sorted(req.events), "enabled": req.enabled})
    return notify.public(db.get_channel(cid))


@router.delete("/api/channels/{cid}", status_code=204)
def delete_channel(cid: int, request: Request):
    _need(request, "admin")
    if not db.delete_channel(cid):
        raise HTTPException(404, "Unknown channel")
    _audit(request, "channel.delete", {"channel_id": cid})


@router.post("/api/channels/{cid}/test")
def test_channel(cid: int, request: Request):
    _need(request, "admin")
    _limit("probe:" + _ip(request), "Too many tests; try again in a minute")
    row = db.get_channel(cid)
    if row is None:
        raise HTTPException(404, "Unknown channel")
    status = notify.send_test(row)
    last = db.list_deliveries(cid, 1)
    _audit(request, "channel.test", {"channel_id": cid, "status": status})
    return {"ok": status == "ok", "status": status, "delivery": last[0] if last else None}


@router.get("/api/deliveries")
def list_deliveries(request: Request, channel: int | None = Query(None, ge=1),
                    limit: int = Query(50, ge=1, le=200)):
    _need(request, "admin")
    return db.list_deliveries(channel, limit)
