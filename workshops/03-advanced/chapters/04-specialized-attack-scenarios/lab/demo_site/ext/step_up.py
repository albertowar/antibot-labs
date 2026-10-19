"""
W3 Ch4 ext: an emailed-code step-up, for a login that needs proof and for a sign-up that needs an inbox.

The starter's login routes verify the password and open the session in one step, and the gate only runs
a check BEFORE the route (`guard("login")`). Two of this chapter's defenses need more:

  1. `action:login_result` (Round 1). After the route has answered, an after_request hook runs a second
     ladder phase with the outcome in `ctx.attrs["login"]` (ok, email, known account, the password that
     was tried). If a check asks for a challenge, the hook takes the session back (`uid` is deleted from
     the Redis session) and answers with the challenge instead, so a step-up login never leaves a session
     behind. A failed login is never rewritten: it keeps its 401. (The same hook as W2 Ch6's, trimmed.)
  2. The `otp` challenge. The store "emails" a six-digit code (it lands in /lab/mailbox/<email>); entering
     it at POST /api/challenge/verify opens the session a login would have opened, or, for a registration
     (Round 4), clears the session so that the same POST /register goes through on the retry.

Nothing here decides anything. Which login or sign-up earns a code is the defenses' call.
Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import hmac
import json
import secrets
from datetime import datetime, timezone

from flask import g, make_response, request

from demo_site import gate, hooks
from demo_site.models import User, db

LOGIN_PATHS = ("/api/login", "/login")
OTP_TTL_S = 300
OTP_TRIES = 3


def _mail(ctx, email, **msg):
    stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    ctx.redis.rpush(f"lab:mailbox:{email.lower()}", json.dumps({**msg, "ts": stamp}))


def _attempt(ctx):
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return str(body.get("email", "")).strip().lower(), str(body.get("password", ""))


# --- 1. the second phase of the login ---------------------------------------------------------

def after_login(resp):
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or request.path not in LOGIN_PATHS:
        return resp
    result = ctx.notes.get("login")                      # set by the route; absent when the gate refused first
    if result not in ("ok", "fail"):
        return resp
    email, password = _attempt(ctx)
    user = User.query.filter_by(email=email).first()
    ctx.user = user
    ctx.attrs["login"] = {"ok": result == "ok", "email": email, "known": user is not None, "password": password}
    if result == "ok":
        gate.revoke_clearance(ctx, "otp")                # a fresh login always needs a fresh code
    d = gate.run_phase("action:login_result", ctx)
    if result != "ok" or d.action in ("allow", "monitor"):
        return resp
    ctx.session.delete("uid")                            # take the session back
    if d.action == "challenge" and d.challenge == "otp":
        ctx.session.set("pending_uid", str(user.id))
    out = gate.respond(d, ctx)
    return make_response(out) if out is not None else resp


# --- 2. the otp challenge ----------------------------------------------------------------------

def _mask(email):
    name, _, host = email.partition("@")
    return f"{name[:1]}***@{host}"


def otp_issue(ctx):
    uid = ctx.session.get("pending_uid")
    user = db.session.get(User, int(uid)) if uid else None
    email = user.email if user else str(ctx.notes.get("email", ""))
    if not email:
        return {"channel": None, "message": "nothing is waiting for a code"}
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:otp:{ctx.session.sid}", json.dumps({"code": code, "tries": 0}), ex=OTP_TTL_S)
    _mail(ctx, email, subject="Your Kestrel code", code=code)
    return {"channel": "email", "to": _mask(email), "length": 6, "expires_s": OTP_TTL_S}


def otp_verify(ctx, answer):
    key = f"lab:otp:{ctx.session.sid}"
    raw = ctx.redis.get(key)
    if not raw:
        return False, "no code is pending, or it expired"
    state = json.loads(raw)
    state["tries"] += 1
    if state["tries"] > OTP_TRIES:
        ctx.redis.delete(key)
        return False, "too many wrong codes: start again"
    if not hmac.compare_digest(str((answer or {}).get("code", "")), state["code"]):
        ctx.redis.set(key, json.dumps(state), ex=OTP_TTL_S)
        return False, "wrong code"
    ctx.redis.delete(key)
    pending = ctx.session.get("pending_uid")
    if pending:                                          # a login: now the session exists
        ctx.session.set("uid", pending)
        ctx.session.delete("pending_uid")
    return True


def init(app):
    app.after_request(after_login)       # registered after the gate's, so it runs BEFORE the gate stamps the response
    hooks.challenges.register("otp", issue=lambda ctx: otp_issue(ctx), verify=lambda ctx, a: otp_verify(ctx, a),
                              clearance_ttl=OTP_TTL_S, uses=1)
