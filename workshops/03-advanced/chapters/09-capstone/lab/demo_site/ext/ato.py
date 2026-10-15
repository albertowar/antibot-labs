"""
W2 Ch6 ext: what the account-takeover defenses need that the starter store does not give them.

The starter's login routes (`POST /api/login`, `POST /login`) verify the password and open the
session in one step, and the gate only runs a check BEFORE the route (`guard("login")`). A login
defense needs three more moments, and this module adds them without touching a starter file:

  1. `action:login_result`. After the route has answered, an after_request hook runs a second
     ladder phase with the outcome in `ctx.attrs["login"]` (ok, email, known account, the
     password that was tried). Counters (failures per account and per cohort) update there, and
     so do the checks that only make sense once the password is right (breached-password screen,
     device and network risk). If such a check asks for a challenge, the hook takes the session
     back (`uid` is deleted from the Redis session) and answers with the challenge instead, so a
     step-up login never leaves a session behind. A failed login is never rewritten: it keeps
     its 401.
  2. The `otp` challenge: a six-digit code the store "emails" (it lands in /lab/mailbox/<email>).
     Entering it at POST /api/challenge/verify opens the session the login would have opened.
  3. Two routes the chapter needs: `POST /api/account/recover` (a legacy endpoint that answers
     differently for real and unknown addresses: Round 2's oracle, closed at Round 3) and
     `POST /api/account/email` (a sensitive change, gated by `action:change_email`; Round 4).

Nothing here is a defense. The decisions live in defenses/*.py; this file only builds the moments
they decide at.
"""

import json
import secrets
import hmac
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, make_response, request

from demo_site import gate, hooks
from demo_site.models import User, db
from demo_site.routes import api_error, current_user, guard
from demo_site.seed import check_password

LOGIN_PATHS = ("/api/login", "/login")
OTP_TTL_S = 300
OTP_TRIES = 3


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _mail(ctx, email, **msg):
    ctx.redis.rpush(f"lab:mailbox:{email.lower()}", json.dumps({**msg, "ts": _now()}))


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
    if user is None:
        return {"channel": None, "message": "no sign-in is waiting for a code"}
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:otp:{ctx.session.sid}", json.dumps({"code": code, "tries": 0}), ex=OTP_TTL_S)
    _mail(ctx, user.email, subject="Your sign-in code", code=code)
    return {"channel": "email", "to": _mask(user.email), "length": 6, "expires_s": OTP_TTL_S}


def otp_verify(ctx, answer):
    key = f"lab:otp:{ctx.session.sid}"
    raw = ctx.redis.get(key)
    if not raw:
        return False, "no code is pending, or it expired"
    state = json.loads(raw)
    state["tries"] += 1
    if state["tries"] > OTP_TRIES:
        ctx.redis.delete(key)
        return False, "too many wrong codes: sign in again"
    if not hmac.compare_digest(str((answer or {}).get("code", "")), state["code"]):
        ctx.redis.set(key, json.dumps(state), ex=OTP_TTL_S)
        return False, "wrong code"
    ctx.redis.delete(key)
    ctx.session.set("uid", ctx.session.get("pending_uid"))
    ctx.session.delete("pending_uid")
    return True


def reauth_issue(ctx):
    return {"need": "your current password", "send": "password in the request body, or answer {password}"}


def reauth_verify(ctx, answer):
    user = ctx.user
    ok = user is not None and check_password(user, str((answer or {}).get("password", "")), current_app.config["LAB"].hash_iters)
    return (True, "") if ok else (False, "wrong password")


# --- 3. the routes ---------------------------------------------------------------------------

bp = Blueprint("ato", __name__, url_prefix="/api/account")


@bp.route("/recover", methods=["POST"])
def recover():
    """Legacy account recovery. Below Round 3 it tells you whether the address has an account."""
    body = request.get_json(silent=True) or request.form
    email = str(body.get("email", "")).strip().lower()
    r = guard("recover", email=email)
    if r:
        return r
    user = User.query.filter_by(email=email).first()
    if user:
        _mail(g.ctx, email, subject="Recover your account", note="a recovery link would be here")
    if g.ctx.attrs.get("uniform_recover"):
        return jsonify(ok=True, message="If that address exists, a recovery email is on its way.")
    if user:
        return jsonify(ok=True, message="Recovery link sent.")
    return api_error("no_account", "No account with that email.", 404)


@bp.route("/email", methods=["POST"])
def change_email():
    """A sensitive change. The route only checks the proof; whether to demand one is the defense's call."""
    user = current_user()
    if not user:
        return api_error("unauthenticated", "Log in first.", 401)
    body = request.get_json(silent=True) or {}
    pw = str(body.get("password", ""))
    g.ctx.attrs["reauth"] = {"password_ok": bool(pw) and check_password(user, pw, current_app.config["LAB"].hash_iters)}
    r = guard("change_email")
    if r:
        return r
    user.extra = {**(user.extra or {}), "email_change_requested": str(body.get("new_email", ""))[:120]}
    db.session.commit()
    g.ctx.note(sensitive="email_change_accepted")
    return jsonify(ok=True, pending_email=user.extra["email_change_requested"])


def init(app):
    app.after_request(after_login)       # registered after the gate's, so it runs BEFORE the gate stamps the response
    hooks.challenges.register("otp", issue=lambda ctx: otp_issue(ctx), verify=lambda ctx, a: otp_verify(ctx, a),
                              clearance_ttl=OTP_TTL_S, uses=1)
    hooks.challenges.register("reauth", issue=lambda ctx: reauth_issue(ctx), verify=lambda ctx, a: reauth_verify(ctx, a),
                              clearance_ttl=60, uses=1)
    app.register_blueprint(bp)
