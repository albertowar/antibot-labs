"""
W3 Ch5 ext: the moments a risk-based login needs that the starter store does not give it.

Nothing here decides. The decisions live in defenses/*.py (wired in defenses/ladder.py); this
module builds the moments they decide at and carries their answer out.

  1. The store's memory. At start-up and after every POST /lab/reset, each seeded account's login
     history is loaded into Redis as feature counts (`lab:rba:hist:<uid>`, from rba_world.py), and
     the population snapshot (`GLOBAL`) is frozen in process. A verified login adds to the account's
     own history; the population snapshot never moves during a run (in production a batch job
     rebuilds it), so no score depends on the order traffic arrives in.

  2. `action:login_result`, through contract 1.7's `hooks.on_action("login")`. After the route has
     checked the password, a second ladder phase runs with the outcome in `ctx.attrs["login"]` (ok,
     email, known account, the password that was tried: W2 Ch6's shape, so its finished checks run
     unchanged) and the login's features in `ctx.attrs["rba"]`. If a check asks for a step-up, the
     session is taken back (`uid` deleted) and the answer is the challenge; if it refuses, a 403.
     A failed login is never rewritten: it keeps its 401.

  3. The `otp` challenge: a six-digit code the store "emails" (it lands in /lab/mailbox/<email>),
     bound to the login that asked for it (`pending_uid` in the same session, so a code earned on
     one account can never open another). Entering it opens the session the login would have
     opened.

  4. "Remember this device". Every verified login (no prompt, or a solved code) appends its
     features to the account's history and, if the browser had no `rd` cookie, issues one. The
     cookie is a bearer token: whoever presents it is "the remembered device". Round 2 is about
     what that costs.

  5. The password-reset confirmation as a decision point. `POST /api/password-reset/confirm`
     carries a token, not a login, so an enricher resolves the token to its account and puts the
     confirming request's features in `ctx.attrs["recovery"]` for Round 3's check. When that check
     asks for a cooling-off (`ctx.attrs["recovery_hold_h"]`), the reset is parked instead of applied:
     the customer gets a 202, the account holder a notice on every channel the store knows, and the
     decision log the outcome `held` (counted as a stop, contract 1.7 `hooks.stopped_outcome`).
"""

import hmac
import json
import secrets
from datetime import datetime, timezone

from flask import g, jsonify, make_response, request

from defenses import netinfo
from demo_site import gate, hooks
from demo_site.models import User, db
from demo_site.seed import username

from . import rba_world

RD_COOKIE = "rd"
RD_TTL_S = 400 * 24 * 3600
OTP_TTL_S = 300
OTP_TRIES = 3
LOGIN_PATHS = ("/api/login", "/login")
CONFIRM_PATH = "/api/password-reset/confirm"

GLOBAL = {}         # the frozen population snapshot: "<feature>:<value>" -> count, "_n"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _mail(ctx_or_redis, email, **msg):
    redis = getattr(ctx_or_redis, "redis", ctx_or_redis)
    redis.rpush(f"lab:mailbox:{email.lower()}", json.dumps({**msg, "ts": _now()}))


# --- 1. the store's memory --------------------------------------------------------------------

def _hist_key(uid):
    return f"lab:rba:hist:{uid}"


def seed(app):
    """Load every seeded account's history into Redis and freeze the population snapshot."""
    per, glob = rba_world.seeded_counts()
    GLOBAL.clear()
    GLOBAL.update(glob)
    redis = app.extensions["lab_redis"]
    with app.app_context():
        ids = {u.email: u.id for u in User.query.filter(User.email.in_([username(i) for i in per])).all()}
    pipe = redis.pipeline()
    for idx, counts in per.items():
        uid = ids.get(username(idx))
        if uid is None:
            continue
        pipe.delete(_hist_key(uid))
        pipe.hset(_hist_key(uid), mapping={k: v for k, v in counts.items()})
    pipe.execute()


def history(redis, uid):
    return {k: int(v) for k, v in redis.hgetall(_hist_key(uid)).items()}


def features(ctx):
    """What this request presents, in the model's vocabulary (rba_world.features_of, live)."""
    ua = ctx.ua
    return {"dev": ctx.cookies.get(RD_COOKIE) or "none", "asn": str(ctx.edge.asn), "cc": ctx.edge.country,
            "ua": f"{ua.family}/{ua.major}/{'m' if ua.mobile else 'd'}"}


def _context(ctx, uid):
    return {"uid": uid, "features": features(ctx), "hist": history(ctx.redis, uid), "glob": GLOBAL,
            "net": netinfo.lookup(ctx.ip)["asn_type"]}


# --- 4. remember a verified login -------------------------------------------------------------

def remember(ctx, uid):
    """Append this verified login to the account's history; issue an `rd` cookie if there is none."""
    f = features(ctx)
    if f["dev"] == "none":
        f["dev"] = secrets.token_urlsafe(16)
        g.rba_issue_rd = f["dev"]
    pipe = ctx.redis.pipeline()
    for k, v in f.items():
        pipe.hincrby(_hist_key(uid), f"{k}:{v}", 1)
    pipe.hincrby(_hist_key(uid), "_n", 1)
    pipe.execute()


def _set_rd(info):
    token = getattr(g, "rba_issue_rd", None)
    if token and info.ctx is not None:
        info.response.set_cookie(RD_COOKIE, token, httponly=True, samesite="Lax", max_age=RD_TTL_S)


# --- 2. the second phase of the login ---------------------------------------------------------

def _attempt(ctx):
    body = ctx.json if isinstance(ctx.json, dict) else ctx.form
    return str(body.get("email", "")).strip().lower(), str(body.get("password", ""))


def after_login(ctx, result, response):
    if ctx is None:
        return None
    email, password = _attempt(ctx)
    user, ok = result.get("user"), bool(result.get("ok"))
    ctx.user = user
    ctx.attrs["login"] = {"ok": ok, "email": email, "known": user is not None, "password": password}
    if ok:
        gate.revoke_clearance(ctx, "otp")                # a fresh login always needs a fresh code
        ctx.attrs["rba"] = _context(ctx, user.id)
    d = gate.run_phase("action:login_result", ctx)
    if not ok:
        return None
    if d.action in ("allow", "monitor"):
        remember(ctx, user.id)
        return None
    ctx.session.delete("uid")                            # take the session back
    if d.action == "challenge" and d.challenge == "otp":
        ctx.session.set("pending_uid", str(user.id))
    out = gate.respond(d, ctx)
    return make_response(out) if out is not None else None


# --- 3. the otp challenge ---------------------------------------------------------------------

def _mask(email):
    name, _, host = email.partition("@")
    return f"{name[:1]}***@{host}"


def otp_issue(ctx):
    uid = ctx.session.get("pending_uid")
    user = db.session.get(User, int(uid)) if uid else None
    if user is None:
        return {"channel": None, "message": "no sign-in is waiting for a code"}
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:rba:otp:{ctx.session.sid}", json.dumps({"code": code, "tries": 0}), ex=OTP_TTL_S)
    _mail(ctx, user.email, subject="Your sign-in code", code=code)
    return {"channel": "email", "to": _mask(user.email), "length": 6, "expires_s": OTP_TTL_S}


def otp_verify(ctx, answer):
    key = f"lab:rba:otp:{ctx.session.sid}"
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
    uid = ctx.session.get("pending_uid")
    ctx.session.set("uid", uid)
    ctx.session.delete("pending_uid")
    remember(ctx, int(uid))
    return True


# --- 5. the password reset as a decision point ------------------------------------------------

def _recovery_enricher(ctx):
    if ctx.path != CONFIRM_PATH or ctx.method != "POST" or not isinstance(ctx.json, dict):
        return
    uid = ctx.redis.get(f"lab:reset:{ctx.json.get('token', '')}")
    if uid:
        ctx.attrs["recovery"] = _context(ctx, int(uid))


def hold_reset():
    """Runs after the gate: park a reset the ladder asked to cool off, instead of applying it."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.path != CONFIRM_PATH or not ctx.attrs.get("recovery_hold_h"):
        return None
    hours = int(ctx.attrs["recovery_hold_h"])
    token = str(ctx.json.get("token", ""))
    uid = int(ctx.attrs["recovery"]["uid"])
    user = db.session.get(User, uid)
    ctx.redis.delete(f"lab:reset:{token}")               # the token cannot be replayed to skip the wait
    ctx.redis.set(f"lab:rba:held:{uid}", json.dumps({"requested": _now(), "hours": hours}), ex=hours * 3600)
    notice = (f"A password reset was requested from a device and network this account has not used. "
              f"It completes in {hours} hours unless you cancel it.")
    _mail(ctx, user.email, subject="Password reset waiting", note=notice)
    ctx.redis.rpush(f"lab:rba:notify:{uid}", json.dumps({"note": notice, "ts": _now()}))  # remembered devices
    ctx.note(recovery="held", hold_h=hours)
    g.outcome = "held"
    return jsonify(ok=False, status="held", completes_in_h=hours,
                   message="For your security this reset completes later. We have notified the account holder."), 202


def init(app):
    hooks.on_action("login", after_login)
    hooks.on_response(_set_rd)
    hooks.enricher(_recovery_enricher)
    hooks.stopped_outcome("held")
    hooks.challenges.register("otp", issue=lambda ctx: otp_issue(ctx), verify=lambda ctx, a: otp_verify(ctx, a),
                              clearance_ttl=OTP_TTL_S, uses=1)
    app.before_request(hold_reset)       # registered after the gate's, so it runs after the ladder
    hooks.on_reset(seed)
    seed(app)
