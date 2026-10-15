"""
The login's collector, the two rungs of the response ladder, and the shape of a refusal. This is
the surface the sign-in stack puts on the login form (the same shape as W2 Ch8's multi-layer
defense, written here on the W3 starter; no starter file is edited). What this module adds:

    form:login slot       risk/collector.html: a hidden honeypot field and static/js/risk.js. The
                          script collects a fingerprint and a short behaviour trace, posts it to
                          POST /api/telemetry as kind "risk", then signs in through POST /api/login
                          and completes whatever challenge comes back (solve the proof of work, or
                          read the emailed code from /lab/mailbox/<email> and type it).
    telemetry "risk"      the blob the layers read (ctx.telemetry("risk"), defenses/features.py)
    challenge "pow"       hashcash, as in W1 Ch7: find n so that sha256(prefix:n) has POW_BITS
                          leading zero bits. Real browsers solve it in well under a second; a bot
                          pays the same CPU, which is nothing for one login and real money for
                          millions. It stops lazy bots and only slows determined ones.
    challenge "step_up"   a one-time code emailed to the account (it lands in the lab mailbox). A
                          credential stuffer does not own the victims' mailboxes, so it cannot
                          pass. The payload is the same whether or not the account exists, so the
                          step-up itself does not confirm valid usernames.
    after_request         a block is DECEPTIVE: gate.respond() lets the route run (g.deceive), and
                          this hook turns whatever it returned into the byte-identical "Wrong email
                          or password" 401 and takes any session back, so the client cannot tell a
                          block from a typo and learns nothing. The starter's hooks.on_action(...)
                          is never called by a route, so this is the workaround (W2 Ch8 uses it too).

Nothing here decides anything: the decisions live in defenses/*.py.
"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from flask import flash, g, make_response, request

from defenses import attempt
from demo_site import hooks
from demo_site.models import User
from demo_site.routes import api_error, render

LOGIN_PATHS = ("/login", "/api/login")
POW_BITS = 15           # ~33k SHA-256 attempts on average
CHALLENGE_TTL = 300     # seconds
CODE_TRIES = 3
WRONG_PASSWORD = ("invalid_credentials", "Wrong email or password.", 401)


# --- the telemetry kind ------------------------------------------------------------------------

def on_risk(ctx, payload):
    """The store already keeps the blob per session; the layers read it through ctx.telemetry("risk")."""
    return {"stored": True, "bytes": len(json.dumps(payload))}


# --- challenge "pow" -----------------------------------------------------------------------------

def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve_pow(prefix, bits=POW_BITS):
    """What the page's WebCrypto loop does (and what the simulated customers run)."""
    nonce = 0
    while leading_zero_bits(hashlib.sha256(f"{prefix}:{nonce}".encode()).digest()) < bits:
        nonce += 1
    return str(nonce)


def pow_issue(ctx):
    prefix = secrets.token_hex(8)
    ctx.note(rung="pow")
    ctx.redis.set(f"lab:ops:pow:{ctx.session.sid}", prefix, ex=CHALLENGE_TTL)
    return {"prefix": prefix, "bits": POW_BITS, "algo": "sha256", "answer": "nonce"}


def pow_verify(ctx, answer):
    key = f"lab:ops:pow:{ctx.session.sid}"
    prefix = ctx.redis.get(key)
    if not prefix:
        return False, "no proof of work is pending, or it expired"
    nonce = str((answer or {}).get("nonce", ""))
    if leading_zero_bits(hashlib.sha256(f"{prefix}:{nonce}".encode()).digest()) < POW_BITS:
        return False, "that nonce does not solve it"
    ctx.redis.delete(key)               # single use
    return True


# --- challenge "step_up" -------------------------------------------------------------------------

def _mail(ctx, email, **msg):
    stamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    ctx.redis.rpush(f"lab:mailbox:{email.lower()}", json.dumps({**msg, "ts": stamp}))


def step_up_issue(ctx):
    """Email a code to the account being signed in to. The answer to the client never differs:
    an unknown address gets the same payload and no mail."""
    email = str(ctx.notes.get("email", "")).lower()
    ctx.note(rung="step_up")
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:ops:code:{ctx.session.sid}", json.dumps({"code": code, "tries": 0}), ex=CHALLENGE_TTL)
    if email and User.query.filter_by(email=email).first() is not None:
        _mail(ctx, email, subject="Your sign-in code", code=code)
    return {"channel": "email", "message": "If this account exists, we emailed it a sign-in code.", "length": 6}


def step_up_verify(ctx, answer):
    key = f"lab:ops:code:{ctx.session.sid}"
    raw = ctx.redis.get(key)
    if not raw:
        return False, "no code is pending, or it expired"
    state = json.loads(raw)
    state["tries"] += 1
    if state["tries"] > CODE_TRIES:
        ctx.redis.delete(key)
        return False, "too many wrong codes: sign in again"
    if not hmac.compare_digest(str((answer or {}).get("code", "")), state["code"]):
        ctx.redis.set(key, json.dumps(state), ex=CHALLENGE_TTL)
        return False, "wrong code"
    ctx.redis.delete(key)
    return True


# --- the shape of a refusal ------------------------------------------------------------------------

def _wrong_password(ctx):
    """The route's own answer to a wrong password, byte for byte."""
    if request.path == "/api/login":
        return api_error(*WRONG_PASSWORD)
    flash("Wrong email or password.", "warn")
    email = attempt.credentials(ctx)[0]
    return make_response(render("login.html", next=request.form.get("next", "/account"), email=email), 401)


def shape_refusal(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or request.path not in LOGIN_PATHS:
        return response
    if getattr(g, "deceive", False):
        ctx.session.delete("uid")                       # the password may well have been right
        return make_response(_wrong_password(ctx))
    return response


def init(app):
    hooks.slot("form:login", "risk/collector.html")
    hooks.telemetry.register("risk", on_risk)
    hooks.challenges.register("pow", issue=pow_issue, verify=pow_verify, clearance_ttl=CHALLENGE_TTL, uses=1)
    hooks.challenges.register("step_up", issue=step_up_issue, verify=step_up_verify, clearance_ttl=CHALLENGE_TTL, uses=1)
    app.after_request(shape_refusal)        # registered after the gate's, so it runs BEFORE the gate stamps the response
