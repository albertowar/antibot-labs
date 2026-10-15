"""
Chapter 8 extension: the login's collector, the two rungs of the response ladder, and the shape
of a refusal. What this module adds (no starter file is edited):

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
    enricher              at level 4 only: check the password of every login attempt, also the ones
                          the gate is about to challenge, so the campaign layer can count failures
                          (the cost: one password hash more per attempt).
    after_request         shapes a refusal on the login routes at levels 1-2 only, where a
                          refusal is LEAKY on purpose: it explains itself (score, layer,
                          reasons). Never do this in production; it is how you read the model
                          while you tune it. From level 3 a block is DECEPTIVE, and since
                          contract 1.7 the gate itself serves it: a `deceive` verdict on the
                          login answers the byte-identical "Wrong email or password" 401
                          without ever checking the password (routes/deceive.py), so the
                          client cannot tell a block from a typo and learns nothing.

Nothing here decides anything: the decisions live in defenses/*.py.
"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone

from flask import g, jsonify, request

from defenses import attempt, policy, veto
from demo_site import hooks
from demo_site.models import User
from demo_site.seed import check_password

LOGIN_PATHS = ("/login", "/api/login")
POW_BITS = 15           # ~33k SHA-256 attempts on average
CHALLENGE_TTL = 300     # seconds
CODE_TRIES = 3


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
    ctx.redis.set(f"lab:ch8:pow:{ctx.session.sid}", prefix, ex=CHALLENGE_TTL)
    return {"prefix": prefix, "bits": POW_BITS, "algo": "sha256", "answer": "nonce"}


def pow_verify(ctx, answer):
    key = f"lab:ch8:pow:{ctx.session.sid}"
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
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:ch8:code:{ctx.session.sid}", json.dumps({"code": code, "tries": 0}), ex=CHALLENGE_TTL)
    if email and User.query.filter_by(email=email).first() is not None:
        _mail(ctx, email, subject="Your sign-in code", code=code)
    return {"channel": "email", "message": "If this account exists, we emailed it a sign-in code.", "length": 6}


def step_up_verify(ctx, answer):
    key = f"lab:ch8:code:{ctx.session.sid}"
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


# --- the enricher: the password outcome, for the campaign layer -----------------------------------

def check_credentials(ctx):
    """At level 4 only, on a login attempt: valid | wrong | unknown (the campaign layer counts failures)."""
    from flask import current_app
    if ctx.level < 4 or ctx.method != "POST" or ctx.path not in LOGIN_PATHS:
        return
    email, password = attempt.credentials(ctx)
    user = User.query.filter_by(email=email).first()
    ok = check_password(user, password, current_app.config["LAB"].hash_iters)
    ctx.attrs["ch8_cred"] = "valid" if ok else ("wrong" if user is not None else "unknown")
    ctx.note(cred=ctx.attrs["ch8_cred"])


# --- the shape of a refusal ------------------------------------------------------------------------

def shape_refusal(response):
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or request.path not in LOGIN_PATHS:
        return response
    if ctx.level <= 2 and response.status_code == 403 and response.is_json and g.decisions:
        d = g.decisions[-1]
        body = response.get_json()
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            body["error"].update(score=policy.score(d.signals), reasons=[
                f"[{s.layer}] {s.name} (+{s.points})" for s in d.signals if s.points])
            if ctx.level == 1:
                body["error"]["layer"] = veto.blocking_layer(d.signals)
            out = jsonify(body)
            out.status_code = response.status_code
            return out
    return response


def init(app):
    hooks.slot("form:login", "risk/collector.html")
    hooks.telemetry.register("risk", on_risk)
    # lambdas, not the functions themselves: the reloader swaps modules in defenses/, not references
    hooks.challenges.register("pow", issue=lambda ctx: pow_issue(ctx), verify=lambda ctx, a: pow_verify(ctx, a),
                              clearance_ttl=CHALLENGE_TTL, uses=1)
    hooks.challenges.register("step_up", issue=lambda ctx: step_up_issue(ctx), verify=lambda ctx, a: step_up_verify(ctx, a),
                              clearance_ttl=CHALLENGE_TTL, uses=1)
    hooks.enricher(check_credentials)
    app.after_request(shape_refusal)        # registered after the gate's, so it runs BEFORE the gate stamps the response
