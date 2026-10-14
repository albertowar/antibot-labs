"""
W1 Ch5 feature: a promo voucher, and the session plumbing the defenses read.

The store already keeps a server-side session (the opaque `sid` cookie points at a
Redis hash `lab:s:<sid>`). This feature adds a promo that, on purpose, keeps its
"unlocked" flag in TWO places:

    - a signed client-side cookie `promo` (itsdangerous, the same format Flask's own
      session uses, so `flask-unsign --decode` reads it). Signed, not encrypted: the
      flag is in plain view, and an old copy stays valid until it expires.
    - the server session (`promo_ok` in the Redis hash), which only `promo_state`
      (Round 1) consults.

With no defense wired, `/promo/redeem` trusts the cookie. That is the bug the chapter
is about: a signature proves the server wrote the cookie once, not that it is the
latest copy. Round 1 moves the decision to the server session and consumes it once.

It also registers the session plumbing the later rounds read:
    - an enricher stamps `js_nonce`, `ua_hash` (User-Agent + Sec-CH-UA) and `landing`
      on the session;
    - a `body_end` slot ships the tiny script that turns the nonce into a `js_ok`
      cookie (a client that never runs JavaScript never sends it back).

No route here is ungated: `/promo/` is a store feature, so the gate runs on it like
any other page. Nothing leaves this machine.
"""

import hashlib
import secrets
import time

from flask import Blueprint, g, jsonify, render_template, request
from itsdangerous import BadSignature, URLSafeSerializer

from demo_site import hooks
from demo_site.routes import csrf_token, guard

PROMO_COOKIE = "promo"
# Deliberately a throwaway key, and the Flask cookie format, so the chapter can show the
# flag in plain view (flask-unsign --decode). The point is replay, not key strength.
PROMO_SECRET = "promo-dev"
QUIZ_Q = "What is 3 + 4?"
QUIZ_A = "7"
VOUCHER_LIMIT = 1

_signer = URLSafeSerializer(PROMO_SECRET, salt="promo")


def _ua_hash(ctx):
    """A browser's identity for this session: User-Agent plus the Client Hints brand list."""
    ua = ctx.header("User-Agent", "") or ""
    ch = ctx.header("Sec-CH-UA", "") or ""
    return hashlib.sha256(f"{ua}|{ch}".encode()).hexdigest()[:16]


def _read_promo(ctx):
    raw = ctx.cookies.get(PROMO_COOKIE)
    if not raw:
        return None
    try:
        return _signer.loads(raw)
    except BadSignature:
        return None


def _issue_promo(resp, data):
    # Not HttpOnly on purpose in the shipped store: nothing reads it from JS, but the
    # chapter wants it visible. The real fix (Round 1) is to stop trusting it, not to hide it.
    resp.set_cookie(PROMO_COOKIE, _signer.dumps(data), httponly=False, samesite="Lax", max_age=3600)


def _enrich(ctx):
    """Stamp the session once, at creation, with what the later rounds compare against."""
    s = ctx.session
    if s.new or not s.get("js_nonce"):
        s.set("js_nonce", secrets.token_hex(8))
        s.set("ua_hash", _ua_hash(ctx))
    if ctx.path == "/" and not s.get("landing"):
        s.set("landing", "1")


def page():
    return render_template("promo/offer.html", csrf=csrf_token(), question=QUIZ_Q)


def unlock():
    ctx = g.ctx
    body = ctx.json if isinstance(ctx.json, dict) else request.form
    if str(body.get("answer", "")).strip() != QUIZ_A:
        return jsonify(error={"code": "wrong_answer", "message": "Not quite. Try again."}), 400
    ctx.session.set("promo_ok", "1")                      # the server's copy (Round 1 reads this)
    resp = jsonify(ok=True)
    _issue_promo(resp, {"promo_ok": True, "left": VOUCHER_LIMIT, "ts": time.time()})  # the client's copy (the bug)
    return resp


def redeem():
    ctx = g.ctx
    if (blocked := guard("promo_redeem")):
        return blocked
    data = _read_promo(ctx)
    if not data or not data.get("promo_ok") or int(data.get("left", 0)) <= 0:
        return jsonify(error={"code": "locked", "message": "Unlock the promo first."}), 403
    code = f"SAVE-{secrets.token_hex(3).upper()}"
    data = dict(data, left=int(data["left"]) - 1)         # the server keeps no count: it lives in the cookie
    ctx.note(promo_voucher=code)
    resp = jsonify(voucher=code, left=data["left"])
    _issue_promo(resp, data)
    return resp


def init(app):
    hooks.enricher(_enrich)
    hooks.slot("body_end", "promo/js_cookie.html")
    bp = Blueprint("promo", __name__, url_prefix="/promo")
    bp.add_url_rule("/", "page", page)
    bp.add_url_rule("/unlock", "unlock", unlock, methods=["POST"])
    bp.add_url_rule("/redeem", "redeem", redeem, methods=["POST"])
    app.register_blueprint(bp)
