"""
Chapter 6 feature module: the CAPTCHAs, the widget, and the promo voucher they protect.

    hooks.challenges.register("captcha", ...)   GET /api/challenge?type=captcha, POST /api/challenge/verify,
                                                and the 403 interstitial the gate serves
    hooks.slot("form:register", ...)            the (mock) Turnstile widget inside the sign-up form
    hooks.slot("body_end", ...)                 the same widget in the footer newsletter form
    hooks.enricher(_landing)                    session flag `landing` once a visitor has seen the home page
    /lab/promo/                                 the page and POST /lab/promo/redeem: a $10 voucher per session
    /lab/captcha/eyes/<id>                      LAB ONLY: what a person sees in the image (a bot must not call it)
    /lab/captcha/provider                       where the mock provider listens

Which defense runs at which level lives in defenses/ (turnstile_check, captcha_gate, solver_signals);
what is here is the store side: routes, templates, the provider, the challenge hook.

The mock Turnstile provider (provider/mock_turnstile.py, test keys, no account, no network) runs next
to the store: this module starts it on a thread unless one answers already (PROVIDER_URL, default
http://127.0.0.1:5001) or PROVIDER_AUTOSTART=0. It listens on 127.0.0.1 only.
"""

import os
import secrets
import socket
import sys
import threading
import time

import requests
from flask import Blueprint, after_this_request, current_app, g, jsonify, redirect, render_template, request

from defenses import captcha_gate, challenge_store, policy

from .. import gate, hooks
from ..routes import csrf_ok, csrf_token, guard

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VOUCHER_LIMIT = 1                    # per session
EYES_TTL = 600


# --- The mock provider ---------------------------------------------------------------------------

def _is_our_provider(url):
    try:
        r = requests.get(f"{url}/lab/health", timeout=1)
        return r.ok and "tokens" in r.json()
    except (requests.RequestException, ValueError):
        return False


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_provider():
    """Make sure a mock provider is answering; sets and returns PROVIDER_URL."""
    url = os.environ.get("PROVIDER_URL", f"http://127.0.0.1:{os.environ.get('PROVIDER_PORT', '5001')}")
    if os.environ.get("PROVIDER_AUTOSTART", "1") == "0" or _is_our_provider(url):
        os.environ["PROVIDER_URL"] = url
        return url
    sys.path.insert(0, os.path.join(LAB, "provider"))
    import mock_turnstile
    from werkzeug.serving import make_server
    port = int(url.rsplit(":", 1)[1])
    try:
        srv = make_server("127.0.0.1", port, mock_turnstile.app, threaded=True)
    except OSError:
        port = _free_port()
        srv = make_server("127.0.0.1", port, mock_turnstile.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True, name="mock-turnstile").start()
    os.environ["PROVIDER_URL"] = f"http://127.0.0.1:{port}"
    return os.environ["PROVIDER_URL"]


# --- The challenge type ----------------------------------------------------------------------------

def _timed(ctx, name, fn, *args):
    """Run a defense call and book its time as defender cost (gate figure + a note in the log)."""
    t0 = time.perf_counter()
    try:
        return fn(*args)
    finally:
        ms = (time.perf_counter() - t0) * 1000
        ctx.note(**{f"{name}_ms": round(ms, 2)})
        g.gate_ms = getattr(g, "gate_ms", 0.0) + ms


def _issue(ctx):
    # captcha_gate is reloaded in place when you edit defenses/*.py; look it up on every call.
    payload = _timed(ctx, "captcha_gen", captcha_gate.issue, ctx)
    cookie = ctx.attrs.pop("captcha_cookie", None)
    if cookie:                       # Round 2's shipped design: the answer rides in a signed cookie
        @after_this_request
        def _set(resp):
            resp.set_cookie(challenge_store.COOKIE_NAME, cookie, httponly=True, samesite="Lax")
            return resp
    return payload


def _verify(ctx, answer):
    return _timed(ctx, "captcha_check", captcha_gate.verify, ctx, answer)


# --- Gating the promo routes ---------------------------------------------------------------------------

def _gate_here():
    """/lab/ is skipped by the gate (lab tooling). The promo is a store feature, so run the gate for it."""
    t_ctx = time.perf_counter()
    ctx = gate.build_ctx(current_app)
    g.ctx = ctx
    for fn in hooks.ENRICHERS:
        try:
            fn(ctx)
        except Exception as e:
            ctx.note(enricher_error=repr(e))
    g.gate_ms += (time.perf_counter() - t_ctx) * 1000
    return gate.respond(gate.run_phase("request", ctx), ctx)


def _landing(ctx):
    """Remember that this session saw the home page (Round 4 reads it). One Redis write per session."""
    if ctx.path == "/" and not ctx.session.get("landing"):
        ctx.session.set("landing", "1")


def _wants_json():
    return request.is_json or "text/html" not in request.headers.get("Accept", "text/html")


def init(app):
    start_provider()
    app.jinja_env.globals.update(captcha_provider=lambda: os.environ["PROVIDER_URL"], captcha_sitekey=policy.SITEKEY)

    hooks.challenges.register("captcha", issue=_issue, verify=_verify, render="captcha/interstitial.html",
                              clearance_ttl=policy.CAPTCHA_CLEARANCE_TTL, uses=1)
    hooks.slot("form:register", "captcha/widget_register.html")
    hooks.slot("body_end", "captcha/widget_footer.html")
    hooks.enricher(_landing)

    promo = Blueprint("promo", __name__, url_prefix="/lab/promo")
    promo.before_request(_gate_here)

    @promo.route("/")
    def page():
        g.ctx.session.set("promo", "1")                       # "unlocked": the visitor has seen the offer
        return render_template("captcha/promo.html", csrf=csrf_token(), voucher=g.ctx.session.get("voucher"))

    @promo.route("/redeem", methods=["POST"])
    def redeem():
        ctx = g.ctx
        as_json = _wants_json()
        if not as_json and not csrf_ok():
            return redirect("/lab/promo/")
        if not ctx.session.get("promo"):
            return jsonify(error={"code": "not_unlocked", "message": "Open the offer page first."}), 400
        if int(ctx.session.get("redeemed", 0)) >= VOUCHER_LIMIT:
            return jsonify(error={"code": "already_redeemed", "message": "One voucher per session."}), 409
        r = guard("promo_redeem")                                 # the CAPTCHA, when the ladder wants it
        if r:
            return r
        ctx.session.incr("redeemed")
        key = policy.redeemed_key(ctx.ip)
        if ctx.redis.incr(key) == 1:
            ctx.redis.expire(key, max(1, int(policy.REDEEM_WINDOW_SIM_S / policy.TIME_SCALE)))
        ctx.redis.incr("lab:promo:vouchers")
        code = "SAVE10-" + secrets.token_hex(4).upper()
        ctx.session.set("voucher", code)
        ctx.note(promo_voucher=code, challenged=bool(ctx.notes.get("cleared")))
        if as_json:
            return jsonify(ok=True, voucher=code, challenged=bool(ctx.notes.get("cleared")))
        return render_template("captcha/promo.html", csrf=csrf_token(), voucher=code)

    lab = Blueprint("captcha_lab", __name__, url_prefix="/lab/captcha")      # ungated lab tooling

    @lab.route("/eyes/<cid>")
    def eyes(cid):
        """LAB ONLY: the text a person reads in image `cid`. Simulated shoppers and the simulated farm call it."""
        text = current_app.extensions["lab_redis"].get(f"lab:eyes:{cid}")
        return jsonify(id=cid, text=text) if text else (jsonify(error="unknown or expired"), 404)

    @lab.route("/provider")
    def provider():
        """Where the mock Turnstile provider listens (tools and attacks ask; it may have taken a free port)."""
        return jsonify(url=os.environ["PROVIDER_URL"], sitekey=policy.SITEKEY)

    app.register_blueprint(promo)
    app.register_blueprint(lab)
