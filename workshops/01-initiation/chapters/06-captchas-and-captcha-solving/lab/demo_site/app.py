"""
Chapter 6 — Demo store with CAPTCHAs (Section 6.6 lab)

The Chapter 5 store: Flask with server-side sessions in Redis, a
newsletter, sign-up, and the promo flow (/promo/unlock → /promo/redeem)
that hands out a $10 voucher once per session. This chapter puts CAPTCHAs
in front of the two endpoints a bot operator cares about.

DEFENSE_LEVEL (restart the app to change it):
  0  no CAPTCHA anywhere
  1  /register requires a provider token (defenses/siteverify.py)
  2  + /promo/redeem requires the self-hosted image CAPTCHA
       (defenses/challenge_store.py, defenses/captcha_generator.py basic)
  3  + the hardened generator style
  4  + solver signals and serve-on-risk (defenses/solver_signals.py)

The app runs with Flask's reloader, so saving a file under defenses/
restarts it with your change.

Lab-only behaviour (never ship any of this):
  - X-Lab-Client-IP is trusted from 127.0.0.1, simulating the edge proxy
    from Chapter 3 so one laptop can play many clients.
  - Every challenge's answer is also written to lab:eyes:<id>, so the
    traffic simulator can "see" the image like a person would.
  - 403 responses say which rule fired. In production that turns your
    defense into a free oracle for the attacker.

Run:  DEFENSE_LEVEL=0 python demo_site/app.py      (http://localhost:5000)
"""

import base64
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path

import redis
from flask import Flask, g, jsonify, render_template_string, request, session
from flask_session import Session

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "defenses"))

import captcha_generator  # noqa: E402
import challenge_store  # noqa: E402
import siteverify  # noqa: E402
import solver_signals  # noqa: E402
from labkit import PROVIDER_URL, REDIS_URL, SITEKEY, TIME_SCALE  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
STYLE = "hardened" if DEFENSE_LEVEL >= 3 else "basic"
SIMULATED_EDGE = os.environ.get("LAB_SIMULATED_EDGE", "1") == "1"
OUR_HOSTNAMES = {"localhost", "127.0.0.1"}
REDEEM_WINDOW_SIM_S = 600

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    SESSION_TYPE="redis",
    SESSION_REDIS=redis.Redis.from_url(REDIS_URL),   # bytes: Flask-Session's own format
    SESSION_KEY_PREFIX="sess:",
    SESSION_PERMANENT=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)
db = redis.Redis.from_url(REDIS_URL, decode_responses=True)

MODULE_HASHES = {
    p.name: hashlib.sha256(p.read_bytes()).hexdigest()[:12]
    for p in sorted((LAB / "defenses").glob("*.py"))
}


def client_ip():
    if SIMULATED_EDGE and request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Lab-Client-IP", request.remote_addr)
    return request.remote_addr


@app.before_request
def context():
    g.timings = {}
    g.ctx = {"ip": client_ip(), "ua": request.headers.get("User-Agent", ""),
             "session_id": getattr(session, "sid", "")}
    if "created_sim" not in session:
        session["created_sim"] = time.time() * TIME_SCALE


@app.after_request
def timing(resp):
    if g.get("timings"):
        resp.headers["Server-Timing"] = ", ".join(
            f"{name};dur={ms:.2f}" for name, ms in g.timings.items())
    return resp


def timed(name, fn, *args, **kwargs):
    start = time.perf_counter()
    try:
        return fn(*args, **kwargs)
    finally:
        g.timings[name] = (time.perf_counter() - start) * 1000


def deny(reason, status=403, **extra):
    return jsonify({"ok": False, "error": reason, **extra}), status


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{{ title }}</title>
<style>body{font:16px system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}
form{display:grid;gap:.6rem;margin:1rem 0}input,button{font:inherit;padding:.4rem}</style>
{% if widget %}<script src="{{ provider }}/turnstile/v0/api.js" defer></script>{% endif %}
</head><body><h1>{{ title }}</h1>{{ body|safe }}
<p><small>DEFENSE_LEVEL={{ level }} · W1 Ch6 lab store</small></p></body></html>"""


def page(title, body, widget=False):
    return render_template_string(PAGE, title=title, body=body, widget=widget,
                                  provider=PROVIDER_URL, level=DEFENSE_LEVEL)


def widget_div(action):
    if DEFENSE_LEVEL < 1:
        return ""
    return f'<div class="cf-turnstile" data-sitekey="{SITEKEY}" data-action="{action}"></div>'


@app.get("/")
def landing():
    session["landing"] = True
    return page("Workshop Store", f"""
<p>Limited drop: <a href="/promo">claim a $10 voucher</a> · <a href="/register">create an account</a></p>
<h2>Newsletter</h2>
<form method="post" action="/newsletter"><input name="email" placeholder="you@example.test">
{widget_div("newsletter")}<button>Subscribe</button></form>""", widget=DEFENSE_LEVEL >= 1)


@app.post("/newsletter")
def newsletter():
    if DEFENSE_LEVEL >= 1:
        # Low value: fail open if the provider is down, and only rate limit.
        v = timed("siteverify", siteverify.verify_token, request.form.get("cf-turnstile-response", ""),
                  remoteip=g.ctx["ip"], expected_action="newsletter",
                  expected_hostnames=OUR_HOSTNAMES, fail_mode="open")
        if not v.ok:
            return deny(v.reason)
    return jsonify({"ok": True, "subscribed": request.form.get("email", "")})


@app.get("/register")
def register_form():
    return page("Create an account", f"""
<form method="post" action="/register"><input name="email" placeholder="email">
<input name="password" type="password" placeholder="password">
{widget_div("register")}<button>Sign up</button></form>""", widget=DEFENSE_LEVEL >= 1)


@app.post("/register")
def register():
    email = request.form.get("email", "").strip().lower()
    if not email or not request.form.get("password"):
        return deny("email and password required", 400)
    if DEFENSE_LEVEL >= 1:
        v = timed("siteverify", siteverify.verify_token, request.form.get("cf-turnstile-response", ""),
                  remoteip=g.ctx["ip"], expected_action="register",
                  expected_hostnames=OUR_HOSTNAMES, fail_mode="closed")
        if not v.ok:
            return deny(v.reason)
    if not db.hsetnx("accounts", email, g.ctx["ip"]):
        return deny("account exists", 409)
    return jsonify({"ok": True, "account": email}), 201


@app.get("/promo/unlock")
def promo_unlock():
    session["promo_unlocked"] = True
    return jsonify({"ok": True, "unlocked": True})


def challenge_required():
    if DEFENSE_LEVEL < 2:
        return False, ["no CAPTCHA below DEFENSE_LEVEL 2"]
    if DEFENSE_LEVEL < 4:
        return True, ["every redemption is challenged"]
    return solver_signals.should_challenge(db, session, g.ctx, time.time() * TIME_SCALE)


@app.get("/promo")
def promo_page():
    required, _ = challenge_required()
    captcha = """<img id="cap" alt="CAPTCHA" width="220" height="72">
<input name="captcha" placeholder="type the characters" autocomplete="off">
<input type="hidden" name="captcha_id" id="cid">
<script>fetch('/captcha/new').then(r => r.json()).then(d => {
  document.getElementById('cap').src = d.image; document.getElementById('cid').value = d.id; });</script>"""
    return page("Claim your $10 voucher", f"""
<form method="post" action="/promo/redeem">{captcha if required else ""}
<button>Redeem</button></form>
<script>fetch('/promo/unlock');</script>""")


@app.get("/promo/status")
def promo_status():
    required, reasons = challenge_required()
    return jsonify({"challenge_required": required, "level": DEFENSE_LEVEL})


@app.get("/captcha/new")
def captcha_new():
    if DEFENSE_LEVEL < 2:
        return deny("no CAPTCHA at this level", 404)
    answer, png = timed("captcha_gen", captcha_generator.new_challenge, STYLE)
    cid, cookie = challenge_store.issue(db, answer, g.ctx)
    db.set(f"lab:eyes:{cid}", answer, ex=600)            # LAB ONLY: simulated eyes
    resp = jsonify({"id": cid, "image": "data:image/png;base64," + base64.b64encode(png).decode()})
    if cookie:
        resp.set_cookie(challenge_store.COOKIE_NAME, cookie, httponly=True, samesite="Lax")
    return resp


def log_solve(**fields):
    fields = {k: str(v) for k, v in fields.items()}
    db.xadd("lab:solvelog", {"actor": request.headers.get("X-Lab-Actor", "?"), **fields},
            maxlen=5000, approximate=True)


@app.post("/promo/redeem")
def promo_redeem():
    if not session.get("promo_unlocked"):
        return deny("promo not unlocked in this session")
    if session.get("redeemed"):
        return deny("already redeemed in this session")

    required, risk = challenge_required()
    if required:
        cid = request.form.get("captcha_id", "")
        ok, reason, record = timed(
            "captcha_check", challenge_store.check, db, cid, request.form.get("captcha", ""),
            g.ctx, request.cookies.get(challenge_store.COOKIE_NAME))
        solve_sim = (time.time() - record["issued_at"]) * TIME_SCALE if record else -1
        if not ok:
            session["captcha_failures"] = session.get("captcha_failures", 0) + 1
            if DEFENSE_LEVEL >= 4:
                solver_signals.note_failure(db, g.ctx, TIME_SCALE)
            log_solve(ok=0, solve_sim=f"{solve_sim:.2f}", decision="wrong", reason=reason)
            return deny(reason, challenge_required=True)
        if DEFENSE_LEVEL >= 4:
            d = solver_signals.assess(db, record, g.ctx, solve_sim)
            log_solve(ok=1, solve_sim=f"{solve_sim:.2f}", decision=d.action,
                      ip_match=int(record.get("issuer_ip") == g.ctx["ip"]),
                      reason="; ".join(d.reasons))
            if d.action == "block":
                return deny("blocked", reasons=d.reasons)
            if d.action == "step_up":
                return deny("step_up", step_up=True, reasons=d.reasons)
        else:
            log_solve(ok=1, solve_sim=f"{solve_sim:.2f}", decision="allow",
                      ip_match=int(record.get("issuer_ip") == g.ctx["ip"]), reason="")

    session["redeemed"] = True
    key = f"redeemed:ip:{g.ctx['ip']}"
    if db.incr(key) == 1:
        db.expire(key, max(1, int(REDEEM_WINDOW_SIM_S / TIME_SCALE)))
    db.incr("lab:vouchers")
    return jsonify({"ok": True, "voucher": "SAVE10-" + secrets.token_hex(4).upper(),
                    "challenged": required})


@app.get("/lab/status")
def lab_status():
    return jsonify({"level": DEFENSE_LEVEL, "style": STYLE, "time_scale": TIME_SCALE,
                    "modules": MODULE_HASHES})


if __name__ == "__main__":
    # debug=True for the auto-reloader; bound to 127.0.0.1 so the debugger
    # is never reachable from the network.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=True, threaded=True)
