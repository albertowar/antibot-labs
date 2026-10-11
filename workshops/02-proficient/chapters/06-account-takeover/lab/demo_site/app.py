"""W2 Ch6 demo store — the login endpoint under attack.

A deliberately small e-commerce back end whose only interesting surface is auth:
``/login``, a second-factor step (``/verify-otp``), a password-reset trigger
(``/forgot-password``), and an account area (``/api/account`` and a sensitive
email change). ``DEFENSE_LEVEL`` (0-4) selects how many pipeline layers run, so a
single process replays every round by restarting with a different level.

Everything bot-detection lives in ../defenses and demo_site/pipeline.py. This file
is the plumbing: parse the request (including the *simulated* network edge used in
the lab), call the pipeline, map its decision onto an HTTP response, and log the
event so the scoreboard can score both the attacker and the real users.

Lab-only shortcuts, all clearly fenced:
  * a fixed SECRET_KEY, so a session cookie minted by the seed script (standing in
    for one an infostealer exfiltrated) validates in this process;
  * an ``X-Lab-Client-IP`` header, honored only from loopback, that stands in for
    the client IP a real CDN would put in front of us;
  * an ``X-Lab-Actor`` header the traffic generators stamp, giving the scoreboard
    the ground truth a real endpoint never has.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time

from flask import Flask, g, jsonify, render_template, request, session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))   # for defenses/
sys.path.insert(0, os.path.dirname(__file__))                        # for store/pipeline

import pipeline  # noqa: E402
from defenses import intel  # noqa: E402
from store import (  # noqa: E402
    ATO_OUTCOMES,
    OUTCOME_ACCOUNT_READ,
    OUTCOME_CHALLENGE,
    OUTCOME_INVALID,
    OUTCOME_LOCKED,
    OUTCOME_REAUTH,
    OUTCOME_SENSITIVE,
    OUTCOME_STEPUP,
    OUTCOME_STEPUP_PASS,
    OUTCOME_SUCCESS,
    OUTCOME_THROTTLED,
    User,
    db,
    log_event,
    make_redis,
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
SIMULATED_EDGE = os.environ.get("LAB_SIMULATED_EDGE", "1") == "1"

app = Flask(__name__)
# Lab-only: a fixed key so seed-minted ("stolen") session cookies validate here.
app.secret_key = os.environ.get("LAB_SECRET_KEY", "w2ch6-lab-fixed-secret-not-for-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{os.path.abspath(os.path.join(DATA_DIR, 'shop.db'))}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

rds = make_redis()

# Map a pipeline action to (HTTP status, JSON status, logged outcome).
_ACTION_MAP = {
    pipeline.INVALID: (401, "error", OUTCOME_INVALID),
    pipeline.THROTTLE: (429, "error", OUTCOME_THROTTLED),
    pipeline.LOCK: (429, "locked", OUTCOME_LOCKED),
    pipeline.CHALLENGE: (200, "challenge", OUTCOME_CHALLENGE),
    pipeline.STEP_UP: (200, "step_up", OUTCOME_STEPUP),
    pipeline.ALLOW: (200, "success", OUTCOME_SUCCESS),
}


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def client_ip() -> str:
    """The client IP, from the simulated edge header when the lab allows it."""
    if SIMULATED_EDGE and _is_loopback(request.remote_addr or ""):
        forwarded = request.headers.get("X-Lab-Client-IP")
        if forwarded:
            return forwarded.strip()
    return request.remote_addr or "0.0.0.0"


def build_ctx(email: str, password: str) -> dict:
    ip = client_ip()
    net = intel.lookup(ip)
    user = User.query.filter_by(email=email).first() if email else None
    return {
        "rds": rds,
        "email": email,
        "password": password,
        "client_ip": ip,
        "cohort": net["cohort"],
        "asn": net["asn"],
        "net_type": net["type"],
        "device_id": request.cookies.get("did") or request.headers.get("X-Lab-Device", ""),
        "client_sig": request.headers.get("X-Client-Sig", ""),
        "user": user,
        "now": time.time(),
        "reauth_totp": "",
        "reauth_password": "",
    }


def actor() -> str:
    return request.headers.get("X-Lab-Actor", "unknown")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/login")
def login():
    t0 = time.perf_counter()
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""
    ctx = build_ctx(email, password)

    decision = pipeline.evaluate(ctx, DEFENSE_LEVEL)
    status, jstatus, outcome = _ACTION_MAP[decision.action]
    latency = (time.perf_counter() - t0) * 1000

    body = {"status": jstatus, "reason": decision.reason}
    if decision.action == pipeline.ALLOW:
        session.clear()
        session["user"] = ctx["user"].id
        session["auth_fresh"] = True
        body["redirect"] = "/account"
    elif decision.action == pipeline.STEP_UP:
        session.clear()
        session["pending_user"] = ctx["user"].id
        body["redirect"] = "/verify-otp"

    log_event(
        level=DEFENSE_LEVEL, actor=actor(), endpoint="login", username=email,
        client_ip=ctx["client_ip"], cohort=ctx["cohort"], asn=ctx["asn"],
        outcome=outcome, score=decision.score, latency_ms=latency,
    )
    g.score_ms = latency
    return jsonify(body), status


@app.post("/verify-otp")
def verify_otp():
    """Complete a step-up with a TOTP code. Only a user who holds the secret can."""
    import pyotp

    uid = session.get("pending_user")
    token = (request.get_json(silent=True) or {}).get("token", "")
    user = db.session.get(User, uid) if uid else None
    if user and user.totp_secret and pyotp.TOTP(user.totp_secret).verify(token, valid_window=1):
        session.clear()
        session["user"] = user.id
        session["auth_fresh"] = True
        log_event(
            level=DEFENSE_LEVEL, actor=actor(), endpoint="verify-otp", username=user.email,
            client_ip=client_ip(), cohort="", asn="", outcome=OUTCOME_STEPUP_PASS,
        )
        return jsonify({"status": "success", "redirect": "/account"}), 200
    return jsonify({"status": "error", "reason": "invalid or missing code"}), 401


@app.post("/forgot-password")
def forgot_password():
    """Password-reset trigger — a classic account-enumeration oracle below L3."""
    email = ((request.get_json(silent=True) or {}).get("email") or "").lower().strip()
    exists = bool(User.query.filter_by(email=email).first())
    if DEFENSE_LEVEL >= 3:
        # Hardened: identical answer for everyone, no timing tell.
        pipeline.get_oracles().equalize_timing("x")
        return jsonify(pipeline.get_oracles().forgot_password_response()), 200
    # Leaky (L0-L2): the response reveals whether the account exists.
    if exists:
        return jsonify({"status": "ok", "message": "Reset link sent to your email."}), 200
    return jsonify({"status": "error", "message": "No account with that email."}), 404


@app.get("/api/account")
def account():
    """Account area. A stolen *session cookie* reaches this without a login."""
    uid = session.get("user")
    user = db.session.get(User, uid) if uid else None
    if not user:
        return jsonify({"status": "error", "reason": "not authenticated"}), 401
    log_event(
        level=DEFENSE_LEVEL, actor=actor(), endpoint="account", username=user.email,
        client_ip=client_ip(), cohort="", asn="", outcome=OUTCOME_ACCOUNT_READ,
    )
    return jsonify({"status": "ok", "email": user.email, "orders": 3, "balance": "$214.00"}), 200


@app.post("/api/account/email")
def change_email():
    """A sensitive action: at L4 it demands a fresh proof, whatever the session is."""
    uid = session.get("user")
    user = db.session.get(User, uid) if uid else None
    if not user:
        return jsonify({"status": "error", "reason": "not authenticated"}), 401
    data = request.get_json(silent=True) or {}

    if DEFENSE_LEVEL >= 4:
        ctx = build_ctx(user.email, "")
        ctx["reauth_totp"] = data.get("reauth_totp", "")
        ctx["reauth_password"] = data.get("reauth_password", "")
        _, _, _, risk = pipeline._impl()
        if risk.needs_reauth(user, ctx):
            log_event(
                level=DEFENSE_LEVEL, actor=actor(), endpoint="change-email",
                username=user.email, client_ip=client_ip(), cohort="", asn="",
                outcome=OUTCOME_REAUTH,
            )
            return jsonify({"status": "reauth", "reason": "re-authentication required"}), 401

    log_event(
        level=DEFENSE_LEVEL, actor=actor(), endpoint="change-email", username=user.email,
        client_ip=client_ip(), cohort="", asn="", outcome=OUTCOME_SENSITIVE,
    )
    return jsonify({"status": "ok", "new_email": data.get("new_email", "")}), 200


# --- Lab instrumentation endpoints (not part of the product) -------------------

@app.get("/lab/info")
def lab_info():
    return jsonify({"level": DEFENSE_LEVEL, "simulated_edge": SIMULATED_EDGE})


@app.get("/lab/events")
def lab_events():
    since = float(request.args.get("since", "0"))
    rows = LoginEvent.query.filter(LoginEvent.ts >= since).order_by(LoginEvent.ts).all()
    return jsonify([
        {"ts": r.ts, "level": r.level, "actor": r.actor, "endpoint": r.endpoint,
         "username": r.username, "client_ip": r.client_ip, "cohort": r.cohort,
         "asn": r.asn, "outcome": r.outcome, "score": r.score, "latency_ms": r.latency_ms}
        for r in rows
    ])


@app.post("/lab/reset")
def lab_reset():
    """Clear the event log and all runtime counters, then reload device history.

    Called at the start of each checkpoint so a round is measured from a clean
    slate without restarting the server.
    """
    LoginEvent.query.delete()
    db.session.commit()
    rds.flushdb()
    load_device_history()
    return jsonify({"status": "ok"})


from store import LoginEvent  # noqa: E402  (after db setup, used above)


def load_device_history() -> None:
    """Seed Redis with the device/ASN history the risk engine compares against.

    Done here, not in seed.py, because the default Redis is an in-process fake:
    only this process can populate the counters the pipeline reads.
    """
    path = os.path.join(DATA_DIR, "device_history.json")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        history = json.load(fh)
    for uid, rec in history.items():
        for did in rec.get("devices", []):
            rds.sadd(f"dev:{uid}", did)
        for asn in rec.get("asns", []):
            rds.sadd(f"asn:{uid}", asn)
        for sig in rec.get("sigs", []):
            rds.sadd(f"sig:{uid}", sig)


@app.after_request
def server_timing(response):
    if "score_ms" in g:
        response.headers["Server-Timing"] = f"login;dur={g.score_ms:.3f}"
    return response


from sqlalchemy import event  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """WAL + relaxed sync keeps the per-request event log cheap under concurrency.

    Guarded so it is a no-op on PostgreSQL (the optional Docker backend).
    """
    if "sqlite3" in type(dbapi_conn).__module__:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


with app.app_context():
    db.create_all()
    load_device_history()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"demo store: DEFENSE_LEVEL={DEFENSE_LEVEL} simulated_edge={SIMULATED_EDGE} on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, threaded=True)
