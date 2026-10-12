"""
Chapter 4 Lab: the demo store's sign-up page, defended by browser fingerprinting.

New accounts get a €10 welcome credit, which is why bots want hundreds of
them. Every visit to the store page runs static/fp_collector.js, which
posts a fingerprint to /api/fp. Every sign-up is scored by the layers
enabled with DEFENSE_LEVEL (0-4). Restart the server with a higher level
at each round:

    DEFENSE_LEVEL=0 python app.py     # Round 0: no defense, log only
    DEFENSE_LEVEL=1 python app.py     # + render-stack plausibility
    DEFENSE_LEVEL=2 python app.py     # + lie detection
    DEFENSE_LEVEL=3 python app.py     # + exact-ID linking
    DEFENSE_LEVEL=4 python app.py     # + fuzzy clustering

LINK_MODE=naive turns off rarity weighting in L3/L4 (Round 3 exercise).

- Score >= 40: sign-up refused (403)
- Score >= 20: suspicious, logged, account created
- Score < 20: clean

Debug endpoints (never blocked): /fp-check, /fp-profile, /fp-dashboard,
POST /lab/reset (loopback only; the checkpoint uses it).

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///fp_lab.db to run without Docker.

Client IPs: every client in this lab is 127.0.0.1, so the scripts send a
simulated address in X-Lab-Client-IP. The app trusts it only from loopback,
standing in for the trusted edge proxy of W1 Ch3. Never trust a client-set
IP header in production.

Every sign-up response carries Server-Timing with the cost of judging the
fingerprint (fpscore) and of the linking queries (fplink).
"""

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, g, jsonify, make_response, render_template, request
from flask_sqlalchemy import SQLAlchemy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'defenses'))

from scoring import evaluate  # noqa: E402
from stable_id import core_components, core_id, device_class, stable_id  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
LINK_MODE = os.environ.get("LINK_MODE", "rarity")
LINK_WINDOW = timedelta(hours=24)
SESSION_COOKIE = "sid"
NONCE_KEY = os.environ.get("NONCE_KEY", "change-me-in-production").encode()
KEPT_HEADERS = ["User-Agent", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "Accept-Language"]

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Fingerprint(db.Model):
    """One collector payload, as received."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    session_id = db.Column(db.String(64), index=True)
    ip = db.Column(db.String(50))
    payload = db.Column(db.Text)       # raw JSON from the collector
    headers = db.Column(db.Text)       # JSON: the request headers the payload arrived with
    stable_id = db.Column(db.String(16))
    core_id = db.Column(db.String(16))
    device_class = db.Column(db.String(200))


class Signup(db.Model):
    """Every sign-up attempt, created or refused."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    level = db.Column(db.Integer)
    email = db.Column(db.String(200))
    ip = db.Column(db.String(50))
    status = db.Column(db.String(20))  # created | refused
    verdict = db.Column(db.String(20))
    score = db.Column(db.Integer)
    reasons = db.Column(db.Text)
    stable_id = db.Column(db.String(16))
    core = db.Column(db.Text)          # JSON core components, for L4

    __table_args__ = (db.Index("ix_signup_stable_id_created", "stable_id", "created_at"),)


with app.app_context():
    db.create_all()


def is_loopback(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def client_ip():
    """X-Lab-Client-IP from loopback only (the lab's stand-in for a trusted edge)."""
    simulated = request.headers.get("X-Lab-Client-IP")
    if simulated and is_loopback(request.remote_addr):
        return simulated
    return request.remote_addr


def session_id():
    return request.cookies.get(SESSION_COOKIE)


def latest_fingerprint(sid):
    if not sid:
        return None
    return (Fingerprint.query.filter_by(session_id=sid)
            .order_by(Fingerprint.id.desc()).first())


def count_accounts(sid):
    """L3: accounts created in the window with this stable_id (indexed query)."""
    since = utcnow() - LINK_WINDOW
    return Signup.query.filter(Signup.status == "created", Signup.stable_id == sid,
                               Signup.created_at > since).count()


def recent_cores():
    """L4: core components of every account created in the window."""
    since = utcnow() - LINK_WINDOW
    rows = (Signup.query.with_entities(Signup.core)
            .filter(Signup.status == "created", Signup.created_at > since).all())
    return [json.loads(core) for (core,) in rows if core]


def judge(record, level):
    """Run the scoring engine on a stored Fingerprint row (or None)."""
    fp = json.loads(record.payload) if record else None
    headers = json.loads(record.headers) if record else {}

    timed_counts = {"ms": 0.0}

    def timed(fn):
        def wrapper(*args):
            started = time.perf_counter()
            try:
                return fn(*args)
            finally:
                timed_counts["ms"] += (time.perf_counter() - started) * 1000
        return wrapper

    started = time.perf_counter()
    result = evaluate(fp, headers, level, timed(count_accounts), timed(recent_cores), LINK_MODE)
    total_ms = (time.perf_counter() - started) * 1000
    g.score_ms = total_ms - timed_counts["ms"]
    g.link_ms = timed_counts["ms"]
    return result


@app.after_request
def server_timing(response):
    if "score_ms" in g:
        response.headers["Server-Timing"] = (
            f"fpscore;dur={g.score_ms:.2f}, fplink;dur={g.link_ms:.2f}")
    return response


@app.route("/")
def store():
    """The sign-up page. Starts a session and embeds a per-session nonce."""
    sid = session_id() or secrets.token_urlsafe(24)
    response = make_response(render_template("index.html", nonce=nonce_for(sid), level=DEFENSE_LEVEL))
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="Lax")
    return response


def nonce_for(sid):
    """A per-session value the page embeds and the payload must echo back."""
    return hmac.new(NONCE_KEY, sid.encode(), hashlib.sha256).hexdigest()[:16]


@app.route("/api/fp", methods=["POST"])
def receive_fingerprint():
    sid = session_id()
    fp = request.get_json(silent=True)
    if not sid or not isinstance(fp, dict):
        return jsonify({"error": "no session or invalid payload"}), 400
    if fp.get("nonce") != nonce_for(sid):
        return jsonify({"error": "payload is not from this session"}), 400
    record = Fingerprint(
        session_id=sid, ip=client_ip(), payload=json.dumps(fp),
        headers=json.dumps({h: request.headers[h] for h in KEPT_HEADERS if h in request.headers}),
        stable_id=stable_id(fp), core_id=core_id(fp), device_class=device_class(fp),
    )
    db.session.add(record)
    db.session.commit()
    # fp_id is the noise-resistant core_id: what W2 Ch6 binds to an account
    return jsonify({"fp_id": record.core_id, "stable_id": record.stable_id,
                    "device_class": record.device_class})


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "email required"}), 400

    record = latest_fingerprint(session_id())
    score, reasons, verdict, signals = judge(record, DEFENSE_LEVEL)
    fp = json.loads(record.payload) if record else None
    status = "refused" if verdict == "bot" else "created"
    db.session.add(Signup(
        level=DEFENSE_LEVEL, email=email, ip=client_ip(), status=status, verdict=verdict,
        score=score, reasons=json.dumps(reasons),
        stable_id=record.stable_id if record else None,
        core=json.dumps(core_components(fp)) if fp else None,
    ))
    db.session.commit()
    if verdict == "suspicious":
        app.logger.warning("Suspicious sign-up | score=%d | %s | ip=%s", score, reasons, client_ip())
    body = {"status": status, "verdict": verdict, "score": score, "signals": signals,
            # Teaching only: never tell a real client which rule caught it.
            "reasons": reasons}
    if status == "created":
        body["credit"] = "€10 welcome credit added"
    return jsonify(body), 403 if status == "refused" else 201


@app.route("/fp-check")
def fp_check():
    """Shows your fingerprint and how each level would judge it (nothing is created)."""
    sid = session_id() or secrets.token_urlsafe(24)
    response = make_response(render_template("fp_check.html", nonce=nonce_for(sid), level=DEFENSE_LEVEL))
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="Lax")
    return response


@app.route("/api/fp/me")
def fp_me():
    """The latest fingerprint for this session, judged at every level."""
    record = latest_fingerprint(session_id())
    if not record:
        return jsonify({"error": "no fingerprint yet: load / or /fp-check first"}), 404
    levels = {}
    for level in range(5):
        score, reasons, verdict, signals = judge(record, level)
        levels[level] = {"score": score, "verdict": verdict, "reasons": reasons, "signals": signals}
    return jsonify({
        "level": DEFENSE_LEVEL, "link_mode": LINK_MODE,
        "fp_id": record.core_id, "stable_id": record.stable_id, "device_class": record.device_class,
        "headers": json.loads(record.headers), "payload": json.loads(record.payload),
        "levels": levels,
    })


@app.route("/fp-profile")
def fp_profile():
    """Download your fingerprint as a real-user profile for tools/profiles/."""
    record = latest_fingerprint(session_id())
    if not record:
        abort(404)
    fp = json.loads(record.payload)
    profile = {
        "cohort": "you", "provenance": "captured",
        "description": f"Captured from {fp.get('nav', {}).get('userAgent', '?')[:80]}",
        "headers": json.loads(record.headers), "users": [{"payload": fp}],
    }
    response = make_response(json.dumps(profile, indent=1))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = "attachment; filename=you.json"
    return response


@app.route("/fp-dashboard")
def fp_dashboard():
    """Sign-up outcomes and the most-reused fingerprints, as JSON."""
    rows = db.session.query(Signup.level, Signup.verdict, Signup.status, db.func.count()).group_by(
        Signup.level, Signup.verdict, Signup.status).all()
    top = (db.session.query(Signup.stable_id, db.func.count())
           .filter(Signup.status == "created").group_by(Signup.stable_id)
           .order_by(db.func.count().desc()).limit(5).all())
    return jsonify({
        "level": DEFENSE_LEVEL, "link_mode": LINK_MODE,
        "signups": [{"level": lv, "verdict": v, "status": s, "count": c} for lv, v, s, c in rows],
        "most_reused_fingerprints": [{"stable_id": sid, "accounts": c} for sid, c in top],
    })


@app.route("/lab/reset", methods=["POST"])
def lab_reset():
    """Wipe fingerprints and sign-ups (loopback only), so every checkpoint starts clean."""
    if not is_loopback(request.remote_addr):
        abort(403)
    Signup.query.delete()
    Fingerprint.query.delete()
    db.session.commit()
    return jsonify({"reset": True, "level": DEFENSE_LEVEL, "link_mode": LINK_MODE})


if __name__ == '__main__':
    print(f"Demo store on http://localhost:{os.environ.get('PORT', 5000)} "
          f"| DEFENSE_LEVEL={DEFENSE_LEVEL} | LINK_MODE={LINK_MODE}")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False, threaded=True)
