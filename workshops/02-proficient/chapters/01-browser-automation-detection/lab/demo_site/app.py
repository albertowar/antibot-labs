"""
W2 Ch1 Lab: the demo store with a JavaScript bot sensor.

This is the Workshop 2 starter state of the store. It keeps Workshop 1's
header rules as an always-on edge layer and adds a sensor that runs in the
page (static/sensor.js):

    GET  /              store page; issues a one-time sensor nonce
    POST /api/sensor    sensor payload -> scored and stored per session
    GET  /api/products  protected: needs a fresh sensor verdict (Level >= 1)
    POST /api/cart      protected: verdict + interaction evidence (Level 4)

Restart the server with a higher level at each round:

    DEFENSE_LEVEL=0 python app.py   # edge rules only, sensor logged (Round 0)
    DEFENSE_LEVEL=1 python app.py   # + sensor gate, automation artifacts
    DEFENSE_LEVEL=2 python app.py   # + consistency
    DEFENSE_LEVEL=3 python app.py   # + lie detection
    DEFENSE_LEVEL=4 python app.py   # + interaction evidence on the cart

Debug endpoints (never blocked): /sensor-check, /sensor-logs, /capture

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///sensor.db to run without Docker.

Responses carry Server-Timing (edge;dur=..., sensor;dur=...) so the
checkpoint can report what each defense costs, not just what it catches.
"""

import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta

from flask import Flask, abort, g, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "defenses"))
sys.path.insert(0, os.path.join(HERE, "..", "defenses", "edge"))

from accept_ch import ACCEPT_CH_VALUE, OFFERED_COOKIE
from edge_rules import evaluate_edge
from scoring import evaluate_action, evaluate_sensor

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
DEBUG_PREFIXES = ("/sensor-check", "/sensor-logs", "/capture")
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "[::1]"}
NONCE_TTL = timedelta(minutes=2)       # page load -> sensor POST
VERDICT_TTL = timedelta(minutes=10)    # sensor POST -> API calls
SID_COOKIE = "sid"
PROFILES_DIR = os.path.join(HERE, "..", "tools", "profiles")

PRODUCTS = [
    {"id": 1, "name": "Widget", "price": 9.99},
    {"id": 2, "name": "Gadget", "price": 24.99},
    {"id": 3, "name": "Doohickey", "price": 4.99},
    {"id": 4, "name": "Limited Sneaker", "price": 189.00},
]

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class SensorNonce(db.Model):
    """One nonce per page load. Single use, short-lived."""
    nonce = db.Column(db.String(64), primary_key=True)
    sid = db.Column(db.String(64), index=True)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)


class SensorVerdict(db.Model):
    """The scored sensor payload for a session."""
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sid = db.Column(db.String(64), index=True)
    level = db.Column(db.Integer)
    ua_string = db.Column(db.Text)
    score = db.Column(db.Integer)
    verdict = db.Column(db.String(20))
    reasons = db.Column(db.Text)
    signals = db.Column(db.Text)
    score_ms = db.Column(db.Float)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.String(64), index=True)
    product_id = db.Column(db.Integer)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


# ---------------------------------------------------------------- edge layer

@app.before_request
def edge_rules():
    """Workshop 1 header rules on every request (always on)."""
    header_names = [name for name, _ in request.headers]
    secure_context = request.is_secure or request.host.split(":")[0] in LOCALHOST_NAMES
    started = time.perf_counter()
    score, reasons, verdict = evaluate_edge(
        request.headers, header_names, request.cookies, request.host, secure_context)
    g.edge_ms = (time.perf_counter() - started) * 1000
    g.edge = {"score": score, "reasons": reasons, "verdict": verdict}
    g.sid = request.cookies.get(SID_COOKIE) or secrets.token_urlsafe(16)
    if request.path.startswith(DEBUG_PREFIXES):
        return
    if verdict == "bot":
        g.block_reasons = reasons
        abort(403)


@app.after_request
def add_headers(response):
    timings = [f"edge;dur={g.edge_ms:.3f}"] if "edge_ms" in g else []
    if "sensor_ms" in g:
        timings.append(f"sensor;dur={g.sensor_ms:.3f}")
    if timings:
        response.headers["Server-Timing"] = ", ".join(timings)
    if "sid" in g and request.cookies.get(SID_COOKIE) != g.sid:
        response.set_cookie(SID_COOKIE, g.sid, httponly=True, samesite="Lax")
    # Workshop 1's Accept-CH negotiation, so Chromium sends high-entropy hints
    response.headers["Accept-CH"] = ACCEPT_CH_VALUE
    if OFFERED_COOKIE not in request.cookies:
        response.set_cookie(OFFERED_COOKIE, "1", httponly=True, samesite="Lax")
    return response


# ---------------------------------------------------------------- the sensor gate

def latest_verdict(sid):
    return (SensorVerdict.query
            .filter(SensorVerdict.sid == sid,
                    SensorVerdict.level == DEFENSE_LEVEL,
                    SensorVerdict.created_at > datetime.utcnow() - VERDICT_TTL)
            .order_by(SensorVerdict.created_at.desc())
            .first())


def require_sensor_verdict():
    """
    Level >= 1: protected endpoints need a fresh sensor verdict for this
    session. A client that never runs the sensor (raw HTTP, JS disabled)
    has none. Returns the verdict row (or None at Level 0).
    """
    verdict = latest_verdict(g.sid)
    if DEFENSE_LEVEL < 1:
        return verdict
    if verdict is None:
        g.block_reasons = ["[gate] No sensor verdict for this session "
                           "(JavaScript disabled, blocked or skipped)"]
        abort(403)
    if verdict.verdict == "bot":
        g.block_reasons = json.loads(verdict.reasons)
        abort(403)
    return verdict


# ---------------------------------------------------------------- routes

@app.route("/")
def index():
    nonce = secrets.token_urlsafe(24)
    db.session.add(SensorNonce(nonce=nonce, sid=g.sid))
    db.session.commit()
    return render_template("index.html", nonce=nonce, level=DEFENSE_LEVEL)


@app.route("/api/sensor", methods=["POST"])
def sensor():
    data = request.get_json(silent=True) or {}
    row = db.session.get(SensorNonce, str(data.get("nonce", "")))
    if (row is None or row.used or row.sid != g.sid
            or datetime.utcnow() - row.issued_at > NONCE_TTL):
        return jsonify({"error": "invalid or expired nonce"}), 400
    row.used = True

    signals = data.get("signals") or {}
    started = time.perf_counter()
    score, reasons, verdict = evaluate_sensor(signals, request.headers, DEFENSE_LEVEL)
    g.sensor_ms = (time.perf_counter() - started) * 1000

    db.session.add(SensorVerdict(
        sid=g.sid, level=DEFENSE_LEVEL, ua_string=request.headers.get("User-Agent", ""),
        score=score, verdict=verdict, reasons=json.dumps(reasons),
        signals=json.dumps(signals), score_ms=g.sensor_ms))
    db.session.commit()
    if verdict == "suspicious":
        app.logger.warning("Suspicious sensor | score=%d | %s", score, reasons)
    # Never tell the client its verdict: that would be a free oracle.
    return jsonify({"ok": True})


@app.route("/api/products")
def products():
    require_sensor_verdict()
    return jsonify({"products": PRODUCTS})


@app.route("/api/cart", methods=["POST"])
def cart():
    verdict = require_sensor_verdict()
    data = request.get_json(silent=True) or {}
    if verdict is not None:
        score, reasons, decision = evaluate_action(
            verdict.score, json.loads(verdict.reasons), data.get("interaction"),
            json.loads(verdict.signals), DEFENSE_LEVEL)
        if decision == "bot" and DEFENSE_LEVEL >= 1:
            g.block_reasons = reasons
            abort(403)
    db.session.add(CartItem(sid=g.sid, product_id=int(data.get("product_id") or 0)))
    db.session.commit()
    return jsonify({"ok": True, "cart_size": CartItem.query.filter_by(sid=g.sid).count()})


# ---------------------------------------------------------------- debug endpoints

@app.route("/sensor-check")
def sensor_check():
    """Debug: how the server scored this session's latest sensor payload."""
    verdict = latest_verdict(g.sid)
    return jsonify({
        "level": DEFENSE_LEVEL,
        "edge": g.edge,
        "sensor": None if verdict is None else {
            "score": verdict.score, "verdict": verdict.verdict,
            "reasons": json.loads(verdict.reasons), "score_ms": verdict.score_ms,
        },
    })


@app.route("/sensor-logs")
def sensor_logs():
    """Debug: the last 50 sensor verdicts, all sessions."""
    rows = SensorVerdict.query.order_by(SensorVerdict.created_at.desc()).limit(50).all()
    return jsonify([{
        "time": r.created_at.isoformat(), "sid": r.sid[:6], "level": r.level,
        "ua": r.ua_string, "score": r.score, "verdict": r.verdict,
        "reasons": json.loads(r.reasons),
    } for r in rows])


# Captured headers per session, so /capture can save a complete profile
_captures = {}


@app.route("/capture")
def capture_page():
    """Open in YOUR browser to save it as a legitimate-user profile."""
    _captures[g.sid] = {"navigation_headers": [[k, v] for k, v in request.headers]}
    return render_template("capture.html")


@app.route("/capture/echo")
def capture_echo():
    _captures.setdefault(g.sid, {})["fetch_headers"] = [[k, v] for k, v in request.headers]
    return jsonify({"ok": True})


@app.route("/capture/save", methods=["POST"])
def capture_save():
    data = request.get_json(silent=True) or {}
    name = re.sub(r"[^a-z0-9-]", "-", str(data.get("name", "my-browser")).lower())[:40]
    captured = _captures.get(g.sid, {})
    if "navigation_headers" not in captured or "fetch_headers" not in captured:
        return jsonify({"error": "reload /capture first"}), 400
    profile = {
        "name": f"captured-{name}",
        "description": "Captured from a real browser with /capture",
        "source": "captured",
        "captured": datetime.utcnow().date().isoformat(),
        **captured,
        "post_headers": [[k, v] for k, v in request.headers],
        "signals": data.get("signals"),
        "interaction": data.get("interaction"),
    }
    os.makedirs(PROFILES_DIR, exist_ok=True)
    path = os.path.join(PROFILES_DIR, f"{profile['name']}.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)
    return jsonify({"ok": True, "path": os.path.relpath(path, os.path.join(HERE, ".."))})


@app.errorhandler(403)
def forbidden(e):
    # Returning the reasons is a teaching aid. In production NEVER tell the
    # client which rule fired: it turns your defense into a free oracle.
    return jsonify({"error": "forbidden", "reasons": g.get("block_reasons", [])}), 403


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL}")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("LAB_DEBUG") == "1", use_reloader=True)
