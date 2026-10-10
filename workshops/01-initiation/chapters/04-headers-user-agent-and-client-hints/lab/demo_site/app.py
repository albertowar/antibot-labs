"""
Chapter 4 Lab: Flask store with layered header fingerprinting.

Every request is scored by the layers enabled with DEFENSE_LEVEL (0-4) and
logged to SQLite. Restart the server with a higher level at each round:

    DEFENSE_LEVEL=0 python app.py     # Round 0/1: no defense, log only
    DEFENSE_LEVEL=1 python app.py     # + User-Agent parsing
    DEFENSE_LEVEL=2 python app.py     # + header presence & consistency
    DEFENSE_LEVEL=3 python app.py     # + Client Hints & header order
    DEFENSE_LEVEL=4 python app.py     # + Accept-CH negotiation

- Score >= 40: blocked as bot (403)
- Score >= 20: logged as suspicious, allowed through
- Score < 20: clean

Debug endpoints (never blocked): /header-check, /header-logs

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///header_logs.db to run without Docker.

Every response carries `Server-Timing: headerscore;dur=<ms>` so the
checkpoint tool can report what the defense costs us, not just what it
catches.
"""

import json
import os
import sys
import time
from datetime import datetime

from flask import Flask, abort, g, jsonify, render_template_string, request
from flask_sqlalchemy import SQLAlchemy

# Add defenses directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'defenses'))

from accept_ch import ACCEPT_CH_VALUE, OFFERED_COOKIE
from scoring import evaluate

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
DEBUG_PATHS = {"/header-check", "/header-logs"}
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "[::1]"}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class HeaderLog(db.Model):
    """Log table for header fingerprint analysis results."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.Integer)
    ip = db.Column(db.String(50))
    path = db.Column(db.String(200))
    ua_string = db.Column(db.Text)
    score = db.Column(db.Integer)
    verdict = db.Column(db.String(20))
    reasons = db.Column(db.Text)


with app.app_context():
    db.create_all()


def score_current_request():
    """Run the scoring engine on the current Flask request."""
    # EnvironHeaders iterates in the order the server received the headers
    header_names = [name for name, _ in request.headers]
    secure_context = request.is_secure or request.host.split(":")[0] in LOCALHOST_NAMES
    return evaluate(
        headers=request.headers,
        header_names=header_names,
        cookies=request.cookies,
        host=request.host,
        secure_context=secure_context,
        level=DEFENSE_LEVEL,
    )


@app.before_request
def check_and_log_headers():
    """Score every request's headers, log the result and block bots."""
    if request.path == "/header-logs":
        return

    started = time.perf_counter()
    score, reasons, verdict = score_current_request()
    g.score_ms = (time.perf_counter() - started) * 1000
    g.score, g.reasons, g.verdict = score, reasons, verdict

    db.session.add(HeaderLog(
        level=DEFENSE_LEVEL,
        ip=request.remote_addr,
        path=request.path,
        ua_string=request.headers.get("User-Agent", ""),
        score=score,
        verdict=verdict,
        reasons=json.dumps(reasons),
    ))
    db.session.commit()

    if request.path in DEBUG_PATHS:
        return
    if verdict == "bot":
        abort(403)
    elif verdict == "suspicious":
        app.logger.warning(
            "Suspicious request | score=%d | reasons=%s | ip=%s",
            score, reasons, request.remote_addr
        )


@app.after_request
def offer_client_hints(response):
    """Report the scoring cost; at level 4, ask Chromium for high-entropy hints."""
    if "score_ms" in g:
        response.headers["Server-Timing"] = f"headerscore;dur={g.score_ms:.3f}"
    if DEFENSE_LEVEL >= 4:
        response.headers["Accept-CH"] = ACCEPT_CH_VALUE
        if OFFERED_COOKIE not in request.cookies:
            response.set_cookie(OFFERED_COOKIE, "1", httponly=True, samesite="Lax")
    return response


INDEX_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Bot Workshop Store</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}
code{background:#eee;padding:0 .3rem}</style></head>
<body>
  <h1>Welcome to the store!</h1>
  <p>Defense level: <code>{{ level }}</code> &middot;
     <a href="/header-check">/header-check</a> &middot;
     <a href="/header-logs">/header-logs</a></p>
  <h2>Products</h2>
  <ul id="products"><li>Loading&hellip;</li></ul>
  <script>
    // A same-origin fetch: compare its Sec-Fetch-* headers with the navigation's
    fetch("/api/products")
      .then(r => r.json())
      .then(data => {
        document.getElementById("products").innerHTML = data.products
          .map(p => `<li>${p.name} &mdash; $${p.price}</li>`).join("");
      });
  </script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, level=DEFENSE_LEVEL)


@app.route("/api/products")
def products():
    return jsonify({"products": [
        {"id": 1, "name": "Widget", "price": 9.99},
        {"id": 2, "name": "Gadget", "price": 24.99},
        {"id": 3, "name": "Doohickey", "price": 4.99},
    ]})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username == "admin" and password == "secret":
        return jsonify({"token": "fake-jwt-token-abc123"})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/header-logs")
def header_logs():
    """View recent header fingerprint logs."""
    logs = HeaderLog.query.order_by(HeaderLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "level": log.level,
        "ip": log.ip,
        "path": log.path,
        "ua_string": log.ua_string,
        "score": log.score,
        "verdict": log.verdict,
        "reasons": json.loads(log.reasons),
    } for log in logs])


@app.route("/header-check")
def header_check():
    """Debug endpoint: see how the server scores your current request headers."""
    return jsonify({
        "level": DEFENSE_LEVEL,
        "score": g.score,
        "verdict": g.verdict,
        "reasons": g.reasons,
        # A list, not a dict, so the arrival order is visible
        "headers_received": [[name, value] for name, value in request.headers],
    })


@app.errorhandler(403)
def forbidden(e):
    # Returning the reasons is a teaching aid. In production NEVER tell the
    # attacker which rule fired: it turns your defense into a free oracle.
    return jsonify({
        "error": "forbidden",
        "message": "Request blocked: headers indicate automated client.",
        "score": g.get("score"),
        "reasons": g.get("reasons", []),
    }), 403


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL}")
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")))
