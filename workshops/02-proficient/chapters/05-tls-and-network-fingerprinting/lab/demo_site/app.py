"""
Chapter 5 Lab: the demo store behind a fingerprinting TLS edge.

    browser / bot ──TLS──▶ fingerproxy :8443 ──HTTP + X-JA4/X-HTTP2 headers──▶ Flask :5000

Flask never sees the handshake. fingerproxy (tools/edge.py) terminates TLS,
computes JA3, JA4 and the HTTP/2 fingerprint, and forwards them as headers.
Every request is scored by the layers enabled with DEFENSE_LEVEL (0-4) and
logged. Restart the server with a higher level at each round:

    DEFENSE_LEVEL=0 python demo_site/app.py   # Round 0: log only
    DEFENSE_LEVEL=1 python demo_site/app.py   # + edge check, JA4 library denylist
    DEFENSE_LEVEL=2 python demo_site/app.py   # + UA ↔ TLS family
    DEFENSE_LEVEL=3 python demo_site/app.py   # + HTTP/2 fingerprint ↔ TLS family
    DEFENSE_LEVEL=4 python demo_site/app.py   # + JS engine proof for browser TLS

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the
reference solutions over your defenses/ files.

- Score >= 40: blocked as bot (403)
- Score >= 20: logged as suspicious, allowed through

Debug endpoints (never blocked): /tls-check, /tls-logs

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///tls_logs.db to run without Docker.

Every response carries `Server-Timing: tlsscore;dur=<ms>` so the checkpoint
can report what scoring costs us, not just what it catches.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

from flask import Flask, abort, g, jsonify, render_template_string, request
from flask_sqlalchemy import SQLAlchemy

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

from edge_headers import from_headers  # noqa: E402
from scoring import evaluate  # noqa: E402
import browser_proof  # noqa: E402  (same module object scoring.py loaded)

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
DEBUG_PATHS = {"/tls-check", "/tls-logs"}
PRODUCTS = [
    {"id": 1, "name": "Widget", "price": 9.99},
    {"id": 2, "name": "Gadget", "price": 24.99},
    {"id": 3, "name": "Doohickey", "price": 4.99},
]

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class TlsLog(db.Model):
    """One row per request: what the edge saw and what we decided."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    level = db.Column(db.Integer)
    path = db.Column(db.String(200))
    ua_string = db.Column(db.Text)
    ja4 = db.Column(db.String(64))
    ja3 = db.Column(db.String(64))
    h2 = db.Column(db.Text)
    tls_engine = db.Column(db.String(20))
    score = db.Column(db.Integer)
    verdict = db.Column(db.String(20))
    reasons = db.Column(db.Text)


with app.app_context():
    db.create_all()


@app.before_request
def score_and_log():
    """Score every request's edge fingerprint, log the result and block bots."""
    if request.path == "/tls-logs":
        return

    started = time.perf_counter()
    fp = from_headers(request.headers)
    score, reasons, verdict, engine = evaluate(
        fp, request.headers, request.cookies, request.path, DEFENSE_LEVEL)
    g.score_ms = (time.perf_counter() - started) * 1000
    g.fp, g.score, g.reasons, g.verdict, g.engine = fp, score, reasons, verdict, engine

    db.session.add(TlsLog(
        level=DEFENSE_LEVEL,
        path=request.path,
        ua_string=request.headers.get("User-Agent", ""),
        ja4=fp.ja4, ja3=fp.ja3, h2=fp.h2,
        tls_engine=engine,
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
        app.logger.warning("Suspicious request | score=%d | reasons=%s", score, reasons)


@app.after_request
def report_cost(response):
    if "score_ms" in g:
        response.headers["Server-Timing"] = f"tlsscore;dur={g.score_ms:.3f}"
    return response


INDEX_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Bot Workshop Store</title>
<style>body{font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}
code{background:#eee;padding:0 .3rem;word-break:break-all}</style></head>
<body>
  <h1>Welcome to the store!</h1>
  <p>Defense level: <code>{{ level }}</code> &middot;
     <a href="/tls-check">/tls-check</a> &middot; <a href="/tls-logs">/tls-logs</a> &middot;
     <a href="/products">no-JS product list</a></p>
  <p>Your JA4: <code>{{ ja4 or "none (not via the edge)" }}</code><br>
     Your HTTP/2: <code>{{ h2 or "none (HTTP/1.1)" }}</code></p>
  <h2>Products</h2>
  <ul id="products"><li>Loading&hellip;</li></ul>
  <script>
    // Layer 4: earn an engine_proof cookie. The TypeError text and the length
    // of eval's source differ between V8, SpiderMonkey and JavaScriptCore.
    function engineSignals() {
      let message = "";
      try { null.f(); } catch (e) { message = e.message; }
      return {nonce: "{{ nonce }}", error_message: message, eval_length: eval.toString().length};
    }
    async function main() {
      await fetch("/api/engine", {method: "POST", headers: {"Content-Type": "application/json"},
                                  body: JSON.stringify(engineSignals())});
      const r = await fetch("/api/products");
      const data = await r.json();
      window.__productsStatus = r.status;
      document.getElementById("products").innerHTML = r.ok
        ? data.products.map(p => `<li>${p.name} &mdash; $${p.price}</li>`).join("")
        : `<li>Blocked (${r.status}): ${data.reasons.join("; ")}</li>`;
    }
    main();
  </script>
</body>
</html>"""

PRODUCTS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Products</title></head>
<body><h1>Products</h1><ul>
{% for p in products %}<li>{{ p.name }} &mdash; ${{ p.price }}</li>{% endfor %}
</ul></body></html>"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML, level=DEFENSE_LEVEL, ja4=g.fp.ja4, h2=g.fp.h2,
                                  nonce=browser_proof.issue_nonce())


@app.route("/products")
def products_page():
    """Server-rendered list: what a visitor without JavaScript can still use."""
    return render_template_string(PRODUCTS_HTML, products=PRODUCTS)


@app.route("/api/products")
def products():
    return jsonify({"products": PRODUCTS})


@app.route("/api/engine", methods=["POST"])
def engine_proof():
    """Layer 4: turn the page's JS signals into a signed, TLS-bound cookie."""
    data = request.get_json(silent=True) or {}
    if not g.fp.present or not browser_proof.nonce_valid(data.get("nonce", "")):
        return jsonify({"error": "bad nonce or no edge fingerprint"}), 400
    engine = browser_proof.classify_engine(data.get("error_message", ""), data.get("eval_length", 0))
    if engine is None:
        return jsonify({"error": "unrecognised JS engine"}), 400
    response = jsonify({"engine": engine})
    response.set_cookie(browser_proof.COOKIE, browser_proof.make_cookie(engine, g.fp.ja4_b),
                        max_age=browser_proof.TTL_SECONDS, httponly=True, secure=True, samesite="Lax")
    return response


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == "admin" and data.get("password") == "secret":
        return jsonify({"token": "fake-jwt-token-abc123"})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/tls-check")
def tls_check():
    """Debug endpoint: what the edge saw for *this* request, and how we scored it."""
    fp = g.fp
    return jsonify({
        "level": DEFENSE_LEVEL,
        "ja4": fp.ja4,
        "ja4_ab": fp.ja4_ab,
        "ja3": fp.ja3,
        "http2": fp.h2,
        "http_version": fp.http_version,
        "tls_engine": g.engine,
        "user_agent": request.headers.get("User-Agent"),
        "score": g.score,
        "verdict": g.verdict,
        "reasons": g.reasons,
    })


@app.route("/tls-logs")
def tls_logs():
    """Recent decisions, newest first."""
    logs = TlsLog.query.order_by(TlsLog.id.desc()).limit(50).all()
    return jsonify([{
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "level": log.level,
        "path": log.path,
        "ua_string": log.ua_string,
        "ja4": log.ja4,
        "http2": log.h2,
        "tls_engine": log.tls_engine,
        "score": log.score,
        "verdict": log.verdict,
        "reasons": json.loads(log.reasons),
    } for log in logs])


@app.errorhandler(403)
def forbidden(e):
    # Returning the reasons is a teaching aid. In production NEVER tell the
    # attacker which rule fired: it turns your defense into a free oracle.
    return jsonify({
        "error": "forbidden",
        "message": "Request blocked: TLS/HTTP fingerprint indicates an automated client.",
        "score": g.get("score"),
        "reasons": g.get("reasons", []),
    }), 403


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL}")
    # Bind to loopback only: the edge is the only thing that should reach us.
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050 (and the same for tools/edge.py)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("LAB_DEBUG") == "1", use_reloader=True)
