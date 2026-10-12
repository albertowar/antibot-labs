"""
Chapter 7 Lab: the demo store on drop day, with an ML scoring layer.

A limited sneaker drop. Real customers and scalper bots walk the same
journey: home → browse → /product/drop → /cart/add → /checkout. The store
logs every request and every telemetry beacon. That event log is the
training data. At checkout the session is scored and the decision applied.

    DEFENSE_LEVEL=0 python demo_site/app.py   # log only (collect the training data)
    DEFENSE_LEVEL=1 python demo_site/app.py   # Round 1: deployed model v2 + anomaly, oracle guard
    DEFENSE_LEVEL=2 python demo_site/app.py   # Round 2: robust model v3 (adversarial + monotone)
    DEFENSE_LEVEL=3 python demo_site/app.py   # Round 3: provenance-sanitized model v4
    DEFENSE_LEVEL=4 python demo_site/app.py   # Round 4: SMOTE-augmented model v5

Lab endpoints (never scored): /lab/status, /orders/<id>

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///ml_lab.db to run without Docker (run every lab
command from the lab/ folder so they all find the same file).

Network: the client IP comes from `X-Lab-Client-IP` (the simulated edge,
tools/labclient.py), and is only trusted from 127.0.0.1.

Every checkout response carries `Server-Timing: mlscore;dur=<ms>`, so the
checkpoint can report what the model costs, not just what it catches.
"""

import hashlib
import json
import os
import secrets
import sys
import time

from flask import Flask, abort, g, jsonify, render_template_string, request
from sqlalchemy import insert, select, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

import oracle_guard  # noqa: E402
from netinfo import ip24  # noqa: E402
from scorer import Scorer  # noqa: E402
from store import (LAB_TIME_SCALE, init_db, logins_t, make_engine, orders_t,  # noqa: E402
                   requests_t, sessions_t, telemetry_t)

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
ASSET_PREFIXES = ("/static/", "/img/")
UNLOGGED = ("/lab/", "/orders/")

app = Flask(__name__)
engine = make_engine()
init_db(engine)
scorer = Scorer(DEFENSE_LEVEL)


def client_ip():
    if request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Lab-Client-IP", request.remote_addr)
    return request.remote_addr


@app.before_request
def start_session():
    g.started = time.time()
    if request.path.startswith(UNLOGGED):
        return
    g.sid = request.cookies.get("sid")
    g.new_sid = g.sid is None
    if g.new_sid:
        g.sid = secrets.token_hex(12)
        with engine.begin() as conn:
            conn.execute(insert(sessions_t).values(sid=g.sid, first_ts=g.started, ip=client_ip(),
                                                ip24=ip24(client_ip())))


@app.after_request
def log_request(response):
    if request.path.startswith(UNLOGGED) or "sid" not in g:
        return response
    if g.new_sid:
        response.set_cookie("sid", g.sid, httponly=True, samesite="Lax")
    with engine.begin() as conn:
        conn.execute(insert(requests_t).values(
            sid=g.sid, ts=g.started, method=request.method, path=request.path,
            status=response.status_code, ip=client_ip(),
            ua=request.headers.get("User-Agent", ""),
            referer=request.headers.get("Referer", ""),
            accept_language=request.headers.get("Accept-Language", ""),
            sec_fetch_site=request.headers.get("Sec-Fetch-Site", ""),
            is_asset=int(request.path.startswith(ASSET_PREFIXES)),
            bytes_out=response.calculate_content_length() or 0))
    if "score_ms" in g:
        response.headers["Server-Timing"] = f"mlscore;dur={g.score_ms:.2f}"
    return response


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Drop Day Store</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body>
  <h1>{{ title }}</h1>
  <p class="meta">Defense level {{ level }}</p>
  {% if home %}
  <p><a href="/product/drop">Limited drop: Model 7 sneakers</a></p>
  <ul>{% for i in range(1, 9) %}<li><a href="/product/{{ i }}">Product {{ i }}</a></li>{% endfor %}</ul>
  <!-- honeypot (W1 Ch7): invisible to humans, irresistible to crawlers -->
  <a href="/specials-archive" class="hp" aria-hidden="true" tabindex="-1">archive</a>
  {% endif %}
  <img src="/img/{{ img }}.svg" alt="">
  <script src="/static/app.js"></script>
</body></html>"""


def page(title, img="hero", home=False):
    return render_template_string(PAGE, title=title, level=DEFENSE_LEVEL, img=img, home=home)


@app.route("/")
def index():
    return page("Drop Day Store", home=True)


@app.route("/product/<int:pid>")
def product(pid):
    return page(f"Product {pid}", img=str(pid))


@app.route("/product/drop")
def drop():
    return page("Model 7 (limited drop)", img="drop")


@app.route("/img/<name>.svg")
def image(name):
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="320" height="200">'
           f'<rect width="320" height="200" fill="#ddd"/><text x="20" y="100">{name[:12]}</text></svg>')
    return svg, 200, {"Content-Type": "image/svg+xml", "Cache-Control": "max-age=3600"}


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /api/v0/\nDisallow: /specials-archive\n", 200, \
        {"Content-Type": "text/plain"}


# --- honeypots: their hits become bot labels (defenses/labels.py) ----------
@app.route("/specials-archive")
def honeypot_page():
    return page("Archive")


@app.route("/api/v0/products")
def honeypot_api():
    return jsonify({"products": []})


@app.route("/api/telemetry", methods=["POST"])
def telemetry():
    """Fingerprint ('fp') and behavior ('beh') summaries from the page collector."""
    body = request.get_json(silent=True) or {}
    kind, data = body.get("kind"), body.get("data")
    if kind not in ("fp", "beh") or not isinstance(data, dict):
        abort(400)
    payload = json.dumps(data, sort_keys=True)
    fp_hash = hashlib.sha256(payload.encode()).hexdigest() if kind == "fp" else None
    with engine.begin() as conn:
        conn.execute(insert(telemetry_t).values(sid=g.sid, ts=time.time(), kind=kind,
                                                payload=payload, fp_hash=fp_hash, ip=client_ip()))
    return "", 204


@app.route("/login", methods=["POST"])
def login():
    username = (request.get_json(silent=True) or {}).get("username", "")
    with engine.begin() as conn:
        conn.execute(insert(logins_t).values(sid=g.sid, ts=time.time(), account=username))
    return jsonify({"ok": True})


@app.route("/cart/add", methods=["POST"])
def cart_add():
    return jsonify({"ok": True, "cart": ["DROP-1"]})


@app.route("/checkout", methods=["POST"])
def checkout():
    """Score the session, record the order, answer according to DEFENSE_LEVEL."""
    now = time.time()
    risk, p_bot, anomaly = 0.0, None, None
    missing = scorer.missing() if DEFENSE_LEVEL > 0 else []
    if DEFENSE_LEVEL > 0 and not missing:
        t0 = time.perf_counter()
        with engine.connect() as conn:
            s = scorer.score(conn, g.sid, now)
        g.score_ms = (time.perf_counter() - t0) * 1000
        risk, p_bot, anomaly = s["risk"], s["p_bot"], s["anomaly"]
    decision = "unscored" if missing else ("block" if risk >= 1.0 else "allow")
    with engine.begin() as conn:
        # Every attempt is recorded, scored or not: it is tomorrow's training data
        order_id = conn.execute(insert(orders_t).values(
            sid=g.sid, ts=now, level=DEFENSE_LEVEL, score=p_bot, anomaly=anomaly,
            decision=decision, status="pending", review_at=None,
            score_ms=g.get("score_ms")).returning(orders_t.c.id)).scalar_one()
        if missing:
            conn.execute(orders_t.update().where(orders_t.c.id == order_id).values(status="error"))
            return jsonify({"error": "model not trained", "missing": missing,
                            "fix": "run defenses/train.py, or tools/checkpoint.py --catch-up"}), 503
        status, body, order_status = oracle_guard.decide(
            conn, DEFENSE_LEVEL, g.sid, client_ip(), risk, order_id)
        conn.execute(orders_t.update().where(orders_t.c.id == order_id)
                     .values(status=order_status))
    return jsonify(body), status


@app.route("/orders/<int:order_id>")
def order_status(order_id):
    with engine.connect() as conn:
        row = conn.execute(select(orders_t).where(orders_t.c.id == order_id)).mappings().first()
    if row is None:
        abort(404)
    return jsonify({"order_id": order_id, "status": row["status"]})


@app.route("/lab/status")
def lab_status():
    with engine.connect() as conn:
        counts = {t: conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar()
                  for t in ("sessions", "requests", "telemetry", "orders")}
    return jsonify({"level": DEFENSE_LEVEL, "time_scale": LAB_TIME_SCALE,
                    "scoring": scorer.describe(), "rows": counts})


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL} · scoring {scorer.describe()}")
    # debug=False: the reloader and debugger slow every request, which would
    # distort the latency numbers the checkpoint reports.
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), threaded=True)
