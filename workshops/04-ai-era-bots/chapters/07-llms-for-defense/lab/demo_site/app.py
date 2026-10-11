"""
W4 Chapter 7 — The demo store, with a rule engine at checkout and nothing smarter

Same drop-day store as W2 Ch7 (home → browse → /product/drop → /cart/add →
/checkout), minus the ML scoring. Every request is logged with the headers
the client sent. That log is what the LLM analyst reads, offline.

    DEFENSE_LEVEL=0 python demo_site/app.py   # log only
    DEFENSE_LEVEL=1 python demo_site/app.py   # shadow: rules recorded, nobody blocked
    DEFENSE_LEVEL=2 python demo_site/app.py   # enforce: matching checkout → 403

The engine reads rules/active.json and hot-reloads it. Nothing in this
process ever calls a language model: an LLM in the request path would add
seconds of latency, a token bill per request and a prompt-injection surface
on every header. The model's output reaches the edge only as a rule that
the gate replayed and a human approved (tools/approve.py).

Lab endpoints (never logged): /lab/status, /orders/<id>

Storage: SQLite by default (DATABASE_URL=sqlite:///llm_lab.db); run every
lab command from the lab/ folder so they all find the same file.

Network: the client IP comes from `X-Lab-Client-IP` (the simulated edge,
tools/labclient.py) and is only trusted from 127.0.0.1. `X-Lab-Run` tags the
session with the script that sent it, lab bookkeeping that stands in for the
time window you would select in production.

Every checkout response carries `Server-Timing: rules;dur=<ms>` so the
checkpoint reports what the rule engine costs.
"""

import os
import secrets
import sys
import time

from flask import Flask, abort, g, jsonify, render_template_string, request
from sqlalchemy import insert, select, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

from netinfo import ip24  # noqa: E402
from rules import RuleEngine  # noqa: E402
from sessionize import card_for_sid, flatten  # noqa: E402
from store import (MAX_FIELD_BYTES, init_db, logins_t, make_engine, orders_t,  # noqa: E402
                   requests_t, rule_hits_t, sessions_t)

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
ASSET_PREFIXES = ("/static/", "/img/")
UNLOGGED = ("/lab/", "/orders/")

app = Flask(__name__)
engine = make_engine()
init_db(engine)
rule_engine = RuleEngine()


def client_ip():
    if request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Lab-Client-IP", request.remote_addr)
    return request.remote_addr


def lab_run():
    if request.remote_addr in ("127.0.0.1", "::1"):
        return request.headers.get("X-Lab-Run", "manual")[:60]
    return "external"


def cap(value):
    """The database is not the resource the flood gets to exhaust."""
    return (value or "")[:MAX_FIELD_BYTES]


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
                                                ip24=ip24(client_ip()), run=lab_run()))


@app.after_request
def log_request(response):
    # 404s are logged too: a probe for /nonexistent-path is part of the
    # session's story, and the path is text the client wrote.
    if request.path.startswith(UNLOGGED) or "sid" not in g:
        return response
    if g.new_sid:
        response.set_cookie("sid", g.sid, httponly=True, samesite="Lax")
    with engine.begin() as conn:
        conn.execute(insert(requests_t).values(
            sid=g.sid, ts=g.started, method=request.method, path=cap(request.path),
            status=response.status_code, ip=client_ip(),
            ua=cap(request.headers.get("User-Agent", "")),
            referer=cap(request.headers.get("Referer", "")),
            accept_language=cap(request.headers.get("Accept-Language", "")),
            is_asset=int(request.path.startswith(ASSET_PREFIXES)),
            bytes_out=response.calculate_content_length() or 0))
    if "rules_ms" in g:
        response.headers["Server-Timing"] = f"rules;dur={g.rules_ms:.3f}"
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
  <!-- honeypot (W1 Ch8): invisible to humans, irresistible to crawlers -->
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


# --- honeypots: their hits are the strongest server-side bot signal ---------
@app.route("/specials-archive")
def honeypot_page():
    return page("Archive")


@app.route("/api/v0/products")
def honeypot_api():
    return jsonify({"products": []})


@app.route("/login", methods=["POST"])
def login():
    # No password: the lab's login is a label source, not an authentication
    # system. The README lists what that means for the gate's cohort.
    username = (request.get_json(silent=True) or {}).get("username", "")
    with engine.begin() as conn:
        conn.execute(insert(logins_t).values(sid=g.sid, ts=time.time(), account=cap(str(username))))
    return jsonify({"ok": True})


@app.route("/cart/add", methods=["POST"])
def cart_add():
    return jsonify({"ok": True, "cart": ["DROP-1"]})


@app.route("/checkout", methods=["POST"])
def checkout():
    """Evaluate the active rules against this session's card, then decide."""
    now = time.time()
    hit, g.rules_ms = None, 0.0
    if DEFENSE_LEVEL >= 1:
        t0 = time.perf_counter()
        with engine.connect() as conn:
            card = card_for_sid(conn, g.sid)
        hit, _ = rule_engine.evaluate(flatten(card)) if card else (None, 0.0)
        g.rules_ms = (time.perf_counter() - t0) * 1000
    blocked = hit is not None and DEFENSE_LEVEL >= 2
    with engine.begin() as conn:
        if hit is not None:
            conn.execute(insert(rule_hits_t).values(ts=now, sid=g.sid, rule_id=hit.get("id"),
                                                    mode="enforce" if blocked else "shadow"))
        order_id = conn.execute(insert(orders_t).values(
            sid=g.sid, ts=now, level=DEFENSE_LEVEL, decision="block" if blocked else "allow",
            status="blocked" if blocked else "confirmed",
            rule_id=hit.get("id") if hit else None,
            rules_ms=g.rules_ms).returning(orders_t.c.id)).scalar_one()
    if blocked:
        # The rule id stays server-side: telling the client which rule fired
        # is a free oracle (W2 Ch7, Round 3).
        return jsonify({"error": "blocked", "order_id": order_id}), 403
    return jsonify({"order_id": order_id, "status": "confirmed"}), 200


@app.route("/orders/<int:order_id>")
def order_status(order_id):
    with engine.connect() as conn:
        row = conn.execute(select(orders_t).where(orders_t.c.id == order_id)).mappings().first()
    if row is None:
        abort(404)
    return jsonify({"order_id": order_id, "status": row["status"]})


@app.route("/lab/status")
def lab_status():
    rule_engine.reload_if_changed()
    with engine.connect() as conn:
        counts = {t: conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar()
                  for t in ("sessions", "requests", "orders", "verdicts")}
    return jsonify({"level": DEFENSE_LEVEL, "rules": rule_engine.describe(), "rows": counts})


if __name__ == "__main__":
    print(f" * Defense level {DEFENSE_LEVEL} · rules {rule_engine.describe()}")
    # debug=False: the reloader and debugger slow every request and would
    # distort the latency numbers the checkpoint reports.
    # PORT: macOS AirPlay Receiver squats on 5000; use e.g. PORT=5050
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), threaded=True)
