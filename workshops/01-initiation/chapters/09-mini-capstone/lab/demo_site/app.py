"""
W1 Ch9 Lab: the demo store on drop day.

The W1 end state of the series' demo store (Flask + Redis + PostgreSQL),
and the starter state for Workshop 2. Twenty limited-edition hoodies go on
sale at once; 40 simulated shoppers and up to five scalper waves want them.

Every request passes ONE gate (`gate()` below):
    defenses/pipeline.py  which layers run, in which order    (you wire it)
    defenses/policy.py    how many points each signal is worth (you tune it)
    defenses/ladder.py    sum -> allow / monitor / challenge / block

    python demo_site/app.py          # http://localhost:5000; restart it after editing a defense file

Storage: Redis (sessions, rate-limit buckets, trap flags, used PoW nonces)
and PostgreSQL (stock and orders) from ../docker-compose.yml. Without
Docker: REDIS_URL=fakeredis:// DATABASE_URL=sqlite:///shop.db.

Lab-only behaviour, never do this in production:
  - X-Lab-Verdict / X-Lab-Score / X-Lab-Signals response headers tell the
    client exactly which rule fired. Real defenses keep that to themselves.
  - /admin/* endpoints are unauthenticated (they only answer on loopback,
    via the lab edge).

Debug endpoint, scored but never blocked: /whoami
"""

import json
import os
import secrets
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from flask import Flask, g, jsonify, make_response, render_template_string, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(LAB, "defenses"))

import ip_reputation  # noqa: E402
import ladder  # noqa: E402
import pipeline  # noqa: E402
import policy  # noqa: E402
import proof_of_work  # noqa: E402
import traps  # noqa: E402
from lab_edge import LabEdge  # noqa: E402
from session_guard import COOKIE, TTL, Session  # noqa: E402
from store import get_redis  # noqa: E402

DROP_STOCK = 20
PORT = int(os.environ.get("PORT", "5000"))
LOG_FILE = os.path.join(LAB, "logs", "decisions.jsonl")

app = Flask(__name__)
app.wsgi_app = LabEdge(app.wsgi_app, os.path.join(LAB, "data", "world.json"))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"timeout": 30, "check_same_thread": False}}
db = SQLAlchemy(app)


class Product(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Integer)
    stock = db.Column(db.Integer)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    product_id = db.Column(db.String(32))
    email = db.Column(db.String(200))
    size = db.Column(db.String(8))
    actor = db.Column(db.String(64))      # ground-truth label from the lab edge; defenses never see it
    ip = db.Column(db.String(64))
    session_id = db.Column(db.String(64))
    score = db.Column(db.Integer)
    decision = db.Column(db.String(16))


def reset_stock():
    Order.query.delete()
    for pid, name, price, stock in (("hoodie", "Drop Hoodie (limited)", 89, DROP_STOCK),
                                    ("tee", "Workshop Tee", 25, 500)):
        product = db.session.get(Product, pid)
        if product is None:
            db.session.add(Product(id=pid, name=name, price=price, stock=stock))
        else:
            product.stock = stock
    db.session.commit()


ip_reputation.reputation()     # load the feeds once, before the first request

with app.app_context():
    db.create_all()
    if db.session.get(Product, "hoodie") is None:
        reset_stock()


# --- Measurement: what every actor experienced ---------------------------------

_stats_lock = threading.Lock()
STATS = defaultdict(Counter)       # actor -> Counter of outcomes
GATE_MS = []                       # gate cost per request
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def record(actor, outcome, result=None, gate_ms=None):
    with _stats_lock:
        STATS[actor][outcome] += 1
        if gate_ms is not None:
            GATE_MS.append(gate_ms)
        if result is not None:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps({
                    "ts": time.time(), "actor": actor, "ip": request.remote_addr,
                    "method": request.method, "path": request.path, "outcome": outcome,
                    "result": {"verdict": result.decision, "flags": result.flags(),
                               "risk_score": result.score},
                }) + "\n")


# --- The gate --------------------------------------------------------------------

def pipeline_config():
    return {
        "layers": [f"{f.__module__}.{f.__name__}" for f in pipeline.LAYERS],
        "challenge_enabled": pipeline.CHALLENGE_ENABLED,
        "purchases_per_session": pipeline.PURCHASES_PER_SESSION,
    }


@app.before_request
def gate():
    """Score every request with the layers in pipeline.LAYERS, then enforce the verdict."""
    if request.path.startswith("/admin/"):
        return None
    redis = get_redis()
    network = ip_reputation.lookup(request.remote_addr)
    session = Session.load_or_create(redis, request.cookies.get(COOKIE), network)
    ctx = ladder.RequestContext(
        ip=request.remote_addr, network=network, method=request.method, path=request.path,
        host=request.host, headers=request.headers, header_names=[n for n, _ in request.headers],
        cookies=request.cookies, form=request.form, session=session, redis=redis,
    )
    started = time.perf_counter()
    result = ladder.run_gate(ctx, pipeline.LAYERS, pipeline.CHALLENGE_ENABLED)
    g.gate_ms = (time.perf_counter() - started) * 1000
    g.session, g.network, g.result = session, network, result
    actor = request.environ.get("lab.actor", "you")

    if request.path == "/whoami":
        record(actor, "whoami", result, g.gate_ms)
        return None
    if result.rate_limited:
        record(actor, "rate_limited", result, g.gate_ms)
        return page("Slow down", "<p>Too many requests. Try again in a moment.</p>", 429)
    if result.decision == "block":
        if result.deceive:
            record(actor, "deceived", result, g.gate_ms)
            return fake_success()
        record(actor, "blocked", result, g.gate_ms)
        return page("Access denied", "<p>Your request was blocked.</p>", 403)
    record(actor, result.decision, result, g.gate_ms)
    return None


@app.after_request
def lab_headers(response):
    if "session" in g and g.session.new:
        response.set_cookie(COOKIE, g.session.sid, max_age=TTL, httponly=True, samesite="Lax")
    if "result" in g:
        response.headers["Server-Timing"] = f"gate;dur={g.gate_ms:.3f}"
        # Teaching only: never tell a real client which rule fired.
        response.headers["X-Lab-Verdict"] = g.result.decision
        response.headers["X-Lab-Score"] = str(g.result.score)
        response.headers["X-Lab-Signals"] = ",".join(g.result.flags())
    return response


def fake_success():
    """What a trapped bot sees: exactly what a buyer sees, minus the hoodie."""
    if request.method == "POST":
        return page("Order confirmed", CONFIRM_HTML.format(order=secrets.randbelow(90000) + 10000))
    if request.path == "/drop":
        return page("Drop Hoodie", "<h1>Drop Hoodie</h1><p>Sold out. Thanks for your interest!</p>")
    return page("VIP presale", "<p>The VIP presale opens soon. Check back later!</p>")


# --- Pages ---------------------------------------------------------------------------

BASE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ title }} · Drop Store</title>
<style>body{font-family:system-ui;max-width:38rem;margin:2.5rem auto;padding:0 1rem;line-height:1.5}
.hp{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
label{display:block;margin:.6rem 0} button{font-size:1.1rem;padding:.4rem 1.2rem}
code{background:#eee;padding:0 .3rem}</style></head>
<body>{{ body|safe }}</body></html>"""

JS_COOKIE = """<script>
  // W1 Ch5: proof that this page's JavaScript ran, in this browser
  document.cookie = "js_ok=" + "{nonce}".split("").reverse().join("") + "; path=/; SameSite=Lax";
</script>"""

INDEX_HTML = """<h1>Drop Store</h1>
<p>Today only: <a href="/drop">the limited-edition Drop Hoodie</a>, {stock} left.</p>
<p>Also in stock: the Workshop Tee.</p>
<a class="vh" href="{trap}" aria-hidden="true" tabindex="-1" rel="nofollow">VIP presale</a>
<p><small>Lab: <a href="/whoami">/whoami</a> shows how the gate scored this request.</small></p>
{js}"""

DROP_HTML = """<h1>Drop Hoodie</h1>
<p>$89 · <strong>{stock}</strong> left · one per customer</p>
{message}
<form id="checkout" method="post" action="/checkout" data-bits="{bits}">
  <input type="hidden" name="csrf" value="{csrf}">
  <label>Email <input name="email" type="email" autocomplete="email" required></label>
  <label>Size <select name="size"><option>S</option><option selected>M</option><option>L</option><option>XL</option></select></label>
  <div class="hp" aria-hidden="true"><label>Leave this empty
    <input name="{honeypot}" tabindex="-1" autocomplete="off"></label></div>
  {pow_fields}
  <button id="buy">Buy now</button> <span id="status"></span>
</form>
{js}
<script>
  // W1 Ch7: solve the proof of work in the browser before submitting
  const form = document.getElementById("checkout");
  const challenge = form.querySelector("[name=pow_challenge]");
  function zeroBits(d) {{ let b = 0; for (const x of d) {{ if (x === 0) {{ b += 8; continue; }} return b + Math.clz32(x) - 24; }} return b; }}
  async function solve(ch, bits) {{
    const enc = new TextEncoder();
    for (let c = 0; ; c++) {{
      const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(ch + ":" + c)));
      if (zeroBits(d) >= bits) return c;
    }}
  }}
  if (challenge) form.addEventListener("submit", async (e) => {{
    e.preventDefault();
    document.getElementById("status").textContent = "Checking your browser…";
    form.querySelector("[name=pow_counter]").value = await solve(challenge.value, +form.dataset.bits);
    form.submit();
  }});
</script>"""

POW_FIELDS = """<input type="hidden" name="pow_challenge" value="{challenge}">
  <input type="hidden" name="pow_counter" value="">"""

CONFIRM_HTML = "<h1>Order confirmed</h1><p>Order #{order}: one Drop Hoodie is on its way.</p>"


def page(title, body, status=200):
    return make_response(render_template_string(BASE_HTML, title=title, body=body), status)


def drop_page(message="", status=200):
    """Render the form. From Round 4 it carries a PoW sized by this request's band."""
    session = g.session
    session.set("form_served_at", f"{time.time():.3f}")
    bits, pow_fields = 0, ""
    if pipeline.CHALLENGE_ENABLED:
        bits = policy.POW_BITS.get(g.result.decision, policy.POW_BITS["challenge"])
        pow_fields = POW_FIELDS.format(challenge=proof_of_work.issue(session, g.network, bits))
    return page("Drop Hoodie", DROP_HTML.format(
        stock=db.session.get(Product, "hoodie").stock, message=message, bits=bits,
        csrf=session.get("csrf"), honeypot=policy.HONEYPOT_FIELD, pow_fields=pow_fields,
        js=JS_COOKIE.format(nonce=session.get("js_nonce"))), status)


@app.route("/")
def index():
    return page("Home", INDEX_HTML.format(stock=db.session.get(Product, "hoodie").stock,
                                          trap=traps.TRAP_LINK,
                                          js=JS_COOKIE.format(nonce=g.session.get("js_nonce"))))


@app.route("/robots.txt")
def robots():
    return make_response(f"User-agent: *\nDisallow: {traps.TRAP_LINK}\n", 200, {"Content-Type": "text/plain"})


@app.route("/drop")
def drop():
    return drop_page()


@app.route("/checkout", methods=["POST"])
def checkout():
    session, actor = g.session, request.environ.get("lab.actor", "you")
    if request.form.get("csrf") != session.get("csrf"):
        record(actor, "bad_form")
        return page("Expired", "<p>Your form expired. <a href='/drop'>Reload the page</a>.</p>", 400)

    cap = pipeline.PURCHASES_PER_SESSION
    if cap and int(session.get("purchases", "0")) >= cap:
        record(actor, "over_cap")
        return page("Limit reached", f"<p>Limit {cap} per customer.</p>", 409)

    if pipeline.CHALLENGE_ENABLED:
        required = policy.POW_BITS.get(g.result.decision, policy.POW_BITS["challenge"])
        ok, why = proof_of_work.verify(get_redis(), request.form.get("pow_challenge", ""),
                                       request.form.get("pow_counter", ""), session, g.network, required)
        if not ok:
            record(actor, "challenged")
            return drop_page(f"<p><em>Please try again ({why}).</em></p>", 401)

    sold = db.session.execute(text(
        "UPDATE product SET stock = stock - 1 WHERE id = 'hoodie' AND stock > 0")).rowcount
    if not sold:
        db.session.commit()
        record(actor, "sold_out")
        return page("Sold out", "<p>Sorry, the Drop Hoodie is sold out.</p>", 410)
    order = Order(product_id="hoodie", email=request.form.get("email", "")[:200],
                  size=request.form.get("size", "")[:8], actor=actor, ip=request.remote_addr,
                  session_id=session.sid, score=g.result.score, decision=g.result.decision)
    db.session.add(order)
    db.session.commit()
    session.incr("purchases")
    record(actor, "purchased")
    return page("Order confirmed", CONFIRM_HTML.format(order=order.id + 10000))


@app.route("/api/stock")
def stock():
    return jsonify({p.id: p.stock for p in Product.query.all()})


@app.route(traps.TRAP_LINK)
def vip_presale():
    return fake_success()


@app.route("/whoami")
def whoami():
    """Debug: how the gate scored THIS request, and what the session remembers."""
    r, s = g.result, g.session
    return jsonify({
        "ip": request.remote_addr, "network": g.network,
        "score": r.score, "decision": r.decision,
        "signals": [vars(sig) for sig in r.signals],
        "pipeline": pipeline_config(),
        "session": {"new": s.new, "age_s": round(time.time() - float(s.get("created_at")), 1),
                    "asn": s.get("asn"), "purchases": s.get("purchases"), "flags": s.flags()},
        "headers_in_order": [n for n, _ in request.headers],
        "gate_ms": round(g.gate_ms, 3),
    })


# --- Lab admin (loopback only, through the lab edge) ------------------------------------

@app.route("/admin/reset-drop", methods=["POST"])
def reset_drop():
    """Restock, forget every session, bucket and trap flag, and zero the counters."""
    reset_stock()
    get_redis().flushdb()
    with _stats_lock:
        STATS.clear()
        GATE_MS.clear()
        open(LOG_FILE, "w").close()       # the log always holds the latest drop
    return jsonify({"stock": DROP_STOCK, "pipeline": pipeline_config()})


@app.route("/admin/scoreboard")
def scoreboard():
    orders = Counter(o.actor for o in Order.query.filter_by(product_id="hoodie"))
    with _stats_lock:
        stats = {actor: dict(c) for actor, c in STATS.items()}
        timings = sorted(GATE_MS)
    p = (lambda q: timings[min(len(timings) - 1, int(q * len(timings)))] if timings else None)
    return jsonify({
        "stock": db.session.get(Product, "hoodie").stock, "sold": dict(orders),
        "outcomes": stats, "gate_ms": {"median": p(0.5), "p95": p(0.95), "requests": len(timings)},
        "pipeline": pipeline_config(),
    })


@app.route("/admin/config")
def config():
    return jsonify({"pipeline": pipeline_config(), "bands": policy.BANDS,
                    "pow_bits": policy.POW_BITS, "rate_limits": policy.RATE_LIMITS})


if __name__ == '__main__':
    print(f"Drop store on http://localhost:{PORT}  layers: {pipeline_config()['layers'] or 'none'}")
    app.run(port=PORT, threaded=True)
