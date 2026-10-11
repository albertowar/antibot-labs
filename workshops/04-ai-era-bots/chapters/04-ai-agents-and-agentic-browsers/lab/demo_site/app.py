"""
W4 Ch4 — Demo store: the Lab Store, at its "end of Workshop 2" state plus agent policy

The shared Flask + Redis + PostgreSQL store (SQLite and an in-memory Redis by
default, so no Docker is needed). It sells a small catalogue and one limited
drop ("Lab Runner 9", one unit per account). The protected action is
POST /api/checkout; every decision goes through defenses/risk_engine.py.

    DEFENSE_LEVEL=0  the W1 request checks (headers, per-egress rate). The end-of-W2 browser
                     stack (automation flags, fingerprint coherence, behavior/flow) runs in
                     SHADOW at every level: you see its points, it never decides.
    DEFENSE_LEVEL=1  + agent policy: declared agents may browse, not buy      (Round 1)
    DEFENSE_LEVEL=2  + agent behavior: robotic sessions get a challenge      (Round 2)
    DEFENSE_LEVEL=3  + verified identity: signed agents from trusted operators may buy (Round 3)
    DEFENSE_LEVEL=4  + checkout gate: mandates, human step-up, per-account/device caps (Round 4)

Run (from lab/):
    python demo_site/app.py                       # DEFENSE_LEVEL=0, http://127.0.0.1:8404
    DEFENSE_LEVEL=2 PORT=8404 python demo_site/app.py

Debug endpoints, never blocked: /whoami (how this request is classified and
scored), /agent-policy (what agents may do here), /lab/mailbox/<email> (the
step-up codes a simulated inbox received; lab only, obviously).

The 403 replies include their reasons. That is for teaching only. In
production, never tell a client which rule caught it.
"""

import hashlib
import ipaddress
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

import agent_behavior  # noqa: E402
import agent_identity  # noqa: E402
import agent_policy  # noqa: E402
import risk_engine  # noqa: E402
from fingerprint_coherence import fingerprint_hash  # noqa: E402
from models import Decision, Mandate, Order, User, db, utcnow  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
PORT = int(os.environ.get("PORT", "8404"))
os.makedirs(INSTANCE, exist_ok=True)
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE, 'shop.db')}")
REDIS_URL = os.environ.get("REDIS_URL", "")  # empty -> fakeredis in this process

DROP_SKU = "lab-runner-9"
PRODUCTS = {
    DROP_SKU: {"name": "Lab Runner 9 (limited drop)", "price": 220, "drop": True, "stock": 30},
    "trail-socks": {"name": "Trail socks, 3-pack", "price": 18, "drop": False},
    "laces-neon": {"name": "Neon laces", "price": 6, "drop": False},
    "cap-classic": {"name": "Classic cap", "price": 28, "drop": False},
    "hydration-vest": {"name": "Hydration vest 5L", "price": 64, "drop": False},
    "gps-watch": {"name": "Trail GPS watch", "price": 180, "drop": False},
}
HTML_PAGES = {"/", "/products", "/cart", "/checkout", "/login", "/register", "/account"} | \
    {f"/product/{sku}" for sku in PRODUCTS}
UNGATED = {"/whoami", "/agent-policy", "/api/telemetry", "/favicon.ico"}
STEP_UP_TTL = 600

# Simulated egress (RFC 5737 documentation ranges), claimed with X-Lab-Egress from loopback only.
# In production the IP comes from the connection or your own edge, never from a client header.
LAB_NETWORKS = [
    (ipaddress.ip_network("198.51.100.0/24"), "residential"),
    (ipaddress.ip_network("203.0.113.0/24"), "residential"),
    (ipaddress.ip_network("192.0.2.0/24"), "datacenter"),
]


def make_store():
    if REDIS_URL and not REDIS_URL.startswith("memory://"):
        import redis
        return redis.Redis.from_url(REDIS_URL, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


def load_secret():
    path = os.path.join(INSTANCE, "lab_secret")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


SECRET = load_secret()
ADMIN_KEY = hashlib.sha256(f"admin:{SECRET}".encode()).hexdigest()[:32]

app = Flask(__name__, static_folder=os.path.join(HERE, "static"))
app.config.update(SECRET_KEY=SECRET, SQLALCHEMY_DATABASE_URI=DATABASE_URL,
                  SESSION_COOKIE_SAMESITE="Lax")
db.init_app(app)
store = make_store()


# --------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------

def _loopback():
    return request.remote_addr in ("127.0.0.1", "::1")


def client_egress():
    claimed = request.headers.get("X-Lab-Egress")
    if claimed and _loopback():
        try:
            ip = ipaddress.ip_address(claimed)
        except ValueError:
            ip = None
        for net, kind in LAB_NETWORKS:
            if ip is not None and ip in net:
                return str(ip), kind
    return request.remote_addr, "local"


def now_ms():
    return int(time.time() * 1000)


def request_context():
    egress, egress_kind = client_egress()
    return {
        "method": request.method, "path": request.path, "headers": request.headers,
        "ua": request.headers.get("User-Agent", ""), "authority": request.host,
        "egress": egress, "egress_kind": egress_kind, "sid": g.get("sid"),
    }


def session_state(page="/checkout"):
    sid = g.sid
    fp = store.get(f"fp:{sid}")
    pages = {}
    for name in store.smembers(f"evpages:{sid}"):
        raw = store.get(f"ev:{sid}:{name}")
        if raw:
            pages[name] = json.loads(raw)
    flow = [json.loads(x) for x in store.lrange(f"flow:{sid}", 0, -1)]
    return {
        "sid": sid, "page": page, "fp": json.loads(fp) if fp else None, "fp_hash": store.get(f"fph:{sid}"),
        "events": pages.get(page), "pages": pages, "flow": flow, "now_ms": now_ms(),
        "http_ua": request.headers.get("User-Agent", ""),
    }


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def user_state(user):
    return {
        "id": user.id, "email": user.email, "address": user.address,
        "account_age_days": (utcnow() - _aware(user.created_at)).total_seconds() / 86400,
        "prior_orders": Order.query.filter(Order.user_id == user.id, Order.sku != DROP_SKU).count(),
    }


def classify_request():
    """The principal behind this request: human, declared agent, or (L3) verified agent."""
    ctx = request_context()
    identity = agent_identity.verify(ctx, store)
    principal = agent_policy.classify(request.headers)
    if DEFENSE_LEVEL >= 3 and identity["status"] == "verified":
        principal = {"kind": "verified_agent", "operator": identity["operator"],
                     "evidence": principal["evidence"] + [f"Web Bot Auth signature by {identity['operator']}"]}
    return principal, identity


@app.before_request
def gate():
    g.t0 = time.perf_counter()
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    g.sid = session["sid"]
    g.did_known = "did" in request.cookies
    g.did = request.cookies.get("did") or secrets.token_hex(16)
    g.actor = (request.headers.get("X-Lab-Actor") or "unknown")[:40] if _loopback() else "unknown"
    if request.path.startswith(("/static/", "/admin/", "/lab/")) or request.path in UNGATED:
        return None
    g.principal, g.identity = classify_request()
    if request.method == "GET" and request.path in HTML_PAGES:
        key = f"flow:{g.sid}"
        store.rpush(key, json.dumps([now_ms(), request.path]))
        store.ltrim(key, -50, -1)
        store.expire(key, 3600)
    g.request_score = risk_engine.score_request(request_context(), store, DEFENSE_LEVEL)
    if g.request_score["outcome"] == "block":
        log_decision("request", g.request_score)
        return blocked_reply(g.request_score)
    return None


@app.after_request
def finish(response):
    if "did" not in request.cookies and "did" in g:
        response.set_cookie("did", g.did, max_age=365 * 86400, httponly=True, samesite="Lax")
    if "risk_ms" in g:
        response.headers["Server-Timing"] = f"risk;dur={g.risk_ms:.3f}"
    return response


def blocked_reply(decision):
    body = {"outcome": "block", "message": "Request blocked.", "score": decision["score"],
            "reasons": decision["reasons"], "level": DEFENSE_LEVEL}
    if request.path.startswith("/api/"):
        return jsonify(body), 403
    return render_page(BLOCKED_HTML, title="Blocked", decision=decision), 403


def log_decision(action, decision, user=None):
    g.risk_ms = (time.perf_counter() - g.t0) * 1000
    principal = g.get("principal") or {"kind": "human", "operator": None}
    db.session.add(Decision(
        sid=g.sid, user_id=user.id if user else None, actor=g.actor, action=action, level=DEFENSE_LEVEL,
        score=decision["score"], outcome=decision["outcome"], principal=principal["kind"],
        operator=principal.get("operator"), reasons=decision["reasons"], shadow=decision.get("shadow", {}),
        features=decision.get("features", {}), score_ms=g.risk_ms,
    ))
    db.session.commit()


def reply(decision, message, status=200, **extra):
    body = {"outcome": decision["outcome"], "message": message, "score": decision["score"],
            "reasons": decision["reasons"], "level": DEFENSE_LEVEL, "principal": g.principal["kind"], **extra}
    return jsonify(body), status


# --------------------------------------------------------------------------
# Telemetry, cart, checkout
# --------------------------------------------------------------------------

@app.post("/api/telemetry")
def telemetry():
    if (request.content_length or 0) > 256 * 1024:
        return jsonify(ok=False, message="telemetry too large"), 413
    body = request.get_json(silent=True) or {}
    page = str(body.get("page", ""))[:100]
    fp = body.get("fp") if isinstance(body.get("fp"), dict) else {}
    events = body.get("events") if isinstance(body.get("events"), dict) else {}
    fph = fingerprint_hash(fp)
    pipe = store.pipeline()
    pipe.set(f"fp:{g.sid}", json.dumps(fp), ex=3600)
    pipe.set(f"fph:{g.sid}", fph, ex=3600)
    pipe.set(f"ev:{g.sid}:{page}", json.dumps(events), ex=3600)
    pipe.sadd(f"evpages:{g.sid}", page)
    pipe.expire(f"evpages:{g.sid}", 3600)
    pipe.execute()
    return jsonify(ok=True, fp_hash=fph)


@app.post("/api/cart/add")
def cart_add():
    sku = (request.get_json(silent=True) or {}).get("sku")
    if sku not in PRODUCTS:
        return jsonify(outcome="error", message="Unknown product."), 404
    store.set(f"cart:{g.sid}", sku, ex=3600)
    decision = {"outcome": "allow", "score": g.request_score["score"], "reasons": list(g.request_score["reasons"])}
    return reply(decision, f"{PRODUCTS[sku]['name']} is in your cart.")


def stock_left(sku):
    raw = store.get(f"stock:{sku}")
    if raw is None:
        store.set(f"stock:{sku}", PRODUCTS[sku].get("stock", 10_000))
        raw = store.get(f"stock:{sku}")
    return int(raw)


def device_key(sess):
    """A known device is its cookie; a device we have never seen is clustered by fingerprint."""
    return g.did if g.did_known else f"fp:{sess['fp_hash'] or 'none'}"


def _checkout(user, confirmed=False):
    sku = store.get(f"cart:{g.sid}") or (request.get_json(silent=True) or {}).get("sku")
    if sku not in PRODUCTS:
        return jsonify(outcome="error", message="Your cart is empty."), 400
    if stock_left(sku) <= 0:
        return jsonify(outcome="error", message="Sold out."), 409
    body = request.get_json(silent=True) or {}
    mandate_id = body.get("mandate") or request.headers.get("X-Agent-Mandate")
    mandate = db.session.get(Mandate, str(mandate_id)) if mandate_id else None
    sess = session_state("/checkout")
    ustate = user_state(user)
    dkey = device_key(sess)
    ctx = {
        "sku": sku, "mandate": mandate, "step_up_confirmed": confirmed, "device_key": dkey, "now": utcnow(),
        "device_units": int(store.get(f"dev:{dkey}") or 0) if sku == DROP_SKU else 0,
        "account_units": Order.query.filter_by(user_id=user.id, sku=sku).count() if sku == DROP_SKU else 0,
    }
    decision = risk_engine.evaluate_checkout(g.request_score, sess, ustate, g.principal, g.identity, ctx, DEFENSE_LEVEL)
    extra = decision.pop("extra", {})
    log_decision("checkout", decision, user)

    if decision["outcome"] == "allow":
        order = Order(user_id=user.id, sku=sku, address=user.address, placed_by=g.principal["kind"],
                      operator=g.principal.get("operator"), mandate_id=extra.get("mandate_ok"))
        db.session.add(order)
        if extra.get("mandate_ok") and mandate is not None:
            mandate.used_at = utcnow()
        db.session.commit()
        store.decr(f"stock:{sku}")
        if sku == DROP_SKU:
            store.incr(f"dev:{dkey}")
            store.expire(f"dev:{dkey}", 86400)
        store.delete(f"cart:{g.sid}", f"stepup:{g.sid}", f"stepup_ok:{g.sid}")
        if g.did not in (user.known_devices or []):
            user.known_devices = list(user.known_devices or []) + [g.did]
            db.session.commit()
        return reply(decision, f"Order confirmed: {PRODUCTS[sku]['name']}.", order_id=order.id)

    if decision["outcome"] == "challenge":
        if DEFENSE_LEVEL >= 4 and extra.get("step_up"):
            code = f"{secrets.randbelow(10 ** 6):06d}"
            store.set(f"stepup:{g.sid}", json.dumps({"code": code, "sku": sku}), ex=STEP_UP_TTL)
            store.rpush(f"mail:{user.email}", json.dumps({"ts": now_ms(), "subject": "Confirm your Lab Store order",
                                                           "code": code}))
            store.expire(f"mail:{user.email}", 3600)
            return reply(decision, f"We emailed a confirmation code to {user.email}. Enter it to finish.",
                         202, step_up=True)
        return reply(decision, "Extra verification is needed before this order can be placed.", 202)

    hint = None
    if extra.get("needs") == "mandate":
        hint = ("Agents: ask your user to grant a mandate at /account (POST /api/account/mandates) and "
                "send its id in the mandate field or the X-Agent-Mandate header.")
    elif g.principal["kind"] == "declared_agent":
        hint = "Agents: see GET /agent-policy for how to become eligible to buy here."
    return reply(decision, "Checkout refused.", 403, hint=hint)


@app.post("/api/checkout")
def checkout():
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    return _checkout(user)


@app.post("/api/checkout/confirm")
def checkout_confirm():
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    raw = store.get(f"stepup:{g.sid}")
    code = str((request.get_json(silent=True) or {}).get("code", "")).strip()
    if not raw or not code or json.loads(raw)["code"] != code:
        decision = {"outcome": "deny", "score": 0, "reasons": ["Wrong or expired confirmation code"]}
        log_decision("confirm", decision, user)
        return reply(decision, "That code is wrong or has expired.", 400)
    store.delete(f"stepup:{g.sid}")
    return _checkout(user, confirmed=True)


# --------------------------------------------------------------------------
# Accounts and mandates
# --------------------------------------------------------------------------

@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    decision = {"outcome": "allow", "score": g.request_score["score"], "reasons": list(g.request_score["reasons"])}
    user = User.query.filter_by(email=email).first()
    if not (user and check_password_hash(user.password_hash, password)):
        decision["outcome"] = "deny"
        log_decision("login", decision)
        return reply(decision, "Wrong email or password.", 401)
    session["uid"] = user.id
    log_decision("login", decision, user)
    return reply(decision, f"Welcome back, {user.email}.")


@app.post("/api/register")
def register():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    address = str(body.get("address", ""))[:300].strip()
    decision = {"outcome": "allow", "score": g.request_score["score"], "reasons": list(g.request_score["reasons"])}
    if not email or "@" not in email or len(password) < 8 or not address:
        return reply(decision | {"outcome": "error"}, "Email, an 8+ character password and an address are required.", 400)
    if User.query.filter_by(email=email).first():
        return reply(decision | {"outcome": "error"}, "That email is already registered.", 409)
    # Lab-speed hashing (1,000 PBKDF2 rounds) so seeding and the Round 4 fleet stay fast.
    # Production: werkzeug's default (600,000+) or argon2id.
    user = User(email=email, password_hash=generate_password_hash(password, "pbkdf2:sha256:1000"),
                address=address, known_devices=[])
    db.session.add(user)
    db.session.commit()
    session["uid"] = user.id
    log_decision("register", decision, user)
    return reply(decision, "Account created.")


@app.get("/api/account/mandates")
def list_mandates():
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    rows = Mandate.query.filter_by(user_id=user.id).order_by(Mandate.created_at.desc()).all()
    return jsonify([mandate_json(m) for m in rows])


@app.post("/api/account/mandates")
def grant_mandate():
    """
    The account holder authorises an agent operator to buy one thing, once, soon.
    Mandates are granted by people: a session that is itself a declared or verified
    agent cannot grant one. (An undeclared agent can; that is Round 4's discussion.)
    """
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    if g.principal["kind"] != "human":
        decision = {"outcome": "block", "score": 60,
                    "reasons": [f"Mandates are granted by account holders, not by agents ({g.principal['kind']})"]}
        log_decision("mandate", decision, user)
        return reply(decision, "An agent cannot grant itself a mandate.", 403)
    body = request.get_json(silent=True) or {}
    operator = str(body.get("operator", ""))[:120].strip().lower()
    sku = body.get("sku")
    ttl = max(1, min(int(body.get("ttl_min", 15) or 15), 60))
    if not operator or sku not in PRODUCTS:
        return jsonify(outcome="error", message="operator and a valid sku are required."), 400
    m = Mandate(id=secrets.token_hex(8), user_id=user.id, operator=operator, sku=sku, max_qty=1,
                expires_at=utcnow() + timedelta(minutes=ttl))
    db.session.add(m)
    db.session.commit()
    decision = {"outcome": "allow", "score": 0, "reasons": []}
    log_decision("mandate", decision, user)
    return reply(decision, "Mandate granted.", mandate=mandate_json(m))


def mandate_json(m):
    return {"id": m.id, "operator": m.operator, "sku": m.sku, "max_qty": m.max_qty,
            "expires_at": _aware(m.expires_at).isoformat(timespec="seconds"),
            "used_at": _aware(m.used_at).isoformat(timespec="seconds") if m.used_at else None}


# --------------------------------------------------------------------------
# Catalogue (HTML or Markdown) and policy
# --------------------------------------------------------------------------

@app.get("/api/products")
def api_products():
    return jsonify([{"sku": k, **v, "stock_left": stock_left(k) if v.get("drop") else None} for k, v in PRODUCTS.items()])


@app.get("/agent-policy")
def agent_policy_doc():
    return jsonify({**agent_policy.AGENT_POLICY, "level": DEFENSE_LEVEL,
                    "identity": "HTTP Message Signatures (RFC 9421), Web Bot Auth profile; Signature-Agent must be a trusted operator",
                    "mandates": "POST /api/account/mandates from the account holder's own session; pass the id at checkout"})


@app.get("/products")
def products_page():
    if agent_policy.wants_markdown(request.headers, g.principal):
        text, tokens = agent_policy.markdown_catalog(PRODUCTS)
        resp = Response(text, mimetype="text/markdown")
        resp.headers["X-Markdown-Tokens"] = str(tokens)
        resp.headers["Content-Signal"] = "search=yes, ai-input=yes, ai-train=no"
        resp.headers["Vary"] = "Accept, User-Agent"
        return resp
    return render_page(PRODUCTS_HTML, "Products", products=PRODUCTS)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

BASE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ title }} · Lab Store</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1b1f24}
 nav a{margin-right:1rem} .card{border:1px solid #ccd;border-radius:8px;padding:1rem;margin:.6rem 0}
 button{font-size:1rem;padding:.6rem 1.4rem;border-radius:6px;border:0;background:#2456c7;color:#fff;cursor:pointer}
 input,select{font-size:1rem;padding:.4rem;margin:.2rem 0 .6rem;width:100%;box-sizing:border-box}
 #result{margin-top:1rem;font-weight:600} .lvl{float:right;color:#777;font-size:.85rem} .hint{color:#555;font-weight:400}
 pre{background:#f4f5f7;padding:.8rem;overflow:auto;font-size:.8rem} footer{margin-top:3rem;color:#888;font-size:.8rem}
</style></head>
<body data-level="{{ level }}">
<nav><a href="/">Lab Store</a><a href="/products">Products</a><a href="/cart">Cart</a>
{% if user %}<a href="/account">{{ user.email }}</a>{% else %}<a href="/login">Log in</a><a href="/register">Register</a>{% endif %}
<span class="lvl">DEFENSE_LEVEL={{ level }}</span></nav>
{{ body|safe }}
<footer>Agents: this store publishes its policy at <a href="/agent-policy">/agent-policy</a>.
The catalogue is available as Markdown with <code>Accept: text/markdown</code>.</footer>
<script src="/static/collector.js"></script>
<script src="/static/shop.js"></script>
</body></html>"""

HOME_HTML = """<h1>Lab Store</h1>
<p>Trail gear for people and, under the right conditions, for their agents.</p>
<div class="card"><strong>Today's drop:</strong> <a href="/product/lab-runner-9">Lab Runner 9 (limited drop)</a> · $220 · one per account</div>
<p><a href="/products">Browse all products</a></p>"""

PRODUCTS_HTML = """<h1>Products</h1>
{% for sku, p in products.items() %}<div class="card"><a href="/product/{{ sku }}">{{ p.name }}</a> · ${{ p.price }}{% if p.drop %} · limited drop{% endif %}</div>{% endfor %}"""

PRODUCT_HTML = """<h1>{{ product.name }}</h1><p>${{ product.price }}{% if product.drop %} · limited drop, one per account{% endif %}.</p>
<p>{{ product.name }} is made for long days out. Lightweight, durable, and shipped from our warehouse within two days.</p>
<button id="add-to-cart" data-sku="{{ sku }}">Add to cart</button>
<div id="result" aria-live="polite"></div>"""

CART_HTML = """<h1>Your cart</h1>
{% if sku %}<div class="card">{{ products[sku].name }} · ${{ products[sku].price }}</div>
<p><a id="go-checkout" href="/checkout">Proceed to checkout</a></p>{% else %}<p>Your cart is empty. <a href="/products">Browse products</a>.</p>{% endif %}"""

CHECKOUT_HTML = """<h1>Checkout</h1>
{% if not user %}<p><a href="/login?next=/checkout">Log in</a> to place your order.</p>
{% elif not sku %}<p>Your cart is empty. <a href="/products">Browse products</a>.</p>
{% else %}<div class="card">{{ products[sku].name }} · ${{ products[sku].price }} · ships to {{ user.address }}</div>
<label>Agent mandate id (only if an agent is buying on your behalf) <input name="mandate" autocomplete="off"></label>
<button id="place-order">Place order</button>
<form id="confirm-form" hidden><p>We emailed you a confirmation code. Enter it to finish your order.</p>
<label>Confirmation code <input name="code" inputmode="numeric" autocomplete="one-time-code"></label>
<button id="confirm-submit" type="submit">Confirm code</button></form>
{% endif %}<div id="result" aria-live="polite"></div>"""

LOGIN_HTML = """<h1>Log in</h1>
<form id="login-form" data-next="{{ next }}"><label>Email <input name="email" type="email" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button id="login-submit" type="submit">Log in</button></form><div id="result" aria-live="polite"></div>"""

REGISTER_HTML = """<h1>Create an account</h1>
<form id="register-form" data-next="{{ next }}"><label>Email <input name="email" type="email"></label>
<label>Password <input name="password" type="password" autocomplete="new-password"></label>
<label>Shipping address <input name="address"></label>
<button id="register-submit" type="submit">Register</button></form><div id="result" aria-live="polite"></div>"""

ACCOUNT_HTML = """<h1>Your account</h1>{% if user %}<p>{{ user.email }} · {{ user.address }}</p>
<p>Orders: {{ orders|join(', ') or 'none' }}</p>
<h2>Agent mandates</h2>
<p>Allow an agent operator to buy one item for you, once, within a time limit.</p>
<form id="mandate-form"><label>Operator <select name="operator"><option>agents.lab-provider.test</option><option>chatgpt.com</option><option>anthropic.com</option><option>perplexity.ai</option></select></label>
<label>Product <select name="sku">{% for s, p in products.items() %}<option value="{{ s }}">{{ p.name }}</option>{% endfor %}</select></label>
<label>Valid for (minutes) <input name="ttl_min" type="number" value="15" min="1" max="60"></label>
<button id="mandate-submit" type="submit">Grant mandate</button></form><div id="mandate-result" aria-live="polite"></div>
{% if mandates %}<ul>{% for m in mandates %}<li><code>{{ m.id }}</code> → {{ m.operator }} for {{ m.sku }}, expires {{ m.expires_at }}{% if m.used_at %} (used){% endif %}</li>{% endfor %}</ul>{% endif %}
{% else %}<p><a href="/login">Log in</a></p>{% endif %}"""

BLOCKED_HTML = """<h1>Blocked</h1><p>Score {{ decision.score }}.</p>
<ul>{% for r in decision.reasons %}<li>{{ r }}</li>{% endfor %}</ul>"""


def render_page(body, title, **ctx):
    user = current_user()
    inner = render_template_string(body, user=user, level=DEFENSE_LEVEL, products=PRODUCTS, **ctx)
    return render_template_string(BASE_HTML, body=inner, title=title, user=user, level=DEFENSE_LEVEL)


@app.get("/")
def home():
    return render_page(HOME_HTML, "Home")


@app.get("/product/<sku>")
def product_page(sku):
    if sku not in PRODUCTS:
        return render_page("<h1>Not found</h1>", "Not found"), 404
    return render_page(PRODUCT_HTML, PRODUCTS[sku]["name"], product=PRODUCTS[sku], sku=sku)


@app.get("/cart")
def cart_page():
    return render_page(CART_HTML, "Cart", sku=store.get(f"cart:{g.sid}"))


@app.get("/checkout")
def checkout_page():
    return render_page(CHECKOUT_HTML, "Checkout", sku=store.get(f"cart:{g.sid}"))


@app.get("/login")
def login_page():
    return render_page(LOGIN_HTML, "Log in", next=request.args.get("next", "/account"))


@app.get("/register")
def register_page():
    return render_page(REGISTER_HTML, "Register", next=request.args.get("next", "/account"))


@app.get("/account")
def account():
    user = current_user()
    orders = [o.sku for o in Order.query.filter_by(user_id=user.id)] if user else []
    mandates = [mandate_json(m) for m in Mandate.query.filter_by(user_id=user.id).order_by(Mandate.created_at.desc())] if user else []
    return render_page(ACCOUNT_HTML, "Account", orders=orders, mandates=mandates)


@app.get("/whoami")
def whoami():
    principal, identity = classify_request()
    ctx = request_context()
    scored = risk_engine.score_request(ctx, store, DEFENSE_LEVEL, count=False)
    sess = session_state("/checkout")
    return jsonify({
        "level": DEFENSE_LEVEL, "sid": g.sid, "user_agent": ctx["ua"], "egress": ctx["egress"],
        "principal": principal, "identity": identity, "request_score": scored,
        "behavior": agent_behavior.features(sess), "behavior_points": agent_behavior.score(sess)[0],
        "w2_shadow": dict(zip(("points", "reasons"), risk_engine.w2_shadow(sess))), "fp_hash": sess["fp_hash"],
    })


# --------------------------------------------------------------------------
# Lab and admin endpoints (tools only). /lab/mailbox is the simulated inbox.
# --------------------------------------------------------------------------

@app.get("/lab/mailbox/<path:email>")
def lab_mailbox(email):
    """The latest message a simulated inbox received. Lab only: in production the code goes to a real mailbox."""
    raw = store.lrange(f"mail:{email.lower()}", -1, -1)
    return jsonify({"email": email, "message": json.loads(raw[0]) if raw else None})


def admin_ok():
    return request.headers.get("X-Lab-Admin") == ADMIN_KEY


@app.post("/admin/reset")
def admin_reset():
    """Clear drop orders, mandates and per-session state so a checkpoint starts clean; restock the drop."""
    if not admin_ok():
        return jsonify(ok=False), 403
    Order.query.filter_by(sku=DROP_SKU).delete()
    Mandate.query.delete()
    if request.args.get("decisions") == "1":
        Decision.query.delete()
    if request.args.get("fresh_accounts") == "1":
        since = datetime.now(timezone.utc) - timedelta(days=1)
        for u in User.query.filter(User.created_at >= since):
            Order.query.filter_by(user_id=u.id).delete()
            db.session.delete(u)
    db.session.commit()
    for pattern in ("flow:*", "fp:*", "fph:*", "ev:*", "evpages:*", "rl:*", "cart:*", "stepup*", "mail:*",
                    "dev:*", "nonce:*", "stock:*"):
        for key in store.scan_iter(pattern, count=1000):
            store.delete(key)
    return jsonify(ok=True, level=DEFENSE_LEVEL)


@app.get("/admin/decisions")
def admin_decisions():
    if not admin_ok():
        return jsonify(ok=False), 403
    query = Decision.query
    if request.args.get("since_id"):
        query = query.filter(Decision.id > int(request.args["since_id"]))
    if request.args.get("action"):
        query = query.filter_by(action=request.args["action"])
    rows = query.order_by(Decision.id.asc()).limit(int(request.args.get("limit", 5000))).all()
    return jsonify([{
        "id": d.id, "sid": d.sid, "user_id": d.user_id, "actor": d.actor, "action": d.action, "level": d.level,
        "score": d.score, "outcome": d.outcome, "principal": d.principal, "operator": d.operator,
        "reasons": d.reasons, "shadow": d.shadow, "features": d.features, "score_ms": d.score_ms,
    } for d in rows])


@app.get("/admin/status")
def admin_status():
    last = Decision.query.order_by(Decision.id.desc()).first()
    return jsonify(level=DEFENSE_LEVEL, last_decision_id=last.id if last else 0,
                   drop_stock_left=stock_left(DROP_SKU), redis="external" if REDIS_URL else "fakeredis")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print(f" * DEFENSE_LEVEL={DEFENSE_LEVEL}  http://127.0.0.1:{PORT}  "
          f"({'Redis ' + REDIS_URL if REDIS_URL else 'fakeredis'}, {DATABASE_URL.split(':')[0]})")
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
