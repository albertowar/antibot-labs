"""
Chapter 9 — Demo store: the "Lab Runner 9" sneaker drop (Section 9.7)

The shared Flask + Redis + PostgreSQL store, at its end-of-Workshop-2 state.
It sells one limited sneaker (one pair per account), and every protected
action goes through the layered risk engine in defenses/risk_engine.py.

    DEFENSE_LEVEL=0  the "end of W2 Ch8" stack: headers, TLS/JA4 consistency,
                     per-egress rate limits, automation flags (W2 Ch1, Ch5)
    DEFENSE_LEVEL=1  + fingerprint coherence                (W2 Ch4)
    DEFENSE_LEVEL=2  + behavior and flow                    (W2 Ch3)
    DEFENSE_LEVEL=3  + session/account model                (W2 Ch7)
    DEFENSE_LEVEL=4  + login token binding and login risk   (W2 Ch2, Ch6)

Every layer is computed on every action. Layers above DEFENSE_LEVEL run in
shadow mode: their points are logged in decisions.shadow but don't count.

Run (from lab/):
    python demo_site/app.py                    # DEFENSE_LEVEL=0, https://localhost:8443
    DEFENSE_LEVEL=2 python demo_site/app.py

Debug endpoints, never blocked: /whoami (how this request scores) and
/lab/capture (record your own browser as a legitimate-user profile).
The 403 replies include their reasons. That is for teaching only. In
production, never tell a client which rule caught it.
"""

import hashlib
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone

import redis
from flask import Flask, g, jsonify, make_response, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

import api_auth  # noqa: E402
import api_hardening  # noqa: E402
import graphql_api  # noqa: E402
import login_risk  # noqa: E402
import risk_engine  # noqa: E402
import session_model  # noqa: E402
import supply_chain  # noqa: E402
import token_binding  # noqa: E402
import wsserver  # noqa: E402
from edge import serve  # noqa: E402
from fingerprint_coherence import fingerprint_hash  # noqa: E402
from models import Decision, Order, User, db, utcnow  # noqa: E402
from streaming import bus as stream_bus  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
PORT = int(os.environ.get("PORT", "8443"))
WS_PORT = int(os.environ.get("WS_PORT", str(PORT + 1)))

DROP_SKU = "lab-runner-9"
PRODUCTS = {
    DROP_SKU: {"name": "Lab Runner 9 (limited drop)", "price": 220, "drop": True},
    "trail-socks": {"name": "Trail socks, 3-pack", "price": 18, "drop": False},
    "laces-neon": {"name": "Neon laces", "price": 6, "drop": False},
    "cap-classic": {"name": "Classic cap", "price": 28, "drop": False},
}
HTML_PAGES = {"/", "/login", "/register", "/account"} | {f"/drop/{sku}" for sku in PRODUCTS}
# Telemetry is always accepted: collect from everyone, decide on actions.
# /api/script-violation is a CSP report sink (L7): never block the browser's own report.
UNGATED = {"/whoami", "/lab/capture", "/lab/capture/profile", "/api/telemetry",
           "/api/script-violation", "/metrics", "/favicon.ico"}

# Simulated egress. The lab runs on one machine, so every request really comes
# from 127.0.0.1. Scripts may claim a source IP with X-Lab-Egress, but only
# from these documentation ranges (RFC 5737), so no real address is ever used.
# In production the IP comes from the TCP connection or your own edge, never
# from a client header.
LAB_NETWORKS = [
    (ipaddress.ip_network("198.51.100.0/24"), "residential"),
    (ipaddress.ip_network("203.0.113.0/24"), "residential"),
    (ipaddress.ip_network("192.0.2.0/24"), "datacenter"),
]


def load_secret():
    os.makedirs(INSTANCE, exist_ok=True)
    path = os.path.join(INSTANCE, "lab_secret")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


SECRET = load_secret()
ADMIN_KEY = hashlib.sha256(f"admin:{SECRET}".encode()).hexdigest()[:32]

app = Flask(__name__, static_folder=os.path.join(HERE, "static"))
app.config.update(
    SECRET_KEY=SECRET,
    SQLALCHEMY_DATABASE_URI=DATABASE_URL,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
db.init_app(app)
store = redis.Redis.from_url(REDIS_URL, decode_responses=True)
MODEL = session_model.load_model()


# --------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------

def client_egress():
    claimed = request.headers.get("X-Lab-Egress")
    if claimed and request.remote_addr in ("127.0.0.1", "::1"):
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
        "method": request.method,
        "path": request.path,
        "headers": request.headers,
        "ua": request.headers.get("User-Agent", ""),
        "ja4": request.environ.get("lab.ja4"),
        "alpn": request.environ.get("lab.tls_alpn", []),
        "tls_extensions": request.environ.get("lab.tls_extensions", []),
        "egress": egress,
        "egress_kind": egress_kind,
        "sid": g.get("sid"),
    }


def session_state(page):
    sid = g.sid
    fp = store.get(f"fp:{sid}")
    events = store.get(f"ev:{sid}:{page}")
    flow = [json.loads(x) for x in store.lrange(f"flow:{sid}", 0, -1)]
    return {
        "sid": sid,
        "page": page,
        "fp": json.loads(fp) if fp else None,
        "fp_hash": store.get(f"fph:{sid}"),
        "events": json.loads(events) if events else None,
        "flow": flow,
        "now_ms": now_ms(),
        "http_ua": request.headers.get("User-Agent", ""),
    }


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def user_state(user):
    norm = session_model.normalize_address(user.address)
    members = store.smembers(f"addr:{norm}")
    return {
        "email": user.email,
        "account_age_days": (utcnow() - _aware(user.created_at)).total_seconds() / 86400,
        "prior_orders": Order.query.filter(Order.user_id == user.id, Order.sku != DROP_SKU).count(),
        "addr_accounts_24h": len(members - {str(user.id)}),
    }


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def remember_address(user):
    key = f"addr:{session_model.normalize_address(user.address)}"
    store.sadd(key, str(user.id))
    store.expire(key, 86400)


@app.before_request
def gate():
    g.t0 = time.perf_counter()
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    g.sid = session["sid"]
    g.did = request.cookies.get("did") or secrets.token_hex(16)
    g.csp_nonce = secrets.token_urlsafe(12)
    if request.path.startswith(("/static/", "/admin/")) or request.path in UNGATED:
        return None
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
        response.set_cookie("did", g.did, max_age=365 * 86400, secure=True, httponly=True, samesite="Lax")
    if "risk_ms" in g:
        response.headers["Server-Timing"] = f"risk;dur={g.risk_ms:.3f}"
    # L7: send a CSP (report-only until you turn on enforcement) on every HTML page.
    if DEFENSE_LEVEL >= 7 and request.path in HTML_PAGES and "csp_nonce" in g:
        name, value = supply_chain.csp_header(g.csp_nonce)
        response.headers[name] = value
    # L6: publish this request to the streaming bus (the detectors read it online).
    if (not request.path.startswith(("/static/", "/admin/")) and request.path != "/favicon.ico"
            and "sid" in g):
        try:
            stream_bus.publish(store, {"sid": g.sid, "ts_ms": now_ms(),
                                       "path": request.path, "method": request.method})
        except Exception:
            pass  # the stream must never break the response
    return response


def blocked_reply(decision):
    body = {"outcome": "block", "message": "Request blocked.", "score": decision["score"],
            "reasons": decision["reasons"], "level": DEFENSE_LEVEL}
    if request.path.startswith("/api/"):
        return jsonify(body), 403
    return render_page(BLOCKED_HTML, title="Blocked", decision=decision), 403


def log_decision(action, decision, user=None):
    g.risk_ms = (time.perf_counter() - g.t0) * 1000
    db.session.add(Decision(
        sid=g.sid, user_id=user.id if user else None, action=action, level=DEFENSE_LEVEL,
        score=decision["score"], outcome=decision["outcome"], reasons=decision["reasons"],
        shadow=decision.get("shadow", {}), features=decision.get("features", {}), score_ms=g.risk_ms,
    ))
    db.session.commit()


def reply(decision, message, status=200, **extra):
    body = {"outcome": decision["outcome"], "message": message, "score": decision["score"],
            "reasons": decision["reasons"], "level": DEFENSE_LEVEL, **extra}
    return jsonify(body), status


# --------------------------------------------------------------------------
# Protected actions
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
    pipe.execute()
    return jsonify(ok=True, fp_hash=fph)


@app.post("/api/buy")
def buy():
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    sku = (request.get_json(silent=True) or {}).get("sku")
    if sku not in PRODUCTS:
        return jsonify(outcome="error", message="Unknown product."), 404
    if Order.query.filter_by(user_id=user.id, sku=sku).first():
        return jsonify(outcome="error", message="One pair per account."), 409
    remember_address(user)
    decision = risk_engine.evaluate_buy(
        g.request_score, session_state(f"/drop/{sku}"), user_state(user), DEFENSE_LEVEL, MODEL, store)
    log_decision("buy", decision, user)
    if decision["outcome"] == "allow":
        db.session.add(Order(user_id=user.id, sku=sku, address=user.address))
        db.session.commit()
        return reply(decision, f"Order confirmed: {PRODUCTS[sku]['name']}.")
    if decision["outcome"] == "challenge":
        return reply(decision, "Extra verification needed before checkout.", 202)
    return reply(decision, "Checkout blocked.", 403)


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    state = session_state("/login")
    cluster = login_risk.cluster_key(request_context(), state)
    token_ok = token_binding.verify(request.headers.get("X-Lab-Token", ""), g.sid, state["fp_hash"], SECRET)
    decision = risk_engine.evaluate_login(g.request_score, state, token_ok, cluster, store, DEFENSE_LEVEL)
    if decision["outcome"] == "block":
        log_decision("login", decision)
        return reply(decision, "Login blocked.", 403)

    user = User.query.filter_by(email=email).first()
    valid = bool(user and check_password_hash(user.password_hash, password))
    login_risk.record_attempt(store, cluster, valid)
    if not valid:
        decision["outcome"] = "deny"
        log_decision("login", decision)
        return reply(decision, "Wrong email or password.", 401)

    if DEFENSE_LEVEL >= 4 and g.did not in (user.known_devices or []):
        decision["outcome"] = "challenge"
        decision["reasons"].append("[L4] Unknown device for this account: step-up (emailed code) required")
        log_decision("login", decision, user)
        return reply(decision, "We sent a code to your email. Enter it to continue.", 202)

    session["uid"] = user.id
    if g.did not in (user.known_devices or []):
        user.known_devices = list(user.known_devices or []) + [g.did]
    log_decision("login", decision, user)
    return reply(decision, f"Welcome back, {user.email}.")


@app.post("/api/register")
def register():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    address = str(body.get("address", ""))[:300].strip()
    decision = {"outcome": g.request_score["outcome"], "score": g.request_score["score"],
                "reasons": list(g.request_score["reasons"])}
    if not email or "@" not in email or len(password) < 8 or not address:
        return reply(decision | {"outcome": "error"}, "Email, an 8+ character password and an address are required.", 400)
    if User.query.filter_by(email=email).first():
        return reply(decision | {"outcome": "error"}, "That email is already registered.", 409)
    # Lab-speed hashing (1,000 PBKDF2 rounds) so seeding and Round 4 stay fast.
    # Production: werkzeug's default (600,000+) or argon2id.
    user = User(email=email, password_hash=generate_password_hash(password, "pbkdf2:sha256:1000"),
                address=address, known_devices=[g.did])
    db.session.add(user)
    db.session.commit()
    remember_address(user)
    session["uid"] = user.id
    log_decision("register", decision, user)
    return reply(decision, "Account created.")


@app.get("/api/challenge")
def challenge():
    return jsonify(token_binding.issue_challenge(store, g.sid))


@app.post("/api/challenge/verify")
def challenge_verify():
    body = request.get_json(silent=True) or {}
    token = token_binding.redeem(store, g.sid, store.get(f"fph:{g.sid}"), str(body.get("nonce", "")),
                                 body.get("counter"), SECRET)
    if token is None:
        return jsonify(ok=False, token=None, message="Challenge failed or expired."), 400
    return jsonify(ok=True, token=token)


@app.get("/api/products")
def products():
    return jsonify([{"sku": k, **v} for k, v in PRODUCTS.items()])


# --------------------------------------------------------------------------
# W3 Ch2 — API surface: GraphQL, a token-bound REST catalog, a WebSocket
# --------------------------------------------------------------------------

@app.get("/api/token")
def api_token():
    """Issue a JA4-bound bearer token to a logged-in client (a mobile app or
    partner script). The token is useless replayed from another TLS stack."""
    user = current_user()
    if user is None:
        return jsonify(ok=False, message="Log in first."), 401
    ja4 = request.environ.get("lab.ja4")
    return jsonify(ok=True, token=api_auth.issue(user.id, ja4, SECRET))


@app.post("/graphql")
def graphql():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(errors=[{"message": "expected a JSON query body"}]), 400
    analysis = graphql_api.analyze_body(body)
    decision = risk_engine.evaluate_api(g.request_score, analysis, None, store, None, g.sid, DEFENSE_LEVEL)
    log_decision("graphql", decision)
    if decision["outcome"] == "block":
        return jsonify(errors=[{"message": "query rejected", "reasons": decision["reasons"]}],
                       outcome="block", score=decision["score"]), 403
    return jsonify(graphql_api.resolve_body(body, PRODUCTS))


@app.get("/api/v1/products")
def api_v1_products():
    """Paginated REST catalog. Requires a JA4-bound token; velocity is counted
    per fingerprint cluster so a residential proxy pool does not dodge it."""
    ja4 = request.environ.get("lab.ja4")
    token_state = api_auth.verify(request.headers.get("Authorization", ""), ja4, SECRET)
    cluster = f"{risk_engine.tls_family(request_context())}:{store.get(f'fph:{g.sid}') or 'none'}"
    decision = risk_engine.evaluate_api(g.request_score, None, token_state, store, cluster, g.sid, DEFENSE_LEVEL)
    log_decision("api_rest", decision)
    if decision["outcome"] == "block":
        return jsonify(error="forbidden", reasons=decision["reasons"], score=decision["score"]), 403
    limit = min(int(request.args.get("limit", 24)), 100)
    offset = int(request.args.get("offset", 0))
    items = [{"sku": k, **v} for k, v in PRODUCTS.items()]
    return jsonify(items=items[offset:offset + limit], total=len(items))


@app.post("/api/script-violation")
def script_violation():
    """CSP report sink (L7). The browser POSTs here when it refuses a connection
    the page tried to make — exactly the signal a skimmer's exfil produces."""
    body = request.get_json(silent=True) or {}
    report = body.get("csp-report", body)
    supply_chain.record_violation(store, g.sid, report)
    return ("", 204)


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
 input{font-size:1rem;padding:.4rem;margin:.2rem 0 .6rem;width:100%;box-sizing:border-box}
 #result{margin-top:1rem;font-weight:600} .lvl{float:right;color:#777;font-size:.85rem}
 pre{background:#f4f5f7;padding:.8rem;overflow:auto;font-size:.8rem}
</style></head>
<body data-level="{{ level }}">
<nav><a href="/">Lab Store</a><a href="/drop/lab-runner-9">The drop</a>
{% if user %}<a href="/account">{{ user.email }}</a>{% else %}<a href="/login">Log in</a><a href="/register">Register</a>{% endif %}
<span class="lvl">DEFENSE_LEVEL={{ level }}</span></nav>
{{ body|safe }}
<script src="/static/runtime_monitor.js" nonce="{{ csp_nonce }}"></script>
<script src="/static/collector.js" nonce="{{ csp_nonce }}"></script>
<script src="/static/challenge.js" nonce="{{ csp_nonce }}"></script>
<script src="/static/shop.js" nonce="{{ csp_nonce }}"></script>
<!-- third-party tag: a real site loads analytics from a vendor here. In the lab
     this file is where attacks/round3_skimmer.py plants its skimmer. -->
<script src="/static/analytics-helper.js" nonce="{{ csp_nonce }}"></script>
</body></html>"""

HOME_HTML = """<h1>Lab Store</h1>
{% for sku, p in products.items() %}<div class="card"><a href="/drop/{{ sku }}">{{ p.name }}</a> · ${{ p.price }}</div>{% endfor %}"""

DROP_HTML = """<h1>{{ product.name }}</h1><p>${{ product.price }} · one pair per account.</p>
{% if user %}<button id="buy" data-sku="{{ sku }}">Buy now</button>
{% else %}<p><a href="/login?next=/drop/{{ sku }}">Log in</a> to buy.</p>{% endif %}
<div id="result" aria-live="polite"></div>"""

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
<p>Orders: {{ orders|join(', ') or 'none' }}</p>{% else %}<p><a href="/login">Log in</a></p>{% endif %}"""

BLOCKED_HTML = """<h1>Blocked</h1><p>Score {{ decision.score }}.</p>
<ul>{% for r in decision.reasons %}<li>{{ r }}</li>{% endfor %}</ul>"""

CAPTURE_HTML = """<h1>Capture your browser</h1>
<p>Move around, scroll, tab through the page, then click the button. The JSON below
is a legitimate-user profile: save it as <code>tools/profiles/mine.json</code> and
<code>tools/legit_traffic.py</code> will replay you in every checkpoint.</p>
<button id="capture">Capture my profile</button><pre id="profile"></pre>"""


def render_page(body, title, **ctx):
    user = current_user()
    inner = render_template_string(body, user=user, level=DEFENSE_LEVEL, **ctx)
    return render_template_string(BASE_HTML, body=inner, title=title, user=user, level=DEFENSE_LEVEL,
                                  csp_nonce=g.get("csp_nonce", ""))


@app.get("/")
def home():
    return render_page(HOME_HTML, "Home", products=PRODUCTS)


@app.get("/drop/<sku>")
def drop(sku):
    if sku not in PRODUCTS:
        return render_page("<h1>Not found</h1>", "Not found"), 404
    return render_page(DROP_HTML, PRODUCTS[sku]["name"], product=PRODUCTS[sku], sku=sku)


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
    return render_page(ACCOUNT_HTML, "Account", orders=orders)


@app.get("/lab/capture")
def capture_page():
    return render_page(CAPTURE_HTML, "Capture")


@app.get("/lab/capture/profile")
def capture_profile():
    state = session_state("/lab/capture")
    return jsonify({
        "name": "mine",
        "source": f"captured from a real browser at /lab/capture on {datetime.now(timezone.utc):%Y-%m-%d}",
        "impersonate": risk_engine.impersonate_hint(request.headers.get("User-Agent", "")),
        "behavior": "recorded",
        "fp": state["fp"],
        "events": state["events"],
    })


@app.get("/whoami")
def whoami():
    ctx = request_context()
    scored = risk_engine.score_request(ctx, store, DEFENSE_LEVEL, count=False)
    state = session_state(request.args.get("page", "/"))
    stream_pts, stream_why = risk_engine.stream_agg.score_stream(store, g.sid)
    return jsonify({
        "level": DEFENSE_LEVEL, "ja4": ctx["ja4"], "tls_family": risk_engine.tls_family(ctx),
        "alpn_offered": ctx["alpn"], "tls_extensions": [f"{e:04x}" for e in ctx["tls_extensions"]],
        "user_agent": ctx["ua"], "egress": ctx["egress"],
        "egress_kind": ctx["egress_kind"], "sid": g.sid, "fp_hash": state["fp_hash"],
        "request_score": scored, "fp": state["fp"],
        "stream": {"points": stream_pts, "reasons": stream_why,
                   "cv": risk_engine.stream_agg_cv(store, g.sid)},
    })


# --------------------------------------------------------------------------
# Admin (tools only): needs the X-Lab-Admin key derived from instance/lab_secret
# --------------------------------------------------------------------------

def admin_ok():
    return request.headers.get("X-Lab-Admin") == ADMIN_KEY


@app.post("/admin/reset")
def admin_reset():
    """Clear drop orders and per-session state so a checkpoint starts clean."""
    if not admin_ok():
        return jsonify(ok=False), 403
    Order.query.filter_by(sku=DROP_SKU).delete()
    if request.args.get("decisions") == "1":
        Decision.query.delete()
    db.session.commit()
    for pattern in ("flow:*", "fp:*", "fph:*", "ev:*", "rl:*", "chal:*", "lr:*", "addr:*"):
        for key in store.scan_iter(pattern, count=1000):
            store.delete(key)
    # Rebuild the 24 h address index from recent registrations.
    since = datetime.fromtimestamp(time.time() - 86400, timezone.utc)
    for user in User.query.filter(User.created_at >= since):
        remember_address(user)
    return jsonify(ok=True, level=DEFENSE_LEVEL)


@app.get("/admin/decisions")
def admin_decisions():
    if not admin_ok():
        return jsonify(ok=False), 403
    sids = [s for s in request.args.get("sids", "").split(",") if s]
    query = Decision.query
    if sids:
        query = query.filter(Decision.sid.in_(sids))
    if request.args.get("action"):
        query = query.filter_by(action=request.args["action"])
    rows = query.order_by(Decision.id.desc()).limit(int(request.args.get("limit", 5000))).all()
    return jsonify([{
        "id": d.id, "sid": d.sid, "user_id": d.user_id, "action": d.action, "level": d.level,
        "score": d.score, "outcome": d.outcome, "reasons": d.reasons, "shadow": d.shadow,
        "features": d.features, "score_ms": d.score_ms,
    } for d in rows])


@app.post("/admin/reload-model")
def admin_reload_model():
    global MODEL
    if not admin_ok():
        return jsonify(ok=False), 403
    MODEL = session_model.load_model()
    return jsonify(ok=MODEL is not None, threshold=MODEL["threshold"] if MODEL else None)


@app.get("/admin/status")
def admin_status():
    return jsonify(level=DEFENSE_LEVEL, model_loaded=MODEL is not None,
                   model_threshold=MODEL["threshold"] if MODEL else None)


@app.get("/metrics")
def metrics():
    """Prometheus text exposition (used by the optional `prod` Docker profile).
    No prometheus_client dependency: the counts come straight from the decisions
    table and a couple of Redis counters, hand-formatted. Scraped by Prometheus,
    drawn in Grafana as the signal-health board."""
    import re
    from sqlalchemy import func
    lines = ["# HELP lab_decisions_total Scored actions by action and outcome.",
             "# TYPE lab_decisions_total counter"]
    rows = db.session.query(Decision.action, Decision.outcome, func.count(Decision.id)) \
        .group_by(Decision.action, Decision.outcome).all()
    for action, outcome, count in rows:
        lines.append(f'lab_decisions_total{{action="{action}",outcome="{outcome}"}} {count}')
    # Per-layer trigger counts, parsed from the reason strings.
    layer_counts = {f"L{i}": 0 for i in range(8)}
    for (reasons,) in db.session.query(Decision.reasons).all():
        for tag in {m for r in (reasons or []) for m in re.findall(r"\[(L\d)\]", r)}:
            layer_counts[tag] = layer_counts.get(tag, 0) + 1
    lines += ["# HELP lab_layer_triggers_total Decisions where each layer contributed a reason.",
              "# TYPE lab_layer_triggers_total counter"]
    for layer, count in sorted(layer_counts.items()):
        lines.append(f'lab_layer_triggers_total{{layer="{layer}"}} {count}')
    lines += ["# HELP lab_ws_flood_events_total WebSocket connections cut for flooding.",
              "# TYPE lab_ws_flood_events_total counter",
              f"lab_ws_flood_events_total {int(store.get('ws:flood') or 0)}",
              "# HELP lab_csp_violations_total CSP violation reports received.",
              "# TYPE lab_csp_violations_total counter",
              f"lab_csp_violations_total {int(store.get('csp:viol:count') or 0)}",
              f"lab_defense_level {DEFENSE_LEVEL}"]
    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    if DEFENSE_LEVEL >= 3 and MODEL is None:
        print(" ! DEFENSE_LEVEL>=3 but no model found: run python tools/train_model.py first.")
    cert, key = os.path.join(INSTANCE, "cert.pem"), os.path.join(INSTANCE, "key.pem")
    if not os.path.exists(cert):
        sys.exit("No TLS certificate. Run: python tools/make_cert.py")
    print(f" * DEFENSE_LEVEL={DEFENSE_LEVEL}  (0-4 inherited W1+W2; 5 API, 6 streaming, 7 supply-chain)")
    print(f" * streaming backend: {stream_bus.BACKEND}")
    wsserver.start(DEFENSE_LEVEL, store, WS_PORT)
    if stream_bus.BACKEND == "kafka":
        threading.Thread(target=stream_bus.run_consumer, args=(store,), daemon=True).start()
        print(" * streaming detectors consuming from Redpanda")
    serve(app, "127.0.0.1", PORT, cert, key)
