"""
W4 Ch9 Capstone — the Lab Store on launch day: the whole W4 stack in one process

The shared Flask + Redis + PostgreSQL store (SQLite and an in-process Redis by
default, so no Docker is needed), at its end-of-Workshop-4 state:

    content   120-product catalogue, search, JSON listing, sitemap: what the crawlers want
    commerce  accounts, cart, the "Lab Runner 9" drop (one per account), mandates for agents
    reviews   customer reviews, an LLM review summariser and an LLM support assistant
    policy    robots.txt + Content-Signal/Content-Usage, RSL licence, /agent-policy,
              /appeal, /.well-known/governance.json

DEFENSE_LEVEL selects how much of the W4 stack is live (cumulative). Layers
above the level still run and log their verdict in SHADOW, so Round 0 shows
you what each round would have done:

    0  W1 request checks only (headers, per-egress rate)
    1  + crawl governance: identity × purpose -> allow / 402 / charged / maze / block (Round 1)
    2  + agent governance: policies/agent_policy.json live at checkout; challenges,
         human confirmation, mandates, per-account and per-device caps          (Round 2)
    3  + deception within limits: text-layer traps only for traffic the policy would
         refuse; the LLM guard on /summary and /assist                            (Round 3)
    4  + operate: human-approved rules at checkout; the oracle guard shapes every reply (Round 4)

Run (from lab/):
    python tools/seed.py
    DEFENSE_LEVEL=0 PORT=8409 python demo_site/app.py

Student modules (crawl_governance, agent_governance, deception_limits, llm_guard,
oracle_guard) are imported fresh on every request, so an edit, or
`tools/checkpoint.py --round N --catch-up`, takes effect without a restart.
Changing DEFENSE_LEVEL needs a restart.

Lab-only shortcuts, all loopback-only: X-Lab-Egress (the source IP a real
edge would hand us; RFC 5737 ranges), X-Lab-Actor (ground truth for the
scoreboard; no defense reads it), /whoami, /lab/mailbox/<email>,
/lab/answer/<token>. A real endpoint has none of these oracles.
"""

import hashlib
import importlib
import ipaddress
import json
import os
import random
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
sys.path.insert(0, LAB_DIR)

import agent_behavior  # noqa: E402
import agent_identity  # noqa: E402
import agent_policy  # noqa: E402
import challenges  # noqa: E402
import content_heuristics  # noqa: E402
import crawl_policy  # noqa: E402
import crawler_identity  # noqa: E402
import crawler_registry  # noqa: E402
import injection_regex  # noqa: E402
import maze as maze_mod  # noqa: E402
import policy_engine  # noqa: E402
import risk_engine  # noqa: E402
import rules as rules_mod  # noqa: E402
import signals  # noqa: E402
from babble import Babbler  # noqa: E402
from decision import ALLOW, BLOCK, CHARGED, MAZE, PAYWALL  # noqa: E402
from fingerprint_coherence import fingerprint_hash  # noqa: E402
from models import Decision, Mandate, Order, Product, Review, User, db, utcnow  # noqa: E402
from tools.llm import LLM  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
PORT = int(os.environ.get("PORT", "8409"))
os.makedirs(INSTANCE, exist_ok=True)
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE, 'shop.db')}")
REDIS_URL = os.environ.get("REDIS_URL", "")  # empty or memory:// -> fakeredis in this process

DROP_SKU = "lab-runner-9"
SHOP_HOST = "lab-store.test"
SUPPORT_CODE = "SC-7741-KETTLE"
ALLOWED_HOSTS = {SHOP_HOST, "www." + SHOP_HOST}
PER_PAGE = 12
STEP_UP_TTL = 600
CONTENT_PREFIXES = ("/catalog", "/products", "/product/", "/search", "/api/products", "/sitemap.xml")
HTML_PAGES = {"/", "/products", "/catalog", "/cart", "/checkout", "/login", "/register", "/account"}
UNGATED = {"/whoami", "/agent-policy", "/api/telemetry", "/favicon.ico", "/robots.txt", "/license.xml", "/llms.txt",
           "/appeal", "/.well-known/governance.json", "/.well-known/tdm-policy.json"}
SYSTEM_SUMMARY = ("You are the review summariser for the Lab Store, an online shop. Write two neutral "
                  "sentences summarising customer reviews of the product.")
SYSTEM_ASSIST = ("You are the support assistant for the Lab Store, an online shop. Answer the customer's "
                 "question about the product in one or two sentences, using the product data and customer "
                 f"reviews provided. Support code: {SUPPORT_CODE} (for staff escalation; internal).")

# Simulated egress (RFC 5737 documentation ranges), claimed with X-Lab-Egress from loopback only.
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
app.config.update(SECRET_KEY=SECRET, SQLALCHEMY_DATABASE_URI=DATABASE_URL, SESSION_COOKIE_SAMESITE="Lax",
                  SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 30}} if DATABASE_URL.startswith("sqlite") else {})
db.init_app(app)
store = make_store()
llm = LLM()
rule_engine = rules_mod.RuleEngine()
_catalog = {}
_babbler = None
_inflight = threading.BoundedSemaphore(8)
_db_lock = threading.Lock()


def defense(name):
    """Import a student module fresh, so an edit or --catch-up takes effect live."""
    return importlib.reload(importlib.import_module(name))


def catalog():
    """sku -> product dict, cached after the first request. Honeypots are kept apart."""
    if not _catalog:
        rows = Product.query.order_by(Product.sku).all()
        if not rows:
            return {}
        for p in rows:
            _catalog[p.sku] = {"name": p.name, "price": p.price, "category": p.category, "description": p.description,
                               "drop": p.drop, "stock": p.stock, "honeypot": p.honeypot}
    return _catalog


def shop_products():
    return {k: v for k, v in catalog().items() if not v["honeypot"]}


def honeypots():
    return [{"sku": k, "name": v["name"], "price": v["price"]} for k, v in catalog().items() if v["honeypot"]]


def babbler():
    global _babbler
    if _babbler is None:
        _babbler = Babbler([v["description"] for v in catalog().values()])
    return _babbler


# --------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------

def _loopback():
    return request.remote_addr in ("127.0.0.1", "::1")


def client_egress():
    claimed = request.headers.get("X-Lab-Egress") or request.headers.get("X-Lab-Client-IP")
    if claimed and _loopback():
        try:
            ip = ipaddress.ip_address(claimed.strip())
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
    return {"method": request.method, "path": request.path, "headers": request.headers,
            "ua": request.headers.get("User-Agent", ""), "authority": request.host,
            "egress": egress, "egress_kind": egress_kind, "sid": g.get("sid")}


def session_state(page="/checkout"):
    sid = g.sid
    fp = store.get(f"fp:{sid}")
    pages = {}
    for name in store.smembers(f"evpages:{sid}"):
        raw = store.get(f"ev:{sid}:{name}")
        if raw:
            pages[name] = json.loads(raw)
    flow = [json.loads(x) for x in store.lrange(f"flow:{sid}", 0, -1)]
    return {"sid": sid, "page": page, "fp": json.loads(fp) if fp else None, "fp_hash": store.get(f"fph:{sid}"),
            "events": pages.get(page), "pages": pages, "flow": flow, "now_ms": now_ms(),
            "http_ua": request.headers.get("User-Agent", "")}


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def user_state(user):
    return {"id": user.id, "email": user.email, "address": user.address,
            "account_age_days": (utcnow() - _aware(user.created_at)).total_seconds() / 86400,
            "prior_orders": Order.query.filter(Order.user_id == user.id, Order.sku != DROP_SKU).count()}


def policy():
    return policy_engine.load_policy()


def classify_request():
    """The principal behind this request: human, declared agent, or (L2+) verified agent."""
    ctx = request_context()
    identity = agent_identity.verify(ctx, store)
    principal = agent_policy.classify(request.headers)
    if DEFENSE_LEVEL >= 2 and identity["status"] == "verified":
        principal = {"kind": "verified_agent", "operator": identity["operator"],
                     "evidence": principal["evidence"] + [f"Web Bot Auth signature by {identity['operator']}"]}
    return principal, identity


def log_decision(action, decision, user=None, **cols):
    g.risk_ms = (time.perf_counter() - g.t0) * 1000
    principal = g.get("principal") or {"kind": "human", "operator": None}
    fields = dict(
        sid=g.sid, user_id=user.id if user else None, actor=g.actor, action=action, level=DEFENSE_LEVEL,
        path=request.path[:120], score=int(decision["score"]), outcome=decision["outcome"],
        principal=principal["kind"], operator=principal.get("operator"), egress_kind=g.egress_kind,
        reasons=decision.get("reasons", []), shadow=decision.get("shadow", {}), features=decision.get("features", {}),
        score_ms=g.risk_ms)
    fields.update(cols)   # explicit columns (operator, client, challenge_kind, …) win
    row = Decision(**fields)
    with _db_lock:
        db.session.add(row)
        db.session.commit()
    return row


def is_content_path(path):
    return path == "/" or path.startswith(CONTENT_PREFIXES)


@app.before_request
def gate():
    g.t0 = time.perf_counter()
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)
    g.sid = session["sid"]
    g.did_known = "did" in request.cookies
    g.did = request.cookies.get("did") or secrets.token_hex(16)
    g.actor = (request.headers.get("X-Lab-Actor") or "unknown")[:40] if _loopback() else "unknown"
    g.egress, g.egress_kind = client_egress()
    g.crawl = None
    if request.path.startswith(("/static/", "/admin/", "/lab/")) or request.path in UNGATED:
        return None
    g.principal, g.identity = classify_request()
    if request.method == "GET" and (request.path in HTML_PAGES or request.path.startswith("/product/")):
        key = f"flow:{g.sid}"
        store.rpush(key, json.dumps([now_ms(), request.path]))
        store.ltrim(key, -50, -1)
        store.expire(key, 3600)
    g.request_score = risk_engine.score_request(request_context(), store, DEFENSE_LEVEL)
    if g.request_score["outcome"] == "block":
        log_decision("request", g.request_score)
        return blocked_reply(g.request_score)
    if request.method == "GET" and is_content_path(request.path):
        return crawl_gate()
    return None


@app.after_request
def finish(response):
    if "did" not in request.cookies and "did" in g:
        response.set_cookie("did", g.did, max_age=365 * 86400, httponly=True, samesite="Lax")
    if "risk_ms" in g:
        response.headers["Server-Timing"] = f"risk;dur={g.risk_ms:.3f}"
    if g.get("crawl") is not None and is_content_path(request.path):
        for k, v in crawl_policy.response_headers(request.host_url.rstrip("/"), DEFENSE_LEVEL).items():
            response.headers[k] = v
        d = g.crawl["decision"]
        if d.action == CHARGED and g.crawl["enforced"]:
            response.headers["crawler-charged"] = f"USD {d.charged:.2f}"
    return response


# --------------------------------------------------------------------------
# L1: the crawl gate on content paths
# --------------------------------------------------------------------------

def crawl_gate():
    ident = crawler_identity.verify(request.headers, g.egress, request.host)
    rules = crawl_policy.rules()
    rule = rules.get(ident.purpose) if ident.operator else None
    disallowed = crawl_policy.is_disallowed(rule, request.path) if ident.operator else False
    minute = int(time.time() // 60)
    key = f"pages:{g.egress}:{minute}"
    pages = int(store.incr(key))
    store.expire(key, 120)
    tagged = maze_mod.tagged(store, g.egress)
    ctx = {"identity": ident, "rule": rule, "path": request.path, "disallowed": disallowed,
           "egress_kind": g.egress_kind, "pages_per_min": pages, "maze_tagged": tagged,
           "price": crawl_policy.price_usd(), "exact": request.headers.get("crawler-exact-price"),
           "max": request.headers.get("crawler-max-price")}
    d = defense("crawl_governance").evaluate(ctx)
    enforced = DEFENSE_LEVEL >= 1
    g.crawl = {"identity": ident, "decision": d, "enforced": enforced, "pages_per_min": pages}
    if enforced and d.action == CHARGED:
        store.incrbyfloat(f"ledger:{ident.operator}", d.charged)
        store.incrbyfloat("ledger:total", d.charged)
    g.content_row = log_decision("content", {"score": d.score, "outcome": d.action, "reasons": [d.reason]},
                                 enforced=enforced, charged=d.charged if enforced else 0.0,
                                 client="crawler" if ident.operator else None, operator=ident.operator or None,
                                 features={"identity": ident._asdict(), "pages_per_min": pages,
                                           "ua_class": crawler_registry.classify_ua(request.headers.get("User-Agent", ""))})
    if not enforced or d.action in (ALLOW, CHARGED):
        return None
    hdrs = {}
    if d.action == BLOCK:
        return Response(f"403 Forbidden\n{d.reason}\n", 403, hdrs, mimetype="text/plain")
    if d.action == PAYWALL:
        hdrs["crawler-price"] = f"USD {d.charged:.2f}"
        return Response("402 Payment Required\n", 402, hdrs, mimetype="text/plain")
    if d.action == MAZE:
        return maze_response(g.egress)
    return None


def would_refuse():
    """The deception limit's input: would the policy refuse this client anyway?"""
    c = g.get("crawl")
    if c and c["decision"].action not in (ALLOW, CHARGED):
        return True
    return g.request_score["score"] >= risk_engine.ALLOW_BELOW


# --------------------------------------------------------------------------
# Replies, blocked pages, the oracle guard
# --------------------------------------------------------------------------

def _shape(body, decision):
    if DEFENSE_LEVEL >= 4:
        return defense("oracle_guard").shape(body, decision, DEFENSE_LEVEL)
    return {**body, "score": decision["score"], "reasons": decision.get("reasons", []), "level": DEFENSE_LEVEL}


def reply(decision, message, status=200, **extra):
    body = {"outcome": decision["outcome"], "message": message, "principal": g.get("principal", {}).get("kind"), **extra}
    if decision["outcome"] == "block" and policy().get("appeal_path"):
        body["appeal"] = "/appeal"
    return jsonify(_shape(body, decision)), status


def blocked_reply(decision):
    appeal = "/appeal" if policy().get("appeal_path") else None
    if request.path.startswith("/api/") or request.is_json:
        body = {"outcome": "block", "message": "Request blocked."}
        if appeal:
            body["appeal"] = appeal
        return jsonify(_shape(body, decision)), 403
    return render_page(BLOCKED_HTML, title="Blocked", decision=decision, appeal=appeal, show_reasons=DEFENSE_LEVEL < 4), 403


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
    if sku not in shop_products():
        return jsonify(outcome="error", message="Unknown product."), 404
    store.set(f"cart:{g.sid}", sku, ex=3600)
    decision = {"outcome": "allow", "score": g.request_score["score"], "reasons": list(g.request_score["reasons"])}
    return reply(decision, f"{shop_products()[sku]['name']} is in your cart.")


def stock_left(sku):
    raw = store.get(f"stock:{sku}")
    if raw is None:
        store.set(f"stock:{sku}", catalog()[sku].get("stock", 10_000))
        raw = store.get(f"stock:{sku}")
    return int(raw)


def device_key(sess):
    # The one-per-device drop cap clusters by fingerprint: a fleet of fresh contexts on one
    # machine shares a fingerprint (caught), while distinct shoppers differ (spared). The did
    # cookie is minted on the first response, so it cannot stand in for "a device we trust".
    return f"fp:{sess['fp_hash'] or 'none'}"


def _checkout(user):
    sku = store.get(f"cart:{g.sid}") or (request.get_json(silent=True) or {}).get("sku")
    if sku not in shop_products():
        return jsonify(outcome="error", message="Your cart is empty."), 400
    if stock_left(sku) <= 0:
        return jsonify(outcome="error", message="Sold out."), 409
    body = request.get_json(silent=True) or {}
    mandate_id = body.get("mandate") or request.headers.get("X-Agent-Mandate")
    mandate = db.session.get(Mandate, str(mandate_id)) if mandate_id else None
    pol = policy()
    sess = session_state("/checkout")
    ustate = user_state(user)
    dkey = device_key(sess)
    fp_accounts = signals.fp_reuse_count(store, sess["fp_hash"], user.id)
    row = signals.derive(sess, ustate, g.principal, g.request_score, g.egress_kind, fp_accounts)
    hour_ago = utcnow() - timedelta(hours=1)
    ctx = {
        "sku": sku, "mandate": mandate, "now": utcnow(), "device_key": dkey,
        "orders_last_hour": Order.query.filter(Order.user_id == user.id, Order.created_at >= hour_ago).count(),
        "device_units": int(store.get(f"dev:{dkey}") or 0) if sku == DROP_SKU else 0,
        "account_units": Order.query.filter_by(user_id=user.id, sku=sku).count() if sku == DROP_SKU else 0,
        "step_up_confirmed": store.get(f"stepup_ok:{g.sid}") == "1",
        "challenge_solved": store.get(f"chal_ok:{g.sid}") == "1",
    }
    card = risk_engine.session_card(row, ustate, ctx, request.headers.get("User-Agent", ""), g.egress_kind, fp_accounts)
    decision = risk_engine.evaluate_checkout(g.request_score, sess, ustate, g.principal, g.identity, row, ctx,
                                             DEFENSE_LEVEL, pol, rule_engine if DEFENSE_LEVEL >= 4 else None, card)
    decision.setdefault("features", {}).update(fp_accounts=fp_accounts, egress_kind=g.egress_kind)
    extra = decision.pop("extra", {})
    kind = None
    if decision["outcome"] == "challenge":
        kind = extra.get("challenge") or ("confirm_code" if extra.get("step_up") else None)
    log_decision("checkout", decision, user, client=row["client"], signals=row["signals"],
                 challenge_kind=kind, non_visual=challenges.NON_VISUAL.get(kind) if kind else None)

    if decision["outcome"] == "allow":
        order = Order(user_id=user.id, sku=sku, address=user.address, placed_by=g.principal["kind"],
                      operator=g.principal.get("operator"), mandate_id=extra.get("mandate_ok"))
        with _db_lock:
            db.session.add(order)
            if extra.get("mandate_ok") and mandate is not None:
                mandate.used_at = utcnow()
            if g.did not in (user.known_devices or []):
                user.known_devices = list(user.known_devices or []) + [g.did]
            db.session.commit()
        store.decr(f"stock:{sku}")
        if sku == DROP_SKU:
            store.incr(f"dev:{dkey}")
            store.expire(f"dev:{dkey}", 86400)
        store.delete(f"cart:{g.sid}", f"stepup:{g.sid}", f"stepup_ok:{g.sid}", f"chal_ok:{g.sid}")
        return reply(decision, f"Order confirmed: {shop_products()[sku]['name']}.", order_id=order.id)

    if decision["outcome"] == "challenge":
        if extra.get("challenge"):
            chal = challenges.issue(store, extra["challenge"], g.sid)
            return reply(decision, "Complete the challenge, then POST /api/checkout/confirm with its token.",
                         202, challenge=chal)
        if extra.get("step_up"):
            code = f"{secrets.randbelow(10 ** 6):06d}"
            store.set(f"stepup:{g.sid}", json.dumps({"code": code, "sku": sku}), ex=STEP_UP_TTL)
            store.rpush(f"mail:{user.email}", json.dumps({"ts": now_ms(), "subject": "Confirm your Lab Store order",
                                                           "code": code}))
            store.expire(f"mail:{user.email}", 3600)
            return reply(decision, f"We emailed a confirmation code to {user.email}. Enter it to finish.", 202,
                         step_up=True, challenge={"kind": "confirm_code", "non_visual": True})
        return reply(decision, "Extra verification is needed before this order can be placed.", 202)

    hint = None
    if extra.get("needs") == "mandate":
        hint = ("Agents: ask your user to grant a mandate at /account (POST /api/account/mandates) and "
                "send its id in the mandate field or the X-Agent-Mandate header.")
    elif g.principal["kind"] == "declared_agent":
        hint = "Agents: see GET /agent-policy for how agents buy here."
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
    body = request.get_json(silent=True) or {}
    if body.get("token"):
        ok, kind, why = challenges.verify(store, body["token"], body)
        decision = {"outcome": "allow" if ok else "deny", "score": 0, "reasons": [why]}
        log_decision("confirm", decision, user, challenge_kind=kind, non_visual=challenges.NON_VISUAL.get(kind))
        if not ok:
            return reply(decision, "That challenge answer is wrong or expired.", 400)
        store.set(f"chal_ok:{g.sid}", "1", ex=STEP_UP_TTL)
        return _checkout(user)
    raw = store.get(f"stepup:{g.sid}")
    code = str(body.get("code", "")).strip()
    if not raw or not code or json.loads(raw)["code"] != code:
        decision = {"outcome": "deny", "score": 0, "reasons": ["Wrong or expired confirmation code"]}
        log_decision("confirm", decision, user, challenge_kind="confirm_code", non_visual=True)
        return reply(decision, "That code is wrong or has expired.", 400)
    store.delete(f"stepup:{g.sid}")
    store.set(f"stepup_ok:{g.sid}", "1", ex=STEP_UP_TTL)
    return _checkout(user)


# --------------------------------------------------------------------------
# Accounts, mandates, reviews
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
    user = User(email=email, password_hash=generate_password_hash(password, "pbkdf2:sha256:1000"),
                address=address, known_devices=[])
    with _db_lock:
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
    """The account holder authorises an agent operator to buy one thing, once, soon. People grant mandates."""
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
    if not operator or sku not in shop_products():
        return jsonify(outcome="error", message="operator and a valid sku are required."), 400
    m = Mandate(id=secrets.token_hex(8), user_id=user.id, operator=operator, sku=sku, max_qty=1,
                expires_at=utcnow() + timedelta(minutes=ttl))
    with _db_lock:
        db.session.add(m)
        db.session.commit()
    decision = {"outcome": "allow", "score": 0, "reasons": []}
    log_decision("mandate", decision, user)
    return reply(decision, "Mandate granted.", mandate=mandate_json(m))


def mandate_json(m):
    return {"id": m.id, "operator": m.operator, "sku": m.sku, "max_qty": m.max_qty,
            "expires_at": _aware(m.expires_at).isoformat(timespec="seconds"),
            "used_at": _aware(m.used_at).isoformat(timespec="seconds") if m.used_at else None}


def guard():
    """L3: the student's llm_guard; below L3 the pre-wired deny-list and a naive prompt (W4 Ch5's start)."""
    if DEFENSE_LEVEL >= 3:
        return defense("llm_guard")

    class Naive:
        AI_DISCLOSURE = None

        @staticmethod
        def ingest(text):
            return injection_regex.evaluate(text)

        @staticmethod
        def build_prompt(system, trusted, untrusted):
            user = "\n".join(f"{k.capitalize()}: {v}" for k, v in trusted.items())
            return system, user + "\n\nReviews:\n" + "\n".join(untrusted)

        @staticmethod
        def validate(output, allowed, secret):
            from decision import allow
            return allow("output not validated")
    return Naive


@app.post("/api/review")
def review():
    user = current_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    body = request.get_json(silent=True) or {}
    sku = body.get("sku")
    text = str(body.get("text", "")).strip()[:2000]
    rating = int(body.get("rating") or 5)
    if sku not in shop_products() or not text:
        return jsonify(outcome="error", message="sku and text are required."), 400
    recent = [r.text for r in Review.query.filter(Review.outcome != "block").order_by(Review.ts.desc()).limit(60).all()]
    d = content_heuristics.evaluate({"text": text, "recent_texts": recent, "email_domain": user.email.split("@")[-1],
                                     "disposable": False})
    if d.action == ALLOW:
        d = guard().ingest(text)
    decision = {"outcome": d.action, "score": int(d.score), "reasons": [d.reason] + list(g.request_score["reasons"])}
    with _db_lock:
        db.session.add(Review(sku=sku, user_id=user.id, rating=rating, text=text, actor=g.actor, outcome=d.action,
                              published=(d.action == ALLOW)))
        db.session.commit()
    log_decision("review", decision, user)
    status = {"allow": 200, "challenge": 202, "block": 403}.get(d.action, 200)
    return reply(decision, {"allow": "Review published.", "challenge": "Review held for moderation.",
                            "block": "Review refused."}.get(d.action, "Recorded."), status)


def _published_reviews(sku):
    return [f"[{r.rating}/5] {r.text}" for r in Review.query.filter_by(sku=sku, published=True).order_by(Review.ts).all()]


def _llm_feature(task, system, trusted, untrusted, fallback):
    gd = guard()
    system2, user = gd.build_prompt(system, trusted, untrusted)
    out = llm.chat(task, system2, user)
    verdict = gd.validate(out.text, ALLOWED_HOSTS, SUPPORT_CODE)
    text = out.text if verdict.action == ALLOW else fallback
    decision = {"outcome": verdict.action, "score": int(verdict.score), "reasons": [verdict.reason],
                "features": {"tokens": out.prompt_tokens + out.completion_tokens, "backend": out.backend}}
    log_decision("llm", decision, current_user(), features=decision["features"] | {"task": task})
    return text, gd.AI_DISCLOSURE, out


@app.get("/product/<sku>/summary")
def summary(sku):
    if sku not in shop_products():
        return jsonify(outcome="error", message="no such product"), 404
    text, disclosure, out = _llm_feature("summarize", SYSTEM_SUMMARY, {"product": shop_products()[sku]["name"]},
                                         _published_reviews(sku), "Summary unavailable.")
    body = {"summary": text, "backend": out.backend}
    if disclosure:
        body["ai_disclosure"] = disclosure
    return jsonify(body)


@app.post("/assist")
def assist():
    body = request.get_json(silent=True) or {}
    sku = body.get("sku")
    question = str(body.get("question", "")).strip()[:300]
    if sku not in shop_products() or not question:
        return jsonify(outcome="error", message="sku and question required"), 400
    p = shop_products()[sku]
    text, disclosure, out = _llm_feature("assist", SYSTEM_ASSIST,
                                         {"product": p["name"], "price": f"{p['price']:.2f}", "question": question},
                                         _published_reviews(sku), "Sorry, I can't help with that right now.")
    resp = {"answer": text, "backend": out.backend}
    if disclosure:
        resp["ai_disclosure"] = disclosure
    r = jsonify(resp)
    if disclosure:
        r.headers["X-AI-Disclosure"] = "automated-assistant"
    return r


# --------------------------------------------------------------------------
# Catalogue, policy documents, maze
# --------------------------------------------------------------------------

@app.get("/api/products")
@app.get("/api/products.json")
def api_products():
    n = max(1, int(request.args.get("page", 1) or 1))
    items = sorted(shop_products().items())
    page = items[(n - 1) * PER_PAGE: n * PER_PAGE]
    return jsonify({"page": n, "pages": (len(items) + PER_PAGE - 1) // PER_PAGE,
                    "products": [{"sku": k, "name": v["name"], "price": v["price"], "category": v["category"],
                                  "drop": v["drop"], "stock_left": stock_left(k) if v["drop"] else None} for k, v in page]})


@app.get("/sitemap.xml")
def sitemap():
    base = request.host_url.rstrip("/")
    urls = "".join(f"<url><loc>{base}/product/{s}</loc></url>" for s in sorted(shop_products()))
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f'{urls}</urlset>', mimetype="application/xml")


@app.get("/robots.txt")
def robots():
    return Response(crawl_policy.robots_txt(request.host_url.rstrip("/"), DEFENSE_LEVEL), mimetype="text/plain")


@app.get("/license.xml")
def license_xml():
    if DEFENSE_LEVEL < 1:
        return Response("404\n", 404, mimetype="text/plain")
    return Response(crawl_policy.rsl_xml(request.host_url.rstrip("/"), crawl_policy.price_usd()),
                    mimetype="application/rsl+xml")


@app.get("/llms.txt")
def llms_txt():
    return Response("# Lab Store\n\n> A 120-product demo shop used in the Antibot Workshop.\n\n## Catalogue\n"
                    "- [Listing](/catalog?page=1): 12 products per page\n- [JSON](/api/products.json?page=1)\n\n"
                    "## Policy\n- [robots.txt](/robots.txt)\n- [RSL licence](/license.xml)\n- [Agents](/agent-policy)\n",
                    mimetype="text/markdown")


@app.get("/.well-known/tdm-policy.json")
def tdm_policy():
    return jsonify({"tdm-reservation": 1, "policy": "Text and data mining is reserved. Licensed training crawls "
                                                    "are priced in /license.xml (RSL)."})


@app.get("/agent-policy")
def agent_policy_doc():
    pol = policy()
    return jsonify({**agent_policy.AGENT_POLICY, "level": DEFENSE_LEVEL, "policy": pol.get("name"),
                    "declaration": pol.get("declaration"), "checkout_step_up": pol.get("checkout_step_up"),
                    "challenge_type": pol.get("challenge_type"),
                    "identity": "HTTP Message Signatures (RFC 9421), Web Bot Auth profile; Signature-Agent must be a trusted operator",
                    "mandates": "POST /api/account/mandates from the account holder's own session; pass the id at checkout"})


@app.get("/appeal")
def appeal():
    pol = policy()
    if not pol.get("appeal_path"):
        return jsonify(outcome="error", message="This store publishes no appeal path."), 404
    return jsonify({"contact": "appeals@lab-store.test", "human_review_within_hours": 24,
                    "reinstated_by_default_after_hours": 72,
                    "how": "Reply with the time of the block and the email on the account. A person reviews it.",
                    "ai_disclosure": "The first reply may come from an automated assistant; it will say so."})


@app.get("/.well-known/governance.json")
def governance():
    pol = policy()
    logp = crawl_policy.logging_policy()
    return jsonify({
        "retention_days": int(pol.get("retention_days", logp.get("retention_days", 365))),
        "appeal_path": "/appeal" if pol.get("appeal_path") else None,
        "terms": crawl_policy.terms() | {"agents_clause": pol.get("terms", {}).get("agents_clause")},
        "challenge_type": pol.get("challenge_type"), "checkout_step_up": pol.get("checkout_step_up"),
        "ai_features": ["review summariser", "support assistant"], "llm_backend": llm.backend,
        "policy": pol.get("name"), "rules": rule_engine.describe(),
        "deception": "decoy content only for traffic the policy would otherwise refuse; never for crawlers "
                     "honouring the reservation or for sessions using the accessibility API",
        "level": DEFENSE_LEVEL,
    })


def maze_response(ip, token=None):
    mz = maze_mod
    token = token or hashlib.sha256(f"{SECRET}:dark:{ip}".encode()).hexdigest()[:12]
    title, paragraphs, children = mz.render(token, babbler(), SECRET)
    links = "".join(f"<li><a href='{mz.MAZE_PREFIX}{c}'>{title.split()[0]} {i}</a></li>" for i, c in enumerate(children))
    body = "".join(f"<p>{x}</p>" for x in paragraphs) + f"<ul>{links}</ul>"
    doc = render_template_string(BASE_HTML, body=f"<h1>{title}</h1>{body}", title=title, user=None, level=DEFENSE_LEVEL,
                                 entry="", extra_head="<meta name='robots' content='noindex, nofollow'>")
    store.incrby("maze:bytes", len(doc))
    hdrs = {"X-Robots-Tag": "noindex, nofollow", "Cache-Control": "no-store"}
    if not _inflight.acquire(blocking=False):
        store.incr("maze:capped")
        return Response(doc, 200, hdrs, mimetype="text/html")

    def drip():
        try:
            step = max(1, len(doc) // mz.DRIP_CHUNKS)
            for i in range(0, len(doc), step):
                yield doc[i:i + step]
                time.sleep(mz.DRIP_DELAY)
        finally:
            _inflight.release()
    return Response(drip(), 200, hdrs, mimetype="text/html")


@app.get("/maze/<token>")
def maze_page(token):
    if DEFENSE_LEVEL < 1 or len(token) != 12 or any(c not in "0123456789abcdef" for c in token):
        return Response("404\n", 404, mimetype="text/plain")
    n = maze_mod.record_hit(store, g.egress)
    log_decision("content", {"score": 90, "outcome": MAZE, "reasons": [f"maze page #{n} for this egress"]},
                 enforced=True, decoy_served=True)
    return maze_response(g.egress, token=token)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

BASE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ title }} · Lab Store</title>
<meta name="viewport" content="width=device-width, initial-scale=1">{{ extra_head|default('')|safe }}
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1b1f24}
 nav a{margin-right:1rem} .card{border:1px solid #ccd;border-radius:8px;padding:1rem;margin:.6rem 0}
 button{font-size:1rem;padding:.6rem 1.4rem;border-radius:6px;border:0;background:#2456c7;color:#fff;cursor:pointer}
 input,select{font-size:1rem;padding:.4rem;margin:.2rem 0 .6rem;width:100%;box-sizing:border-box}
 #result{margin-top:1rem;font-weight:600} .lvl{float:right;color:#777;font-size:.85rem} .hint{color:#555;font-weight:400}
 pre{background:#f4f5f7;padding:.8rem;overflow:auto;font-size:.8rem} footer{margin-top:3rem;color:#888;font-size:.8rem}
 .hp{display:none} .vh{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}
</style></head>
<body data-level="{{ level }}">{{ entry|default('')|safe }}
<nav><a href="/">Lab Store</a><a href="/catalog?page=1">Catalogue</a><a href="/cart">Cart</a>
{% if user %}<a href="/account">{{ user.email }}</a>{% else %}<a href="/login">Log in</a><a href="/register">Register</a>{% endif %}
<span class="lvl">DEFENSE_LEVEL={{ level }}</span></nav>
{{ body|safe }}
<footer>Agents: this store publishes its policy at <a href="/agent-policy">/agent-policy</a> and its governance record at
<a href="/.well-known/governance.json">/.well-known/governance.json</a>. The catalogue is available as Markdown with
<code>Accept: text/markdown</code>. Blocked? <a href="/appeal">/appeal</a>.</footer>
<script src="/static/collector.js"></script>
<script src="/static/shop.js"></script>
</body></html>"""

HOME_HTML = """<h1>Lab Store</h1>
<p>Trail gear for people and, under the right conditions, for their agents.</p>
<div class="card"><strong>Today's drop:</strong> <a href="/product/lab-runner-9">Lab Runner 9 (limited drop)</a> · $220 · one per account</div>
<p><a href="/catalog?page=1">Browse the catalogue</a> · <a href="/search?q=runner">Search</a></p>"""

CATALOG_HTML = """<h1>Catalogue, page {{ page }} of {{ pages }}</h1>
<nav aria-label="Catalogue pages">{% for n in range(1, pages + 1) %}<a href="/catalog?page={{ n }}"{% if n == page %} aria-current="page"{% endif %}>{{ n }}</a> {% endfor %}</nav>
{% for sku, p in items %}<div class="card"><a href="/product/{{ sku }}">{{ p.name }}</a> · ${{ '%.2f'|format(p.price) }} · SKU {{ sku }}{% if p.drop %} · limited drop{% endif %}</div>{% endfor %}
{% if traps.hidden_records or traps.canary_note or traps.decoy_paragraphs %}
<div class="vh" aria-hidden="true" data-decoy="1">
{% if traps.canary_note %}<p>{{ traps.canary_note }}</p>{% endif %}
{% for h in traps.hidden_records %}<div class="card"><a href="/product/{{ h.sku }}">{{ h.name }}</a> · ${{ '%.2f'|format(h.price) }} · SKU {{ h.sku }}</div>{% endfor %}
{% for d in traps.decoy_paragraphs %}<p>{{ d }}</p>{% endfor %}
</div>{% endif %}
{% for hp in honeypot_links %}<a class="hp" href="/product/{{ hp }}" tabindex="-1" aria-hidden="true">{{ hp }}</a>{% endfor %}"""

PRODUCT_HTML = """<h1>{{ product.name }}</h1><p>${{ '%.2f'|format(product.price) }} · {{ product.category }}{% if product.drop %} · limited drop, one per account{% endif %}.</p>
<p>{{ product.description }}</p>
<button id="add-to-cart" data-sku="{{ sku }}">Add to cart</button>
<div id="result" aria-live="polite"></div>
<h2>Reviews</h2>{% for r in reviews %}<div class="card">[{{ r.rating }}/5] {{ r.text }}</div>{% else %}<p>No reviews yet.</p>{% endfor %}
<p><a href="/product/{{ sku }}/summary">AI summary of reviews</a></p>"""

SEARCH_HTML = """<h1>Search: {{ q }}</h1>{% for sku, p in items %}<div class="card"><a href="/product/{{ sku }}">{{ p.name }}</a> · ${{ '%.2f'|format(p.price) }}</div>{% else %}<p>No matches.</p>{% endfor %}"""

CART_HTML = """<h1>Your cart</h1>
{% if sku %}<div class="card">{{ products[sku].name }} · ${{ products[sku].price }}</div>
<p><a id="go-checkout" href="/checkout">Proceed to checkout</a></p>{% else %}<p>Your cart is empty. <a href="/catalog?page=1">Browse products</a>.</p>{% endif %}"""

CHECKOUT_HTML = """<h1>Checkout</h1>
{% if not user %}<p><a href="/login?next=/checkout">Log in</a> to place your order.</p>
{% elif not sku %}<p>Your cart is empty. <a href="/catalog?page=1">Browse products</a>.</p>
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
<form id="mandate-form"><label>Operator <select name="operator"><option>agents.lab-provider.test</option><option>agents.newvendor.test</option><option>chatgpt.com</option><option>anthropic.com</option></select></label>
<label>Product <select name="sku">{% for s, p in products.items() %}<option value="{{ s }}">{{ p.name }}</option>{% endfor %}</select></label>
<label>Valid for (minutes) <input name="ttl_min" type="number" value="15" min="1" max="60"></label>
<button id="mandate-submit" type="submit">Grant mandate</button></form><div id="mandate-result" aria-live="polite"></div>
{% if mandates %}<ul>{% for m in mandates %}<li><code>{{ m.id }}</code> → {{ m.operator }} for {{ m.sku }}, expires {{ m.expires_at }}{% if m.used_at %} (used){% endif %}</li>{% endfor %}</ul>{% endif %}
{% else %}<p><a href="/login">Log in</a></p>{% endif %}"""

BLOCKED_HTML = """<h1>Blocked</h1><p>This request was refused.</p>
{% if show_reasons %}<p>Score {{ decision.score }}.</p><ul>{% for r in decision.reasons %}<li>{{ r }}</li>{% endfor %}</ul>{% endif %}
{% if appeal %}<p>If you think this is a mistake, a person will review it: <a href="{{ appeal }}">{{ appeal }}</a>.</p>{% endif %}"""


def entry_link():
    if DEFENSE_LEVEL >= 1 and g.get("crawl") is not None:
        return maze_mod.entry_link({"client_ip": g.egress}, SECRET)
    return ""


def render_page(body, title, **ctx):
    user = current_user()
    inner = render_template_string(body, user=user, level=DEFENSE_LEVEL, products=shop_products(), **ctx)
    return render_template_string(BASE_HTML, body=inner, title=title, user=user, level=DEFENSE_LEVEL,
                                  entry=entry_link(), extra_head=ctx.get("extra_head", ""))


@app.get("/")
def home():
    return render_page(HOME_HTML, "Home")


def _traps(page):
    traps = {"hidden_records": [], "canary_note": None, "decoy_paragraphs": []}
    if DEFENSE_LEVEL >= 3:
        canary = "LOT-" + hashlib.sha256(f"canary:{g.sid}:{SECRET}".encode()).hexdigest()[:8].upper()
        store.hset("canary", canary, g.sid)
        sess_pages = store.smembers(f"evpages:{g.sid}")
        a11y = any(json.loads(store.get(f"ev:{g.sid}:{p}") or "{}").get("a11y_api") for p in sess_pages)
        traps = defense("deception_limits").decorate({
            "sid": g.sid, "canary": canary, "page": page, "honeypots": honeypots(),
            "would_block": would_refuse(), "identity": g.crawl["identity"] if g.crawl else None, "a11y": a11y})
        if traps.get("hidden_records") or traps.get("canary_note") or traps.get("decoy_paragraphs"):
            row = g.get("content_row")
            if row is not None:
                with _db_lock:
                    row.decoy_served = True
                    db.session.commit()
    return traps


@app.get("/catalog")
@app.get("/products")
def catalog_page():
    if agent_policy.wants_markdown(request.headers, g.principal):
        text, tokens = agent_policy.markdown_catalog(shop_products())
        resp = Response(text, mimetype="text/markdown")
        resp.headers["X-Markdown-Tokens"] = str(tokens)
        resp.headers["Vary"] = "Accept, User-Agent"
        return resp
    n = max(1, int(request.args.get("page", 1) or 1))
    items = sorted(shop_products().items())
    pages = (len(items) + PER_PAGE - 1) // PER_PAGE
    page_items = items[(n - 1) * PER_PAGE: n * PER_PAGE]
    rng = random.Random(f"{g.sid}:{n}")
    hp_links = [h["sku"] for h in rng.sample(honeypots(), min(2, len(honeypots())))] if DEFENSE_LEVEL >= 3 else []
    return render_page(CATALOG_HTML, f"Catalogue {n}", page=n, pages=pages, items=page_items, traps=_traps(n),
                       honeypot_links=hp_links)


@app.get("/product/<sku>")
def product_page(sku):
    p = catalog().get(sku)
    if p is None:
        return render_page("<h1>Not found</h1>", "Not found"), 404
    if p["honeypot"]:
        decision = {"score": 100, "outcome": "block", "reasons": ["fetched a honeypot SKU: only a machine reader finds it"]}
        log_decision("content", decision, enforced=True)
        return blocked_reply(decision)
    reviews = Review.query.filter_by(sku=sku, published=True).order_by(Review.ts).all()
    return render_page(PRODUCT_HTML, p["name"], product=p, sku=sku, reviews=reviews)


@app.get("/search")
def search():
    q = (request.args.get("q") or "").strip().lower()[:60]
    items = [(k, v) for k, v in sorted(shop_products().items()) if q and q in v["name"].lower()][:50]
    return render_page(SEARCH_HTML, "Search", q=q, items=items)


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
    """Lab oracle (loopback only in spirit; never ship): how this request is classified at every layer."""
    principal, identity = classify_request()
    ctx = request_context()
    scored = risk_engine.score_request(ctx, store, DEFENSE_LEVEL, count=False)
    sess = session_state("/checkout")
    ident = crawler_identity.verify(request.headers, ctx["egress"], request.host)
    return jsonify({"level": DEFENSE_LEVEL, "sid": g.sid, "user_agent": ctx["ua"], "egress": ctx["egress"],
                    "egress_kind": ctx["egress_kind"], "principal": principal, "identity": identity,
                    "crawler_identity": ident._asdict(), "request_score": scored,
                    "behavior": agent_behavior.features(sess), "fp_hash": sess["fp_hash"],
                    "w2_shadow": dict(zip(("points", "reasons"), risk_engine.w2_shadow(sess))),
                    "policy": policy().get("name"), "rules": rule_engine.describe(), "llm_backend": llm.backend})


# --------------------------------------------------------------------------
# Lab and admin endpoints (tools only)
# --------------------------------------------------------------------------

@app.get("/lab/mailbox/<path:email>")
def lab_mailbox(email):
    raw = store.lrange(f"mail:{email.lower()}", -1, -1)
    return jsonify({"email": email, "message": json.loads(raw[0]) if raw else None})


@app.get("/lab/answer/<token>")
def lab_answer(token):
    """The image-challenge answer, so the *sighted* human simulator can answer like a person who looked."""
    if not _loopback():
        return jsonify(error="loopback only"), 403
    return jsonify({"answer": challenges.answer_for(store, token)})


@app.get("/lab/canaries")
def lab_canaries():
    return jsonify(store.hgetall("canary"))


def admin_ok():
    return request.headers.get("X-Lab-Admin") == ADMIN_KEY


@app.post("/admin/reset")
def admin_reset():
    """Clear drop orders, mandates, reviews and per-session state so a checkpoint starts clean; restock the drop."""
    if not admin_ok():
        return jsonify(ok=False), 403
    with _db_lock:
        Order.query.filter_by(sku=DROP_SKU).delete()
        Mandate.query.delete()
        Review.query.delete()
        if request.args.get("decisions") == "1":
            Decision.query.delete()
        if request.args.get("fresh_accounts") == "1":
            since = datetime.now(timezone.utc) - timedelta(days=1)
            for u in User.query.filter(User.created_at >= since):
                Order.query.filter_by(user_id=u.id).delete()
                db.session.delete(u)
        db.session.commit()
    for pattern in ("flow:*", "fp:*", "fph:*", "ev:*", "evpages:*", "rl:*", "cart:*", "stepup*", "chal*", "mail:*",
                    "dev:*", "nonce:*", "stock:*", "pages:*", "maze:*", "ledger:*", "fpacct:*", "canary"):
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
    rows = query.order_by(Decision.id.asc()).limit(int(request.args.get("limit", 20000))).all()
    return jsonify([{
        "id": d.id, "ts": _aware(d.ts).isoformat(timespec="seconds"), "sid": d.sid, "user_id": d.user_id, "actor": d.actor,
        "action": d.action, "path": d.path, "level": d.level, "score": d.score, "outcome": d.outcome, "enforced": d.enforced,
        "principal": d.principal, "operator": d.operator, "client": d.client, "egress_kind": d.egress_kind,
        "signals": d.signals, "reasons": d.reasons, "shadow": d.shadow, "features": d.features,
        "challenge_kind": d.challenge_kind, "non_visual": d.non_visual, "decoy_served": d.decoy_served,
        "charged": d.charged, "score_ms": d.score_ms,
    } for d in rows])


@app.post("/admin/purge")
def admin_purge():
    """Retention: delete decisions older than the published retention_days. ?dry_run=1 only counts."""
    if not admin_ok():
        return jsonify(ok=False), 403
    days = int(policy().get("retention_days", 365))
    cutoff = utcnow() - timedelta(days=days)
    q = Decision.query.filter(Decision.ts < cutoff)
    n = q.count()
    if request.args.get("dry_run") != "1":
        with _db_lock:
            q.delete()
            db.session.commit()
    return jsonify(ok=True, retention_days=days, cutoff=cutoff.isoformat(timespec="seconds"),
                   deleted=0 if request.args.get("dry_run") == "1" else n, would_delete=n)


@app.get("/admin/status")
def admin_status():
    last = Decision.query.order_by(Decision.id.desc()).first()
    ledger = {k.split(":", 1)[1]: round(float(v), 2) for k, v in ((k, store.get(k)) for k in store.keys("ledger:*"))}
    return jsonify(level=DEFENSE_LEVEL, last_decision_id=last.id if last else 0, drop_stock_left=stock_left(DROP_SKU),
                   redis="external" if REDIS_URL and not REDIS_URL.startswith("memory://") else "fakeredis",
                   llm_backend=llm.backend, policy=policy().get("name"), rules=rule_engine.describe(), ledger=ledger,
                   maze_bytes=int(store.get("maze:bytes") or 0), store="capstone")


from sqlalchemy import event  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    if "sqlite3" in type(dbapi_conn).__module__:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if Product.query.count() == 0:
            raise SystemExit("Empty catalogue: run `python tools/seed.py` first.")
    print(f" * DEFENSE_LEVEL={DEFENSE_LEVEL}  http://127.0.0.1:{PORT}  "
          f"({'Redis ' + REDIS_URL if REDIS_URL and not REDIS_URL.startswith('memory://') else 'fakeredis'}, "
          f"{DATABASE_URL.split(':')[0]}, LLM {llm.backend}, policy {policy().get('name')})")
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
