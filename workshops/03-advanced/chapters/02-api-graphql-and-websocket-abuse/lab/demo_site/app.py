"""W3 Ch2 — demo store: the "Lab Runner 9" sneaker shop, now behind an API.

The end-of-Workshop-2 store, reached through three API surfaces instead of only
HTML: a versioned REST API, a GraphQL endpoint, and a WebSocket feed. Every
protected action is scored by the layered risk engine in defenses/engine.py.

    DEFENSE_LEVEL=0  no API defenses (the attacker's playground)
    DEFENSE_LEVEL=1  + cost-aware REST rate limiting        (Round 1, L1)
    DEFENSE_LEVEL=2  + GraphQL depth/alias/token limits      (Round 2, L2)
    DEFENSE_LEVEL=3  + persisted-query allowlist             (Round 3, L3)
    DEFENSE_LEVEL=4  + WebSocket connect/origin/rate guard   (Round 4, L4)
    DEFENSE_LEVEL=5  + HMAC request signing + token binding  (Round 5, L5)

Each level includes every level below it. Layers above DEFENSE_LEVEL run in
shadow mode: their points are logged in decisions.shadow but do not count.

Run (from lab/):
    python tools/seed.py
    DEFENSE_LEVEL=0 python demo_site/app.py          # http://127.0.0.1:5000
    DEFENSE_LEVEL=2 python demo_site/app.py

Debug endpoint, never gated: /whoami (how this request scores now).
Block replies list the reasons they fired. That is for teaching only. In
production, never tell a client which rule caught it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import sys
import time

import jwt
from flask import Flask, g, jsonify, request
from flask_sock import Sock
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

import engine  # noqa: E402
import graphql_limits  # noqa: E402
import persisted_queries  # noqa: E402
import rate_cost  # noqa: E402
import request_signing  # noqa: E402
import response_deception  # noqa: E402
import token_binding  # noqa: E402
import ws_guard  # noqa: E402
from models import Decision, Order, Product, User, db, now  # noqa: E402
from schema import schema  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
PORT = int(os.environ.get("PORT", "5000"))
os.makedirs(INSTANCE, exist_ok=True)
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE, 'shop.db')}")

MAX_BATCH = 25  # basic hygiene: cap array-batched GraphQL operations at every level

LAB_NETWORKS = [
    (ipaddress.ip_network("198.51.100.0/24"), "residential"),
    (ipaddress.ip_network("203.0.113.0/24"), "residential"),
    (ipaddress.ip_network("192.0.2.0/24"), "datacenter"),
]


def load_secret() -> str:
    path = os.path.join(INSTANCE, "lab_secret")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


SECRET = load_secret()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET,
    SQLALCHEMY_DATABASE_URI=DATABASE_URL,
    SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread": False, "timeout": 10}}
    if DATABASE_URL.startswith("sqlite") else {},
)
db.init_app(app)
sock = Sock(app)

from store import make_redis  # noqa: E402

store = make_redis()


# --------------------------------------------------------------------------
# Request context
# --------------------------------------------------------------------------

def client_egress() -> tuple[str, str]:
    """(ip, class). A loopback request may claim an RFC 5737 egress for the lab."""
    claimed = request.headers.get("X-Lab-Egress")
    if claimed and request.remote_addr in ("127.0.0.1", "::1"):
        try:
            ip = ipaddress.ip_address(claimed)
        except ValueError:
            ip = None
        if ip is not None:
            for net, kind in LAB_NETWORKS:
                if ip in net:
                    return str(ip), kind
    return request.remote_addr or "127.0.0.1", "local"


def ua_family(ua: str) -> str:
    ua = ua or ""
    low = ua.lower()
    if "firefox" in low:
        return "firefox"
    if "edg/" in low or "opr/" in low:
        return "chrome"
    if "chrome" in low:
        return "chrome"
    if "safari" in low and "mobile" in low:
        return "safari"
    if any(s in low for s in ("python", "httpx", "curl", "aiohttp", "go-http", "node")):
        return "script"
    return "other"


def decode_token(tok: str):
    try:
        return jwt.decode(tok, SECRET, algorithms=["HS256"])
    except Exception:
        return None


def issue_token(user: User, ip_class: str, uaf: str) -> str:
    payload = {
        "sub": user.id,
        "jti": secrets.token_hex(8),
        "bind": token_binding.binding_hash(ip_class, uaf),
        "iat": int(time.time()),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def ctx_from_request(count_key_detail=False) -> dict:
    ip, ip_class = client_egress()
    uaf = ua_family(request.headers.get("User-Agent", ""))
    actor = request.headers.get("X-Lab-Actor", "unknown")
    auth = request.headers.get("Authorization", "")
    token = auth.split(" ", 1)[1] if auth.startswith("Bearer ") else ""
    payload = decode_token(token) if token else None
    key = payload["sub"] if payload else ip
    return {"ip": ip, "ip_class": ip_class, "ua_family": uaf, "actor": actor,
            "token": token, "payload": payload, "key": key}


# --------------------------------------------------------------------------
# Decision logging
# --------------------------------------------------------------------------

def log_decision(surface: str, action: str, decision: dict, ctx: dict, cost_ms: float):
    row = Decision(ts=now(), actor=ctx.get("actor", ""), client_ip=ctx.get("ip", ""),
                   level=DEFENSE_LEVEL, surface=surface, action=action,
                   score=decision["score"], outcome=decision["outcome"],
                   reasons=decision["reasons"], shadow=decision.get("shadow", {}),
                   cost_ms=round(cost_ms, 3))
    db.session.add(row)
    db.session.commit()
    g.cost_ms = cost_ms


@app.after_request
def add_timing(resp):
    if hasattr(g, "cost_ms"):
        resp.headers["Server-Timing"] = f"score;dur={g.cost_ms:.3f}"
    return resp


def blocked(reasons, status=403):
    # Teaching only: a production API must not echo which rule fired.
    return jsonify({"error": "request blocked", "reasons": reasons}), status


# --------------------------------------------------------------------------
# REST API v2
# --------------------------------------------------------------------------

@app.get("/api/v2/products")
def products():
    ctx = ctx_from_request()
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = int(request.args.get("per_page", 20) or 20)
    ctx.update(is_list=True, is_detail=False, per_page=per_page)
    t0 = time.perf_counter()
    decision = engine.combine([(1, "L1", rate_cost.score_rest(ctx, store, count=True))], DEFENSE_LEVEL)
    cost_ms = (time.perf_counter() - t0) * 1000
    log_decision("rest", "products.list", decision, ctx, cost_ms)
    if decision["outcome"] == "block":
        return blocked(decision["reasons"])
    eff = min(per_page, 200)  # sane hard cap; the L1 oversized-page penalty is separate
    q = Product.query.filter_by(hidden=False).order_by(Product.id)
    rows = q.offset((page - 1) * eff).limit(eff).all()
    return jsonify({"page": page, "per_page": eff, "items": [p.public() for p in rows],
                    "has_more": q.offset(page * eff).first() is not None})


@app.get("/api/v2/products/<int:pid>")
def product_detail(pid):
    ctx = ctx_from_request()
    ctx.update(is_list=False, is_detail=True, product_id=pid, per_page=1)
    t0 = time.perf_counter()
    decision = engine.combine([(1, "L1", rate_cost.score_rest(ctx, store, count=True))], DEFENSE_LEVEL)
    cost_ms = (time.perf_counter() - t0) * 1000
    log_decision("rest", "products.detail", decision, ctx, cost_ms)
    if decision["outcome"] == "block":
        return blocked(decision["reasons"])
    p = db.session.get(Product, pid)
    if not p:
        return jsonify({"error": "not found"}), 404
    return jsonify(p.public())


@app.post("/api/v2/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    email, password = body.get("email", ""), body.get("password", "")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "exists"}), 409
    user = User(id=secrets.token_hex(8), email=email,
                password_hash=generate_password_hash(password),
                api_secret=secrets.token_hex(16))
    db.session.add(user)
    db.session.commit()
    return jsonify({"status": "registered", "user_id": user.id})


@app.post("/api/v2/auth/login")
def login():
    ctx = ctx_from_request()
    body = request.get_json(silent=True) or {}
    user = User.query.filter_by(email=body.get("email", "")).first()
    if not user or not check_password_hash(user.password_hash, body.get("password", "")):
        return jsonify({"error": "invalid credentials"}), 401
    token = issue_token(user, ctx["ip_class"], ctx["ua_family"])
    # The signing secret is delivered once, over this authenticated response.
    return jsonify({"access_token": token, "token_type": "Bearer",
                    "api_secret": user.api_secret})


def _protected_decision(ctx, action):
    """L1 cost + L5 signing/binding, as one decision."""
    payload = ctx.get("payload")
    user = db.session.get(User, payload["sub"]) if payload else None
    secret = user.api_secret if user else ""
    body = request.get_data() or b""
    path = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path
    sign = request_signing.verify(request.method, path, request.headers, body, secret, time.time())
    bind = token_binding.score(payload.get("bind") if payload else None,
                               ctx["ip_class"], ctx["ua_family"])
    ctx.update(is_list=False, is_detail=False, per_page=1)
    layers = [
        (1, "L1", rate_cost.score_rest(ctx, store, count=True)),
        (5, "L5", sign),
        (5, "L5", bind),
    ]
    base = {"score": 0, "reasons": [], "shadow": {}}
    if not payload:
        base["reasons"].append("no bearer token")
    return engine.combine(layers, DEFENSE_LEVEL, base=base), user


@app.get("/api/v2/account/orders")
def account_orders():
    ctx = ctx_from_request()
    if not ctx.get("payload"):
        return jsonify({"error": "unauthenticated"}), 401
    t0 = time.perf_counter()
    decision, user = _protected_decision(ctx, "account.orders")
    cost_ms = (time.perf_counter() - t0) * 1000
    log_decision("rest", "account.orders", decision, ctx, cost_ms)
    if decision["outcome"] == "block":
        return blocked(decision["reasons"], status=401)
    rows = Order.query.filter_by(user_id=user.id).all()
    return jsonify({"orders": [{"id": o.id, "sku": o.sku, "ts": o.ts} for o in rows]})


@app.get("/api/v2/inventory/<sku>")
def inventory(sku):
    """Pricing/inventory read: when a caller is judged a bot, we deceive rather
    than block, so a scraper banks poisoned numbers without learning it was caught."""
    ctx = ctx_from_request()
    if not ctx.get("payload"):
        return jsonify({"error": "unauthenticated"}), 401
    t0 = time.perf_counter()
    decision, user = _protected_decision(ctx, "inventory.read")
    cost_ms = (time.perf_counter() - t0) * 1000
    log_decision("rest", "inventory.read", decision, ctx, cost_ms)
    p = Product.query.filter_by(sku=sku).first()
    if not p:
        return jsonify({"error": "not found"}), 404
    item = p.public()
    if DEFENSE_LEVEL >= 5 and response_deception.should_deceive(decision["outcome"]):
        item = response_deception.poison_products([item])[0]
        return jsonify({"item": item, "deceived": True})
    return jsonify({"item": item})


# --------------------------------------------------------------------------
# GraphQL
# --------------------------------------------------------------------------

@app.get("/graphql")
def graphql_info():
    return jsonify({
        "message": "POST a GraphQL operation. Introspection and GraphiQL are disabled.",
        "limits": {"max_depth": graphql_limits.MAX_DEPTH, "max_aliases": graphql_limits.MAX_ALIASES,
                   "max_tokens": graphql_limits.MAX_TOKENS, "max_batch": MAX_BATCH},
    })


def _run_graphql_op(op: dict, ctx: dict):
    query = op.get("query", "") or ""
    provided_hash = (op.get("extensions", {}) or {}).get("persistedQuery", {}).get("sha256Hash")
    t0 = time.perf_counter()
    decision = engine.combine([
        (2, "L2", graphql_limits.score_query(query)),
        (3, "L3", persisted_queries.score_query(query, provided_hash)),
    ], DEFENSE_LEVEL)
    cost_ms = (time.perf_counter() - t0) * 1000
    log_decision("graphql", op.get("operationName") or "query", decision, ctx, cost_ms)
    if decision["outcome"] == "block":
        return {"errors": [{"message": r} for r in decision["reasons"]]}, False
    context = {"cost": 0}
    result = schema.execute_sync(query, variable_values=op.get("variables"),
                                 operation_name=op.get("operationName"), context_value=context)
    out = {"data": result.data}
    if result.errors:
        out["errors"] = [{"message": str(e.message)} for e in result.errors]
    out["extensions"] = {"cost": context["cost"]}
    return out, True


@app.post("/graphql")
def graphql_endpoint():
    ctx = ctx_from_request()
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"errors": [{"message": "invalid JSON body"}]}), 400
    if isinstance(body, list):
        if len(body) > MAX_BATCH:
            return jsonify({"errors": [{"message": f"batch too large (max {MAX_BATCH})"}]}), 400
        results = [_run_graphql_op(op, ctx)[0] for op in body]
        return jsonify(results)
    result, ok = _run_graphql_op(body, ctx)
    return jsonify(result), (200 if ok else 400)


# --------------------------------------------------------------------------
# WebSocket live feed
# --------------------------------------------------------------------------

@sock.route("/ws/drop")
def ws_drop(ws):
    ctx = ctx_from_request()
    origin = request.headers.get("Origin")
    token = request.args.get("token", "")
    payload = decode_token(token) if token else None
    subject = payload["sub"] if payload else None
    bucket = ws_guard.ConnBucket()
    accepted = 0
    outcome = "allow"
    reasons: list[str] = []

    if DEFENSE_LEVEL >= 4:
        ok, reason = ws_guard.authorize(origin, subject, action_needs_auth=False)
        if not ok:
            outcome, reasons = "block", [f"[L4] {reason}"]
            _log_ws(ctx, "connect", outcome, reasons, accepted)
            ws.send(json.dumps({"error": reason, "code": 4403}))
            return

    while True:
        raw = ws.receive(timeout=10)
        if raw is None:
            break
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        action = msg.get("action", "")

        if DEFENSE_LEVEL >= 4:
            ok, reason = ws_guard.message_allowed(bucket)
            if not ok:
                reasons.append(f"[L4] {reason}")
                if bucket.violations >= 3:
                    outcome = "block"
                    ws.send(json.dumps({"error": "rate limit abuse", "code": 4029}))
                    ws.close()
                    break
                ws.send(json.dumps({"error": reason}))
                continue
            if action == "bid":
                ok, reason = ws_guard.authorize(origin, subject, action_needs_auth=True)
                if not ok:
                    reasons.append(f"[L4] {reason}")
                    ws.send(json.dumps({"error": reason, "code": 4401}))
                    continue

        accepted += 1
        if action == "subscribe":
            ws.send(json.dumps({"event": "inventory", "sku": "lab-runner-9", "left": 50}))
        elif action == "bid":
            ws.send(json.dumps({"event": "bid_ack", "item": msg.get("item_id")}))
        else:
            ws.send(json.dumps({"event": "ok"}))

    if outcome == "allow" and reasons:
        outcome = "challenge"
    _log_ws(ctx, "feed", outcome, reasons, accepted)


def _log_ws(ctx, action, outcome, reasons, accepted):
    score = 60 if outcome == "block" else (30 if outcome == "challenge" else 0)
    decision = {"score": score, "outcome": outcome,
                "reasons": reasons + [f"messages accepted: {accepted}"], "shadow": {}}
    with app.app_context():
        log_decision("ws", action, decision, ctx, 0.0)


# --------------------------------------------------------------------------
# Debug + admin
# --------------------------------------------------------------------------

@app.get("/")
def home():
    return jsonify({"store": "Lab Runner 9", "api": "/api/v2", "graphql": "/graphql",
                    "ws": "/ws/drop", "defense_level": DEFENSE_LEVEL})


@app.get("/whoami")
def whoami():
    ctx = ctx_from_request()
    ctx.update(is_list=True, is_detail=False, per_page=20)
    decision = engine.combine([(1, "L1", rate_cost.score_rest(ctx, store, count=False))], DEFENSE_LEVEL)
    return jsonify({"ip": ctx["ip"], "ip_class": ctx["ip_class"], "ua_family": ctx["ua_family"],
                    "authenticated": bool(ctx["payload"]), "level": DEFENSE_LEVEL,
                    "decision": decision})


@app.get("/admin/decisions")
def admin_decisions():
    q = Decision.query.order_by(Decision.id.desc())
    surface = request.args.get("surface")
    actor = request.args.get("actor")
    if surface:
        q = q.filter_by(surface=surface)
    if actor:
        q = q.filter_by(actor=actor)
    limit = int(request.args.get("limit", 200))
    rows = q.limit(limit).all()
    return jsonify([r.as_dict() for r in rows])


@app.post("/admin/reset")
def admin_reset():
    Decision.query.delete()
    db.session.commit()
    for k in store.scan_iter("cost:*"):
        store.delete(k)
    for k in store.scan_iter("enum:*"):
        store.delete(k)
    return jsonify({"status": "reset"})


@app.get("/admin/status")
def admin_status():
    return jsonify({"level": DEFENSE_LEVEL, "decisions": Decision.query.count()})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print(f"[demo_site] DEFENSE_LEVEL={DEFENSE_LEVEL} on http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, threaded=True)
