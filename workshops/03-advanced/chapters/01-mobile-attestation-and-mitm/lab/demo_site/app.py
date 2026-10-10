"""
W3 Ch1 — Demo store: the "Lab Runner" mobile app backend (Section 1.x)

The W2 sneaker store now ships a native mobile app. This is its JSON API. The
app sells one limited sneaker (one pair per account), and the buy endpoint is
the protected action every round attacks.

    DEFENSE_LEVEL=0  L0 only: app-shape + per-egress rate (the baseline the
                     faithful MitM replay in Round 1 walks straight past)
    DEFENSE_LEVEL=1  + attestation: require a valid provider verdict   (Round 2)
    DEFENSE_LEVEL=2  + request signing: bound, fresh, single-use       (Round 3)
    DEFENSE_LEVEL=3  + device verdict: integrity + device/egress velocity (Round 4)

Every layer is computed on every buy. Layers above DEFENSE_LEVEL run in shadow
mode: their points land in decisions.shadow but don't count.

No Docker needed: the store defaults to SQLite and an in-memory Redis
(fakeredis). Set DATABASE_URL / REDIS_URL for the production-shaped path.

Run (from lab/):
    python tools/make_cert.py
    REDIS_URL=memory:// python demo_site/app.py           # DEFENSE_LEVEL=0
    DEFENSE_LEVEL=2 REDIS_URL=memory:// python demo_site/app.py

Debug endpoint, never blocked: /api/mobile/whoami (how this request scores).
The 403 replies include their reasons for teaching only. In production, never
tell a client which rule caught it.
"""

import hashlib
import ipaddress
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
INSTANCE = os.path.join(LAB_DIR, "instance")
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

import mobile_core  # noqa: E402
import risk_engine  # noqa: E402
from edge import serve  # noqa: E402
from models import Decision, Order, User, db, utcnow  # noqa: E402

DEFENSE_LEVEL = int(os.environ.get("DEFENSE_LEVEL", "0"))
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{os.path.join(INSTANCE, 'shop.db')}")
REDIS_URL = os.environ.get("REDIS_URL", "memory://")
PORT = int(os.environ.get("PORT", "8443"))

DROP_SKU = "lab-runner-9"
PRODUCTS = {
    DROP_SKU: {"name": "Lab Runner 9 (limited drop)", "price": 220, "drop": True},
    "trail-socks": {"name": "Trail socks, 3-pack", "price": 18, "drop": False},
}
NONCE_TTL = 180
MTOK_TTL = 3600
UNGATED = {"/api/mobile/whoami", "/favicon.ico"}

# Simulated egress. The lab runs on one machine, so every request really comes
# from 127.0.0.1. Scripts may claim a source IP with X-Lab-Egress, but only from
# documentation ranges (RFC 5737), so no real address is ever used. In
# production the IP comes from the TCP connection or your own edge, never a
# client header.
LAB_NETWORKS = [
    (ipaddress.ip_network("198.51.100.0/24"), "residential"),
    (ipaddress.ip_network("203.0.113.0/24"), "residential"),
    (ipaddress.ip_network("192.0.2.0/24"), "datacenter"),
]


def make_store():
    if REDIS_URL.startswith("memory://"):
        import fakeredis
        return fakeredis.FakeStrictRedis(decode_responses=True)
    import redis
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


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

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET, SQLALCHEMY_DATABASE_URI=DATABASE_URL)
db.init_app(app)
store = make_store()


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
        "method": request.method, "path": request.path, "headers": request.headers,
        "ua": request.headers.get("User-Agent", ""),
        "ja4": request.environ.get("lab.ja4"), "alpn": request.environ.get("lab.tls_alpn", []),
        "egress": egress, "egress_kind": egress_kind, "sid": g.get("sid"),
    }


def buy_context(raw_body):
    ctx = request_context()
    ctx.update(body=raw_body, now_ms=now_ms())
    return ctx


def bearer_user():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    uid = store.get(f"mtok:{token}") if token else None
    return db.session.get(User, int(uid)) if uid else None


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@app.before_request
def gate():
    g.t0 = time.perf_counter()
    g.sid = request.headers.get("X-Lab-Device") or secrets.token_hex(8)
    if request.path.startswith(("/admin/",)) or request.path in UNGATED:
        return None
    g.request_score = risk_engine.score_request(request_context(), store, DEFENSE_LEVEL)
    if g.request_score["outcome"] == "block":
        log_decision("request", g.request_score)
        return jsonify(_body(g.request_score, "Request blocked.")), 403
    return None


@app.after_request
def finish(response):
    if "risk_ms" in g:
        response.headers["Server-Timing"] = f"risk;dur={g.risk_ms:.3f}"
    return response


def _body(decision, message, **extra):
    return {"outcome": decision["outcome"], "message": message, "score": decision["score"],
            "reasons": decision["reasons"], "level": DEFENSE_LEVEL, **extra}


def log_decision(action, decision, user=None):
    g.risk_ms = (time.perf_counter() - g.t0) * 1000
    db.session.add(Decision(
        sid=g.get("sid"), user_id=user.id if user else None, action=action, level=DEFENSE_LEVEL,
        score=decision["score"], outcome=decision["outcome"], reasons=decision["reasons"],
        shadow=decision.get("shadow", {}), features=decision.get("features", {}), score_ms=g.risk_ms))
    db.session.commit()


def reply(decision, message, status=200, **extra):
    return jsonify(_body(decision, message, **extra)), status


# --------------------------------------------------------------------------
# Mobile API
# --------------------------------------------------------------------------

@app.get("/api/mobile/config")
def mobile_config():
    return jsonify(app_id=mobile_core.APP_ID, app_version=mobile_core.APP_VERSION,
                   products=[{"sku": k, **v} for k, v in PRODUCTS.items()], level=DEFENSE_LEVEL)


@app.get("/api/mobile/nonce")
def mobile_nonce():
    """A single-use server challenge the app binds its attestation to (Round 3)."""
    nonce = secrets.token_hex(16)
    store.set(f"issued:{nonce}", 1, ex=NONCE_TTL)
    return jsonify(nonce=nonce, ttl=NONCE_TTL)


@app.post("/api/mobile/register")
def mobile_register():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    address = str(body.get("address", ""))[:300].strip()
    if not email or "@" not in email or len(password) < 8 or not address:
        return jsonify(outcome="error", message="Email, 8+ char password and address required."), 400
    if User.query.filter_by(email=email).first():
        return jsonify(outcome="error", message="That email is already registered."), 409
    # Lab-speed hashing so Round 4 stays fast. Production: argon2id or werkzeug default.
    user = User(email=email, password_hash=generate_password_hash(password, "pbkdf2:sha256:1000"),
                address=address, known_devices=[g.get("sid")])
    db.session.add(user)
    db.session.commit()
    token = secrets.token_hex(24)
    store.set(f"mtok:{token}", str(user.id), ex=MTOK_TTL)
    return jsonify(outcome="allow", token=token, email=user.email)


@app.post("/api/mobile/login")
def mobile_login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", ""))[:200].strip().lower()
    password = str(body.get("password", ""))[:200]
    user = User.query.filter_by(email=email).first()
    if not (user and check_password_hash(user.password_hash, password)):
        return jsonify(outcome="deny", message="Wrong email or password."), 401
    token = secrets.token_hex(24)
    store.set(f"mtok:{token}", str(user.id), ex=MTOK_TTL)
    return jsonify(outcome="allow", token=token, email=user.email)


@app.post("/api/mobile/buy")
def mobile_buy():
    raw = request.get_data() or b""
    body = json.loads(raw.decode() or "{}") if raw else {}
    user = bearer_user()
    if user is None:
        return jsonify(outcome="error", message="Log in first."), 401
    sku = body.get("sku")
    if sku not in PRODUCTS:
        return jsonify(outcome="error", message="Unknown product."), 404
    if Order.query.filter_by(user_id=user.id, sku=sku).first():
        return jsonify(outcome="error", message="One pair per account."), 409

    verdict = mobile_core.verify(request.headers.get("X-Attest", ""))
    decision = risk_engine.evaluate_buy(g.request_score, buy_context(raw), verdict, store, DEFENSE_LEVEL)
    log_decision("buy", decision, user)
    if decision["outcome"] == "allow":
        db.session.add(Order(user_id=user.id, sku=sku, address=user.address))
        db.session.commit()
        return reply(decision, f"Order confirmed: {PRODUCTS[sku]['name']}.")
    if decision["outcome"] == "challenge":
        return reply(decision, "Extra verification needed before checkout.", 202)
    return reply(decision, "Checkout blocked.", 403)


@app.get("/api/mobile/whoami")
def mobile_whoami():
    ctx = request_context()
    scored = risk_engine.score_request(ctx, store, DEFENSE_LEVEL, count=False)
    verdict = mobile_core.verify(request.headers.get("X-Attest", ""))
    return jsonify(
        level=DEFENSE_LEVEL, ja4=ctx["ja4"], alpn_offered=ctx["alpn"],
        user_agent=ctx["ua"], egress=ctx["egress"], egress_kind=ctx["egress_kind"],
        attested=verdict is not None,
        integrity=None if verdict is None else mobile_core.integrity_level(verdict),
        app_integrity=None if verdict is None else verdict.get("appIntegrity"),
        request_score=scored)


# --------------------------------------------------------------------------
# A tiny landing page so a browser visiting the store sees something
# --------------------------------------------------------------------------

@app.get("/")
def home():
    return (f"<h1>Lab Runner store</h1><p>This store is driven by its mobile app's JSON API "
            f"under <code>/api/mobile/</code>. DEFENSE_LEVEL={DEFENSE_LEVEL}.</p>"
            f"<p>See <code>/api/mobile/whoami</code> for how your client scores.</p>")


# --------------------------------------------------------------------------
# Admin (tools only): needs the X-Lab-Admin key derived from instance/lab_secret
# --------------------------------------------------------------------------

def admin_ok():
    return request.headers.get("X-Lab-Admin") == ADMIN_KEY


@app.post("/admin/reset")
def admin_reset():
    if not admin_ok():
        return jsonify(ok=False), 403
    Order.query.filter_by(sku=DROP_SKU).delete()
    if request.args.get("decisions") == "1":
        Decision.query.delete()
    db.session.commit()
    for pattern in ("rl:*", "nonce:*", "issued:*", "spent:*", "dev:*", "weakdev:*", "mtok:*"):
        for key in store.scan_iter(pattern, count=1000):
            store.delete(key)
    return jsonify(ok=True, level=DEFENSE_LEVEL)


@app.get("/admin/decisions")
def admin_decisions():
    if not admin_ok():
        return jsonify(ok=False), 403
    query = Decision.query
    if request.args.get("action"):
        query = query.filter_by(action=request.args["action"])
    rows = query.order_by(Decision.id.desc()).limit(int(request.args.get("limit", 5000))).all()
    return jsonify([{
        "id": d.id, "sid": d.sid, "user_id": d.user_id, "action": d.action, "level": d.level,
        "score": d.score, "outcome": d.outcome, "reasons": d.reasons, "shadow": d.shadow,
        "features": d.features, "score_ms": d.score_ms} for d in rows])


@app.get("/admin/status")
def admin_status():
    return jsonify(level=DEFENSE_LEVEL, store=("memory" if REDIS_URL.startswith("memory://") else "redis"))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    cert, key = os.path.join(INSTANCE, "cert.pem"), os.path.join(INSTANCE, "key.pem")
    if not os.path.exists(cert):
        sys.exit("No TLS certificate. Run: python tools/make_cert.py")
    print(f" * DEFENSE_LEVEL={DEFENSE_LEVEL}  store={'memory' if REDIS_URL.startswith('memory://') else REDIS_URL}")
    serve(app, "127.0.0.1", PORT, cert, key)
