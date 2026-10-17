"""
W3 Ch1 ext: the Lab Runner mobile app's backend, on /api/mobile/.

The store ships a native app. This is its JSON API, and the buy endpoint is the protected action every round
attacks. The app sells the starter's limited drop `lab-runner-9` (one pair per account, DROP_STOCK units):

    GET  /api/mobile/config     app id, version, the drop
    GET  /api/mobile/nonce      a single-use server challenge the app binds its attestation to (Round 3)
    POST /api/mobile/register   {email, password}      -> {token}   (a bearer token, not the web session)
    POST /api/mobile/login      {email, password}      -> {token}
    POST /api/mobile/buy        {sku, size?}           header X-Attest: the provider's signed verdict
    GET  /api/mobile/orders     your orders             the read Round 5 gates (a bearer alone can read it)
    GET  /api/mobile/whoami     never gated: how the gate sees your client (JA4, attested, integrity, request score)

Round 5 (device-bound sessions): login/register accept X-Device-Key (the install's public key, SPKI base64url)
and X-Key-Attest (the provider's signed claim about where that key lives). The server verifies the claim,
checks it names this key, and stores the key next to the bearer token. That binding is infrastructure; whether
a request's X-Device-Proof is good enough is the defense's call (defenses/session_binding.py).

Nothing in this file decides anything. The enricher below verifies the provider's SIGNATURE on X-Attest and
hands the decoded verdict (or None) and the exact request bytes to the checks as ctx.attrs["attest"] /
["body"] / ["now_ms"]; whether a verdict is good enough is the defenses' call. The buy calls
`guard("mobile_buy")` once its own validation passes, so the attestation checks run on the buy only.

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import json
import secrets
import time

from flask import Blueprint, current_app, g, jsonify, request

from demo_site import gate, hooks
from demo_site.models import Order, OrderItem, Product, User, db
from demo_site.routes import api_error, guard
from demo_site.routes.pages import place_order
from demo_site.seed import check_password, set_password

NONCE_TTL = 180
TOKEN_TTL = 3600
TOKEN_PREFIX = "lab:ch1:mtok:"
DROP_SKU = "lab-runner-9"

bp = Blueprint("mobile", __name__, url_prefix="/api/mobile")


def _core():
    # Imported at call time: the reloader replaces defenses/* modules, not the references an ext holds.
    from defenses import mobile_core
    return mobile_core


def _enrich(ctx):
    """Verify the provider's signature on X-Attest and expose what the checks need. Runs at every level."""
    if not ctx.path.startswith("/api/mobile/"):
        return
    ctx.attrs["attest"] = _core().verify(request.headers.get("X-Attest", ""))
    ctx.attrs["body"] = request.get_data()
    ctx.attrs["now_ms"] = int(time.time() * 1000)
    # Round 5: the bearer on this request, the key it was bound to at login ({pub, storage, deviceId, kid} or
    # None for a legacy login without a key), and the raw X-Device-Proof header.
    auth = request.headers.get("Authorization", "")
    bearer = auth[7:] if auth.startswith("Bearer ") else None
    raw = ctx.redis.get(_core().BIND_PREFIX + bearer) if bearer else None
    ctx.attrs["bearer"] = bearer
    ctx.attrs["binding"] = json.loads(raw) if raw else None
    ctx.attrs["proof"] = request.headers.get("X-Device-Proof") or None


def _bearer_user():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    uid = g.ctx.redis.get(TOKEN_PREFIX + token) if token else None
    return db.session.get(User, int(uid)) if uid else None


def _token_for(user):
    token = secrets.token_hex(24)
    g.ctx.redis.set(TOKEN_PREFIX + token, str(user.id), ex=TOKEN_TTL)
    _bind(token)
    return token


def _bind(token):
    """Round 5: bind the new token to the install's key, if the app sent one and the provider vouches for it.

    The claim must verify, belong to this app and name THIS key (requestHash carries the thumbprint). A legacy
    app, or a claim that does not check out, leaves the token unbound; the defense decides what that costs.
    """
    pub = request.headers.get("X-Device-Key", "")
    claim = _core().verify(request.headers.get("X-Key-Attest", ""))
    if not pub or claim is None or claim.get("appId") != _core().APP_ID:
        return
    try:
        kid = _core().thumbprint(pub)
    except ValueError:
        return
    if claim.get("requestHash") != kid:
        return
    g.ctx.redis.set(_core().BIND_PREFIX + token, json.dumps(
        {"pub": pub, "kid": kid, "storage": claim.get("keyStorage"), "deviceId": claim.get("deviceId")}), ex=TOKEN_TTL)


@bp.get("/config")
def config():
    p = Product.query.filter_by(sku=DROP_SKU).first()
    return jsonify(app_id=_core().APP_ID, app_version=_core().APP_VERSION, drop=p.to_dict(stock=True) if p else None,
                   level=current_app.config["LAB"].defense_level)


@bp.get("/nonce")
def nonce():
    n = secrets.token_hex(16)
    g.ctx.redis.set(_core().ISSUED_PREFIX + n, 1, ex=NONCE_TTL)
    return jsonify(nonce=n, ttl=NONCE_TTL)


@bp.post("/register")
def register():
    body = request.get_json(silent=True) or {}
    email, password = str(body.get("email", "")).strip().lower()[:120], str(body.get("password", ""))[:200]
    if "@" not in email or len(password) < 8:
        return api_error("invalid", "Use a valid email and a password of 8+ characters.")
    if User.query.filter_by(email=email).first():
        return api_error("exists", "That email is already registered.", 409)
    user = User(email=email, name=str(body.get("name", ""))[:80], extra={"sid": g.ctx.session.sid, "via": "mobile"})
    set_password(user, password, current_app.config["LAB"].hash_iters)
    db.session.add(user)
    db.session.commit()
    return jsonify(ok=True, token=_token_for(user), email=user.email), 201


@bp.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    email, password = str(body.get("email", "")).strip().lower(), str(body.get("password", ""))
    user = User.query.filter_by(email=email).first()
    if not check_password(user, password, current_app.config["LAB"].hash_iters):
        return api_error("bad_credentials", "Wrong email or password.", 401)
    return jsonify(ok=True, token=_token_for(user), email=user.email)


@bp.post("/buy")
def buy():
    user = _bearer_user()
    if user is None:
        return api_error("unauthenticated", "Log in first.", 401)
    body = request.get_json(silent=True) or {}
    p = Product.query.filter_by(sku=body.get("sku", ""), is_drop=True).first()
    if p is None:
        return api_error("not_found", "No such drop.", 404)
    size = str(body.get("size") or (p.sizes[0] if p.sizes else ""))
    if p.max_per_account:
        bought = db.session.query(db.func.coalesce(db.func.sum(OrderItem.qty), 0)).join(Order).filter(
            Order.user_id == user.id, OrderItem.sku == p.sku).scalar()
        if bought >= p.max_per_account:
            return api_error("limit", "One pair per account.", 409)
    blocked = guard("mobile_buy", sku=p.sku, integrity=_integrity(g.ctx))
    if blocked:
        return blocked
    order, problem = place_order([{"product": p, "sku": p.sku, "size": size, "qty": 1, "line_cents": p.price_cents}],
                                 user.email, user, {"kind": "drop", "sku": p.sku, "api": "mobile"})
    if problem:
        return api_error("sold_out", problem, 410)
    return jsonify(ok=True, order=order.to_dict()), 201


@bp.get("/orders")
def orders():
    """The signed-in user's orders. A read, but it shows a bearer thief the victim's data, so it is gated too."""
    user = _bearer_user()
    if user is None:
        return api_error("unauthenticated", "Log in first.", 401)
    blocked = guard("mobile_read")
    if blocked:
        return blocked
    rows = Order.query.filter_by(user_id=user.id).order_by(Order.id).all()
    return jsonify(ok=True, orders=[o.to_dict() for o in rows])


def _integrity(ctx):
    verdict = ctx.attrs.get("attest")
    return None if verdict is None else _core().integrity_level(verdict)


@bp.get("/whoami")
def whoami():
    """How the gate sees this client. Never gated, so you can read it from a client the gate would refuse."""
    ctx = gate.build_ctx(current_app)
    _enrich(ctx)
    verdict = ctx.attrs.get("attest")
    d = gate.run_phase("request", ctx)
    from defenses import ja4
    return jsonify(level=ctx.level, ip=ctx.edge.ip, ja4=ctx.edge.ja4, ja4_source=ctx.edge.ja4_source,
                   ja4_library=ja4.library_label(ja4.fingerprint(ctx)), user_agent=ctx.ua.raw,
                   attested=verdict is not None, integrity=_integrity(ctx),
                   bound=ctx.attrs.get("binding") is not None, proof=ctx.attrs.get("proof") is not None,
                   app_integrity=None if verdict is None else verdict.get("appIntegrity"),
                   request_score={"score": d.score, "action": d.action, "signals": d.flags()})


def init(app):
    _core().ensure_keys()              # create the provider's key pair now, not on the first concurrent request
    hooks.enricher(_enrich)
    hooks.ungate("/api/mobile/whoami")
    app.register_blueprint(bp)
