"""
W3 Ch2 ext: the chapter's own REST surface, /api/v2/ (the contract reserves the namespace for this chapter).

The catalogue is NOT here: products are the starter's /api/products. What the starter has no equivalent of is
the data plane a mobile app and a partner would use, so this module adds it:

    POST /api/v2/auth/login      {email, password}  -> {access_token, token_type, api_secret}
    GET  /api/v2/reviews         ?page=1&limit=20   -> the review corpus in bulk (limit up to 500)
    GET  /api/v2/account/orders  bearer             -> the caller's orders           (Round 5: the protected read)
    GET  /api/v2/inventory/<sku> bearer             -> price and stock, true or poisoned (Round 5: deception)

Nothing in this file decides anything. The enricher below decodes the bearer token (or the ?token= of a
WebSocket handshake) and hands the checks what they need as ctx.attrs: the subject, the binding claim, the
per-token signing secret, the exact request bytes and target. Whether a request is good enough is the
defenses' call (defenses/rate_cost.py, request_signing.py, token_binding.py). The two protected routes call
`guard(...)` / `gate.run_phase(...)` once they have checked the token exists, so the Round 5 checks run on those
reads only, and response_deception.py (shipped complete) turns a refusal on the inventory read into poison.

The token is a signed JWT (HS256, PyJWT): sub = user id, jti, bind = the coarse client claim, exp. The signing
secret the first-party app uses to sign each request is derived from the jti and delivered once, in the login
answer, and never sent again. Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import hashlib
import hmac
import math
import secrets
import time

import jwt
from flask import Blueprint, current_app, g, jsonify, request

from demo_site import gate, hooks
from demo_site.models import Order, Product, Review, User, db
from demo_site.routes import api_error, guard
from demo_site.seed import check_password

TOKEN_TTL = 3600
bp = Blueprint("api_v2", __name__, url_prefix="/api/v2")


def _defense(name):
    # Imported at call time: the reloader replaces defenses/* modules, not the references an ext holds.
    import importlib
    return importlib.import_module(f"defenses.{name}")


def _secret():
    return current_app.config["SECRET_KEY"]


def signing_secret(jti):
    """The per-token HMAC key the first-party app signs requests with (derived, so nothing is stored)."""
    return hmac.new(_secret().encode(), b"api2-sign:" + jti.encode(), hashlib.sha256).hexdigest()[:32]


def _decode(token):
    try:
        claims = jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return {"sub": claims["sub"], "jti": claims["jti"], "bind": claims.get("bind", ""),
            "secret": signing_secret(claims["jti"])}


def _enrich(ctx):
    """Decode the bearer token and expose the request bytes the signature covers. Runs at every level."""
    if not (ctx.path.startswith("/api/v2/") or ctx.path.startswith("/ws/")):
        return
    auth = ctx.header("Authorization", "") or ""
    token = auth[7:] if auth.startswith("Bearer ") else ctx.args.get("token", "")
    ctx.attrs["bearer"] = _decode(token) if token else None
    target = request.full_path
    ctx.attrs["target"] = target[:-1] if target.endswith("?") else target
    ctx.attrs["body"] = request.get_data()
    ctx.attrs["now"] = time.time()


def _bearer_user():
    bearer = (g.ctx.attrs or {}).get("bearer")
    return db.session.get(User, int(bearer["sub"])) if bearer else None


@bp.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    user = User.query.filter_by(email=str(body.get("email", "")).strip().lower()).first()
    if not check_password(user, str(body.get("password", "")), current_app.config["LAB"].hash_iters):
        return api_error("invalid_credentials", "Wrong email or password.", 401)
    jti = secrets.token_hex(8)
    claims = {"sub": str(user.id), "jti": jti, "bind": _defense("token_binding").binding_hash(g.ctx),
              "iat": int(time.time()), "exp": int(time.time()) + TOKEN_TTL}
    token = jwt.encode(claims, _secret(), algorithm="HS256")
    # The signing secret is delivered once, over this authenticated answer.
    return jsonify(access_token=token, token_type="Bearer", api_secret=signing_secret(jti))


@bp.get("/reviews")
def reviews():
    """Every published review, in bulk: the oversized-page surface Round 1's cost budget is for."""
    limit = max(1, min(request.args.get("limit", 20, type=int), 500))
    page = max(1, request.args.get("page", 1, type=int))
    q = Review.query.filter_by(status="published").order_by(Review.id)
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return jsonify(items=[r.to_dict() for r in rows], page=page, pages=max(1, math.ceil(total / limit)), total=total)


@bp.get("/account/orders")
def account_orders():
    user = _bearer_user()
    if user is None:
        return api_error("unauthenticated", "A bearer token is required.", 401)
    r = guard("api2_orders")
    if r:
        return r
    rows = Order.query.filter_by(user_id=user.id).order_by(Order.id).all()
    return jsonify(items=[o.to_dict() for o in rows], total=len(rows))


@bp.get("/inventory/<sku>")
def inventory(sku):
    """Price and stock for one SKU. When the caller is judged a bot we deceive instead of refusing, so a
    scraper banks poisoned numbers without learning it was caught (defenses/response_deception.py)."""
    if _bearer_user() is None:
        return api_error("unauthenticated", "A bearer token is required.", 401)
    p = Product.query.filter_by(sku=sku, hidden=False).first()
    if p is None:
        return api_error("not_found", "No such product.", 404)
    d = gate.run_phase("action:api2_inventory")
    if d.action == "rate_limit":
        return gate.respond(d, g.ctx)
    item = {"sku": p.sku, "price_cents": p.price_cents, "price": p.price, "stock": p.stock}
    deception = _defense("response_deception")
    if deception.should_deceive(d.action):
        item = deception.poison(item)
        g.deceive, g.outcome = True, "deceived"
    return jsonify(item=item)


def init(app):
    hooks.enricher(_enrich)
    app.register_blueprint(bp)
