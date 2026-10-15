"""
Capstone feature module: the API surface Workshop 3 defends (W3 Ch2). No starter file is edited, and nothing here
decides anything (defenses/api_hardening.py and defenses/ws_ratelimit.py decide).

    POST /graphql            a deliberately small, dependency-free resolver over the catalogue: products(limit,
                             offset), product(sku), and introspection (__schema). The contract reserves the path
                             for the W3 API chapter. A JSON array is a batch.
    GET  /api/v1/products    the paginated REST catalogue (?limit=&offset=, up to 100 a page): the partner and
                             mobile surface. The starter's /api/products is untouched.
    GET  /api/token          a bearer token for the logged-in account, bound to the client's claimed JA4 (a+b)
    GET  /ws/price           a WebSocket price feed (flask-sock, on the store's own port)

The request goes through the store's gate like any other: the Ctx carries the parsed JSON body (ctx.json) and the
bearer token the enricher below decoded (ctx.attrs["api_token"]); whether a request is good enough is the defense's
call. A refused request never reaches the routes. The WebSocket is the exception, and says so: its handshake is
ungated (`/ws/` is skipped by the gate) and the feed meters each connection itself, from level 5, with the token
bucket of defenses/ws_ratelimit.py. In production the socket terminates at the same edge as the HTTP; the lab keeps
it out of the gate so the flood is one request, which is the point (an HTTP limiter never sees it).

Ext modules are not hot-reloaded: restart the store after editing this file. They are written to call the defenses
through importlib at call time, because the reloader replaces defenses/* modules, not the references an ext holds.
"""

import importlib
import json
import re

from flask import Blueprint, current_app, g, jsonify, request
from flask_sock import Sock

from demo_site import hooks
from demo_site.models import Product

DROP_SKU = "lab-runner-9"
IDLE_TIMEOUT_S = 10
FLOOD_KEY = "lab:ws:flood"
_SKU = re.compile(r'sku\s*:\s*"([^"]+)"')

bp = Blueprint("api9", __name__)
SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "products", "args": ["limit", "offset"], "type": "[Product]"},
            {"name": "product", "args": ["sku"], "type": "Product"}]},
        {"kind": "OBJECT", "name": "Product", "fields": [{"name": "sku"}, {"name": "name"}, {"name": "price"}, {"name": "drop"}]},
    ],
}


def _defense(name):
    return importlib.import_module(f"defenses.{name}")


def _ja4_ab(ctx):
    return _defense("ja4").fingerprint(ctx).ja4_ab


def _catalog():
    return Product.query.filter_by(hidden=False).order_by(Product.id).all()


def _view(p):
    return {"sku": p.sku, "name": p.name, "price": round(p.price_cents / 100, 2), "drop": bool(p.is_drop)}


# --- the GraphQL resolver -------------------------------------------------------------------------------

def resolve(op):
    """Resolve one allowed operation against the catalogue."""
    query = op.get("query", "") if isinstance(op, dict) else ""
    if any(tok in query for tok in ("__schema", "__type")):
        return {"data": {"__schema": SCHEMA}}
    data = {}
    skus = _SKU.findall(query)
    if "products" in query and not skus:
        limit_m, offset_m = re.search(r"limit\s*:\s*(\d+)", query), re.search(r"offset\s*:\s*(\d+)", query)
        limit = int(limit_m.group(1)) if limit_m else 1000
        offset = int(offset_m.group(1)) if offset_m else 0
        data["products"] = [_view(p) for p in _catalog()][offset:offset + limit]
    by_sku = {p.sku: p for p in Product.query.filter(Product.sku.in_(set(skus))).all()} if skus else {}
    for idx, sku in enumerate(skus):
        # aliased batches become product_0, product_1, ... so each result is addressable
        data[f"product_{idx}" if len(skus) > 1 else "product"] = _view(by_sku[sku]) if sku in by_sku else None
    return {"data": data}


@bp.post("/graphql")
def graphql():
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(errors=[{"message": "expected a JSON query body"}]), 400
    if isinstance(body, list):
        return jsonify([resolve(op) for op in body])
    return jsonify(resolve(body))


# --- the REST catalogue and the token ---------------------------------------------------------------------

@bp.get("/api/v1/products")
def v1_products():
    limit = max(1, min(request.args.get("limit", 24, type=int), 100))
    offset = max(0, request.args.get("offset", 0, type=int))
    items = _catalog()
    return jsonify(items=[_view(p) for p in items[offset:offset + limit]], total=len(items), limit=limit, offset=offset)


@bp.get("/api/token")
def api_token():
    """A bearer token for the logged-in account, bound to the claimed JA4 a+b. Useless replayed from another TLS stack."""
    user = g.ctx.user
    if user is None:
        return jsonify(error={"code": "unauthenticated", "message": "Log in first."}), 401
    return jsonify(ok=True, token=_defense("api_token").issue(user.id, _ja4_ab(g.ctx), current_app.config["SECRET_KEY"]))


def _decode_bearer(ctx):
    """Enricher: decode the bearer token of an /api/v1 call into ctx.attrs (the defense judges it)."""
    if ctx.path.startswith("/api/v1/"):
        ctx.attrs["api_token"] = _defense("api_token").verify(ctx.header("Authorization", ""), _ja4_ab(ctx),
                                                              current_app.config["SECRET_KEY"])


# --- the price WebSocket ----------------------------------------------------------------------------------

def price_feed(ws):
    """Send a hello, then answer every message with the current price. Metered per connection from level 5."""
    redis = current_app.extensions["lab_redis"]
    bucket = _defense("ws_ratelimit").TokenBucket()
    p = Product.query.filter_by(sku=DROP_SKU).first()
    price = round(p.price_cents / 100, 2) if p else 0
    metered = current_app.config["LAB"].defense_level >= 5
    ws.send(json.dumps({"type": "hello", "sku": DROP_SKU, "metered": metered}))
    while True:
        raw = ws.receive(timeout=IDLE_TIMEOUT_S)
        if raw is None:
            return
        if current_app.config["LAB"].defense_level >= 5 and not bucket.allow():
            redis.incr(FLOOD_KEY)
            ws.close(reason=1008, message="message rate limit exceeded")
            return
        ws.send(json.dumps({"type": "price", "sku": DROP_SKU, "price": price}))


def init(app):
    app.register_blueprint(bp)
    hooks.enricher(_decode_bearer)
    hooks.ungate("/ws/")
    Sock(app).route("/ws/price")(price_feed)
