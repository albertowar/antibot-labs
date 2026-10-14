"""
W2 Ch7 ext: what a learned bot detector needs that the starter store does not give it.

The starter logs one decision per GATED request and keeps only the latest telemetry payload per kind.
A model needs more: every request (assets included, they are the cheapest tell of a script), the
headers each one arrived with, every telemetry report, and the account a session signed in to. This
module adds all of it without touching a starter file:

  1. request log      an after_request hook writes one event per request into Redis (ml_store.py)
  2. telemetry        kinds "fp" (device claims) and "beh" (behaviour summary) on the contract's
                      POST /api/telemetry; each report is also appended to the session's log
  3. honeypots        a hidden link (/archive) and a robots.txt-disallowed endpoint (/partner-feed):
                      hits become bot labels (defenses/labels.py), exactly as in W1 Ch8
  4. deferred orders  at DEFENSE_LEVEL 4 the purchase is answered "202 pending" for everybody and the
                      real decision is applied at review time (defenses/enforcement.py, Round 4)
  5. lab routes       GET /lab/ml/status, GET /lab/ml/export (the training-data pull),
                      GET /lab/ml/orders/<number> (what a review decided)

Nothing here is a defense. The decisions live in defenses/*.py (ml_check, enforcement). The honeypot
routes are ordinary gated routes; the /lab/ routes are lab pages: loopback only, never gated.
"""

import hashlib
import json
import time

from flask import Blueprint, Response, current_app, g, jsonify, make_response, request

from demo_site import hooks
from demo_site.models import Order, Product, User, db, utcnow

from . import ml_store

BUY_PATHS = ("/api/buy",)
ASSET_PREFIXES = ("/static/", "/img/")
NOT_LOGGED = ("/lab/", "/whoami", "/health", "/favicon.ico")
LOGIN_PATHS = ("/api/login", "/login")
HONEYPOT_PATHS = ("/archive", "/partner-feed")

bp = Blueprint("ml", __name__)


def is_buy(method, path):
    return method == "POST" and (path in BUY_PATHS or path.startswith("/drop/"))


def _redis():
    return current_app.extensions["lab_redis"]


# --- 1. the request log -----------------------------------------------------------------------

def _stamp(ctx):
    """Request start time, shared by the log and the checkout score (one 'as of' for training and serving)."""
    ctx.attrs["ml_ts"] = time.time()


def _body_email():
    body = request.get_json(silent=True) if request.is_json else request.form
    return str((body or {}).get("email", "")).strip().lower()


def _after(resp):
    path = request.path
    if path.startswith(NOT_LOGGED):
        return resp
    ctx = getattr(g, "ctx", None)
    sid = ctx.session.sid if ctx is not None else request.cookies.get("sid")
    if not sid:
        return resp
    redis = _redis()
    ip = (request.environ.get("lab.edge") or {}).get("ip") or request.remote_addr
    ts = (ctx.attrs.get("ml_ts") if ctx is not None else None) or time.time()
    ml_store.log_event(redis, {
        "sid": sid, "ts": ts, "method": request.method, "path": path, "status": resp.status_code, "ip": ip,
        "ua": request.headers.get("User-Agent", ""), "referer": request.headers.get("Referer", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
        "sec_fetch_site": request.headers.get("Sec-Fetch-Site", ""),
        "is_asset": int(path.startswith(ASSET_PREFIXES)), "bytes": resp.calculate_content_length() or 0})
    if request.method == "POST" and path in LOGIN_PATHS and resp.status_code in (200, 302, 303):
        ml_store.log_login(redis, sid, _body_email())
    return _defer(ctx, resp)


# --- 2. telemetry -------------------------------------------------------------------------------

def _on_telemetry(kind):
    def handler(ctx, payload):
        fields = {k: v for k, v in payload.items() if k != "kind"}
        # a fingerprint is identified by its content: identical devices collide on purpose
        fp_hash = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest() if kind == "fp" else None
        ml_store.log_telemetry(_redis(), ctx.session.sid, {"ts": ctx.attrs.get("ml_ts", time.time()), "kind": kind,
                                                           "payload": fields, "fp_hash": fp_hash, "ip": ctx.edge.ip})
        return {"stored": True}
    return handler


# --- 4. deferred orders (Round 4) ---------------------------------------------------------------

def _defer(ctx, resp):
    """At level 4 ml_check scores but does not block; the purchase is answered the same way for everyone."""
    deferred = ctx.attrs.get("ml_deferred") if ctx is not None else None
    if not deferred or not getattr(g, "purchased", False) or resp.status_code not in (200, 201):
        return resp
    from defenses import enforcement             # through the module: defenses/ is hot-reloaded
    order = Order.query.filter_by(session_id=ctx.session.sid).order_by(Order.id.desc()).first()
    if order is None:
        return resp
    record = dict(enforcement.decide_later(deferred["risk"], time.time()), sku=order.items[0].sku if order.items else "")
    _redis().set(f"lab:ml:review:{order.number}", json.dumps(record), ex=24 * 3600)
    out = make_response(jsonify(status="pending", order=order.number,
                                message="Order received. We'll email you a confirmation shortly."), 202)
    return out


def _cancel(order):
    """The review said no: cancel the order and put the unit back on the shelf."""
    order.status = "cancelled"
    for item in order.items:
        db.session.execute(db.update(Product).where(Product.sku == item.sku).values(stock=Product.stock + item.qty))
    db.session.commit()


@bp.route("/lab/ml/orders/<number>")
def order_state(number):
    """What this order is now: pending until the review runs, then confirmed or cancelled."""
    from defenses import enforcement
    order = Order.query.filter_by(number=number).first()
    if order is None:
        return jsonify(error={"code": "not_found", "message": "No such order."}), 404
    raw = _redis().get(f"lab:ml:review:{number}")
    if raw is None:
        return jsonify(order=number, status="cancelled" if order.status == "cancelled" else "confirmed")
    status = enforcement.state(json.loads(raw), time.time())
    if status == "cancelled" and order.status != "cancelled":
        _cancel(order)
    return jsonify(order=number, status=status)


# --- 3. honeypots -----------------------------------------------------------------------------

@bp.route("/archive")
def archive():
    """Hidden from people (an off-screen link), irresistible to a crawler that follows every href."""
    return Response("<!doctype html><title>Archive</title><h1>Specials archive</h1><p>Nothing here.</p>", mimetype="text/html")


@bp.route("/partner-feed")
def partner_feed():
    """Disallowed in robots.txt and linked from nowhere: only a client that guessed it, or ignored the rules, calls it."""
    return jsonify(items=[])


# --- 5. lab routes ------------------------------------------------------------------------------

@bp.route("/lab/ml/status")
def status():
    from defenses import models
    return jsonify(level=current_app.config["LAB"].defense_level, time_scale=models.time_scale(),
                   scoring=models.describe(current_app.config["LAB"].defense_level))


@bp.route("/lab/ml/export")
def export():
    """The store's event log, for tools/ to append to data/history/ (the training set). Never gated."""
    out = ml_store.export(_redis())
    accounts = []
    for email in sorted(set(out["logins"].values())):
        u = User.query.filter_by(email=email).first()
        if u is None:
            continue
        past = Order.query.filter(Order.user_id == u.id, Order.session_id.is_(None)).count()    # seeded history only
        accounts.append({"account": email, "orders": past, "age_days": (utcnow() - u.created_at).days})
    return jsonify(dict(out, accounts=accounts))


def init(app):
    hooks.enricher(_stamp)
    for kind in ("fp", "beh"):
        hooks.telemetry.register(kind, _on_telemetry(kind))
    hooks.slot("body_end", "ml/honeypot.html")
    hooks.robots(lambda: [f"Disallow: {p}" for p in HONEYPOT_PATHS])
    app.register_blueprint(bp)
    app.after_request(_after)
    # a standalone run (not under tools/checkpoint.py) must not sell out: the drop day is thousands of orders
    import os
    if "DROP_STOCK" not in os.environ:
        with app.app_context():
            Product.query.filter_by(is_drop=True).update({"stock": 5000})
            db.session.commit()
