"""JSON API. Same catalogue, same cart, same checkout as the pages, for scripts and apps."""

import json
import secrets

from flask import Blueprint, current_app, g, jsonify, request

from .. import gate, hooks
from ..models import GiftCard, Order, Product, Review, User, db, utcnow
from ..seed import check_password, set_password
from . import Cart, after_action, api_error, current_user, guard
from .pages import listing_query, paginate, place_order

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/products")
def products():
    q, category, sort = request.args.get("q", "").strip(), request.args.get("category", ""), request.args.get("sort", "featured")
    items, page, pages, total = paginate(listing_query(q, category, sort), request.args.get("page", 1, type=int))
    return jsonify(items=[p.to_dict() for p in items], page=page, pages=pages, total=total)


@bp.route("/products/<sku>")
def product(sku):
    p = Product.query.filter_by(sku=sku).first()
    if not p or (p.hidden and not request.args.get("ref")):
        return api_error("not_found", "No such product.", 404)
    return jsonify(p.to_dict(stock=True))


@bp.route("/search")
def search():
    q = request.args.get("q", "").strip()
    items, page, pages, total = paginate(listing_query(q), request.args.get("page", 1, type=int))
    return jsonify(items=[p.to_dict() for p in items], page=page, pages=pages, total=total, q=q)


@bp.route("/reviews/<sku>", methods=["GET"])
def reviews(sku):
    rows = Review.query.filter_by(sku=sku, status="published").order_by(Review.created_at.desc()).limit(50).all()
    return jsonify(items=[r.to_dict() for r in rows], total=len(rows))


@bp.route("/reviews", methods=["POST"])
def post_review():
    body = request.get_json(silent=True) or {}
    p = Product.query.filter_by(sku=body.get("sku", "")).first()
    if not p:
        return api_error("not_found", "No such product.", 404)
    r = guard("review", sku=p.sku)
    if r:
        return r
    user = current_user()
    rating = max(1, min(5, int(body.get("rating", 5))))
    rev = Review(sku=p.sku, user_id=user.id if user else None, author=(body.get("author") or (user.name.split()[0] if user and user.name else "Guest"))[:40],
                 rating=rating, title=str(body.get("title", ""))[:120], body=str(body.get("body", ""))[:2000],
                 status="published", extra={"sid": g.ctx.session.sid})
    db.session.add(rev)
    db.session.commit()
    return after_action("review", (jsonify(rev.to_dict()), 201), review=rev, product=p)


@bp.route("/cart")
def cart():
    c = Cart(g.ctx)
    return jsonify(items=[{"sku": x["sku"], "name": x["product"].name, "size": x["size"], "qty": x["qty"],
                           "line_cents": x["line_cents"]} for x in c.lines()], total_cents=c.total_cents(), count=c.count())


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    body = request.get_json(silent=True) or request.form
    p = Product.query.filter_by(sku=body.get("sku", ""), hidden=False).first()
    if not p or p.is_drop:
        return api_error("not_found", "No such product.", 404)
    r = guard("cart_add", sku=p.sku)
    if r:
        return r
    Cart(g.ctx).add(p.sku, body.get("size", ""), max(1, int(body.get("qty", 1))))
    return jsonify(ok=True, count=Cart(g.ctx).count())


@bp.route("/cart/remove", methods=["POST"])
def cart_remove():
    body = request.get_json(silent=True) or request.form
    Cart(g.ctx).remove(body.get("sku", ""), body.get("size", ""))
    return jsonify(ok=True, count=Cart(g.ctx).count())


@bp.route("/checkout", methods=["POST"])
def checkout():
    body = request.get_json(silent=True) or {}
    c = Cart(g.ctx)
    lines = c.lines()
    user = current_user()
    email = (user.email if user else str(body.get("email", ""))).strip().lower()
    if not lines:
        return api_error("empty_cart", "Your cart is empty.")
    if "@" not in email:
        return api_error("invalid_email", "Enter an email address.")
    r = guard("checkout", total_cents=c.total_cents())
    if r:
        return r
    if getattr(g, "deceive", False):
        return jsonify(ok=True, order={"number": "K" + secrets.token_hex(4).upper(), "status": "paid", "fake": True}), 201
    order, problem = place_order(lines, email, user, {"kind": "cart", "api": True})
    if problem:
        return api_error("sold_out", problem, 409)
    c.clear()
    return after_action("checkout", (jsonify(ok=True, order=order.to_dict()), 201), order=order)


@bp.route("/buy", methods=["POST"])
def buy():
    """Drop purchase: {sku, size, email?}. One request, one unit."""
    body = request.get_json(silent=True) or {}
    p = Product.query.filter_by(sku=body.get("sku", ""), is_drop=True).first()
    if not p:
        return api_error("not_found", "No such drop.", 404)
    if not p.drop_open:
        return api_error("not_open", "This drop has not opened yet.", 425)
    user = current_user()
    email = (user.email if user else str(body.get("email", ""))).strip().lower()
    size = str(body.get("size", ""))
    if "@" not in email or (p.sizes and size not in p.sizes):
        return api_error("invalid", "Pick a size and give an email.")
    if p.max_per_account and user:
        from ..models import OrderItem
        bought = db.session.query(db.func.coalesce(db.func.sum(OrderItem.qty), 0)).join(Order).filter(
            Order.user_id == user.id, OrderItem.sku == p.sku).scalar()
        if bought >= p.max_per_account:
            return api_error("limit", "Limit reached for this account.", 409)
    r = guard("drop_buy", sku=p.sku)
    if r:
        return r
    if getattr(g, "deceive", False):
        return jsonify(ok=True, order={"number": "K" + secrets.token_hex(4).upper(), "status": "paid", "fake": True}), 201
    order, problem = place_order([{"product": p, "sku": p.sku, "size": size, "qty": 1, "line_cents": p.price_cents}],
                                 email, user, {"kind": "drop", "sku": p.sku, "api": True})
    if problem:
        return api_error("sold_out", problem, 410)
    return after_action("drop_buy", (jsonify(ok=True, order=order.to_dict()), 201), order=order)


@bp.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or request.form
    email, password = str(body.get("email", "")).strip().lower(), str(body.get("password", ""))
    r = guard("login", email=email)
    if r:
        return r
    user = User.query.filter_by(email=email).first()
    if check_password(user, password, current_app.config["LAB"].hash_iters):
        g.ctx.session.set("uid", user.id)
        user.last_login_at = utcnow()
        db.session.commit()
        g.ctx.note(login="ok")
        return after_action("login", jsonify(ok=True, user=user.to_dict()), user=user, ok=True)
    reason = "unknown_user" if user is None else "wrong_password"
    g.ctx.note(login="fail", login_reason=reason)
    return after_action("login", api_error("invalid_credentials", "Wrong email or password.", 401),
                        user=user, ok=False, reason=reason)


@bp.route("/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or request.form
    email, password, name = str(body.get("email", "")).strip().lower(), str(body.get("password", "")), str(body.get("name", ""))[:80]
    if "@" not in email or len(password) < 8:
        return api_error("invalid", "Use a valid email and a password of 8+ characters.")
    r = guard("register", email=email)
    if r:
        return r
    if User.query.filter_by(email=email).first():
        return api_error("exists", "That email is already registered.", 409)
    u = User(email=email, name=name, extra={"sid": g.ctx.session.sid})
    set_password(u, password, current_app.config["LAB"].hash_iters)
    db.session.add(u)
    db.session.commit()
    g.ctx.session.set("uid", u.id)
    return after_action("register", (jsonify(ok=True, user=u.to_dict()), 201), user=u)


@bp.route("/logout", methods=["POST"])
def logout():
    g.ctx.session.delete("uid")
    return jsonify(ok=True)


@bp.route("/account")
def account():
    user = current_user()
    if not user:
        return api_error("unauthenticated", "Log in first.", 401)
    return jsonify(user.to_dict())


@bp.route("/orders")
def orders():
    user = current_user()
    if not user:
        return api_error("unauthenticated", "Log in first.", 401)
    rows = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    return jsonify(items=[o.to_dict() for o in rows], total=len(rows))


@bp.route("/password-reset", methods=["POST"])
def password_reset():
    body = request.get_json(silent=True) or request.form
    email = str(body.get("email", "")).strip().lower()
    r = guard("password_reset", email=email)
    if r:
        return r
    user = User.query.filter_by(email=email).first()
    if user:                                   # the token lands in the lab mailbox (/lab/mailbox/<email>)
        token = secrets.token_urlsafe(16)
        g.ctx.redis.set(f"lab:reset:{token}", user.id, ex=900)
        g.ctx.redis.rpush(f"lab:mailbox:{email}", json.dumps({"subject": "Reset your password", "token": token,
                                                              "ts": utcnow().isoformat()}))
    return jsonify(ok=True, message="If that address exists, a reset email is on its way.")


@bp.route("/password-reset/confirm", methods=["POST"])
def password_reset_confirm():
    body = request.get_json(silent=True) or request.form
    uid = g.ctx.redis.get(f"lab:reset:{body.get('token', '')}")
    if not uid or len(str(body.get("password", ""))) < 8:
        return api_error("invalid_token", "Token unknown, expired, or password too short.")
    user = User.query.get(int(uid))
    set_password(user, str(body["password"]), current_app.config["LAB"].hash_iters)
    db.session.commit()
    g.ctx.redis.delete(f"lab:reset:{body['token']}")
    return jsonify(ok=True)


@bp.route("/gift-cards/balance")
def gift_card_balance():
    code = request.args.get("code", "").strip().upper()
    r = guard("gift_card_check", code=code)
    if r:
        return r
    card = GiftCard.query.filter_by(code=code).first()
    g.ctx.note(gift_card="hit" if card else "miss")
    if not card:
        return api_error("not_found", "No such card.", 404)
    return jsonify(card.to_dict())


@bp.route("/gift-cards/redeem", methods=["POST"])
def gift_card_redeem():
    user = current_user()
    if not user:
        return api_error("unauthenticated", "Log in first.", 401)
    body = request.get_json(silent=True) or request.form
    code = str(body.get("code", "")).strip().upper()
    r = guard("gift_card_redeem", code=code)
    if r:
        return r
    card = GiftCard.query.filter_by(code=code).first()
    if not card or card.redeemed_by:
        return api_error("not_found", "No such card.", 404)
    user.loyalty_points = (user.loyalty_points or 0) + card.balance_cents // 100
    card.redeemed_by = user.id
    db.session.commit()
    return jsonify(ok=True, loyalty_points=user.loyalty_points)


@bp.route("/telemetry", methods=["POST"])
def telemetry():
    """The one sink for every collector a chapter ships: {"kind": "...", ...}."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body.get("kind"):
        return api_error("invalid", "Send a JSON object with a `kind`.")
    kind = str(body["kind"])[:32]
    g.ctx.redis.set(f"lab:s:{g.ctx.session.sid}:telemetry:{kind}", json.dumps(body), ex=3600)
    g.ctx.redis.rpush(f"lab:telemetry:{kind}", json.dumps({"sid": g.ctx.session.sid, "ts": utcnow().isoformat(), "payload": body}))
    g.ctx.redis.ltrim(f"lab:telemetry:{kind}", -5000, -1)
    handler = hooks.telemetry.handlers.get(kind)
    out = handler(g.ctx, body) if handler else None
    return jsonify(ok=True, kind=kind, result=out)


@bp.route("/challenge")
def challenge():
    ctype = hooks.challenges.get(request.args.get("type", ""))
    if not ctype:
        return api_error("unknown_challenge", "No such challenge type.", 404, available=hooks.challenges.names())
    return jsonify(type=request.args["type"], payload=ctype["issue"](g.ctx))


@bp.route("/challenge/verify", methods=["POST"])
def challenge_verify():
    body = request.get_json(silent=True) or {}
    name = str(body.get("type", ""))
    ctype = hooks.challenges.get(name)
    if not ctype:
        return api_error("unknown_challenge", "No such challenge type.", 404)
    out = ctype["verify"](g.ctx, body.get("answer") or {})
    ok, reason = (bool(out[0]), str(out[1])) if isinstance(out, tuple) else (bool(out), "")
    g.ctx.note(challenge=name, challenge_ok=ok, challenge_reason=reason)
    if not ok:
        return api_error("challenge_failed", reason or "That answer did not verify.", 403, reason=reason)
    gate.grant_clearance(g.ctx, name)
    return jsonify(ok=True, cleared=name)
