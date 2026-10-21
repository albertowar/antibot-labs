"""HTML pages. Every form works without JavaScript; static/js/store.js only improves them."""

import hmac
import secrets

from flask import Blueprint, abort, g, redirect, request, url_for
from sqlalchemy import or_

from .. import account as acct
from .. import gate
from ..models import AccountChange, GiftCard, Newsletter, Order, OrderItem, Product, Review, User, db, utcnow
from ..seed import check_password, set_password
from . import Cart, after_action, api_error, csrf_ok, current_user, guard, render, settle_change, submit_change

bp = Blueprint("pages", __name__)
PAGE_SIZE = 24
CATEGORIES = ["shoes", "packs", "jackets", "headlamps", "poles", "kitchen"]
SORTS = {"featured": Product.id.asc(), "price_asc": Product.price_cents.asc(), "price_desc": Product.price_cents.desc(),
         "rating": Product.rating.desc(), "newest": Product.id.desc()}


def flash(msg, kind="info"):
    g.ctx.session.set("flash", f"{kind}|{msg}")


def take_flash():
    raw = g.ctx.session.get("flash")
    if raw:
        g.ctx.session.delete("flash")
        kind, _, msg = raw.partition("|")
        return {"kind": kind, "msg": msg}
    return None


def listing_query(q="", category="", sort="featured"):
    query = Product.query.filter_by(hidden=False, is_drop=False)
    if category in CATEGORIES:
        query = query.filter_by(category=category)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Product.name.ilike(like), Product.blurb.ilike(like), Product.category.ilike(like)))
    return query.order_by(SORTS.get(sort, SORTS["featured"]))


def paginate(query, page):
    total = query.count()
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(1, page), pages)
    items = query.offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE).all()
    return items, page, pages, total


@bp.app_context_processor
def inject():
    from ..config import STORE_NAME, STORE_TAGLINE
    cart = Cart(g.ctx).count() if getattr(g, "ctx", None) else 0
    return {"store_name": STORE_NAME, "store_tagline": STORE_TAGLINE, "user": current_user(), "cart_count": cart,
            "categories": CATEGORIES, "flash": take_flash() if getattr(g, "ctx", None) else None}


@bp.route("/")
def home():
    drops = Product.query.filter_by(is_drop=True, hidden=False).order_by(Product.id).all()
    featured = Product.query.filter_by(hidden=False, is_drop=False).order_by(Product.rating.desc()).limit(8).all()
    return render("home.html", drops=drops, featured=featured)


@bp.route("/products")
@bp.route("/catalog")
def products():
    q, category, sort = request.args.get("q", "").strip(), request.args.get("category", ""), request.args.get("sort", "featured")
    items, page, pages, total = paginate(listing_query(q, category, sort), request.args.get("page", 1, type=int))
    return render("products.html", items=items, page=page, pages=pages, total=total, q=q, category=category, sort=sort)


@bp.route("/search")
def search():
    q = request.args.get("q", "").strip()
    items, page, pages, total = paginate(listing_query(q), request.args.get("page", 1, type=int))
    return render("products.html", items=items, page=page, pages=pages, total=total, q=q, category="", sort="featured",
                  heading=f'Results for "{q}"' if q else "Search")


@bp.route("/product/<sku>")
def product(sku):
    p = Product.query.filter_by(sku=sku).first_or_404()
    if p.is_drop:
        return redirect(url_for("pages.drop", sku=sku))
    reviews = Review.query.filter_by(sku=sku, status="published").order_by(Review.created_at.desc()).limit(10).all()
    related = Product.query.filter(Product.category == p.category, Product.sku != sku, Product.hidden.is_(False),
                                   Product.is_drop.is_(False)).limit(4).all()
    return render("product.html", p=p, reviews=reviews, related=related)


@bp.route("/review/<sku>", methods=["POST"])
def review(sku):
    p = Product.query.filter_by(sku=sku).first_or_404()
    if not csrf_ok():
        abort(400)
    user = current_user()
    r = guard("review", sku=sku)
    if r:
        return r
    rating = max(1, min(5, request.form.get("rating", 5, type=int)))
    author = user.name.split()[0] if user and user.name else request.form.get("author", "Guest")[:40]
    rev = Review(sku=sku, user_id=user.id if user else None, author=author, rating=rating,
                 title=request.form.get("title", "")[:120], body=request.form.get("body", "")[:2000],
                 status="published", extra={"sid": g.ctx.session.sid})
    db.session.add(rev)
    all_ratings = [x.rating for x in Review.query.filter_by(sku=sku, status="published")] + [rating]
    p.rating = sum(all_ratings) / len(all_ratings)
    db.session.commit()
    flash("Thanks for your review.", "ok")
    return after_action("review", redirect(url_for("pages.product", sku=sku)), review=rev, product=p)


@bp.route("/cart")
def cart():
    c = Cart(g.ctx)
    return render("cart.html", lines=c.lines(), total_cents=c.total_cents())


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    if not csrf_ok():
        abort(400)
    sku, size, qty = request.form.get("sku", ""), request.form.get("size", ""), max(1, request.form.get("qty", 1, type=int))
    p = Product.query.filter_by(sku=sku, hidden=False).first()
    if not p or p.is_drop:
        abort(404)
    r = guard("cart_add", sku=sku)
    if r:
        return r
    Cart(g.ctx).add(sku, size, qty)
    flash(f"Added {p.name} to your cart.", "ok")
    return redirect(request.form.get("next") or url_for("pages.cart"))


@bp.route("/cart/remove", methods=["POST"])
def cart_remove():
    if not csrf_ok():
        abort(400)
    Cart(g.ctx).remove(request.form.get("sku", ""), request.form.get("size", ""))
    return redirect(url_for("pages.cart"))


def place_order(lines, email, user, extra=None):
    """Atomic stock decrement per line, then the order. Returns (order, problem)."""
    for line in lines:
        updated = db.session.execute(
            db.update(Product).where(Product.sku == line["sku"], Product.stock >= line["qty"])
            .values(stock=Product.stock - line["qty"])).rowcount
        if not updated:
            db.session.rollback()
            return None, f"{line['product'].name} is sold out."
    order = Order(number="K" + secrets.token_hex(4).upper(), user_id=user.id if user else None, email=email,
                  total_cents=sum(x["line_cents"] for x in lines), session_id=g.ctx.session.sid,
                  actor=request.environ.get("lab.actor", "you"), extra=extra or {})
    for line in lines:
        order.items.append(OrderItem(sku=line["sku"], name=line["product"].name, size=line["size"], qty=line["qty"],
                                     price_cents=line["product"].price_cents))
    if user:
        user.loyalty_points = (user.loyalty_points or 0) + order.total_cents // 100
    db.session.add(order)
    db.session.commit()
    g.purchased = True
    return order, None


@bp.route("/checkout", methods=["GET", "POST"])
def checkout():
    c = Cart(g.ctx)
    lines = c.lines()
    user = current_user()
    if request.method == "GET":
        if not lines:
            return redirect(url_for("pages.cart"))
        return render("checkout.html", lines=lines, total_cents=c.total_cents(), address=user.addresses[0] if user and user.addresses else None)
    if not csrf_ok():
        abort(400)
    if not lines:
        return redirect(url_for("pages.cart"))
    email = (user.email if user else request.form.get("email", "")).strip().lower()
    if not email or "@" not in email:
        flash("Enter an email address.", "warn")
        return redirect(url_for("pages.checkout"))
    f = request.form
    try:
        ship, card = acct.checkout_facts(user, f.get("line1") or f.get("address", ""), f.get("city", ""), f.get("postcode", ""),
                                            f.get("address_id"), f.get("card", ""))
    except acct.ChangeError as e:
        flash(e.message, "warn")
        return redirect(url_for("pages.checkout"))
    r = guard("checkout", total_cents=c.total_cents(), ship_to=ship["normalized"], ship_to_new=ship["new"],
              card_saved=card["saved"], card_bin6=card["bin6"], card_fp=card["fingerprint"])
    if r:
        return r
    if getattr(g, "deceive", False):
        return render("order_confirmed.html", order=None, fake=True)
    order, problem = place_order(lines, email, user, {"kind": "cart", "ship_to": ship, "card": card})
    if problem:
        flash(problem, "warn")
        return redirect(url_for("pages.cart"))
    c.clear()
    return after_action("checkout", render("order_confirmed.html", order=order, fake=False), order=order)


@bp.route("/drop/<sku>", methods=["GET", "POST"])
def drop(sku):
    p = Product.query.filter_by(sku=sku, is_drop=True).first_or_404()
    user = current_user()
    if request.method == "GET":
        bought = 0
        if user and p.max_per_account:
            bought = db.session.query(db.func.coalesce(db.func.sum(OrderItem.qty), 0)).join(Order).filter(
                Order.user_id == user.id, OrderItem.sku == sku).scalar()
        return render("drop.html", p=p, bought=bought)
    if not csrf_ok():
        abort(400)
    if not p.drop_open:
        flash("This drop has not opened yet.", "warn")
        return redirect(url_for("pages.drop", sku=sku))
    email = (user.email if user else request.form.get("email", "")).strip().lower()
    size = request.form.get("size", "")
    if not email or "@" not in email or (p.sizes and size not in p.sizes):
        flash("Pick a size and enter your email.", "warn")
        return redirect(url_for("pages.drop", sku=sku))
    if p.max_per_account and user:
        bought = db.session.query(db.func.coalesce(db.func.sum(OrderItem.qty), 0)).join(Order).filter(
            Order.user_id == user.id, OrderItem.sku == sku).scalar()
        if bought >= p.max_per_account:
            flash("Limit reached for this account.", "warn")
            return redirect(url_for("pages.drop", sku=sku))
    r = guard("drop_buy", sku=sku)
    if r:
        return r
    if getattr(g, "deceive", False):
        return render("order_confirmed.html", order=None, fake=True)
    line = {"product": p, "sku": sku, "size": size, "qty": 1, "line_cents": p.price_cents}
    order, problem = place_order([line], email, user, {"kind": "drop", "sku": sku})
    if problem:
        return render("drop.html", p=p, bought=0, sold_out=True), 410
    return after_action("drop_buy", render("order_confirmed.html", order=order, fake=False), order=order)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render("login.html", next=request.args.get("next", "/account"))
    if not csrf_ok():
        abort(400)
    email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
    r = guard("login", email=email)
    if r:
        return r
    user = User.query.filter_by(email=email).first()
    from flask import current_app
    if check_password(user, password, current_app.config["LAB"].hash_iters):
        g.ctx.session.set("uid", user.id)
        gate.stamp_login(g.ctx)
        user.last_login_at = utcnow()
        db.session.commit()
        g.ctx.note(login="ok")
        return after_action("login", redirect(request.form.get("next") or url_for("pages.account")),
                            user=user, ok=True)
    reason = "unknown_user" if user is None else "wrong_password"
    g.ctx.note(login="fail", login_reason=reason)
    flash("Wrong email or password.", "warn")
    return after_action("login", (render("login.html", next=request.form.get("next", "/account"), email=email), 401),
                        user=user, ok=False, reason=reason)


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    g.ctx.session.delete("uid")
    gate.clear_auth(g.ctx)
    return redirect(url_for("pages.home"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render("register.html")
    if not csrf_ok():
        abort(400)
    email, password, name = request.form.get("email", "").strip().lower(), request.form.get("password", ""), request.form.get("name", "")[:80]
    if "@" not in email or len(password) < 8:
        flash("Use a valid email and a password of 8+ characters.", "warn")
        return render("register.html", email=email, name=name), 400
    r = guard("register", email=email)
    if r:
        return r
    if User.query.filter_by(email=email).first():
        flash("That email is already registered.", "warn")
        return render("register.html", email=email, name=name), 409
    from flask import current_app
    u = User(email=email, name=name, extra={"sid": g.ctx.session.sid})
    set_password(u, password, current_app.config["LAB"].hash_iters)
    db.session.add(u)
    db.session.commit()
    g.ctx.session.set("uid", u.id)
    gate.stamp_login(g.ctx)
    flash("Welcome to Kestrel.", "ok")
    return after_action("register", redirect(url_for("pages.account")), user=u)


def account_page(notice=None, status=200):
    orders = Order.query.filter_by(user_id=current_user().id).order_by(Order.created_at.desc()).limit(5).all()
    return render("account.html", orders=orders, notice=notice), status


@bp.route("/account")
def account():
    if not current_user():
        return redirect(url_for("pages.login", next="/account"))
    return account_page()[0]


def _change_view(kind):
    """POST /account/<kind>: the HTML side of an account change (the forms on /account)."""
    user = current_user()
    if not user:
        return redirect(url_for("pages.login", next="/account"))
    if request.method == "GET":
        return redirect(url_for("pages.account"))
    if not csrf_ok():
        abort(400)
    try:
        change, early = submit_change(kind, user, request.form.to_dict())
    except acct.ChangeError as e:
        flash(e.message, "warn")
        return account_page(status=e.status)
    if early:
        return early
    if change.status == "applied":
        flash("Saved. We emailed the address on file.", "ok")
        resp = redirect(url_for("pages.account"))
    elif change.status == "pending":
        resp = account_page({"testid": "change-pending", "msg": "Your change is on hold for review. We emailed the address on file; "
                             "you can cancel it from that message."}, 202)
    elif change.status == "confirm":
        resp = account_page({"testid": "change-confirm", "msg": "Check your new address: we sent a link to confirm it."})
    else:
        flash("That change could not be applied.", "warn")
        resp = redirect(url_for("pages.account"))
    return settle_change(change, user, resp)


@bp.route("/account/email", methods=["GET", "POST"])
def account_email():
    return _change_view("email")


@bp.route("/account/password", methods=["GET", "POST"])
def account_password():
    return _change_view("password")


@bp.route("/account/address", methods=["GET", "POST"])
def account_address():
    return _change_view("address")


@bp.route("/account/card", methods=["GET", "POST"])
def account_card():
    return _change_view("card")


def _notice(testid, title, message, status=200):
    """The answer to a link followed from a mail: JSON for API clients, a small page for browsers."""
    if gate.wants_json():
        return {"status": testid.removeprefix("change-"), "message": message}, status
    return render("notice.html", testid=testid, title=title, message=message), status


def _change_for_link(**match):
    token = request.args.get("token", "")
    row = AccountChange.query.filter_by(**match).first() if token else None
    return row if row and hmac.compare_digest(row.token or "", token) else None


@bp.route("/account/email/confirm")
def email_confirm():
    """The link mailed to the NEW address. No login: opening it proves the mailbox is theirs."""
    change = _change_for_link(token=request.args.get("token", ""), kind="email")
    if change is None:
        return _notice("unknown-link", "Unknown link", "That link is not valid.", 404)
    if change.status == "cancelled":
        return _notice("change-cancelled", "Change cancelled", "This change was cancelled.", 410)
    if change.status != "confirm":
        return _notice("change-confirmed", "Already confirmed", "This address is already confirmed.")
    user = db.session.get(User, change.user_id)
    hold = (change.extra or {}).get("hold")
    acct.hold_change(change, hold) if hold else acct.apply_change(change)
    resp = (_notice("change-pending", "On hold", "Confirmed. The change is on hold for review.", 202) if change.status == "pending"
            else _notice("change-confirmed", "Email confirmed", "Your email address is updated.") if change.status == "applied"
            else _notice("change-cancelled", "Not applied", "That address is no longer available.", 409))
    return settle_change(change, user, resp, confirmed=True)


@bp.route("/account/changes/<int:cid>/cancel")
def change_cancel(cid):
    """The cancel link in the notice mailed to the old address. No login: it is the owner's link."""
    change = db.session.get(AccountChange, cid)
    if change is None or not hmac.compare_digest(change.token or "", request.args.get("token", "")):
        return _notice("unknown-link", "Unknown link", "That link is not valid.", 404)
    if change.status == "applied":
        return _notice("change-applied", "Too late to cancel", "This change has already been applied.", 409)
    first = change.status != "cancelled"
    acct.cancel_change(change, "owner_link")
    resp = _notice("change-cancelled", "Change cancelled", "The change was cancelled. Nothing was updated.")
    if first:
        resp = after_action("change_cancel", resp, change=change, user=db.session.get(User, change.user_id))
    return resp


@bp.route("/orders")
def orders():
    user = current_user()
    if not user:
        return redirect(url_for("pages.login", next="/orders"))
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    return render("orders.html", orders=orders)


@bp.route("/gift-cards", methods=["GET", "POST"])
def gift_cards():
    if request.method == "GET":
        return render("gift_cards.html")
    if not csrf_ok():
        abort(400)
    code = request.form.get("code", "").strip().upper()
    r = guard("gift_card_check", code=code)
    if r:
        return r
    card = GiftCard.query.filter_by(code=code).first()
    g.ctx.note(gift_card="hit" if card else "miss")
    return render("gift_cards.html", code=code, card=card)


@bp.route("/newsletter", methods=["POST"])
def newsletter():
    email = (request.form.get("email") or (request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    if "@" not in email:
        return api_error("invalid_email", "Enter an email address.") if request.is_json else redirect(url_for("pages.home"))
    r = guard("newsletter", email=email)
    if r:
        return r
    if not Newsletter.query.filter_by(email=email).first():
        db.session.add(Newsletter(email=email, extra={"sid": g.ctx.session.sid}))
        db.session.commit()
    if request.is_json:
        return {"ok": True}
    flash("You're on the list.", "ok")
    return redirect(request.form.get("next") or url_for("pages.home"))
