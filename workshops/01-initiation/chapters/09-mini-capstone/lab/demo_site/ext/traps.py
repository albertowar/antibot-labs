"""
Chapter 8 feature module: the pages and hooks the traps need.

    hooks.slot("head", ...)           traps.css (.hp hides a trap with display:none, .hp-offscreen only off-screen)
    hooks.slot("form:register", ...)  the signup honeypot and the timing token (defenses/form_traps.py)
    hooks.slot("body_end", ...)       the hidden trap link and traps.js (defenses/crawl_traps.py)
    hooks.robots(...)                 extra robots.txt lines: the trap paths a good crawler must skip
    /catalog/archive[/<n>]            the maze behind the trap link          (level 3+, else 404)
    /.env, /wp-admin/, /wp-login.php  scanner decoys, a canary DB password   (level 3+, else 404)
    /api/internal/<path>              the export URL only a JS miner finds   (level 3+, else 404)
    SKU p121 (hidden)                 the honey record, created at level 3+  (never listed)
    /lab/traps                        how the store sees YOU: level, config, sanction

It also finishes what the gate cannot. A `deceive` verdict only sets g.deceive: the starter's signup
and review routes do not honour it, so this module answers a faked POST /register or POST /review/<sku>
itself, with the same redirect the real route gives. For `quarantine` the real route runs and this
module flags the account and parks the review afterwards (status "pending": shown to its author only).

The trap CHECKS (what counts as a hit, what to do about it) are in defenses/; this file never decides
anything about a request. Ext modules are not hot-reloaded: restart after editing this file.
"""

import re
import threading
from types import SimpleNamespace

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request
from markupsafe import Markup

from defenses import crawl_traps, form_traps, policy, responses

from .. import gate, hooks
from ..models import Product, Review, User, db, utcnow

HONEY = {"sku": crawl_traps.HONEY_SKU, "name": "Seafoam Glaze Espresso Cup", "category": "kitchen",
         "price_cents": 1749, "blurb": "Stoneware, seafoam glaze. Holds 120 ml. Out of stock for good."}
_lock = threading.Lock()
_state = {"honey": None}         # None = unknown; reconciled on the next request


def _level():
    return current_app.config["LAB"].defense_level


# --- The honey record: a hidden product that exists only while the level asks for it ----------------

def _sync_honey(ctx):
    """Enricher. Keeps the hidden product in step with the level (and absent at level 0, where smoke.py counts)."""
    want = ctx.level >= 3
    if _state["honey"] is want:
        return
    with _lock:
        row = Product.query.filter_by(sku=HONEY["sku"]).first()
        if want and not row:
            db.session.add(Product(hidden=True, stock=0, sizes=[], colorway="Seafoam", rating=0.0, **HONEY))
            db.session.commit()
        elif not want and row:
            db.session.delete(row)
            db.session.commit()
        _state["honey"] = want


# --- Template helpers ---------------------------------------------------------------------------------

def _trap_fields():
    return Markup(form_traps.render_fields(g.ctx.session.sid, _level()))


def _trap_link():
    return Markup(crawl_traps.trap_link_html()) if _level() >= 3 else Markup("")


def _own_reviews(sku):
    """Reviews this session's author posted that are parked in quarantine: the shadow ban shows them only to their author."""
    sid = g.ctx.session.sid
    rows = Review.query.filter_by(sku=sku, status="pending").order_by(Review.created_at.desc()).all()
    return [r for r in rows if (r.extra or {}).get("sid") == sid]


# --- Fake and quarantined answers ---------------------------------------------------------------------

def _fake_account_page():
    """What a faked signup sees at /account: a plausible, empty account. Nothing was created."""
    who = g.ctx.session.get("faked_name") or "there"
    ghost = SimpleNamespace(name=who, loyalty_points=0, saved_card_last4=None, saved_card_brand=None,
                            created_at=utcnow(), addresses=[], email=g.ctx.session.get("faked_email", ""))
    return render_template("account.html", user=ghost, orders=[])


def _intercept():
    """before_request, after the gate's: finish a `deceive` verdict on the two writes a bot abuses."""
    ctx = getattr(g, "ctx", None)
    if ctx is None:
        return None
    g.traps_uid = ctx.session.user_id
    if request.method == "GET" and request.path == "/account" and not ctx.user and ctx.session.get("faked_email"):
        return _fake_account_page()
    if not g.deceive or request.method != "POST":
        return None
    if request.path == "/register":
        ctx.session.set("faked_email", request.form.get("email", "").strip().lower())
        ctx.session.set("faked_name", request.form.get("name", "")[:80])
        ctx.session.set("flash", "ok|Welcome to Kestrel.")        # the same flash the real route sets
        ctx.note(account="faked")
        return redirect("/account")
    m = re.match(r"/review/([^/]+)$", request.path)
    if m:
        ctx.session.set("flash", "ok|Thanks for your review.")
        ctx.note(review="faked")
        return redirect(f"/product/{m.group(1)}")
    return None


def _after(response):
    """after_request, before the gate's: flag what the real routes just created, and tell the decision log."""
    ctx = getattr(g, "ctx", None)
    if ctx is None or request.method != "POST" or response.status_code != 302:
        return response
    contained = bool(ctx.attrs.get("quarantine"))
    if request.path == "/register" and ctx.session.user_id and ctx.session.user_id != getattr(g, "traps_uid", None):
        user = db.session.get(User, ctx.session.user_id)
        if contained:
            user.extra = {**(user.extra or {}), "quarantined": True}
            db.session.commit()
        ctx.note(account="quarantined" if contained else "created")
    m = re.match(r"/review/([^/]+)$", request.path)
    if m and not g.deceive:
        user = ctx.user
        contained = contained or bool(user and (user.extra or {}).get("quarantined"))
        mine = Review.query.filter_by(sku=m.group(1), status="published").order_by(Review.id.desc()).all()
        mine = [r for r in mine if (r.extra or {}).get("sid") == ctx.session.sid][:1]
        if mine and contained:
            mine[0].status, mine[0].extra = "pending", {**(mine[0].extra or {}), "quarantined": True}
            db.session.commit()
        ctx.note(review="quarantined" if contained else "published")
    return response


# --- Pages --------------------------------------------------------------------------------------------

def _build_blueprint():
    bp = Blueprint("traps", __name__)

    def armed():
        if _level() < 3:
            abort(404)

    @bp.route("/catalog/archive")
    @bp.route("/catalog/archive/<int:n>")
    def archive(n=1):
        armed()
        return render_template("traps/archive.html", n=n)

    @bp.route("/.env")
    def dotenv():
        armed()
        # Canary values: if these ever show up in a login attempt, you know where they came from.
        return "APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=canary-7f3a9c\n", 200, {"Content-Type": "text/plain"}

    @bp.route("/wp-admin/", methods=["GET", "POST"])
    @bp.route("/wp-login.php", methods=["GET", "POST"])
    def wordpress():
        armed()
        return render_template("traps/wp_login.html", tried=request.method == "POST")

    @bp.route("/api/internal/<path:rest>", methods=["GET", "POST"])
    def internal(rest):
        armed()
        return jsonify(error={"code": "unauthorized", "message": "Authentication required."}), 401

    @bp.route("/lab/traps")
    def status():
        """How the store sees YOU: your address, session, any sanction, and the trap configuration."""
        ctx = gate.build_ctx(current_app)
        level = ctx.level
        return jsonify(
            level=level, client_ip=ctx.ip, session=ctx.session.sid,
            response_mode=policy.TRAP_RESPONSE_MODE if level >= 4 else None,
            sanction_key=policy.TRAP_SANCTION_KEY if level >= 4 else None,
            sanctioned=responses.sanctioned(ctx) if level >= 4 else None,
            honeypot=form_traps.HONEYPOT if level >= 2 else None,
            honeypot_field=form_traps.honeypot_name(ctx.session.sid, level) if level >= 1 else None,
            min_fill_seconds=policy.MIN_FILL_SECONDS if level >= 2 else None,
            robots_extra=crawl_traps.robots_lines(level))

    return bp


def init(app):
    app.jinja_env.globals.update(trap_fields=_trap_fields, trap_link=_trap_link, own_reviews=_own_reviews)
    hooks.slot("head", "traps/head.html")
    hooks.slot("form:register", "traps/fields.html")
    hooks.slot("body_end", "traps/footer.html")
    # Read the module and the level at call time, never cached: the reloader replaces defenses/*
    # modules, and /lab/level replaces the Config object.
    hooks.robots(lambda: crawl_traps.robots_lines(_level()))
    hooks.enricher(_sync_honey)
    app.register_blueprint(_build_blueprint())
    app.before_request(_intercept)
    app.after_request(_after)

    @app.after_request
    def _reset_honey(response):                  # /lab/reset?mode=full reseeds: forget what we knew
        if request.path == "/lab/reset":
            _state["honey"] = None
        return response
