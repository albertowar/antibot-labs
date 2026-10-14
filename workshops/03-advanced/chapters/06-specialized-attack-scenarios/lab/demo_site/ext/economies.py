"""
W3 Ch6 ext: the surfaces and the facts the five scenario defenses decide on.

The store already has everything the attackers need (a login, a limited drop, a catalogue, a
registration form). What it does not have is the product telemetry a defender reads off them, and
a place for ad clicks. This module adds both without touching a starter file:

  Enrichers (run on every request, at every level; they only RECORD facts in ctx.attrs):
    ctx.attrs["catalog"]  a product or listing read: kind, key, and whether the SKU is a honeypot   (Round 3)
    ctx.attrs["drop"]     a drop purchase: seconds since the session viewed the drop, and the device (Round 2)
    ctx.attrs["signup"]   a registration: email, domain, on the disposable list, and the device     (Round 4)
  The decisions are in defenses/*.py; nothing here blocks anything.

  Honeypot SKUs  p121, p122 (hidden=True), created while the level is 3 or more and removed below,
                 because tools/smoke.py counts 122 products at level 0. They are reachable by a link no
                 person sees: a visually hidden, unfocusable anchor in the navigation (level 3+), which
                 robots.txt also tells crawlers to skip.
  Canary         every page carries a hidden per-session token (a hash of the session id). If it turns up
                 in a competitor's catalogue, you know which session scraped you. Attribution is a defense.
  Ad tracker     POST /api/ads/impression, POST /api/ads/click (JSON {"campaign"}), GET /api/ads/report.
                 A click consumes the session's impression (one impression, at most one billable click), runs
                 the `action:ad_click` phase with ctx.attrs["ad"] (had_impression, dwell_ms) and is "billed"
                 only if the ladder lets it through (Round 5).

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import hashlib
import os
import re
import threading
import time

from flask import Blueprint, current_app, g, jsonify, request
from markupsafe import Markup

from demo_site import hooks
from demo_site.models import Product, db
from demo_site.routes import guard

HONEY = [
    {"sku": "p121", "name": "Archive Clearance Pack", "category": "packs", "price_cents": 1999,
     "blurb": "Unlisted. Out of stock for good."},
    {"sku": "p122", "name": "Staff Sample Jacket", "category": "jackets", "price_cents": 2999,
     "blurb": "Unlisted. Out of stock for good."},
]
HONEY_SKUS = tuple(h["sku"] for h in HONEY)
DROP_SKUS = ("lab-runner-9", "lab-hoodie-1")
TRAP_LEVEL = 3                       # the honeypots exist from this level on
LISTINGS = {"/products", "/catalog", "/search", "/api/products", "/api/search"}
PRODUCT_PATH = re.compile(r"^/(?:product|api/products)/([^/]+)$")
DROP_BUY_PATH = re.compile(r"^/drop/([^/]+)$")
_lock = threading.Lock()
_state = {"honey": None, "disposable": None}


def _body(ctx):
    return ctx.json if isinstance(ctx.json, dict) else ctx.form


def _disposable():
    if _state["disposable"] is None:
        path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "disposable_domains.txt")
        with open(path) as fh:
            _state["disposable"] = {ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")}
    return _state["disposable"]


def _device(ctx):
    return ctx.cookies.get("did") or ctx.session.sid


# --- enrichers: record facts, decide nothing ---------------------------------------------------------

def _facts(ctx):
    path = ctx.path
    if ctx.method == "GET":
        m = PRODUCT_PATH.match(path)
        sku = m.group(1) if m else (DROP_BUY_PATH.match(path).group(1) if DROP_BUY_PATH.match(path) else None)
        if sku in DROP_SKUS:                                 # a view of the drop: the funnel's first step
            if ctx.session.get(f"view:{sku}") is None:
                ctx.session.set(f"view:{sku}", f"{time.time()}")
        elif m:
            ctx.attrs["catalog"] = {"kind": "product", "key": f"sku:{sku}", "honeypot": sku in HONEY_SKUS}
        elif path in LISTINGS:
            ctx.attrs["catalog"] = {"kind": "listing", "honeypot": False,
                                    "key": f"list:{path}:{ctx.args.get('category', '')}:{ctx.args.get('page', '1')}:{ctx.args.get('q', '')}"}
        return
    if ctx.method != "POST":
        return
    drop_sku = None
    if path == "/api/buy":
        drop_sku = str((ctx.json or {}).get("sku", "")) if isinstance(ctx.json, dict) else ""
    elif DROP_BUY_PATH.match(path):
        drop_sku = DROP_BUY_PATH.match(path).group(1)
    if drop_sku in DROP_SKUS:
        seen = ctx.session.get(f"view:{drop_sku}")
        ctx.attrs["drop"] = {"sku": drop_sku, "device": _device(ctx),
                             "view_age_s": (time.time() - float(seen)) if seen is not None else None}
    elif path in ("/register", "/api/register"):
        email = str(_body(ctx).get("email", "")).strip().lower()
        domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        ctx.attrs["signup"] = {"email": email, "domain": domain, "disposable": domain in _disposable(),
                               "device": _device(ctx)}


def _sync_honey(ctx):
    """Keep the honeypot products in step with the level (absent at levels below TRAP_LEVEL)."""
    want = ctx.level >= TRAP_LEVEL
    if _state["honey"] is want:
        return
    with _lock:
        for h in HONEY:
            row = Product.query.filter_by(sku=h["sku"]).first()
            if want and not row:
                db.session.add(Product(hidden=True, stock=0, sizes=[], colorway="Plain", rating=0.0, **h))
            elif not want and row:
                db.session.delete(row)
        db.session.commit()
        _state["honey"] = want


# --- template helpers: the hidden link and the canary ----------------------------------------------

def _trap_link():
    if current_app.config["LAB"].defense_level < TRAP_LEVEL:
        return Markup("")
    return Markup(f'<a href="/product/{HONEY_SKUS[0]}" tabindex="-1" aria-hidden="true" '
                  f'style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">Archive clearance</a>')


def _canary():
    ctx = getattr(g, "ctx", None)
    if ctx is None:
        return ""
    return hashlib.sha256(f"canary:{ctx.session.sid}".encode()).hexdigest()[:12]


# --- the ad tracker ----------------------------------------------------------------------------------

bp = Blueprint("economies", __name__, url_prefix="/api/ads")


def _campaign():
    body = request.get_json(silent=True) or {}
    return str(body.get("campaign", "camp-1"))[:32]


@bp.route("/impression", methods=["POST"])
def impression():
    campaign = _campaign()
    g.ctx.redis.set(f"lab:ads:imp:{g.ctx.session.sid}:{campaign}", f"{time.time()}", ex=900)
    return jsonify(ok=True, campaign=campaign)


@bp.route("/click", methods=["POST"])
def click():
    campaign = _campaign()
    seen = g.ctx.redis.getdel(f"lab:ads:imp:{g.ctx.session.sid}:{campaign}")     # one impression pays for one click
    g.ctx.attrs["ad"] = {"campaign": campaign, "had_impression": seen is not None,
                         "dwell_ms": (time.time() - float(seen)) * 1000 if seen is not None else 0.0}
    r = guard("ad_click", campaign=campaign)
    if r:
        return r
    g.ctx.redis.incr(f"lab:ads:billed:{campaign}")
    return jsonify(ok=True, counted=True, campaign=campaign, cpc_cents=45)


@bp.route("/report")
def report():
    campaign = request.args.get("campaign", "camp-1")
    return jsonify(campaign=campaign, billed_clicks=int(g.ctx.redis.get(f"lab:ads:billed:{campaign}") or 0))


def init(app):
    app.jinja_env.globals.update(ch6_trap_link=_trap_link, ch6_canary=_canary)
    hooks.slot("nav", "economies/trap_link.html")
    hooks.slot("body_end", "economies/canary.html")
    hooks.enricher(_facts)
    hooks.enricher(_sync_honey)
    hooks.robots(lambda: [f"Disallow: /product/{s}" for s in HONEY_SKUS]
                 if current_app.config["LAB"].defense_level >= TRAP_LEVEL else [])
    app.register_blueprint(bp)

    @app.after_request
    def _forget_honey(response):                         # /lab/reset?mode=full reseeds: forget what we knew
        if request.path == "/lab/reset":
            _state["honey"] = None
        return response
