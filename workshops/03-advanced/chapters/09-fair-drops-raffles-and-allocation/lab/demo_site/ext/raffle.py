"""
W3 Ch9 ext: a raffle for the Kestrel drop, and the facts the allocation defenses decide on.

How the drop is sold depends on DEFENSE_LEVEL, which is the one place this lab uses the level as a switch
instead of a ladder rung (like Chapter 4's honeypot SKUs):

    level 0   first come, first served: the starter's POST /drop/<sku> and POST /api/buy, with W3 Ch4's funnel
              in front (Round 0). The drop opens at a set second so every client races for the same instant.
    level 1+  a raffle: the FCFS buy is closed ("raffle_only") and entries go to /raffle/<sku>.

The raffle (lab-clock free: every window is a state change you trigger with a lab route):

    open -> [entries] -> draw -> [claims] -> expire -> [claims] -> rescore -> [claims] -> done

    GET  /raffle/<sku>            the page (also /api/raffle/<sku>: {mode, state, units})
    POST /raffle/<sku>/enter      one entry: your ship-to and, optionally, a card   (guard("raffle_enter"))
    GET  /raffle/<sku>/me         your entry: entered | won | not_selected | claimed | pending_review
    POST /raffle/<sku>/claim      a winner pays: place_order(kind="raffle")          (guard("raffle_claim"))
         (JSON mirrors under /api/raffle/<sku>/..., the shapes the attacks and the shoppers use)
    GET  /raffle/verify           the email-verification link (simulated: the store has no such column)

  Lab-only (loopback; not part of the production surface):
    POST /lab/raffle/open         seed the cast (raffle_world), open the event. {"delay_s": FCFS opening, seconds}
    POST /lab/raffle/draw         close entries, run the batch phase "raffle:draw", rank winners and a waitlist
    POST /lab/raffle/expire       unclaimed wins lapse; the next on the waitlist is promoted
    POST /lab/raffle/rescore      run "raffle:rescore" over the claimed, held and waiting entries, then promote
    GET  /lab/raffle/report       fairness metrics and per-cohort outcomes (scoreboard side: ground truth)

How the gate sees a batch decision (the precedent is W3 Ch2's ws:message): the three lab routes above keep a
Ctx (hooks.ungate(..., session=True)) but not the ladder, and call gate.run_phase themselves with the whole
entry list in ctx.attrs["entries"]. The checks that apply to "raffle:draw" / "raffle:rescore" MUTATE those
dicts (weight, excluded, cluster, verdict); the ladder's usual verdict is not what decides. The decision log
gets one row per call, with the counts in `extra`, which is what a batch decision looks like in an audit log.

The draw is seeded: LAB_SEED, the event and the round number; entries sorted by email; a weight w makes the
key u ** (1 / w) (Efraimidis and Spirakis, weighted sampling without replacement). Same entries, same result.

Ground truth (who is a fan, who is a crew) is NEVER stored on an entry. The report joins the entry's session
to the decision log, the way the scoreboard does, and only /lab/raffle/report reads it.

Ext modules are not hot-reloaded: restart the store after editing this file.
"""

import hmac
import re
import secrets
import time
from datetime import datetime, timedelta

from flask import Blueprint, current_app, g, jsonify, redirect, request, url_for
from sqlalchemy import JSON

from demo_site import account as acct
from demo_site import gate, hooks, orders
from demo_site.models import (AccountChange, Address, Decision, Order, OrderItem, Product, User, db, utcnow)
from demo_site.routes import after_action, api_error, current_user, guard, render
from demo_site.routes import pages
from demo_site.routes.pages import place_order
from demo_site.seed import N_USERS, set_password

from . import raffle_world as W

RAFFLE_LEVEL = 1                         # the level at which the store raffles the drop instead of selling it
OTP_TTL_S = 900
WORLD_TAG = "raffle"
ENTRY_STATUS = ("entered", "excluded", "won", "waitlist", "claimed", "held", "expired", "cancelled")
LIVE = ("won", "claimed", "held")        # entries that hold a unit

DROP_BUY_PATH = re.compile(r"^/drop/([^/]+)$")
PRODUCT_PATH = re.compile(r"^/(?:product|api/products)/([^/]+)$")


# --- tables ---------------------------------------------------------------------------------------------

class RaffleEvent(db.Model):
    __tablename__ = "raffle_events"
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(32), index=True)
    units = db.Column(db.Integer, default=0)
    state = db.Column(db.String(12), default="open")          # open | drawn
    rounds = db.Column(db.Integer, default=0)                  # draws made (the seed's third part)
    opened_ts = db.Column(db.Float, default=0.0)
    extra = db.Column(JSON, default=dict)


class RaffleEntry(db.Model):
    """One entry. Raw facts as the request carried them; the checks derive everything else."""
    __tablename__ = "raffle_entries"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, index=True)
    user_id = db.Column(db.Integer, index=True, nullable=True)
    email = db.Column(db.String(120), index=True)
    sid = db.Column(db.String(64), index=True)
    did = db.Column(db.String(64), default="")
    ip = db.Column(db.String(45), default="")
    asn = db.Column(db.Integer, default=0)
    ja4 = db.Column(db.String(64), default="")
    ua = db.Column(db.String(32), default="")
    entered_at = db.Column(db.Float, default=0.0)              # seconds after the event opened
    size = db.Column(db.String(8), default="")
    line1 = db.Column(db.String(120), default="")
    city = db.Column(db.String(80), default="")
    postcode = db.Column(db.String(16), default="")
    bin6 = db.Column(db.String(6), default="")
    card_fp = db.Column(db.String(32), default="")
    last4 = db.Column(db.String(4), default="")
    age_days = db.Column(db.Float, default=0.0)
    created_ts = db.Column(db.Float, default=0.0)              # when the account was created (epoch seconds)
    paid_orders = db.Column(db.Integer, default=0)
    verified = db.Column(db.Boolean, default=False)
    weight = db.Column(db.Float, default=1.0)
    key = db.Column(db.Float, default=0.0)
    rank = db.Column(db.Integer, default=0)
    status = db.Column(db.String(12), default="entered", index=True)
    reasons = db.Column(JSON, default=list)
    cluster_id = db.Column(db.String(32), default="")
    order_number = db.Column(db.String(16), default="")
    claim = db.Column(JSON, default=dict)                      # facts of the claim: card, ship-to
    extra = db.Column(JSON, default=dict)


def _event(sku=W.SKU):
    """The raffle for `sku`, or None while the store is selling the drop first come, first served."""
    if sku != W.SKU or current_app.config["LAB"].defense_level < RAFFLE_LEVEL:
        return None
    return RaffleEvent.query.order_by(RaffleEvent.id.desc()).first()


def _latest():
    return RaffleEvent.query.order_by(RaffleEvent.id.desc()).first()


def _epoch(dt):
    return (dt - datetime(1970, 1, 1)).total_seconds()


# --- Round 0 facts: the funnel's view of a drop purchase (the shape W3 Ch4's economies.py provides) ------

def _drop_facts(ctx):
    """ctx.attrs["drop"] on a drop purchase: seconds since this session viewed the drop, and the device."""
    path = ctx.path
    if ctx.method == "GET":
        m = PRODUCT_PATH.match(path) or DROP_BUY_PATH.match(path)
        if m and m.group(1) == W.SKU and ctx.session.get(f"view:{W.SKU}") is None:
            ctx.session.set(f"view:{W.SKU}", f"{time.time()}")
        return
    if ctx.method != "POST":
        return
    sku = None
    if path == "/api/buy":
        sku = str((ctx.json or {}).get("sku", "")) if isinstance(ctx.json, dict) else ""
    elif DROP_BUY_PATH.match(path):
        sku = DROP_BUY_PATH.match(path).group(1)
    if sku == W.SKU:
        seen = ctx.session.get(f"view:{sku}")
        ctx.attrs["drop"] = {"sku": sku, "device": ctx.cookies.get("did") or ctx.session.sid,
                             "view_age_s": (time.time() - float(seen)) if seen is not None else None}


def _close_first_come():
    """From level 1 on the drop is allocated by the raffle: the first-come buy is refused."""
    if request.method != "POST" or current_app.config["LAB"].defense_level < RAFFLE_LEVEL:
        return None
    body = request.get_json(silent=True) if request.is_json else None
    target = request.path == "/api/buy" and isinstance(body, dict) and body.get("sku") == W.SKU
    if not (target or request.path == f"/drop/{W.SKU}") or _latest() is None:
        return None
    g.outcome = "blocked"
    return jsonify(error={"code": "raffle_only", "message": "This drop is allocated by raffle. Enter at "
                                                           f"/raffle/{W.SKU}."}), 409


# --- the entry --------------------------------------------------------------------------------------------

class Out:
    """What do_enter / do_me / do_claim return when the route (not the gate) answers: a JSON payload and
    a status. `extra` carries the claim's rows to the post-write hooks. A gate answer (a block, a
    challenge) is returned as it is, which is how a caller tells the two apart."""

    def __init__(self, payload, status=200, extra=None):
        self.payload, self.status, self.extra = payload, status, extra


def _error(code, message, status=400):
    return Out({"error": {"code": code, "message": message}}, status)


def _ship_for(user, body):
    saved = list(user.addresses) if user else []
    if body.get("address_id") not in (None, ""):
        row = next((a for a in saved if str(a.id) == str(body["address_id"])), None)
        if row is None:
            raise acct.ChangeError("invalid_address", "That is not one of your saved addresses.")
        return row.line1, row.city, row.postcode
    if body.get("line1"):
        return str(body["line1"])[:120], str(body.get("city", ""))[:80], str(body.get("postcode", ""))[:16]
    if saved:
        return saved[0].line1, saved[0].city, saved[0].postcode
    raise acct.ChangeError("no_address", "Give a delivery address, or save one in your account first.")


def _card_for(user, body):
    """The card an entry (or claim) pays with: a typed number, else the saved card, else none."""
    if str(body.get("card") or "").strip():
        facts = acct.card_facts(body["card"])
        if facts is None:
            raise acct.ChangeError("invalid_card", "Enter a card number.")
        return {"bin6": facts["bin6"], "fp": facts["fingerprint"], "last4": facts["last4"], "brand": facts["brand"],
                "saved": bool(user and (user.extra or {}).get("card_fp") == facts["fingerprint"]), "typed": True}
    if user and user.saved_card_last4:
        ux = user.extra or {}
        return {"bin6": ux.get("card_bin", ""), "fp": ux.get("card_fp", ""), "last4": user.saved_card_last4,
                "brand": user.saved_card_brand or "", "saved": True, "typed": False}
    return {"bin6": "", "fp": "", "last4": "", "brand": "", "saved": False, "typed": False}


def do_enter(sku, body):
    ev = _event(sku)
    if ev is None:
        return _error("no_raffle", "This drop is not a raffle.", 404)
    if ev.state != "open":
        return _error("closed", "Entries are closed.", 409)
    user = current_user()
    ctx = g.ctx
    email = (user.email if user else str(body.get("email", ""))).strip().lower()
    if "@" not in email:
        return _error("invalid_email", "Enter an email address.")
    p = Product.query.filter_by(sku=sku).first()
    size = str(body.get("size") or W.SIZE)
    if p.sizes and size not in p.sizes:
        return _error("invalid", "Pick a size.")
    try:
        line1, city, postcode = _ship_for(user, body) if user else (str(body.get("line1", ""))[:120],
                                                                     str(body.get("city", ""))[:80],
                                                                     str(body.get("postcode", ""))[:16])
        card = _card_for(user, body)
    except acct.ChangeError as e:
        return _error(e.code, e.message, e.status)
    prior = RaffleEntry.query.filter_by(event_id=ev.id, user_id=user.id).count() if user else \
        RaffleEntry.query.filter_by(event_id=ev.id, email=email).count()
    ux = (user.extra or {}) if user else {}
    age_days = (utcnow() - user.created_at).total_seconds() / 86400 if user else 0.0
    paid = Order.query.filter_by(user_id=user.id, status="paid").count() if user else 0
    ctx.attrs["entry"] = {"account": bool(user), "email": email, "prior": prior, "verified": bool(ux.get("email_verified")),
                          "age_days": round(age_days, 3), "paid_orders": paid,
                          "ship": {"line1": line1, "city": city, "postcode": postcode},
                          "card": {k: card[k] for k in ("bin6", "fp", "last4")}, "device": ctx.cookies.get("did", "")}
    r = guard("raffle_enter", prior=prior, verified=bool(ux.get("email_verified")), age_days=round(age_days, 1),
              paid_orders=paid, has_card=bool(card["fp"]))
    if r:
        return r
    row = RaffleEntry(event_id=ev.id, user_id=user.id if user else None, email=email, sid=ctx.session.sid,
                      did=ctx.cookies.get("did", ""), ip=ctx.edge.ip, asn=ctx.edge.asn, ja4=ctx.edge.ja4,
                      ua=f"{ctx.ua.family}/{ctx.ua.major}", entered_at=round(time.time() - ev.opened_ts, 3), size=size,
                      line1=line1, city=city, postcode=postcode, bin6=card["bin6"], card_fp=card["fp"],
                      last4=card["last4"], age_days=round(age_days, 3),
                      created_ts=_epoch(user.created_at) if user else 0.0, paid_orders=paid,
                      verified=bool(ux.get("email_verified")), status="entered", reasons=[], extra={})
    db.session.add(row)
    db.session.commit()
    ctx.note(raffle_entry=row.id)
    return Out({"ok": True, "status": "entered", "entry": row.id}, 201)


def _public_status(ev, e):
    if e is None:
        return "none"
    if e.status in ("won", "claimed"):
        return e.status
    if e.status == "held":
        return "pending_review"
    if ev.state == "open" or e.status == "entered":
        return "entered"
    return "not_selected"


def do_me(sku):
    ev = _event(sku)
    if ev is None:
        return _error("no_raffle", "This drop is not a raffle.", 404)
    user = current_user()
    if not user:
        return _error("unauthenticated", "Log in first.", 401)
    rows = RaffleEntry.query.filter_by(event_id=ev.id, user_id=user.id).order_by(RaffleEntry.id).all()
    pick = next((e for e in rows if e.status in ("won", "claimed", "held")), rows[0] if rows else None)
    return Out({"state": ev.state, "status": _public_status(ev, pick), "entries": len(rows)})


def do_claim(sku, body):
    ev = _event(sku)
    if ev is None:
        return _error("no_raffle", "This drop is not a raffle.", 404)
    user = current_user()
    if not user:
        return _error("unauthenticated", "Log in first.", 401)
    entry = RaffleEntry.query.filter_by(event_id=ev.id, user_id=user.id, status="won").order_by(RaffleEntry.id).first()
    if entry is None:
        return _error("not_a_winner", "You have no entry to claim.", 409)
    try:
        ship = _ship_for(user, body) if (body.get("address_id") or body.get("line1")) else (entry.line1, entry.city, entry.postcode)
        card = _card_for(user, body)
    except acct.ChangeError as e:
        return _error(e.code, e.message, e.status)
    if not card["fp"]:
        return _error("card_required", "Add a payment card to claim.", 402)
    saved_norm = {acct.normalize_address(a.line1, a.city, a.postcode) for a in user.addresses}
    norm = acct.normalize_address(*ship)
    ctx = g.ctx
    ctx.attrs["claim"] = {"entry_card": {"bin6": entry.bin6, "fp": entry.card_fp}, "card": {k: card[k] for k in ("bin6", "fp", "saved")},
                          "card_new": card["fp"] != entry.card_fp,
                          "ship": {"line1": ship[0], "city": ship[1], "postcode": ship[2], "normalized": norm,
                                   "new": norm not in saved_norm,
                                   "changed": norm != acct.normalize_address(entry.line1, entry.city, entry.postcode)},
                          "age_days": entry.age_days, "paid_orders": entry.paid_orders, "email": user.email}
    r = guard("raffle_claim", card_new=ctx.attrs["claim"]["card_new"], ship_new=ctx.attrs["claim"]["ship"]["new"],
              ship_changed=ctx.attrs["claim"]["ship"]["changed"])
    if r:
        return r
    p = Product.query.filter_by(sku=sku).first()
    line = {"product": p, "sku": sku, "size": entry.size or W.SIZE, "qty": 1, "line_cents": p.price_cents}
    shipped = {"normalized": norm, "new": ctx.attrs["claim"]["ship"]["new"], "address_id": None}
    order, problem = place_order([line], user.email, user, {"kind": "raffle", "sku": sku, "entry": entry.id, "ship_to": shipped,
                                                            "card": {"bin6": card["bin6"], "last4": card["last4"], "fingerprint": card["fp"],
                                                                     "saved": card["saved"]}})
    if problem:
        entry.status, entry.reasons = "expired", (entry.reasons or []) + ["sold_out"]
        db.session.commit()
        return _error("sold_out", problem, 410)
    entry.status, entry.order_number = "claimed", order.number
    entry.claim = {"ship": ctx.attrs["claim"]["ship"], "card_fp": card["fp"], "bin6": card["bin6"], "card_new": ctx.attrs["claim"]["card_new"]}
    db.session.commit()
    return Out({"ok": True, "status": "claimed", "order": order.to_dict()}, 201, extra=(order, entry))


def _hold_after_claim(ctx, result, response):
    """A check may park a claim for review: ctx.attrs["hold"] = {"reason": ...}. The unit stays reserved
    (orders.py: a held order is neither a purchase nor a stop until the review lands)."""
    hold = ctx.attrs.get("hold")
    order, entry = result.get("order"), result.get("entry")
    if not (isinstance(hold, dict) and order is not None):
        return None
    order.status = "pending"
    order.extra = dict(order.extra or {}, hold=hold)
    entry.status = "held"
    entry.reasons = (entry.reasons or []) + [f"hold:{hold.get('reason', 'review')}"]
    db.session.commit()
    g.outcome = "held"
    return jsonify(ok=True, status="pending_review", order=order.number), 202


def _claim_response(res):
    if not isinstance(res, Out):
        return res
    if res.extra is None:
        return jsonify(res.payload), res.status
    order, entry = res.extra
    return after_action("raffle_claim", (jsonify(res.payload), res.status), order=order, entry=entry)


# --- routes: JSON -----------------------------------------------------------------------------------------

bp = Blueprint("raffle", __name__)


def _json(res):
    return (jsonify(res.payload), res.status) if isinstance(res, Out) else res


@bp.route("/api/raffle/<sku>")
def api_event(sku):
    ev = _event(sku)
    p = Product.query.filter_by(sku=sku, is_drop=True).first()
    if p is None:
        return api_error("not_found", "No such drop.", 404)
    if ev is None:
        return jsonify(mode="first_come", state="open" if p.drop_open else "scheduled", drop_open=p.drop_open,
                       drop_at=p.drop_at.isoformat() + "Z" if p.drop_at else None, stock=p.stock)
    return jsonify(mode="raffle", state=ev.state, units=ev.units, enter=f"/api/raffle/{sku}/enter")


@bp.route("/api/raffle/<sku>/enter", methods=["POST"])
def api_enter(sku):
    return _json(do_enter(sku, request.get_json(silent=True) or request.form.to_dict()))


@bp.route("/api/raffle/<sku>/me")
def api_me(sku):
    return _json(do_me(sku))


@bp.route("/api/raffle/<sku>/claim", methods=["POST"])
def api_claim(sku):
    return _claim_response(do_claim(sku, request.get_json(silent=True) or request.form.to_dict()))


# --- routes: pages ----------------------------------------------------------------------------------------

def _flash(msg, kind="ok"):
    g.ctx.session.set("flash", f"{kind}|{msg}")


def _page_result(res, sku, ok_message):
    if not isinstance(res, Out):
        return res                                              # the gate's own answer (block, challenge page)
    if res.status < 300:
        _flash(ok_message)
    else:
        _flash(res.payload["error"]["message"] if "error" in res.payload else "That did not go through.", "warn")
    return redirect(url_for("raffle.page", sku=sku))


@bp.route("/raffle/<sku>")
def page(sku):
    p = Product.query.filter_by(sku=sku, is_drop=True).first_or_404()
    ev = _event(sku)
    user = current_user()
    mine = do_me(sku).payload if ev is not None and user else None
    return render("raffle/page.html", p=p, ev=ev, mine=mine)


@bp.route("/raffle/<sku>/enter", methods=["POST"])
def enter(sku):
    from flask import abort
    from demo_site.routes import csrf_ok
    if not csrf_ok():
        abort(400)
    return _page_result(do_enter(sku, request.form.to_dict()), sku, "You are in the draw.")


@bp.route("/raffle/<sku>/me")
def me(sku):
    return redirect(url_for("raffle.page", sku=sku))


@bp.route("/raffle/<sku>/claim", methods=["POST"])
def claim(sku):
    from flask import abort
    from demo_site.routes import csrf_ok
    if not csrf_ok():
        abort(400)
    res = do_claim(sku, request.form.to_dict())
    if isinstance(res, Out) and res.extra is not None:
        _claim_response(res)                                   # runs the hooks (a hold may park the order)
    return _page_result(res, sku, "Claimed. Your order is placed (or in review).")


def _token(email):
    return hmac.new(current_app.config["SECRET_KEY"].encode(), f"verify:{email}".encode(), "sha256").hexdigest()[:20]


@bp.route("/raffle/verify")
def verify():
    email, token = request.args.get("email", "").strip().lower(), request.args.get("token", "")
    user = User.query.filter_by(email=email).first()
    if user is None or not hmac.compare_digest(token, _token(email)):
        return api_error("invalid_token", "That link is not valid.", 400)
    user.extra = dict(user.extra or {}, email_verified=True)
    db.session.commit()
    return jsonify(ok=True, verified=True)


def _mail_verify_link(redis, email):
    acct.send_mail(redis, email, subject="Verify your email to enter drops", kind="verify",
                   verify_url=f"/raffle/verify?email={email}&token={_token(email)}")


def _after_register(ctx, result, response):
    user = result.get("user")
    if user is not None:
        _mail_verify_link(ctx.redis, user.email)
    return None


# --- the claim step-up: an in-session one-time code (a separate type from any login code, contract 1.8) ----

def otp_issue(ctx):
    if ctx.user is None:
        return {"error": "sign in first"}
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:raffle:otp:{ctx.session.sid}", code, ex=600)
    acct.send_mail(ctx.redis, ctx.user.email, subject="Your claim code", code=code, purpose="raffle_claim")
    return {"sent_to": re.sub(r"(?<=.).(?=[^@]*@)", "*", ctx.user.email), "digits": 6}


def otp_verify(ctx, answer):
    stored = ctx.redis.get(f"lab:raffle:otp:{ctx.session.sid}")
    if stored is None:
        return False, "code expired"
    if not hmac.compare_digest(str(answer.get("code", "")), str(stored)):
        return False, "wrong code"
    ctx.redis.delete(f"lab:raffle:otp:{ctx.session.sid}")      # it proves the person at the keyboard; it never writes uid
    return True


# --- the world: seed the cast -----------------------------------------------------------------------------

def _purge(app=None):
    """Remove the cast, the event and every entry. Also the on_reset hook (POST /lab/reset deletes the
    users it did not seed; this removes what hung off them)."""
    RaffleEntry.query.delete()
    RaffleEvent.query.delete()
    ids = [u.id for u in User.query.filter(User.id > N_USERS + 1)]
    if ids:
        oids = [o.id for o in Order.query.filter(Order.user_id.in_(ids))]
        if oids:
            OrderItem.query.filter(OrderItem.order_id.in_(oids)).delete(synchronize_session=False)
            Order.query.filter(Order.id.in_(oids)).delete(synchronize_session=False)
        AccountChange.query.filter(AccountChange.user_id.in_(ids)).delete(synchronize_session=False)
        Address.query.filter(Address.user_id.in_(ids)).delete(synchronize_session=False)
        User.query.filter(User.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()


def _reset_hook(app):
    _purge()
    p = Product.query.filter_by(sku=W.SKU).first()
    if p is not None:
        p.drop_at = utcnow() - timedelta(minutes=1)
        db.session.commit()


def _seed_world(redis, iters):
    now = utcnow()
    users = []
    for a in W.accounts():
        f = acct.card_facts(a.card) if a.card else None
        u = User(email=a.email, name=a.name, created_at=now - timedelta(days=a.age_days),
                 extra={"world": WORLD_TAG, "cohort": a.cohort, "email_verified": a.verified})
        set_password(u, a.password, iters)
        if f:
            u.saved_card_brand, u.saved_card_last4 = f["brand"], f["last4"]
            u.extra = dict(u.extra, card_bin=f["bin6"], card_fp=f["fingerprint"])
        users.append((a, u))
    db.session.add_all([u for _, u in users])
    db.session.flush()
    skus = [p.sku for p in Product.query.filter(Product.is_drop.is_(False), Product.hidden.is_(False)).limit(40)]
    prods = {p.sku: p for p in Product.query.filter(Product.sku.in_(skus))}
    n_order = 0
    for a, u in users:
        if a.address:
            db.session.add(Address(user_id=u.id, line1=a.address[0], city=a.address[1], postcode=a.address[2], country="US"))
        for k in range(a.paid_orders):
            sku = skus[(u.id + k) % len(skus)]
            pr = prods[sku]
            n_order += 1
            o = Order(number=f"R{WORLD_TAG[:1].upper()}{n_order:06d}", user_id=u.id, email=u.email, total_cents=pr.price_cents,
                      status="paid", session_id="raffle-world",
                      created_at=now - timedelta(days=a.age_days * (k + 1) / (a.paid_orders + 1)), extra={"kind": "history"})
            o.items.append(OrderItem(sku=sku, name=pr.name, size=(pr.sizes or [""])[0], qty=1, price_cents=pr.price_cents))
            db.session.add(o)
        if not a.verified:
            _mail_verify_link(redis, a.email)
    db.session.commit()
    return len(users)


@bp.route("/lab/raffle/open", methods=["POST"])
def lab_open():
    body = request.get_json(silent=True) or {}
    cfg = current_app.config["LAB"]
    _purge()
    n = _seed_world(current_app.extensions["lab_redis"], cfg.hash_iters)
    p = Product.query.filter_by(sku=W.SKU).first()
    delay = float(body.get("delay_s", 4.0))
    p.drop_at = utcnow() + timedelta(seconds=delay) if cfg.defense_level < RAFFLE_LEVEL else utcnow() - timedelta(minutes=1)
    ev = RaffleEvent(sku=W.SKU, units=p.stock, state="open", opened_ts=time.time(), extra={})
    db.session.add(ev)
    db.session.commit()
    return jsonify(ok=True, event=ev.id, units=ev.units, accounts=n, mode="raffle" if cfg.defense_level >= RAFFLE_LEVEL else "first_come",
                   opens_in_s=delay if cfg.defense_level < RAFFLE_LEVEL else 0)


# --- the batch decisions ----------------------------------------------------------------------------------

def _view(e):
    """What a check may see of an entry. No ground truth, no session ids; the mutable fields are the decision."""
    return {"id": e.id, "email": e.email, "user_id": e.user_id, "device": e.did, "ip": e.ip, "asn": e.asn, "ja4": e.ja4,
            "ua": e.ua, "t": e.entered_at, "size": e.size, "line1": e.line1, "city": e.city, "postcode": e.postcode,
            "bin6": e.bin6, "card_fp": e.card_fp, "age_days": e.age_days, "created_ts": e.created_ts,
            "paid_orders": e.paid_orders, "verified": e.verified, "status": e.status, "claim": dict(e.claim or {}),
            "weight": e.weight if e.weight and e.weight > 0 else 1.0, "excluded": None, "cluster": e.cluster_id or None,
            "reasons": list(e.reasons or []), "verdict": None}


def _free_units(ev):
    live = RaffleEntry.query.filter(RaffleEntry.event_id == ev.id, RaffleEntry.status.in_(LIVE)).count()
    return max(0, ev.units - live)


def _promote(ev):
    """Fill the free units from the waitlist, best key first. Returns how many were promoted."""
    free = _free_units(ev)
    waiting = RaffleEntry.query.filter_by(event_id=ev.id, status="waitlist").order_by(RaffleEntry.rank).limit(free).all()
    for e in waiting:
        e.status = "won"
    db.session.commit()
    return len(waiting)


def _batch(phase, ev, rows):
    ctx = g.ctx
    views = [_view(e) for e in rows]
    ctx.attrs["raffle"] = {"event": ev.id, "units": ev.units, "round": ev.rounds, "phase": phase}
    ctx.attrs["entries"] = views
    d = gate.run_phase(phase, ctx)
    return views, d


def _tag(e, v):
    e.reasons = list(dict.fromkeys(list(e.reasons or []) + list(v.get("reasons") or [])))
    e.cluster_id = v.get("cluster") or e.cluster_id or ""


@bp.route("/lab/raffle/draw", methods=["POST"])
def lab_draw():
    import random
    ev = _latest()
    if ev is None or ev.state != "open":
        return api_error("not_open", "No open event to draw.", 409)
    rows = RaffleEntry.query.filter_by(event_id=ev.id, status="entered").order_by(RaffleEntry.email, RaffleEntry.id).all()
    views, d = _batch("raffle:draw", ev, rows)
    rng = random.Random(f"{current_app.config['LAB'].lab_seed}:{ev.id}:{ev.rounds}")
    ranked, excluded = [], 0
    for e, v in zip(rows, views):
        _tag(e, v)
        w = float(v.get("weight") or 0)
        if v.get("excluded") or w <= 0:
            e.status = "excluded"
            e.reasons = list(dict.fromkeys(e.reasons + [str(v.get("excluded") or "zero_weight")]))
            e.weight, excluded = 0.0, excluded + 1
            continue
        e.weight, e.key = w, rng.random() ** (1.0 / w)
        ranked.append(e)
    ranked.sort(key=lambda e: -e.key)
    free = _free_units(ev)
    for i, e in enumerate(ranked):
        e.rank = i + 1
        e.status = "won" if i < free else "waitlist"
    ev.state, ev.rounds = "drawn", ev.rounds + 1
    db.session.commit()
    g.ctx.note(entries=len(rows), excluded=excluded, drawn=len(ranked), winners=min(free, len(ranked)),
               clusters=len({v["cluster"] for v in views if v.get("cluster")}))
    return jsonify(ok=True, entries=len(rows), excluded=excluded, winners=min(free, len(ranked)), waitlist=max(0, len(ranked) - free),
                   action=d.action)


@bp.route("/lab/raffle/expire", methods=["POST"])
def lab_expire():
    ev = _latest()
    if ev is None:
        return api_error("no_event", "No event.", 409)
    lapsed = RaffleEntry.query.filter_by(event_id=ev.id, status="won").all()
    for e in lapsed:
        e.status, e.reasons = "expired", (e.reasons or []) + ["claim_window_lapsed"]
    db.session.commit()
    promoted = _promote(ev)
    g.ctx.note(expired=len(lapsed), promoted=promoted)
    return jsonify(ok=True, expired=len(lapsed), promoted=promoted)


@bp.route("/lab/raffle/rescore", methods=["POST"])
def lab_rescore():
    ev = _latest()
    if ev is None or ev.state != "drawn":
        return api_error("not_drawn", "Nothing to re-score before the draw.", 409)
    rows = RaffleEntry.query.filter(RaffleEntry.event_id == ev.id, RaffleEntry.status.in_(("claimed", "held", "waitlist"))
                                    ).order_by(RaffleEntry.email, RaffleEntry.id).all()
    views, d = _batch("raffle:rescore", ev, rows)
    cancelled = released = dropped = 0
    for e, v in zip(rows, views):
        _tag(e, v)
        if e.status == "waitlist":
            if v.get("excluded"):
                e.status, e.reasons, dropped = "excluded", list(dict.fromkeys(e.reasons + [str(v["excluded"])])), dropped + 1
            continue
        order = Order.query.filter_by(number=e.order_number).first() if e.order_number else None
        if v.get("verdict") == "cancel" and order is not None:
            orders.cancel_order(order, v.get("excluded") or "rescored")
            e.status, e.reasons, cancelled = "cancelled", list(dict.fromkeys(e.reasons + [str(v.get("excluded") or "rescored")])), cancelled + 1
        elif v.get("verdict") == "release" and e.status == "held" and order is not None:
            order.status, e.status, released = "paid", "claimed", released + 1
    db.session.commit()
    promoted = _promote(ev)
    g.ctx.note(cancelled=cancelled, released=released, dropped=dropped, promoted=promoted)
    return jsonify(ok=True, cancelled=cancelled, released=released, dropped_from_waitlist=dropped, promoted=promoted, action=d.action)


# --- the report (scoreboard side) -------------------------------------------------------------------------

def _identity(actor):
    """A person is one identity; a crew is one identity, except `crowd`, whose members are people."""
    parts = actor.split(":")
    return actor if parts[0] != "bot" or (len(parts) > 1 and parts[1] == "crowd") else f"bot:{parts[1]}"


@bp.route("/lab/raffle/report")
def lab_report():
    log = current_app.extensions.get("decision_log")
    log and log.flush()
    ev = _latest()
    if ev is None:
        return api_error("no_event", "No event.", 409)
    entries = RaffleEntry.query.filter_by(event_id=ev.id).all()
    actor_of = {}
    sids = list({e.sid for e in entries})
    for i in range(0, len(sids), 400):
        for sid, actor in db.session.query(Decision.sid, Decision.actor).filter(Decision.sid.in_(sids[i:i + 400])).distinct():
            actor_of.setdefault(sid, actor)
    cohorts, detail = {}, []
    for e in entries:
        actor = actor_of.get(e.sid, "you")
        kind, cohort = actor.split(":")[0], (actor.split(":")[1] if ":" in actor else actor)
        row = cohorts.setdefault(cohort, {"kind": kind, "identities": set(), "entries": 0, "excluded": 0, "merged": 0, "won_first": 0,
                                          "claimed": 0, "held": 0, "cancelled": 0, "expired": 0, "weight": 0.0})
        row["identities"].add(_identity(actor))
        row["entries"] += 1
        merged = e.status == "excluded" and any(str(r).startswith("cluster") for r in (e.reasons or []))
        row["merged"] += merged
        row["excluded"] += e.status == "excluded" and not merged
        for st in ("claimed", "held", "cancelled", "expired"):
            row[st] += e.status == st
        row["weight"] += e.weight or 0.0
        detail.append({"email": e.email, "cohort": cohort, "kind": kind, "status": e.status, "reasons": e.reasons or [],
                       "cluster": e.cluster_id, "weight": e.weight})
    # units that ended up paid, by who got them
    paid = {"human": 0, "bot": 0, "other": 0}
    for o in Order.query.filter(Order.session_id.isnot(None), Order.status == "paid").all():
        if any(i.sku == W.SKU for i in o.items):
            k = (o.actor or "you").split(":")[0]
            paid[k if k in paid else "other"] += sum(i.qty for i in o.items if i.sku == W.SKU)
    held = Order.query.filter(Order.session_id.isnot(None), Order.status == "pending").count()
    # who tried for a unit: entered the raffle or posted a first-come buy
    idents = {"human": set(), "bot": set()}
    for actor, in db.session.query(Decision.actor).filter(Decision.method == "POST", Decision.path.in_(
            ["/api/buy", f"/api/raffle/{W.SKU}/enter"])).distinct():
        k = (actor or "you").split(":")[0]
        if k in idents:
            idents[k].add(_identity(actor))
    n_h, n_b = len(idents["human"]), len(idents["bot"])
    total_idents = max(1, n_h + n_b)
    fair_rate = min(1.0, ev.units / total_idents)
    fan_rate = (paid["human"] / n_h) if n_h else 0.0
    for row in cohorts.values():
        row["identities"] = len(row["identities"])
        row["weight"] = round(row["weight"], 2)
    metrics = {"units": ev.units, "fan_units": paid["human"], "bot_units": paid["bot"], "held_orders": held,
               "fan_share": round(paid["human"] / ev.units, 3) if ev.units else 0.0,
               "bot_share": round(paid["bot"] / ev.units, 3) if ev.units else 0.0,
               "entries": len(entries), "identities": n_h + n_b, "fan_identities": n_h,
               "entries_per_identity": round(len(entries) / total_idents, 2) if entries else None,
               "fan_odds_vs_fair": round(fan_rate / fair_rate, 3) if fair_rate else None}
    return jsonify(event={"id": ev.id, "state": ev.state, "rounds": ev.rounds, "units": ev.units}, metrics=metrics, cohorts=cohorts,
                   entries=detail if request.args.get("detail") else None)


# --- wiring -----------------------------------------------------------------------------------------------

def init(app):
    with app.app_context():
        db.create_all()
    app.register_blueprint(bp)
    for path in ("/lab/raffle/draw", "/lab/raffle/expire", "/lab/raffle/rescore"):
        hooks.ungate(path, session=True)                       # a Ctx and a log row, not the ladder
    hooks.enricher(_drop_facts)
    hooks.on_action("raffle_claim", _hold_after_claim)
    hooks.on_action("register", _after_register)
    hooks.challenges.register("otp_session", issue=lambda ctx: otp_issue(ctx), verify=lambda ctx, a: otp_verify(ctx, a),
                              clearance_ttl=OTP_TTL_S, uses=1, reauth=True)
    hooks.on_reset(_reset_hook)
    app.before_request(_close_first_come)                      # registered after the gate's, so it runs after the ladder
