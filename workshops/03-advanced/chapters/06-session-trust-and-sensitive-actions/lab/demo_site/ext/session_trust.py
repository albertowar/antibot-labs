"""
W3 Ch6 ext: the moments a session-trust defense needs that the starter store does not give it.

Nothing here decides. The decisions live in defenses/*.py (sudo_reauth, session_trust,
stepup_channels, change_hold; wired in defenses/ladder.py); this module builds what they decide on
and carries their answer out.

  1. What the session carries. An enricher reads `ctx.auth` (how the session proved who it is, contract
     1.8) and the stamps this module writes at the login (`st_*` in the session hash) and puts the raw
     numbers in `ctx.attrs["st"]`: the trust the Chapter 5 login granted, how old and how idle the session
     is on the LAB CLOCK, whether the network or browser drifted since, and which step-up factors were
     solved how long ago. The enricher computes no trust; defenses/session_trust.py does.

  2. The login stamps. An `on_action("login")` handler (and a wrapper around Chapter 5's `otp`) writes
     the starting trust from the Chapter 5 band: low band on a known device and network, low band
     carried by the remembered-device cookie alone, medium band plus the emailed code, or a cold start.

  3. Five challenge types, all registered `reauth=True` and none of which ever writes `uid`:
     `sudo` (the password again), `otp_session` (a code to the on-file email), `sms_otp` (a code to the
     on-file phone, a fictional 555-01xx number delivered to the lab mailbox), `device_confirm` (approve
     on an enrolled phone, with number matching, in an inbox at /lab/devices/<uid>) and `kba` (questions
     about the store's own data). Chapter 5's `otp` cannot be reused after login: it writes `uid`.

  4. The lab clock. `POST /lab/clock {"advance_s": N}` is how a tool waits. One lab second stands for
     policy.LAB_CLOCK_DIVISOR real seconds. Trust decay and the cooling-off both run on it, so a round
     that lasts minutes can cover a day.

  5. Holds. A check that sets `ctx.attrs["hold"]` parks an account change (contract 1.8), an order or a
     gift-card redemption. This module records the hold on the lab clock, fans the notice out to the
     channels the check asked for (`ctx.attrs["notify_channels"]`), and `tick()` releases what is due.

  6. The world. `tick()` first lets the owner of an account notice a notice (WORLD SIMULATION: it reads
     ground truth to know who started the hold, because the owner knows whether they did; no defense
     calls it) and cancel, then releases the holds that are due. Whether an owner notices depends on the
     channel (session_world.OWNER_SEES, a lab assumption). An attacker who holds the webmail can purge
     the old inbox (POST /lab/mailbox/<email>/purge); it cannot reach a phone or an enrolled device.

  7. Restricted mode's masked account page: `ctx.attrs["mask"]` (set by a check) masks /api/account
     and /api/orders on the way out.
"""

import hmac
import json
import re
import secrets
import threading
import time
from datetime import timedelta

from flask import Blueprint, current_app, g, jsonify, request

from defenses import policy
from demo_site import account as acct
from demo_site import gate, hooks
from demo_site.models import AccountChange, Address, Decision, GiftCard, Order, OrderItem, User, db, utcnow
from demo_site.orders import cancel_order
from demo_site.seed import check_password, username

from . import rba, rba_world as W, session_world as SW

CLOCK_KEY = "lab:st:clock"
DEVICES_KEY = "lab:st:devices"          # set of user ids with an enrolled device
HOLDS_KEY = "lab:st:holds"
LOCK = threading.RLock()
OTP_TTL_S = 300
TRIES = 3

bp = Blueprint("st", __name__)


# --- 4. the lab clock -------------------------------------------------------------------------

def lab_now(redis):
    return time.time() + float(redis.get(CLOCK_KEY) or 0)


# --- 1. what the session carries --------------------------------------------------------------

def stamp_trust(ctx, kind):
    """Write the trust the login granted, on the lab clock, and reset everything earned since."""
    now = lab_now(ctx.redis)
    s = ctx.session
    for k in list(s.all()):
        if k.startswith("st_f_"):
            s.delete(k)
    s.set("st_base", str(policy.LOGIN_TRUST[kind]))
    s.set("st_kind", kind)
    s.set("st_login_at", f"{now}")
    s.set("st_seen", f"{now}")
    s.set("st_asn", str(ctx.edge.asn))
    s.set("st_ua", rba.features(ctx)["ua"])


def state(ctx):
    """ctx.attrs["st"]: the raw inputs of session trust (None for an anonymous session)."""
    if ctx.user is None:
        return None
    r, s = ctx.redis, ctx.session.all()
    now = lab_now(r)
    known = ctx.auth["at"] is not None and "st_base" in s          # an unstamped session: nobody knows how it began
    seen = float(s.get("st_seen", now))
    ctx.session.set("st_seen", f"{now}")
    ua = rba.features(ctx)["ua"]
    return {
        "uid": ctx.user.id,
        "login_kind": s.get("st_kind", "unknown"),
        "login_base": float(s.get("st_base", 0)) if known else 0.0,
        "login_age_s": max(0.0, now - float(s.get("st_login_at", now))),
        "idle_s": max(0.0, now - seen),
        "drift": {"asn": bool(s.get("st_asn")) and s["st_asn"] != str(ctx.edge.asn),
                  "ua": bool(s.get("st_ua")) and s["st_ua"] != ua},
        "factors": {k[5:]: max(0.0, now - float(v)) for k, v in s.items() if k.startswith("st_f_")},
        "methods": list(ctx.auth["methods"]),
        "channels": {"phone": bool((ctx.user.extra or {}).get("phone")),
                     "device": bool(r.sismember(DEVICES_KEY, str(ctx.user.id)))},
    }


def _enrich(ctx):
    ctx.attrs["st"] = state(ctx)


# --- 2. the login stamps ----------------------------------------------------------------------

def after_login(ctx, result, response):
    """After Chapter 5's handler: a login that opened the session without a prompt starts at the
    trust its band earns. A login that was stepped up starts when the code is solved (otp wrapper)."""
    if ctx is None or not result.get("ok") or not ctx.session.get("uid"):
        return None
    rb = ctx.attrs.get("rba")
    if not rb:
        return None
    hist, f = rb["hist"], rb["features"]
    if hist.get("_n", 0) < policy.RBA_COLD_START:
        kind = "cold_start"
    elif hist.get(f"dev:{f['dev']}", 0) > 0 and hist.get(f"asn:{f['asn']}", 0) > 0:
        kind = "familiar"
    else:
        kind = "device_only"
    stamp_trust(ctx, kind)
    return None


def after_register(ctx, result, response):
    if ctx is not None and ctx.session.get("uid"):
        stamp_trust(ctx, "cold_start")
    return None


def _wrap_otp():
    spec = hooks.challenges.get("otp")
    orig = spec["verify"]

    def verify(ctx, answer):
        uid = ctx.session.get("pending_uid")
        n = rba.history(ctx.redis, int(uid)).get("_n", 0) if uid else 0
        out = orig(ctx, answer)
        if (out[0] if isinstance(out, tuple) else out):
            gate.stamp_login(ctx)                                # Chapter 5's otp writes uid itself: stamp it here
            gate.stamp_step_up(ctx, "otp")
            stamp_trust(ctx, "cold_start" if n < policy.RBA_COLD_START else "emailed_code")
        return out
    hooks.challenges.register("otp", issue=spec["issue"], verify=verify, render=spec["render"],
                              clearance_ttl=spec["clearance_ttl"], uses=spec["uses"])


# --- 3. the challenge types -------------------------------------------------------------------

def _solved(ctx, ftype):
    """A step-up was solved: remember when, and re-baseline the drift (the person at the keyboard just
    proved themselves from this network and this browser). Never touches uid."""
    ctx.session.set(f"st_f_{ftype}", f"{lab_now(ctx.redis)}")
    ctx.session.set("st_asn", str(ctx.edge.asn))
    ctx.session.set("st_ua", rba.features(ctx)["ua"])


def _tries(ctx, name, limit):
    key = f"lab:st:tries:{ctx.session.sid}:{name}"
    n = ctx.redis.incr(key)
    ctx.redis.expire(key, OTP_TTL_S)
    return n <= limit


def _mail(redis, box, **msg):
    redis.rpush(f"lab:mailbox:{box.lower()}", json.dumps({**msg, "ts": utcnow().isoformat()}))


def _mask_email(email):
    name, _, host = email.partition("@")
    return f"{name[:1]}***@{host}"


def sudo_issue(ctx):
    return {"factor": "password", "message": "Enter your password again to continue."}


def sudo_verify(ctx, answer):
    if ctx.user is None:
        return False, "sign in first"
    if not _tries(ctx, "sudo", 5):
        return False, "too many wrong passwords"
    if not check_password(ctx.user, str((answer or {}).get("password", "")), current_app.config["LAB"].hash_iters):
        return False, "wrong password"
    _solved(ctx, "sudo")
    return True


def _code_issue(ctx, kind):
    if ctx.user is None:
        return {"channel": None, "message": "sign in first"}
    code = f"{secrets.randbelow(10 ** 6):06d}"
    ctx.redis.set(f"lab:st:code:{ctx.session.sid}:{kind}", json.dumps({"code": code, "tries": 0}), ex=OTP_TTL_S)
    return code


def otp_session_issue(ctx):
    code = _code_issue(ctx, "otp_session")
    if not isinstance(code, str):
        return code
    _mail(ctx.redis, ctx.user.email, subject="Confirm it is you", code=code, kind="otp_session")
    return {"channel": "email", "to": _mask_email(ctx.user.email), "length": 6, "expires_s": OTP_TTL_S}


def sms_issue(ctx):
    phone = (ctx.user.extra or {}).get("phone") if ctx.user else None
    if not phone:
        return {"channel": None, "message": "no phone number on file"}
    code = _code_issue(ctx, "sms_otp")
    _mail(ctx.redis, SW.sms_box(ctx.user.email), to=phone, text=f"Kestrel: your code is {code}", code=code)
    return {"channel": "sms", "to": f"{phone[:-2]}**", "length": 6, "expires_s": OTP_TTL_S}


def _code_verify(ctx, kind, answer):
    key = f"lab:st:code:{ctx.session.sid}:{kind}"
    raw = ctx.redis.get(key)
    if not raw:
        return False, "no code is pending, or it expired"
    st = json.loads(raw)
    st["tries"] += 1
    if st["tries"] > TRIES:
        ctx.redis.delete(key)
        return False, "too many wrong codes: ask for a new one"
    if not hmac.compare_digest(str((answer or {}).get("code", "")), st["code"]):
        ctx.redis.set(key, json.dumps(st), ex=OTP_TTL_S)
        return False, "wrong code"
    ctx.redis.delete(key)
    _solved(ctx, kind)
    return True


def device_issue(ctx):
    if ctx.user is None or not ctx.redis.sismember(DEVICES_KEY, str(ctx.user.id)):
        return {"channel": None, "message": "no enrolled device"}
    n = ctx.redis.incr(f"lab:st:pushes:{ctx.session.sid}")           # ASVS 6.6.4: rate-limit push prompts
    ctx.redis.expire(f"lab:st:pushes:{ctx.session.sid}", 600)
    if n > 3:
        return {"channel": "device", "message": "too many requests: wait before asking again"}
    rid, number = secrets.token_hex(4), f"{secrets.randbelow(100):02d}"
    ctx.redis.hset(f"lab:st:req:{rid}", mapping={"uid": ctx.user.id, "number": number, "status": "pending",
                                                 "sid": ctx.session.sid})
    ctx.redis.expire(f"lab:st:req:{rid}", OTP_TTL_S)
    ctx.redis.rpush(f"lab:st:dev:{ctx.user.id}", json.dumps({"id": rid, "kind": "approve", "ts": utcnow().isoformat(),
                                                             "text": "Someone is asking to confirm a sensitive action. "
                                                                     "Enter the number shown on the screen to approve."}))
    return {"channel": "device", "request_id": rid, "number": number,
            "message": "Open the Kestrel app on your phone and enter this number to approve."}


def device_verify(ctx, answer):
    rid = str((answer or {}).get("request_id", ""))
    req = ctx.redis.hgetall(f"lab:st:req:{rid}")
    if not req or req.get("sid") != ctx.session.sid or ctx.user is None or str(ctx.user.id) != req.get("uid"):
        return False, "no such request for this session"
    if req.get("status") != "approved":
        return False, "not approved yet"
    ctx.redis.delete(f"lab:st:req:{rid}")
    _solved(ctx, "device_confirm")
    return True


QUESTIONS = {
    "postcode": "What is the postcode of the address on file?",
    "card_last4": "What are the last four digits of the saved card?",
    "last_order_total": "What was the total of your most recent order, in dollars (like 89.00)?",
    "member_month": "In which month (1-12) did you create your account?",
}


def kba_truth(user):
    """The store's own answers: exactly what a session that can read the account page can read."""
    last = Order.query.filter_by(user_id=user.id, status="paid").order_by(Order.created_at.desc(), Order.id.desc()).first()
    return {"postcode": (user.addresses[0].postcode if user.addresses else ""),
            "card_last4": user.saved_card_last4 or "",
            "last_order_total": f"{last.total_cents / 100:.2f}" if last else "",
            "member_month": str(user.created_at.month) if user.created_at else ""}


def kba_issue(ctx):
    if ctx.user is None:
        return {"questions": []}
    truth = kba_truth(ctx.user)
    ids = [q for q in QUESTIONS if truth[q]][:3]
    ctx.redis.set(f"lab:st:kba:{ctx.session.sid}", json.dumps({"qs": ids, "tries": 0}), ex=OTP_TTL_S)
    return {"questions": [{"id": q, "text": QUESTIONS[q]} for q in ids]}


def kba_verify(ctx, answer):
    raw = ctx.redis.get(f"lab:st:kba:{ctx.session.sid}")
    if not raw or ctx.user is None:
        return False, "no questions are pending"
    st = json.loads(raw)
    st["tries"] += 1
    if st["tries"] > TRIES:
        return False, "too many tries"
    ctx.redis.set(f"lab:st:kba:{ctx.session.sid}", json.dumps(st), ex=OTP_TTL_S)
    truth, given = kba_truth(ctx.user), (answer or {}).get("answers") or {}
    norm = lambda v: re.sub(r"\s+", "", str(v)).lower()                      # noqa: E731
    if all(norm(given.get(q, "")) == norm(truth[q]) for q in st["qs"]):
        _solved(ctx, "kba")
        return True
    return False, "those answers did not match"


# --- 5. holds, notices -------------------------------------------------------------------------

def _holds(redis):
    return [json.loads(x) for x in redis.lrange(HOLDS_KEY, 0, -1)]


def _save_holds(redis, recs):
    with redis.pipeline() as p:
        p.delete(HOLDS_KEY)
        for r in recs:
            p.rpush(HOLDS_KEY, json.dumps(r))
        p.execute()


def record_hold(ctx, kind, ref, user, hours, channels, email):
    """Park a hold on the lab clock. Once per (kind, ref)."""
    with LOCK:
        recs = _holds(ctx.redis)
        if any(r["kind"] == kind and r["ref"] == ref for r in recs):
            return next(r for r in recs if r["kind"] == kind and r["ref"] == ref)
        now = lab_now(ctx.redis)
        rec = {"id": len(recs) + 1, "kind": kind, "ref": ref, "uid": user.id, "sid": ctx.session.sid, "hours": hours,
               "created": now, "release_at": now + hours * 3600 / policy.LAB_CLOCK_DIVISOR, "channels": list(channels),
               "email": email, "token": secrets.token_urlsafe(12), "reviewed": False, "done": None}
        recs.append(rec)
        _save_holds(ctx.redis, recs)
        return rec


def fan_out(redis, user, channels, subject, text, cancel_url, hold=None, email=None):
    """The notice, on every channel the check asked for. The default account mail (the old address
    with a cancel link) is the store's own; this adds the channels an attacker who owns the inbox cannot purge."""
    msg = {"subject": subject, "text": text, "cancel_url": cancel_url, "hold": hold}
    if "email" in channels and email:
        _mail(redis, email, **msg)
    if "sms" in channels and (user.extra or {}).get("phone"):
        _mail(redis, SW.sms_box(user.email), to=user.extra["phone"], **msg)
    if "device" in channels and redis.sismember(DEVICES_KEY, str(user.id)):
        redis.rpush(f"lab:st:dev:{user.id}", json.dumps({"id": secrets.token_hex(4), "kind": "notice", "ts": utcnow().isoformat(), **msg}))
    if "banner" in channels:
        redis.rpush(f"lab:st:banner:{user.id}", json.dumps({**msg, "ts": utcnow().isoformat()}))


def _hold_hours(ctx):
    hold = ctx.attrs.get("hold")
    return float(hold["hours"]) if isinstance(hold, dict) and float(hold.get("hours") or 0) > 0 else 0.0


def on_change(ctx, result, response):
    change, user = result["change"], result["user"]
    if ctx is None:
        return None
    channels = ctx.attrs.get("notify_channels") or ()
    first = ctx.redis.setnx(f"lab:st:fan:change:{change.id}", "1")
    email = (change.extra or {}).get("notice_email") or user.email
    if first:
        ctx.redis.set(f"lab:st:fan_email:{change.id}", email)
        if channels:
            fan_out(ctx.redis, user, channels, "Your account was changed" if change.status != "pending" else "A change to your account is on hold",
                    f"A {change.kind} change was requested on your account. If it was not you, cancel it.",
                    f"/account/changes/{change.id}/cancel?token={change.token}", hold=f"change:{change.id}",
                    email=email if "email" in channels else None)
    if change.status == "pending":
        hours = float(((change.extra or {}).get("hold") or {}).get("hours") or 0) or _hold_hours(ctx)
        rec = record_hold(ctx, "change", change.id, user, hours, ("email",) + tuple(c for c in channels if c != "email"),
                          ctx.redis.get(f"lab:st:fan_email:{change.id}") or user.email)
        g.outcome = "held"
        ctx.note(hold_h=hours, hold_id=rec["id"])
    return None


def on_checkout(ctx, result, response):
    order = result["order"]
    hours = _hold_hours(ctx) if ctx is not None else 0
    if ctx is None or ctx.user is None or not hours:
        return None
    order.status = "pending"
    order.extra = dict(order.extra or {}, hold={"hours": hours, "reason": ctx.attrs["hold"].get("reason", "")})
    db.session.commit()
    channels = ctx.attrs.get("notify_channels") or ()
    rec = record_hold(ctx, "order", order.number, ctx.user, hours, ("email",) + tuple(c for c in channels if c != "email"), ctx.user.email)
    fan_out(ctx.redis, ctx.user, ("email",) + tuple(channels), "An order is on hold",
            f"Order {order.number} ships to an address that is not on your account. If it was not you, cancel it.",
            f"/account/holds/{rec['id']}/cancel?token={rec['token']}", hold=f"hold:{rec['id']}", email=ctx.user.email)
    g.outcome = "held"
    ctx.note(hold_h=hours, hold_id=rec["id"])
    return jsonify(ok=True, status="pending", hold_h=hours, order=order.to_dict()), 202


def on_gift(ctx, result, response):
    user, card = result["user"], result["gift_card"]
    hours = _hold_hours(ctx) if ctx is not None else 0
    if ctx is None or not hours:
        return None
    user.loyalty_points = max(0, (user.loyalty_points or 0) - card.balance_cents // 100)    # un-apply, keep it parked
    card.redeemed_by = None
    db.session.commit()
    channels = ctx.attrs.get("notify_channels") or ()
    rec = record_hold(ctx, "gift", card.id, user, hours, ("email",) + tuple(c for c in channels if c != "email"), user.email)
    fan_out(ctx.redis, user, ("email",) + tuple(channels), "A gift card redemption is on hold",
            "A gift card redemption was requested on your account. If it was not you, cancel it.",
            f"/account/holds/{rec['id']}/cancel?token={rec['token']}", hold=f"hold:{rec['id']}", email=user.email)
    g.outcome = "held"
    ctx.note(hold_h=hours, hold_id=rec["id"])
    return jsonify(ok=True, status="pending", hold_h=hours), 202


# --- 6. the world: owners notice, holds come due -----------------------------------------------

def _initiator_is_bot(app, sid):
    log = app.extensions.get("decision_log")
    if log is not None:
        log.flush()
    row = Decision.query.filter_by(sid=sid).order_by(Decision.id).first()
    return bool(row and (row.actor or "").startswith("bot:"))


def _present(redis, rec):
    """Channels on which the notice for this hold is still sitting where the owner would see it."""
    out = []
    key = f"change:{rec['ref']}" if rec["kind"] == "change" else f"hold:{rec['id']}"
    email = rec["email"].lower()
    if any(m.get("hold") == key or (rec["kind"] == "change" and m.get("change_id") == rec["ref"])
           for m in (json.loads(x) for x in redis.lrange(f"lab:mailbox:{email}", 0, -1))):
        out.append("email")
    user = db.session.get(User, rec["uid"])
    for ch, listkey in (("sms", f"lab:mailbox:sms:{(user.email if user else '').lower()}"),
                        ("device", f"lab:st:dev:{rec['uid']}"), ("banner", f"lab:st:banner:{rec['uid']}")):
        if any(json.loads(x).get("hold") == key for x in redis.lrange(listkey, 0, -1)):
            out.append(ch)
    return out


def _cancel(rec):
    if rec["kind"] == "change":
        ch = db.session.get(AccountChange, rec["ref"])
        if ch is not None:
            acct.cancel_change(ch, "owner_notice")
    elif rec["kind"] == "order":
        o = Order.query.filter_by(number=rec["ref"]).first()
        if o is not None and o.status == "pending":
            cancel_order(o, "owner_notice")


def _release(rec):
    if rec["kind"] == "change":
        ch = db.session.get(AccountChange, rec["ref"])
        if ch is not None and ch.status == "pending":
            acct.release_change(ch)
    elif rec["kind"] == "order":
        o = Order.query.filter_by(number=rec["ref"]).first()
        if o is not None and o.status == "pending":
            o.status = "paid"
            db.session.commit()
    elif rec["kind"] == "gift":
        card, user = db.session.get(GiftCard, rec["ref"]), db.session.get(User, rec["uid"])
        if card is not None and user is not None and card.redeemed_by is None:
            card.redeemed_by = user.id
            user.loyalty_points = (user.loyalty_points or 0) + card.balance_cents // 100
            db.session.commit()


def tick(app):
    """Let the world move: owners react to what they were told, then due holds are released."""
    redis = app.extensions["lab_redis"]
    with LOCK:
        recs, now, out = _holds(redis), lab_now(redis), {"cancelled": 0, "released": 0}
        for rec in recs:
            if rec["done"] or rec["reviewed"]:
                continue
            rec["reviewed"] = True
            if not _initiator_is_bot(app, rec["sid"]):
                continue                                           # the owner knows they asked for this one
            if any(SW.owner_sees(rec["uid"] - 1, ch, rec["id"]) for ch in _present(redis, rec)):
                _cancel(rec)
                rec["done"] = "cancelled"
                out["cancelled"] += 1
        for rec in recs:
            if not rec["done"] and rec["release_at"] <= now:
                _release(rec)
                rec["done"] = "released"
                out["released"] += 1
        _save_holds(redis, recs)
    return out


# --- 7. restricted mode: the masked account page ----------------------------------------------

def _mask(info):
    ctx = info.ctx
    if ctx is None or not ctx.attrs.get("mask") or info.status != 200 or info.path not in ("/api/account", "/api/orders"):
        return
    data = json.loads(info.response.get_data(as_text=True))
    if info.path == "/api/account":
        data = {"email": _mask_email(data.get("email", "")), "name": (data.get("name") or "")[:1] + "***",
                "saved_card": "•••• ••••" if data.get("saved_card") else None, "created_at": None,
                "loyalty_points": data.get("loyalty_points"), "restricted": True,
                "addresses": [{"id": a["id"], "line1": "•••", "city": a["city"], "postcode": "•••", "country": a["country"]}
                              for a in data.get("addresses", [])]}
    else:
        data = {"items": [{"number": o["number"], "status": o["status"], "total": None, "total_cents": None, "items": []}
                          for o in data.get("items", [])], "total": data.get("total"), "restricted": True}
    info.response.set_data(json.dumps(data))


# --- the world's data: seed ----------------------------------------------------------------------

def seed(app):
    """Configure the accounts the chapter manages and the stolen sessions. Idempotent; runs at start
    and after every POST /lab/reset (which empties Redis)."""
    redis = app.extensions["lab_redis"]
    redis.delete(CLOCK_KEY)
    now = time.time()
    with app.app_context():
        users = {u.email: u for u in User.query.filter(User.email.in_([username(i) for i in SW.managed()])).all()}
        for i in SW.managed():
            u = users.get(username(i))
            if u is None:
                continue
            ch = SW.channels(i)
            extra = dict(u.extra or {})
            if ch["phone"]:
                extra["phone"] = SW.phone_of(i)
            else:
                extra.pop("phone", None)
            if not u.saved_card_last4:
                digits = f"4111{i:08d}{1000 + (i * 37) % 9000}"
                facts = acct.card_facts(digits)
                u.saved_card_brand, u.saved_card_last4 = facts["brand"], facts["last4"]
                extra.update(card_bin=facts["bin6"], card_fp=facts["fingerprint"])
            u.extra = extra
            if not u.addresses:
                db.session.add(Address(user_id=u.id, line1=f"{10 + i % 90} Alder Street", city="Portland",
                                       postcode=f"97{i % 1000:03d}", country="US"))
            if not Order.query.filter_by(user_id=u.id).first():
                o = Order(number=f"H{i:06d}", user_id=u.id, email=u.email, total_cents=4500 + (i % 7) * 1500,
                          created_at=utcnow() - timedelta(days=21 + i % 30))
                o.items.append(OrderItem(sku="p001", name="Trail Sneaker", size="M", qty=1, price_cents=o.total_cents))
                db.session.add(o)
            if ch["device"]:
                redis.sadd(DEVICES_KEY, str(u.id))
        db.session.commit()
        for k, i in enumerate(SW.victims("session")):                  # the stolen sessions: live, six lab hours old
            u = users.get(username(i))
            a = SW.account(i)
            sid = SW.session_sid(i)
            home_asn = W.pool_info(a.home_pool)[0]
            t = now - 120
            redis.hset(f"lab:s:{sid}", mapping={
                "uid": u.id, "csrf": secrets.token_urlsafe(8), "created_at": f"{t}", "created_ip": "192.0.2.1",
                "created_asn": home_asn, "auth_at": f"{t}", "auth_methods": json.dumps(["password"]),
                "seen_at": f"{now - 3}", "st_base": str(policy.LOGIN_TRUST["familiar"]), "st_kind": "familiar",
                "st_login_at": f"{t}", "st_seen": f"{now - 3}", "st_asn": str(home_asn),
                "st_ua": W.ua_key(a.devices[0].browser)})
            redis.expire(f"lab:s:{sid}", 7 * 24 * 3600)


# --- lab routes ------------------------------------------------------------------------------------

@bp.route("/lab/clock", methods=["GET", "POST"])
def clock():
    """The lab clock: POST {"advance_s": N} moves it N lab seconds and lets the world run (tick)."""
    redis = current_app.extensions["lab_redis"]
    if request.method == "POST":
        redis.incrbyfloat(CLOCK_KEY, float((request.get_json(silent=True) or {}).get("advance_s", 0)))
        out = tick(current_app)
    else:
        out = {}
    return jsonify(ok=True, offset_s=float(redis.get(CLOCK_KEY) or 0), divisor=policy.LAB_CLOCK_DIVISOR, **out)


@bp.route("/lab/st/tick", methods=["POST"])
def tick_route():
    return jsonify(ok=True, **tick(current_app))


@bp.route("/lab/devices/<int:uid>")
def device_inbox(uid):
    """What an enrolled phone shows: approval requests (without the number: it is on the web screen) and notices."""
    redis = current_app.extensions["lab_redis"]
    items = []
    for x in redis.lrange(f"lab:st:dev:{uid}", 0, -1):
        m = json.loads(x)
        if m["kind"] == "approve":
            m["status"] = redis.hget(f"lab:st:req:{m['id']}", "status") or "expired"
        items.append(m)
    return jsonify(uid=uid, items=items)


@bp.route("/lab/devices/<int:uid>/<rid>/approve", methods=["POST"])
def device_approve(uid, rid):
    """Tap Approve on the phone and type the number shown on the web screen (number matching)."""
    redis = current_app.extensions["lab_redis"]
    req = redis.hgetall(f"lab:st:req:{rid}")
    if not req or req.get("uid") != str(uid):
        return jsonify(error={"code": "not_found", "message": "No such request."}), 404
    if str((request.get_json(silent=True) or {}).get("number", "")) != req["number"]:
        return jsonify(error={"code": "wrong_number", "message": "That is not the number on the screen."}), 403
    redis.hset(f"lab:st:req:{rid}", "status", "approved")
    return jsonify(ok=True)


@bp.route("/lab/mailbox/<path:email>/purge", methods=["POST"])
def mailbox_purge(email):
    """Delete mail from an inbox: what a webmail session can do to the old address's notices."""
    current_app.extensions["lab_redis"].delete(f"lab:mailbox:{email.lower()}")
    return jsonify(ok=True)


@bp.route("/lab/st/channels/<email>")
def channels(email):
    """What the owner of a managed account knows about themselves: their phone, their device, their gift card."""
    u = User.query.filter_by(email=email.lower()).first()
    if u is None:
        return jsonify(error={"code": "not_found"}), 404
    i = u.id - 1
    card = db.session.get(GiftCard, SW.gift_code_id(i)) if i in SW.cohort() else None
    truth = kba_truth(u)
    return jsonify(index=i, uid=u.id, last_order_total=truth["last_order_total"], member_month=truth["member_month"], phone=(u.extra or {}).get("phone"),
                   device=bool(current_app.extensions["lab_redis"].sismember(DEVICES_KEY, str(u.id))),
                   gift_code=card.code if card else None, saved_card_last4=u.saved_card_last4,
                   postcode=(u.addresses[0].postcode if u.addresses else None))


@bp.route("/lab/st/loot")
def loot():
    """The crews' loot: gift-card codes cracked earlier (W1 Ch8's attack), not yet redeemed."""
    rows = GiftCard.query.filter(GiftCard.id.in_(list(SW.LOOT_IDS)), GiftCard.redeemed_by.is_(None)).limit(
        request.args.get("n", 60, type=int)).all()
    return jsonify(items=[{"code": c.code, "balance_cents": c.balance_cents} for c in rows])


@bp.route("/lab/st/ledger")
def ledger():
    """What happened to the accounts in ?index=240,241,...: persisted, shipped and redeemed dollars, still held."""
    out = {"accounts": {}, "persisted": 0, "shipped_cents": 0, "gift_cents": 0, "held": 0, "compromised": 0}
    for i in [int(x) for x in request.args.get("index", "").split(",") if x]:
        uid = i + 1
        persisted = AccountChange.query.filter(AccountChange.user_id == uid, AccountChange.status == "applied",
                                               AccountChange.kind.in_(["email", "password"])).count()
        orders = Order.query.filter(Order.user_id == uid, Order.session_id.isnot(None)).all()
        shipped = sum(o.total_cents for o in orders if o.status == "paid" and ((o.extra or {}).get("ship_to") or {}).get("new"))
        gifts = sum(c.balance_cents for c in GiftCard.query.filter(GiftCard.redeemed_by == uid, GiftCard.id.in_(list(SW.LOOT_IDS))))
        held = (AccountChange.query.filter_by(user_id=uid, status="pending").count()
                + sum(1 for o in orders if o.status == "pending"))
        out["accounts"][i] = {"persisted": persisted, "shipped_cents": shipped, "gift_cents": gifts, "held": held}
        out["persisted"] += int(persisted > 0)
        out["shipped_cents"] += shipped
        out["gift_cents"] += gifts
        out["held"] += held
        out["compromised"] += int(persisted > 0 or shipped > 0 or gifts > 0)
    return jsonify(out)


@bp.route("/account/holds/<int:hid>/cancel")
def hold_cancel(hid):
    """The cancel link in the notice about a held order or gift-card redemption. No login: it is the owner's link."""
    redis = current_app.extensions["lab_redis"]
    with LOCK:
        recs = _holds(redis)
        rec = next((r for r in recs if r["id"] == hid), None)
        if rec is None or not hmac.compare_digest(rec["token"], request.args.get("token", "")):
            return jsonify(error={"code": "unknown_link", "message": "That link is not valid."}), 404
        if rec["done"]:
            return jsonify(status=rec["done"], message="Too late to cancel."), 409
        _cancel(rec)
        rec["done"] = "cancelled"
        _save_holds(redis, recs)
    return jsonify(status="cancelled", message="Cancelled. Nothing was changed.")


def init(app):
    _wrap_otp()
    hooks.enricher(_enrich)
    hooks.on_action("login", after_login)
    hooks.on_action("register", after_register)
    for name in ("change_email", "change_password", "address_add", "card_add"):
        hooks.on_action(name, on_change)
    hooks.on_action("checkout", on_checkout)
    hooks.on_action("gift_card_redeem", on_gift)
    hooks.on_response(_mask)
    reg = hooks.challenges.register
    reg("sudo", issue=sudo_issue, verify=sudo_verify, reauth=True, clearance_ttl=60)
    reg("otp_session", issue=otp_session_issue, verify=lambda ctx, a: _code_verify(ctx, "otp_session", a), reauth=True, clearance_ttl=60)
    reg("sms_otp", issue=sms_issue, verify=lambda ctx, a: _code_verify(ctx, "sms_otp", a), reauth=True, clearance_ttl=60)
    reg("device_confirm", issue=device_issue, verify=device_verify, reauth=True, clearance_ttl=60)
    reg("kba", issue=kba_issue, verify=kba_verify, reauth=True, clearance_ttl=60)
    hooks.on_reset(seed)
    app.register_blueprint(bp)
    seed(app)
