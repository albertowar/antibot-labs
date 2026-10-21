"""
Account-change helpers (contract 1.8): the write side of /account/{email,password,address,card},
plus the card and address facts checkout shares with them.

Every change is an `AccountChange` row. A route validates, runs the `change_email`,
`change_password`, `address_add` or `card_add` gate, writes the row and calls `apply_change`. A check
that sets `ctx.attrs["hold"] = {"hours": h, "reason": r}` turns the apply into a hold: the row stays
`pending` until `release_change` (a cooling-off clock, a reviewer, POST /lab/account/changes/<id>/release)
or `cancel_change` (the owner's link, a reviewer) ends it. Nothing here decides; it only moves rows
between statuses, the way orders.py moves orders.

Trade-off to teach with it: a hold gives the real owner time to notice the mail to the OLD address,
and every held change is a customer waiting, so a hold is a price the defense chooses to charge.
"""

import hashlib
import json
import re
from datetime import timedelta

from .models import Address, User, db, utcnow

KINDS = ("email", "password", "address", "card")
ACTIONS = {"email": "change_email", "password": "change_password", "address": "address_add", "card": "card_add"}


class ChangeError(Exception):
    """A request the route refuses before the gate runs (bad input) or after it (wrong password)."""

    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


# --- card and address facts --------------------------------------------------------------------

def card_facts(number):
    """Brand, bin6, last4 and fingerprint of a card number, or None if it is not digits.

    The checkout has never validated a card ("any card number is accepted and nothing is charged"),
    so this accepts what it accepts: 4 to 19 digits once spaces and dashes are removed (the lab's
    "4242" counts). The fingerprint is the first 16 hex of SHA-256 of the digits. Unsalted, so
    anyone holding a number can compute it; a real processor keys it, which is what makes a
    fingerprint safe to hand around. Here it is what links "the same card" across accounts."""
    digits = re.sub(r"[\s-]", "", str(number or ""))
    if not (4 <= len(digits) <= 19 and digits.isdigit()):
        return None
    brand = "Visa" if digits[0] == "4" else "Mastercard" if digits[0] in "25" else "Amex" if digits[:2] in ("34", "37") else "Card"
    return {"brand": brand, "bin6": digits[:6], "last4": digits[-4:],
            "fingerprint": hashlib.sha256(digits.encode()).hexdigest()[:16]}


_UNITS = {"apartment": "APT", "apt": "APT", "unit": "UNIT", "suite": "STE", "ste": "STE", "floor": "FL", "fl": "FL",
          "room": "RM", "rm": "RM", "building": "BLDG", "bldg": "BLDG"}


def normalize_address(line1, city, postcode):
    """One comparable string for an address: "12 ELM STREET APT 4, PORTLAND, 97201".

    Deliberately simple: casefold, "#" read as UNIT, punctuation dropped, whitespace collapsed,
    and the secondary-unit words mapped to the USPS Publication 28 abbreviations (APT, UNIT, STE,
    FL, RM, BLDG). It does not touch street suffixes ("Street" vs "St"), directionals, ZIP+4 or
    typos, so two spellings of one door can still differ; a real store buys an address-validation
    service for that and still sees look-alikes."""
    def clean(text, units=False):
        words = re.sub(r"[^\w\s]", " ", str(text or "").casefold().replace("#", " unit ")).split()
        return " ".join(_UNITS.get(w, w.upper()) if units else w.upper() for w in words)
    return ", ".join([clean(line1, units=True), clean(city), clean(postcode)])


def checkout_facts(user, line1="", city="", postcode="", address_id=None, card=""):
    """Where an order ships and which card paid, as the gate and `order.extra` record them.

    ship_to: {"normalized", "new", "address_id"}. An `address_id` must be one of the account's
    saved addresses (ChangeError otherwise); typed fields that normalize to a saved address count
    as that address, so a browser that pre-fills the form is not "new". With neither, the
    checkout behaves as it always did and ship_to is empty. card: {"saved", brand, bin6, last4,
    fingerprint}; a logged-in customer with a saved card and no typed number paid with the saved one."""
    saved = list(user.addresses) if user else []
    ship = {"normalized": "", "new": False, "address_id": None}
    if address_id not in (None, ""):
        row = next((a for a in saved if str(a.id) == str(address_id)), None)
        if row is None:
            raise ChangeError("invalid_address", "That is not one of your saved addresses.")
        ship = {"normalized": normalize_address(row.line1, row.city, row.postcode), "new": False, "address_id": row.id}
    elif line1 or city or postcode:
        norm = normalize_address(line1, city, postcode)
        match = next((a for a in saved if normalize_address(a.line1, a.city, a.postcode) == norm), None)
        ship = {"normalized": norm, "new": match is None, "address_id": match.id if match else None}
    extra = (user.extra or {}) if user else {}
    facts = card_facts(card)
    if facts:
        out = {"saved": bool(user and extra.get("card_fp") == facts["fingerprint"]), **facts}
    elif user and user.saved_card_last4 and not str(card or "").strip():
        out = {"saved": True, "brand": user.saved_card_brand or "", "bin6": extra.get("card_bin", ""),
               "last4": user.saved_card_last4, "fingerprint": extra.get("card_fp", "")}
    else:
        out = {"saved": False, "brand": "", "bin6": "", "last4": "", "fingerprint": ""}
    return ship, out


# --- the four changes --------------------------------------------------------------------------

def prepare_change(kind, fields, user, hash_iters):
    """Validate a request. Returns (payload, extra, facts, proof): the row's payload and extra, the
    kwargs for the gate (a check reads them from ctx.notes) and, when the request carried a
    password, whether it was right (None when it carried none). Raises ChangeError on bad input."""
    from .seed import check_password, set_password
    get = lambda k: str(fields.get(k) or "").strip()      # noqa: E731
    pw = fields.get("current_password") if kind == "password" else fields.get("password")
    proof = None if pw is None or pw == "" else check_password(user, str(pw), hash_iters)
    if kind == "email":
        new = get("new_email").lower()
        if "@" not in new or len(new) > 120:
            raise ChangeError("invalid_email", "Enter a valid email address.")
        if new == user.email:
            raise ChangeError("unchanged", "That is already your email address.")
        if User.query.filter_by(email=new).first():
            raise ChangeError("exists", "That email is already registered.", 409)
        return {"new_email": new}, {}, {"new_email": new}, proof
    if kind == "password":
        new = str(fields.get("new_password") or "")
        if len(new) < 8:
            raise ChangeError("invalid", "Use a password of 8+ characters.")
        if proof is None:
            raise ChangeError("invalid", "Send your current password.")
        probe = User(email=user.email)                    # only to reuse set_password's salting; never saved
        set_password(probe, new, hash_iters)
        cred = {"salt": probe.password_salt.hex(), "hash": probe.password_hash.hex()}
        return {}, {"credential": cred}, {"password_ok": proof}, proof
    if kind == "address":
        line1, city, postcode = get("line1")[:120], get("city")[:80], get("postcode")[:16]
        country = (get("country") or "US")[:2].upper()
        if not (line1 and city and postcode):
            raise ChangeError("invalid", "Give a street address, a city and a postcode.")
        norm = normalize_address(line1, city, postcode)
        known = {normalize_address(a.line1, a.city, a.postcode) for a in user.addresses}
        return ({"line1": line1, "city": city, "postcode": postcode, "country": country, "normalized": norm}, {},
                {"address": norm, "address_new": norm not in known}, proof)
    if kind == "card":
        facts = card_facts(fields.get("card"))
        if facts is None:
            raise ChangeError("invalid_card", "Enter a card number.")
        return (facts, {}, {"card_bin6": facts["bin6"], "card_fp": facts["fingerprint"],
                            "card_new": facts["fingerprint"] != (user.extra or {}).get("card_fp")}, proof)
    raise ChangeError("unknown_kind", "Unknown change.", 404)


def apply_change(change):
    """Write the change to the account and mark it applied. Remembers what it replaced
    (`extra["before"]`) for undo_change. An email taken by someone else in the meantime cancels instead."""
    user, p, extra = db.session.get(User, change.user_id), change.payload or {}, dict(change.extra or {})
    if change.kind == "email":
        if User.query.filter(User.email == p["new_email"], User.id != user.id).first():
            return cancel_change(change, "email_taken", force=True)
        extra["before"] = {"email": user.email}
        user.email = p["new_email"]
    elif change.kind == "password":
        cred = extra.pop("credential")
        extra["before"] = {"salt": user.password_salt.hex(), "hash": user.password_hash.hex()}
        user.password_salt, user.password_hash = bytes.fromhex(cred["salt"]), bytes.fromhex(cred["hash"])
    elif change.kind == "address":
        row = Address(user_id=user.id, line1=p["line1"], city=p["city"], postcode=p["postcode"], country=p["country"])
        db.session.add(row)
        db.session.flush()
        extra["before"] = {"address_id": row.id}
    elif change.kind == "card":
        ux = dict(user.extra or {})
        extra["before"] = {"brand": user.saved_card_brand, "last4": user.saved_card_last4,
                           "bin": ux.get("card_bin"), "fp": ux.get("card_fp")}
        user.saved_card_brand, user.saved_card_last4 = p["brand"], p["last4"]
        user.extra = dict(ux, card_bin=p["bin6"], card_fp=p["fingerprint"])
    change.status, change.applied_at, change.extra = "applied", utcnow(), extra
    db.session.commit()
    return change


def hold_change(change, hold):
    """Park the change as `pending` for `hold = {"hours", "reason"}` (the ctx.attrs["hold"] contract)."""
    until = utcnow() + timedelta(hours=float(hold.get("hours") or 0))
    change.status = "pending"
    change.extra = dict(change.extra or {}, hold=hold, until=until.isoformat() + "Z")
    db.session.commit()
    return change


def release_change(change):
    """pending -> applied. Anything else is returned unchanged (a cancelled change stays cancelled)."""
    return apply_change(change) if change.status == "pending" else change


def cancel_change(change, reason="", force=False):
    """pending or confirm -> cancelled. Idempotent; an applied change stays applied (undo_change is
    the lab's way back). `force` is for apply_change's own conflict case."""
    if change.status in ("pending", "confirm") or force:
        extra = dict(change.extra or {}, reason=reason)
        extra.pop("credential", None)
        change.status, change.extra = "cancelled", extra
        db.session.commit()
    return change


def undo_change(change):
    """Put back what an applied change replaced. POST /lab/reset calls it, newest change first."""
    user, before = db.session.get(User, change.user_id), (change.extra or {}).get("before")
    if user is None or change.status != "applied" or not before:
        return
    if change.kind == "email":
        user.email = before["email"]
    elif change.kind == "password":
        user.password_salt, user.password_hash = bytes.fromhex(before["salt"]), bytes.fromhex(before["hash"])
    elif change.kind == "address":
        Address.query.filter_by(id=before["address_id"]).delete()
    elif change.kind == "card":
        user.saved_card_brand, user.saved_card_last4 = before["brand"], before["last4"]
        ux = dict(user.extra or {}, card_bin=before["bin"], card_fp=before["fp"])
        user.extra = {k: v for k, v in ux.items() if v is not None}
    db.session.commit()


def describe(change):
    """(HTTP status, JSON body) a route answers with. Only a held change is a 202; an email change
    waiting for its link is a plain 200 `confirm`, so a hold on it is not announced before the link."""
    base = {"status": change.status, "change_id": change.id}
    if change.status == "pending":
        return 202, dict(base, until=(change.extra or {}).get("until"))
    if change.status == "cancelled":
        return 409, dict(base, reason=(change.extra or {}).get("reason", ""))
    return 200, dict(base, ok=True)


def send_mail(redis, email, **msg):
    """Drop a message in the lab mailbox (GET /lab/mailbox/<email>), the store's only outbox."""
    redis.rpush(f"lab:mailbox:{email.lower()}", json.dumps({**msg, "ts": utcnow().isoformat()}))


def notify(redis, change, user):
    """The default notices. The account's current address hears about every change, with a link
    that cancels it while it is still pending; an email change also mails its confirm link to the
    NEW address. Call once the change's status is final for the request."""
    send_mail(redis, user.email, subject="Your account was changed", kind=change.kind, change_id=change.id,
              status=change.status, cancel_url=f"/account/changes/{change.id}/cancel?token={change.token}")
    if change.kind == "email" and change.status == "confirm":
        send_mail(redis, change.payload["new_email"], subject="Confirm your new email address",
                  change_id=change.id, confirm_url=f"/account/email/confirm?token={change.token}")
