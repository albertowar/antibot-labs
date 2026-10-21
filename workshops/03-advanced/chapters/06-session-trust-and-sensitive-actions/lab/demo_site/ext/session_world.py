"""
session_world: who the chapter's account holders are, what each one can be reached on, and what each
attacker holds. Pure data and deterministic (no Flask, no Redis), so three parties can share it
without talking to each other, the way Chapter 5's rba_world.py does (which this module builds on):

  * demo_site/ext/session_trust.py seeds the store from it (a saved address and card, an order, a phone,
    an enrolled device, the stolen sessions) at start-up and after every POST /lab/reset;
  * tools/personas_ch6.py builds the 80-person cohort from it (each person's goal and sign-in);
  * attacks/_common.py reads each crew's HOLDINGS from it (what that crew bought, stole or read).

The store never reads a goal or a holding, and an attack never reads anyone's channels. tools/ and the
ext's world simulation (an owner noticing a message) are the only places the two meet.

Accounts (seed users, `demo_site/seed.py: username(i)`), on top of Chapter 5's:

    100-179  the cohort, one person each: Chapter 5's 80 sign-ins, here with a goal to reach
    240-251  crew "premium": the password, the remembered-device cookie and the browser of 12 victims
    260-265  crew "mailbox": the password, the browser and a live webmail session of 6 victims
    280-285  crew "session": a live session cookie out of a stealer log of 6 victims; no password

What each account can be reached on. `phone` is a fictional +1-555-01xx number that gets an SMS (the
lab mailbox stands in for the carrier), `device` an enrolled phone app that can approve a request.
Neither is a secret the crews hold: the owner has them, the attacker does not.
"""

import hashlib
import hmac
import random

from . import rba_world as W

KIT_SESSION = range(280, 286)

# Goals, in the order the cohort is dealt out. See cohort().
GOALS = {
    "routine":       "buy to the saved address with the saved card",
    "rotator":       "change the password",
    "mover":         "add a new address and ship an order to it",
    "gift_giver":    "redeem a gift card",
    "card_expired":  "replace the saved card",
    "cgnat_phone":   "add a second address",
    "traveller":     "ship an order to the hotel",
    "new_phone":     "replace the saved card from the new phone",
    "shared_family": "redeem a gift card from the family laptop",
    "no_inbox":      "change the email address on file (the old inbox is gone)",
}

# Chapter 5's cohort personas, dealt to this chapter's: ch5 persona -> [(ch6 persona, n), ...]. The rest
# of a ch5 persona's accounts become `routine` buyers on an awkward network.
DEAL = {
    "returning":        [("routine", 26), ("mover", 10), ("gift_giver", 8), ("card_expired", 6), ("rotator", 4)],
    "cgnat_phone":      [("cgnat_phone", 6)],
    "traveller":        [("traveller", 3)],
    "vpn":              [("traveller", 1)],
    "new_device":       [("new_phone", 3)],
    "forgot_new_phone": [("new_phone", 1)],
    "shared_device":    [("shared_family", 2)],
    "cleared_cookies":  [("shared_family", 1)],
    "no_inbox":         [("no_inbox", 2)],
    "forgot_home":      [("no_inbox", 1)],
}

# The crews' holdings (what the crew has, per victim). Used by the attacks and the README, never by the store.
HOLDINGS = {
    "premium": {"password": True, "rd": True, "webmail": False, "session": False, "device": False, "phone": False},
    "mailbox": {"password": True, "rd": False, "webmail": True, "session": False, "device": False, "phone": False},
    "session": {"password": False, "rd": False, "webmail": False, "session": True, "device": False, "phone": False},
}

# Channel plans for victims (N neither, P phone, D device, B both), over the crew's accounts in order.
VICTIM_CHANNELS = {"premium": "NPDBNPDBPDBN", "mailbox": "NPDBNP", "session": "NPDBND"}
_PLAN = {"N": (False, False), "P": (True, False), "D": (False, True), "B": (True, True)}

# Where the crews ship and who they claim to be: invented, fictional, the same for every victim (a linking signal).
MULE = {"line1": "9 Dockside Lane", "city": "Fairview", "postcode": "00000", "country": "US"}
MULE_MAIL = "drop{n:03d}@mule.example.test"

# Whether an owner notices a message on a channel inside the cooling-off window. Lab assumptions, not
# measurements: the point of the chapter is that the number depends on the channel.
OWNER_SEES = {"email": 0.50, "sms": 0.90, "device": 0.90, "banner": 0.60}


def _h(*parts):
    digest = hmac.new(str(W.WORLD_SEED).encode(), ":".join(str(p) for p in parts).encode(), hashlib.sha256).digest()
    return int.from_bytes(digest[:4], "big") / 2 ** 32


def session_sid(index):
    """The session cookie value a stealer log holds for victim `index` (an opaque token)."""
    return hashlib.sha256(f"sid:{W.WORLD_SEED}:{index}".encode()).hexdigest()[:32]


def phone_of(index):
    return f"+1-555-01{(index * 13) % 100:02d}"


def sms_box(email):
    """The lab-mailbox key the carrier delivers this account's SMS to: GET /lab/mailbox/<this>."""
    return f"sms:{email}"


_COHORT = {}


def cohort():
    """{account index: ch6 persona}: the 80 people. Chapter 5's accounts, dealt out by DEAL."""
    if not _COHORT:
        by5 = {}
        for idx, a in sorted(W.accounts().items()):
            if a.persona in {name for name, _ in W.COHORT}:
                by5.setdefault(a.persona, []).append(idx)
        for p5, idxs in by5.items():
            plan = [name for name, n in DEAL[p5] for _ in range(n)]
            for k, idx in enumerate(idxs):
                _COHORT[idx] = plan[k] if k < len(plan) else "routine"
    return _COHORT


_SESSION_ACCOUNTS = {}


def account(index):
    """The Account (devices, home network) behind any managed index; the session crew's are built here."""
    if index in KIT_SESSION:
        if not _SESSION_ACCOUNTS:
            rng = random.Random(W.WORLD_SEED + 6)
            for i in KIT_SESSION:
                _SESSION_ACCOUNTS[i] = W._account(i, "session", rng)
        return _SESSION_ACCOUNTS[index]
    return W.accounts()[index]


def victims(kit):
    """The accounts a crew holds: premium and mailbox from Chapter 5's kits, session from here."""
    return list(KIT_SESSION) if kit == "session" else list(W.KITS[kit])


def channels(index):
    """{"phone": bool, "device": bool}: what the account owner can be reached on."""
    persona = cohort().get(index)
    if persona is None:
        for kit in HOLDINGS:
            vs = victims(kit)
            if index in vs:
                plan = VICTIM_CHANNELS[kit]
                return dict(zip(("phone", "device"), _PLAN[plan[vs.index(index) % len(plan)]]))
        return {"phone": False, "device": False}
    if persona == "traveller":
        return {"phone": True, "device": True}
    if persona == "new_phone":
        return {"phone": True, "device": False}
    if persona == "shared_family":
        return {"phone": False, "device": False}
    if persona == "no_inbox":
        ids = [i for i, p in sorted(cohort().items()) if p == "no_inbox"]
        return {"phone": ids.index(index) != 1, "device": False}
    return {"phone": index % 5 < 3, "device": index % 3 != 0}


def managed():
    """Every account the chapter configures: the cohort and the three crews' victims."""
    out = set(cohort())
    for kit in HOLDINGS:
        out.update(victims(kit))
    return sorted(out)


def gift_code_id(index):
    """The GiftCard row id a cohort member holds (one). The crews' loot is ids 101-200 (LOOT_IDS)."""
    return (index - 100) % 100 + 1


LOOT_IDS = range(101, 201)


def owner_sees(index, channel, change_id):
    """Does the owner of `index` notice a message on `channel` about `change_id`? Deterministic."""
    return _h("owner", index, channel, change_id) < OWNER_SEES[channel]
