"""
rba_world: who the chapter's customers are, what the store remembers about them, and what each
attacker holds. Pure data and deterministic (WORLD_SEED), with no Flask and no Redis, so three
parties can share it without talking to each other:

  * demo_site/ext/rba.py seeds the store's memory from it (login history and remembered devices)
    at start-up and after every POST /lab/reset;
  * tools/personas_ch5.py builds the sign-in cohort from it (each person's device and network today);
  * attacks/_common.py reads each crew's KIT from it (what that crew bought).

The split matters for honesty. The store never reads a kit, and an attack never reads anyone's
history or another crew's kit. tools/calibrate.py reads both, offline, because choosing a
threshold needs labelled examples of each side; that is the one place they meet.

Accounts (seed users, `demo_site/seed.py: username(i)`):

    100-179  the sign-in cohort, one person each (COHORT below)
    200-219  kit "cheap":   stealer-log credentials only (email + password)
    240-251  kit "premium": stealer logs with the store's remembered-device cookie and the browser's UA
    260-265  kit "mailbox": stealer logs with the credentials, the browser's UA and a live webmail
                            session (the store's own cookie had expired)
    270-275  kit "inbox":   a webmail session only (the email account was taken over; no store password)

Users 000-029 (the weak, breached passwords of W2 Ch6) are left alone: this chapter's credentials
are fresh, which is exactly why the breach screen at level 0 never fires on them.
"""

import base64
import hashlib
import hmac
import json
import os
import random
from collections import Counter
from dataclasses import dataclass, field

WORLD_SEED = 20261018
HISTORY_DAYS = 90
WORLD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "world.json")

# Browser profiles (tools/browsers.py tuples).
DESKTOPS = [("chrome", 153, "windows"), ("chrome", 153, "macos"), ("firefox", 155), ("safari", "macos")]
PHONES = [("safari", "ios"), ("chrome", 153, "android")]
NEW_LAPTOP = ("chrome", 153, "windows")

HOME_POOLS = ["home_broadband", "home_cable", "home_fiber"]
PHONE_POOL = "mobile_cgnat"


def _h(*parts):
    return hmac.new(str(WORLD_SEED).encode(), ":".join(str(p) for p in parts).encode(), hashlib.sha256).digest()


def rd_token(account, device):
    """The remembered-device token the store issued to one of an account's browsers (the `rd` cookie)."""
    return base64.urlsafe_b64encode(_h("rd", account, device)[:16]).rstrip(b"=").decode()


def ua_key(profile):
    """The coarse user-agent value the risk model scores: family/major/(m)obile or (d)esktop.

    Must agree with what demo_site/ext/rba.py derives from the real User-Agent header
    (defenses/context.py UserAgent.parse); tools/calibrate.py --check asserts that it does.
    """
    fam = profile[0]
    if fam == "chrome":
        return f"chrome/{profile[1]}/{'m' if profile[2] == 'android' else 'd'}"
    if fam == "firefox":
        return f"firefox/{profile[1]}/d"
    return f"safari/26/{'m' if profile[1] == 'ios' else 'd'}"


_POOLS = {}


def pool_info(name):
    """(asn, country) of a data/world.json pool: what the store's edge reports for its addresses."""
    if not _POOLS:
        with open(WORLD_FILE) as fh:
            for k, p in json.load(fh)["pools"].items():
                _POOLS[k] = (p["asn"], p["country"])
    return _POOLS[name]


@dataclass(frozen=True)
class Device:
    name: str               # "laptop" or "phone"
    browser: tuple
    phone: bool = False


@dataclass
class Account:
    index: int
    persona: str            # cohort persona, or the kit name for a victim
    home_pool: str
    home_slot: int          # which address of the home pool is "theirs"
    devices: list = field(default_factory=list)
    history_n: int = 30     # verified logins in the seeded 90 days

    @property
    def email(self):
        return f"user{self.index:03d}@example.test"


# The sign-in cohort: one row per kind of person, how many, and today's login.
#   persona            n
COHORT = [
    ("returning",       54),  # own laptop or phone, home network: the easy majority
    ("cgnat_phone",      6),  # own phone over the carrier's shared address
    ("new_device",       3),  # a new laptop at home: no remembered device yet
    ("cleared_cookies",  3),  # own laptop, home network, cookies cleared
    ("traveller",        3),  # own laptop, a hotel network in Germany
    ("vpn",              3),  # own laptop through a commercial VPN
    ("shared_device",    2),  # the family laptop, remembered for another account in the house
    ("no_inbox",         2),  # own laptop, home network; lost access to the email inbox
    ("forgot_home",      2),  # forgot the password; resets it on their own laptop at home
    ("forgot_new_phone", 2),  # forgot the password; resets it on a new phone over the carrier network
]

KITS = {
    "cheap": range(200, 220),
    "premium": range(240, 252),
    "mailbox": range(260, 266),
    "inbox": range(270, 276),
}


def _account(index, persona, rng):
    a = Account(index=index, persona=persona, home_pool=HOME_POOLS[index % len(HOME_POOLS)],
                home_slot=index % 50, history_n=rng.randint(20, 60))
    a.devices = [Device("laptop", DESKTOPS[rng.randrange(len(DESKTOPS))])]
    phone = PHONES[rng.randrange(len(PHONES))]
    if persona in ("cgnat_phone", "forgot_new_phone") or rng.random() < 0.6:
        a.devices.append(Device("phone", phone, phone=True))
    return a


_ACCOUNTS = {}


def accounts():
    """Every account the chapter seeds, cohort and victims, keyed by seed index."""
    if not _ACCOUNTS:
        rng = random.Random(WORLD_SEED)
        i = 100
        for persona, n in COHORT:
            for _ in range(n):
                _ACCOUNTS[i] = _account(i, persona, rng)
                i += 1
        for kit_name, idxs in KITS.items():
            for j in idxs:
                _ACCOUNTS[j] = _account(j, kit_name, rng)
    return _ACCOUNTS


def history(account):
    """The seeded login history: `history_n` verified logins over HISTORY_DAYS, oldest first.

    Each event is (days_ago, device_name, pool): mostly the laptop at home; the phone a third of
    the time, half of that over the carrier network (always, for the phone-first personas).
    """
    rng = random.Random(WORLD_SEED * 7 + account.index)
    phone = next((d for d in account.devices if d.phone), None)
    events = []
    for k in range(account.history_n):
        days_ago = HISTORY_DAYS - (k * HISTORY_DAYS) // account.history_n
        if phone is not None and rng.random() < 0.35:
            carrier = account.persona in ("cgnat_phone", "forgot_new_phone") or rng.random() < 0.5
            events.append((days_ago, phone.name, PHONE_POOL if carrier else account.home_pool))
        else:
            events.append((days_ago, account.devices[0].name, account.home_pool))
    return events


def features_of(account, device_name, pool, browser, rd_of=None):
    """The feature values one login presents: what the store's ext computes from a live request.

    `rd_of` is the account whose remembered-device cookie the browser carries (default: this one).
    """
    asn, cc = pool_info(pool)
    dev = rd_token(account.index if rd_of is None else rd_of, device_name) if device_name else "none"
    return {"dev": dev, "asn": str(asn), "cc": cc, "ua": ua_key(browser)}


def seeded_counts():
    """(per-account Counter, global Counter) of feature values over every seeded history.

    Keys are "<feature>:<value>" plus "_n" (number of logins). The store loads the per-account
    counters into Redis and freezes the global one as its population snapshot (in production a
    nightly batch job rebuilds it; online updates would make every score depend on traffic order).
    """
    per, glob = {}, Counter()
    for idx, a in accounts().items():
        c = Counter()
        for _days, dev_name, pool in history(a):
            dev = next(d for d in a.devices if d.name == dev_name)
            for k, v in features_of(a, dev_name, pool, dev.browser).items():
                c[f"{k}:{v}"] += 1
            c["_n"] += 1
        per[idx] = c
        glob.update(c)
    return per, glob


def spouse(account):
    """For shared_device: the household member whose remembered laptop this person borrows.

    A returning customer on the same home network (same ISP), so only the device and the browser
    are new to this account.
    """
    same_isp = [a for i, a in sorted(accounts().items())
                if a.persona == "returning" and a.home_pool == account.home_pool]
    return same_isp[account.index % len(same_isp)]


def today(account):
    """How a cohort member signs in today: {"device", "browser", "pool", "rd_of"}.

    `device` is the name of the remembered device they use (None: a browser the store has never
    seen, or one whose cookies were cleared); `rd_of` is the account whose `rd` cookie that browser
    carries (their own, or the spouse's on a shared laptop).
    """
    p, laptop = account.persona, account.devices[0]
    phone = next((d for d in account.devices if d.phone), None)
    if p == "cgnat_phone":
        return {"device": phone.name, "browser": phone.browser, "pool": PHONE_POOL, "rd_of": account.index}
    if p == "returning" and phone is not None and account.index % 3 == 0:
        return {"device": phone.name, "browser": phone.browser, "pool": account.home_pool, "rd_of": account.index}
    if p == "new_device":
        return {"device": None, "browser": NEW_LAPTOP, "pool": account.home_pool, "rd_of": None}
    if p == "cleared_cookies":
        return {"device": None, "browser": laptop.browser, "pool": account.home_pool, "rd_of": None}
    if p == "traveller":
        return {"device": laptop.name, "browser": laptop.browser, "pool": "home_eu", "rd_of": account.index}
    if p == "vpn":
        return {"device": laptop.name, "browser": laptop.browser, "pool": "consumer_vpn", "rd_of": account.index}
    if p == "shared_device":
        s = spouse(account)
        return {"device": "laptop", "browser": s.devices[0].browser, "pool": s.home_pool, "rd_of": s.index}
    if p == "forgot_new_phone":
        return {"device": None, "browser": PHONES[0], "pool": PHONE_POOL, "rd_of": None}
    return {"device": laptop.name, "browser": laptop.browser, "pool": account.home_pool, "rd_of": account.index}


# --- The attackers' kits -------------------------------------------------------------------
#
# What each crew holds about each victim. Passwords come from demo_site/seed.py `password_for`:
# they are fresh (never in a breach corpus), because an infostealer read them straight out of the
# victim's browser.

def kit(name):
    """[{"index", "email", ...}] for one crew. The extra fields depend on the kit."""
    out = []
    for i in KITS[name]:
        a = accounts()[i]
        row = {"index": i, "email": a.email, "home_pool": a.home_pool,
               "password": name != "inbox"}
        if name in ("premium", "mailbox"):
            row["browser"] = a.devices[0].browser          # the stealer log records the browser profile
        if name == "premium":
            row["rd"] = rd_token(i, a.devices[0].name)     # ... and, in this kit, the store's cookies
        if name in ("mailbox", "inbox"):
            row["webmail_session"] = True
        out.append(row)
    return out
