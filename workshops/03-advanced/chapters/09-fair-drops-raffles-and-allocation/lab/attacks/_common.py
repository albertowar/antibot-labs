"""
Shared plumbing for the W3 Ch9 attack scripts: the crews that want the pair.

Rules of engagement, enforced in code:
  - Every script imports tools/labclient.py, which asks labnet.py (lab root) for DEMO_URL and refuses anything that
    is not this machine.
  - Source addresses are rented from data/world.json (documentation ranges): residential_proxy_net for the crews
    that pay for a fleet (a different address on every request), the home pools for the paid people of the crowd.
  - Every account, card, address and mailbox is synthetic (demo_site/ext/raffle_world.py). The fresh farms register
    their own accounts while they run; the others "bought" or "recruited" theirs, which the world seeds when the
    round opens. A script reads only its own crew's kit.

Each script ends by printing ONE JSON line for tools/checkpoint.py:
    {"attacker": "bot:account_farm", "attempted": 300, "succeeded": 118, ...}
`attempted` is the accounts the crew fielded, `succeeded` what it got: in entry mode, entries accepted; in claim
mode (--claim), pairs paid for. The checkpoint replaces `succeeded` with the units the crew finally holds after
claims, cancellations and re-draws, read from the store's report.

Every script runs in one of two modes, like a real crew reading the product page: if the drop is first come, first
served (GET /api/raffle/<sku> says mode=first_come) it stages and buys at the opening second; if it is a raffle it
enters (and, with --claim, pays for what it won).
"""

import json
import os
import random
import re
import sys
import time
from calendar import timegm
from concurrent.futures import ThreadPoolExecutor

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(LAB, "tools"))
import browsers  # noqa: E402
import labclient  # noqa: E402  (runs the labnet guard on import)
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402
from demo_site.ext import raffle_world as W  # noqa: E402

SKU = W.SKU
CHROME = ("chrome", 153, "windows")
PATIENCE_S = 1.1            # above Chapter 4's one-second funnel floor


def headers(kind="post", referer=None):
    """A real Chrome's User-Agent and a JSON Accept (W1 Ch4: free to forge); requests adds the content type."""
    ua = dict(browsers.headers_for(CHROME, "post", BASE_URL, referer)).get("User-Agent", "")
    return [("User-Agent", ua), ("Accept", "application/json")]


def person_ja4(key):
    """A browser's TLS fingerprint, claimed: one per person here (a real browser shares its fingerprint with
    millions of others; that is why it is a weak link)."""
    import hashlib
    return "t13d1516h2_" + hashlib.sha256(str(key).encode()).hexdigest()[:12]


def fleet(actor, ip=None, ja4=None):
    """One account's client: a rotating residential address on every request (or one fixed home address),
    and the crew's tooling fingerprint (claimed) unless a person's own browser is given."""
    ja4 = ja4 or W.crew_ja4(actor.split(":")[1])
    if ip:
        return LabClient(actor, ip=ip, ja4=ja4)
    return LabClient(actor, pool=world_pool("residential_proxy_net"), ja4=ja4)


def mode():
    """('raffle' | 'first_come', info) as any visitor would read it off the drop."""
    info = LabClient("bot:probe", ip=world_pool("residential_proxy_net")[0]).get(f"/api/raffle/{SKU}", headers()).json()
    return info["mode"], info


def open_epoch(info):
    """When a first-come drop opens, as epoch seconds (the API gives an ISO time in UTC)."""
    if info.get("drop_open") or not info.get("drop_at"):
        return time.time()
    stamp = info["drop_at"].rstrip("Z")
    secs, _, frac = stamp.partition(".")
    return timegm(time.strptime(secs, "%Y-%m-%dT%H:%M:%S")) + (float("0." + frac) if frac else 0.0)


def mail_link(client, email, kind):
    """The newest message of `kind` in this account's own inbox (the crew owns the mailbox)."""
    msgs = client.get(f"/lab/mailbox/{email}").json()["messages"]
    return next((m for m in reversed(msgs) if m.get("kind") == kind or (kind == "code" and "code" in m)), None)


def register(client, email, password, name="Pat Holder", verify=True):
    """Create the account and, for a raffle, follow its verification link (the crew owns the mailbox)."""
    r = client.post("/api/register", json={"email": email, "password": password, "name": name}, headers=headers())
    if r.status_code != 201:
        return False
    link = mail_link(client, email, "verify") if verify else None
    if link:
        client.get(link["verify_url"], headers=headers("link"))
    return True


def login(client, email, password):
    return client.post("/api/login", json={"email": email, "password": password}, headers=headers()).status_code == 200


def enter(client, body=None):
    """POST the entry. Returns (status, X-Lab-Signals)."""
    r = client.post(f"/api/raffle/{SKU}/enter", json=body or {}, headers=headers())
    return r.status_code, r.headers.get("X-Lab-Signals", "")


def buy(client, email):
    r = client.post("/api/buy", json={"sku": SKU, "size": W.SIZE, "email": email}, headers=headers())
    return r.status_code


def claim(client, email, body=None):
    """me -> claim, solving the in-session code from the crew's own inbox. Returns 'paid' | 'held' | 'lost' | 'refused'."""
    me = client.get(f"/api/raffle/{SKU}/me", headers=headers("link")).json()
    if me.get("status") != "won":
        return "lost"
    for _ in range(2):
        r = client.post(f"/api/raffle/{SKU}/claim", json=body or {}, headers=headers())
        if r.status_code == 201:
            return "paid"
        if r.status_code == 202:
            return "held"
        err = (r.json() or {}).get("error", {}) if r.headers.get("Content-Type", "").startswith("application/json") else {}
        if err.get("code") == "challenge_required":
            code = mail_link(client, email, "code")
            if not code:
                return "refused"
            v = client.post("/api/challenge/verify", json={"type": "otp_session", "answer": {"code": code["code"]}}, headers=headers())
            if v.status_code != 200:
                return "refused"
            continue
        return "refused"
    return "refused"


def map_threads(fn, items, workers=32):
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(fn, items))


def report(**out):
    print(json.dumps(out))


def args_claim(ap):
    ap.add_argument("--claim", action="store_true", help="after the draw: pay for the pairs this crew won")
    ap.add_argument("--wins", default=None, help="with --claim: a JSON file listing the emails the crew was told it won "
                    "(the 'you won' mail); default is to log in to every account and look")


def only_wins(kit_or_range, path, key=lambda a: a.email):
    """Restrict a kit to the accounts named in the --wins file (the crew reads its own inboxes)."""
    if not path:
        return kit_or_range
    with open(path) as fh:
        wins = set(json.load(fh))
    return [a for a in kit_or_range if key(a) in wins]
