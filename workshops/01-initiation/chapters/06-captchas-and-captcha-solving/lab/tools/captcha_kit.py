"""
Chapter 6 plumbing shared by the attack scripts and the shoppers (tools/personas_ch6.py).

Everything here is lab plumbing, not defense or attack logic:

  - the mock provider: `mint_token()` asks it for a token, as its widget would after a pass
  - bot clients: a labclient.LabClient from a rented datacenter IP that already does what earlier
    chapters forced it to (a current Chrome User-Agent, cookies); each round adds one new trick
  - the promo and CAPTCHA calls, as a client sees them (contract routes + /promo/*)
  - simulated time: LAB_TIME_SCALE=5 means one real second counts as five simulated seconds
    (defenses/policy.py), so a 40-second farm solve takes 8 real seconds
  - "eyes": `look_at()` reads the lab-only /lab/captcha/eyes/<id> route, standing in for a human
    reading the image. Shoppers and the simulated solving farm (attacks/farm.py) use it. A bot
    script that is not a farm must NEVER call it.
  - `report()` / `emit()`: every attack ends by printing one JSON line, which tools/checkpoint.py reads

Everything goes through tools/labclient.py, the one localhost guard.
"""

import base64
import json
import os
import random
import secrets
import sys
import time
from urllib.parse import urlparse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import labclient  # noqa: E402
from labclient import LabClient, admin, assert_local, world_pool  # noqa: E402,F401

TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "5"))
SITEKEY = "lab-sitekey-0000"            # the mock's TEST key pair; same values as defenses/policy.py
BOT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
JSON_HEADERS = [("User-Agent", BOT_UA), ("Accept", "application/json")]


def provider_url():
    """The mock provider (started by the store, or by hand). Read late: the store may pick a free port.

    PROVIDER_URL if set; otherwise ask the store where it put the provider; otherwise the default port.
    """
    url = os.environ.get("PROVIDER_URL")
    if not url:
        try:
            url = requests.get(labclient.BASE_URL + "/lab/captcha/provider", timeout=5).json()["url"]
        except (requests.RequestException, ValueError, KeyError):
            url = "http://127.0.0.1:5001"
    return assert_local(url).rstrip("/")


def sim_sleep(sim_seconds):
    """Sleep for a simulated duration (divided by LAB_TIME_SCALE)."""
    time.sleep(max(0.0, sim_seconds) / TIME_SCALE)


def sim_now():
    return time.time() * TIME_SCALE


def mint_token(ip, action, hostname="127.0.0.1", sitekey=SITEKEY, cdata=""):
    """Ask the mock provider for a token, as its widget would after a pass.

    The mock cannot tell people from programs (no provider can, perfectly), so the lab models the
    provider's cost with a rule of engagement: bot scripts mint tokens for non-interactive actions
    (newsletter) and for OTHER hostnames freely, but an interactive token for THIS site costs money:
    it only comes from attacks/farm.py. See the README, Round 1.
    """
    r = requests.post(f"{provider_url()}/lab/mint", timeout=5, headers={"X-Lab-Client-IP": ip},
                      json={"sitekey": sitekey, "action": action, "hostname": hostname, "cdata": cdata})
    r.raise_for_status()
    return r.json()["token"]


def provider_chaos(mode, seconds=5, ip=None):
    """Simulate a provider outage: siteverify answers HTTP 500 for a few seconds.

    `ip` scopes it to siteverify calls about that client (the form's `remoteip`), so a lab with other
    people signing up at the same moment is not caught in your incident. A real outage is global.
    """
    requests.post(f"{provider_url()}/lab/chaos", json={"mode": mode, "seconds": seconds, "ip": ip}, timeout=5)


def bot(name, ip=None, rotate=None, rng=None):
    """A bot with an actor label for the scoreboard.

    By default it rents one datacenter address (`cloud_vm`). `ip=` pins another; `rotate=` is a list of
    addresses and the client picks a new one for EVERY request, like a rotating proxy pool.
    """
    rng = rng or random.Random()
    if rotate:
        return LabClient(f"bot:{name}", pool=list(rotate), rng=rng)
    return LabClient(f"bot:{name}", ip=ip or rng.choice(world_pool("cloud_vm")), rng=rng)


def get(c, path, **kw):
    return c.get(path, JSON_HEADERS, **kw)


def post_json(c, path, body=None, **kw):
    return c.post(path, headers=JSON_HEADERS, json=body if body is not None else {}, **kw)


def unlock(c):
    """Open the offer page: a redemption without it is refused ("not unlocked")."""
    return c.get("/promo/", [("User-Agent", BOT_UA), ("Accept", "text/html")])


def visit_home(c):
    return c.get("/", [("User-Agent", BOT_UA), ("Accept", "text/html")])


def new_challenge(c):
    """Fetch a CAPTCHA. Returns (challenge_id, png_bytes) or (None, None)."""
    r = get(c, "/api/challenge?type=captcha")
    if r.status_code != 200:
        return None, None
    p = r.json()["payload"]
    return p["id"], base64.b64decode(p["image"].split(",", 1)[1])


def answer_challenge(c, challenge_id, text, ip=None):
    """POST the answer; 200 means the session is cleared for one redemption."""
    return post_json(c, "/api/challenge/verify", {"type": "captcha", "answer": {"id": challenge_id, "text": text}}, ip=ip)


def redeem(c, ip=None):
    """Claim the voucher. Returns (status, body); a 403 body carries the CAPTCHA payload."""
    r = post_json(c, "/promo/redeem", ip=ip)
    return r.status_code, r.json()


def look_at(challenge_id):
    """LAB ONLY: what a human sees in the image. Stands in for human eyes (shoppers, the farm)."""
    r = requests.get(labclient.BASE_URL + f"/lab/captcha/eyes/{challenge_id}", timeout=10)
    return r.json().get("text") if r.ok else None


def typo(text, rng=random):
    """A plausible human misread: one character swapped for a lookalike."""
    lookalikes = {"B": "8", "8": "B", "S": "5", "5": "S", "Z": "2", "2": "Z",
                  "G": "6", "6": "G", "U": "V", "V": "U", "M": "N", "N": "M"}
    i = rng.randrange(len(text))
    c = text[i]
    wrong = lookalikes.get(c) or rng.choice([x for x in "ACDEFHKRTWXY" if x != c])
    return text[:i] + wrong + text[i + 1:]


def new_email(prefix):
    return f"{prefix}-{secrets.token_hex(4)}@example.test"


def store_level():
    return admin("GET", "/lab/status")["level"]


def image_style(level=None):
    """The style the store draws at this level (white-box: the attacker trains on the defender's own generator)."""
    level = store_level() if level is None else level
    return "hardened" if level >= 3 else "basic"


def reasons(actor, key, limit=2000):
    """Why the store said no, from the decision log (the client is never told): {reason: count}.

    `key` is a field the defenses note into the log's extra: turnstile_reason (siteverify.py),
    captcha_reason (challenge_store.py / solver_signals.py). Reasons that mean "fine" are left out.
    """
    items = admin("GET", "/lab/decisions", params={"actor": actor, "limit": limit})["items"]
    out = {}
    for d in items:
        why = (d.get("extra") or {}).get(key)
        if why and why not in ("provider accepted token", "correct"):
            out[why] = out.get(why, 0) + 1
    return out


def report(name, attempted, succeeded, **extra):
    """An attack's result: at least {"name", "attempted", "succeeded"}. `emit()` prints it."""
    return {"name": name, "attempted": attempted, "succeeded": succeeded, **extra}


def emit(result):
    """Every attack ends with exactly one JSON line, printed LAST: tools/checkpoint.py reads it."""
    print(json.dumps(result, default=str))


def host_of(url):
    return urlparse(url).hostname


def claim(c, solve):
    """The shape of every CAPTCHA attack: open the offer, hit the CAPTCHA, answer it, redeem.

    `solve(png_bytes, challenge_id)` returns the bot's answer. Returns (voucher or None, why):
    "no captcha" when the store did not ask for one, otherwise the step that failed.
    """
    unlock(c)
    status, body = redeem(c)
    if status == 200:
        return body["voucher"], "no captcha"
    err = body.get("error", {})
    if err.get("code") != "challenge_required":
        return None, err.get("code", str(status))
    payload = err["payload"]
    png = base64.b64decode(payload["image"].split(",", 1)[1])
    r = answer_challenge(c, payload["id"], solve(png, payload["id"]))
    if r.status_code != 200:
        return None, "answer refused"
    status, body = redeem(c)
    return (body["voucher"], "solved") if status == 200 else (None, body.get("error", {}).get("code", str(status)))
