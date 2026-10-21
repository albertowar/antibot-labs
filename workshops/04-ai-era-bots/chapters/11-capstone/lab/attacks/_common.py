"""
W4 Ch11 Capstone — Shared attacker helpers (rules of engagement built in)

Every attack script imports this module, and this module imports
tools/labclient.py, which runs the labnet.py loopback guard on import:

  - target() only returns URLs on this machine and exits on anything else.
    These scripts must never point at a site you don't own.
  - Egress IPs are *claimed* with X-Lab-Client-IP from the shared world
    (data/world.json: RFC 5737 / 3849 documentation ranges). No real proxy, no
    proxy list, no third-party infrastructure, no third-party LLM API is ever used.
  - Accounts, emails and addresses are synthetic (@mail.example), seeded by the
    store extension or registered during the run.
  - X-Lab-Actor labels every session for the scoreboard. No defense reads it.

It also measures what each attack costs the attacker (wall time and CPU),
because that cost is what the defenses are for.
"""

import json
import os
import random
import sys
import time
from urllib.parse import urlparse

import requests

try:
    import resource
except ImportError:
    resource = None

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "tools"))
sys.path.insert(0, LAB_DIR)

import labclient  # noqa: E402  (runs the labnet guard on import)
import personas  # noqa: E402
from labclient import world_pool  # noqa: E402
from crawl import (BROWSER_HEADERS, CHROME_UA, DATACENTER, RESIDENTIAL, SEARCHBOT_RANGE,  # noqa: E402,F401
                   SEARCHBOT_UA, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, extract_links, print_report,
                   searchbot_signer, trainbot_signer)
from defenses.challenges import solve_pow  # noqa: E402,F401

BASE_URL = labclient.BASE_URL


def target():
    """The guarded demo-store URL (labnet.py via labclient)."""
    return BASE_URL


DROP_SKU = "lab-runner-9"
DROP_SIZE = "9"
LAB_AGENT_UA = CHROME_UA + " LabAgent/1.0 (+https://agents.lab-provider.test)"
FARM_RESIDENTIAL = world_pool("residential_proxy")   # a residential proxy network (v6 homes)
CLOUD = world_pool("cloud_gcp")                      # a datacenter nobody published
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn", "avery", "rowan"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright", "scott", "green"]


def authority(base):
    return urlparse(base).netloc


def owner_accounts(n=6):
    return personas.owner_accounts(n)


def fleet_identity(rng):
    """A farm's throwaway account: random name + digits, its own synthetic inbox, one reshipper."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    return {"email": email, "password": f"Fleet-{rng.getrandbits(32):08x}",
            "address": f"48 Harbor Freight Way, Unit {rng.randint(1, 400)}, Elizabeth NJ 07201"}


def mailbox_code(base, email):
    r = requests.get(f"{base}/lab/mailbox/{email}", timeout=10)
    msgs = (r.json() or {}).get("messages") or []
    for msg in reversed(msgs):
        if msg.get("code"):
            return msg["code"]
    return None


def grant_mandate(base, account, operator, sku=DROP_SKU, ttl_min=15, egress=None):
    """The account holder, in their OWN browser session, approves a purchase by an operator."""
    s = requests.Session()
    s.headers.update({"User-Agent": CHROME_UA, **BROWSER_HEADERS, "X-Lab-Actor": "human:agent-owner"} |
                     ({"X-Lab-Client-IP": egress} if egress else {}))
    s.get(f"{base}/login")
    r = s.post(f"{base}/api/login", json={"email": account["email"], "password": account["password"]})
    if r.status_code >= 400 or not (r.json() or {}).get("ok", True):
        return None, f"owner login failed ({r.status_code})"
    r = s.post(f"{base}/api/account/mandates", json={"operator": operator, "sku": sku, "ttl_min": ttl_min})
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if body.get("outcome") != "allow":
        return None, body.get("message", f"mandate refused ({r.status_code})")
    return body["mandate"]["id"], None


class Cost:
    def __enter__(self):
        self.wall = time.perf_counter()
        self.cpu = self._cpu()
        return self

    def __exit__(self, *exc):
        self.wall_s = time.perf_counter() - self.wall
        self.cpu_s = self._cpu() - self.cpu
        return False

    @staticmethod
    def _cpu():
        if resource is None:
            return 0.0
        s, c = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
        return s.ru_utime + s.ru_stime + c.ru_utime + c.ru_stime


def summary(name, results, cost):
    """The dict every agent campaign's run() returns (read by tools/checkpoint.py)."""
    outcomes, reasons, kinds = {}, {}, {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        for reason in r.get("reasons", []):
            reasons[reason] = reasons.get(reason, 0) + 1
        for k in r.get("challenges", []):
            kinds[k] = kinds.get(k, 0) + 1
    succeeded = sum(1 for r in results if r.get("success"))
    cost_wall = getattr(cost, "wall_s", 0.0) if cost else 0.0
    cost_cpu = getattr(cost, "cpu_s", 0.0) if cost else 0.0
    return {"attack": name, "attempted": len(results), "succeeded": succeeded, "outcomes": outcomes,
            "challenges": kinds, "top_reasons": sorted(reasons, key=reasons.get, reverse=True)[:4],
            "wall_s": round(cost_wall, 2), "cpu_s": round(cost_cpu, 2),
            "wall_s_per_attempt": round(cost_wall / max(1, len(results)), 2)}


def report(s, success_label="orders placed"):
    print(f"  [{s['attack']}] {s['succeeded']}/{s['attempted']} {success_label}; outcomes {json.dumps(s['outcomes'])}"
          f"{'; challenges ' + json.dumps(s['challenges']) if s['challenges'] else ''}")
    for reason in s["top_reasons"]:
        print(f"      - {reason[:140]}")
    print(f"      attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU ({s['wall_s_per_attempt']} s per attempt)")


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")
