"""
W4 Ch9 Capstone — Shared attacker helpers (rules of engagement built in)

Every attack script imports this module. It enforces the lab's rules:

  - target() only returns http://localhost / 127.0.0.1 / ::1 URLs and exits on
    anything else. These scripts must never point at a site you don't own.
  - Egress IPs are *claimed* with the X-Lab-Egress header from RFC 5737
    documentation ranges. No real proxy, no proxy list, no third-party
    infrastructure, no third-party LLM API is ever used.
  - Accounts, emails and addresses are synthetic (@mail.example), seeded by
    tools/seed.py or registered during the run.
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
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import personas  # noqa: E402
from challenges import solve_pow  # noqa: E402,F401
from crawl import (BASE_URL, BROWSER_HEADERS, CHROME_UA, DATACENTER, RESIDENTIAL, SEARCHBOT_RANGE,  # noqa: E402,F401
                   SEARCHBOT_UA, TRAINBOT_RANGE, TRAINBOT_UA, Crawler, extract_links, print_report,
                   require_local, searchbot_signer, trainbot_signer)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target as _target, require_local, require_local_env  # noqa: E402
BASE_URL = _target("DEMO_URL", BASE_URL)


def target():
    """The guarded demo-store URL (see labnet.py)."""
    return BASE_URL


DROP_SKU = "lab-runner-9"
LAB_AGENT_UA = CHROME_UA + " LabAgent/1.0 (+https://agents.lab-provider.test)"
FARM_RESIDENTIAL = [f"198.51.100.{i}" for i in range(1, 120)]
CLOUD = [f"192.0.2.{i}" for i in range(100, 199)]
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
    msg = (r.json() or {}).get("message") or {}
    return msg.get("code")


def grant_mandate(base, account, operator, sku=DROP_SKU, ttl_min=15, egress=None):
    """The account holder, in their OWN browser session, approves a purchase by an operator."""
    s = requests.Session()
    s.headers.update({"User-Agent": CHROME_UA, **BROWSER_HEADERS, "X-Lab-Actor": "agent-owner"} |
                     ({"X-Lab-Egress": egress} if egress else {}))
    s.get(f"{base}/login")
    r = s.post(f"{base}/api/login", json={"email": account["email"], "password": account["password"]})
    if r.json().get("outcome") != "allow":
        return None, f"owner login failed: {r.json().get('message')}"
    r = s.post(f"{base}/api/account/mandates", json={"operator": operator, "sku": sku, "ttl_min": ttl_min})
    body = r.json()
    if body.get("outcome") != "allow":
        return None, body.get("message", "mandate refused")
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
    return {"attack": name, "attempts": len(results), "succeeded": succeeded, "outcomes": outcomes,
            "challenges": kinds, "top_reasons": sorted(reasons, key=reasons.get, reverse=True)[:4],
            "wall_s": round(cost_wall, 2), "cpu_s": round(cost_cpu, 2),
            "wall_s_per_attempt": round(cost_wall / max(1, len(results)), 2), "results": results}


def report(s, success_label="orders placed"):
    print(f"  [{s['attack']}] {s['succeeded']}/{s['attempts']} {success_label}; outcomes {json.dumps(s['outcomes'])}"
          f"{'; challenges ' + json.dumps(s['challenges']) if s['challenges'] else ''}")
    for reason in s["top_reasons"]:
        print(f"      - {reason[:140]}")
    print(f"      attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU ({s['wall_s_per_attempt']} s per attempt)")


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")
