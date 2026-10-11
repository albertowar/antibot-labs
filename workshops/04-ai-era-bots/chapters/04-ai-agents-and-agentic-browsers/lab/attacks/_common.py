"""
W4 Ch4 — Shared attacker helpers (rules of engagement built in)

Every attack script imports this module. It enforces the lab's rules:

  - target() only returns http://localhost / 127.0.0.1 / ::1 URLs and exits on
    anything else. These scripts must never point at a site you don't own.
  - Egress IPs are *claimed* with the X-Lab-Egress header from data/egress_pool.txt,
    a documentation range (RFC 5737). No real proxy, no proxy list, no third-party
    infrastructure, no third-party LLM API is ever used.
  - Accounts, emails and addresses are synthetic (@mail.example), seeded by tools/seed.py.
  - X-Lab-Actor labels every session for the scoreboard. No defense reads it.

It also measures what each attack costs the attacker (wall time and CPU,
including the browser), because that cost is what the defenses are for.
"""

import json
import os
import random
import sys
import time
from urllib.parse import urlparse

import requests

try:
    import resource  # Unix only; on Windows CPU cost is reported as 0
except ImportError:
    resource = None

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "tools"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import personas  # noqa: E402

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DROP_SKU = "lab-runner-9"
DROP_NAME = "Lab Runner 9 (limited drop)"
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/150.0.0.0 Safari/537.36")
LAB_AGENT_UA = CHROME_UA + " LabAgent/1.0 (+https://agents.lab-provider.test)"
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn", "avery", "rowan"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright", "scott", "green"]


def target():
    url = os.environ.get("DEMO_URL", "http://127.0.0.1:8404").rstrip("/")
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"🛑 Refusing to run against {host!r}. Lab attacks only run against your own local demo store.")
    return url


def authority(base):
    return urlparse(base).netloc


def headless():
    """HEADLESS=1 forces headless (CI, no display); otherwise headful when a display exists."""
    env = os.environ.get("HEADLESS")
    if env is not None:
        return env not in ("0", "false", "no")
    return not (os.environ.get("DISPLAY") or sys.platform in ("darwin", "win32"))


def egress_pool():
    with open(os.path.join(HERE, "data", "egress_pool.txt")) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def owner_accounts(n=5):
    return personas.owner_accounts(n)


def fleet_identity(rng):
    """A fleet's throwaway account: random name + digits, its own synthetic inbox, one reshipper."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    return {"email": email, "password": f"Fleet-{rng.getrandbits(32):08x}",
            "address": f"48 Harbor Freight Way, Unit {rng.randint(1, 400)}, Elizabeth NJ 07201"}


def mailbox_code(base, email):
    """Read the latest step-up code from the lab inbox (synthetic inboxes the fleet owns)."""
    r = requests.get(f"{base}/lab/mailbox/{email}", timeout=10)
    msg = (r.json() or {}).get("message") or {}
    return msg.get("code")


def grant_mandate(base, account, operator, sku=DROP_SKU, ttl_min=15, egress=None):
    """
    The account holder, in their OWN session, approves a purchase by an operator.
    Modelled as a plain HTTP session with a browser UA: this is the human, not the agent.
    """
    s = requests.Session()
    s.headers.update({"User-Agent": CHROME_UA, "Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Mode": "navigate",
                      "X-Lab-Actor": "agent-owner"} | ({"X-Lab-Egress": egress} if egress else {}))
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
    """Wall-clock and CPU seconds for this process and its (finished) children."""

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
    """The dict every attack's run() returns (read by tools/checkpoint.py)."""
    outcomes, reasons = {}, {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        for reason in r.get("reasons", []):
            reasons[reason] = reasons.get(reason, 0) + 1
    succeeded = sum(1 for r in results if r.get("success"))
    return {
        "attack": name, "attempts": len(results), "succeeded": succeeded, "outcomes": outcomes,
        "top_reasons": sorted(reasons, key=reasons.get, reverse=True)[:4],
        "steps_total": sum(r.get("steps", 0) for r in results),
        "wall_s": round(cost.wall_s, 2), "cpu_s": round(cost.cpu_s, 2),
        "wall_s_per_attempt": round(cost.wall_s / max(1, len(results)), 2),
        "results": results,
    }


def report(s, success_label="orders placed"):
    print(f"=== {s['attack']}: {s['succeeded']}/{s['attempts']} {success_label} ===")
    print(f"  outcomes: {json.dumps(s['outcomes'])}   agent steps: {s['steps_total']}")
    for reason in s["top_reasons"]:
        print(f"    - {reason[:140]}")
    print(f"  attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU ({s['wall_s_per_attempt']} s per attempt)")


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")
