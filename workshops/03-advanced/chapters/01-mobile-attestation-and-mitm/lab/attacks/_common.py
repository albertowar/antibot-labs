"""
W3 Ch1 — Shared attacker helpers (rules of engagement built in)

Every attack script imports this module. It enforces the lab's rules:

  - target() only returns http(s)://localhost / 127.0.0.1 / ::1 URLs and exits
    on anything else. These scripts must never point at a site you do not own.
  - Egress IPs are *claimed* with the X-Lab-Egress header from
    data/egress_pool.txt, a documentation range (RFC 5737). No real proxy, no
    proxy list, no third-party infrastructure is ever used.
  - Accounts, emails and addresses are synthetic (@mail.example).

It also measures what each attack costs the attacker (wall time / CPU), because
the economics are the point of the last round.
"""

import json
import os
import random
import sys
import time
import warnings

try:
    import resource  # Unix only; on Windows CPU cost is reported as 0
except ImportError:
    resource = None

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target as _target, require_local, require_local_env  # noqa: E402
BASE_URL = _target("DEMO_URL", "https://localhost:8443")


def target():
    """The guarded demo-store URL (see labnet.py)."""
    return BASE_URL


FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright"]


def egress_pool():
    with open(os.path.join(HERE, "data", "egress_pool.txt")) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def farm_identity(rng):
    """A scalper's throwaway account."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    return {"email": email, "password": f"Farm-{rng.getrandbits(32):08x}",
            "address": f"48 Harbor Freight Way, Unit {rng.randint(1, 400)}, Elizabeth NJ 07201"}


class Cost:
    """Wall-clock and CPU seconds for this process and its finished children."""

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


def summary(name, results, cost, success_key="bought"):
    """The dict every attack's run() returns (read by tools/checkpoint.py)."""
    outcomes, reasons = {}, {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        for reason in r.get("reasons", []):
            reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "attack": name, "attempts": len(results),
        "succeeded": sum(1 for r in results if r.get(success_key)),
        "outcomes": outcomes,
        "top_reasons": sorted(reasons, key=reasons.get, reverse=True)[:4],
        "wall_s": round(cost.wall_s, 2), "cpu_s": round(cost.cpu_s, 2),
        "wall_s_per_attempt": round(cost.wall_s / max(1, len(results)), 2),
        "results": results,
    }


def report(s, success_label="pairs bought"):
    print(f"=== {s['attack']}: {s['succeeded']}/{s['attempts']} {success_label} ===")
    print(f"  outcomes: {json.dumps(s['outcomes'])}")
    for reason in s["top_reasons"]:
        print(f"    - {reason}")
    print(f"  attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU "
          f"({s['wall_s_per_attempt']} s per attempt)")


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")
