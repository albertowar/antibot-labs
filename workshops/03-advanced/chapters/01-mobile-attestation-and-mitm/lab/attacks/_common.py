"""
Shared attacker helpers for Chapter 1 (rules of engagement built in).

Every attack script imports this module, and through it tools/labclient.py, which runs the labnet guard
(the target must be this machine) and rents source addresses from data/world.json: documentation ranges,
never a real proxy, never a public proxy list. Accounts, emails and addresses are synthetic (@mail.example).

It also measures what each attack costs the attacker (wall time, CPU), because the economics are the point
of the last round, and prints the one JSON line tools/checkpoint.py reads:

    attempted / succeeded     buys the attacker tried / pairs it actually got
    outcomes, top_signals     what the store answered, and the gate signals behind the refusals
"""

import json
import os
import random
import sys
import time

try:
    import resource  # Unix only; on Windows CPU cost is reported as 0
except ImportError:
    resource = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "..", "tools"), os.path.join(HERE, "..")]

from labclient import BASE_URL, world_pool  # noqa: E402,F401
from mobile_sdk import DROP_SKU, MobileApp, forge_token  # noqa: E402,F401

FIRST = ["alex", "sam", "jordan", "taylor", "casey", "riley", "morgan", "jamie", "drew", "quinn"]
LAST = ["miller", "davis", "clark", "lewis", "walker", "young", "hall", "allen", "king", "wright"]


def farm_identity(rng):
    """A scalper's throwaway account."""
    email = f"{rng.choice(FIRST)}{rng.choice(LAST)}{rng.randint(100, 9999)}@mail.example"
    return {"email": email, "password": f"Farm-{rng.getrandbits(32):08x}"}


def rng_for(name):
    return random.Random(f"{name}:{time.time_ns()}")


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


def summary(name, results, cost, **extra):
    """The dict every attack's run() returns: results are MobileApp.result() dicts, one per attempted buy."""
    outcomes, signals = {}, {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        for s in r["signals"]:
            signals[s] = signals.get(s, 0) + 1
    return {"attack": name, "attempted": len(results), "succeeded": sum(1 for r in results if r["bought"]),
            "outcomes": outcomes, "top_signals": sorted(signals, key=signals.get, reverse=True)[:4],
            "wall_s": round(cost.wall_s, 2), "cpu_s": round(cost.cpu_s, 2),
            "wall_s_per_attempt": round(cost.wall_s / max(1, len(results)), 2), **extra}


def finish(s, label="pairs bought"):
    print(f"=== {s['attack']}: {s['succeeded']}/{s['attempted']} {label} ===")
    print(f"  outcomes: {json.dumps(s['outcomes'])}")
    for signal in s["top_signals"]:
        print(f"    - {signal}")
    print(f"  attacker cost: {s['wall_s']} s wall, {s['cpu_s']} s CPU ({s['wall_s_per_attempt']} s per attempt)")
    print(json.dumps(s))
