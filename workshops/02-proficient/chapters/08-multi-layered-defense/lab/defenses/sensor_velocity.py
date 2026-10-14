"""
Layer: per-IP velocity (stand-in for W1 Ch2)

Counts login attempts per source IP in a 10-minute window. A retry after a solved challenge is
the same attempt, so it reads the counter without adding to it (attempt.py).

False positives: carrier-grade NAT puts hundreds of mobile users behind a handful of addresses,
and so do universities and offices. Per-IP limits punish them first. Attackers with a
residential proxy pool simply spread out until they are below the line.
"""

from . import attempt
from .store import Counters

LAYER = "velocity"
SIGNALS = {
    "ip_elevated": "3+ login attempts from this IP in 10 min",
    "ip_burst": "6+ login attempts from this IP in 10 min",
}

ELEVATED, BURST, WINDOW = 3, 6, 600


def sense(ctx):
    counters = Counters(ctx.redis, prefix="lab:ch8:c")
    attempts = (counters.count("vel", ctx.edge.ip, WINDOW) if attempt.resumed(ctx)
                else counters.hit("vel", ctx.edge.ip, WINDOW))
    if attempts >= BURST:
        return ["ip_burst"]
    if attempts >= ELEVATED:
        return ["ip_elevated"]
    return []
