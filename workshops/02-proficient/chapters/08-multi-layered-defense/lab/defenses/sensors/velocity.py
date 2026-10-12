"""
Layer: per-IP velocity (stand-in for W1 Ch1)

Counts login attempts per source IP in a 10-minute window.

False positives: carrier-grade NAT puts hundreds of mobile users behind a
handful of addresses, and so do universities and offices. Per-IP limits
punish them first. Attackers with a residential proxy pool simply spread
out until they are below the line.
"""

LAYER = "velocity"
SIGNALS = {
    "ip_elevated": "3+ login attempts from this IP in 10 min",
    "ip_burst": "6+ login attempts from this IP in 10 min",
}

ELEVATED, BURST = 3, 6


def sense(ctx):
    attempts = ctx.counters.bump("vel", ctx.edge["ip"])
    if attempts >= BURST:
        return ["ip_burst"]
    if attempts >= ELEVATED:
        return ["ip_elevated"]
    return []
