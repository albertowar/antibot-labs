"""
W4 Ch11 Capstone — L1 crawl governance (REFERENCE SOLUTION, Round 1)

identity × purpose → allow / charged / paywall / maze / block. See the student
stub for the ctx contract. The order of checks is the order of cost:

    1. maze-tagged IPs stay in the maze (cheapest: one Redis read)
    2. a declared crawler we could verify is governed by the reservation:
         search      -> allow
         licensed    -> the 402 exchange (paywall.evaluate): charged when it pays,
                        402 with a price when it does not. Never 403: a 403 to a
                        verified training crawler is a lost licence fee.
         trap path   -> block: it read a Disallow and walked past it
         deny        -> block (not used by the reference reservation)
    3. a declared crawler we could NOT verify -> block. A UA token from outside
       the operator's ranges and unsigned is the Googlebot impostor of W4 Ch2.
    4. undeclared clients are people until they behave like a crawler: a
       datacenter egress fetching more than STEALTH_PAGES_PER_MIN content pages
       in a minute goes to the maze. Residential undeclared clients are never
       mazed on volume alone: that is where CGNAT and offices live.

False positives this still has, named: a VPN user (datacenter egress) who
opens 30+ product tabs in a minute; a reader on a corporate proxy that
happens to sit in a cloud range. Both heal with the TAG_TTL in maze.py.
"""

from . import paywall
from .decision import allow, block, maze

STEALTH_PAGES_PER_MIN = 30


def evaluate(ctx):
    ident = ctx["identity"]
    if ctx["maze_tagged"]:
        return maze(f"{ctx['egress_kind']} client already in the maze: catalogue dark")
    if ident.operator:
        if not ident.verified:
            return block(f"declared {ident.operator} but unverified ({ident.how}): can't trust, can't bill", 80.0)
        if ctx["rule"] == "deny":
            return block(f"policy denies {ident.purpose} for verified {ident.operator}", 60.0)
        if ctx["disallowed"]:
            return block(f"verified {ident.operator} in a Disallowed path", 70.0)
        if ctx["rule"] == "licensed":
            return paywall.evaluate({"identity": ident, "path": ctx["path"], "price": ctx["price"],
                                     "exact": ctx["exact"], "max": ctx["max"]})
        return allow(f"verified {ident.operator} ({ident.purpose}) within policy")
    if ctx["egress_kind"] == "datacenter" and ctx["pages_per_min"] > STEALTH_PAGES_PER_MIN:
        return maze(f"undeclared datacenter client at {ctx['pages_per_min']} pages/min: deterrence")
    return allow("undeclared client within a human page budget")
