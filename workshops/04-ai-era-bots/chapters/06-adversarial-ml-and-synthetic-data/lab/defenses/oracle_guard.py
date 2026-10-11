"""
W4 Ch6 — Round 1 Defense: deny the extraction oracle  [STUDENT FILE]

A per-/24 query budget. A clone needs many labelled queries, and a cheap
extractor sends them from a handful of datacenter /24s. Count scored
checkouts per /24 in the recent window; once a /24 is over BUDGET, stop
answering truthfully and return a CONSTANT block. A constant answer carries
no information, so the extra probes teach the clone nothing — worse, they
teach it that genuinely-allowed configs are blocked, so its fidelity falls.
To rebuild fidelity the attacker must spread across many /24s, which means
buying residential proxies: exactly the spend cohort features (W2 Ch7) see.

Bonus (not required for the round to pass): add boundary randomized response
— within BAND of the threshold, flip the verdict with probability FLIP_P,
keyed deterministically on the session id so a real customer gets a stable
answer. It blunts probing right at the decision line. Left out here to keep
the budget's effect on fidelity easy to read.

Cost, paid by real users and reported by the checkpoint: a CGNAT /24 with
many real phones behind it can exceed the budget on a busy drop and get
soft-denied. Tune BUDGET against your own mobile volume, and prefer
challenging over blocking when you can.

TODO (Round 1): decide() below. _recent_from_ip24() is given.
Fell behind? python tools/checkpoint.py --round 1 --catch-up
"""

import os
import sys
import time

from sqlalchemy import text

sys.path.insert(0, os.path.dirname(__file__))

from netinfo import ip24  # noqa: E402
from store import LAB_TIME_SCALE  # noqa: E402

WINDOW_S = 3600
BUDGET = 20              # scored checkouts per /24 before the oracle goes constant


def _allow(order_id):
    return 200, {"order_id": order_id, "status": "confirmed"}, "confirmed"


def _block(order_id, reason="blocked"):
    return 403, {"error": reason}, "blocked"


def _recent_from_ip24(conn, prefix24, since):
    row = conn.execute(text(
        "SELECT COUNT(*) FROM orders o JOIN sessions s ON o.sid = s.sid "
        "WHERE s.ip24 = :p AND o.ts >= :since AND o.score IS NOT NULL"),
        {"p": prefix24, "since": since}).scalar()
    return int(row or 0)


def decide(conn, level, sid, ip, risk, order_id):
    """TODO (Round 1): per-/24 query budget, then the truthful verdict.

    since = now - WINDOW_S * LAB_TIME_SCALE. If _recent_from_ip24(conn, ip24(ip), since)
    is over BUDGET, return _block(order_id, reason="rate_limited") no matter what
    risk says: a constant answer leaks nothing to the extractor. Otherwise answer
    truthfully. Until then: the truthful oracle, which is what the extractor wants.
    """
    return _block(order_id) if risk >= 1.0 else _allow(order_id)
