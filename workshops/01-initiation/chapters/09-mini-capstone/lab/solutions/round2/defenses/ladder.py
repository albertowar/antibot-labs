"""
Round 2 reference ladder (catch-up file): every check up to IP reputation.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks exist at which DEFENSE_LEVEL, and a level above 2 has nothing wired. `python tools/checkpoint.py
--round 2 --catch-up` copies this over defenses/ladder.py (your version is kept as ladder.py.bak;
`--restore` puts it back). The full ladder, with the reading guide, is the live defenses/ladder.py.
"""

from . import (client_hints, drop_guard, header_inspector, header_order, ip_reputation, prefix_limit,
               rate_limit, trusted_proxy, ua_inspector)

LADDER = {
    0: [],
    1: [trusted_proxy.CHECK, rate_limit.CHECK, prefix_limit.CHECK, drop_guard.RATE_CHECK,
        ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK],
    2: [ip_reputation.CHECK],
}
