"""
Round 4 reference ladder (catch-up file): every check up to the proof of work, the binding and the cap.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks exist at which DEFENSE_LEVEL, and a level above 4 has nothing wired. `python tools/checkpoint.py
--round 4 --catch-up` copies this over defenses/ladder.py (your version is kept as ladder.py.bak;
`--restore` puts it back). The full ladder, with the reading guide, is the live defenses/ladder.py.
"""

from . import (client_hints, crawl_traps, drop_guard, header_inspector, header_order, ip_reputation,
               pow_adaptive, pow_budget, pow_gate, prefix_limit, rate_limit, responses, trusted_proxy,
               ua_inspector)

LADDER = {
    0: [],
    1: [trusted_proxy.CHECK, rate_limit.CHECK, prefix_limit.CHECK, drop_guard.RATE_CHECK,
        ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK],
    2: [ip_reputation.CHECK],
    3: [drop_guard.FORM_CHECK, crawl_traps.CHECK, drop_guard.SESSION_CHECK],
    4: [drop_guard.CAP_CHECK, drop_guard.BINDING_CHECK, pow_gate.CHECK, pow_budget.CHECK,
        pow_adaptive.CHECK, responses.CHECK],
}
