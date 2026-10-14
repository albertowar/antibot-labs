"""
The ladder: which checks run at which DEFENSE_LEVEL. Chapter 9 ships it pre-written: you read each
round's defenses, then switch levels (`python tools/checkpoint.py --round N` sets the level for you;
by hand: `curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'`).

Level k is enforced when k <= DEFENSE_LEVEL, so level 4 runs everything below it too. Cheapest and
most certain first inside a level: a hard verdict (rate limit, block, fake success) stops the gate
before the slower checks run.

    L1  W1 Ch2 + Ch4   trusted_proxy, rate_limit, prefix_limit, the drop's own rate limit,
                       then the four header checks (UA, header set, Client Hints, header order)
    L2  W1 Ch3         ip_reputation (cloud ranges, hosting ASNs, VPN lists; Private Relay is trusted)
    L3  W1 Ch8 + Ch5   the drop form's honeypot and timing token, the crawl traps,
                       then the session as evidence (landing page, JS cookie, session age)
    L4  W1 Ch7 + Ch5   the proof-of-work gate (adaptive price, single-use, bound pass),
                       one hoodie per customer, the session bound to its browser and network,
                       and the sanction a trapped client carries (responses)

Every module below is the finished version of the check a chapter built, copied byte for byte
(shared.json). `drop_guard` is the capstone's: it points those checks at the drop. Edit this file to
experiment (reorder, move a check between levels); the Drop Day exercise only needs policy.py.

Fell behind? `python tools/checkpoint.py --round N --catch-up` is a no-op in this pre-written lab:
every defense is already here, so catching up means restarting at the round's level.
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
