"""
Round 5 reference ladder (catch-up file): the same as Round 4. Round 5 adds no check; the real browser is answered by levels 1-4.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks run at which DEFENSE_LEVEL. `python tools/checkpoint.py --round 5 --catch-up` copies this over
defenses/ladder.py (your version is kept as ladder.py.bak).
"""

from . import accept_ch, client_hints, header_inspector, header_order, ua_inspector

LADDER = {
    0: [],
    1: [ua_inspector.CHECK],
    2: [header_inspector.CHECK],
    3: [client_hints.CHECK, header_order.CHECK],
    4: [accept_ch.CHECK],
}
