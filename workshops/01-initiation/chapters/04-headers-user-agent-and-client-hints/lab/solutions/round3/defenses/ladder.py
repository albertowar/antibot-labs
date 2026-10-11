"""
Round 3 reference ladder (catch-up file): adds Client Hints and header order.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks run at which DEFENSE_LEVEL. `python tools/checkpoint.py --round 3 --catch-up` copies this over
defenses/ladder.py (your version is kept as ladder.py.bak).
"""

from . import client_hints, header_inspector, header_order, ua_inspector

LADDER = {
    0: [],
    1: [ua_inspector.CHECK],
    2: [header_inspector.CHECK],
    3: [client_hints.CHECK, header_order.CHECK],
}
