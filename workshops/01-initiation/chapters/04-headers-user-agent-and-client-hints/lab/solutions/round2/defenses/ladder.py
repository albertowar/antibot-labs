"""
Round 2 reference ladder (catch-up file): adds the presence and Fetch Metadata check.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks run at which DEFENSE_LEVEL. `python tools/checkpoint.py --round 2 --catch-up` copies this over
defenses/ladder.py (your version is kept as ladder.py.bak).
"""

from . import header_inspector, ua_inspector

LADDER = {
    0: [],
    1: [ua_inspector.CHECK],
    2: [header_inspector.CHECK],
}
