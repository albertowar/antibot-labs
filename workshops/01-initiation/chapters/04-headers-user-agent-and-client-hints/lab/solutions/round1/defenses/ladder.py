"""
Round 1 reference ladder (catch-up file): the User-Agent check is on.

This lab ships every defense pre-written, so a catch-up only restores the wiring: the ladder says which
checks run at which DEFENSE_LEVEL. `python tools/checkpoint.py --round 1 --catch-up` copies this over
defenses/ladder.py (your version is kept as ladder.py.bak).
"""

from . import ua_inspector

LADDER = {
    0: [],
    1: [ua_inspector.CHECK],
}
