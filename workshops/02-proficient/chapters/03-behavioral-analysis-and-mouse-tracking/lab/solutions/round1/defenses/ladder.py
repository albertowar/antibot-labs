"""
The ladder for Chapter 3 (pre-written: every layer ships complete; you switch levels).

    level  adds                                            module
    0      nothing: the collector records, nobody is stopped -
    1      presence & sanity                               behavior_l1.py
    2      kinematics & keystroke dynamics                 behavior_l2.py
    3      motor-control realism                           behavior_l3.py
    4      layout jitter & replay signatures               behavior_l4.py (+ the page jitter)
    5      touch realism                                   behavior_l5.py

Level k is enforced when k <= DEFENSE_LEVEL, so each level includes every one
below it. Every check runs only on POST /drop/<sku> (phase action:drop_buy).

Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}'
-H 'Content-Type: application/json'`, or let `python tools/checkpoint.py --round 3` do it.
`--catch-up` installs solutions/round<N>/defenses/ladder.py, the ladder as it stands
after Round N.
"""

from . import behavior_l1

LADDER = {
    0: [],
    1: [behavior_l1.CHECK],
}
