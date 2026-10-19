"""
The ladder for Chapter 2 (pre-written: every layer ships complete; you switch levels).

    level  adds                                                 module
    0      nothing: sign-ups are recorded, nobody is refused    -
    1      a fingerprint is required + render-stack plausibility fp_gate.py, render_stack.py
    2      lie detection: page vs. worker vs. headers           lie_detector.py
    3      exact-ID linking, rarity-weighted                    linking.py (+ stable_id.py, rarity.py)
    4      fuzzy clustering on noise-resistant components       fuzzy_cluster.py

Round N runs at level N (no offset: level 0 is the bare store). Level k is enforced when
k <= DEFENSE_LEVEL, so each level includes every level below it. Every check runs only on the
sign-up action (phase action:register: POST /register and POST /api/register).

Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}'
-H 'Content-Type: application/json'`, or let `python tools/checkpoint.py --round 3` do it.
`--catch-up` installs solutions/round<N>/defenses/ladder.py, the ladder as it stands
after Round N.
"""

from . import fp_gate, render_stack

LADDER = {
    0: [],
    1: [fp_gate.CHECK, render_stack.CHECK],
}
