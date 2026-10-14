"""
The ladder: which checks run at which DEFENSE_LEVEL. The capstone ships it pre-written: every defense is
complete, because you built each one in Chapters 1 to 6; you read them, switch levels and watch the
scoreboard. `python tools/checkpoint.py --round N` sets the level for you; by hand:
`curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 2}'`.

Level k is enforced when k <= DEFENSE_LEVEL, so each level includes every level below it. One offset to
remember: Round N runs at level N+1, because the W2 starter has no baseline (level 0 is the bare store by
contract) and Round 0's layer, the one the naive fleet runs into, therefore lives at level 1.

    level  round  layer                                   modules (copied from)
    0      -      the bare store                          -
    1      0      request: headers, TLS consistency        ua_inspector, header_inspector, client_hints,
                                                           header_order (Ch1) · ja4_denylist, tls_family (Ch5)
                  buy: did the page's JavaScript run?      sensor_gate, automation_artifacts (Ch1)
                  login: per-IP velocity, account lock     login_throttle (Ch6)
    2      1      buy: does the fingerprint cohere?        consistency, lie_detection (Ch1)
    3      2      buy: how did the hand get to the click?  behavior_l1, behavior_l2 (Ch3) · flow (capstone)
    4      3      buy: is this account a farm's?           session_model (capstone)
    5      4      login: token binding, cluster failures   token_binding, login_risk (capstone; tokens from Ch2)

The sensor checks are Chapter 1's own, re-pointed at the buy by drop_guard.at_drop(). Cheapest and most
certain first inside a level: a hard verdict (the login throttle) stops the gate before the slower checks.

Fell behind? `python tools/checkpoint.py --round N --catch-up` only restores the wiring (ladder.py and policy.py): every
defense is already here, so catching up means running at the round's level.
"""

from . import (automation_artifacts, behavior_l1, behavior_l2, client_hints, consistency, flow, header_inspector,
               header_order, ja4_denylist, lie_detection, login_risk, login_throttle, sensor_gate, session_model,
               tls_family, token_binding, ua_inspector)
from .drop_guard import at_drop

LADDER = {
    0: [],
    1: [ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK,
        ja4_denylist.CHECK, tls_family.CHECK, login_throttle.CHECK,
        at_drop(sensor_gate.CHECK), at_drop(automation_artifacts.CHECK)],
    2: [at_drop(consistency.CHECK), at_drop(lie_detection.CHECK)],
    3: [behavior_l1.CHECK, behavior_l2.CHECK, flow.CHECK],
    4: [session_model.CHECK],
    5: [token_binding.CHECK, login_risk.CHECK],
}
