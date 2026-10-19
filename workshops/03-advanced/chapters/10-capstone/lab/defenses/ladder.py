"""
The ladder: which checks run at which DEFENSE_LEVEL. The capstone ships it pre-written: every layer is complete
(the Workshop 2 layers are the finished checks of that workshop, copied byte for byte: shared.json) and the three
Round 1 to 3 files carry one `TODO (Round N)` number each, with the answer in solutions/roundN/. You read the
layers, switch levels and watch the scoreboard. `python tools/checkpoint.py --round N` sets the level for you; by
hand: `curl -X POST localhost:5000/lab/level -H 'content-type: application/json' -d '{"level": 5}'`.

Level k is enforced when k <= DEFENSE_LEVEL, so each level includes every level below it. Level 0 is the bare store,
by contract (`tools/verify.py --smoke` runs there), so the eight layers of the chapter, L0 to L7, sit on levels 1 to
7 and two of them share a level:

    level  layer  round  what it does                                             modules (W2 chapter it comes from)
    0      -      -      the bare store                                           -
    1      L0     0      request: headers, TLS family; buy: sensor gate and       ua_inspector, header_inspector,
                         automation artifacts; login: per-IP velocity             client_hints, header_order (Ch1) ·
                                                                                  ja4_denylist, tls_family (Ch7) ·
                                                                                  sensor_gate, automation_artifacts (Ch1)
                                                                                  · login_throttle (Ch4)
    2      L1     0      buy: does the fingerprint cohere?                        consistency, lie_detection (Ch1)
    3      L2     0      buy: how did the hand get to the click?                  behavior_l1, behavior_l2 (Ch3) · flow
    4      L3+L4  0      buy: is this account a farm's? · login: token, cluster   session_model · token_binding, login_risk
    5      L5     1      API: GraphQL cost and depth, introspection, JA4-bound    api_hardening (+ the per-connection
                         token, REST velocity; the WebSocket's message bucket     bucket in defenses/ws_ratelimit.py)
    6      L6     2      stream: rate, regularity (Welford CV), navigation        stream_layer (stream_detectors)
    7      L7     3, 4   buy: CSP violations reported by this session's page      supply_chain (CSP is a response header)

Rounds: 0 runs at level 4 (the whole inherited stack), 1 at 5, 2 at 6, 3 and 4 at 7. The "before" column of a
round is the level below it (`--level N`: 4 for Round 1, and so on).

The Workshop 2 checks are Chapter 1's, Chapter 3's and Chapter 4's own, re-pointed at the buy by drop_guard.at_drop().
Their docstrings count levels the way the W2 Ch9 lab does (token at 5, model at 4); here the model and the login token
share level 4. Cheapest and most certain first inside a level: a hard verdict (the login throttle) stops the gate
before the slower checks. Run with LAB_SHADOW=1 and the levels above the current one still run, logged in
`X-Lab-Shadow` and the decision log but never enforced: see what a layer WOULD do before it can hurt anyone.

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs solutions/round1..N: the three numbers you
were asked to set (Rounds 1 to 3). Round 0 and Round 4 have nothing to install.
"""

from . import (api_hardening, automation_artifacts, behavior_l1, behavior_l2, client_hints, consistency, flow,
               header_inspector, header_order, ja4_denylist, lie_detection, login_risk, login_throttle, sensor_gate,
               session_model, stream_layer, supply_chain, tls_family, token_binding, ua_inspector)
from .drop_guard import at_drop

LADDER = {
    0: [],
    1: [ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK,
        ja4_denylist.CHECK, tls_family.CHECK, login_throttle.CHECK,
        at_drop(sensor_gate.CHECK), at_drop(automation_artifacts.CHECK)],
    2: [at_drop(consistency.CHECK), at_drop(lie_detection.CHECK)],
    3: [behavior_l1.CHECK, behavior_l2.CHECK, flow.CHECK],
    4: [session_model.CHECK, token_binding.CHECK, login_risk.CHECK],
    5: [api_hardening.CHECK],
    6: [stream_layer.CHECK],
    7: [supply_chain.CHECK],
}
