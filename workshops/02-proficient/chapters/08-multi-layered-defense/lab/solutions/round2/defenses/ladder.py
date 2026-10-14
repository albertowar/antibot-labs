"""
The ladder for Chapter 8 (pre-written: every layer ships complete; you switch levels).

    level  adds                                                      enforced by
    0      shadow mode: the eight sensor layers run and log          sensors.py     (nothing is enforced)
    1      the veto chain: any layer over its own line blocks        policy.decide -> veto.py
    2      the risk score and the response ladder                    policy.decide
    3      the correlation layer; a block is deceptive from here on  correlation.py, policy.block_action
    4      the campaign layer and the step-up                        campaign.py, policy.CAMPAIGN_ACTION

Round N runs at level N. Level k is enforced when k <= DEFENSE_LEVEL, so each level includes every
level below it. The sensors and the two later layers are checks that only REPORT (signals with
points); what the signals mean is decided in policy.decide(), because the point of the chapter is
that detection and decision are separate. Every check runs only on the login action
(phase action:login: POST /login and POST /api/login).

Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}'
-H 'Content-Type: application/json'`, or let `python tools/checkpoint.py --round 3` do it.
`--catch-up` installs solutions/round<N>/defenses/{ladder,policy}.py, the files as they stand after
Round N, and sets nothing else: the checkpoint sets the level itself.
"""

from . import sensors

LADDER = {
    0: [sensors.CHECK],
    1: [],                      # the veto chain is policy.decide at level 1
    2: [],                      # the risk score is policy.decide from level 2
}
