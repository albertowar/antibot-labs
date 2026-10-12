"""
The ladder for Chapter 1. (YOUR FILE in wire-it labs; this one ships wired: you finish the
TODO (Round N) function in each layer module instead.)

    level  adds                                                        module               round
    0      nothing: the bare store (the contract's level 0)            -                    -
    1      W1's header rules: User-Agent, header shape, Client Hints,  ua_inspector, ...    Round 0
           header order, Accept-CH                                     accept_ch
    2      the sensor gate + automation artifacts                      sensor_gate, ...     Round 1
    3      consistency (JS vs HTTP, headless shape, GPU)               consistency          Round 2
    4      lie detection (native code, realms)                         lie_detection        Round 3
    5      interaction evidence on the cart                            interaction          Round 4 (and 5)

One offset to remember: Round N runs at level N+1. The W2 starter has no baseline (every workshop
runs on its own) and level 0 is the bare store by contract, so W1's header rules, which the
attacker of this chapter has already beaten, get level 1 here. They are copied from W1 Ch4's lab
(`scripts/lab_diff.py --shared` compares the copies). `tools/checkpoint.py --round N` sets the
right level for you.

Level k is enforced when k <= DEFENSE_LEVEL. Points from every check add up (defenses/policy.py):
20+ is logged as suspicious, 40+ is blocked.

Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference layer
modules from solutions/round1..N.
"""

from . import (accept_ch, automation_artifacts, client_hints, consistency, header_inspector, header_order,
               interaction, lie_detection, sensor_gate, ua_inspector)

LADDER = {
    0: [],
    1: [ua_inspector.CHECK, header_inspector.CHECK, client_hints.CHECK, header_order.CHECK, accept_ch.CHECK],
    2: [sensor_gate.CHECK, automation_artifacts.CHECK],
    3: [consistency.CHECK],
    4: [lie_detection.CHECK],
    5: [interaction.CHECK],
}
