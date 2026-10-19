"""
The ladder for Chapter 4 (pre-written: every defense ships complete; you switch levels).

    level  adds                                                         module
    0      nothing: the bare store                                      -
    1      the catalogue needs the js_ok cookie the inline script sets  js_gate (+ cookie_gate)
    2      signed, session-bound, single-use challenge                  js_challenge (+ tokens)
    3      polymorphic, obfuscated variant pool                         js_challenge (+ variants)
    4      environment-bound answer                                     js_challenge (+ env_integrity)
    5      clearance budget                                             js_gate (+ clearance)

One check, js_gate, wired at level 1. Levels 2-5 change WHICH challenge it serves and how strictly
it honours a pass (js_challenge.issue/verify and js_gate read ctx.level), so they add no new check.
Round N = level N.

Switch levels without a restart: `python tools/checkpoint.py --round N` does it, or
`curl -X POST localhost:5000/lab/level -H 'Content-Type: application/json' -d '{"level": 3}'`.
`--catch-up` installs solutions/round<N>/defenses/ladder.py and policy.py.
"""

from . import js_gate

LADDER = {
    0: [],
    1: [js_gate.CHECK],
    2: [],             # js_challenge: signed, single-use nonce
    3: [],             # js_challenge: the variant pool
    4: [],             # js_challenge: environment-bound answer
}
