"""
The ladder for Chapter 5 (pre-written: every control ships complete; you switch levels).

    level  adds                                          where it lands
    0      nothing: the vendor include skims freely      -
    1      script inventory + change detection           out-of-band (inventory_scripts.py, script_monitor.py)
    2      CSP, host-allowlist (Report-Only, then enforce)   Content-Security-Policy header
    3      CSP nonce + strict-dynamic, SRI on the vendor tag   header + the vendor <script integrity=...>
    4      runtime monitor, loaded first                 a <script> in <head> and POST /api/telemetry

Level k is on when k <= DEFENSE_LEVEL, so each level includes the ones below it, and a higher level's
check may replace a lower one's (level 3's policy replaces level 2's). These checks run in the "page"
phase (see page_controls.py): they decide what an HTML response carries, not whether a request is
served, so the gate never refuses a shopper because of them.

Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}'
-H 'Content-Type: application/json'`, or let `python tools/checkpoint.py --round 3` do it.
`--catch-up` installs solutions/round<N>/defenses/ladder.py, the ladder as it stands after Round N.
"""

from . import csp_policies, generate_sri, inventory, runtime_monitor

LADDER = {
    0: [],
    1: [inventory.CHECK],
    2: [csp_policies.WEAK],
    3: [csp_policies.STRICT, generate_sri.CHECK],
    4: [runtime_monitor.CHECK],
}
