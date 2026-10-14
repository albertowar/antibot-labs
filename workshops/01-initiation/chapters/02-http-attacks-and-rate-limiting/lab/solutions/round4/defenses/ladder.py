"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 4.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 4` sets level 4.

Round 4 keys the limits on something other than "every request from this IP": the login
endpoint gets its own tight per-IP bucket, and each targeted account gets a cap that no amount
of address rotation escapes.
"""

from . import account_limit, endpoint_limit, fixed_window, flood_monitor, rate_limit

LADDER = {
    0: [],
    1: [flood_monitor.CHECK],
    2: [fixed_window.CHECK],
    3: [rate_limit.CHECK],
    4: [endpoint_limit.CHECK, account_limit.CHECK],
}
