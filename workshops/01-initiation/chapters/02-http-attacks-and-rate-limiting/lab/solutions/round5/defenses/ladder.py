"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 5.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 5` sets level 5.

Round 5 fixes the foundation every earlier layer stood on. `trusted_proxy` makes client_ip()
read X-Forwarded-For from the right, so every per-IP limit keys on the real address instead
of whatever the client claimed. `prefix_limit` counts per /24 and per /64, so rotating inside
one allocation (an IPv6 /64) no longer looks like many clients.
"""

from . import (account_limit, endpoint_limit, fixed_window, flood_monitor,
               prefix_limit, rate_limit, trusted_proxy)

LADDER = {
    0: [],
    1: [flood_monitor.CHECK],
    2: [fixed_window.CHECK],
    3: [rate_limit.CHECK],
    4: [endpoint_limit.CHECK, account_limit.CHECK],
    5: [trusted_proxy.CHECK, prefix_limit.CHECK],
}
