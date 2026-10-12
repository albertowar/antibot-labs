"""
The ladder: which checks run at which DEFENSE_LEVEL. (YOUR FILE: wire one round at a time.)

Every check below is already written; read its docstring (what it catches, what it misses,
who it hurts), then wire it and run `python tools/checkpoint.py --round N`.

    Round 1   rate_limit                   1: [rate_limit.CHECK]
    Round 2   blocklists                   2: [blocklists.CHECK]
    Round 3   ip_reputation                3: [ip_reputation.CHECK]
    Round 4   trusted_proxy                4: [trusted_proxy.CHECK]
    Round 5   prefix_limit, geo_velocity   5: [prefix_limit.CHECK, geo_velocity.CHECK]

Level k is enforced when k <= DEFENSE_LEVEL. Cheapest and most certain first inside a level:
a hard verdict stops the gate before the slower checks run.

Change it, save, and the store picks it up on the next request (LAB_RELOAD=1).
Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the reference
version for round N.
"""

# from . import rate_limit              # 1. import the check module
LADDER = {
    0: [],
    # 1: [rate_limit.CHECK],            # 2. wire it into its round's level
}
