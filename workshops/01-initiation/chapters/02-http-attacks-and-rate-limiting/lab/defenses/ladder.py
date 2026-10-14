"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N`
sets level N. Change it, save, and the store picks it up on the next request
(LAB_RELOAD=1). Fell behind? `python tools/checkpoint.py --round N --catch-up` installs
the reference wiring (solutions/roundN/) for rounds 1..N.
"""

# from . import flood_monitor          # 1. import the round's check module(s)

LADDER = {
    0: [],
    # TODO (Round 1): 1: [flood_monitor.CHECK] — watch the flood, block nothing.
    # TODO (Round 2): 2: [fixed_window.CHECK] — the first real limit, and its boundary.
    # TODO (Round 3): 3: [rate_limit.CHECK] — or sliding_window.CHECK; pick one, compare both.
    # TODO (Round 4): 4: [endpoint_limit.CHECK, account_limit.CHECK] — login gets its own keys.
    # TODO (Round 5): 5: [trusted_proxy.CHECK, prefix_limit.CHECK] — fix which address they all key on.
}
