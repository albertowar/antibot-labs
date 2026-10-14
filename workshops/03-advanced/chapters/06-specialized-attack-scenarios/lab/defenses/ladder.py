"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets
level N. Level 0 is this lab's Round 0: the generic per-IP bucket and nothing else. Change this
file, save, and the store picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference version of every check
up to round N, and of this file.

Each round's check is a stub you finish first (the `TODO (Round N)` in defenses/<check>.py);
wiring it here is the second half. Inside a level the order is cost order, cheapest and most
certain first.
"""

from . import generic_layers

# from . import breached_passwords      # 1. import the round's check module

LADDER = {
    0: [generic_layers.CHECK],
    # TODO (Round 1): 1: [breached_passwords.CHECK]  - a correct but breached password needs an emailed code.
    # TODO (Round 2): 2: [scalping_funnel.CHECK]     - funnel integrity and one unit per device.
    # TODO (Round 3): 3: [scrape_defense.CHECK]      - honeypot SKUs and catalogue coverage.
    # TODO (Round 4): 4: [account_cluster.CHECK]     - disposable domains, egress velocity, device clusters.
    # TODO (Round 5): 5: [ivt_scoring.CHECK]         - GIVT hard filters and the SIVT engagement funnel.
}
