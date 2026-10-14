"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire one round at a time.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets
level N. Level 0 is the bare store: logins are not throttled, screened or scored. Change this
file, save, and the store picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference version of every check
up to round N, and of this file.

Each round's check is a stub you finish first (the `TODO (Round N)` in defenses/<check>.py);
wiring it here is the second half. Inside a level the order is cost order, cheapest and most
certain first, except where one check feeds another (Round 4 notes it).
"""

# from . import login_throttle          # 1. import the round's check module

LADDER = {
    0: [],
    # TODO (Round 1): 1: [login_throttle.CHECK] — per-IP velocity and per-account lockout.
    # TODO (Round 2): 2: [population_signals.CHECK] — per-cohort failure and unknown-account ratios.
    # TODO (Round 3): 3: [breached_passwords.CHECK, oracles.CHECK] — step up a correct-but-breached password; close the recover oracle.
    # TODO (Round 4): 4: [risk_engine.CHECK, risk_engine.REAUTH] — device and network context; fresh proof for an email change.
}
