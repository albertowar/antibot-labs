"""
The ladder: which checks run at which DEFENSE_LEVEL. YOUR FILE: wire Round 1.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.
Level 0 is the bare store: the event log is written and nothing is scored. Change this file, save,
and the store picks it up on the next request (LAB_RELOAD=1). Fell behind?
`python tools/checkpoint.py --round N --catch-up` installs the reference version of every file you
would write up to round N, and of this one, and trains the models.

One check, the model scorer, serves every level (it reads ctx.level to pick model v1, model v2, the
anomaly detector, deferred enforcement). So you wire it once, here, at level 1; Rounds 2 to 4 finish
cohort.py, anomaly.py and enforcement.py instead of adding entries.
"""

# from . import ml_check          # 1. import the scoring check

LADDER = {
    0: [],
    # TODO (Round 1): 1: [ml_check.CHECK] — and finish _check() in defenses/ml_check.py.
}
