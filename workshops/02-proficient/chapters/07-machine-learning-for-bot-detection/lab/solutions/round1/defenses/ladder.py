"""
The ladder: which checks run at which DEFENSE_LEVEL. (Round 1 reference.)

One check, the model scorer, serves every level: it reads ctx.level to pick model v1 (level 1),
model v2 (levels 2 and up), the anomaly detector (levels 3 and up) and deferred enforcement
(level 4). Rounds 2 to 4 change what that check loads and what it is allowed to do, not where it is wired.
"""

from . import ml_check

LADDER = {
    0: [],
    1: [ml_check.CHECK],
}
