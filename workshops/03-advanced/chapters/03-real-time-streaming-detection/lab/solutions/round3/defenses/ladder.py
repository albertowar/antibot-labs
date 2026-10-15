"""
The ladder for Chapter 3, as it stands after Round 3. Reference version: `--catch-up` installs it.

Level k is enforced when k <= DEFENSE_LEVEL, and the consumer scores with the `detect` half of every check
listed at or below the level. `python tools/checkpoint.py --round 3` sets level 3.
"""

from . import cross_key, heavy_hitters, regularity, window_rate

LADDER = {
    0: [],
    1: [window_rate.CHECK],
    2: [heavy_hitters.CHECK],
    3: [regularity.CHECK, cross_key.CHECK],
}
