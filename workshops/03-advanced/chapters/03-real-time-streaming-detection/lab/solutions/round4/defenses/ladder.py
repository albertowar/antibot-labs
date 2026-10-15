"""
The ladder for Chapter 3, as it stands after Round 4. Reference version: `--catch-up` installs it.

Level k is enforced when k <= DEFENSE_LEVEL, and the consumer scores with the `detect` half of every check
listed at or below the level. `python tools/checkpoint.py --round 4` sets level 4.
"""

from . import composite, cross_key, heavy_hitters, regularity, window_rate

LADDER = {
    0: [],
    1: [window_rate.CHECK],
    2: [heavy_hitters.CHECK],
    3: [regularity.CHECK, cross_key.CHECK],
    4: [composite.CHECK],
}
