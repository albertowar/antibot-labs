"""
The ladder for Chapter 3 (pre-written: every detector ships complete; you switch levels).

    level  adds                                           stream half (scores)       gate half (enforces)
    0      nothing: the log fills, nobody reads it        -                          -
    1      sliding-window rate per (IP, endpoint)         window_rate.detect         window_rate.CHECK
    2      + heavy hitters (Count-Min, HyperLogLog)       heavy_hitters.detect       heavy_hitters.CHECK
    3      + timing regularity, + distinct IPs/account    regularity, cross_key      regularity.CHECK, cross_key.CHECK
    4      + the composite verdict                        composite.detect           composite.CHECK

Level k is enforced when k <= DEFENSE_LEVEL, so each level includes the ones below it. A detector
has two halves. The consumer thread (demo_site/ext/stream.py -> defenses/consumer.py) reads the
event stream and runs the `detect` of every check this ladder enables at the current level; it
writes a flag. The gate runs the `CHECK` on the next request and refuses what the flag names.
The ladder is the single list that turns both halves on, so `/lab/status` shows what is live.

Switch levels without a restart: `curl -X POST localhost:5000/lab/level -d '{"level": 3}'
-H 'Content-Type: application/json'`, or let `python tools/checkpoint.py --round 3` do it.
`--catch-up` installs solutions/round<N>/defenses/ladder.py, the ladder as it stands after
Round N (undoing an experiment); the checkpoint sets the level itself.
"""

from . import composite, cross_key, heavy_hitters, regularity, window_rate

LADDER = {
    0: [],
    1: [window_rate.CHECK],
    2: [heavy_hitters.CHECK],
    3: [regularity.CHECK, cross_key.CHECK],
    4: [composite.CHECK],
}
