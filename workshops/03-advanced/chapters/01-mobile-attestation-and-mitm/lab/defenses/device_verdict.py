"""
W3 Ch1 — L3 defense: score the verdict and the device's velocity  (Round 4)

Round 4's attacker cannot forge a verdict (Round 2) or replay one (Round 3), so
they do the only thing left: run the REAL app on an emulator or a rack of
devices and mint many fresh, genuine, correctly-bound verdicts. Each one is
individually valid. You stop the *fleet*, not the single request, with two
signals:

  1. Integrity. An emulator or a tampered device cannot earn hardware-backed
     integrity. Score the strongest level the verdict carries
     (mobile_core.integrity_level): "strong"/"device" cost nothing, "basic"
     is friction, "none" is heavy.

  2. Velocity. One deviceId buying again and again, or many weak-integrity
     devices from one egress in an hour, is a farm. Count per deviceId and per
     egress in Redis and add points past a threshold.

    score(ctx, verdict, store) -> (points, [reasons])

>>> READ BEFORE YOU TUNE THIS: the integrity signal is exactly what hurts real
>>> users. A rooted power user, a GrapheneOS phone and a cheap uncertified
>>> Android all return weak integrity too. Tune so the FARM is blocked (verdict
>>> + velocity) while a lone weak device is only CHALLENGED, not blocked. The
>>> checkpoint reports challenged real users as friction so you can see the cost.
>>> Catch up with:  python tools/checkpoint.py --round 4 --catch-up
"""

from mobile_core import integrity_level

DEVICE_BUYS_PER_HOUR = 3
WEAK_DEVICES_PER_EGRESS_HOUR = 3


def score(ctx, verdict, store):
    # TODO (Round 4): implement the integrity + velocity scoring described above.
    return 0, []
