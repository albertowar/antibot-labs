"""
Round 4 defense (level 4): score the verdict and the device's velocity. (Reference solution.)

Integrity is graded, not binary: strong and device cost nothing, basic is friction (25, served and logged),
none is heavy (40) and an unrecognised build adds 10, so a GrapheneOS phone lands at 50 (the challenge band,
which this store enforces as a refusal) and an emulator at 50 too. What turns "suspicious" into "blocked" is
velocity: more than three weak-integrity devices from one address in an hour, or one device buying more than
three times, adds 80.

Who it hurts: every real customer whose phone cannot earn hardware-backed integrity (GrapheneOS, rooted,
uncertified Android), and anyone whose weak phone shares an address with three others, which is exactly what
carrier-grade NAT produces. The checkpoint prints them. Counting only *weak* devices per address keeps the
CGNAT crowd of ordinary phones out of the farm signal.
"""

import time

from .mobile_core import integrity_level
from .pipeline import Check, Signal

DEVICE_BUYS_PER_HOUR = 3
WEAK_DEVICES_PER_EGRESS_HOUR = 3
INTEGRITY_POINTS = {"strong": 0, "device": 0, "basic": 25, "none": 40}


def _check(ctx):
    verdict = ctx.attrs.get("attest")
    if verdict is None:
        return None
    signals = []
    level = integrity_level(verdict)
    if INTEGRITY_POINTS[level]:
        signals.append(Signal("device_verdict", "weak_integrity", INTEGRITY_POINTS[level], f"{level}: no hardware-backed attestation"))
    if verdict.get("appIntegrity") != "PLAY_RECOGNIZED":
        signals.append(Signal("device_verdict", "unrecognised_app", 10, str(verdict.get("appIntegrity"))))

    # Velocity. The gate runs this check once per buy attempt, so the counters count attempts.
    hour = int(time.time() // 3600)
    did = verdict.get("deviceId", "?")
    dkey = f"lab:ch1:dev:{did}:{hour}"
    n_dev = int(ctx.redis.incr(dkey))
    ctx.redis.expire(dkey, 3700)
    if n_dev > DEVICE_BUYS_PER_HOUR:
        signals.append(Signal("device_verdict", "device_velocity", 80, f"{n_dev} buys from device {did[:8]} this hour"))
    if level in ("basic", "none"):
        ekey = f"lab:ch1:weakdev:{ctx.ip}:{hour}"
        ctx.redis.sadd(ekey, did)
        ctx.redis.expire(ekey, 3700)
        n_weak = ctx.redis.scard(ekey)
        if n_weak > WEAK_DEVICES_PER_EGRESS_HOUR:
            signals.append(Signal("device_verdict", "farm", 80, f"{n_weak} weak-integrity devices from {ctx.ip} this hour"))
    return signals or None


CHECK = Check("device_verdict", _check, phases=("action:mobile_buy",))
