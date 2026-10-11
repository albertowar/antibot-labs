"""
W3 Ch1 — L3 defense: score the verdict and the device's velocity  (Round 4, reference)
"""

import time

from mobile_core import integrity_level

DEVICE_BUYS_PER_HOUR = 3
WEAK_DEVICES_PER_EGRESS_HOUR = 3
INTEGRITY_POINTS = {"strong": 0, "device": 0, "basic": 25, "none": 40}


def score(ctx, verdict, store):
    if verdict is None or not ctx["path"].startswith("/api/mobile/"):
        return 0, []
    points, reasons = 0, []
    level = integrity_level(verdict)
    pts = INTEGRITY_POINTS[level]
    if pts:
        points += pts
        reasons.append(f"Weak device integrity: {level} (no hardware-backed attestation)")
    if verdict.get("appIntegrity") != "PLAY_RECOGNIZED":
        points += 10
        reasons.append(f"App integrity {verdict.get('appIntegrity')} (not a store build)")

    # Velocity. Count real buys only (the gate calls score once per buy attempt).
    hour = int(time.time() // 3600)
    did = verdict.get("deviceId", "?")
    dkey = f"dev:{did}:{hour}"
    n_dev = int(store.incr(dkey))
    store.expire(dkey, 3700)
    if n_dev > DEVICE_BUYS_PER_HOUR:
        points += 60
        reasons.append(f"{n_dev} buys from device {did[:8]} this hour (limit {DEVICE_BUYS_PER_HOUR})")

    if level in ("basic", "none"):
        ekey = f"weakdev:{ctx['egress']}:{hour}"
        store.sadd(ekey, did)
        store.expire(ekey, 3700)
        n_weak = store.scard(ekey)
        if n_weak > WEAK_DEVICES_PER_EGRESS_HOUR:
            points += 60
            reasons.append(f"{n_weak} weak-integrity devices from {ctx['egress']} this hour (farm)")
    return points, reasons
